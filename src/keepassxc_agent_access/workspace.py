"""Owner registry and independent KeePass worker sessions."""

from contextlib import nullcontext
from dataclasses import asdict, dataclass, replace
from functools import partial
from hashlib import file_digest
import json
from pathlib import Path
from threading import Event, RLock
from uuid import uuid4

from .access_settings import Action, AccessStore, label, uuid_text
from .keyring import KeyringError
from .settings import SettingsError, SettingsStore, write_private_json
from .vault import UnlockCancelled, VaultChanged, VaultError, VaultTarget, open_vault


def new_id():
    return str(uuid4())


@dataclass(frozen=True)
class Binding:
    action: Action
    revision: str


@dataclass(frozen=True)
class Registration:
    id: str
    name: str
    target: VaultTarget
    identity: str | None
    item: str | None
    bindings: tuple[Binding, ...] = ()
    fingerprint: str | None = None

    def binding(self, entry, action_id):
        return next((b for b in self.bindings if (b.action.entry, b.action.id) == (entry, action_id)), None)


@dataclass(frozen=True)
class Unlocked:
    worker: object
    groups: tuple
    entries: tuple


class Workspace:
    def __init__(self, directory, keyring, opener=partial(open_vault, writable=True)):
        self.directory = Path(directory)
        self.path = self.directory / "workspace.json"
        self.legacy_access = AccessStore(self.directory / "access.json")
        self.keyring = keyring
        self.opener = opener
        self.mutex = RLock()
        self.keyring_mutex = RLock()
        self.owner_generation = 0
        self.registrations = {}
        self.sessions = {}
        self.opening = {}
        self.editing = set()
        self.pending = ()
        self.paused = True
        self.generation = 0
        self._load()

    def _load(self):
        try:
            saved = json.loads(self.path.read_text())
        except FileNotFoundError:
            old = SettingsStore(self.directory / "settings.json").read()
            if old.target:
                record = Registration(new_id(), old.target.database.stem, old.target, None, old.active_item)
                self._save({record.id: record}, old.pending_items)
            elif old.pending_items:
                self._save({}, old.pending_items)
            return
        except (ValueError, OSError):
            raise SettingsError("Vault registry could not be read.") from None
        try:
            if saved["version"] != 1:
                raise ValueError
            self.pending = tuple(saved["pending"])
            for row in saved["vaults"]:
                bindings = tuple(Binding(Action(**b["action"]), uuid_text(b["revision"])) for b in row["bindings"])
                target = VaultTarget(Path(row["database"]), Path(row["key_file"]) if row["key_file"] else None)
                record = Registration(uuid_text(row["id"]), label(row["name"]), target,
                                      uuid_text(row["identity"]) if row["identity"] else None, row["item"], bindings, row.get("fingerprint"))
                if record.id in self.registrations:
                    raise ValueError
                self.registrations[record.id] = record
        except (KeyError, AttributeError, TypeError, ValueError):
            raise SettingsError("Vault registry could not be read.") from None

    def _save(self, records, pending=None):
        pending = self.pending if pending is None else pending
        write_private_json(self.path, {
            "version": 1, "pending": pending,
            "vaults": [{
                "id": r.id, "name": r.name, "database": str(r.target.database),
                "key_file": str(r.target.key_file) if r.target.key_file else None,
                "identity": r.identity, "item": r.item, "bindings": [asdict(b) for b in r.bindings],
                "fingerprint": r.fingerprint,
            } for r in records.values()],
        })
        self.registrations, self.pending = records, pending

    def cleanup(self):
        with self.keyring_mutex:
            with self.mutex:
                pending = self.pending
            for item in pending:
                try:
                    self.keyring.remove(item)
                except KeyringError:
                    continue
                with self.mutex:
                    self._save(self.registrations, tuple(i for i in self.pending if i != item))

    def _replace(self, record, pending=None):
        self._save({**self.registrations, record.id: record}, pending)

    def _check_target(self, target, identifier):
        for record in self.registrations.values():
            if record.id == identifier:
                continue
            other = record.target.database
            try:
                same = target.database.samefile(other)
            except OSError:
                same = target.database.resolve() == other.resolve()
            if same:
                raise VaultError("This database is already registered.")

    def add(self, target, password, remember, name=None, *, cycle=None):
        return self._open(new_id(), target, password, remember, label(name or target.database.stem),
                          adding=True, cycle=cycle)

    def unlock(self, identifier, password=None, remember=None, *, cycle=None):
        with self.mutex:
            target = self.registrations[identifier].target
        return self._open(identifier, target, password, remember, cycle=cycle)

    def relink(self, identifier, target, password, remember=None, *, cycle=None):
        return self._open(identifier, target, password, remember, relinking=True, cycle=cycle)

    def _open(self, identifier, target, password, remember, name=None, *, adding=False, relinking=False, cycle=None):
        target = VaultTarget(target.database.resolve(), target.key_file.resolve() if target.key_file else None)
        with self.mutex:
            if cycle is not None and cycle != self.owner_generation:
                raise UnlockCancelled
            if identifier in self.opening or identifier in self.editing:
                raise VaultError("This vault is already being opened or edited.")
            record = self.registrations.get(identifier)
            if record is None and not adding:
                raise UnlockCancelled
            if relinking and record.identity is None:
                raise VaultError("Unlock the original database before relinking this registration.")
            if relinking and record.target.database.exists() and target.database != record.target.database:
                raise VaultError("The original vault still exists. Register a different file separately.")
            self._check_target(target, identifier)
            cancelled = self.opening[identifier] = Event()
        worker = None
        previous = None
        try:
            if password is None:
                if record is None or record.item is None:
                    raise VaultError("Enter the vault password to unlock.")
                with self.keyring_mutex:
                    password = self.keyring.retrieve(record.item)
            try:
                with target.database.open("rb") as source:
                    fingerprint = file_digest(source, "sha256").hexdigest()
            except OSError:
                raise VaultError("The database is missing or unreadable.") from None
            if relinking and record.fingerprint != fingerprint:
                raise VaultError("The selected file does not match the last verified vault.")
            worker = self.opener(target, password, cancelled)
            snapshot = worker.owner_snapshot()
            session = Unlocked(worker, tuple(snapshot["groups"]), tuple(snapshot["entries"]))
            with self.keyring_mutex if remember else nullcontext():
                with self.mutex:
                    if cancelled.is_set() or self.registrations.get(identifier) != record:
                        raise UnlockCancelled
                    if record and record.identity and record.identity != worker.identity:
                        raise VaultError("The selected file does not match the registered vault.")
                    item = new_id() if remember is True else None if remember is False or record is None else record.item
                    if remember:
                        # Journal the new item before writing it to the OS service.
                        self._save(self.registrations, self.pending + (item,))
                if remember:
                    self.keyring.remember(item, password)
                with self.mutex:
                    if cancelled.is_set() or self.registrations.get(identifier) != record:
                        raise UnlockCancelled
                    self._check_target(target, identifier)
                    if record is None:
                        record = Registration(identifier, name, target, worker.identity, None)
                    elif record.identity is None:
                        imported = self.legacy_access.read().for_vault(worker.identity).actions
                        record = replace(record, identity=worker.identity,
                                         bindings=tuple(Binding(action, new_id()) for action in imported))
                    pending = tuple(i for i in self.pending if i != item)
                    if record.item and record.item != item:
                        pending += (record.item,)
                    updated = replace(record, target=target, item=item, fingerprint=fingerprint)
                    if updated != self.registrations.get(identifier):
                        self._replace(updated, pending)
                    previous = self.sessions.get(identifier)
                    self.sessions[identifier] = session
                    worker = None
            return identifier
        finally:
            with self.mutex:
                self.opening.pop(identifier, None)
            if worker is not None:
                worker.close()
            if previous is not None:
                previous.worker.close()
            # Stale keyring references are already journaled and can be retried at startup.
            try:
                self.cleanup()
            except SettingsError:
                pass

    def session(self, identifier):
        if identifier in self.editing:
            return None
        return self.owner_session(identifier)

    def owner_session(self, identifier):
        session = self.sessions.get(identifier)
        return session if session and session.worker.available else None

    def put_entry(self, identifier, parent, *, title, username="", url="", password=None, entry=None):
        return self._edit(identifier, "put_entry", parent=parent, title=title,
                          username=username, url=url, password=password, entry=entry)

    def remove_entry(self, identifier, entry):
        return self._edit(identifier, "remove_entry", entry=entry)

    def put_group(self, identifier, parent, *, name, group=None):
        return self._edit(identifier, "put_group", parent=parent, name=name, group=group)

    def remove_group(self, identifier, group):
        return self._edit(identifier, "remove_group", group=group)

    def _edit(self, identifier, change, **values):
        with self.mutex:
            if identifier in self.editing or identifier in self.opening:
                raise VaultError("This vault is already being opened or edited.")
            session = self.owner_session(identifier)
            if session is None:
                raise VaultError("Unlock the vault before editing.")
            self.editing.add(identifier)

        def gate(send):
            with self.mutex:
                if self.sessions.get(identifier) is not session:
                    return False
                send()
                return True

        try:
            result = session.worker.owner_edit({"change": change, **values}, gate)
            with self.mutex:
                record = self.registrations.get(identifier)
                current = self.sessions.get(identifier)
                if current is session:
                    snapshot = result["snapshot"]
                    self.sessions[identifier] = Unlocked(session.worker, tuple(snapshot["groups"]),
                                                         tuple(snapshot["entries"]))
                if record is not None and (current is session or current is None):
                    try:
                        self._replace(replace(record, fingerprint=result["fingerprint"]))
                    except SettingsError:
                        raise VaultError("The edit was saved, but Keeper could not update its vault registry.") from None
            if not result["durable"]:
                raise VaultError("The edit was saved, but the filesystem did not confirm its disk flush.")
            return result["id"]
        except VaultChanged:
            with self.mutex:
                if self.sessions.get(identifier) is session:
                    self.sessions.pop(identifier)
            session.worker.close()
            raise
        finally:
            with self.mutex:
                if self.sessions.get(identifier) is session and not session.worker.available:
                    self.sessions.pop(identifier)
                self.editing.remove(identifier)

    def lock(self, identifier):
        with self.mutex:
            if identifier in self.opening:
                self.opening[identifier].set()
            session = self.sessions.pop(identifier, None)
        if session:
            session.worker.close()

    def pause(self, paused=True):
        with self.mutex:
            if self.paused != paused:
                self.paused = paused
                self.generation += 1

    def lock_all(self):
        with self.mutex:
            self.owner_generation += 1
            self.pause()
            for job in self.opening.values():
                job.set()
            sessions, self.sessions = self.sessions, {}
        for session in sessions.values():
            session.worker.close()

    def rename(self, identifier, name):
        with self.mutex:
            self._replace(replace(self.registrations[identifier], name=label(name)))

    def remove(self, identifier):
        with self.mutex:
            record = self.registrations[identifier]
            records = {key: value for key, value in self.registrations.items() if key != identifier}
            self._save(records, self.pending + ((record.item,) if record.item else ()))
            self.lock(identifier)
        self.cleanup()

    def forget(self, identifier):
        with self.mutex:
            record = self.registrations[identifier]
            if record.item:
                self._replace(replace(record, item=None), self.pending + (record.item,))
        self.cleanup()

    def save_binding(self, identifier, action, original=None):
        with self.mutex:
            record = self.registrations[identifier]
            session = self.session(identifier)
            if session is None or not any(row["id"] == action.entry for row in session.entries):
                raise VaultError("Unlock the vault and select an entry first.")
            old = record.binding(action.entry, original) if original else None
            existing = record.binding(action.entry, action.id)
            if existing and existing is not old:
                raise ValueError("This entry already has that action ID.")
            revision = old.revision if old and old.action.url == action.url and old.action.id == action.id else new_id()
            bindings = tuple(b for b in record.bindings if b is not old) + (Binding(action, revision),)
            self._replace(replace(record, bindings=bindings))

    def remove_binding(self, identifier, entry, action_id):
        with self.mutex:
            record = self.registrations[identifier]
            old = record.binding(entry, action_id)
            self._replace(replace(record, bindings=tuple(b for b in record.bindings if b is not old)))
