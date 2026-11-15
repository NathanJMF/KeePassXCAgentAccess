"""Owner registry and independent KeePass worker sessions."""

from dataclasses import asdict, dataclass, replace
from hashlib import file_digest
import json
from pathlib import Path
from threading import Event, RLock
from uuid import uuid4

from .access_settings import Action, AccessStore, label, uuid_text
from .keyring import KeyringError
from .settings import SettingsError, SettingsStore, write_private_json
from .vault import UnlockCancelled, VaultError, VaultTarget, open_vault


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
    def __init__(self, directory, keyring, opener=open_vault):
        self.directory = Path(directory)
        self.path = self.directory / "workspace.json"
        self.legacy_access = AccessStore(self.directory / "access.json")
        self.keyring = keyring
        self.opener = opener
        self.mutex = RLock()
        self.registrations = {}
        self.sessions = {}
        self.opening = {}
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
        with self.mutex:
            for item in self.pending:
                try:
                    self.keyring.remove(item)
                except KeyringError:
                    continue
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

    def add(self, target, password, remember, name=None):
        return self._open(new_id(), target, password, remember, label(name or target.database.stem), adding=True)

    def unlock(self, identifier, password=None, remember=None):
        with self.mutex:
            target = self.registrations[identifier].target
        return self._open(identifier, target, password, remember)

    def relink(self, identifier, target, password, remember=None):
        return self._open(identifier, target, password, remember, relinking=True)

    def _open(self, identifier, target, password, remember, name=None, *, adding=False, relinking=False):
        target = VaultTarget(target.database.resolve(), target.key_file.resolve() if target.key_file else None)
        with self.mutex:
            if identifier in self.opening:
                raise VaultError("This vault is already being opened.")
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
            with self.mutex:
                if cancelled.is_set() or self.registrations.get(identifier) != record:
                    raise UnlockCancelled
                self._check_target(target, identifier)
                if record is None:
                    record = Registration(identifier, name, target, worker.identity, None)
                elif record.identity and record.identity != worker.identity:
                    raise VaultError("The selected file does not match the registered vault.")
                elif record.identity is None:
                    imported = self.legacy_access.read().for_vault(worker.identity).actions
                    record = replace(record, identity=worker.identity,
                                     bindings=tuple(Binding(action, new_id()) for action in imported))
                old_item = record.item
                item = new_id() if remember is True else None if remember is False else old_item
                pending = self.pending + ((old_item,) if old_item and old_item != item else ())
                if remember is True:
                    # Queue the new reference before saving it so a failed registration can be cleaned up.
                    self._save(self.registrations, self.pending + (item,))
                    self.keyring.remember(item, password)
                try:
                    updated = replace(record, target=target, item=item, fingerprint=fingerprint)
                    if updated != self.registrations.get(identifier):
                        self._replace(updated, pending)
                except BaseException:
                    self.cleanup()
                    raise
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
        session = self.sessions.get(identifier)
        return session if session and session.worker.available else None

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
