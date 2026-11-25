"""Owner registry and independent KeePass worker sessions."""

from contextlib import nullcontext
from dataclasses import asdict, dataclass, replace
from functools import partial
from hashlib import sha256
import json
import os
from pathlib import Path
from threading import Event, RLock
from uuid import uuid4

from .access_settings import (Action, AccessStore, GUEST_AUTO_APPROVAL_OPTIONS, MAX_TOKEN_LIFESPAN_DAYS,
                              MIN_TOKEN_LIFESPAN_DAYS, SCOPED_AUTO_APPROVAL_OPTIONS,
                              TOKEN_AUTO_APPROVAL_OPTIONS, label, uuid_text)
from .discovery import DiscoveryCatalog
from .keyring import KeyringError
from .settings import SettingsError, SettingsStore, write_private_json
from .vault import UnlockCancelled, VaultChanged, VaultError, VaultTarget, open_vault


def new_id():
    return str(uuid4())


def ordered_groups(groups):
    """Yield visible groups with their paths in the vault's tree order."""
    children = {}
    for group in groups:
        children.setdefault(group["parent"], []).append(group)
    pending = [(group, ()) for root in children.get(None, ()) for group in reversed(children.get(root["id"], ()))]
    while pending:
        group, parent_path = pending.pop()
        path = (*parent_path, group["name"] or "(Untitled group)")
        yield group, path
        pending.extend((child, path) for child in reversed(children.get(group["id"], ())))


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
    credential_epoch: str | None = None
    credential_nonces: tuple[tuple[str, str], ...] = ()

    def __post_init__(self):
        if self.credential_epoch is not None:
            object.__setattr__(self, "credential_epoch", uuid_text(self.credential_epoch))
        if not isinstance(self.credential_nonces, (list, tuple)):
            raise ValueError("Invalid credential approval revisions.")
        nonces = []
        for pair in self.credential_nonces:
            if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                raise ValueError("Invalid credential approval revision.")
            nonces.append((uuid_text(pair[0]), uuid_text(pair[1])))
        if len({entry for entry, _ in nonces}) != len(nonces):
            raise ValueError("Duplicate credential approval revisions.")
        object.__setattr__(self, "credential_nonces", tuple(sorted(nonces)))

    def credential_revision(self, entry):
        entry = uuid_text(entry)
        epoch = self.credential_epoch or self.id
        nonce = dict(self.credential_nonces).get(entry, "")
        return sha256(("Keeper credential-use revision v1\0" + epoch + "\0" + entry + "\0" + nonce).encode("ascii")).hexdigest()

    def binding(self, entry, action_id):
        return next((b for b in self.bindings if (b.action.entry, b.action.id) == (entry, action_id)), None)


@dataclass(frozen=True)
class Unlocked:
    worker: object
    groups: tuple
    entries: tuple
    recycle_bin: dict | None = None


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
        preferences = self.legacy_access.read()
        self.paused = preferences.agent_paused
        self.review_usage = preferences.review_usage
        self.review_actions = preferences.review_actions - {"read_results"}
        if preferences.review_results:
            self.review_actions |= {"read_results"}
        self.auto_approve_tokens = preferences.auto_approve_tokens
        self.auto_approve_guest_actions = preferences.auto_approve_guest_actions
        self.auto_approve_scoped_actions = preferences.auto_approve_scoped_actions
        self.auto_approve_token_changes = preferences.auto_approve_token_changes
        self.auto_approve_token_extensions = preferences.auto_approve_token_extensions
        self.auto_approve_token_credential_uses = preferences.auto_approve_token_credential_uses
        self.auto_approve_token_rotations = preferences.auto_approve_token_rotations
        self.token_lifespan_days = preferences.token_lifespan_days
        self.unlock_on_desktop_unlock = preferences.unlock_on_desktop_unlock
        self.resume_on_desktop_unlock = preferences.resume_on_desktop_unlock
        self.token_auto_approval_acknowledged = preferences.token_auto_approval_acknowledged
        self.generation = 0
        self._load()
        self.discovery = DiscoveryCatalog(self.directory / "discovery.json")

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
                                      uuid_text(row["identity"]) if row["identity"] else None, row["item"], bindings, row.get("fingerprint"),
                                      row.get("credential_epoch"), row.get("credential_nonces", ()))
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
                "fingerprint": r.fingerprint, "credential_epoch": r.credential_epoch,
                "credential_nonces": r.credential_nonces,
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
            worker = self.opener(target, password, cancelled)
            fingerprint = worker.fingerprint
            if relinking and record.fingerprint != fingerprint:
                raise VaultError("The selected file does not match the last verified vault.")
            snapshot = worker.owner_snapshot()
            session = Unlocked(worker, tuple(snapshot["groups"]), tuple(snapshot["entries"]),
                               snapshot.get("recycle_bin"))
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
                    elif record.fingerprint != fingerprint:
                        # An external save can change credentials without changing entry IDs.
                        record = replace(record, bindings=tuple(replace(b, revision=new_id()) for b in record.bindings),
                                         credential_epoch=new_id(), credential_nonces=())
                    pending = tuple(i for i in self.pending if i != item)
                    if record.item and record.item != item:
                        pending += (record.item,)
                    updated = replace(record, target=target, item=item, fingerprint=fingerprint)
                    if updated != self.registrations.get(identifier):
                        self._replace(updated, pending)
                    previous = self.sessions.get(identifier)
                    self.sessions[identifier] = session
                    self.discovery.remember(identifier, session.groups, session.entries)
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

    def credential_revision(self, identifier, entry):
        with self.mutex:
            return self.registrations[identifier].credential_revision(entry)

    def session(self, identifier):
        if identifier in self.editing:
            return None
        return self.owner_session(identifier)

    def owner_session(self, identifier):
        session = self.sessions.get(identifier)
        return session if session and session.worker.available else None

    def entry_notes(self, identifier, entry):
        """Read one active entry’s notes, or return None if the text exceeds the worker response limit."""
        with self.mutex:
            session = self.owner_session(identifier)
            if session is None:
                raise VaultError("Unlock the vault before reading entry notes.")
            if identifier in self.editing or identifier in self.opening:
                raise VaultError("This vault is already being opened or edited.")
            if not any(row["id"] == entry for row in session.entries):
                raise VaultError("The entry is unavailable.")
        notes = session.worker.owner_entry_notes(entry)
        with self.mutex:
            if self.owner_session(identifier) is not session:
                raise VaultError("The vault changed while loading the entry notes. Try again.")
        return notes

    def put_entry(self, identifier, parent, *, title, username="", url="", password=None, notes=None, entry=None):
        return self._edit(identifier, "put_entry", parent=parent, title=title,
                          username=username, url=url, password=password, notes=notes, entry=entry)

    def remove_entry(self, identifier, entry):
        return self._edit(identifier, "remove_entry", entry=entry)

    def delete_entry(self, identifier, entry):
        return self._edit(identifier, "delete_entry", entry=entry)

    def put_group(self, identifier, parent, *, name, group=None):
        return self._edit(identifier, "put_group", parent=parent, name=name, group=group)

    def remove_group(self, identifier, group):
        return self._edit(identifier, "remove_group", group=group)

    def delete_group(self, identifier, group):
        return self._edit(identifier, "delete_group", group=group)

    def _edit(self, identifier, change, *, expected=None, may_commit=None, before_commit=None, **values):
        with self.mutex:
            if identifier in self.editing or identifier in self.opening:
                raise VaultError("This vault is already being opened or edited.")
            session = self.owner_session(identifier)
            if session is None:
                raise VaultError("Unlock the vault before editing.")
            if expected is not None and session is not expected:
                raise VaultChanged("The vault changed. Reopen the request and review it again.")
            self.editing.add(identifier)

        def gate(publish):
            with self.mutex:
                if self.sessions.get(identifier) is not session or may_commit is not None and not may_commit():
                    return False
                if change == "put_entry":
                    self._invalidate_changed_credentials(identifier, session, values)
                if before_commit is not None:
                    before_commit()
                publish()
                return True

        try:
            result = session.worker.owner_edit({"change": change, **values}, gate)
            with self.mutex:
                record = self.registrations.get(identifier)
                current = self.sessions.get(identifier)
                if record is not None and (current is session or current is None):
                    self.discovery.remember(identifier, result["snapshot"]["groups"], result["snapshot"]["entries"])
                if current is session:
                    snapshot = result["snapshot"]
                    self.sessions[identifier] = Unlocked(session.worker, tuple(snapshot["groups"]),
                                                         tuple(snapshot["entries"]), snapshot.get("recycle_bin"))
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

    def _invalidate_changed_credentials(self, identifier, session, values):
        entry_id = values.get("entry")
        if entry_id is None:
            return
        old = next((entry for entry in session.entries if entry["id"] == entry_id), None)
        if (old is None or values.get("username") == old["username"]
                and values.get("password") is None and not values.get("generate_password")):
            return
        record = self.registrations[identifier]
        bindings = tuple(replace(binding, revision=new_id()) if binding.action.entry == entry_id else binding
                         for binding in record.bindings)
        nonces = dict(record.credential_nonces)
        nonces[entry_id] = new_id()
        # Both saved-action and reusable grants must become stale before the
        # credential commit, including entries without any configured action.
        # A failed commit can require fresh approval, but cannot silently reuse
        # an old grant with changed credentials after a crash or restart.
        self._replace(replace(record, bindings=bindings, credential_nonces=tuple(nonces.items())))
        try:
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            raise SettingsError("Could not save the new credential approval revision safely.") from None

    def lock(self, identifier):
        with self.mutex:
            if identifier in self.opening:
                self.opening[identifier].set()
            session = self.sessions.pop(identifier, None)
        if session:
            session.worker.close()

    def requires_review(self, operation):
        return self.review_usage or operation in self.review_actions

    def set_review_usage(self, reviewed):
        with self.mutex:
            if self.review_usage != reviewed:
                self.legacy_access.write(replace(self.legacy_access.read(), review_usage=reviewed))
                self.review_usage = reviewed
                if reviewed:
                    self.generation += 1

    def set_review_action(self, operation, reviewed):
        with self.mutex:
            actions = self.review_actions | {operation} if reviewed else self.review_actions - {operation}
            if self.review_actions != actions:
                self.legacy_access.write(replace(self.legacy_access.read(), review_actions=actions - {"read_results"},
                                                review_results="read_results" in actions))
                self.review_actions = actions
                if reviewed:
                    self.generation += 1

    def token_auto_approval_enabled(self, setting):
        return not self.review_usage and self.token_auto_approval_acknowledged and getattr(self, setting)

    def guest_auto_approval_enabled(self, operation):
        return not self.review_usage and operation in self.auto_approve_guest_actions

    def scoped_auto_approval_enabled(self, operation):
        return (not self.requires_review("use_https") and not self.requires_review("read_results")
                and operation in self.auto_approve_scoped_actions)

    def set_scoped_auto_approval(self, operation, enabled):
        if operation not in SCOPED_AUTO_APPROVAL_OPTIONS:
            raise ValueError("Choose a supported scoped operation.")
        with self.mutex:
            previous = self.auto_approve_scoped_actions
            actions = previous | {operation} if enabled else previous - {operation}
            if actions != previous:
                self.legacy_access.write(replace(self.legacy_access.read(), auto_approve_scoped_actions=actions))
                self.auto_approve_scoped_actions = actions
                if not enabled:
                    self.generation += 1

    def set_guest_auto_approval(self, operation, enabled):
        if operation not in GUEST_AUTO_APPROVAL_OPTIONS:
            raise ValueError("Choose a supported guest operation.")
        with self.mutex:
            previous = self.auto_approve_guest_actions
            actions = previous | {operation} if enabled else previous - {operation}
            if previous != actions:
                self.legacy_access.write(replace(self.legacy_access.read(), auto_approve_guest_actions=actions))
                self.auto_approve_guest_actions = actions
                if not enabled:
                    self.generation += 1

    def acknowledge_token_auto_approval(self, acknowledged):
        with self.mutex:
            if self.token_auto_approval_acknowledged == acknowledged:
                return
            settings = self.legacy_access.read()
            # A fresh opt-in must not silently enable a legacy or previously disabled policy.
            reset = {key: False for key in TOKEN_AUTO_APPROVAL_OPTIONS}
            self.legacy_access.write(replace(settings, token_auto_approval_acknowledged=acknowledged, **reset))
            self.token_auto_approval_acknowledged = acknowledged
            for key in TOKEN_AUTO_APPROVAL_OPTIONS:
                setattr(self, key, False)

    def set_desktop_unlock_policy(self, setting, enabled):
        if setting not in ("unlock_on_desktop_unlock", "resume_on_desktop_unlock"):
            raise ValueError("Choose a desktop unlock setting.")
        if type(enabled) is not bool:
            raise ValueError("Choose whether to enable this desktop unlock behavior.")
        with self.mutex:
            self.legacy_access.write(replace(self.legacy_access.read(), **{setting: enabled}))
            setattr(self, setting, enabled)

    def set_token_auto_approval(self, setting, enabled):
        with self.mutex:
            if setting not in TOKEN_AUTO_APPROVAL_OPTIONS:
                raise ValueError("Choose a token auto-approval setting.")
            if enabled and not self.token_auto_approval_acknowledged:
                raise ValueError("Accept the warning before enabling token auto-approval.")
            self.legacy_access.write(replace(self.legacy_access.read(), **{setting: enabled}))
            setattr(self, setting, enabled)

    def set_token_lifespan_days(self, days):
        """Set the default life span in days for new and auto-extended tokens."""
        if type(days) is not int or not MIN_TOKEN_LIFESPAN_DAYS <= days <= MAX_TOKEN_LIFESPAN_DAYS:
            raise ValueError(f"Choose a token life span between {MIN_TOKEN_LIFESPAN_DAYS} and {MAX_TOKEN_LIFESPAN_DAYS} days.")
        with self.mutex:
            self.legacy_access.write(replace(self.legacy_access.read(), token_lifespan_days=days))
            self.token_lifespan_days = days

    def pause(self, paused=True, *, persist=True):
        with self.mutex:
            if persist:
                settings = self.legacy_access.read()
                if settings.agent_paused != paused:
                    self.legacy_access.write(replace(settings, agent_paused=paused))
            if self.paused != paused:
                self.paused = paused
                self.generation += 1

    def lock_all(self):
        with self.mutex:
            self.owner_generation += 1
            self.pause(True, persist=False)
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
            self.discovery.forget(identifier)
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
            compatible = old and old.action.scope == action.scope
            revision = old.revision if compatible else new_id()
            bindings = tuple(b for b in record.bindings if b is not old) + (Binding(action, revision),)
            self._replace(replace(record, bindings=bindings))

    def remove_binding(self, identifier, entry, action_id):
        with self.mutex:
            record = self.registrations[identifier]
            old = record.binding(entry, action_id)
            self._replace(replace(record, bindings=tuple(b for b in record.bindings if b is not old)))
