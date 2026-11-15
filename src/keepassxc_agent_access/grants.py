"""Persistent owner-approved grants, keyed by a runner credential verifier."""

from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
from pathlib import Path
import re
from time import time

from .access_settings import ActionType, action_id, label, uuid_text
from .activity import Attribution, entry_target_labels
from .protocol import ListingError
from .settings import SettingsError, write_private_json
from .workspace import new_id


MAX_ITEMS = 16
MAX_PENDING = 64
LIVE_GRANT_STATES = frozenset(("pending", "active", "disabled"))
OPTIONAL_METADATA_FIELDS = ("username", "url")


def verifier(credential):
    if not isinstance(credential, str) or not re.fullmatch(r"[0-9a-f]{64}", credential):
        raise ListingError("ineligible")
    return sha256(bytes.fromhex(credential)).hexdigest()


def _validate_metadata(metadata, username, url):
    if any(type(permission) is not bool for permission in (metadata, username, url)):
        raise ValueError
    if (username or url) and not metadata:
        raise ValueError


@dataclass(frozen=True)
class Item:
    vault: str | None
    entry: str | None
    label: str | None
    metadata: bool
    action: str | None
    username: bool = False
    url: bool = False

    def __post_init__(self):
        _validate_metadata(self.metadata, self.username, self.url)

    @classmethod
    def parse(cls, data):
        allowed = {"vault", "entry", "label", "metadata", "action", *OPTIONAL_METADATA_FIELDS}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError
        entry, name = data.get("entry"), data.get("label")
        vault, metadata, action = data.get("vault"), data.get("metadata", False), data.get("action")
        if (entry is None) == (name is None) or entry is not None and vault is None:
            raise ValueError
        if not metadata and action is None:
            raise ValueError
        return cls(uuid_text(vault) if vault is not None else None,
                   uuid_text(entry) if entry is not None else None,
                   label(name) if name is not None else None, metadata,
                   action_id(action) if action is not None else None,
                   username=data.get("username", False), url=data.get("url", False))


@dataclass(frozen=True)
class Scope:
    vault: str
    entry: str
    metadata: bool
    action: str | None
    revision: str | None
    username: bool = False
    url: bool = False

    def __post_init__(self):
        _validate_metadata(self.metadata, self.username, self.url)

    def audit_summary(self):
        operations = [name for name in ("metadata", *OPTIONAL_METADATA_FIELDS) if getattr(self, name)]
        if self.action:
            operations.append(f"action {self.action}")
        return f"{self.vault}/{self.entry} ({', '.join(operations)})"


@dataclass(frozen=True)
class Choice:
    scope: Scope
    vault_name: str
    path: tuple[str, ...]
    destination: str | None
    kind: ActionType | None = None
    username: str | None = None
    url: str | None = None


@dataclass(frozen=True)
class Grant:
    id: str
    verifier: str
    uid: int
    requested: float
    identity: str
    project: str
    context: Attribution
    items: tuple[Item, ...]
    status: str = "pending"
    scope: tuple[Scope, ...] = ()
    last_used: float | None = None
    generation: int = 0


class Grants:
    def __init__(self, workspace, activity):
        self.workspace = workspace
        self.activity = activity
        self.path = Path(workspace.directory) / "tokens.json"
        self.records = {}
        self.credentials = {}
        try:
            saved = json.loads(self.path.read_text())
            if saved["version"] != 1:
                raise ValueError
            for row in saved["grants"]:
                record = Grant(**dict(row, context=Attribution(**row["context"]),
                                      items=tuple(Item(**item) for item in row["items"]),
                                      scope=tuple(Scope(**scope) for scope in row["scope"])))
                if record.id in self.records or record.verifier in self.credentials:
                    raise ValueError
                self.records[record.id] = record
                self.credentials[record.verifier] = record.id
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError, KeyError):
            raise SettingsError("Access tokens could not be loaded.") from None

    def _put(self, record):
        records = {**self.records, record.id: record}
        write_private_json(self.path, {"version": 1, "grants": [asdict(r) for r in records.values()]})
        self.records = records
        self.credentials[record.verifier] = record.id

    def authenticate(self, credential, uid):
        identifier = self.credentials.get(verifier(credential))
        record = self.records.get(identifier)
        if record is None or record.uid != uid:
            raise ListingError("ineligible")
        return record

    def enroll(self, credential, uid, payload, attribution):
        try:
            if not isinstance(payload, dict) or set(payload) != {"identity", "project", "items"}:
                raise ValueError
            identity, project = label(payload["identity"]).strip(), label(payload["project"])
            if not identity:
                raise ValueError
            data = payload["items"]
            if not isinstance(data, list) or not 0 < len(data) <= MAX_ITEMS:
                raise ValueError
            items = tuple(Item.parse(item) for item in data)
            if len(set(items)) != len(items):
                raise ValueError
        except (ValueError, AttributeError, TypeError):
            raise ListingError("invalid_request") from None
        digest = verifier(credential)
        identity_key = identity.casefold()
        with self.workspace.mutex:
            identifier = self.credentials.get(digest)
            if identifier:
                record = self.records[identifier]
                if (record.uid, record.identity.strip(), record.project, record.items) != (uid, identity, project, items):
                    raise ListingError("ineligible")
                return record.status
            if any(row.status in LIVE_GRANT_STATES and row.identity.strip().casefold() == identity_key
                   for row in self.records.values()):
                raise ListingError("identity_in_use")
            if sum(row.status == "pending" for row in self.records.values()) >= MAX_PENDING:
                raise ListingError("busy")
            record = Grant(new_id(), digest, uid, time(), identity, project, attribution, items)
            self._change(record, "Request token", "Pending approval")
            return record.status

    def rows(self):
        with self.workspace.mutex:
            rows = [row for row in self.records.values() if row.status in LIVE_GRANT_STATES]
            return sorted(rows, key=lambda row: (row.status != "pending", -row.requested, row.id))

    def choices(self, item):
        with self.workspace.mutex:
            result = []
            for identifier, record in self.workspace.registrations.items():
                if item.vault and identifier != item.vault:
                    continue
                session = self.workspace.session(identifier)
                if not session:
                    continue
                for entry in session.entries:
                    if item.entry and entry["id"] != item.entry or item.label and entry["title"] != item.label:
                        continue
                    binding = record.binding(entry["id"], item.action) if item.action else None
                    if item.action and (binding is None or not binding.action.enabled):
                        continue
                    scope = Scope(identifier, entry["id"], item.metadata, item.action,
                                  binding.revision if binding else None, username=item.username, url=item.url)
                    result.append(Choice(scope, record.name, (*entry["group_path"], entry["title"]),
                                         binding.action.url if binding else None,
                                         kind=binding.action.kind if binding else None,
                                         username=entry.get("username") if item.username else None,
                                         url=entry.get("url") if item.url else None))
            return tuple(result)

    def decide(self, identifier, choices):
        with self.workspace.mutex:
            record = self.records[identifier]
            if record.status != "pending":
                raise ListingError("revoked")
            if choices is None:
                self._change(replace(record, status="denied", items=()), "Deny token", "Denied")
                return
            if len(choices) != len(record.items) or any(
                selected not in self.choices(item) for item, selected in zip(record.items, choices)
            ):
                raise ValueError("The requested scope changed. Reopen the request and review it again.")
            scope = tuple(choice.scope for choice in choices)
            self._change(replace(record, status="active", scope=scope), "Approve token", "Approved")

    def transition(self, identifier, status):
        with self.workspace.mutex:
            record = self.records[identifier]
            commands = {
                ("active", "disabled"): "Disable token",
                ("disabled", "active"): "Re-enable token",
                ("active", "removed"): "Remove token",
                ("disabled", "removed"): "Remove token",
            }
            action = commands.get((record.status, status))
            if action is None:
                raise ListingError("revoked")
            row = replace(record, status=status, generation=record.generation + 1)
            if status == "removed":
                row = replace(row, scope=(), items=())
            self._change(row, action, status.capitalize(), target_scope=record.scope)

    def _target(self, scope):
        vault_ids = {item.vault for item in scope}
        if not vault_ids:
            return {}
        if len(vault_ids) > 1:
            return {"vault": "Multiple vaults", "entry_title": "Multiple keys"}
        vault_id, = vault_ids
        vault = self.workspace.registrations.get(vault_id)
        target = {"vault_id": vault_id, "vault": vault.name if vault else None}
        entry_ids = {item.entry for item in scope}
        if len(entry_ids) > 1:
            target["entry_title"] = "Multiple keys"
            return target
        entry_id, = entry_ids
        session = self.workspace.session(vault_id)
        folder, title = entry_target_labels(session.entries, entry_id) if session else (None, None)
        target.update(entry=entry_id, folder=folder, entry_title=title)
        return target

    def _change(self, record, action, outcome, *, target_scope=None):
        scope = ", ".join(item.audit_summary() for item in record.scope)
        target = self._target(record.scope if target_scope is None else target_scope)
        event = self.activity.begin(record.uid, record.context, action, None, token=record.id,
                                    agent=record.identity, project=record.project, scope=scope or None, **target)
        if action == "Approve token":
            self.activity.authorize(event, "Approved in Access")
        self._put(record)
        self.activity.finish(event, outcome)

    def used(self, record):
        current = self.records[record.id]
        if current.generation == record.generation and current.status == "active":
            self._put(replace(current, last_used=max(time(), current.last_used or 0)))
