"""Persistent owner-approved grants, keyed by a runner credential verifier."""

from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
from pathlib import Path
import re
from time import time

from .access_settings import action_id, label, uuid_text
from .activity import Attribution
from .protocol import ListingError
from .settings import SettingsError, write_private_json
from .workspace import new_id


MAX_ITEMS = 16
MAX_PENDING = 64


def verifier(credential):
    if not isinstance(credential, str) or not re.fullmatch(r"[0-9a-f]{64}", credential):
        raise ListingError("ineligible")
    return sha256(bytes.fromhex(credential)).hexdigest()


@dataclass(frozen=True)
class Item:
    vault: str | None
    entry: str | None
    label: str | None
    metadata: bool
    action: str | None

    @classmethod
    def parse(cls, data):
        if not isinstance(data, dict) or set(data) - {"vault", "entry", "label", "metadata", "action"}:
            raise ValueError
        entry, name = data.get("entry"), data.get("label")
        vault, metadata, action = data.get("vault"), data.get("metadata", False), data.get("action")
        if (entry is None) == (name is None) or entry is not None and vault is None:
            raise ValueError
        if type(metadata) is not bool or not (metadata or action is not None):
            raise ValueError
        return cls(uuid_text(vault) if vault is not None else None,
                   uuid_text(entry) if entry is not None else None,
                   label(name) if name is not None else None, metadata,
                   action_id(action) if action is not None else None)


@dataclass(frozen=True)
class Scope:
    vault: str
    entry: str
    metadata: bool
    action: str | None
    revision: str | None


@dataclass(frozen=True)
class Choice:
    scope: Scope
    vault_name: str
    path: tuple[str, ...]
    destination: str | None


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
            identity, project = label(payload["identity"]), label(payload["project"])
            data = payload["items"]
            if not isinstance(data, list) or not 0 < len(data) <= MAX_ITEMS:
                raise ValueError
            items = tuple(Item.parse(item) for item in data)
            if len(set(items)) != len(items):
                raise ValueError
        except (ValueError, AttributeError, TypeError):
            raise ListingError("invalid_request") from None
        digest = verifier(credential)
        with self.workspace.mutex:
            identifier = self.credentials.get(digest)
            if identifier:
                record = self.records[identifier]
                if (record.uid, record.identity, record.project, record.items) != (uid, identity, project, items):
                    raise ListingError("ineligible")
                return record.status
            if sum(row.status == "pending" for row in self.records.values()) >= MAX_PENDING:
                raise ListingError("busy")
            record = Grant(new_id(), digest, uid, time(), identity, project, attribution, items)
            self._change(record, "Request token", "Pending approval")
            return record.status

    def rows(self):
        with self.workspace.mutex:
            rows = [row for row in self.records.values() if row.status in ("pending", "active", "disabled")]
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
                    result.append(Choice(Scope(identifier, entry["id"], item.metadata, item.action,
                                               binding.revision if binding else None),
                                         record.name, (*entry["group_path"], entry["title"]),
                                         binding.action.url if binding else None))
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
            self._change(row, action, status.capitalize())

    def _change(self, record, action, outcome):
        scope = ", ".join(
            f"{item.vault}/{item.entry} ({', '.join(op for op in ('metadata' if item.metadata else None, item.action) if op)})"
            for item in record.scope
        )
        event = self.activity.begin(record.uid, record.context, action, None, token=record.id,
                                    agent=record.identity, project=record.project, scope=scope or None)
        if action == "Approve token":
            self.activity.authorize(event, "Approved in Access")
        self._put(record)
        self.activity.finish(event, outcome)

    def used(self, record):
        current = self.records[record.id]
        if current.generation == record.generation and current.status == "active":
            self._put(replace(current, last_used=max(time(), current.last_used or 0)))
