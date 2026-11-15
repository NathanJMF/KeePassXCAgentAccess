"""Persistent owner-approved grants, keyed by a runner credential verifier."""

from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
from pathlib import Path
import re
from time import time

from .access_settings import ActionType, action_id, label, uuid_text
from .activity import Attribution, entry_target_labels, folder_label
from .protocol import ListingError
from .settings import SettingsError, write_private_json
from .workspace import new_id, ordered_groups


MAX_ITEMS = 16
MAX_PENDING = 64
LIVE_GRANT_STATES = frozenset(("pending", "active", "disabled"))
OPTIONAL_METADATA_FIELDS = ("username", "url")
ENTRY_EDITS = {
    "update_entry": "Update entry details",
    "move_entry": "Move entry",
    "recycle_entry": "Move entry to recycle bin",
    "replace_password": "Replace password",
}
GROUP_EDITS = {
    "create_entry": "Create entries in group",
    "create_group": "Create groups in group",
    "rename_group": "Rename group",
    "move_group": "Move group and its contents",
    "recycle_group": "Move group and its contents to recycle bin",
    "move_into": "Move entries or groups into group",
}
EDIT_PERMISSIONS = ENTRY_EDITS | GROUP_EDITS


def _edit_permissions(values, allowed):
    if not isinstance(values, (tuple, list)) or any(not isinstance(value, str) or value not in allowed for value in values):
        raise ValueError
    if len(set(values)) != len(values):
        raise ValueError
    return tuple(sorted(values))


def group_location(groups, identifier):
    return next((path for group, path in ordered_groups(groups) if group["id"] == identifier), ())



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
    group: str | None = None
    edits: tuple[str, ...] = ()

    def __post_init__(self):
        _validate_metadata(self.metadata, self.username, self.url)
        object.__setattr__(self, "edits", _edit_permissions(self.edits, GROUP_EDITS if self.group else ENTRY_EDITS))

    @classmethod
    def parse(cls, data):
        allowed = {"vault", "entry", "label", "group", "metadata", "action", "edits", *OPTIONAL_METADATA_FIELDS}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError
        entry, name, group = data.get("entry"), data.get("label"), data.get("group")
        vault, metadata, action = data.get("vault"), data.get("metadata", False), data.get("action")
        if sum(value is not None for value in (entry, name, group)) != 1:
            raise ValueError
        if vault is None and (entry is not None or group is not None):
            raise ValueError
        edits = _edit_permissions(data.get("edits", ()), GROUP_EDITS if group is not None else ENTRY_EDITS)
        if not metadata and action is None and not edits:
            raise ValueError
        if group is not None and (metadata or action is not None):
            raise ValueError
        return cls(uuid_text(vault) if vault is not None else None,
                   uuid_text(entry) if entry is not None else None,
                   label(name) if name is not None else None, metadata,
                   action_id(action) if action is not None else None,
                   username=data.get("username", False), url=data.get("url", False),
                   group=uuid_text(group) if group is not None else None, edits=edits)


@dataclass(frozen=True)
class Scope:
    vault: str
    entry: str | None
    metadata: bool
    action: str | None
    revision: str | None
    username: bool = False
    url: bool = False
    group: str | None = None
    edits: tuple[str, ...] = ()

    def __post_init__(self):
        _validate_metadata(self.metadata, self.username, self.url)
        object.__setattr__(self, "edits", _edit_permissions(self.edits, GROUP_EDITS if self.group else ENTRY_EDITS))

    def audit_summary(self):
        operations = [name for name in ("metadata", *OPTIONAL_METADATA_FIELDS) if getattr(self, name)]
        if self.action:
            operations.append(f"action {self.action}")
        operations.extend(self.edits)
        resource = self.entry if self.group is None else f"group {self.group}"
        return f"{self.vault}/{resource} ({', '.join(operations)})"


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
class PermissionChange:
    id: str
    requested: float
    context: Attribution
    items: tuple[Item, ...]
    status: str = "pending"


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
    change: PermissionChange | None = None
    superseded_changes: tuple[str, ...] = ()

    @property
    def pending_change(self):
        return self.change if self.change and self.change.status == "pending" else None


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
                change = row.get("change")
                if change is not None:
                    change = PermissionChange(**dict(change, context=Attribution(**change["context"]),
                                                     items=tuple(Item(**item) for item in change["items"])))
                record = Grant(**dict(row, context=Attribution(**row["context"]),
                                      items=tuple(Item(**item) for item in row["items"]),
                                      scope=tuple(Scope(**scope) for scope in row["scope"]), change=change,
                                      superseded_changes=tuple(row.get("superseded_changes", ()))))
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
            required = {"identity", "project", "items"}
            if not isinstance(payload, dict) or not required <= payload.keys() <= required | {"change_id"}:
                raise ValueError
            change_id = uuid_text(payload["change_id"]) if "change_id" in payload else None
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
                if (record.uid, record.identity.strip(), record.project) != (uid, identity, project):
                    raise ListingError("ineligible")
                if change_id:
                    return self._request_change(record, change_id, items, attribution)
                if record.items != items:
                    raise ListingError("ineligible")
                return record.status
            if change_id:
                raise ListingError("ineligible")
            if any(row.status in LIVE_GRANT_STATES and row.identity.strip().casefold() == identity_key
                   for row in self.records.values()):
                raise ListingError("identity_in_use")
            self._check_request_capacity()
            record = Grant(new_id(), digest, uid, time(), identity, project, attribution, items)
            self._change(record, "Request token", "Pending approval")
            choices = self._automatic_choices(items) if self.workspace.auto_approve_tokens else None
            if choices:
                self._decide(record, choices, automatic=True)
                return "active"
            return record.status

    def _request_change(self, record, change_id, items, attribution):
        if record.status != "active":
            raise ListingError("ineligible")
        previous = record.change
        if previous and change_id == previous.id:
            if previous.items != items:
                raise ListingError("invalid_request")
            return previous.status
        if change_id in record.superseded_changes:
            raise ListingError("revoked")
        if record.pending_change:
            raise ListingError("token_change_pending")
        self._check_request_capacity()
        change = PermissionChange(change_id, time(), attribution, items)
        superseded = (*record.superseded_changes, previous.id) if previous else record.superseded_changes
        row = replace(record, change=change, superseded_changes=superseded)
        choices = self._automatic_choices(items) if self.workspace.auto_approve_token_changes else None
        self._change(row, "Request token permissions", "Pending approval", context=attribution,
                     target_scope=tuple(choice.scope for choice in choices) if choices else ())
        if choices:
            self._decide(row, choices, change_id=change_id, automatic=True)
            return "active"
        return change.status

    def _check_request_capacity(self):
        pending = sum(row.status == "pending" or bool(row.pending_change)
                      for row in self.records.values())
        if pending >= MAX_PENDING:
            raise ListingError("busy")

    def _automatic_choices(self, items):
        # A locked vault can hide another match for an unqualified label.
        for item in items:
            if item.vault is None and any(self.workspace.session(vault) is None
                                          for vault in self.workspace.registrations):
                return None
        matches = [self.choices(item) for item in items]
        return [choices[0] for choices in matches] if all(len(choices) == 1 for choices in matches) else None

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
                if item.group is not None:
                    matches = [group for group in session.groups if group["id"] == item.group]
                    if len(matches) == 1:
                        scope = Scope(identifier, None, False, None, None, group=item.group, edits=item.edits)
                        path = group_location(session.groups, item.group) or (matches[0]["name"] or "Root",)
                        result.append(Choice(scope, record.name, path, None))
                    continue
                for entry in session.entries:
                    if item.entry and entry["id"] != item.entry or item.label and entry["title"] != item.label:
                        continue
                    binding = record.binding(entry["id"], item.action) if item.action else None
                    if item.action and (binding is None or not binding.action.enabled):
                        continue
                    scope = Scope(identifier, entry["id"], item.metadata, item.action,
                                  binding.revision if binding else None, username=item.username, url=item.url, edits=item.edits)
                    result.append(Choice(scope, record.name, (*entry["group_path"], entry["title"]),
                                         binding.action.url if binding else None,
                                         kind=binding.action.kind if binding else None,
                                         username=entry.get("username") if item.username else None,
                                         url=entry.get("url") if item.url else None))
            return tuple(result)

    def decide(self, identifier, choices, *, change_id=None):
        with self.workspace.mutex:
            self._decide(self.records[identifier], choices, change_id=change_id)

    def _decide(self, record, choices, *, change_id=None, automatic=False):
        if change_id:
            change = record.change
            if record.status != "active" or change is None or (change.id, change.status) != (change_id, "pending"):
                raise ListingError("revoked")
            items, context = change.items, change.context
        else:
            if record.status != "pending":
                raise ListingError("revoked")
            items, context = record.items, record.context
        if choices is None:
            if change_id:
                self._change(replace(record, change=replace(change, status="denied")),
                             "Deny token permissions", "Denied", context=context, target_scope=())
            else:
                self._change(replace(record, status="denied", items=()), "Deny token", "Denied")
            return
        if len(choices) != len(items) or any(
            selected not in self.choices(item) for item, selected in zip(items, choices)
        ):
            raise ValueError("The requested scope changed. Reopen the request and review it again.")
        scope = tuple(choice.scope for choice in choices)
        action = "Approve token permissions" if change_id else "Approve token"
        row = replace(record, status="active", scope=scope)
        if change_id:
            row = replace(row, change=replace(change, status="active"), generation=record.generation + 1)
        decision = "Auto approved" if automatic else "Approved in Access"
        self._change(row, action, "Approved", context=context, decision=decision)

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
            if row.pending_change:
                row = replace(row, change=replace(row.change, status="denied"))
            if status == "removed":
                row = replace(row, scope=(), items=(), change=None, superseded_changes=())
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
        resources = {(item.entry, item.group) for item in scope}
        if len(resources) > 1:
            target["entry_title"] = "Multiple resources" if any(group for _, group in resources) else "Multiple keys"
            return target
        (entry_id, group_id), = resources
        session = self.workspace.session(vault_id)
        if group_id is not None:
            target.update(group_id=group_id, folder=folder_label(group_location(session.groups, group_id)) if session else None)
        else:
            folder, title = entry_target_labels(session.entries, entry_id) if session else (None, None)
            target.update(entry=entry_id, folder=folder, entry_title=title)
        return target

    def _change(self, record, action, outcome, *, target_scope=None, context=None, decision=None):
        scope_items = record.scope if target_scope is None else target_scope
        scope = ", ".join(item.audit_summary() for item in scope_items)
        target = self._target(scope_items)
        event = self.activity.begin(record.uid, context or record.context, action, None, token=record.id,
                                    agent=record.identity, project=record.project, scope=scope or None, **target)
        if decision:
            self.activity.authorize(event, decision)
        self._put(record)
        self.activity.finish(event, outcome)

    def used(self, record):
        current = self.records[record.id]
        if current.generation == record.generation and current.status == "active":
            self._put(replace(current, last_used=max(time(), current.last_used or 0)))
