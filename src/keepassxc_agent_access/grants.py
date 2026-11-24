"""Persistent owner-approved grants, keyed by a runner credential verifier."""

from collections import Counter
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
from pathlib import Path
import re
from time import time

from .access_settings import ActionType, Destination, action_id, label, uuid_text
from .activity import Attribution, entry_target_labels, folder_label
from .protocol import ListingError
from .settings import SettingsError, write_private_json
from .workspace import new_id, ordered_groups


MAX_ITEMS = 16
MAX_PENDING = 64
LIVE_GRANT_STATES = frozenset(("pending", "active", "disabled"))
OPTIONAL_METADATA_FIELDS = ("username", "url")
CREDENTIAL_USES = {
    "local_command": "Use Password in Local Commands",
    "networked_command": "Use Password in Networked Commands",
    "https": "Use Password in HTTPS Requests",
    "https_body": "API Request Bodies (Credential Disclosure)",
    "https_results": "Read Selected HTTPS Results",
    "browser": "Use Password in Browser Sign-ins",
}
NETWORK_CREDENTIAL_USES = frozenset(("networked_command", "https", "https_body", "https_results", "browser"))
MAX_ORIGINS = 8
ENTRY_EDITS = {
    "update_entry": "Update Entry Details",
    "move_entry": "Move Entry",
    "recycle_entry": "Move Entry to Recycle Bin",
    "replace_password": "Replace Password",
}
GROUP_EDITS = {
    "create_entry": "Create Entries in Group",
    "create_group": "Create Groups in Group",
    "rename_group": "Rename Group",
    "move_group": "Move Group and Its Contents",
    "recycle_group": "Move Group and Its Contents to Recycle Bin",
    "move_into": "Move Entries or Groups into Group",
}
EDIT_PERMISSIONS = ENTRY_EDITS | GROUP_EDITS


def _edit_permissions(values, allowed):
    if not isinstance(values, (tuple, list)) or any(not isinstance(value, str) or value not in allowed for value in values):
        raise ValueError
    if len(set(values)) != len(values):
        raise ValueError
    return tuple(sorted(values))


def credential_permissions(uses, origins, *, group=None):
    """Freeze transport permissions and the destinations explicitly reviewed by the owner."""
    uses = _edit_permissions(uses, CREDENTIAL_USES)
    if "https_body" in uses and not {"https", "https_results"} & set(uses):
        raise ValueError("Credential request bodies also require HTTPS use permission.")
    if not isinstance(origins, (tuple, list)) or len(origins) > MAX_ORIGINS:
        raise ValueError("Choose at most eight approved destinations.")
    normalized = []
    for value in origins:
        destination = Destination.parse(value)
        if destination.path != "/":
            raise ValueError("Credential destinations must be HTTPS origins without a path.")
        normalized.append(destination.url)
    if len(set(normalized)) != len(normalized):
        raise ValueError("Approved destinations must be unique.")
    if group is not None and (uses or normalized):
        raise ValueError("Credential use permissions belong to individual entries.")
    if bool(set(uses) & NETWORK_CREDENTIAL_USES) != bool(normalized):
        raise ValueError("Network credential use requires explicit approved destinations.")
    return uses, tuple(sorted(normalized))


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
    uses: tuple[str, ...] = ()
    origins: tuple[str, ...] = ()

    def __post_init__(self):
        _validate_metadata(self.metadata, self.username, self.url)
        object.__setattr__(self, "edits", _edit_permissions(self.edits, GROUP_EDITS if self.group else ENTRY_EDITS))
        uses, origins = credential_permissions(self.uses, self.origins, group=self.group)
        object.__setattr__(self, "uses", uses)
        object.__setattr__(self, "origins", origins)

    @classmethod
    def parse(cls, data):
        allowed = {"vault", "entry", "label", "group", "metadata", "action", "edits", "uses", "origins", *OPTIONAL_METADATA_FIELDS}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError
        entry, name, group = data.get("entry"), data.get("label"), data.get("group")
        vault, metadata, action = data.get("vault"), data.get("metadata", False), data.get("action")
        if sum(value is not None for value in (entry, name, group)) != 1:
            raise ValueError
        if vault is None and (entry is not None or group is not None):
            raise ValueError
        edits = _edit_permissions(data.get("edits", ()), GROUP_EDITS if group is not None else ENTRY_EDITS)
        uses, origins = credential_permissions(data.get("uses", ()), data.get("origins", ()), group=group)
        if not metadata and action is None and not edits and not uses:
            raise ValueError
        if group is not None and (metadata or action is not None):
            raise ValueError
        return cls(uuid_text(vault) if vault is not None else None,
                   uuid_text(entry) if entry is not None else None,
                   label(name) if name is not None else None, metadata,
                   action_id(action) if action is not None else None,
                   username=data.get("username", False), url=data.get("url", False),
                   group=uuid_text(group) if group is not None else None, edits=edits, uses=uses, origins=origins)


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
    uses: tuple[str, ...] = ()
    origins: tuple[str, ...] = ()
    use_revision: str | None = None
    result_certificates: tuple[tuple[str, str], ...] = ()

    def __post_init__(self):
        if self.use_revision is not None and (not isinstance(self.use_revision, str)
                or not re.fullmatch(r"[0-9a-f]{64}", self.use_revision) or not self.uses):
            raise ValueError("Invalid credential-use approval revision.")
        _validate_metadata(self.metadata, self.username, self.url)
        object.__setattr__(self, "edits", _edit_permissions(self.edits, GROUP_EDITS if self.group else ENTRY_EDITS))
        uses, origins = credential_permissions(self.uses, self.origins, group=self.group)
        object.__setattr__(self, "uses", uses)
        object.__setattr__(self, "origins", origins)
        certificates = self.result_certificates
        if (not isinstance(certificates, (list, tuple)) or len(certificates) > MAX_ORIGINS
                or any(not isinstance(pair, (list, tuple)) or len(pair) != 2
                       or not isinstance(pair[0], str) or pair[0] not in origins
                       or not isinstance(pair[1], str) or not re.fullmatch(r"[0-9a-f]{64}", pair[1])
                       for pair in certificates)
                or len({pair[0] for pair in certificates}) != len(certificates)
                or certificates and ("https_results" not in uses or self.use_revision is None)):
            raise ValueError("Invalid owner-approved result certificates.")
        object.__setattr__(self, "result_certificates", tuple(sorted(tuple(pair) for pair in certificates)))

    def audit_summary(self):
        operations = [name for name in ("metadata", *OPTIONAL_METADATA_FIELDS) if getattr(self, name)]
        if self.action:
            operations.append(f"action {self.action}")
        operations.extend(self.edits)
        operations.extend(CREDENTIAL_USES[use] for use in self.uses)
        if self.origins:
            operations.append("approved destinations " + "; ".join(self.origins))
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
    released_entries: tuple[tuple[str, str], ...] = ()
    workflow: tuple[str, str] | None = None

    def __post_init__(self):
        if self.workflow is not None:
            if not isinstance(self.workflow, (list, tuple)) or len(self.workflow) != 2:
                raise ValueError("Invalid workflow token restriction.")
            identifier, digest = self.workflow
            if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise ValueError("Invalid workflow token restriction.")
            object.__setattr__(self, "workflow", (uuid_text(identifier), digest))

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
                                      superseded_changes=tuple(row.get("superseded_changes", ())),
                                      released_entries=tuple((uuid_text(vault), uuid_text(entry))
                                                             for vault, entry in row.get("released_entries", ()))))
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

    def authenticate(self, credential, uid, *, allow_workflow=False):
        identifier = self.credentials.get(verifier(credential))
        record = self.records.get(identifier)
        if record is None or record.uid != uid or record.workflow is not None and not allow_workflow:
            raise ListingError("ineligible")
        return record

    def can_issue_workflow(self, draft):
        if draft.verifier in self.credentials:
            raise ListingError("ineligible")
        if any(row.status in LIVE_GRANT_STATES and row.identity.strip().casefold() == draft.identity.casefold()
               for row in self.records.values()):
            raise ListingError("identity_in_use")
        return True

    def workflow_candidate(self, credential, uid, registration, context, item, workflow):
        if not isinstance(registration, dict) or set(registration) != {"identity", "project"}:
            raise ValueError("Provide a task identity and project.")
        identity = label(registration["identity"]).strip()
        project = label(registration["project"])
        if not identity:
            raise ValueError("Provide a readable identity for the task.")
        request = Item.parse(item)
        choices = self.choices(request)
        if len(choices) != 1:
            raise ListingError("ineligible")
        draft = Grant(new_id(), verifier(credential), uid, time(), identity, project, context,
                      (request,), status="active", scope=(choices[0].scope,), workflow=workflow)
        self.can_issue_workflow(draft)
        return draft

    def issue_workflow(self, draft):
        self.can_issue_workflow(draft)
        self._put(draft)

    @staticmethod
    def result_certificate_pins(record, vault, entry, revision, origin):
        return tuple(dict(scope.result_certificates).get(origin) for scope in record.scope
                     if (scope.vault, scope.entry, scope.use_revision) == (vault, entry, revision)
                     and "https_results" in scope.uses and origin in scope.origins)

    def result_certificate_status(self, record, vault, entry, revision, origin, fingerprint):
        pins = self.result_certificate_pins(record, vault, entry, revision, origin)
        trusted = bool(pins) and all(pin == fingerprint for pin in pins)
        first_pin = bool(pins) and not any(pins)
        changed_pin = bool(pins) and any(pins) and not trusted
        return pins, trusted, first_pin, changed_pin

    def result_certificate_auto_pin(self, record, vault, entry, revision, origin, fingerprint):
        pins, trusted, first_pin, changed_pin = self.result_certificate_status(
            record, vault, entry, revision, origin, fingerprint)
        auto_pin = (
            (first_pin and self.workspace.scoped_auto_approval_enabled("tls_first_pin"))
            or (changed_pin and self.workspace.scoped_auto_approval_enabled("tls_cert_repin"))
        )
        return pins, trusted, auto_pin

    @staticmethod
    def _scope_without_revision(scope):
        return (scope.vault, scope.entry, scope.metadata, scope.action, scope.group,
                scope.username, scope.url, scope.edits, scope.uses, scope.origins)

    @staticmethod
    def _preserve_result_certificates(previous_scope, new_scopes):
        known = {(item.vault, item.entry, origin): pin
                 for item in previous_scope for origin, pin in item.result_certificates}
        if not known:
            return new_scopes
        preserved = []
        for scope in new_scopes:
            if "https_results" in scope.uses and scope.use_revision is not None and not scope.result_certificates:
                certs = tuple((origin, known[(scope.vault, scope.entry, origin)])
                              for origin in scope.origins if (scope.vault, scope.entry, origin) in known)
                if certs:
                    scope = replace(scope, result_certificates=certs)
            preserved.append(scope)
        return tuple(preserved)

    def refresh_rotated_credential(self, token_id, vault, entry, revision):
        if revision is None or self.workspace.paused or not self.workspace.token_auto_approval_enabled("auto_approve_token_rotations"):
            return None
        with self.workspace.mutex:
            record = self.records.get(token_id)
            if (record is None or record.status != "active" or record.workflow is not None
                    or (vault, entry) in record.released_entries):
                return None
            if not any((s.vault, s.entry) == (vault, entry) and s.uses
                       and s.use_revision is not None and s.use_revision != revision for s in record.scope):
                return None
            updated_scope = tuple(
                replace(s, use_revision=revision) if (s.vault, s.entry) == (vault, entry) and s.uses else s
                for s in record.scope
            )
            updated = replace(record, scope=updated_scope)
            self._change(updated, "Approve token permissions", "Approved",
                         decision="Auto approved rotated password")
            return updated

    def result_certificate_trusted(self, record, vault, entry, revision, origin, fingerprint):
        pins = self.result_certificate_pins(record, vault, entry, revision, origin)
        return bool(pins) and all(pin == fingerprint for pin in pins)

    def trust_result_certificate(self, identifier, generation, vault, entry, revision, origin, fingerprint, expected):
        """Owner approval of a concrete workflow also pins its TLS identity to this scope.

        This is never an enrollment field. The broker records trust at verified
        dispatch after an owner review or the owner's explicit first-pin policy.
        """
        with self.workspace.mutex:
            record = self.records[identifier]
            if record.status != "active" or record.generation != generation:
                raise ListingError("revoked")
            pins = self.result_certificate_pins(record, vault, entry, revision, origin)
            if not pins or (pins != expected and any(pin != fingerprint for pin in pins)):
                # Another owner decision replaced the certificate while this
                # dialog was open. A stale approval must not restore old trust.
                raise ListingError("revoked")
            scopes = []
            matched = False
            for scope in record.scope:
                if ((scope.vault, scope.entry, scope.use_revision) == (vault, entry, revision)
                        and "https_results" in scope.uses and origin in scope.origins):
                    certificates = dict(scope.result_certificates)
                    certificates[origin] = fingerprint
                    scope = replace(scope, result_certificates=tuple(certificates.items()))
                    matched = True
                scopes.append(scope)
            if not matched:
                raise ListingError("revoked")
            self._put(replace(record, scope=tuple(scopes)))

    def enroll(self, credential, uid, payload, attribution):
        try:
            if not isinstance(payload, dict) or not {"items"} <= payload.keys() <= {"identity", "project", "items", "change_id"}:
                raise ValueError
            change_id = uuid_text(payload["change_id"]) if "change_id" in payload else None
            if change_id is None and not {"identity", "project"} <= payload.keys():
                raise ValueError
            identity = label(payload["identity"]).strip() if "identity" in payload else None
            project = label(payload["project"]) if "project" in payload else None
            if "identity" in payload and not identity:
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
        with self.workspace.mutex:
            identifier = self.credentials.get(digest)
            if identifier:
                record = self.records[identifier]
                if record.workflow is not None:
                    raise ListingError("ineligible")
                if (record.uid != uid
                        or (identity is not None and record.identity.strip() != identity)
                        or (project is not None and record.project != project)):
                    raise ListingError("ineligible")
                if change_id:
                    return self._request_change(record, change_id, items, attribution)
                if record.items != items:
                    raise ListingError("ineligible")
                return record.status
            if change_id:
                raise ListingError("ineligible")
            identity_key = identity.casefold()
            if any(row.status in LIVE_GRANT_STATES and row.identity.strip().casefold() == identity_key
                   for row in self.records.values()):
                raise ListingError("identity_in_use")
            self._check_request_capacity()
            record = Grant(new_id(), digest, uid, time(), identity, project, attribution, items)
            self._change(record, "Request token", "Pending approval")
            choices = None
            if self.workspace.token_auto_approval_enabled("auto_approve_tokens"):
                allow_uses = self.workspace.token_auto_approval_enabled("auto_approve_token_credential_uses")
                choices = self._automatic_choices(items, allow_uses=allow_uses)
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
        choices = None
        if self.workspace.token_auto_approval_enabled("auto_approve_token_changes"):
            allow_uses = self.workspace.token_auto_approval_enabled("auto_approve_token_credential_uses")
            choices = self._automatic_choices(items, allow_uses=allow_uses)
        if choices is None and self.workspace.token_auto_approval_enabled("auto_approve_token_rotations"):
            candidate = self._automatic_choices(items, allow_uses=True)
            if candidate and (Counter(self._scope_without_revision(s) for s in record.scope)
                              == Counter(self._scope_without_revision(c.scope) for c in candidate)):
                choices = candidate
        if choices and self._restores_released_entry(record, (choice.scope for choice in choices)):
            choices = None
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

    def _automatic_choices(self, items, *, allow_uses=False):
        if any(item.uses for item in items) and not allow_uses:
            return None
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
                    if len(matches) == 1 and not (matches[0]["parent"] is None and "create_entry" in item.edits):
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
                                  binding.revision if binding else None, username=item.username, url=item.url, edits=item.edits,
                                  uses=item.uses, origins=item.origins,
                                  use_revision=record.credential_revision(entry["id"]) if item.uses else None)
                    result.append(Choice(scope, record.name, (*entry["group_path"], entry["title"]),
                                         binding.action.destination if binding else None,
                                         kind=binding.action.kind if binding else None,
                                         username=entry.get("username") if item.username else None,
                                         url=entry.get("url") if item.url else None))
            return tuple(result)

    def decide(self, identifier, choices, *, change_id=None):
        with self.workspace.mutex:
            self._decide(self.records[identifier], choices, change_id=change_id)

    @staticmethod
    def _restores_released_entry(record, scopes):
        return not set(record.released_entries).isdisjoint((item.vault, item.entry) for item in scopes)

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
        if automatic and self._restores_released_entry(record, scope):
            raise ListingError("revoked")
        granted = {(item.vault, item.entry) for item in scope}
        released = tuple(entry for entry in record.released_entries if entry not in granted)
        action = "Approve token permissions" if change_id else "Approve token"
        if change_id:
            scope = self._preserve_result_certificates(record.scope, scope)
        row = replace(record, status="active", scope=scope, released_entries=released)
        if change_id:
            row = replace(row, change=replace(change, status="active"), generation=record.generation + 1)
        decision = "Auto approved" if automatic else "Approved in Access"
        self._change(row, action, "Approved", context=context, decision=decision)

    def release_entry(self, token, vault, entry, context):
        """Relinquish one entry on the calling token, including all its uses."""
        with self.workspace.mutex:
            current = self.records.get(token.id)
            if current is None or current.status != "active" or current.generation != token.generation:
                raise ListingError("ineligible")
            target = (vault, entry)
            removed = tuple(item for item in current.scope if (item.vault, item.entry) == target)
            pending = current.pending_change
            may_restore = (pending is not None and target in current.released_entries
                           and any(item.group is None and item.vault in (None, vault)
                                   and item.entry in (None, entry) for item in pending.items))
            # A repeated release can withdraw a pending restoration. A label
            # can resolve differently at review time, so match its vault too.
            if not removed and not may_restore:
                if target in current.released_entries or not self.activity.has_provision(token.id, vault, entry):
                    return {"status": "released", "cancelled_change": False}
            remaining = tuple(item for item in current.scope if (item.vault, item.entry) != target)
            change = replace(pending, status="denied") if pending else current.change
            row = replace(current, scope=remaining, generation=current.generation + 1, change=change,
                          released_entries=tuple(sorted(set(current.released_entries) | {target})))
            decision = "Released by agent"
            if pending:
                decision += " · Pending permission change canceled"
            audit_scope = removed or (Scope(vault, entry, False, None, None),)
            self._change(row, "Release entry access", "Released", target_scope=audit_scope, context=context,
                         decision=decision)
            return {"status": "released", "cancelled_change": pending is not None}

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
                row = replace(row, scope=(), items=(), change=None, superseded_changes=(), released_entries=())
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
