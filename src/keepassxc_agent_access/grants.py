"""Persistent owner-approved grants, keyed by a runner credential verifier."""

from collections import Counter
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
from math import isfinite
from pathlib import Path
import re
from time import time

from .access_settings import MAX_TOKEN_LIFESPAN_DAYS, ActionType, Destination, action_id, label, uuid_text
from .activity import Attribution, entry_target_labels, folder_label
from .protocol import ListingError
from .settings import SettingsError, write_private_json
from .workspace import new_id, ordered_groups


MAX_ITEMS = 32
MAX_PENDING = 64
LIVE_GRANT_STATES = frozenset(("pending", "active", "disabled"))
OPTIONAL_METADATA_FIELDS = ("username", "url", "notes")
CREDENTIAL_USES = {
    "local_command": "Use Password in Local Commands",
    "networked_command": "Use Password in Networked Commands",
    "https": "Use Password in HTTPS Requests",
    "https_body": "API Request Bodies (Credential Disclosure)",
    "https_results": "Read Selected HTTPS Results",
    "browser": "Use Password in Browser Sign-ins",
    "ssh_exec": "Run SSH Commands",
    "ssh_sftp": "Transfer Files Over SSH",
    "ssh_sudo": "Run Elevated SSH Commands (sudo)",
}
NETWORK_CREDENTIAL_USES = frozenset((
    "networked_command", "https", "https_body", "https_results", "browser",
    "ssh_exec", "ssh_sftp", "ssh_sudo",
))
MAX_ORIGINS = 16
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
    use_set = set(uses)
    if "https_body" in use_set and not {"https", "https_results"} & use_set:
        raise ValueError("Credential request bodies also require HTTPS use permission.")
    if "ssh_sudo" in use_set and "ssh_exec" not in use_set:
        raise ValueError("Elevated SSH commands also require SSH command execution permission.")
    if not isinstance(origins, (tuple, list)) or len(origins) > MAX_ORIGINS:
        raise ValueError(f"Choose at most {MAX_ORIGINS} approved destinations.")
    if group is not None and (uses or origins):
        raise ValueError("Credential use permissions belong to individual entries.")
    needs_ssh = bool(use_set & {"ssh_exec", "ssh_sftp", "ssh_sudo"})
    needs_https = bool(use_set & {"https", "https_body", "https_results", "browser"})
    needs_network_cmd = "networked_command" in use_set
    allowed = tuple(
        scheme for scheme, enabled in (
            ("https", needs_https or needs_network_cmd),
            ("ssh", needs_ssh),
            ("tcp", needs_network_cmd),
        ) if enabled
    )
    if not allowed and origins:
        raise ValueError("Network credential use requires explicit approved destinations.")
    normalized = []
    seen_schemes = set()
    for value in origins:
        destination = Destination.parse(value, allowed_schemes=allowed)
        if destination.scheme == "https" and destination.path != "/":
            raise ValueError("Credential destinations must be HTTPS origins without a path.")
        normalized.append(destination.url)
        seen_schemes.add(destination.scheme)
    if len(set(normalized)) != len(normalized):
        raise ValueError("Approved destinations must be unique.")
    if bool(use_set & NETWORK_CREDENTIAL_USES) != bool(normalized):
        raise ValueError("Network credential use requires explicit approved destinations.")
    if needs_ssh and "ssh" not in seen_schemes:
        raise ValueError("SSH credential uses require at least one ssh:// destination.")
    if needs_https and "https" not in seen_schemes:
        raise ValueError("HTTPS and browser credential uses require at least one https:// destination.")
    if needs_network_cmd and not (seen_schemes & {"https", "tcp"}):
        raise ValueError("Networked command use requires an https:// or tcp:// destination.")
    return uses, tuple(sorted(normalized))


def group_location(groups, identifier):
    return next((path for group, path in ordered_groups(groups) if group["id"] == identifier), ())



def verifier(credential):
    if not isinstance(credential, str) or not re.fullmatch(r"[0-9a-f]{64}", credential):
        raise ListingError("ineligible", detail="Invalid token credential.")
    return sha256(bytes.fromhex(credential)).hexdigest()


def _validate_metadata(metadata, username, url, notes=False):
    if any(type(permission) is not bool for permission in (metadata, username, url, notes)):
        raise ValueError
    if (username or url or notes) and not metadata:
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
    notes: bool = False
    group: str | None = None
    edits: tuple[str, ...] = ()
    uses: tuple[str, ...] = ()
    origins: tuple[str, ...] = ()

    def __post_init__(self):
        _validate_metadata(self.metadata, self.username, self.url, self.notes)
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
                   notes=data.get("notes", False),
                   group=uuid_text(group) if group is not None else None, edits=edits, uses=uses, origins=origins)


def _validate_origin_pins(pins, *, origins, uses, use_revision, required_uses, error_message, required_scheme=None):
    if (not isinstance(pins, (list, tuple)) or len(pins) > MAX_ORIGINS
            or any(not isinstance(pair, (list, tuple)) or len(pair) != 2
                   or not isinstance(pair[0], str) or pair[0] not in origins
                   or (required_scheme is not None and not pair[0].startswith(f"{required_scheme}://"))
                   or not isinstance(pair[1], str) or not re.fullmatch(r"[0-9a-f]{64}", pair[1])
                   for pair in pins)
            or len({pair[0] for pair in pins}) != len(pins)
            or pins and (not (set(uses) & required_uses) or use_revision is None)):
        raise ValueError(error_message)
    return tuple(sorted(tuple(pair) for pair in pins))


@dataclass(frozen=True)
class Scope:
    vault: str
    entry: str | None
    metadata: bool
    action: str | None
    revision: str | None
    username: bool = False
    url: bool = False
    notes: bool = False
    group: str | None = None
    edits: tuple[str, ...] = ()
    uses: tuple[str, ...] = ()
    origins: tuple[str, ...] = ()
    use_revision: str | None = None
    result_certificates: tuple[tuple[str, str], ...] = ()
    ssh_host_keys: tuple[tuple[str, str], ...] = ()

    def __post_init__(self):
        if self.use_revision is not None and (not isinstance(self.use_revision, str)
                or not re.fullmatch(r"[0-9a-f]{64}", self.use_revision) or not self.uses):
            raise ValueError("Invalid credential-use approval revision.")
        _validate_metadata(self.metadata, self.username, self.url, self.notes)
        object.__setattr__(self, "edits", _edit_permissions(self.edits, GROUP_EDITS if self.group else ENTRY_EDITS))
        uses, origins = credential_permissions(self.uses, self.origins, group=self.group)
        object.__setattr__(self, "uses", uses)
        object.__setattr__(self, "origins", origins)
        object.__setattr__(self, "result_certificates", _validate_origin_pins(
            self.result_certificates, origins=origins, uses=uses, use_revision=self.use_revision,
            required_uses={"https_results"}, error_message="Invalid owner-approved result certificates.",
        ))
        object.__setattr__(self, "ssh_host_keys", _validate_origin_pins(
            self.ssh_host_keys, origins=origins, uses=uses, use_revision=self.use_revision,
            required_uses={"ssh_exec", "ssh_sftp"}, required_scheme="ssh",
            error_message="Invalid owner-approved SSH host keys.",
        ))

    def audit_summary(self):
        operations = [name for name in ("metadata", "username", "url") if getattr(self, name)]
        if self.notes:
            operations.append("Entry Notes")
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
    mode: str = "replace"
    submitted_items: tuple[Item, ...] | None = None


@dataclass(frozen=True)
class ExtensionRequest:
    id: str
    requested: float
    context: Attribution
    days: int
    status: str = "pending"

    def __post_init__(self):
        if self.status not in ("pending", "active", "denied"):
            raise ValueError("Invalid extension request status.")
        if type(self.days) is not int or not 1 <= self.days <= MAX_TOKEN_LIFESPAN_DAYS:
            raise ValueError("Invalid extension duration.")


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
    revocation_generation: int | None = None
    change: PermissionChange | None = None
    superseded_changes: tuple[str, ...] = ()
    released_entries: tuple[tuple[str, str], ...] = ()
    workflow: tuple[str, str] | None = None
    expires_at: float | None = None
    extension: ExtensionRequest | None = None

    def __post_init__(self):
        if self.revocation_generation is None:
            object.__setattr__(self, "revocation_generation", self.generation)
        if self.expires_at is not None and (type(self.expires_at) not in (int, float) or not isfinite(self.expires_at)):
            raise ValueError("Invalid token expiration.")
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

    @property
    def pending_extension(self):
        return self.extension if self.extension and self.extension.status == "pending" else None


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
                    submitted = change.get("submitted_items")
                    change = PermissionChange(**dict(
                        change,
                        context=Attribution(**change["context"]),
                        items=tuple(Item(**item) for item in change["items"]),
                        **({"submitted_items": tuple(Item(**item) for item in submitted)}
                           if submitted is not None else {}),
                    ))
                ext = row.get("extension")
                if ext is not None:
                    ext = ExtensionRequest(**dict(ext, context=Attribution(**ext["context"])))
                record = Grant(**dict(row, context=Attribution(**row["context"]),
                                      items=tuple(Item(**item) for item in row["items"]),
                                      scope=tuple(Scope(**scope) for scope in row["scope"]), change=change,
                                      extension=ext,
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
        now = time()
        default_expiry = now + self.workspace.token_lifespan_days * 86400
        backfilled = False
        for identifier, record in list(self.records.items()):
            if record.status in LIVE_GRANT_STATES and record.expires_at is None:
                self.records[identifier] = replace(record, expires_at=default_expiry)
                backfilled = True
        if backfilled:
            self._save_all(self.records)
        self.prune_expired(now=now)

    def _save_all(self, records):
        write_private_json(self.path, {"version": 1, "grants": [asdict(r) for r in records.values()]})
        self.records = records
        self.credentials = {r.verifier: r.id for r in records.values()}

    def _put(self, record):
        records = {**self.records, record.id: record}
        write_private_json(self.path, {"version": 1, "grants": [asdict(r) for r in records.values()]})
        self.records = records
        self.credentials[record.verifier] = record.id

    def is_expired(self, record, now=None):
        return record.expires_at is not None and (time() if now is None else now) >= record.expires_at

    def is_active(self, record, now=None):
        return record is not None and record.status == "active" and not self.is_expired(record, now)

    def extension_target(self, record, days, now=None):
        now = time() if now is None else now
        return max(record.expires_at or now, now + days * 86400)

    def prune_expired(self, now=None, retention_days=None):
        now = time() if now is None else now
        with self.workspace.mutex:
            affected = set()
            for record in list(self.records.values()):
                if record.status in LIVE_GRANT_STATES and self.is_expired(record, now):
                    decision = "Pending token expired" if record.status == "pending" else "Token life span expired"
                    updated = replace(
                        record, status="expired", generation=record.generation + 1,
                        revocation_generation=record.revocation_generation + 1,
                        scope=(), items=(), change=None, extension=None,
                        superseded_changes=(), released_entries=(),
                    )
                    self._change(updated, "Expire token", "Expired", target_scope=record.scope, decision=decision)
                    affected.add(record.id)
            if retention_days is not None:
                cutoff = now - retention_days * 86400
                remaining = {}
                pruned = False
                for identifier, record in self.records.items():
                    anchor = record.expires_at if record.expires_at is not None else record.requested
                    if (record.status in ("expired", "removed", "denied")
                            and anchor <= cutoff
                            and (record.last_used is None or record.last_used <= cutoff)):
                        affected.add(identifier)
                        pruned = True
                    else:
                        remaining[identifier] = record
                if pruned:
                    self._save_all(remaining)
            return len(affected)

    def authenticate(self, credential, uid, *, allow_workflow=False):
        identifier = self.credentials.get(verifier(credential))
        record = self.records.get(identifier)
        if record is None or record.uid != uid or record.workflow is not None and not allow_workflow:
            raise ListingError("ineligible", detail="Token credential is unrecognized, belongs to another user, or is restricted to a workflow.")
        if record.status in LIVE_GRANT_STATES and self.is_expired(record):
            self.prune_expired()
            record = self.records.get(identifier)
            if record is None:
                raise ListingError("ineligible", detail="Token has expired and is no longer available.")
        return record

    def can_issue_workflow(self, draft):
        if draft.verifier in self.credentials:
            raise ListingError("ineligible", detail="Token credential is already registered.")
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
            raise ListingError("ineligible", detail="Workflow target entry could not be uniquely resolved.")
        self.prune_expired()
        now = time()
        draft = Grant(new_id(), verifier(credential), uid, now, identity, project, context,
                      (request,), status="active", scope=(choices[0].scope,), workflow=workflow,
                      expires_at=now + self.workspace.token_lifespan_days * 86400)
        self.can_issue_workflow(draft)
        return draft

    def issue_workflow(self, draft):
        self.can_issue_workflow(draft)
        self._put(draft)

    @staticmethod
    def _origin_pins(record, vault, entry, revision, origin, *, field, required_uses):
        return tuple(dict(getattr(scope, field)).get(origin) for scope in record.scope
                     if (scope.vault, scope.entry, scope.use_revision) == (vault, entry, revision)
                     and (required_uses & set(scope.uses)) and origin in scope.origins)

    def _pin_status(self, record, vault, entry, revision, origin, fingerprint, *, field, required_uses):
        pins = self._origin_pins(record, vault, entry, revision, origin, field=field, required_uses=required_uses)
        trusted = bool(pins) and all(pin == fingerprint for pin in pins)
        first_pin = bool(pins) and not any(pins)
        changed_pin = bool(pins) and any(pins) and not trusted
        return pins, trusted, first_pin, changed_pin

    def _pin_auto_pin(self, record, vault, entry, revision, origin, fingerprint, *,
                      field, required_uses, first_option, repin_option):
        pins, trusted, first_pin, changed_pin = self._pin_status(
            record, vault, entry, revision, origin, fingerprint, field=field, required_uses=required_uses)
        auto_pin = (
            (first_pin and self.workspace.scoped_auto_approval_enabled(first_option))
            or (changed_pin and self.workspace.scoped_auto_approval_enabled(repin_option))
        )
        return pins, trusted, auto_pin

    def _trust_origin_pin(self, identifier, generation, vault, entry, revision, origin, fingerprint, expected, *,
                          field, required_uses):
        with self.workspace.mutex:
            record = self.records[identifier]
            if not self.is_active(record) or record.generation != generation:
                raise ListingError("revoked")
            pins = self._origin_pins(record, vault, entry, revision, origin, field=field, required_uses=required_uses)
            if not pins or (pins != expected and any(pin != fingerprint for pin in pins)):
                # Another owner decision replaced the pin while this dialog
                # was open. A stale approval must not restore old trust.
                raise ListingError("revoked")
            scopes = []
            matched = False
            for scope in record.scope:
                if ((scope.vault, scope.entry, scope.use_revision) == (vault, entry, revision)
                        and (required_uses & set(scope.uses)) and origin in scope.origins):
                    entries = dict(getattr(scope, field))
                    entries[origin] = fingerprint
                    scope = replace(scope, **{field: tuple(entries.items())})
                    matched = True
                scopes.append(scope)
            if not matched:
                raise ListingError("revoked")
            self._put(replace(record, scope=tuple(scopes)))

    @classmethod
    def result_certificate_pins(cls, record, vault, entry, revision, origin):
        return cls._origin_pins(record, vault, entry, revision, origin,
                                field="result_certificates", required_uses=frozenset({"https_results"}))

    def result_certificate_status(self, record, vault, entry, revision, origin, fingerprint):
        return self._pin_status(record, vault, entry, revision, origin, fingerprint,
                                field="result_certificates", required_uses=frozenset({"https_results"}))

    def result_certificate_auto_pin(self, record, vault, entry, revision, origin, fingerprint):
        return self._pin_auto_pin(record, vault, entry, revision, origin, fingerprint,
                                  field="result_certificates", required_uses=frozenset({"https_results"}),
                                  first_option="tls_first_pin", repin_option="tls_cert_repin")

    @classmethod
    def ssh_host_key_pins(cls, record, vault, entry, revision, origin):
        return cls._origin_pins(record, vault, entry, revision, origin,
                                field="ssh_host_keys", required_uses=frozenset({"ssh_exec", "ssh_sftp"}))

    def ssh_host_key_status(self, record, vault, entry, revision, origin, fingerprint):
        return self._pin_status(record, vault, entry, revision, origin, fingerprint,
                                field="ssh_host_keys", required_uses=frozenset({"ssh_exec", "ssh_sftp"}))

    def ssh_host_key_auto_pin(self, record, vault, entry, revision, origin, fingerprint):
        return self._pin_auto_pin(record, vault, entry, revision, origin, fingerprint,
                                  field="ssh_host_keys", required_uses=frozenset({"ssh_exec", "ssh_sftp"}),
                                  first_option="ssh_first_pin", repin_option="ssh_key_repin")

    def ssh_host_key_trusted(self, record, vault, entry, revision, origin, fingerprint):
        pins = self.ssh_host_key_pins(record, vault, entry, revision, origin)
        return bool(pins) and all(pin == fingerprint for pin in pins)

    def trust_ssh_host_key(self, identifier, generation, vault, entry, revision, origin, fingerprint, expected):
        """Pin an owner-approved or first-use SSH host key fingerprint onto this scope."""
        return self._trust_origin_pin(
            identifier, generation, vault, entry, revision, origin, fingerprint, expected,
            field="ssh_host_keys", required_uses=frozenset({"ssh_exec", "ssh_sftp"}),
        )

    @staticmethod
    def _scope_without_revision(scope):
        return (scope.vault, scope.entry, scope.metadata, scope.action, scope.group,
                scope.username, scope.url, scope.notes, scope.edits, scope.uses, scope.origins)

    @staticmethod
    def _preserve_trusted_pins(previous_scope, new_scopes):
        known_certs = {(item.vault, item.entry, origin): pin
                       for item in previous_scope for origin, pin in item.result_certificates}
        known_ssh = {(item.vault, item.entry, origin): pin
                     for item in previous_scope for origin, pin in item.ssh_host_keys}
        if not known_certs and not known_ssh:
            return new_scopes
        preserved = []
        for scope in new_scopes:
            if "https_results" in scope.uses and scope.use_revision is not None and not scope.result_certificates:
                certs = tuple((origin, known_certs[(scope.vault, scope.entry, origin)])
                              for origin in scope.origins if (scope.vault, scope.entry, origin) in known_certs)
                if certs:
                    scope = replace(scope, result_certificates=certs)
            if ({"ssh_exec", "ssh_sftp"} & set(scope.uses)) and scope.use_revision is not None and not scope.ssh_host_keys:
                keys = tuple((origin, known_ssh[(scope.vault, scope.entry, origin)])
                             for origin in scope.origins if (scope.vault, scope.entry, origin) in known_ssh)
                if keys:
                    scope = replace(scope, ssh_host_keys=keys)
            preserved.append(scope)
        return tuple(preserved)

    _preserve_result_certificates = _preserve_trusted_pins

    def refresh_rotated_credential(self, token_id, vault, entry, revision):
        if revision is None or self.workspace.paused or not self.workspace.token_auto_approval_enabled("auto_approve_token_rotations"):
            return None
        with self.workspace.mutex:
            record = self.records.get(token_id)
            if (not self.is_active(record) or record.workflow is not None
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

    def is_stale(self, record):
        """Return True if any credential-use scope on an active/disabled grant is stale."""
        if record.status not in ("active", "disabled") or self.is_expired(record):
            return False
        with self.workspace.mutex:
            for scope in record.scope:
                if not scope.uses:
                    continue
                registration = self.workspace.registrations.get(scope.vault)
                if registration is None or scope.use_revision != registration.credential_revision(scope.entry):
                    return True
            return False

    def reapprove_credentials(self, identifier):
        """Re-approve current vault credential revisions for an active or disabled grant."""
        with self.workspace.mutex:
            record = self.records.get(identifier)
            if record is not None and record.status in LIVE_GRANT_STATES and self.is_expired(record):
                self.prune_expired()
                raise ListingError("revoked")
            if record is None or record.status not in ("active", "disabled"):
                raise ListingError("revoked")
            updated_scope = []
            for scope in record.scope:
                if scope.uses and (scope.vault, scope.entry) not in record.released_entries:
                    reg = self.workspace.registrations.get(scope.vault)
                    stale = reg is None or scope.use_revision != reg.credential_revision(scope.entry)
                    if reg is None or self.workspace.session(scope.vault) is None:
                        if stale:
                            raise ValueError("Unlock all affected vaults before re-approving current credentials.")
                    else:
                        rev = reg.credential_revision(scope.entry)
                        if rev is not None and rev != scope.use_revision:
                            scope = replace(scope, use_revision=rev)
                updated_scope.append(scope)
            updated_scope = tuple(updated_scope)
            if updated_scope == record.scope:
                raise ValueError("All approved credentials are already current.")
            updated = replace(record, scope=updated_scope)
            self._change(updated, "Approve token permissions", "Approved",
                         decision="Re-approved current credential in Access")
            return updated

    def result_certificate_trusted(self, record, vault, entry, revision, origin, fingerprint):
        pins = self.result_certificate_pins(record, vault, entry, revision, origin)
        return bool(pins) and all(pin == fingerprint for pin in pins)

    def trust_result_certificate(self, identifier, generation, vault, entry, revision, origin, fingerprint, expected):
        """Owner approval of a concrete workflow also pins its TLS identity to this scope.

        This is never an enrollment field. The broker records trust at verified
        dispatch after an owner review or the owner's explicit first-pin policy.
        """
        return self._trust_origin_pin(
            identifier, generation, vault, entry, revision, origin, fingerprint, expected,
            field="result_certificates", required_uses=frozenset({"https_results"}),
        )

    def enroll(self, credential, uid, payload, attribution):
        try:
            if not isinstance(payload, dict) or not {"items"} <= payload.keys() <= {"identity", "project", "items", "change_id", "mode"}:
                raise ValueError
            change_id = uuid_text(payload["change_id"]) if "change_id" in payload else None
            mode = payload.get("mode", "replace")
            if not isinstance(mode, str) or mode not in ("replace", "add"):
                raise ValueError
            if mode == "add" and change_id is None:
                raise ValueError
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
            self.prune_expired()
            identifier = self.credentials.get(digest)
            stale_record = None
            if identifier:
                record = self.records[identifier]
                if record.status in ("denied", "removed", "expired"):
                    if record.workflow is not None or record.uid != uid or change_id is not None:
                        raise ListingError("ineligible", detail="This token is closed and cannot accept permission changes.")
                    stale_record = record
                else:
                    if record.workflow is not None:
                        raise ListingError("ineligible", detail="Workflow tokens cannot be modified.")
                    if (record.uid != uid
                            or (identity is not None and record.identity.strip() != identity)
                            or (project is not None and record.project != project)):
                        raise ListingError("ineligible", detail="Token identity, project, or user does not match the existing registration.")
                    if change_id:
                        return self._request_change(record, change_id, items, attribution, mode=mode)
                    if record.items != items:
                        raise ListingError("ineligible", detail="Use change_id to update an existing token's permissions.")
                    return record.status
            if change_id:
                raise ListingError("ineligible", detail="No existing token matches this credential for a permission change.")
            identity_key = identity.casefold()
            if any(row.status in LIVE_GRANT_STATES and row.identity.strip().casefold() == identity_key
                   for row in self.records.values()):
                raise ListingError("identity_in_use")
            self._check_request_capacity()
            if stale_record is not None:
                del self.records[stale_record.id]
                del self.credentials[digest]
            now = time()
            record = Grant(new_id(), digest, uid, now, identity, project, attribution, items,
                           expires_at=now + self.workspace.token_lifespan_days * 86400)
            try:
                self._change(record, "Request token", "Pending approval")
            except BaseException:
                if stale_record is not None:
                    self.records[stale_record.id] = stale_record
                    self.credentials[digest] = stale_record.id
                raise
            choices = None
            if self.workspace.token_auto_approval_enabled("auto_approve_tokens"):
                allow_uses = self.workspace.token_auto_approval_enabled("auto_approve_token_credential_uses")
                choices = self._automatic_choices(items, allow_uses=allow_uses)
            if choices:
                self._decide(record, choices, automatic=True)
                return "active"
            return record.status

    @staticmethod
    def _merge_add_items(existing_scope, incoming_items):
        merged = []
        index_by_key = {}

        def merge_pair(base, extra):
            return Item(
                base.vault,
                base.entry,
                base.label or extra.label,
                base.metadata or extra.metadata,
                base.action or extra.action,
                username=base.username or extra.username,
                url=base.url or extra.url,
                notes=base.notes or extra.notes,
                group=base.group,
                edits=tuple(sorted(set(base.edits) | set(extra.edits))),
                uses=tuple(sorted(set(base.uses) | set(extra.uses))),
                origins=tuple(sorted(set(base.origins) | set(extra.origins))),
            )

        def add_item(item):
            if item.entry is not None or item.group is not None:
                key = ("target", item.vault, item.entry, item.group, item.action)
            else:
                key = ("label", item.vault, item.label, item.action)
            if key in index_by_key:
                pos = index_by_key[key]
                merged[pos] = merge_pair(merged[pos], item)
            else:
                index_by_key[key] = len(merged)
                merged.append(item)

        for scope in existing_scope:
            add_item(Item(
                scope.vault, scope.entry, None, scope.metadata, scope.action,
                username=scope.username, url=scope.url, notes=scope.notes,
                group=scope.group, edits=scope.edits, uses=scope.uses, origins=scope.origins,
            ))
        for item in incoming_items:
            add_item(item)
        if len(merged) > MAX_ITEMS:
            raise ValueError(f"Combined scope exceeds maximum of {MAX_ITEMS} items.")
        return tuple(merged)

    def _request_change(self, record, change_id, items, attribution, *, mode="replace"):
        if record.status != "active":
            raise ListingError("ineligible", detail=f"Token status is {record.status}; an active token is required for permission changes.")
        previous = record.change
        if previous and change_id == previous.id:
            expected_items = previous.submitted_items if previous.submitted_items is not None else previous.items
            if previous.mode != mode or expected_items != items:
                raise ListingError("invalid_request")
            return previous.status
        if change_id in record.superseded_changes:
            raise ListingError("revoked")
        if record.pending_change:
            raise ListingError("token_change_pending")
        try:
            effective_items = self._merge_add_items(record.scope, items) if mode == "add" else items
        except ValueError as error:
            raise ListingError("invalid_request", detail=str(error) or None) from None
        self._check_request_capacity()
        change = PermissionChange(change_id, time(), attribution, effective_items, mode=mode, submitted_items=items)
        superseded = (*record.superseded_changes, previous.id) if previous else record.superseded_changes
        row = replace(record, change=change, superseded_changes=superseded)
        choices = None
        if self.workspace.token_auto_approval_enabled("auto_approve_token_changes"):
            allow_uses = self.workspace.token_auto_approval_enabled("auto_approve_token_credential_uses")
            choices = self._automatic_choices(effective_items, allow_uses=allow_uses)
        if choices is None and self.workspace.token_auto_approval_enabled("auto_approve_token_rotations"):
            candidate = self._automatic_choices(effective_items, allow_uses=True)
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
        pending = sum(row.status == "pending" or bool(row.pending_change) or bool(row.pending_extension)
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
            if any(row.status in LIVE_GRANT_STATES and self.is_expired(row) for row in self.records.values()):
                self.prune_expired()
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
                                  binding.revision if binding else None, username=item.username, url=item.url,
                                  notes=item.notes, edits=item.edits,
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

    @staticmethod
    def _scope_covers(old_scopes, new_scopes):
        def covers(old, new):
            return (
                new.vault == old.vault
                and new.entry == old.entry
                and new.group == old.group
                and new.action == old.action
                and (old.action is None or new.revision == old.revision)
                and (not old.metadata or new.metadata)
                and (not old.username or new.username)
                and (not old.url or new.url)
                and (not old.notes or new.notes)
                and set(old.edits) <= set(new.edits)
                and set(old.uses) <= set(new.uses)
                and (not old.uses or new.use_revision == old.use_revision)
                and set(old.origins) <= set(new.origins)
                and set(old.result_certificates) <= set(new.result_certificates)
                and set(old.ssh_host_keys) <= set(new.ssh_host_keys)
            )

        return all(any(covers(old, new) for new in new_scopes) for old in old_scopes)

    def _decide(self, record, choices, *, change_id=None, automatic=False):
        if record.status in LIVE_GRANT_STATES and self.is_expired(record):
            self.prune_expired()
            raise ListingError("revoked")
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
                self._change(replace(record, status="denied", items=(), expires_at=None), "Deny token", "Denied")
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
        additive = False
        if change_id:
            scope = self._preserve_trusted_pins(record.scope, scope)
            additive = self._scope_covers(record.scope, scope)
        row = replace(record, status="active", scope=scope, released_entries=released)
        if change_id:
            rev_gen = record.revocation_generation if additive else record.revocation_generation + 1
            row = replace(row, change=replace(change, status="active"),
                          generation=record.generation + 1, revocation_generation=rev_gen)
        else:
            now = time()
            row = replace(row, expires_at=max(record.expires_at or now,
                                              now + self.workspace.token_lifespan_days * 86400))
        decision = "Auto approved" if automatic else "Approved in Access"
        self._change(row, action, "Approved", context=context, decision=decision)

    def release_entry(self, token, vault, entry, context):
        """Relinquish one entry on the calling token, including all its uses."""
        with self.workspace.mutex:
            current = self.records.get(token.id)
            if current is not None and current.status in LIVE_GRANT_STATES and self.is_expired(current):
                self.prune_expired()
                raise ListingError("ineligible", detail="Token has expired.")
            if not self.is_active(current) or current.generation != token.generation:
                raise ListingError("ineligible", detail="An active, current token is required to release an entry.")
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
            row = replace(current, scope=remaining, generation=current.generation + 1,
                          revocation_generation=current.revocation_generation + 1, change=change,
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
            record = self.records.get(identifier)
            if record is None:
                raise ListingError("revoked")
            if record.status in LIVE_GRANT_STATES and self.is_expired(record):
                self.prune_expired()
                raise ListingError("revoked")
            commands = {
                ("active", "disabled"): "Disable token",
                ("disabled", "active"): "Re-enable token",
                ("active", "removed"): "Remove token",
                ("disabled", "removed"): "Remove token",
            }
            action = commands.get((record.status, status))
            if action is None:
                raise ListingError("revoked")
            row = replace(record, status=status, generation=record.generation + 1,
                          revocation_generation=record.revocation_generation + 1)
            if row.pending_change:
                row = replace(row, change=replace(row.change, status="denied"))
            if status == "disabled" and row.pending_extension:
                row = replace(row, extension=replace(row.extension, status="denied"))
            if status == "removed":
                row = replace(row, scope=(), items=(), change=None, extension=None, expires_at=None,
                              superseded_changes=(), released_entries=())
            self._change(row, action, status.capitalize(), target_scope=record.scope)

    def extend(self, identifier, days=None, *, decision="Extended in Access"):
        """Reset an active or disabled non-expired token's life span directly for the owner."""
        if days is not None and (type(days) is not int or not 1 <= days <= MAX_TOKEN_LIFESPAN_DAYS):
            raise ValueError(f"Choose an extension between 1 and {MAX_TOKEN_LIFESPAN_DAYS} days.")
        with self.workspace.mutex:
            record = self.records.get(identifier)
            if record is None:
                raise ListingError("revoked")
            if record.status in LIVE_GRANT_STATES and self.is_expired(record):
                self.prune_expired()
                raise ListingError("revoked")
            if record.status not in ("active", "disabled"):
                raise ListingError("revoked")
            now = time()
            target_days = self.workspace.token_lifespan_days if days is None else days
            new_exp = now + target_days * 86400
            ext = replace(record.pending_extension, status="active") if record.pending_extension else record.extension
            updated = replace(record, expires_at=new_exp, extension=ext)
            self._change(updated, "Extend token", "Approved", decision=decision)
            return updated

    def request_extension(self, token_id, days, attribution, *, extension_id=None):
        """Record or auto-approve an agent life span extension request."""
        requested_days = self.workspace.token_lifespan_days if days is None else days
        if type(requested_days) is not int or not 1 <= requested_days <= MAX_TOKEN_LIFESPAN_DAYS:
            raise ListingError("invalid_request")
        if extension_id is not None:
            try:
                extension_id = uuid_text(extension_id)
            except (AttributeError, TypeError, ValueError):
                raise ListingError("invalid_request") from None
        with self.workspace.mutex:
            record = self.records.get(token_id)
            if record is None:
                raise ListingError("ineligible", detail="Token credential is unrecognized.")
            if record.status in LIVE_GRANT_STATES and self.is_expired(record):
                self.prune_expired()
                raise ListingError("ineligible", detail="Token has expired.")
            if record.workflow is not None or not self.is_active(record):
                detail = "Workflow tokens cannot be extended." if record.workflow is not None else f"Cannot extend token with status {record.status}."
                raise ListingError("ineligible", detail=detail)
            if extension_id is not None:
                if record.extension and record.extension.id == extension_id:
                    if record.extension.days != requested_days:
                        raise ListingError("invalid_request")
                    return record.extension.status, record
                if record.pending_extension:
                    raise ListingError("token_extension_pending")
            elif record.pending_extension:
                if record.pending_extension.days == requested_days:
                    return "pending", record
                raise ListingError("token_extension_pending")
            now = time()
            ext_id = extension_id or new_id()
            auto = (not self.workspace.paused
                    and self.workspace.token_auto_approval_enabled("auto_approve_token_extensions")
                    and requested_days <= self.workspace.token_lifespan_days)
            if auto:
                new_exp = self.extension_target(record, requested_days, now)
                ext = ExtensionRequest(ext_id, now, attribution, requested_days, status="active")
                updated = replace(record, expires_at=new_exp, extension=ext)
                self._change(updated, "Extend token", "Approved", context=attribution,
                             decision=f"Auto approved ({requested_days}d)")
                return "active", updated
            self._check_request_capacity()
            ext = ExtensionRequest(ext_id, now, attribution, requested_days, status="pending")
            updated = replace(record, extension=ext)
            self._change(updated, "Request token extension", "Pending approval", context=attribution)
            return "pending", updated

    def decide_extension(self, identifier, extension_id, approved):
        """Approve or deny a pending agent life span extension request."""
        with self.workspace.mutex:
            record = self.records.get(identifier)
            if record is None:
                raise ListingError("revoked")
            if record.status in LIVE_GRANT_STATES and self.is_expired(record):
                self.prune_expired()
                raise ListingError("revoked")
            ext = record.pending_extension
            if record.status not in ("active", "disabled") or ext is None or ext.id != extension_id:
                raise ListingError("revoked")
            if not approved:
                updated = replace(record, extension=replace(ext, status="denied"))
                self._change(updated, "Deny token extension", "Denied", context=ext.context)
                return updated
            now = time()
            new_exp = self.extension_target(record, ext.days, now)
            updated = replace(record, expires_at=new_exp, extension=replace(ext, status="active"))
            self._change(updated, "Extend token", "Approved", context=ext.context,
                         decision=f"Approved in Access ({ext.days}d)")
            return updated

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
        if current.generation == record.generation and self.is_active(current):
            self._put(replace(current, last_used=max(time(), current.last_used or 0)))
