"""One-time agent edits with durable approval and an owner-only review."""

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from time import time

from .access_settings import uuid_text
from .activity import ActivityError, Attribution, entry_label, folder_label
from .protocol import ListingError, decode, encode
from .settings import SettingsError
from .vault import VaultChanged, VaultError
from .vault_edits import EditError, edit_text


@dataclass(frozen=True)
class _EditKind:
    title: str
    target: str | None
    parent: bool = False
    fields: tuple[str, ...] = ()
    required: tuple[str, ...] = ()


_ENTRY_FIELDS = ("title", "username", "url")
_KINDS = {
    "create_entry": _EditKind("Create entry", None, True, _ENTRY_FIELDS, ("title",)),
    "update_entry": _EditKind("Update entry", "entry", False, _ENTRY_FIELDS),
    "create_group": _EditKind("Create group", None, True, ("name",), ("name",)),
    "rename_group": _EditKind("Rename group", "group", False, ("name",), ("name",)),
    "move_entry": _EditKind("Move entry", "entry", True),
    "move_group": _EditKind("Move group", "group", True),
    "recycle_entry": _EditKind("Recycle entry", "entry"),
    "recycle_group": _EditKind("Recycle group", "group"),
    "replace_password": _EditKind("Replace password", "entry"),
}
_MAX_PENDING = 64
_MAX_PER_TOKEN = 8


@dataclass(frozen=True)
class EditRequest:
    id: str
    operation: str
    vault: str
    entry: str | None = None
    group: str | None = None
    parent: str | None = None
    fields: tuple[tuple[str, str], ...] = ()
    password_source: str | None = None

    @classmethod
    def parse(cls, payload):
        try:
            if not isinstance(payload, dict):
                raise ValueError
            operation = payload["operation"]
            kind = _KINDS[operation]
            required = {"id", "operation", "vault"}
            if kind.target:
                required.add(kind.target)
            if kind.parent:
                required.add("parent")
            if operation == "replace_password":
                required.add("password_source")
            if not required <= payload.keys() or payload.keys() - (required | {"fields"}):
                raise ValueError
            fields = payload.get("fields", {})
            if (not isinstance(fields, dict) or fields.keys() - set(kind.fields)
                    or not set(kind.required) <= fields.keys() or operation == "update_entry" and not fields):
                raise ValueError
            source = payload.get("password_source")
            if operation == "replace_password" and source not in ("generate", "owner"):
                raise ValueError
            return cls(uuid_text(payload["id"]), operation, uuid_text(payload["vault"]),
                       entry=uuid_text(payload["entry"]) if kind.target == "entry" else None,
                       group=uuid_text(payload["group"]) if kind.target == "group" else None,
                       parent=uuid_text(payload["parent"]) if kind.parent else None,
                       fields=tuple((name, edit_text(fields[name], required=name in ("title", "name")))
                                    for name in kind.fields if name in fields),
                       password_source=source)
        except (AttributeError, EditError, KeyError, TypeError, ValueError):
            raise ListingError("invalid_request") from None

    @property
    def title(self):
        return _KINDS[self.operation].title


@dataclass(frozen=True)
class EditRecord:
    token_id: str
    request: EditRequest
    requested: float
    identity: str
    project: str
    status: str
    token_generation: int
    context: Attribution | None = None

    @property
    def id(self):
        return self.request.id


@dataclass(frozen=True)
class EditPreview:
    record: EditRecord
    vault_name: str
    target_path: tuple[str, ...]
    destination_path: tuple[str, ...] | None
    old: tuple[tuple[str, str], ...]
    new: tuple[tuple[str, str], ...]
    group_count: int
    entry_count: int
    _session: object = field(repr=False, compare=False)
    _change: str = field(repr=False)
    _values: tuple = field(repr=False)

    @property
    def password_source(self):
        return self.record.request.password_source


_SCHEMA = """
CREATE TABLE IF NOT EXISTS edit_requests (
    token TEXT NOT NULL,
    id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    digest TEXT NOT NULL,
    payload BLOB,
    context BLOB,
    requested REAL NOT NULL,
    identity TEXT NOT NULL,
    project TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT,
    PRIMARY KEY (token, id)
);
CREATE INDEX IF NOT EXISTS edit_requests_status ON edit_requests(status, requested);
"""


class EditRequests:
    def __init__(self, workspace, grants, activity):
        self.workspace = workspace
        self.grants = grants
        self.activity = activity
        with self.activity.connection() as db:
            db.executescript(_SCHEMA)
            if "context" not in {column["name"] for column in db.execute("PRAGMA table_info(edit_requests)")}:
                db.execute("ALTER TABLE edit_requests ADD COLUMN context BLOB")
            db.execute("""
                UPDATE edit_requests SET payload=NULL, context=NULL, status=CASE
                    WHEN status='dispatched' THEN 'interrupted' ELSE 'stale' END
                WHERE status IN ('applying', 'dispatched')
            """)

    @staticmethod
    def _response(row):
        status = "applying" if row["status"] == "dispatched" else row["status"]
        response = {"id": row["id"], "status": status}
        if row["result"] is not None:
            response["result"] = row["result"]
        return response

    @staticmethod
    def _record(row):
        payload = decode(row["payload"])
        payload["fields"] = tuple(tuple(pair) for pair in payload["fields"])
        context = Attribution(**decode(row["context"])) if row["context"] else None
        return EditRecord(row["token"], EditRequest(**payload), row["requested"], row["identity"],
                          row["project"], EditRequests._response(row)["status"], row["generation"], context)

    @staticmethod
    def _get(db, token_id, request_id):
        return db.execute("SELECT * FROM edit_requests WHERE token=? AND id=?",
                          (token_id, request_id)).fetchone()

    def _active(self, token):
        current = self.grants.records.get(token.id)
        return current is not None and current.status == "active" and current.generation == token.generation

    def _status(self, record, old, new, result=None):
        with self.activity.connection() as db:
            changed = db.execute("""
                UPDATE edit_requests SET status=?, result=?,
                    payload=CASE WHEN ? IN ('applying', 'dispatched') THEN payload ELSE NULL END,
                    context=CASE WHEN ? IN ('applying', 'dispatched') THEN context ELSE NULL END
                WHERE token=? AND id=? AND status=?
            """, (new, result, new, new, record.token_id, record.id, old)).rowcount
            if changed != 1:
                raise ActivityError()

    def _event(self, token, request, label, context=None, preview=None):
        scope = [f"Edit request {request.id}"]
        if request.group:
            scope.append(f"Group {request.group}")
        if request.parent:
            scope.append(f"Destination group {request.parent}")
        if request.fields:
            scope.append("Fields " + ", ".join(name for name, _ in request.fields))
        if request.password_source:
            scope.append(f"Replacement source {request.password_source}")
        registration = self.workspace.registrations.get(request.vault)
        vault_name = preview.vault_name if preview else registration.name if registration else None
        folder, title, destination = None, None, None
        group_id = request.group or (request.parent if request.entry is None else None)
        if preview is not None:
            folder, title, destination = _reviewed_target(preview)
            if request.entry:
                group_id = _unique(preview._session.entries, request.entry)["group"]
        return self.activity.begin(
            token.uid, context or token.context, f"{label} · {request.title}", destination, entry=request.entry,
            vault=vault_name, vault_id=request.vault,
            token=token.id, agent=token.identity, project=token.project, scope=" · ".join(scope),
            folder=folder, entry_title=title, group_id=group_id, edit_request_id=request.id,
        )

    def _stale(self, record, token, preview=None, *, label="Apply edit"):
        event = (self._event(token, record.request, label, record.context, preview)
                 if token is not None else None)
        self._status(record, "pending", "stale")
        if event is not None:
            self.activity.finish(event, "Stale")

    def _discard_stale_proposals(self):
        with self.activity.connection() as db:
            rows = [self._record(row) for row in db.execute(
                "SELECT * FROM edit_requests WHERE status='pending'")]
        for record in rows:
            current = self.grants.records.get(record.token_id)
            if current is None or current.generation != record.token_generation or current.status != "active":
                self._stale(record, current, label="Cancel edit")

    def submit(self, token, payload, context=None):
        request = EditRequest.parse(payload)
        frame = encode(asdict(request))
        digest = sha256(frame).hexdigest()
        attribution = encode(asdict(context or token.context))
        with self.workspace.mutex:
            if not self._active(token):
                raise ListingError("ineligible")
            self._discard_stale_proposals()
            with self.activity.connection() as db:
                previous = self._get(db, token.id, request.id)
                if previous:
                    if previous["digest"] != digest:
                        raise ListingError("invalid_request")
                    return self._response(previous)
                count, own = db.execute("""
                    SELECT count(*), count(CASE WHEN token=? THEN 1 END)
                    FROM edit_requests WHERE status IN ('pending', 'applying', 'dispatched')
                """, (token.id,)).fetchone()
                if count >= _MAX_PENDING or own >= _MAX_PER_TOKEN:
                    raise ListingError("busy")
            # Submission deliberately checks only syntax and token identity.
            # Matching a vault or entry belongs to the owner preview.
            event = self._event(token, request, "Request edit", context=context)
            try:
                with self.activity.connection() as db:
                    db.execute("""
                        INSERT INTO edit_requests(token, id, generation, digest, payload, context, requested,
                                                  identity, project, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
                    """, (token.id, request.id, token.generation, digest, frame, attribution, time(),
                          token.identity, token.project))
            except ActivityError:
                self.activity.finish(event, "Failed")
                raise
            self.activity.finish(event, "Pending review")
            return {"id": request.id, "status": "pending"}

    def status(self, token, request_id):
        try:
            request_id = uuid_text(request_id)
        except (AttributeError, TypeError, ValueError):
            raise ListingError("invalid_request") from None
        with self.workspace.mutex:
            if not self._active(token):
                raise ListingError("ineligible")
            self._discard_stale_proposals()
            with self.activity.connection() as db:
                row = self._get(db, token.id, request_id)
                if row is None:
                    raise ListingError("ineligible")
                return self._response(row)

    def rows(self):
        with self.workspace.mutex:
            self._discard_stale_proposals()
            with self.activity.connection() as db:
                return [self._record(row) for row in db.execute("""
                    SELECT * FROM edit_requests WHERE status IN ('pending', 'applying', 'dispatched')
                    ORDER BY requested DESC
                """)]

    def _pending(self, token_id, request_id):
        with self.activity.connection() as db:
            row = self._get(db, token_id, request_id)
            if row is None or row["status"] != "pending":
                raise VaultError("This edit request is no longer pending.")
            return self._record(row)

    def preview(self, token_id, request_id):
        with self.workspace.mutex:
            record = self._pending(token_id, request_id)
            registration = self.workspace.registrations.get(record.request.vault)
            session = self.workspace.session(record.request.vault)
            if registration is None:
                raise VaultError("This request refers to a vault that is unavailable.")
            if session is None:
                raise VaultError("Unlock the requested vault before reviewing this edit.")
            return _preview(record, registration.name, session)

    def deny(self, token_id, request_id, *, preview=None):
        with self.workspace.mutex:
            record = self._pending(token_id, request_id)
            token = self.grants.records.get(token_id)
            if token is None:
                raise VaultError("The requesting token is unavailable.")
            if preview is not None and preview.record != record:
                raise VaultError("The review belongs to a different edit request.")
            event = self._event(token, record.request, "Deny edit", record.context, preview)
            self._status(record, "pending", "denied")
            self.activity.finish(event, "Denied")

    def approve(self, preview, password=None):
        record = preview.record
        request = record.request
        if preview.password_source == "owner":
            try:
                edit_text(password, required=True)
            except EditError:
                raise VaultError("Enter the replacement password before approving.") from None
        elif password is not None:
            raise VaultError("This edit request does not accept a password.")
        with self.workspace.mutex:
            pending = self._pending(record.token_id, record.id)
            token = self.grants.records.get(record.token_id)
            if token is None or token.status != "active" or token.generation != pending.token_generation:
                self._stale(pending, token, preview)
                raise VaultError("The requesting token changed. Ask the agent to submit a fresh request.")
            if self.workspace.paused:
                raise VaultError("Resume agent access before approving this edit.")
            try:
                checked = self.preview(record.token_id, record.id)
                if checked != preview or checked._session is not preview._session:
                    raise VaultError("The review is stale.")
            except VaultError:
                self._stale(pending, token, preview)
                raise VaultError("The vault changed. Ask the agent to submit a fresh request.") from None
            generation = self.workspace.generation
            event = self._event(token, request, "Apply edit", record.context, checked)
            self.activity.authorize(event, "Approved in edit review")
            self._status(record, "pending", "applying")

        def may_commit():
            return (not self.workspace.paused and self.workspace.generation == generation
                    and self._active(token))

        dispatched = False

        def before_commit():
            nonlocal dispatched
            self.activity.dispatched(event)
            self._status(record, "applying", "dispatched")
            dispatched = True

        values = dict(checked._values)
        if preview.password_source == "owner":
            values["password"] = password
        try:
            identifier = self.workspace._edit(request.vault, checked._change, expected=checked._session,
                                              may_commit=may_commit, before_commit=before_commit, **values)
        except (ActivityError, SettingsError, VaultError) as error:
            if isinstance(error, VaultChanged) or not dispatched and not may_commit():
                status, outcome = "stale", "Stale"
            elif dispatched:
                status, outcome = "interrupted", "Interrupted · outcome unknown"
            else:
                status, outcome = "failed", "Failed"
            with self.workspace.mutex:
                self._status(record, "dispatched" if dispatched else "applying", status)
                self.activity.finish(event, outcome)
            if status == "interrupted":
                raise VaultError("Could not confirm the edit outcome. Reopen the vault to check it.") from None
            raise
        result = identifier if request.operation in ("create_entry", "create_group") else None
        target = {}
        if request.operation == "create_entry":
            target.update(entry=result, entry_title=entry_label(values["title"]))
        elif request.operation == "create_group":
            target.update(group_id=result, folder=folder_label((*checked.destination_path[1:], values["name"])))
        with self.workspace.mutex:
            self._status(record, "dispatched", "applied", result)
            self.activity.finish(event, "Succeeded", **target)
            self.grants.used(token)
        return {"id": record.id, "status": "applied", **({"result": result} if result else {})}


def _reviewed_target(preview):
    request = preview.record.request
    destination = None
    parts = ()
    if preview.destination_path is not None:
        parts = preview.destination_path[1:]
        if request.operation in ("recycle_entry", "recycle_group") and not parts:
            # A session without recorded recycle-bin metadata uses the logical bin name.
            parts = preview.destination_path
        destination = folder_label(parts)
    if request.entry:
        return folder_label(preview.target_path[1:-1]), entry_label(preview.target_path[-1]), destination
    if request.group:
        return folder_label(preview.target_path[1:]), None, destination
    # A create request only targets its parent until the new resource is saved.
    return folder_label(parts), None, destination


def _unique(rows, identifier):
    matches = [row for row in rows if row["id"] == identifier]
    if len(matches) != 1:
        raise VaultError("The exact entry or group is unavailable in this vault.")
    return matches[0]


def _group_path(groups, identifier):
    path = []
    visited = set()
    while identifier is not None:
        row = _unique(groups, identifier)
        if identifier in visited:
            raise VaultError("The vault contains an invalid group hierarchy.")
        visited.add(identifier)
        path.append(row["name"])
        identifier = row["parent"]
    return tuple(reversed(path)), visited


def _subtree(session, identifier):
    children = {}
    for row in session.groups:
        children.setdefault(row["parent"], []).append(row["id"])
    stack = [identifier]
    visited = set()
    while stack:
        current = stack.pop()
        if current in visited:
            raise VaultError("The vault contains an invalid group hierarchy.")
        visited.add(current)
        stack.extend(children.get(current, ()))
    return len(visited), sum(row["group"] in visited for row in session.entries)


def _preview(record, vault_name, session):
    request = record.request
    operation = request.operation
    old, target = (), ()
    group_count, entry_count = 0, 0
    destination, ancestors = None, set()
    if request.parent:
        destination, ancestors = _group_path(session.groups, request.parent)

    if request.entry:
        entry = _unique(session.entries, request.entry)
        source, _ = _group_path(session.groups, entry["group"])
        target = (*source, entry["title"])
        entry_count = 1
        old = tuple((field, entry[field]) for field, _ in request.fields)
    if request.group:
        group = _unique(session.groups, request.group)
        if group["parent"] is None:
            raise VaultError("This operation cannot change the vault root group.")
        target, _ = _group_path(session.groups, request.group)
        group_count, entry_count = _subtree(session, request.group)
        old = tuple((field, group[field]) for field, _ in request.fields)
        if request.group in ancestors:
            raise VaultError("The destination must be outside the group being moved.")

    proposed = dict(request.fields)
    new = request.fields
    if operation == "create_entry":
        new = tuple((field, proposed.get(field, "")) for field in _ENTRY_FIELDS)
        change = "put_entry"
        values = dict(parent=request.parent, entry=None, title=proposed["title"],
                      username=proposed.get("username", ""), url=proposed.get("url", ""), password=None)
    elif operation == "create_group":
        change = "put_group"
        values = dict(parent=request.parent, group=None, name=proposed["name"])
    elif operation in ("update_entry", "move_entry", "replace_password"):
        change = "put_entry"
        values = dict(parent=request.parent or entry["group"], entry=request.entry,
                      password=None, generate_password=request.password_source == "generate",
                      **{field: proposed.get(field, entry[field]) for field in _ENTRY_FIELDS})
    elif operation in ("rename_group", "move_group"):
        change = "put_group"
        values = dict(parent=request.parent or group["parent"], group=request.group,
                      name=proposed.get("name", group["name"]))
    elif operation in ("recycle_entry", "recycle_group"):
        if session.recycle_bin is not None and not session.recycle_bin["enabled"]:
            raise VaultError("Enable the vault’s recycle bin before approving removal.")
        destination = tuple(session.recycle_bin["path"]) if session.recycle_bin else ("Recycle Bin",)
        change = "remove_entry" if request.entry else "remove_group"
        values = {("entry" if request.entry else "group"): request.entry or request.group}
    return EditPreview(record, vault_name, target, destination, old, new, group_count, entry_count,
                       session, change, tuple(values.items()))
