"""Authorize scoped requests and recheck their state before releasing data."""

from collections import Counter, deque
from contextlib import contextmanager
from threading import BoundedSemaphore
from time import monotonic, time

from .approvals import Approval, ApprovalQueue
from .access_settings import action_id, uuid_text
from .activity import ActivityError, Attribution, entry_label, entry_target_labels
from .grants import OPTIONAL_METADATA_FIELDS, verifier
from .protocol import RESPONSE_LIMIT, ListingError, encode, validate_command, validate_upload
from .settings import SettingsError


REQUEST_WINDOW = 60
TOKEN_REQUESTS = 48
BROKER_REQUESTS = 240


class ScopedBroker:
    accepts_upload = True

    def __init__(self, workspace, grants, activity, edits=None, approvals=None):
        self.workspace = workspace
        self.grants = grants
        self.activity = activity
        self.edits = edits
        self.approvals = approvals or ApprovalQueue()
        self.requests = deque()
        self.request_counts = Counter()
        self.request_classes = Counter()
        self.next_limit_notice = 0
        self.command_slots = BoundedSemaphore(2)

    @contextmanager
    def _command_slot(self):
        if not self.command_slots.acquire(blocking=False):
            raise ListingError("busy")
        try:
            yield
        finally:
            self.command_slots.release()

    def _charge_request(self, credential_key, uid, *, active):
        # Called under the workspace mutex before the request can write audit data.
        # Unapproved callers share a separate budget from active agents.
        now = monotonic()
        key = (active, credential_key)
        while self.requests and self.requests[0][0] <= now - REQUEST_WINDOW:
            _, expired = self.requests.popleft()
            self.request_classes[expired[0]] -= 1
            self.request_counts[expired] -= 1
            if not self.request_counts[expired]:
                del self.request_counts[expired]
        if self.request_classes[active] >= BROKER_REQUESTS or self.request_counts[key] >= TOKEN_REQUESTS:
            if now >= self.next_limit_notice:
                self.next_limit_notice = now + REQUEST_WINDOW
                event = self.activity.begin(uid, Attribution(), "Broker request rate limit", None)
                self.activity.finish(event, "Rate limited")
            raise ListingError("busy")
        self.requests.append((now, key))
        self.request_counts[key] += 1
        self.request_classes[active] += 1

    def __call__(self, payload, uid, _engine, live, dispatch, deliver, *, upload=None):
        try:
            return self.handle(payload, uid, live, dispatch, deliver, upload=upload)
        except (ActivityError, SettingsError):
            raise ListingError("audit_unavailable") from None

    def handle(self, payload, uid, live, dispatch, deliver, *, upload=None):
        try:
            if not isinstance(payload, dict) or type(payload.get("version")) is not int or payload["version"] != 1:
                raise ValueError
            operation = payload["operation"]
            keys = set(payload) - {"version", "operation", "credential", "context"}
            context = Attribution.parse(payload.get("context", {}))
            entry, binding_id, vault = None, None, None
            fields = ()
            command = None
            input_info = None
            if operation in ("request_access", "request_edit") and keys == {"request"}:
                pass
            elif operation == "edit_status" and keys == {"id"}:
                pass
            elif operation in ("access_status", "list_vaults") and not keys:
                pass
            elif operation == "list_entries" and keys <= {"vault", "fields"}:
                vault = uuid_text(payload["vault"]) if "vault" in keys else None
                fields = payload.get("fields", [])
                if (not isinstance(fields, list) or len(fields) > len(OPTIONAL_METADATA_FIELDS)
                        or any(field not in OPTIONAL_METADATA_FIELDS for field in fields)
                        or len(set(fields)) != len(fields)):
                    raise ValueError
            elif operation == "use_password" and {"entry", "action"} <= keys <= {"entry", "action", "vault", "command", "upload"}:
                entry = uuid_text(payload["entry"])
                binding_id = action_id(payload["action"])
                vault = uuid_text(payload["vault"]) if "vault" in keys else None
                if "command" in keys:
                    command = validate_command(payload["command"])
                if "upload" in keys:
                    if command is None or upload is None:
                        raise ValueError
                    input_info = validate_upload(payload["upload"])
            else:
                raise ValueError
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ListingError("invalid_request") from None
        credential = payload.get("credential")
        if credential is None:
            raise ListingError("token_required")

        if isinstance(credential, str) and credential and credential in encode(
            {"context": payload.get("context"), "request": payload.get("request")}
        ).decode("ascii"):
            raise ListingError("invalid_request")

        if operation == "request_edit":
            with self.workspace.mutex:
                if not live():
                    raise ListingError("revoked")
                token = self.grants.authenticate(credential, uid)
                if self.edits is None or token.status != "active":
                    raise ListingError("ineligible")
                self._charge_request(token.verifier, uid, active=True)
            return encode(self.edits.submit(token, payload["request"], context, live=live))

        with self.workspace.mutex:
            if not live():
                raise ListingError("revoked")
            if operation == "request_access":
                self._charge_request(verifier(credential), uid, active=False)
                status = self.grants.enroll(credential, uid, payload["request"], context)
                return encode({"status": status})
            token = self.grants.authenticate(credential, uid)
            if operation == "access_status":
                return encode({"status": token.status})
            if operation == "edit_status":
                if self.edits is None:
                    raise ListingError("ineligible")
                return encode(self.edits.status(token, payload["id"]))
            self._charge_request(token.verifier, uid, active=token.status == "active")
            generation = self.workspace.generation
            review_usage = self.workspace.requires_review(operation)
            name = {"list_vaults": "List vaults", "list_entries": "List entries",
                    "use_password": "Use password"}[operation]
            registered = self._catalog(token)
            chosen = vault
            if vault is None and len(registered) == 1 and operation != "list_vaults":
                chosen = next(iter(registered))
            registration = self.workspace.registrations.get(chosen) if chosen in registered else None
            session = self.workspace.session(chosen) if registration else None
            binding = registration.binding(entry, binding_id) if registration and entry else None
            permitted = (
                binding is not None and binding.action.enabled and
                any((s.vault, s.entry, s.action, s.revision) == (chosen, entry, binding_id, binding.revision)
                    for s in token.scope)
            )
            folder, title = entry_target_labels(session.entries, entry) if permitted and session else (None, None)
            scope_summary = f"Requested entry fields · {', '.join(fields)}" if fields else None
            if input_info is not None:
                scope_summary = f"Input file · {input_info['size']} bytes · SHA-256 {input_info['sha256']}"
            event = self.activity.begin(
                uid, context, name + (f" · {binding.action.name}" if permitted else ""),
                binding.action.destination if permitted else None, entry if permitted else None,
                vault=registration.name if registration else None, vault_id=chosen if registration else None,
                token=token.id, agent=token.identity, project=token.project, folder=folder, entry_title=title,
                scope=scope_summary,
            )

        def guard(effect):
            with self.workspace.mutex:
                current = self.grants.records[token.id]
                if (self.workspace.paused or self.workspace.generation != generation
                        or current.generation != token.generation or current.status != "active"):
                    return False
                if operation == "list_vaults":
                    if self._catalog(current) != registered:
                        return False
                else:
                    if self.workspace.session(chosen) is not session:
                        return False
                    record = self.workspace.registrations.get(chosen)
                    if record is None:
                        return False
                    if binding is not None:
                        saved = record.binding(entry, binding_id)
                        if saved is not binding or not saved.action.enabled:
                            return False
                return effect()

        dispatch_started = False
        try:
            if token.status != "active":
                raise ListingError("ineligible")
            with self.workspace.mutex:
                if self.workspace.paused:
                    raise ListingError("paused")
            if operation != "list_vaults":
                if vault is None and len(registered) > 1:
                    raise ListingError("select_vault")
                if session is None or (operation == "use_password" and not permitted):
                    raise ListingError("ineligible")
            if operation == "use_password":
                expected = binding.action.command if binding.action.is_command else None
                if command != expected or binding.action.accepts_input != (input_info is not None):
                    raise ListingError("ineligible")
                if session.worker.entry(entry) is None:
                    raise ListingError("ineligible")
            if not guard(live):
                raise ListingError("revoked")
            if review_usage:
                if operation == "list_vaults":
                    scope = tuple(registered.values())
                elif operation == "list_entries":
                    grants = [item for item in token.scope if item.vault == chosen and item.metadata]
                    identifiers = {item.entry for item in grants}
                    paths = tuple(" / ".join((*row["group_path"], entry_label(row["title"])))
                                  for row in session.entries if row["id"] in identifiers)
                    optional = {"username": "username", "url": "stored URL"}
                    columns = ("entry ID", "title", "group path",
                               *(optional[field] for field in fields if any(getattr(item, field) for item in grants)))
                    scope = (registration.name, *(paths or ("No entries in scope",)),
                             "Visible fields: " + ", ".join(columns))
                else:
                    scope = (" › ".join(part for part in (registration.name, folder, title) if part),)
                    if input_info is not None:
                        scope += (scope_summary,)
                ticket = Approval(event, uid, context, name + (f" · {binding.action.name}" if binding else ""),
                                  scope, binding.action.destination if binding else None, monotonic() + self.approvals.timeout,
                                  identity=token.identity, project=token.project, requested=time())
                result = self.approvals.wait(ticket, lambda: guard(live))
                if result != "approved":
                    raise ListingError(result)
            self.activity.authorize(event, "Approved once" if review_usage else "Approved token")
            if not guard(live):
                raise ListingError("revoked")
            if operation == "list_vaults":
                result = {"vaults": [{"id": key, "name": name} for key, name in registered.items()]}
            elif operation == "list_entries":
                result = self._entries(token, session, chosen, fields)
            else:
                def gate(send):
                    def audit_and_send():
                        nonlocal dispatch_started
                        self.activity.dispatched(event)
                        dispatch_started = True
                        send()
                    return guard(lambda: dispatch(audit_and_send))

                if binding.action.is_command:
                    with self._command_slot():
                        if input_info is None:
                            result = session.worker.use(binding.action, gate)
                        else:
                            with upload(input_info, guard) as input_path:
                                result = session.worker.use(binding.action, gate, input_path=input_path)
                else:
                    result = session.worker.use(binding.action, gate)
            succeeded = result.get("outcome", "succeeded") == "succeeded"
            frame = encode(result)
            if len(frame) > RESPONSE_LIMIT:
                raise ListingError("too_large")
            delivered = deliver(frame, guard)
            if operation == "use_password":
                # Already-dispatched remote work can still complete after revocation.
                outcome = {"succeeded": "Succeeded", "failed": "Failed",
                           "uncertain": "Interrupted · outcome unknown"}[result["outcome"]]
                self.activity.finish(event, outcome, result.get("http_status"))
            elif not delivered:
                raise ListingError("revoked")
            else:
                self.activity.finish(event, "Succeeded")
            if succeeded and delivered:
                with self.workspace.mutex:
                    self.grants.used(token)
            return None
        except ListingError as error:
            outcome = "Denied"
            if dispatch_started:
                outcome = "Interrupted · outcome unknown"
            elif error.code in ("busy", "too_large"):
                outcome = "Failed"
            elif error.code == "revoked" or not guard(live) and error.code == "unavailable":
                outcome = "Revoked"
            elif error.code == "paused":
                outcome = "Paused"
            elif error.code == "expired":
                outcome = "Expired"
            self.activity.finish(event, outcome)
            raise

    def _catalog(self, token):
        identifiers = {scope.vault for scope in token.scope}
        return {r.id: r.name for r in self.workspace.registrations.values() if r.id in identifiers}

    @staticmethod
    def _entries(token, session, vault, fields):
        permissions = {}
        for scope in token.scope:
            if scope.vault == vault and scope.metadata:
                allowed = permissions.setdefault(scope.entry, set())
                allowed.update(field for field in fields if getattr(scope, field))
        result = session.worker.scoped_entries(permissions.keys())
        if "error" in result:
            raise ListingError(result["error"])
        # The worker provides only the scoped identities and basic metadata. Read
        # separately approved values from this same session's owner projection.
        owner_rows = {}
        if any(permissions.values()):
            for row in session.entries:
                identifier = row["id"]
                if permissions.get(identifier):
                    owner_rows[identifier] = row if identifier not in owner_rows else {}
        rows = []
        for row in result["entries"]:
            identifier = row["id"]
            if identifier not in permissions:
                continue
            projected = {"id": identifier, "title": row["title"], "group_path": row["group_path"]}
            values = owner_rows.get(identifier, {})
            projected.update({field: values[field] for field in fields
                              if field in permissions[identifier] and isinstance(values.get(field), str)})
            rows.append(projected)
        return {"entries": rows}
