"""Authorize scoped requests and recheck their state before releasing data."""

from collections import Counter, deque
from contextlib import contextmanager
from hashlib import sha256
import json
from types import SimpleNamespace
from threading import BoundedSemaphore
from time import monotonic, time

from .approvals import Approval, ApprovalQueue
from .access_settings import ActionType, Destination, action_id, uuid_text
from .activity import ActivityError, Attribution, entry_label, entry_target_labels
from .grants import OPTIONAL_METADATA_FIELDS, verifier
from .protocol import RESPONSE_LIMIT, ListingError, decode, encode, validate_command, validate_upload
from .settings import SettingsError
from .usage import requires_body_permission, requires_write_permission, usage_action, usage_origin


REQUEST_WINDOW = 60
TOKEN_REQUESTS = 48
BROKER_REQUESTS = 240


def access_details(token):
    """Project only this grant's attribution and permissions, never credentials."""
    def item(value, *, requested=False):
        result = {key: getattr(value, key) for key in
                  ("vault", "entry", "group", "metadata", "username", "url", "action")}
        result["edits"] = list(value.edits)
        if value.uses:
            result["uses"] = list(value.uses)
            result["origins"] = list(value.origins)
        if requested:
            result["label"] = value.label
        return result

    pending = token.pending_change
    return {
        "status": token.status, "identity": token.identity, "project": token.project,
        **{key: getattr(token.context, key) for key in ("model", "chat", "chat_id")},
        "scope": [item(value) for value in token.scope],
        "requested_items": [item(value, requested=True) for value in token.items],
        "pending_change": ({"id": pending.id, "items": [item(value, requested=True) for value in pending.items]}
                           if pending else None),
    }


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
        self.certificate_reviews = set()

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
            usage = None
            if operation in ("request_access", "request_edit") and keys == {"request"}:
                pass
            elif operation == "edit_status" and keys == {"id"}:
                pass
            elif operation == "discover" and keys <= {"vault", "summary"}:
                vault = uuid_text(payload["vault"]) if "vault" in keys else None
                if type(payload.get("summary", False)) is not bool:
                    raise ValueError
            elif operation == "access_status" and keys <= {"details"}:
                if type(payload.get("details", False)) is not bool:
                    raise ValueError
            elif operation == "list_vaults" and not keys:
                pass
            elif operation == "list_entries" and keys <= {"vault", "fields"}:
                vault = uuid_text(payload["vault"]) if "vault" in keys else None
                fields = payload.get("fields", [])
                if (not isinstance(fields, list) or len(fields) > len(OPTIONAL_METADATA_FIELDS)
                        or any(field not in OPTIONAL_METADATA_FIELDS for field in fields)
                        or len(set(fields)) != len(fields)):
                    raise ValueError
            elif operation == "use_password" and {"entry", "usage"} <= keys <= {"entry", "usage", "vault", "upload"}:
                entry = uuid_text(payload["entry"])
                vault = uuid_text(payload["vault"]) if "vault" in keys else None
                if not isinstance(payload["usage"], dict):
                    raise ValueError
                # Own a detached descriptor before review or dispatch can wait.
                usage = decode(encode(payload["usage"]))
                if "upload" in keys:
                    if upload is None:
                        raise ValueError
                    input_info = validate_upload(payload["upload"])
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
        if operation == "discover":
            if "credential" in payload:
                raise ListingError("invalid_request")
            return self._discover(uid, context, live, deliver, vault=vault, summary=payload.get("summary", False))
        credential = payload.get("credential")
        if credential is None:
            raise ListingError("token_required")

        if isinstance(credential, str) and credential and credential in encode(
            {key: value for key, value in payload.items() if key != "credential"}
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
                return encode(access_details(token) if payload.get("details") else {"status": token.status})
            if operation == "edit_status":
                if self.edits is None:
                    raise ListingError("ineligible")
                return encode(self.edits.status(token, payload["id"]))
            self._charge_request(token.verifier, uid, active=token.status == "active")
            generation = self.workspace.generation
            name = {"list_vaults": "List vaults", "list_entries": "List entries",
                    "use_password": "Use password"}[operation]
            registered = self._catalog(token)
            chosen = vault
            if vault is None and len(registered) == 1 and operation != "list_vaults":
                chosen = next(iter(registered))
            registration = self.workspace.registrations.get(chosen) if chosen in registered else None
            session = self.workspace.session(chosen) if registration else None
            binding = registration.binding(entry, binding_id) if registration and entry and usage is None else None
            if usage is not None:
                try:
                    action = usage_action(entry, usage, accepts_input=input_info is not None, pin_executable=False)
                except (ValueError, TypeError, KeyError):
                    denied = self.activity.begin(uid, context, "Use password", None,
                                                 vault=registration.name if registration else None,
                                                 vault_id=chosen if registration else None,
                                                 token=token.id, agent=token.identity, project=token.project)
                    self.activity.finish(denied, "Denied")
                    raise ListingError("invalid_request") from None
                binding = SimpleNamespace(action=action)
            review_operation = binding.action.kind.review_operation if binding else operation
            review_usage = self.workspace.requires_review(review_operation)
            review_policy = review_usage
            certificate_pin = None
            certificate_trusted = False
            certificate_committed = False
            certificate_expected = ()
            credential_revision = registration.credential_revision(entry) if registration and entry else None
            if binding is not None and binding.action.kind == ActionType.RESULTS:
                # Saved actions already bind the owner's exact certificate in
                # their reviewed action revision; dynamic uses need scope trust.
                if usage is not None:
                    certificate_pin = decode(binding.action.result_request.encode("utf-8")).get("certificate_sha256")
                if certificate_pin:
                    certificate_expected = self.grants.result_certificate_pins(
                        token, chosen, entry, credential_revision, usage_origin(binding.action.url))
                    certificate_trusted = bool(certificate_expected) and all(
                        pin == certificate_pin for pin in certificate_expected)
                    certificate_committed = certificate_trusted
                review_policy = review_usage or self.workspace.requires_review("use_https")
                review_usage = review_policy or certificate_pin is not None and not certificate_trusted
            if usage is not None:
                origin = None
                if binding.action.kind != ActionType.STDIN:
                    origin = usage_origin(binding.action.url)
                candidates = tuple(s for s in token.scope
                                   if (s.vault, s.entry) == (chosen, entry) and usage["type"] in s.uses
                                   and (origin is None or origin in s.origins)
                                   and (not requires_body_permission(binding.action) or "https_body" in s.uses)
                                   and (not requires_write_permission(binding.action) or "https" in s.uses))
                permitted = registration is not None and any(
                    s.use_revision is not None and s.use_revision == registration.credential_revision(entry)
                    for s in candidates)
                credential_changed = bool(candidates) and not permitted
            else:
                permitted = (
                    binding is not None and binding.action.enabled and
                    any((s.vault, s.entry, s.action, s.revision) == (chosen, entry, binding_id, binding.revision)
                        for s in token.scope)
                )
            recognized = permitted or usage is not None and credential_changed
            folder, title = entry_target_labels(session.entries, entry) if recognized and session else (None, None)
            scope_summary = f"Requested entry fields · {', '.join(fields)}" if fields else None
            if usage is not None:
                scope_summary = f"Agent-supplied {usage.get('type', 'operation')} · SHA-256 {sha256(encode(usage)).hexdigest()}"
                if binding.action.kind == ActionType.RESULTS:
                    workflow = decode(binding.action.result_request.encode("utf-8"))
                    scope_summary += (" · " + workflow["request"].get("method", "GET")
                                      + " · Fields: " + ", ".join(workflow["result"]["columns"]))
                    if certificate_pin:
                        previous_pins = sorted({pin for pin in certificate_expected if pin})
                        scope_summary += (" · Certificate SHA-256: " + certificate_pin
                                          + " · Previously trusted: " + (", ".join(previous_pins) or "None"))
            elif permitted and binding.action.request_summary:
                scope_summary = binding.action.request_summary
            if input_info is not None:
                artifact_summary = f"Input file · {input_info['size']} bytes · SHA-256 {input_info['sha256']}"
                scope_summary = f"{scope_summary} · {artifact_summary}" if scope_summary else artifact_summary
            event = self.activity.begin(
                uid, context, name + (f" · {binding.action.name}" if recognized else ""),
                (self._usage_destination(binding.action) if usage is not None else binding.action.destination)
                if recognized else None, entry if recognized else None,
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
                if certificate_committed:
                    pins = self.grants.result_certificate_pins(
                        current, chosen, entry, credential_revision, usage_origin(binding.action.url))
                    if not pins or any(pin != certificate_pin for pin in pins):
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
                    if usage is not None and not any(
                            s.use_revision is not None and s.use_revision == record.credential_revision(entry)
                            for s in candidates):
                        return False
                    if binding is not None and usage is None:
                        saved = record.binding(entry, binding_id)
                        if saved is not binding or not saved.action.enabled:
                            return False
                return effect()

        dispatch_started = False
        certificate_reservation = None
        try:
            if token.status != "active":
                raise ListingError("ineligible")
            with self.workspace.mutex:
                if self.workspace.paused:
                    raise ListingError("paused")
            if operation != "list_vaults":
                if vault is None and len(registered) > 1:
                    raise ListingError("select_vault")
                if operation == "use_password" and usage is not None and credential_changed:
                    raise ListingError("credential_changed")
                if session is None or (operation == "use_password" and not permitted):
                    raise ListingError("ineligible")
            if operation == "use_password":
                expected = binding.action.command if binding.action.is_command else None
                if ((usage is None and command != expected)
                        or binding.action.accepts_input != (input_info is not None)):
                    raise ListingError("ineligible")
                if session.worker.entry(entry) is None:
                    raise ListingError("ineligible")
                if usage is not None and binding.action.is_command:
                    # Hash only an authorized command, outside the global owner
                    # mutex. The worker rechecks this pin before execution.
                    try:
                        binding.action = usage_action(entry, usage, accepts_input=input_info is not None)
                    except (ValueError, TypeError, OSError):
                        raise ListingError("ineligible") from None
            if not guard(live):
                raise ListingError("revoked")
            if certificate_pin and not review_policy:
                with self.workspace.mutex:
                    certificate_expected = self.grants.result_certificate_pins(
                        self.grants.records[token.id], chosen, entry, credential_revision, usage_origin(binding.action.url))
                    certificate_trusted = bool(certificate_expected) and all(
                        pin == certificate_pin for pin in certificate_expected)
                    certificate_committed = certificate_trusted
                    review_usage = not certificate_trusted
                    if review_usage:
                        key = (token.id, token.generation, chosen, entry, credential_revision,
                               usage_origin(binding.action.url), certificate_pin)
                        if key in self.certificate_reviews:
                            raise ListingError("busy")
                        self.certificate_reviews.add(key)
                        certificate_reservation = key
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
                    if usage is not None:
                        if binding.action.kind == ActionType.RESULTS:
                            from .result_delivery import parse_result_usage
                            declared = parse_result_usage(usage)
                            scope += declared.description
                            scope += ("Complete requested workflow:\n" + json.dumps(declared.data, ensure_ascii=False, indent=2),)
                        else:
                            scope += ("Requested operation · " + encode(usage).decode("ascii").strip(),)
                        if input_info is not None:
                            scope += (artifact_summary,)
                        if binding.action.kind == ActionType.RESULTS:
                            if certificate_pin and not certificate_trusted:
                                scope += ("Verify this certificate fingerprint. Approving also trusts this certificate for this token, entry and destination. Future requests follow your Auto Approve settings. A changed certificate requires review again.",)
                            scope += ("Release only the selected fields from this approved endpoint. Login responses, passwords and session tickets stay private.",
                                      "Trust this endpoint to supply these fields. Filters cannot guarantee secrecy if a service deliberately encodes credentials in its results.")
                        if binding.action.opaque:
                            scope += ("Command output and exit status stay private. The agent receives only a dispatch receipt.",)
                        if binding.action.kind == ActionType.NETWORK_PROMPT:
                            scope += ("This command may send the credential to the approved TCP peer and port. The relay does not verify the command's application protocol.",)
                    elif binding.action.request_json:
                        scope += ("Fixed JSON body · " + binding.action.request_json,)
                    elif scope_summary:
                        scope += (scope_summary,)
                ticket = Approval(event, uid, context, name + (f" · {binding.action.name}" if binding else ""),
                                  scope, (self._usage_destination(binding.action) if usage is not None else binding.action.destination)
                                  if binding else None, monotonic() + self.approvals.timeout,
                                  identity=token.identity, project=token.project, requested=time(),
                                  trusts_certificate=bool(certificate_pin and not certificate_trusted))
                result = self.approvals.wait(ticket, lambda: guard(live))
                if result != "approved":
                    raise ListingError(result)
            self.activity.authorize(event, ("Approved once; trust certificate on verified dispatch"
                                           if certificate_pin and not certificate_trusted else "Approved once")
                                    if review_usage else "Approved token")
            if not guard(live):
                raise ListingError("revoked")
            if operation == "list_vaults":
                result = {"vaults": [{"id": key, "name": name} for key, name in registered.items()]}
            elif operation == "list_entries":
                result = self._entries(token, session, chosen, fields)
            else:
                def gate(send):
                    def audit_and_send():
                        nonlocal dispatch_started, certificate_committed
                        if not dispatch_started:
                            if certificate_pin and not certificate_trusted:
                                # The trusted worker reaches this gate only after
                                # TLS has verified the exact reviewed fingerprint.
                                # Persist under the same live guard as dispatch.
                                self.grants.trust_result_certificate(
                                    token.id, token.generation, chosen, entry, credential_revision,
                                    usage_origin(binding.action.url), certificate_pin, certificate_expected)
                                certificate_committed = True
                            self.activity.dispatched(event)
                            dispatch_started = True
                        send()
                    return guard(lambda: dispatch(audit_and_send))

                if binding.action.kind == ActionType.RESULTS:
                    username_allowed = any((s.vault, s.entry) == (chosen, entry) and s.username for s in token.scope)
                    result = session.worker.use(binding.action, gate, allow_username=username_allowed)
                elif binding.action.is_command or binding.action.browser:
                    with self._command_slot():
                        if input_info is None:
                            result = session.worker.use(binding.action, gate)
                        else:
                            with upload(input_info, guard) as input_path:
                                result = session.worker.use(binding.action, gate, input_path=input_path)
                else:
                    result = session.worker.use(binding.action, gate)
            private_outcome = result.pop("_execution_outcome", None)
            if binding is not None and binding.action.opaque and dispatch_started:
                result = {"outcome": "dispatched"}
            succeeded = result.get("outcome", "succeeded") in ("succeeded", "dispatched")
            frame = encode(result)
            if len(frame) > RESPONSE_LIMIT:
                raise ListingError("too_large")
            delivered = deliver(frame, guard)
            if (operation == "use_password" and binding.action.kind == ActionType.RESULTS and not delivered):
                self.activity.finish(event, "Results Not Delivered", result.get("http_status"))
                return None
            if operation == "use_password":
                # Already-dispatched remote work can still complete after revocation.
                outcome = {"succeeded": "Succeeded", "failed": "Failed", "dispatched": "Dispatched",
                           "uncertain": "Interrupted · outcome unknown"}[result["outcome"]]
                if result["outcome"] == "dispatched" and private_outcome in ("succeeded", "failed", "uncertain"):
                    outcome = {"succeeded": "Succeeded", "failed": "Failed", "uncertain": "Interrupted · outcome unknown"}[private_outcome]
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
            elif error.code == "credential_changed":
                outcome = "Stale"
            self.activity.finish(event, outcome)
            raise
        finally:
            if certificate_reservation is not None:
                with self.workspace.mutex:
                    self.certificate_reviews.discard(certificate_reservation)

    @staticmethod
    def _usage_destination(action):
        if action.kind == ActionType.RESULTS:
            return f"Protected HTTPS results · {usage_origin(action.url)}"
        if action.kind == ActionType.STDIN:
            return "Isolated local command"
        if action.kind == ActionType.NETWORK_PROMPT:
            target = Destination.parse(action.url)
            return f"TCP peer {target.host}:{target.port}"
        operation = "Browser form POST" if action.browser else action.method
        return f"{operation} {usage_origin(action.url)}"

    def _discover(self, uid, context, live, deliver, *, vault=None, summary=False):
        with self.workspace.mutex:
            self._charge_request(("discovery", uid), uid, active=False)
            if not live():
                raise ListingError("revoked")
            event = self.activity.begin(uid, context, "Discover resources", None)
            generation = self.workspace.generation
            references = self.workspace.discovery.references(self.workspace)
            catalog = None
            if not self.workspace.paused:
                catalog = self.workspace.discovery.read(self.workspace, vault=vault, summary=summary)

        def guard(effect):
            with self.workspace.mutex:
                current = self.workspace.discovery.references(self.workspace)
                if (self.workspace.paused or self.workspace.generation != generation
                        or len(current) != len(references)
                        or any(old is not new for old, new in zip(references, current))):
                    return False
                return effect()

        try:
            if self.workspace.paused:
                raise ListingError("paused")
            reply = encode(catalog)
            if len(reply) > RESPONSE_LIMIT:
                raise ListingError("too_large")
            if not guard(live):
                raise ListingError("revoked")
            self.activity.authorize(event, "Discovery catalog")
            if not deliver(reply, guard):
                raise ListingError("revoked")
            self.activity.finish(event, "Succeeded")
        except ListingError as error:
            self.activity.finish(event, {"paused": "Paused", "too_large": "Too large"}.get(error.code, "Revoked"))
            raise
        return None

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
