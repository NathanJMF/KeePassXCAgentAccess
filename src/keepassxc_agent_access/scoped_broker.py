"""Authorize scoped requests and recheck their state before releasing data."""

from collections import Counter, deque
from contextlib import contextmanager
from hashlib import sha256
import json
from types import SimpleNamespace
from threading import BoundedSemaphore
from time import monotonic, time

from .approvals import Approval, ApprovalQueue
from .account_provision import parse_provision
from .access_settings import ActionType, Destination, action_id, uuid_text
from .activity import ActivityError, Attribution, entry_label, entry_target_labels
from .console_access import ConsoleAccess
from .grants import OPTIONAL_METADATA_FIELDS, verifier
from .guest_access import GuestAccess
from .protocol import (CONSOLE_OPERATIONS, GUEST_OPERATIONS, RESPONSE_LIMIT, WORKFLOW_OPERATIONS, ListingError,
                       decode, encode, validate_command, validate_upload)
from .result_delivery import result_fields
from .settings import SettingsError
from .usage import requires_body_permission, requires_write_permission, usage_action, usage_origin
from .workflow import WorkflowAccess


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
        self.console_access = ConsoleAccess(self)
        self.guest_access = GuestAccess(self)
        self.workflows = WorkflowAccess(self)

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

    def handle(self, payload, uid, live, dispatch, deliver, *, upload=None, approved_step=None):
        try:
            if not isinstance(payload, dict) or type(payload.get("version")) is not int or payload["version"] != 1:
                raise ValueError
            operation = payload["operation"]
            keys = set(payload) - {"version", "operation", "credential", "context"}
            context = Attribution.parse(payload.get("context", {}))
            if isinstance(operation, str) and operation in CONSOLE_OPERATIONS:
                if upload is not None:
                    raise ValueError
                return self.console_access.handle(operation, keys, payload, uid, context, live, dispatch, deliver,
                                                  approved_step=approved_step)
            entry, binding_id, vault = None, None, None
            fields = ()
            command = None
            input_info = None
            usage = None
            receipt = None
            provision = None
            if operation in ("request_access", "request_edit") and keys == {"request"}:
                pass
            elif operation in WORKFLOW_OPERATIONS and upload is None:
                if operation == "workflow_request":
                    if keys != {"request"}:
                        raise ValueError
                else:
                    if keys != ({"workflow", "step"} if operation == "workflow_run" else {"workflow"}):
                        raise ValueError
                    identifier = uuid_text(payload["workflow"])
                    name = payload["step"] if operation == "workflow_run" else None
                    if operation == "workflow_run" and not isinstance(name, str):
                        raise ValueError
            elif operation in GUEST_OPERATIONS and upload is None:
                pass
            elif operation == "edit_status" and keys == {"id"}:
                pass
            elif operation == "write_status" and keys == {"receipt"}:
                receipt = uuid_text(payload["receipt"])
            elif operation == "release_entry" and keys == {"vault", "entry"}:
                vault, entry = uuid_text(payload["vault"]), uuid_text(payload["entry"])
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
            elif (operation == "use_password"
                  and {"entry", "usage"} <= keys <= {"entry", "usage", "vault", "upload", "receipt", "provision"}):
                entry = uuid_text(payload["entry"])
                vault = uuid_text(payload["vault"]) if "vault" in keys else None
                if not isinstance(payload["usage"], dict):
                    raise ValueError
                # Own a detached descriptor before review or dispatch can wait.
                usage = decode(encode(payload["usage"]))
                if "receipt" in keys:
                    receipt = uuid_text(payload["receipt"])
                    if usage.get("type") != "https_results":
                        raise ValueError
                if "provision" in keys:
                    provision = parse_provision(payload["provision"], usage)
                    if receipt is None or vault is None or provision["entry"] == entry or approved_step is not None:
                        raise ValueError
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

        if operation in GUEST_OPERATIONS:
            try:
                return self.guest_access.handle(operation, keys, payload, uid, context, live, dispatch, deliver,
                                                approved_step=approved_step)
            except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
                raise ListingError("invalid_request") from None
        if operation in WORKFLOW_OPERATIONS:
            if operation == "workflow_request":
                try:
                    return self.workflows.propose(payload["request"], credential, uid, context, live, deliver)
                except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
                    raise ListingError("invalid_request") from None
            workflow, step_payload = self.workflows.resolve(identifier, name, payload, uid, live)
            if operation == "workflow_status":
                return self.workflows.status(workflow, deliver)
            return self.handle(step_payload, uid, live, dispatch, deliver, approved_step=(workflow, name))
        if operation == "request_edit":
            with self.workspace.mutex:
                if not live():
                    raise ListingError("revoked")
                token = self.grants.authenticate(credential, uid)
                if self.edits is None or token.status != "active":
                    raise ListingError("ineligible")
                self._charge_request(token.verifier, uid, active=True)
            return encode(self.edits.submit(token, payload["request"], context, live=live))
        if operation == "write_status":
            return self._write_status(credential, uid, receipt, live, deliver)

        with self.workspace.mutex:
            if not live():
                raise ListingError("revoked")
            if operation == "request_access":
                self._charge_request(verifier(credential), uid, active=False)
                status = self.grants.enroll(credential, uid, payload["request"], context)
                return encode({"status": status})
            token = self.grants.authenticate(credential, uid)
            if operation == "release_entry":
                self._charge_request(token.verifier, uid, active=token.status == "active")
                return encode(self.grants.release_entry(token, vault, entry, context))
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
            account_revision = None
            account_labels = ()
            if provision:
                account = provision["entry"]
                if (session is None or (chosen, account) in token.released_entries
                        or not any(row["id"] == account for row in session.entries)):
                    raise ListingError("ineligible")
                account_revision = registration.credential_revision(account)
                account_labels = entry_target_labels(session.entries, account)
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
            write_once = False
            write_approval_required = False
            credential_revision = registration.credential_revision(entry) if registration and entry else None
            if binding is not None and binding.action.kind == ActionType.RESULTS:
                # Saved actions already bind the owner's exact certificate in
                # their reviewed action revision; dynamic uses need scope trust.
                if usage is not None:
                    certificate_pin = decode(binding.action.result_request.encode("utf-8")).get("certificate_sha256")
                    write_once = usage.get("approve_write_once") is True
                if certificate_pin:
                    certificate_expected = self.grants.result_certificate_pins(
                        token, chosen, entry, credential_revision, usage_origin(binding.action.url))
                    certificate_trusted = bool(certificate_expected) and all(
                        pin == certificate_pin for pin in certificate_expected)
                    certificate_committed = certificate_trusted
                review_policy = write_once or review_usage or self.workspace.requires_review("use_https")
                review_usage = review_policy or certificate_pin is not None and not certificate_trusted
            remember_certificate = bool(certificate_pin and not certificate_trusted and not write_once)
            if usage is not None:
                origin = None
                if binding.action.kind != ActionType.STDIN:
                    origin = usage_origin(binding.action.url)
                body_required = requires_body_permission(binding.action)
                write_required = requires_write_permission(binding.action)
                matching = tuple(s for s in token.scope
                                   if (s.vault, s.entry) == (chosen, entry) and usage["type"] in s.uses
                                   and (origin is None or origin in s.origins)
                                   and (not body_required or "https_body" in s.uses))
                candidates = tuple(s for s in matching if not write_required or write_once or "https" in s.uses)
                permitted = registration is not None and any(
                    s.use_revision is not None and s.use_revision == credential_revision
                    for s in candidates)
                credential_changed = bool(candidates) and not permitted
                write_approval_required = write_required and not write_once and not permitted and any(
                    s.use_revision is not None and s.use_revision == credential_revision for s in matching)
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
                    scope_summary += " · " + workflow["request"]["method"]
                    if write_required:
                        scope_summary += " " + workflow["request"]["path"]
                    if receipt:
                        if not write_required:
                            raise ListingError("invalid_request")
                        scope_summary += f" · Write receipt {receipt}"
                    if provision:
                        scope_summary += f" · Account entry {provision['entry']}"
                    scope_summary += " · Fields: " + ", ".join(result_fields(workflow["result"]))
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
                uid, context, "Provision Account" if provision and recognized else
                name + (f" · {binding.action.name}" if recognized else ""),
                (self._usage_destination(binding.action) if usage is not None else binding.action.destination)
                if recognized else None, entry if recognized else None,
                vault=registration.name if registration else None, vault_id=chosen if registration else None,
                token=token.id, agent=token.identity, project=token.project, folder=folder, entry_title=title,
                scope=scope_summary,
                workflow_id=approved_step[0].id if approved_step else None,
                workflow_step=approved_step[1] if approved_step else None,
            )

        def guard(effect):
            with self.workspace.mutex:
                current = self.grants.records[token.id]
                if (self.workspace.paused or self.workspace.generation != generation
                        or current.generation != token.generation or current.status != "active"):
                    return False
                if approved_step and not self.workflows.current(approved_step[0]):
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
                    if provision and (record.credential_revision(provision["entry"]) != account_revision
                                      or (chosen, provision["entry"]) in current.released_entries):
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
        receipt_stage = None
        result_steps = 0
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
                if session is not None and write_approval_required:
                    raise ListingError("write_approval_required")
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
            if receipt:
                operation_data = [chosen, entry, binding.action.result_request]
                if provision:
                    operation_data.append(provision)
                digest = sha256(encode(operation_data)).hexdigest()

                def claim():
                    failure = self.activity.claim_write(token.id, receipt, token.generation,
                                                        chosen, entry, credential_revision, digest,
                                                        secondary_entry=provision["entry"] if provision else None)
                    if failure:
                        raise ListingError(failure)
                    return True

                if not guard(lambda: live(claim)):
                    raise ListingError("revoked")
                receipt_stage = "pending"
            if certificate_pin and not review_policy:
                with self.workspace.mutex:
                    certificate_expected = self.grants.result_certificate_pins(
                        self.grants.records[token.id], chosen, entry, credential_revision, usage_origin(binding.action.url))
                    certificate_trusted = bool(certificate_expected) and all(
                        pin == certificate_pin for pin in certificate_expected)
                    certificate_committed = certificate_trusted
                    review_usage = not certificate_trusted
                    remember_certificate = not certificate_trusted
                    if review_usage:
                        key = (token.id, token.generation, chosen, entry, credential_revision,
                               usage_origin(binding.action.url), certificate_pin)
                        if key in self.certificate_reviews:
                            raise ListingError("busy")
                        self.certificate_reviews.add(key)
                        certificate_reservation = key
            if review_usage and approved_step is None:
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
                    if provision:
                        scope = (f"Admin credential: {scope[0]} ({entry})",
                                 "Account credential: " + " › ".join(
                                     part for part in (registration.name, *account_labels) if part)
                                 + f" ({provision['entry']})",
                                 "The receiving service may store the account password. "
                                 "Approve only if this is the intended account and service.",
                                 f"Private {provision['body_type']} fields: " + ", ".join(
                                     f"{target} from account {source}" for source, target in provision["fields"].items()))
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
                            if remember_certificate:
                                scope += ("Verify this certificate fingerprint. Approving also trusts this certificate for this token, entry and destination. Future requests follow your Auto Approve settings. A changed certificate requires review again.",)
                            elif write_once and certificate_pin and not certificate_trusted:
                                scope += ("Verify this certificate fingerprint before approving this write. Trust applies only to this operation.",)
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
                                  trusts_certificate=remember_certificate, write_once=write_once,
                                  provision_account=provision is not None)
                result = self.approvals.wait(ticket, lambda: guard(live))
                if result != "approved":
                    raise ListingError(result)
            decision = "Approved token"
            if provision:
                decision = "Approved account provisioning once"
            elif approved_step:
                decision = "Approved in workflow review"
            elif write_once:
                decision = "Approved write once"
            elif remember_certificate:
                decision = "Approved once; trust certificate on verified dispatch"
            elif review_usage:
                decision = "Approved once"
            self.activity.authorize(event, decision)
            if not guard(live):
                raise ListingError("revoked")
            if operation == "list_vaults":
                result = {"vaults": [{"id": key, "name": name} for key, name in registered.items()]}
            elif operation == "list_entries":
                result = self._entries(token, session, chosen, fields)
            else:
                def gate(send):
                    def audit_and_send():
                        nonlocal dispatch_started, certificate_committed, receipt_stage, result_steps
                        if not dispatch_started:
                            if remember_certificate:
                                # The trusted worker reaches this gate only after
                                # TLS has verified the exact reviewed fingerprint.
                                # Persist under the same live guard as dispatch.
                                self.grants.trust_result_certificate(
                                    token.id, token.generation, chosen, entry, credential_revision,
                                    usage_origin(binding.action.url), certificate_pin, certificate_expected)
                                certificate_committed = True
                            self.activity.dispatched(event)
                            dispatch_started = True
                        if receipt:
                            result_steps += 1
                            if result_steps == (2 if "login" in workflow else 1):
                                self.activity.advance_write(token.id, receipt, "pending", "dispatching")
                                receipt_stage = "dispatching"
                        send()
                    return guard(lambda: dispatch(audit_and_send))

                if binding.action.kind == ActionType.RESULTS:
                    username_allowed = any((s.vault, s.entry) == (chosen, entry) and s.username for s in token.scope)
                    options = {"allow_username": username_allowed}
                    if provision:
                        options["provision"] = provision
                    result = session.worker.use(binding.action, gate, **options)
                    captured = None
                    if approved_step:
                        result, captured = self.workflows.capture(*approved_step, result)
                    if receipt_stage == "dispatching":
                        self.activity.advance_write(token.id, receipt, "dispatching", result["outcome"],
                                                    result.get("http_status"), captured_id=captured)
                        receipt_stage = None
                        if captured is not None:
                            self.workflows.remember(*approved_step, captured)
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
            # Older saved-action callers accept an uncertain write response.
            # Keep the observed status in Activity for the owner.
            frame = encode({"outcome": "uncertain"} if usage is None
                           and result.get("outcome") == "acknowledged" else result)
            if len(frame) > RESPONSE_LIMIT:
                raise ListingError("too_large")
            delivered = deliver(frame, guard)
            if (operation == "use_password" and binding.action.kind == ActionType.RESULTS and not delivered):
                self.activity.finish(event, "Results Not Delivered", result.get("http_status"))
                return None
            if operation == "use_password":
                # Already-dispatched remote work can still complete after revocation.
                outcome = {"succeeded": "Succeeded", "failed": "Failed", "dispatched": "Dispatched",
                           "uncertain": "Interrupted · outcome unknown",
                           "acknowledged": "Acknowledged · result unavailable"}[result["outcome"]]
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
            if receipt_stage:
                self.activity.advance_write(token.id, receipt, receipt_stage,
                                            "uncertain" if receipt_stage == "dispatching" else "not_sent")
            if certificate_reservation is not None:
                with self.workspace.mutex:
                    self.certificate_reviews.discard(certificate_reservation)

    def _write_status(self, credential, uid, receipt, live, deliver):
        with self.workspace.mutex:
            if not live():
                raise ListingError("revoked")
            token = self.grants.authenticate(credential, uid)
            self._charge_request(token.verifier, uid, active=token.status == "active")
            row = self.activity.write_receipt(token.id, receipt)
            generation = self.workspace.generation
            session = self.workspace.session(row["vault"]) if row is not None else None

        def guard(effect):
            with self.workspace.mutex:
                current = self.grants.records.get(token.id)
                if (self.workspace.paused or self.workspace.generation != generation or row is None
                        or current is None or current.status != "active"):
                    return False
                if row["generation"] != current.generation:
                    return False
                registration = self.workspace.registrations.get(row["vault"])
                if (registration is None or session is None or self.workspace.session(row["vault"]) is not session
                        or registration.credential_revision(row["entry"]) != row["revision"]):
                    return False
                return effect()

        if not guard(live):
            raise ListingError("ineligible")
        result = {"id": receipt, "status": row["stage"]}
        if row["http_status"] is not None:
            result["http_status"] = row["http_status"]
        if not deliver(encode(result), guard):
            raise ListingError("revoked")
        return None

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
