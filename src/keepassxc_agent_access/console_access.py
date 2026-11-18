"""Owner decisions for guest consoles and exact, short-lived reconnects."""
from dataclasses import dataclass, replace
from hashlib import sha256
import json
from math import ceil
from threading import Thread
from time import monotonic, sleep, time

from .access_settings import uuid_text
from .activity import entry_target_labels
from .approvals import Approval
from .console_request import parse_console
from .console_transport import validate_inputs
from .grants import verifier
from .protocol import CONSOLE_OPERATIONS, CONSOLE_SECONDS, MAX_CONSOLE_REUSE_MINUTES, ListingError, encode
from .workspace import new_id


MAX_CONSOLES = 4
MAX_REUSABLE_CONSOLES = 32


@dataclass(frozen=True)
class ConsoleGrant:
    token_id: str
    token_generation: int
    generation: int
    vault: str
    entry: str
    credential_revision: str
    origin: str
    endpoint: str
    session: object
    expires: float
    ready: bool = False
    workflow_id: str | None = None
    workflow_step: str | None = None
    trusted_pin: str | None = None


class ConsoleAccess:
    def __init__(self, broker):
        self.broker = broker
        self.workspace = broker.workspace
        self.activity = broker.activity
        self.sessions = {}
        self.reusable = {}

    def current(self, grant):
        token = self.broker.grants.records.get(grant.token_id)
        registration = self.workspace.registrations.get(grant.vault)
        return (monotonic() < grant.expires and not self.workspace.paused
                and self.workspace.generation == grant.generation
                and token is not None and token.status == "active" and token.generation == grant.token_generation
                and self.workspace.session(grant.vault) is grant.session and registration is not None
                and registration.credential_revision(grant.entry) == grant.credential_revision
                and (grant.trusted_pin is None or self.broker.grants.result_certificate_trusted(
                    token, grant.vault, grant.entry, grant.credential_revision, grant.origin, grant.trusted_pin)))

    @staticmethod
    def discard_worker_console(identifier, grant):
        # Disposal cannot read pixels or send guest input. It also works after
        # owner revocation, so a disconnected request cannot leave a live socket.
        def close(send):
            send()
            return True

        worker = grant.session.worker
        while worker.available and monotonic() < grant.expires:
            try:
                worker.console({"operation": "console_close", "entry": grant.entry, "console": identifier}, close)
                return
            except ListingError as error:
                if error.code != "busy":
                    return  # An unavailable worker also has a socket deadline.
                sleep(.05)

    def watch(self, identifier, grant):
        while True:
            with self.workspace.mutex:
                if self.sessions.get(identifier) is not grant:
                    return
                if not self.current(grant):
                    del self.sessions[identifier]
                    break
            sleep(.25)
        self.discard_worker_console(identifier, grant)

    def handle(self, operation, keys, payload, uid, context, live, dispatch, deliver, *, approved_step=None):
        credential = payload.get("credential")
        status_only = False
        requested_minutes = 0
        reuse_until = None
        reuse_key = None
        try:
            if isinstance(credential, str) and credential and credential in encode(
                    {key: value for key, value in payload.items() if key != "credential"}).decode("ascii"):
                raise ValueError
            required = {"vault", "entry", "request"}
            if operation == "console_open" and required <= keys <= required | {"reuse_minutes"}:
                vault, entry = uuid_text(payload["vault"]), uuid_text(payload["entry"])
                descriptor = parse_console(payload["request"])
                if "reuse_minutes" in keys:
                    requested_minutes = payload["reuse_minutes"]
                    if (type(requested_minutes) is not int or not 1 <= requested_minutes <= MAX_CONSOLE_REUSE_MINUTES
                            or "certificate_sha256" not in descriptor):
                        raise ValueError
            elif operation in CONSOLE_OPERATIONS - {"console_open"}:
                expected = {"console", "events"} if operation == "console_input" else {"console"}
                if operation == "console_view" and "status_only" in keys:
                    if payload["status_only"] is not True:
                        raise ValueError
                    expected.add("status_only")
                    status_only = True
                if keys != expected:
                    raise ValueError
                identifier = uuid_text(payload["console"])
                events = validate_inputs(payload["events"]) if operation == "console_input" else None
            else:
                raise ValueError
        except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
            raise ListingError("invalid_request") from None

        with self.workspace.mutex:
            auto_open = False
            if not live():
                raise ListingError("revoked")
            if self.workspace.paused:
                raise ListingError("paused")
            token = self.broker.grants.authenticate(
                credential, uid, allow_workflow=approved_step is not None or operation != "console_open")
            self.broker._charge_request(token.verifier, uid, active=token.status == "active")
            if token.status != "active":
                raise ListingError("ineligible")
            if operation == "console_open":
                registration = self.workspace.registrations.get(vault)
                session = self.workspace.session(vault) if registration else None
                if session is None:
                    raise ListingError("ineligible")
                revision = registration.credential_revision(entry)
                origin = descriptor["origin"]
                matching = tuple(scope for scope in token.scope
                                 if (scope.vault, scope.entry, scope.use_revision) == (vault, entry, revision)
                                 and {"https_results", "https_body"} <= set(scope.uses) and origin in scope.origins)
                if not matching:
                    raise ListingError("ineligible")
                if session.worker.available is False:
                    raise ListingError("ineligible")
                if len(self.sessions) >= MAX_CONSOLES:
                    raise ListingError("busy")
                identifier = new_id()
                grant = ConsoleGrant(token.id, token.generation, self.workspace.generation,
                                     vault, entry, revision, origin, descriptor["socket"]["path"], session,
                                     monotonic() + CONSOLE_SECONDS + self.broker.approvals.timeout)
                reuse_minutes = 0
                if approved_step:
                    workflow, step = approved_step
                    self.broker.workflows.claim_console(workflow, step)
                    grant = replace(grant, workflow_id=workflow.id, workflow_step=step)
                    reuse_until = workflow.deadline
                elif self.workspace.guest_auto_approval_enabled(operation) and "certificate_sha256" in descriptor:
                    digest = sha256(encode(descriptor)).hexdigest()
                    reuse_key = (token.id, vault, entry, digest)
                    self.reusable = {key: permit for key, permit in self.reusable.items() if self.current(permit)}
                    if permit := self.reusable.get(reuse_key):
                        reuse_until = permit.expires
                        grant = replace(grant, trusted_pin=permit.trusted_pin)
                    else:
                        if len(self.reusable) + len(self.sessions) < MAX_REUSABLE_CONSOLES:
                            reuse_minutes = requested_minutes
                        pin = descriptor["certificate_sha256"]
                        auto_open = (self.workspace.scoped_auto_approval_enabled("guest_first_use")
                                     and any("https" in scope.uses for scope in matching)
                                     and self.broker.grants.result_certificate_trusted(token, vault, entry, revision, origin, pin))
                        if auto_open:
                            grant = replace(grant, trusted_pin=pin)
                            if reuse_minutes:
                                reuse_until = monotonic() + reuse_minutes * 60
                self.sessions[identifier] = grant
            else:
                grant = self.sessions.get(identifier)
                if (grant is None or grant.token_id != token.id or not grant.ready
                        or token.workflow is not None and token.workflow[0] != grant.workflow_id):
                    raise ListingError("console_closed")
                registration = self.workspace.registrations.get(grant.vault)
                session = grant.session
            folder, title = entry_target_labels(session.entries, grant.entry)
            label = {"console_open": "Open Guest Console", "console_view": "View Guest Console",
                     "console_input": "Send Guest Console Input", "console_close": "Close Guest Console"}[operation]
            if status_only:
                label = "Check Guest Console"
            scope = f"Console {identifier} · {grant.endpoint}"
            if reuse_key is not None and (reuse_until is not None or reuse_minutes):
                scope += f" · Connection SHA-256 {reuse_key[-1]}"
            if operation == "console_input":
                scope += f" · {len(events)} input events"
            try:
                event = self.activity.begin(uid, context, label, grant.origin, grant.entry,
                                            vault=registration.name if registration else None, vault_id=grant.vault,
                                            token=token.id, agent=token.identity, project=token.project,
                                            folder=folder, entry_title=title, scope=scope,
                                            workflow_id=grant.workflow_id, workflow_step=grant.workflow_step)
            except BaseException:
                if operation == "console_open":
                    self.sessions.pop(identifier, None)
                raise

        def guard(effect):
            with self.workspace.mutex:
                if self.sessions.get(identifier) is not grant or not self.current(grant):
                    return False
                if reuse_until is not None and monotonic() >= reuse_until:
                    return False
                return effect()

        open_started = False
        keep_console = False
        dispatched = False
        try:
            authorization = "Approved console session"
            if operation == "console_open" and not auto_open and reuse_until is None:
                details = (" › ".join(part for part in (registration.name, folder, title) if part),
                           f"Private login: POST {descriptor['login']['path']}",
                           f"Console setup: POST {descriptor['connect']['path']}",
                           f"Guest console: {descriptor['socket']['path']}",
                           f"Allow screenshots and keyboard/mouse input for up to {CONSOLE_SECONDS // 60} minutes.",
                           "Review the target guest and the POST payload below. Input can change the guest, and the guest screen may contain private data.",
                           "Exact connection details:\n" + json.dumps(descriptor, ensure_ascii=True, indent=2))
                ticket = Approval(event, uid, context, label, details, grant.origin,
                                  monotonic() + self.broker.approvals.timeout, identity=token.identity,
                                  project=token.project, requested=time(), opens_console=True, reuse_minutes=reuse_minutes)
                result = self.broker.approvals.wait(ticket, lambda: guard(live))
                if result != "approved":
                    raise ListingError(result)
                if reuse_minutes:
                    reuse_until = monotonic() + reuse_minutes * 60
                    authorization = f"Owner approved console for {reuse_minutes} min"
                else:
                    authorization = "Approved console once"
            elif operation == "console_open":
                authorization = (approved_step[0].step_authorization if approved_step else
                                 "Auto approved scoped console" if auto_open else "Used approved console connection")
            self.activity.authorize(event, authorization)
            def gate(send):
                def authorize():
                    nonlocal dispatched
                    if not dispatched:
                        self.activity.dispatched(event)
                        dispatched = True
                    send()
                return guard(lambda: dispatch(authorize))

            if not guard(live):
                raise ListingError("revoked")
            request = {"operation": operation, "console": identifier, "entry": grant.entry}
            if operation == "console_open":
                request["request"] = descriptor
                if reuse_until is not None:
                    request["expires_at"] = reuse_until
                open_started = True
            elif operation == "console_input":
                request["events"] = events
            elif status_only:
                request["status_only"] = True
            result = session.worker.console(request, gate)
            if result.get("error"):
                raise ListingError("console_closed" if result["error"] == "console_closed" else "console_failed")
            if operation == "console_open":
                # Binding state changes under the same predicate as authorization.
                def publish():
                    nonlocal grant
                    expires = monotonic() + CONSOLE_SECONDS
                    if reuse_until is not None:
                        expires = min(expires, reuse_until)
                    grant = replace(grant, ready=True, expires=expires)
                    self.sessions[identifier] = grant
                    if reuse_minutes:
                        self.reusable[reuse_key] = replace(grant, ready=False, expires=reuse_until)
                    return True
                if not guard(lambda: live(publish)):
                    raise ListingError("revoked")
                Thread(target=self.watch, args=(identifier, grant), daemon=True).start()
                result = {"console": identifier, "expires_in": max(1, ceil(grant.expires - monotonic()))}
                if requested_minutes:
                    result["reuse_expires_in"] = max(0, ceil(reuse_until - monotonic())) if reuse_until else 0
            if not deliver(encode(result), guard):
                raise ListingError("revoked")
            self.activity.finish(event, "Succeeded")
            if operation == "console_open" or operation == "console_input":
                with self.workspace.mutex:
                    self.broker.grants.used(token)
            if operation == "console_close":
                with self.workspace.mutex:
                    self.sessions.pop(identifier, None)
            keep_console = True
            return None
        except ListingError as error:
            if operation != "console_open" and error.code in ("console_closed", "console_failed"):
                with self.workspace.mutex:
                    self.sessions.pop(identifier, None)
            outcome = {"declined": "Denied", "expired": "Expired", "revoked": "Revoked"}.get(error.code, "Failed")
            if operation == "console_input" and dispatched:
                outcome = "Interrupted · outcome unknown"
            self.activity.finish(event, outcome)
            raise
        finally:
            if operation == "console_open" and not keep_console:
                with self.workspace.mutex:
                    self.sessions.pop(identifier, None)
                if open_started and dispatched:
                    self.discard_worker_console(identifier, grant)
