"""One owner decision authorizes a short, task-token-bound guest console."""
from dataclasses import dataclass, replace
import json
from threading import Thread
from time import monotonic, sleep, time

from .access_settings import uuid_text
from .activity import entry_target_labels
from .approvals import Approval
from .console_request import CONSOLE_SECONDS, parse_console
from .console_transport import validate_inputs
from .grants import verifier
from .protocol import CONSOLE_OPERATIONS, ListingError, encode
from .workspace import new_id


MAX_CONSOLES = 4


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


class ConsoleAccess:
    def __init__(self, broker):
        self.broker = broker
        self.workspace = broker.workspace
        self.activity = broker.activity
        self.sessions = {}

    def current(self, grant):
        token = self.broker.grants.records.get(grant.token_id)
        registration = self.workspace.registrations.get(grant.vault)
        return (monotonic() < grant.expires and not self.workspace.paused
                and self.workspace.generation == grant.generation
                and token is not None and token.status == "active" and token.generation == grant.token_generation
                and self.workspace.session(grant.vault) is grant.session and registration is not None
                and registration.credential_revision(grant.entry) == grant.credential_revision)

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

    def handle(self, operation, keys, payload, uid, context, live, dispatch, deliver):
        credential = payload.get("credential")
        try:
            if isinstance(credential, str) and credential and credential in encode(
                    {key: value for key, value in payload.items() if key != "credential"}).decode("ascii"):
                raise ValueError
            if operation == "console_open" and keys == {"vault", "entry", "request"}:
                vault, entry = uuid_text(payload["vault"]), uuid_text(payload["entry"])
                descriptor = parse_console(payload["request"])
            elif operation in CONSOLE_OPERATIONS - {"console_open"}:
                if keys != ({"console", "events"} if operation == "console_input" else {"console"}):
                    raise ValueError
                identifier = uuid_text(payload["console"])
                events = validate_inputs(payload["events"]) if operation == "console_input" else None
            else:
                raise ValueError
        except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
            raise ListingError("invalid_request") from None

        with self.workspace.mutex:
            if not live():
                raise ListingError("revoked")
            if self.workspace.paused:
                raise ListingError("paused")
            token = self.broker.grants.authenticate(credential, uid)
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
                if not any((scope.vault, scope.entry, scope.use_revision) == (vault, entry, revision)
                           and {"https_results", "https_body"} <= set(scope.uses)
                           and origin in scope.origins for scope in token.scope):
                    raise ListingError("ineligible")
                if session.worker.available is False:
                    raise ListingError("ineligible")
                if len(self.sessions) >= MAX_CONSOLES:
                    raise ListingError("busy")
                identifier = new_id()
                grant = ConsoleGrant(token.id, token.generation, self.workspace.generation,
                                     vault, entry, revision, origin, descriptor["socket"]["path"], session,
                                     monotonic() + CONSOLE_SECONDS + self.broker.approvals.timeout)
                self.sessions[identifier] = grant
            else:
                grant = self.sessions.get(identifier)
                if grant is None or grant.token_id != token.id or not grant.ready:
                    raise ListingError("console_closed")
                registration = self.workspace.registrations.get(grant.vault)
                session = grant.session
            folder, title = entry_target_labels(session.entries, grant.entry)
            label = {"console_open": "Open Guest Console", "console_view": "View Guest Console",
                     "console_input": "Send Guest Console Input", "console_close": "Close Guest Console"}[operation]
            scope = f"Console {identifier} · {grant.endpoint}"
            if operation == "console_input":
                scope += f" · {len(events)} input events"
            try:
                event = self.activity.begin(uid, context, label, grant.origin, grant.entry,
                                            vault=registration.name if registration else None, vault_id=grant.vault,
                                            token=token.id, agent=token.identity, project=token.project,
                                            folder=folder, entry_title=title, scope=scope)
            except BaseException:
                if operation == "console_open":
                    self.sessions.pop(identifier, None)
                raise

        def guard(effect):
            with self.workspace.mutex:
                if self.sessions.get(identifier) is not grant or not self.current(grant):
                    return False
                return effect()

        open_started = False
        keep_console = False
        dispatched = False
        try:
            if operation == "console_open":
                details = (" › ".join(part for part in (registration.name, folder, title) if part),
                           f"Private login: POST {descriptor['login']['path']}",
                           f"Approve this one-time POST: {descriptor['connect']['path']}",
                           f"Guest console: {descriptor['socket']['path']}",
                           f"Allow screenshots and keyboard/mouse input for up to {CONSOLE_SECONDS // 60} minutes.",
                           "Review the target guest and the POST payload below. Input can change the guest, and the guest screen may contain private data.",
                           "Exact connection details:\n" + json.dumps(descriptor, ensure_ascii=True, indent=2))
                ticket = Approval(event, uid, context, label, details, grant.origin,
                                  monotonic() + self.broker.approvals.timeout, identity=token.identity,
                                  project=token.project, requested=time(), opens_console=True)
                result = self.broker.approvals.wait(ticket, lambda: guard(live))
                if result != "approved":
                    raise ListingError(result)
            self.activity.authorize(event, "Approved console once" if operation == "console_open" else "Approved console session")
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
                open_started = True
            elif operation == "console_input":
                request["events"] = events
            result = session.worker.console(request, gate)
            if result.get("error"):
                raise ListingError("console_closed" if result["error"] == "console_closed" else "console_failed")
            if operation == "console_open":
                # Binding state changes under the same predicate as authorization.
                def publish():
                    nonlocal grant
                    grant = replace(grant, ready=True, expires=monotonic() + CONSOLE_SECONDS)
                    self.sessions[identifier] = grant
                    return True
                if not guard(lambda: live(publish)):
                    raise ListingError("revoked")
                Thread(target=self.watch, args=(identifier, grant), daemon=True).start()
                result = {"console": identifier, "expires_in": CONSOLE_SECONDS}
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
