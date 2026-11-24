"""Review known HTTPS writes together and bind typed results between them."""

from dataclasses import dataclass
from hashlib import sha256
import json
from math import ceil
import re
from time import monotonic, time
from uuid import UUID, uuid5

from .access_settings import Destination, label, uuid_text
from .activity import entry_target_labels
from .approvals import Approval
from .console_request import parse_console
from .guest_request import parse_guest_request
from .grants import verifier
from .protocol import ListingError, decode, encode
from .result_delivery import parse_result_usage


STEP = re.compile(r"[a-z][a-z0-9_-]{0,31}")
REFERENCE = re.compile(r"\{([a-z][a-z0-9_-]{0,31})\}")
MAX_STEPS = 8
MAX_WORKFLOWS = 16


@dataclass(frozen=True)
class Step:
    name: str
    request: dict
    result: dict
    capture: bool
    kind: str = "write"
    command: str | None = None
    expected_id: int | None = None

    def resolve(self, common, values):
        def binding(name):
            if not isinstance(name, str) or name not in values:
                raise ListingError("dependency_unavailable")
            return values[name]

        def body(value):
            if isinstance(value, dict):
                if set(value) == {"$from"}:
                    return binding(value["$from"])
                return {key: body(item) for key, item in value.items()}
            if isinstance(value, list):
                return [body(item) for item in value]
            return value

        def resolve_request(raw):
            request = dict(raw)
            parts = request["path"].split("/")
            for index, part in enumerate(parts):
                if match := REFERENCE.fullmatch(part):
                    parts[index] = str(binding(match[1]))
                elif "{" in part or "}" in part or "%7b" in part.lower() or "%7d" in part.lower():
                    raise ValueError("Only whole path segments may reference approved step results.")
            request["path"] = "/".join(parts)
            for field in ("json", "query", "form"):
                if field in request:
                    content = request[field]
                    if not isinstance(content, dict):
                        raise ValueError("Workflow request bodies and parameters must be objects.")
                    request[field] = body(content)
                    if field in ("query", "form"):
                        request[field] = {key: str(item) if type(item) is int else item
                                          for key, item in request[field].items()}
            return request

        if self.kind == "console":
            return parse_console({**common, "connect": resolve_request(self.request["connect"]),
                                  "socket": resolve_request(self.request["socket"])})
        if self.kind == "guest":
            descriptor = {**common, **self.request}
            for stage in ("submit", "poll"):
                descriptor[stage] = {**descriptor[stage], "request": resolve_request(descriptor[stage]["request"])}
            parse_guest_request(descriptor).start(self.command)
            return descriptor
        request = resolve_request(self.request)
        return parse_result_usage({"type": "https_results", **common, "request": request,
                                   "result": self.result, "approve_write_once": True})


def parse_workflow(raw):
    data = decode(encode(raw))
    required = {"id", "vault", "entry", "origin", "certificate_sha256", "steps"}
    if not isinstance(data, dict) or not required <= data.keys() <= required | {"login", "minutes"}:
        raise ValueError("Provide a pinned workflow and its ordered steps.")
    identifier, vault, entry = (uuid_text(data[key]) for key in ("id", "vault", "entry"))
    minutes = data.get("minutes", 30)
    if type(minutes) is not int or not 1 <= minutes <= 60:
        raise ValueError("Choose a workflow window from 1 to 60 minutes.")
    common = {key: data[key] for key in ("origin", "certificate_sha256", "login") if key in data}
    if not isinstance(data["steps"], list) or not 1 <= len(data["steps"]) <= MAX_STEPS:
        raise ValueError("Provide one to eight approved steps.")
    values = {}
    steps = {}
    for raw_step in data["steps"]:
        if not isinstance(raw_step, dict):
            raise ValueError("Provide a named workflow step.")
        kind = raw_step.get("kind", "write")
        required_step = {"name", "request"}
        allowed_step = {
            "write": (required_step | {"result"}, {"capture_id", "kind", "expected_id"}),
            "console": (required_step | {"kind"}, set()),
            "guest": (required_step | {"kind", "command"}, set()),
        }.get(kind)
        if allowed_step is None or not allowed_step[0] <= raw_step.keys() <= allowed_step[0] | allowed_step[1]:
            raise ValueError("Provide the name, request and selected result fields.")
        name, capture = raw_step["name"], raw_step.get("capture_id", False)
        if not isinstance(name, str) or not STEP.fullmatch(name) or name in steps or type(capture) is not bool:
            raise ValueError("Use distinct names for workflow steps.")
        expected = raw_step.get("expected_id")
        if "expected_id" in raw_step and (not capture or type(expected) is not int or not 1 <= expected < 2**53):
            raise ValueError("Set an expected positive integer for a captured ID.")
        request = raw_step["request"]
        if not isinstance(request, dict) or kind == "console" and set(request) != {"connect", "socket"}:
            raise ValueError("Provide an exact step request.")
        if kind == "guest" and set(request) & {"origin", "login", "certificate_sha256"}:
            raise ValueError("All workflow steps share the same origin, certificate and sign-in.")
        step = Step(name, request, raw_step.get("result", {}), capture, kind, raw_step.get("command"), expected)
        try:
            request = step.resolve(common, values)
        except ListingError:
            raise ValueError("References must identify a preceding step that captures an ID.") from None
        if capture and "scalar" not in request.data["result"]:
            raise ValueError("A captured ID must come from a scalar result.")
        if capture:
            values[name] = expected if expected is not None else 2**53 - 1
        steps[name] = step
    digest = sha256(encode(data)).hexdigest()
    return identifier, vault, entry, minutes, common, steps, digest


def receipt_id(identifier, step):
    return str(uuid5(UUID(identifier), step))


@dataclass
class Workflow:
    id: str
    token: str
    token_generation: int
    workspace_generation: int
    vault: str
    entry: str
    revision: str
    session: object
    deadline: float
    common: dict
    steps: dict
    captures: dict
    opened: set
    trusted_endpoint: tuple[str, str] | None = None
    auto_approved: bool = False
    pending_pin: tuple[str, str, tuple] | None = None

    @property
    def step_authorization(self):
        return "Auto approved workflow step" if (self.trusted_endpoint or self.auto_approved) else "Approved in workflow review"


class WorkflowAccess:
    def __init__(self, broker):
        self.broker = broker
        self.workspace = broker.workspace
        self.approvals = broker.approvals
        self.activity = broker.activity
        self.active = {}
        self.pending = set()

    def current(self, workflow, draft=None, *, allow_paused=False):
        token = self.broker.grants.records.get(workflow.token)
        if token is None and draft is not None:
            try:
                self.broker.grants.can_issue_workflow(draft)
            except ListingError:
                return False
            token = draft
        record = self.workspace.registrations.get(workflow.vault)
        return ((not self.workspace.paused or allow_paused) and monotonic() < workflow.deadline
                and self.workspace.generation == workflow.workspace_generation
                and token is not None and token.status == "active" and token.generation == workflow.token_generation
                and record is not None and record.credential_revision(workflow.entry) == workflow.revision
                and self.workspace.session(workflow.vault) is workflow.session
                and (workflow.trusted_endpoint is None or self.broker.grants.result_certificate_trusted(
                    token, workflow.vault, workflow.entry, workflow.revision, *workflow.trusted_endpoint)))

    def propose(self, raw, credential, uid, context, live, deliver, *, enrollment=None):
        identifier, vault, entry, minutes, common, steps, digest = parse_workflow(raw)
        origin = Destination.parse(common["origin"]).url
        needed = {"https_results", "https_body"} if "login" in common else {"https_results"}
        with self.workspace.mutex:
            if not live():
                raise ListingError("revoked")
            registration = self.workspace.registrations.get(vault)
            session = self.workspace.session(vault) if registration else None
            if session is None:
                raise ListingError("ineligible")
            grants = self.broker.grants
            hashed = verifier(credential)
            draft = None
            if enrollment is not None and hashed not in grants.credentials:
                self.broker._charge_request(hashed, uid, active=False)
                draft = grants.workflow_candidate(credential, uid, enrollment, context,
                                                  {"vault": vault, "entry": entry, "uses": sorted(needed),
                                                   "origins": [origin]}, (identifier, digest))
                token = draft
            else:
                token = grants.authenticate(credential, uid, allow_workflow=True)
                self.broker._charge_request(hashed, uid, active=token.status == "active")
                if enrollment is not None and (not token.workflow or not isinstance(enrollment, dict)
                        or set(enrollment) != {"identity", "project"}
                        or (label(enrollment["identity"]).strip(), label(enrollment["project"])) != (
                            token.identity, token.project)):
                    raise ListingError("ineligible")
            if token.status != "active":
                raise ListingError("ineligible")
            resume_access = self.workspace.paused and draft is not None
            if self.workspace.paused and not resume_access:
                raise ListingError("paused")
            if token.workflow and token.workflow != (identifier, digest):
                raise ListingError("receipt_conflict")
            revision = registration.credential_revision(entry)

            def matching_scopes(active_token):
                return tuple(scope for scope in active_token.scope
                             if (scope.vault, scope.entry, scope.use_revision) == (vault, entry, revision)
                             and needed <= set(scope.uses) and origin in scope.origins)

            matching = matching_scopes(token)
            if not matching and draft is None:
                refreshed = grants.refresh_rotated_credential(token.id, vault, entry, revision)
                if refreshed is not None:
                    token = refreshed
                    matching = matching_scopes(token)
            if not matching:
                raise ListingError("ineligible")
            guest_operations = {"guest": "guest_run", "console": "console_open"}
            if draft is not None:
                expected_pins, cert_trusted, auto_pin = (None,), False, self.workspace.scoped_auto_approval_enabled("tls_first_pin")
            else:
                expected_pins, cert_trusted, auto_pin = grants.result_certificate_auto_pin(
                    token, vault, entry, revision, origin, common["certificate_sha256"])
            steps_auto = all(step.kind == "write" or (
                self.workspace.scoped_auto_approval_enabled("guest_first_use")
                and self.workspace.guest_auto_approval_enabled(guest_operations[step.kind]))
                             for step in steps.values())
            if draft is None and token.workflow is None:
                automatic = (
                    any("https" in scope.uses for scope in matching)
                    and self.workspace.scoped_auto_approval_enabled("workflow")
                    and (cert_trusted or auto_pin)
                    and steps_auto
                )
            else:
                automatic = (
                    not self.workspace.paused
                    and self.workspace.token_auto_approval_enabled("auto_approve_tokens")
                    and self.workspace.token_auto_approval_enabled("auto_approve_token_credential_uses")
                    and self.workspace.scoped_auto_approval_enabled("workflow")
                    and (cert_trusted or auto_pin)
                    and steps_auto
                )
            self.active = {key: value for key, value in self.active.items() if self.current(value)}
            key = (token.id, identifier)
            pending_key = (hashed, None if draft else identifier)
            if len(self.active) + len(self.pending) >= MAX_WORKFLOWS or pending_key in self.pending:
                raise ListingError("busy")
            if draft is None:
                failure = self.activity.claim_workflow(token.id, identifier, digest)
                if failure:
                    raise ListingError(failure)
            if key in self.active:
                raise ListingError("receipt_exists")
            review_deadline = monotonic() + self.approvals.timeout
            pending_pin = (origin, common["certificate_sha256"], expected_pins) if (
                automatic and not cert_trusted and auto_pin) else None
            workflow = Workflow(identifier, token.id, token.generation, self.workspace.generation, vault, entry,
                                revision, session, review_deadline + 1, common, steps, {}, set(),
                                (origin, common["certificate_sha256"]) if (automatic and cert_trusted) else None,
                                auto_approved=automatic, pending_pin=pending_pin)
            folder, name = entry_target_labels(session.entries, entry)
            action = "Review Workflow"
            event = self.activity.begin(uid, context, action, origin, entry, vault=registration.name, vault_id=vault,
                                        token=token.id, agent=token.identity, project=token.project, folder=folder,
                                        entry_title=name, scope=f"{len(steps)} steps · SHA-256 {digest}", workflow_id=identifier)
            self.pending.add(pending_key)

        def guard(effect):
            with self.workspace.mutex:
                return self.current(workflow, draft, allow_paused=resume_access) and effect()

        enrollment_detail = ("Register this identity for the exact workflow and its status checks.",) if draft else ()
        details = (*enrollment_detail,
                   " › ".join(part for part in (registration.name, folder, name) if part) + f" ({entry})",
                   f"Review these {len(steps)} exact steps. Each can run once within {minutes} minutes.",
                   "With Guest Consoles auto approval enabled, a listed console can reconnect within this window.",
                   "Independent steps can run in any order.",
                   "A result reference uses an integer supplied by an earlier write to this service. "
                   "Check that the reviewed paths and fields identify the intended resources.",
                   "Connection and certificate:\n" + json.dumps(common, ensure_ascii=True, indent=2),
                   *tuple(json.dumps({"name": step.name, "kind": step.kind, "request": step.request,
                                      **({"result": step.result, "capture_id": step.capture,
                                          **({"expected_id": step.expected_id} if step.expected_id is not None else {})}
                                         if step.kind == "write"
                                         else {"command": step.command} if step.kind == "guest" else {})},
                                     ensure_ascii=True, indent=2)
                          for step in steps.values()))
        ticket = Approval(event, uid, context, action, details, origin, review_deadline, identity=token.identity,
                          project=token.project, requested=time(), workflow_review=True,
                          workflow_enrollment=draft is not None, resume_access=resume_access)
        outcome = "Revoked"
        try:
            if not automatic:
                answer = self.approvals.wait(ticket, lambda: guard(live))
                if answer != "approved":
                    outcome = {"declined": "Denied", "expired": "Expired"}.get(answer, "Revoked")
                    raise ListingError(answer)
            self.activity.authorize(event, "Auto approved scoped workflow" if automatic else
                                    "Owner approved workflow-only token" if draft else "Owner approved exact workflow")

            def publish():
                if draft is not None:
                    grants.issue_workflow(draft)
                    failure = self.activity.claim_workflow(token.id, identifier, digest)
                    if failure:
                        raise ListingError(failure)
                for name, step in steps.items():
                    if not step.capture:
                        continue
                    row = self.activity.write_receipt(token.id, receipt_id(identifier, name))
                    if row is None or row["stage"] != "succeeded":
                        continue
                    if (row["vault"], row["entry"], row["generation"], row["revision"]) != (
                            vault, entry, token.generation, revision):
                        continue
                    value = row["captured_id"]
                    if (type(value) is int and 1 <= value < 2**53
                            and (step.expected_id is None or value == step.expected_id)):
                        workflow.captures[name] = value
                workflow.deadline = monotonic() + minutes * 60
                if resume_access:
                    self.workspace.pause(False)
                    workflow.workspace_generation = self.workspace.generation
                self.active[key] = workflow
                return True

            if not guard(lambda: live(publish)):
                raise ListingError("revoked")
            outcome = "Approved"
            deliver(encode(self.detail(workflow)), guard)
        finally:
            with self.workspace.mutex:
                self.pending.discard(pending_key)
            self.activity.finish(event, outcome)

    @staticmethod
    def detail(workflow):
        return {"id": workflow.id, "expires_in": max(1, ceil(workflow.deadline - monotonic())),
                "receipts": {name: receipt_id(workflow.id, name) for name, step in workflow.steps.items()
                             if step.kind != "console"}}

    def status(self, workflow, deliver):
        def guard(effect):
            with self.workspace.mutex:
                return self.current(workflow) and effect()

        if not deliver(encode(self.detail(workflow)), guard):
            raise ListingError("revoked")

    def resolve(self, identifier, name, payload, uid, live):
        with self.workspace.mutex:
            if not live():
                raise ListingError("revoked")
            token = self.broker.grants.authenticate(payload["credential"], uid, allow_workflow=True)
            if token.workflow and token.workflow[0] != identifier:
                raise ListingError("workflow_unavailable")
            workflow = self.active.get((token.id, identifier))
            if workflow is None or not self.current(workflow):
                raise ListingError("workflow_unavailable")
            if name is None:
                self.broker._charge_request(token.verifier, uid, active=True)
                return workflow, None
            if name not in workflow.steps:
                raise ListingError("invalid_request")
            step = workflow.steps[name]
            try:
                descriptor = step.resolve(workflow.common, workflow.captures)
            except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
                raise ListingError("dependency_unavailable") from None
            common = {
                "version": 1, "credential": payload["credential"],
                "context": payload.get("context", {}), "vault": workflow.vault, "entry": workflow.entry,
            }
            receipt = receipt_id(identifier, name)
            if step.kind == "console":
                return workflow, {**common, "operation": "console_open", "request": descriptor}
            if step.kind == "guest":
                return workflow, {**common, "operation": "guest_run", "workflow": descriptor,
                                  "command": step.command, "receipt": receipt}
            return workflow, {**common, "operation": "use_password", "usage": descriptor.data, "receipt": receipt}

    def claim_console(self, workflow, step):
        if not self.current(workflow):
            raise ListingError("revoked")
        if step in workflow.opened and not self.workspace.guest_auto_approval_enabled("console_open"):
            raise ListingError("receipt_exists")
        workflow.opened.add(step)

    def capture(self, workflow, name, result):
        step = workflow.steps[name]
        if not step.capture or result.get("outcome") != "succeeded":
            return result, None
        field = step.result["scalar"]
        values = result.get("data", [])
        value = values[0].get(field) if len(values) == 1 else None
        if (type(value) is not int or not 1 <= value < 2**53
                or step.expected_id is not None and value != step.expected_id):
            return {"outcome": "acknowledged", "http_status": result["http_status"]}, None
        return result, value

    def remember(self, workflow, name, value):
        with self.workspace.mutex:
            if self.current(workflow):
                workflow.captures[name] = value
