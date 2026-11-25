"""Authorize guest commands and keep their remote job IDs private."""

from collections import Counter
from dataclasses import dataclass, replace
from hashlib import sha256
import json
from math import ceil
from time import monotonic, time

from .access_settings import uuid_text
from .activity import entry_target_labels
from .approvals import Approval
from .guest_request import parse_guest_request
from .protocol import ERRORS, ListingError, MAX_GUEST_REUSE_MINUTES, encode
from .usage import usage_action


JOB_SECONDS = 900
MAX_GUEST_JOBS = 32
MAX_JOBS_PER_TOKEN = 8


@dataclass(frozen=True)
class GuestGrant:
    token_id: str
    token_generation: int
    generation: int
    vault: str
    entry: str
    revision: str
    session: object
    expires: float
    workflow_id: str | None = None
    workflow_step: str | None = None
    trusted_endpoint: tuple[str, str] | None = None


class GuestAccess:
    def __init__(self, broker):
        self.broker = broker
        self.workspace = broker.workspace
        self.activity = broker.activity
        self.grants = {}
        self.jobs = {}
        self.pending = Counter()

    @staticmethod
    def login_key(grant, receipt, fingerprint):
        return sha256(encode([grant.token_id, grant.token_generation, grant.generation, grant.vault,
                              grant.entry, grant.revision, receipt, fingerprint])).hexdigest()

    def current(self, grant):
        token = self.broker.grants.records.get(grant.token_id)
        registration = self.workspace.registrations.get(grant.vault)
        return (not self.workspace.paused and monotonic() < grant.expires
                and self.workspace.generation == grant.generation
                and self.broker.grants.is_active(token) and token.revocation_generation == grant.token_generation
                and self.workspace.session(grant.vault) is grant.session and registration is not None
                and registration.credential_revision(grant.entry) == grant.revision
                and (grant.trusted_endpoint is None or self.broker.grants.result_certificate_trusted(
                    token, grant.vault, grant.entry, grant.revision, *grant.trusted_endpoint)))

    def handle(self, operation, keys, payload, uid, context, live, dispatch, deliver, *, approved_step=None):
        credential = payload.get("credential")
        starting = operation == "guest_run"
        receipt = uuid_text(payload["receipt"])
        required = {"receipt", "vault", "entry", "workflow", "command"} if starting else {"receipt"}
        if not required <= keys <= required | ({"reuse_minutes"} if starting else set()):
            raise ValueError
        if starting:
            vault, entry = uuid_text(payload["vault"]), uuid_text(payload["entry"])
            requested_minutes = payload.get("reuse_minutes", 0)
            if type(requested_minutes) is not int or not 0 <= requested_minutes <= MAX_GUEST_REUSE_MINUTES:
                raise ValueError
            workflow = parse_guest_request(payload["workflow"])
            command = payload["command"]
            request = workflow.start(command)
            fingerprint = sha256(encode([workflow.submit.canonical_json, workflow.poll.canonical_json,
                                         workflow.body_type, workflow.command_field, workflow.job_query,
                                         workflow.argument_prefix])).hexdigest()
        with self.workspace.mutex:
            if not live():
                raise ListingError("revoked")
            if self.workspace.paused:
                raise ListingError("paused")
            token = self.broker.grants.authenticate(credential, uid, allow_workflow=approved_step is not None or not starting)
            self.broker._charge_request(token.verifier, uid, active=self.broker.grants.is_active(token))
            if not self.broker.grants.is_active(token):
                raise ListingError("ineligible")
            job_key = (token.id, receipt)
            self.jobs = {key: job for key, job in self.jobs.items() if self.current(job[0])}
            self.grants = {key: permit for key, permit in self.grants.items() if self.current(permit)}
            reused = False
            auto_start = False
            reuse_minutes = 0
            private_job = None
            if starting:
                registration = self.workspace.registrations.get(vault)
                session = self.workspace.session(vault) if registration else None
                if session is None:
                    raise ListingError("ineligible")
                revision = registration.credential_revision(entry)
                needed = {"https_results", "https_body"} if "login" in request.data else {"https_results"}
                def matching_scopes(active_token):
                    return tuple(scope for scope in active_token.scope
                                 if (scope.vault, scope.entry, scope.use_revision) == (vault, entry, revision)
                                 and needed <= set(scope.uses) and request.origin in scope.origins)

                matching = matching_scopes(token)
                if not matching:
                    refreshed = self.broker.grants.refresh_rotated_credential(token.id, vault, entry, revision)
                    if refreshed is not None:
                        token = refreshed
                        matching = matching_scopes(token)
                if not matching:
                    if any((scope.vault, scope.entry) == (vault, entry) and scope.use_revision != revision
                           and needed <= set(scope.uses) and request.origin in scope.origins for scope in token.scope):
                        raise ListingError("credential_changed")
                    raise ListingError("ineligible")
                grant_key = (token.id, vault, entry, fingerprint)
                automatic = not approved_step and self.workspace.guest_auto_approval_enabled("guest_run")
                permit = self.grants.get(grant_key) if automatic else None
                reused = permit is not None
                if automatic and not reused and len(self.grants) + self.pending.total() < MAX_GUEST_JOBS:
                    reuse_minutes = requested_minutes
                grant = permit or GuestGrant(token.id, token.revocation_generation, self.workspace.generation, vault, entry,
                                             revision, session, monotonic() + self.broker.approvals.timeout + 30)
                pending_pin = None
                if automatic and not reused and self.workspace.scoped_auto_approval_enabled("guest_first_use"):
                    if "certificate_sha256" in request.data:
                        endpoint = (request.origin, request.data["certificate_sha256"])
                        expected_pins, cert_trusted, auto_pin = self.broker.grants.result_certificate_auto_pin(
                            token, vault, entry, revision, *endpoint)
                        auto_start = any("https" in scope.uses for scope in matching) and (cert_trusted or auto_pin)
                        if auto_start:
                            expires = monotonic() + (reuse_minutes * 60 if reuse_minutes else JOB_SECONDS)
                            grant = replace(grant, expires=expires,
                                            trusted_endpoint=endpoint if cert_trusted else None)
                            if not cert_trusted:
                                pending_pin = (*endpoint, expected_pins)
                    else:
                        auto_start = any("https" in scope.uses for scope in matching)
                        if auto_start:
                            expires = monotonic() + (reuse_minutes * 60 if reuse_minutes else JOB_SECONDS)
                            grant = replace(grant, expires=expires, trusted_endpoint=None)
                if approved_step:
                    task, step = approved_step
                    grant = replace(grant, expires=task.deadline, workflow_id=task.id, workflow_step=step)
            else:
                job = self.jobs.get(job_key)
                if job is None or token.workflow is not None and token.workflow[0] != job[0].workflow_id:
                    raise ListingError("guest_job_unavailable")
                grant, request, private_job, fingerprint = job
                registration = self.workspace.registrations[grant.vault]
            title = {"guest_run": "Run Guest Command", "guest_status": "Check Guest Command",
                     "guest_release": "Release Guest Command"}[operation]
            folder, key = entry_target_labels(grant.session.entries, grant.entry)
            event = self.activity.begin(uid, context, title, request.origin, grant.entry,
                                        vault=registration.name, vault_id=grant.vault, token=token.id,
                                        agent=token.identity, project=token.project, folder=folder, entry_title=key,
                                        scope=f"Write receipt {receipt} · Workflow SHA-256 {fingerprint}",
                                        workflow_id=grant.workflow_id, workflow_step=grant.workflow_step)
            if operation == "guest_release":
                del self.jobs[job_key]
                self.activity.finish(event, "Released")

        if operation == "guest_release":
            if "login" in request.data:
                try:
                    grant.session.worker.forget_guest_login(self.login_key(grant, receipt, fingerprint))
                except ListingError:
                    pass  # A busy worker discards the private cache at its deadline.
            return encode({"id": receipt, "outcome": "released"})

        def guard(effect):
            with self.workspace.mutex:
                if not self.current(grant):
                    return False
                if approved_step and not self.broker.workflows.current(approved_step[0]):
                    return False
                if not starting and self.jobs.get(job_key) is not job:
                    return False
                return effect()

        stage = None
        reserved = False
        dispatches = 0
        try:
            if starting:
                digest = sha256(encode([vault, entry, fingerprint, request.canonical_json])).hexdigest()

                def claim():
                    nonlocal reserved
                    existing = sum(key[0] == token.id for key in self.jobs)
                    if (len(self.jobs) + self.pending.total() >= MAX_GUEST_JOBS
                            or existing + self.pending[token.id] >= MAX_JOBS_PER_TOKEN):
                        raise ListingError("busy")
                    failure = self.activity.claim_write(token.id, receipt, token.generation, vault, entry,
                                                        grant.revision, digest)
                    if failure:
                        raise ListingError(failure)
                    self.pending[token.id] += 1
                    reserved = True
                    return True

                if not guard(lambda: live(claim)):
                    raise ListingError("revoked")
                stage = "pending"
            if starting and not reused and not auto_start and approved_step is None:
                details = (
                    " › ".join(part for part in (registration.name, folder, key) if part),
                    (f"Any command in the {workflow.body_type} field {workflow.command_field!r} for up to {reuse_minutes} minutes."
                     if reuse_minutes else f"Run once using the {workflow.body_type} field {workflow.command_field!r}."),
                    "The credential and destination service must restrict this operation to the intended guest.",
                    "First command request:\n" + json.dumps(request.data, ensure_ascii=True, indent=2),
                    f"Job status will use {workflow.job_query!r} from the matched command response.",
                    "Job status endpoint:\n" + json.dumps(workflow.poll.data, ensure_ascii=True, indent=2),
                )
                ticket = Approval(event, uid, context, title, details, request.origin,
                                  monotonic() + self.broker.approvals.timeout, identity=token.identity,
                                  project=token.project, requested=time(), reuse_minutes=reuse_minutes, guest_command=True)
                answer = self.broker.approvals.wait(ticket, lambda: guard(live))
                if answer != "approved":
                    raise ListingError(answer)
                if reuse_minutes:
                    grant = replace(grant, expires=monotonic() + reuse_minutes * 60)
            decision = "Approved guest job status"
            if starting:
                decision = (approved_step[0].step_authorization if approved_step else
                            "Used approved guest command endpoint" if reused else
                            "Auto approved scoped guest command" if auto_start else
                            f"Owner approved guest commands for {reuse_minutes} min" if reuse_minutes else
                            "Owner approved guest command once")
            self.activity.authorize(event, decision)

            def gate(send):
                def record_dispatch():
                    nonlocal dispatches, stage, grant
                    dispatches += 1
                    if dispatches == 1:
                        if starting and pending_pin is not None:
                            pin_origin, pin_digest, expected_pins = pending_pin
                            self.broker.grants.trust_result_certificate(
                                token.id, token.generation, grant.vault, grant.entry, grant.revision,
                                pin_origin, pin_digest, expected_pins)
                            grant = replace(grant, trusted_endpoint=(pin_origin, pin_digest))
                        elif approved_step and approved_step[0].pending_pin is not None:
                            wf = approved_step[0]
                            pin_origin, pin_digest, expected_pins = wf.pending_pin
                            self.broker.grants.trust_result_certificate(
                                token.id, token.generation, grant.vault, grant.entry, grant.revision,
                                pin_origin, pin_digest, expected_pins)
                            wf.trusted_endpoint = (pin_origin, pin_digest)
                            wf.pending_pin = None
                        self.activity.dispatched(event)
                    if starting and dispatches == (2 if "login" in request.data else 1):
                        self.activity.advance_write(token.id, receipt, "pending", "dispatching")
                        stage = "dispatching"
                    send()

                return guard(lambda: dispatch(record_dispatch))

            action = usage_action(grant.entry, request.data)
            options = {"private_result": private_job}
            if "login" in request.data:
                options["login_context"] = {"key": self.login_key(grant, receipt, fingerprint),
                                            "expires": grant.expires, "reuse": not starting}
            result = grant.session.worker.use(action, gate, **options)
            if starting:
                status = result["outcome"]
                job = None
                if status == "succeeded":
                    try:
                        remote_id = result["data"][0]["job_id"]
                        job = (replace(grant, expires=min(grant.expires, monotonic() + JOB_SECONDS)
                                       if reused or reuse_minutes or approved_step else monotonic() + JOB_SECONDS),
                               workflow.status(remote_id), remote_id, fingerprint)
                    except (ValueError, KeyError, IndexError, TypeError):
                        status = "acknowledged"
                if stage == "dispatching":
                    self.activity.advance_write(token.id, receipt, stage, status, result.get("http_status"))
                    stage = None
                if job is not None:
                    def publish():
                        self.jobs[job_key] = job
                        if reuse_minutes and len(self.grants) < MAX_GUEST_JOBS:
                            self.grants.setdefault(grant_key, grant)
                        return True

                    if not guard(publish):
                        raise ListingError("guest_job_unavailable")
                result = {key: result[key] for key in ("http_status",) if key in result}
                result.update(id=receipt, outcome=status)
                if requested_minutes:
                    with self.workspace.mutex:
                        permit = self.grants.get(grant_key)
                        result["reuse_expires_in"] = max(0, ceil(permit.expires - monotonic())) if permit else 0
            else:
                result["id"] = receipt
            delivered = deliver(encode(result), guard)
            outcome = {"succeeded": "Succeeded", "failed": "Failed",
                       "acknowledged": "Acknowledged · result unavailable",
                       "uncertain": "Interrupted · outcome unknown"}[result["outcome"]]
            self.activity.finish(event, outcome if delivered else "Results Not Delivered", result.get("http_status"))
            if delivered and dispatches:
                with self.workspace.mutex:
                    self.broker.grants.used(token)
            return None
        except ListingError as error:
            outcome = {"declined": "Denied", "expired": "Expired", "revoked": "Revoked"}.get(error.code, "Failed")
            self.activity.finish(
                event,
                "Interrupted · outcome unknown" if stage == "dispatching" else outcome,
                detail=(error.detail or ERRORS.get(error.code)),
            )
            raise
        finally:
            if reserved:
                with self.workspace.mutex:
                    self.pending[token.id] -= 1
                    if not self.pending[token.id]:
                        del self.pending[token.id]
            if stage:
                self.activity.advance_write(token.id, receipt, stage,
                                            "uncertain" if stage == "dispatching" else "not_sent")
