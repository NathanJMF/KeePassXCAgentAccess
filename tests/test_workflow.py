"""One review of exact writes and task-local, server-supplied IDs."""

import json
import os
from pathlib import Path
import subprocess
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from keepassxc_agent_access.activity_grouping import activity_groups
from keepassxc_agent_access.agent_cli import _validate
from keepassxc_agent_access.broker import BrokerConfig, ListingBroker
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.protocol import ListingError, decode, encode
from keepassxc_agent_access.workflow import WorkflowAccess, parse_workflow
import test_result_broker as broker_tests
import test_console as consoles
import test_guest as guests


class WorkflowTests(TestCase):
    setUp = broker_tests.ResultBrokerTests.setUp
    invoke = broker_tests.ResultBrokerTests.invoke
    enroll = broker_tests.ResultBrokerTests.enroll
    approve = broker_tests.ResultBrokerTests.approve
    reviewed = broker_tests.ResultBrokerTests.reviewed

    def manifest(self):
        return {
            "id": str(uuid4()), "vault": self.vaults[0], "entry": self.entry,
            "origin": "https://fixtures.example.test/", "certificate_sha256": "a" * 64,
            "steps": [
                {"name": "create", "request": {"path": "/guests", "method": "POST", "auth": "bearer",
                                                "json": {"name": "synthetic"}},
                 "result": {"path": "/data/id", "scalar": "guest_id"}, "capture_id": True},
                {"name": "start", "request": {"path": "/guests/{create}/state", "method": "PUT", "auth": "bearer",
                                               "json": {"state": "running", "id": {"$from": "create"}}},
                 "result": {"path": "/data", "columns": ["state"]}},
            ],
        }

    def register(self, manifest, index=0):
        return self.approve([{"vault": manifest["vault"], "entry": manifest["entry"], "uses": ["https_results"],
                              "origins": [manifest["origin"]]}], index=index)

    def run_step(self, manifest, name, **kwargs):
        return self.invoke("workflow_run", workflow=manifest["id"], step=name, **kwargs)

    def test_auto_approved_workflow_requires_trusted_pin_and_standing_write_access(self):
        manifest = self.manifest()
        self.register(manifest)
        identifier = self.approve([{"vault": manifest["vault"], "entry": manifest["entry"],
                                    "uses": ["https_results", "https"], "origins": [manifest["origin"]]}], index=1)
        token = self.grants.records[identifier]
        revision = self.workspace.registrations[manifest["vault"]].credential_revision(manifest["entry"])
        self.grants.trust_result_certificate(token.id, token.generation, manifest["vault"], manifest["entry"],
                                             revision, token.scope[0].origins[0], manifest["certificate_sha256"], (None,))
        self.workspace.set_review_action("read_results", False)
        self.workspace.set_scoped_auto_approval("workflow", True)
        with self.assertRaises(ListingError) as denied:
            self.reviewed(lambda: self.invoke("workflow_request", request=manifest), approve=False)
        self.assertEqual(denied.exception.code, "declined")
        allowed = self.invoke("workflow_request", request=manifest, index=1)
        self.assertEqual(allowed["id"], manifest["id"])
        self.assertIn("Auto approved scoped workflow", {r["decision"] for r in self.activity.rows()})

        def worker_use(_action, gate, **_kwargs):
            self.assertTrue(gate(lambda: None))
            return {"outcome": "succeeded", "http_status": 200, "data": [{"guest_id": 842}]}

        worker = self.workspace.session(manifest["vault"]).worker
        with patch.object(worker, "use", side_effect=worker_use):
            self.assertEqual(self.run_step(manifest, "create", index=1)["data"], [{"guest_id": 842}])
        self.assertIn("Auto approved workflow step", {r["decision"] for r in self.activity.rows()})
        self.workspace.set_review_usage(True)
        with self.assertRaises(ListingError) as revoked:
            self.run_step(manifest, "start", index=1)
        self.assertEqual(revoked.exception.code, "workflow_unavailable")

    def test_workflow_request_honors_tls_first_pin_and_enrollment_auto_approval(self):
        manifest = self.manifest()
        self.register(manifest)
        identifier = self.approve([{"vault": manifest["vault"], "entry": manifest["entry"],
                                    "uses": ["https_results", "https"], "origins": [manifest["origin"]]}], index=1)
        self.workspace.set_review_action("read_results", False)
        self.workspace.set_scoped_auto_approval("workflow", True)
        self.workspace.set_scoped_auto_approval("tls_first_pin", True)
        allowed = self.invoke("workflow_request", request=manifest, index=1)
        self.assertEqual(allowed["id"], manifest["id"])
        worker = self.workspace.session(manifest["vault"]).worker

        def worker_use(_action, gate, **_kwargs):
            self.assertTrue(gate(lambda: None))
            return {"outcome": "succeeded", "http_status": 200, "data": [{"guest_id": 842}]}

        with patch.object(worker, "use", side_effect=worker_use):
            self.assertEqual(self.run_step(manifest, "create", index=1)["data"], [{"guest_id": 842}])
        self.assertEqual(self.grants.records[identifier].scope[0].result_certificates,
                         (("https://fixtures.example.test:443/", manifest["certificate_sha256"]),))

        # Enrollment via workflow_request auto-approves only when token credential-uses opt-in is enabled.
        manifest2 = self.manifest()
        manifest2["id"] = str(uuid4())
        self.workspace.acknowledge_token_auto_approval(True)
        self.workspace.set_token_auto_approval("auto_approve_tokens", True)
        with self.assertRaises(ListingError) as denied:
            self.reviewed(lambda: self.invoke(
                "workflow_request", request=manifest2,
                enrollment={"identity": "Manual workflow agent", "project": "Fixture"}, index=2), approve=False)
        self.assertEqual(denied.exception.code, "declined")
        self.workspace.set_token_auto_approval("auto_approve_token_credential_uses", True)
        manifest3 = self.manifest()
        manifest3["id"] = str(uuid4())
        enrolled = self.invoke("workflow_request", request=manifest3,
                               enrollment={"identity": "Auto workflow agent", "project": "Fixture"}, index=2)
        self.assertEqual(enrolled["id"], manifest3["id"])

    def test_two_writes_share_one_review_and_one_immutable_dependency(self):
        manifest = self.manifest()
        self.register(manifest)
        self.register(manifest, index=1)
        self.workspace.set_review_usage(True)

        def inspect(ticket):
            self.assertTrue(ticket.workflow_review)
            self.assertIn("Each can run once", " ".join(ticket.scope))
            self.assertIn("/guests/{create}/state", " ".join(ticket.scope))
            self.assertIn("a" * 64, " ".join(ticket.scope))

        details = self.reviewed(lambda: self.invoke("workflow_request", request=manifest), inspect=inspect)
        self.assertEqual(_validate(details, {"operation": "workflow_request", "request": manifest}), details)
        receipts = details["receipts"]
        with self.assertRaises(ListingError) as error:
            self.run_step(manifest, "start")
        self.assertEqual(error.exception.code, "dependency_unavailable")
        with self.assertRaises(ListingError) as error:
            self.run_step(manifest, "create", index=1)
        self.assertEqual(error.exception.code, "workflow_unavailable")
        with self.assertRaises(ListingError) as error:
            self.run_step(manifest, "start", request={"id": 999})
        self.assertEqual(error.exception.code, "invalid_request")
        observed = []

        def worker_use(action, gate, **_kwargs):
            self.assertTrue(gate(lambda: None))
            request = json.loads(action.result_request)["request"]
            observed.append(request)
            return {"outcome": "succeeded", "http_status": 200,
                    "data": [{"guest_id": 842}] if request["path"] == "/guests" else [{"state": "running"}]}

        worker = self.workspace.session(self.vaults[0]).worker
        with patch.object(worker, "use", side_effect=worker_use):
            self.assertEqual(self.run_step(manifest, "create")["data"], [{"guest_id": 842}])
            self.assertEqual(self.run_step(manifest, "start")["data"], [{"state": "running"}])
            self.assertEqual(self.invoke("write_status", receipt=receipts["start"])["status"], "succeeded")
            with self.assertRaises(ListingError) as error:
                self.run_step(manifest, "start")
            self.assertEqual(error.exception.code, "receipt_exists")
        self.assertEqual([row["path"] for row in observed], ["/guests", "/guests/842/state"])
        self.assertEqual(observed[-1]["json"], {"state": "running", "id": 842})
        grouped = activity_groups(self.activity.rows())
        rows, = [rows for key, (_, rows) in grouped.items() if key[0] == "workflow"]
        self.assertEqual(sum(row["decision"] == "Approved in workflow review" for row in rows), 2)
        self.assertEqual(sum(row["decision"] == "Owner approved exact workflow" for row in rows), 1)

    def test_invalid_output_cannot_drive_a_step_and_changed_manifest_refuses_existing_id(self):
        manifest = self.manifest()
        self.register(manifest)
        self.reviewed(lambda: self.invoke("workflow_request", request=manifest))
        worker = self.workspace.session(self.vaults[0]).worker

        def no_id(_action, gate, **_kwargs):
            self.assertTrue(gate(lambda: None))
            return {"outcome": "succeeded", "http_status": 200, "data": [{"guest_id": True}]}

        with patch.object(worker, "use", side_effect=no_id):
            self.assertEqual(self.run_step(manifest, "create"), {"outcome": "acknowledged", "http_status": 200})
            with self.assertRaises(ListingError) as error:
                self.run_step(manifest, "start")
            self.assertEqual(error.exception.code, "dependency_unavailable")
        self.engine.workflows = WorkflowAccess(self.engine)
        manifest["steps"][0]["request"]["path"] = "/alternative"
        with self.assertRaises(ListingError) as error:
            self.invoke("workflow_request", request=manifest)
        self.assertEqual(error.exception.code, "receipt_conflict")

    def test_ambiguous_or_forward_path_bindings_are_rejected(self):
        manifest = self.manifest()
        manifest["steps"].reverse()
        with self.assertRaises(ValueError):
            parse_workflow(manifest)
        manifest["steps"].reverse()
        for path in ("/guest/prefix-{create}", "/guest/%7Bcreate%7D"):
            manifest["steps"][1]["request"]["path"] = path
            with self.assertRaises(ValueError):
                parse_workflow(manifest)
        manifest["steps"][1]["request"]["path"] = "/guest/{create}/" + "a" * 2030
        with self.assertRaises(ValueError):
            parse_workflow(manifest)

    def test_resume_restores_only_committed_typed_bindings_and_never_replays_create(self):
        manifest = self.manifest()
        self.register(manifest)
        details = self.reviewed(lambda: self.invoke("workflow_request", request=manifest))
        worker = self.workspace.session(self.vaults[0]).worker
        sent = []

        def send(action, gate, **_kwargs):
            self.assertTrue(gate(lambda: None))
            path = json.loads(action.result_request)["request"]["path"]
            sent.append(path)
            return {"outcome": "succeeded", "http_status": 200, "data": [
                {"guest_id": 456} if path == "/guests" else {"state": "running"}]}

        with patch.object(worker, "use", side_effect=send):
            self.run_step(manifest, "create")
            self.engine.workflows = WorkflowAccess(self.engine)
            self.activity.recover(30)
            with self.assertRaises(ListingError) as error:
                self.run_step(manifest, "start")
            self.assertEqual(error.exception.code, "workflow_unavailable")
            updated = self.reviewed(lambda: self.invoke("workflow_request", request=manifest))
            self.assertEqual(updated["receipts"], details["receipts"])
            with self.assertRaises(ListingError) as error:
                self.run_step(manifest, "create")
            self.assertEqual(error.exception.code, "receipt_exists")
            self.run_step(manifest, "start")
        self.assertEqual(sent, ["/guests", "/guests/456/state"])

    def test_console_and_guest_command_can_share_the_same_task_review(self):
        manifest = self.manifest()
        descriptor = consoles.descriptor(manifest["origin"], manifest["certificate_sha256"])
        manifest["login"] = descriptor["login"]
        for stage in ("connect", "socket"):
            descriptor[stage]["path"] = descriptor[stage]["path"].replace("/103/", "/{create}/")
        guest = guests.workflow()
        del guest["origin"], guest["certificate_sha256"]
        guest["submit"]["request"]["path"] = "/guests/{create}/exec"
        guest["poll"]["request"]["path"] = "/guests/{create}/status"
        manifest["steps"] = [manifest["steps"][0],
                             {"name": "console", "kind": "console",
                              "request": {stage: descriptor[stage] for stage in ("connect", "socket")}},
                             {"name": "diagnose", "kind": "guest", "request": guest, "command": "check guest"}]
        self.approve([{"vault": manifest["vault"], "entry": manifest["entry"], "uses": ["https_results", "https_body"],
                       "origins": [manifest["origin"]]}])
        self.workspace.set_guest_auto_approval("console_open", True)
        details = self.reviewed(lambda: self.invoke("workflow_request", request=manifest))
        self.assertEqual(_validate(details, {"operation": "workflow_request", "request": manifest}), details)
        self.assertEqual(set(details["receipts"]), {"create", "diagnose"})
        worker = self.workspace.session(self.vaults[0]).worker

        def send(action, gate, **_kwargs):
            self.assertTrue(gate(lambda: None))
            self.assertTrue(gate(lambda: None))
            path = json.loads(action.result_request)["request"]["path"]
            fields = ({"guest_id": 321} if path == "/guests" else
                      {"job_id": 72} if path == "/guests/321/exec" else {"done": True, "code": 0})
            return {"outcome": "succeeded", "http_status": 200, "data": [fields]}

        def console(request, gate):
            if request["operation"] == "console_open":
                self.assertIn("/321/", request["request"]["connect"]["path"])
                self.assertIn("/321/", request["request"]["socket"]["path"])
            self.assertTrue(gate(lambda: None))
            return {"outcome": "succeeded"}

        with patch.object(worker, "use", side_effect=send), patch.object(worker, "console", side_effect=console, create=True):
            self.run_step(manifest, "create")
            for _ in range(2):
                result = self.run_step(manifest, "console")
                payload = {"operation": "workflow_run", "workflow": manifest["id"], "step": "console"}
                self.assertEqual(_validate(result, payload), result)
                self.invoke("console_close", console=result["console"])
            job = self.run_step(manifest, "diagnose")
            self.assertEqual(job["id"], details["receipts"]["diagnose"])
            self.assertEqual(self.invoke("guest_status", receipt=job["id"])["data"], [{"done": True, "code": 0}])
        self.assertEqual(self.engine.approvals.pending(), ())
        self.assertEqual(sum(row["decision"] == "Owner approved exact workflow" for row in self.activity.rows()), 1)

    def test_fresh_cli_profile_registers_and_runs_with_one_decision(self):
        manifest = self.manifest()
        self.workspace.set_review_usage(True)
        self.workspace.pause()
        root = self.workspace.directory
        profile = root / "fresh-profile"
        profile.mkdir(mode=0o700)
        token_file = profile / "token"
        endpoint = root / "fixture.sock"
        engine = self.engine
        broker = ListingBroker(BrokerConfig(endpoint, 1500), lambda: engine, engine)
        executable = Path(__file__).resolve().parents[1] / "keepassxc-agent"
        environment = {**os.environ, "KEEPASSXC_AGENT_SOCKET": str(endpoint), "KEEPASSXC_AGENT_TOKEN_FILE": str(token_file),
                       "KEEPASSXC_AGENT_IDENTITY": "Synthetic workflow agent", "KEEPASSXC_AGENT_PROJECT": "Fixture"}
        seen = []

        def cli(*arguments, data=None, succeeds=True):
            result = subprocess.run([executable, *arguments, "--json"], cwd="/tmp", env=environment, capture_output=True,
                                    input=encode(data) if data is not None else b"", timeout=8)
            self.assertEqual(result.returncode == 0, succeeds, result.stderr.decode())
            if token_file.exists():
                self.assertNotIn(token_file.read_bytes().strip(), result.stdout + result.stderr)
            return decode(result.stdout) if succeeds else result.stderr.decode()

        def inspect(ticket):
            self.assertTrue(ticket.workflow_enrollment)
            self.assertTrue(ticket.resume_access)
            self.assertFalse(engine.grants.records)
            self.assertTrue(token_file.is_file())

        def worker_use(action, gate, **_kwargs):
            self.assertTrue(gate(lambda: None))
            request = json.loads(action.result_request)["request"]
            seen.append(request["path"])
            return {"outcome": "succeeded", "http_status": 200, "data": [
                {"guest_id": 103} if request["path"] == "/guests" else {"state": "running"}]}

        worker = self.workspace.session(self.vaults[0]).worker
        # Model a runner peer on this fixture socket only. This tests CLI and broker
        # routing at wire level, independently of Linux namespace installation.
        with patch("keepassxc_agent_access.broker.peer_uid", return_value=1500), patch.object(worker, "use", side_effect=worker_use):
            broker.start()
            try:
                approved = self.reviewed(lambda: cli("workflows", "request", "--register", data=manifest), inspect=inspect)
                self.assertFalse(self.workspace.paused)
                self.assertEqual(cli("access", "status", "--details")["workflow"], manifest["id"])
                for name in ("create", "start"):
                    cli("workflows", "run", "--workflow", manifest["id"], "--step", name)
                self.assertEqual(cli("results", "status", "--receipt", approved["receipts"]["start"])["status"], "succeeded")
                direct_use = {"type": "https_results", "origin": manifest["origin"], "approve_write_once": True,
                              "request": manifest["steps"][0]["request"], "result": manifest["steps"][0]["result"]}
                self.assertIn("unavailable for this token", cli("use", "--entry", self.entry, "--vault", self.vaults[0],
                                                                 data=direct_use, succeeds=False))
                direct_enroll = {"items": [{"vault": self.vaults[0], "entry": self.entry, "metadata": True}]}
                self.assertIn("unavailable for this token", cli("access", "request", data=direct_enroll, succeeds=False))
                engine.grants = Grants(self.workspace, self.activity)
                engine.workflows = WorkflowAccess(engine)
                changed = {**manifest, "minutes": 15}
                self.assertIn("already refers", cli("workflows", "request", data=changed, succeeds=False))
                self.assertEqual(cli("access", "status", "--details")["workflow"], manifest["id"])
            finally:
                broker.stop()
        self.assertEqual(seen, ["/guests", "/guests/103/state"])
        rows = self.activity.rows()
        self.assertEqual(sum(row["decision"] == "Owner approved workflow-only token" for row in rows), 1)
        self.assertFalse(self.engine.approvals.pending())

    def test_denial_and_racing_traditional_registration_grant_no_workflow(self):
        manifest = self.manifest()
        enrollment = {"identity": "Workflow agent", "project": "Fixture"}
        self.workspace.pause()
        with self.assertRaises(ListingError) as declined:
            self.reviewed(lambda: self.invoke("workflow_request", request=manifest, enrollment=enrollment), approve=False)
        self.assertEqual(declined.exception.code, "declined")
        self.assertFalse(self.grants.records)
        self.assertTrue(self.workspace.paused)

        def register_during_review(_ticket):
            self.enroll([{"vault": self.vaults[0], "entry": self.entry, "metadata": True}], identity="Normal agent")

        with self.assertRaises(ListingError) as raced:
            self.reviewed(lambda: self.invoke("workflow_request", request=manifest, enrollment=enrollment),
                          inspect=register_during_review)
        self.assertEqual(raced.exception.code, "revoked")
        token, = self.grants.records.values()
        self.assertEqual(token.status, "pending")
        self.assertIsNone(token.workflow)

    def test_unpinned_workflow_string_captures_failed_retries_and_credential_changed(self):
        # Optional certificate_sha256 + safe string capture + path/JSON substitution + recovery.
        manifest = {
            "id": str(uuid4()), "vault": self.vaults[0], "entry": self.entry,
            "origin": "https://fixtures.example.test/",
            "steps": [
                {"name": "create", "request": {"path": "/tasks", "method": "POST", "auth": "bearer",
                                               "json": {"name": "synthetic"}},
                 "result": {"path": "/data/id", "scalar": "task_id"}, "capture_id": True,
                 "expected_id": "UPID:node1:0001"},
                {"name": "check", "request": {"path": "/tasks/{create}/status", "method": "PUT", "auth": "bearer",
                                              "json": {"upid": {"$from": "create"}}},
                 "result": {"path": "/data", "columns": ["state"]}},
            ],
        }
        # Unsafe path segments (e.g., containing '/' or '..') are rejected when substituted into URL path segments.
        for bad_id in ("bad/id", "..", ".", "bad?id", True, "a{{password}}"):
            bad = {**manifest, "id": str(uuid4()), "steps": [{**manifest["steps"][0], "expected_id": bad_id}, manifest["steps"][1]]}
            with self.subTest(bad_id=bad_id), self.assertRaises(ValueError):
                parse_workflow(bad)

        identifier = self.approve([{"vault": manifest["vault"], "entry": manifest["entry"],
                                    "uses": ["https_results", "https"], "origins": [manifest["origin"]]}])
        self.workspace.set_review_action("read_results", False)
        self.workspace.set_scoped_auto_approval("workflow", True)
        details = self.invoke("workflow_request", request=manifest)
        self.assertEqual(details["id"], manifest["id"])

        worker = self.workspace.session(self.vaults[0]).worker
        seen_paths = []
        fail_next = [True]

        def worker_use(action, gate, **_kwargs):
            self.assertTrue(gate(lambda: None))
            req = json.loads(action.result_request)["request"]
            seen_paths.append(req["path"])
            if req["path"] == "/tasks":
                return {"outcome": "succeeded", "http_status": 200, "data": [{"task_id": "UPID:node1:0001"}]}
            if fail_next[0]:
                fail_next[0] = False
                return {"outcome": "failed", "http_status": 500}
            return {"outcome": "succeeded", "http_status": 200, "data": [{"state": "done"}]}

        with patch.object(worker, "use", side_effect=worker_use):
            self.assertEqual(self.run_step(manifest, "create")["data"], [{"task_id": "UPID:node1:0001"}])
            # Failed step returns failed and can be retried with the same receipt.
            self.assertEqual(self.run_step(manifest, "check")["outcome"], "failed")
            self.assertEqual(self.invoke("write_status", receipt=details["receipts"]["check"])["status"], "failed")
            self.assertEqual(self.run_step(manifest, "check")["data"], [{"state": "done"}])
            self.assertEqual(self.invoke("write_status", receipt=details["receipts"]["check"])["status"], "succeeded")
            # Succeeded step still refuses replay.
            with self.assertRaises(ListingError) as dup:
                self.run_step(manifest, "check")
            self.assertEqual(dup.exception.code, "receipt_exists")
        self.assertEqual(seen_paths, ["/tasks", "/tasks/UPID:node1:0001/status", "/tasks/UPID:node1:0001/status"])

        # String capture persists across activity recovery & workflow re-request.
        manifest2 = {**manifest, "id": str(uuid4()),
                     "steps": [{k: v for k, v in manifest["steps"][0].items() if k != "expected_id"}, manifest["steps"][1]]}
        with patch.object(worker, "use", side_effect=lambda a, g, **_k: (g(lambda: None), {"outcome": "succeeded", "http_status": 200, "data": [{"task_id": "job-abc"}]})[1]):
            self.invoke("workflow_request", request=manifest2)
            self.run_step(manifest2, "create")
        self.engine.workflows = WorkflowAccess(self.engine)
        self.activity.recover(30)
        self.invoke("workflow_request", request=manifest2)
        with patch.object(worker, "use", side_effect=worker_use):
            self.assertEqual(self.run_step(manifest2, "check")["data"], [{"state": "done"}])
        self.assertEqual(seen_paths[-1], "/tasks/job-abc/status")

        # Unsafe runtime string capture fails cleanly with dependency_unavailable when bound into a URL path.
        manifest3 = {**manifest2, "id": str(uuid4())}
        self.invoke("workflow_request", request=manifest3)
        with patch.object(worker, "use", side_effect=lambda a, g, **_k: (g(lambda: None), {"outcome": "succeeded", "http_status": 200, "data": [{"task_id": "bad/seg"}]})[1]):
            self.run_step(manifest3, "create")
        with self.assertRaises(ListingError) as dep:
            self.run_step(manifest3, "check")
        self.assertEqual(dep.exception.code, "dependency_unavailable")

        # Credential rotation raises credential_changed instead of ineligible.
        self.workspace._invalidate_changed_credentials(self.vaults[0], self.workspace.session(self.vaults[0]),
            {"entry": self.entry, "username": "rotated-user", "password": None})
        with self.assertRaises(ListingError) as changed:
            self.invoke("workflow_request", request={**manifest, "id": str(uuid4())})
        self.assertEqual(changed.exception.code, "credential_changed")

    def test_workflow_auto_approves_on_results_only_scope_when_expanded_actions_enabled(self):
        manifest = self.manifest()
        del manifest["certificate_sha256"]
        self.approve([{"vault": manifest["vault"], "entry": manifest["entry"],
                       "uses": ["https_results"], "origins": [manifest["origin"]]}])
        self.workspace.set_review_action("read_results", False)
        self.workspace.set_scoped_auto_approval("workflow", True)
        with self.assertRaises(ListingError) as denied:
            self.reviewed(lambda: self.invoke("workflow_request", request=manifest), approve=False)
        self.assertEqual(denied.exception.code, "declined")

        self.workspace.acknowledge_token_auto_approval(True)
        self.workspace.set_token_auto_approval("auto_approve_expanded_scoped_actions", True)
        with patch.object(self.engine.approvals, "wait", side_effect=AssertionError("Should auto-approve")):
            details = self.invoke("workflow_request", request={**manifest, "id": str(uuid4())})
        self.assertIn("receipts", details)
