"""One review of exact writes and task-local, server-supplied IDs."""

import json
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from keepassxc_agent_access.activity_grouping import activity_groups
from keepassxc_agent_access.agent_cli import _validate
from keepassxc_agent_access.protocol import ListingError
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
