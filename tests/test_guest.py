"""Verify narrowly reviewed guest commands and opaque polling through Keeper."""

from http.server import BaseHTTPRequestHandler
from hashlib import sha256
import json
from pathlib import Path
import ssl
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from keepassxc_agent_access.agent_cli import _validate
from keepassxc_agent_access.agent_runner import invocation
from keepassxc_agent_access.guest_request import parse_guest_request
from keepassxc_agent_access.protocol import ListingError, decode
from keepassxc_agent_access.result_delivery import GuestLoginCache, deliver_results
import test_result_broker as broker_tests
from tls_fixture import tls_service


def workflow(origin="https://guest.example.test/", pin="a" * 64):
    return {
        "origin": origin, "certificate_sha256": pin,
        "body_type": "json", "command_field": "command", "job_query": "job",
        "submit": {"request": {"path": "/guests/103/exec", "auth": "bearer", "method": "POST"},
                   "job_path": "/data/id"},
        "poll": {"request": {"path": "/guests/103/status", "auth": "bearer", "method": "GET"},
                 "result": {"path": "/data", "columns": ["done", "code"]}},
    }


class GuestTests(TestCase):
    setUp = broker_tests.ResultBrokerTests.setUp
    invoke = broker_tests.ResultBrokerTests.invoke
    enroll = broker_tests.ResultBrokerTests.enroll
    approve = broker_tests.ResultBrokerTests.approve
    reviewed = broker_tests.ResultBrokerTests.reviewed

    def scope(self, origin, index=0):
        return self.approve([{"vault": self.vaults[0], "entry": self.entry, "uses": ["https_results", "https_body"],
                              "origins": [origin]}], index=index)

    def run_guest(self, **kwargs):
        return self.invoke("guest_run", **{"vault": self.vaults[0], "entry": self.entry, "receipt": str(uuid4()),
                                           "command": "check service", "workflow": workflow(), **kwargs})

    def test_first_guest_command_auto_approves_only_inside_trusted_write_scope(self):
        descriptor = workflow()
        self.scope(descriptor["origin"])
        vault = self.vaults[0]
        identifier = self.approve([{"vault": vault, "entry": self.entry, "uses": ["https_results", "https"],
                                    "origins": [descriptor["origin"]]}], index=1)
        token = self.grants.records[identifier]
        revision = self.workspace.registrations[vault].credential_revision(self.entry)
        self.grants.trust_result_certificate(token.id, token.generation, vault, self.entry, revision,
                                             token.scope[0].origins[0], descriptor["certificate_sha256"], (None,))
        self.workspace.set_review_action("read_results", False)
        self.workspace.set_guest_auto_approval("guest_run", True)
        self.workspace.set_scoped_auto_approval("guest_first_use", True)

        def worker_use(_action, gate, **_kwargs):
            self.assertTrue(gate(lambda: None))
            return {"outcome": "succeeded", "http_status": 200, "data": [{"job_id": 14}]}

        worker = self.workspace.session(vault).worker
        with patch.object(worker, "use", side_effect=worker_use) as send:
            with self.assertRaises(ListingError) as denied:
                self.reviewed(lambda: self.run_guest(), approve=False)
            self.assertEqual(denied.exception.code, "declined")
            approved = self.run_guest(index=1, reuse_minutes=3)
            self.assertGreater(approved["reuse_expires_in"], 0)
            send.assert_called_once()
        self.assertIn("Auto approved scoped guest command", {r["decision"] for r in self.activity.rows()})

    def test_reuse_is_explicit_exact_and_job_polling_needs_no_second_review(self):
        origin = "https://guest.example.test/"
        self.scope(origin)
        self.scope(origin, index=1)
        self.workspace.set_guest_auto_approval("guest_run", True)
        remote_id = "job_private_value_123"
        commands = []

        def worker_use(action, gate, *, private_result=None):
            self.assertTrue(gate(lambda: None))
            request = json.loads(action.result_request)["request"]
            if request["method"] == "POST":
                commands.append(request["json"]["command"])
                return {"outcome": "succeeded", "http_status": 200, "data": [{"job_id": remote_id}]}
            self.assertEqual(request["query"], {"job": remote_id})
            self.assertEqual(private_result, remote_id)
            return {"outcome": "succeeded", "http_status": 200, "data": [{"done": True, "code": 0}]}

        def inspect(ticket):
            self.assertTrue(ticket.guest_command)
            self.assertEqual(ticket.reuse_minutes, 3)
            self.assertIn("Any command", " ".join(ticket.scope))
            self.assertIn("/guests/103/exec", " ".join(ticket.scope))
            self.assertIn('"command": "check service"', " ".join(ticket.scope))

        worker = self.workspace.session(self.vaults[0]).worker
        with patch.object(worker, "use", side_effect=worker_use):
            first = self.reviewed(lambda: self.run_guest(reuse_minutes=3), inspect=inspect)
            self.assertGreater(first["reuse_expires_in"], 0)
            self.assertNotIn(remote_id, repr(first))
            activity = self.activity.rows()
            self.assertNotIn(remote_id, repr(activity))
            status = self.invoke("guest_status", receipt=first["id"])
            self.assertEqual(status["data"], [{"done": True, "code": 0}])
            self.assertNotIn(remote_id, repr(status))
            second = self.run_guest(reuse_minutes=30, command="status check")
            self.assertLessEqual(second["reuse_expires_in"], first["reuse_expires_in"])
            self.assertEqual(commands, ["check service", "status check"])
            with patch("keepassxc_agent_access.guest_access.MAX_JOBS_PER_TOKEN", 2):
                with self.assertRaises(ListingError) as busy:
                    self.run_guest()
                self.assertEqual(busy.exception.code, "busy")
                self.assertEqual(self.invoke("guest_release", receipt=first["id"])["outcome"], "released")
                self.assertEqual(self.invoke("write_status", receipt=first["id"])["status"], "succeeded")
                self.assertEqual(self.run_guest()["outcome"], "succeeded")
            modified = workflow()
            modified["submit"]["request"]["path"] = "/guests/104/exec"
            for change in ({"workflow": modified}, {"index": 1}):
                with self.assertRaises(ListingError) as refused:
                    self.reviewed(lambda: self.run_guest(**change), approve=False)
                self.assertEqual(refused.exception.code, "declined")
            with self.assertRaises(ListingError) as refused:
                self.invoke("guest_status", receipt=first["id"], index=1)
            self.assertEqual(refused.exception.code, "guest_job_unavailable")
            self.workspace.set_review_usage(True)
            def once(ticket):
                self.assertEqual(ticket.reuse_minutes, 0)
                self.assertIn('"command": "check service"', " ".join(ticket.scope))
            third = self.reviewed(lambda: self.run_guest(reuse_minutes=3), inspect=once)
            self.assertEqual(third["reuse_expires_in"], 0)
            self.assertEqual(self.invoke("guest_status", receipt=third["id"])["outcome"], "succeeded")
            self.workspace.pause()
            self.workspace.pause(False)
            with self.assertRaises(ListingError):
                self.invoke("guest_status", receipt=third["id"])

    def test_guest_workflow_uses_tls_and_never_releases_raw_job_id(self):
        secret = "synthetic-private-credential"
        remote_id = 1682
        cookie, csrf = "synthetic-private-cookie", "synthetic-private-csrf"
        start_path = "/api2/json/nodes/example/qemu/103/agent/exec"
        status_path = start_path + "-status"
        seen = []

        class Service(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, data):
                body = json.dumps({"data": data}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append((self.path, body))
                if self.path == "/login" and body == {"password": secret}:
                    self.reply({"ticket": cookie, "csrf": csrf})
                elif (self.path == start_path and self.headers.get("Cookie") == "PVEAuthCookie=" + cookie
                      and self.headers.get("CSRFPreventionToken") == csrf):
                    self.reply({"pid": remote_id})
                else:
                    self.send_error(404)

            def do_GET(self):
                target = urlsplit(self.path)
                seen.append((target.path, parse_qs(target.query)))
                if (target.path == status_path and parse_qs(target.query) == {"pid": [str(remote_id)]}
                        and self.headers.get("Cookie") == "PVEAuthCookie=" + cookie):
                    self.reply({"exited": True, "exitcode": 0, "out-data": "guest ready\nservice ready\n",
                                "unselected": secret, "private": remote_id, "private_text": f"PID {remote_id}"})
                else:
                    self.send_error(404)

        login_cache = GuestLoginCache()

        def worker_use(action, gate, *, private_result=None, login_context=None):
            return deliver_results(json.loads(action.result_request), SimpleNamespace(username="", password=secret),
                                   lambda: gate(lambda: None), private_result=private_result,
                                   login_context=login_context, login_cache=login_cache)

        with TemporaryDirectory() as base, tls_service(Path(base), handler=Service) as (certificate, url, _):
            origin = url + "/"
            pin = sha256(ssl.PEM_cert_to_DER_cert(certificate.read_text())).hexdigest()
            self.scope(origin)
            worker = self.workspace.session(self.vaults[0]).worker
            self.workspace.set_guest_auto_approval("guest_run", True)
            descriptor = workflow(origin, pin)
            descriptor["login"] = {"path": "/login", "json": {"password": "{{password}}"},
                                   "capture": {"cookie": "/data/ticket", "csrf": "/data/csrf"}}
            descriptor["argument_prefix"] = ["/bin/bash", "-c"]
            descriptor["job_query"] = "pid"
            headers = {"Cookie": "PVEAuthCookie={{session.cookie}}", "CSRFPreventionToken": "{{session.csrf}}"}
            descriptor["submit"].update(job_path="/data/pid")
            descriptor["submit"]["request"].update(path=start_path, auth="session", headers=headers)
            descriptor["poll"]["request"].update(path=status_path, auth="session", headers=headers)
            descriptor["poll"]["result"]["columns"] = ["exited", "exitcode", "out-data"]
            command = "printf 'guest ready\\n'\nprintf 'service ready\\n'"
            with patch.object(worker, "use", side_effect=worker_use):
                reply = self.reviewed(lambda: self.run_guest(workflow=descriptor, command=command, reuse_minutes=5))
                status = self.invoke("guest_status", receipt=reply["id"])
                self.assertEqual(_validate(status, {"operation": "guest_status", "receipt": reply["id"]})["data"],
                                 [{"exited": True, "exitcode": 0, "out-data": "guest ready\nservice ready\n"}])
                self.assertEqual(self.invoke("guest_status", receipt=reply["id"]), status)
                self.assertEqual(self.invoke("write_status", receipt=reply["id"])["status"], "succeeded")
                with self.assertRaises(ListingError) as refused:
                    self.run_guest(workflow=descriptor, command=command, receipt=reply["id"])
                self.assertEqual(refused.exception.code, "receipt_exists")
            self.assertEqual(seen, [("/login", {"password": secret}), (start_path, {"command": ["/bin/bash", "-c", command]}),
                                    (status_path, {"pid": [str(remote_id)]}), (status_path, {"pid": [str(remote_id)]})])
            for field in ("private", "private_text"):
                leak = {**descriptor["poll"], "result": {"path": "/data", "columns": [field]}}
                request = parse_guest_request({**descriptor, "poll": leak}).status(remote_id)
                self.assertEqual(deliver_results(request, SimpleNamespace(username="", password=secret), lambda: True,
                                                private_result=remote_id), {"outcome": "failed"})

    def test_only_the_command_and_typed_job_value_can_be_substituted(self):
        request = parse_guest_request(workflow())
        self.assertEqual(request.start("check a=b&node=outside").data["request"]["json"],
                         {"command": "check a=b&node=outside"})
        for remote_id in ("../../host", "x&node=outside", None, True, -1):
            with self.assertRaises(ValueError):
                request.status(remote_id)
        self.assertEqual(request.status(1).data["request"]["query"], {"job": "1"})
        changed = workflow()
        changed["poll"]["request"]["query"] = {"JOB": "preassigned"}
        with self.assertRaises(ValueError):
            parse_guest_request(changed)
        receipt = str(uuid4())
        args, body = invocation("guest_run", {"vault": self.vaults[0], "entry": self.entry, "receipt": receipt,
                                               "workflow": workflow(), "guest_command": "status", "reuse_minutes": 6})
        self.assertIn("--receipt=" + receipt, args)
        self.assertEqual(decode(body)["command"], "status")
