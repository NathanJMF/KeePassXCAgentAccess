"""Result release needs explicit scope, review and live guards at every step."""

from concurrent.futures import ThreadPoolExecutor
from time import monotonic, sleep
import unittest
from unittest.mock import patch

import test_scoped_broker as base
from keepassxc_agent_access.protocol import ListingError
from keepassxc_agent_access.grants import Grants


class ResultBrokerTests(unittest.TestCase):
    setUp = base.ScopedBrokerTests.setUp
    invoke = base.ScopedBrokerTests.invoke
    enroll = base.ScopedBrokerTests.enroll
    approve = base.ScopedBrokerTests.approve
    assert_code = base.ScopedBrokerTests.assert_code

    def item(self, uses=("https_results",), **kwargs):
        return {"vault": self.vaults[0], "entry": self.entry, "uses": list(uses),
                "origins": ["https://api.example.test/"], **kwargs}

    def request(self, login=False, **changes):
        result = {"type": "https_results", "origin": "https://api.example.test/",
                  "request": {"path": "/inventory", "auth": "basic"},
                  "result": {"path": "/data", "columns": ["vmid", "node"]}, **changes}
        if login:
            result["login"] = {"path": "/auth", "form": {"username": "{{username}}", "password": "{{password}}"},
                               "capture": {"ticket": "/data/ticket"}}
            result["request"] = {"path": "/inventory", "auth": "session", "headers": {"Cookie": "session={{session.ticket}}"}}
        return result

    def use(self, usage, **kwargs):
        return self.invoke("use_password", entry=self.entry, vault=self.vaults[0], usage=usage, **kwargs)

    def fake_worker(self, action, gate, *, allow_username=False):
        self.assertFalse(allow_username)
        self.assertTrue(gate(lambda: None))
        if '"login"' in action.result_request:
            self.assertTrue(gate(lambda: None))
        return {"outcome": "succeeded", "http_status": 200, "data": [{"vmid": 814, "node": "node-fresh"}]}

    def reviewed(self, operation, *, inspect=lambda ticket: None):
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(operation)
            deadline = monotonic() + 3
            while monotonic() < deadline and not self.engine.approvals.pending():
                sleep(.01)
            ticket, = self.engine.approvals.pending()
            inspect(ticket)
            self.engine.approvals.resolve(ticket.id, True)
            return future.result(3)

    def test_old_credential_scope_cannot_release_results(self):
        self.approve([self.item(("https", "https_body"))])
        self.assert_code("ineligible", "use_password", entry=self.entry, vault=self.vaults[0], usage=self.request())

    def test_default_review_binds_request_projection_and_audits_without_data(self):
        self.approve([self.item(("https_results", "https_body"))])
        worker = self.workspace.session(self.vaults[0]).worker
        def inspect(ticket):
            text = " ".join(ticket.scope)
            for expected in ("/auth", "/inventory", "vmid", "node", "endpoint"):
                self.assertIn(expected, text)
            self.assertEqual(ticket.identity, "Fixture agent 0")
        with patch.object(worker, "use", side_effect=self.fake_worker):
            result = self.reviewed(lambda: self.use(self.request(login=True)), inspect=inspect)
        self.assertEqual(result["data"], [{"vmid": 814, "node": "node-fresh"}])
        event, = self.activity.rows(action="Read HTTPS Results")
        self.assertEqual(event["outcome"], "Succeeded")
        self.assertIn("GET", event["scope"])
        self.assertIn("vmid, node", event["scope"])
        self.assertNotIn("node-fresh", repr(event))
        self.assertEqual(event["decision"], "Approved once")

    def test_login_body_and_resource_write_each_require_their_own_scope(self):
        self.approve([self.item()])
        self.assert_code("ineligible", "use_password", entry=self.entry, vault=self.vaults[0], usage=self.request(login=True))
        self.assert_code("ineligible", "use_password", entry=self.entry, vault=self.vaults[0],
                         usage=self.request(request={"path": "/jobs", "auth": "bearer", "method": "POST", "json": {"task": "create"}}))

    def test_pin_is_reviewed_once_then_auto_approve_survives_reload(self):
        self.approve([self.item()])
        self.workspace.set_review_action("read_results", False)
        self.assertFalse(self.workspace.requires_review("read_results"))
        worker = self.workspace.session(self.vaults[0]).worker
        with patch.object(worker, "use", side_effect=self.fake_worker):
            self.assertEqual(self.use(self.request())["data"][0]["vmid"], 814)
            workflow = self.request(certificate_sha256="a" * 64)
            def inspect(ticket):
                self.assertTrue(ticket.trusts_certificate)
                self.assertIn("Future requests follow your Auto Approve settings", " ".join(ticket.scope))
            result = self.reviewed(lambda: self.use(workflow), inspect=inspect)
            self.assertEqual(result["data"][0]["vmid"], 814)
            self.assertEqual(self.use(workflow)["data"][0]["vmid"], 814)
            self.grants = self.engine.grants = Grants(self.workspace, self.activity)
            self.assertEqual(self.use(workflow)["data"][0]["vmid"], 814)
            self.assertEqual(self.engine.approvals.pending(), ())
            self.assertFalse(self.invoke("access_status", details=True)["scope"][0].get("result_certificates"))
        events = self.activity.rows(action="Read HTTPS Results")
        self.assertEqual(sum(row["decision"] == "Approved token" for row in events), 3)
        self.assertEqual(sum("trust certificate" in (row["decision"] or "") for row in events), 1)
        self.assertIn("Certificate SHA-256: " + "a" * 64, events[0]["scope"])

    def test_changed_pin_and_different_token_require_their_own_review(self):
        self.approve([self.item()])
        self.approve([self.item()], index=1)
        self.workspace.set_review_action("read_results", False)
        worker = self.workspace.session(self.vaults[0]).worker
        with patch.object(worker, "use", side_effect=self.fake_worker):
            self.reviewed(lambda: self.use(self.request(certificate_sha256="a" * 64)))
            self.reviewed(lambda: self.use(self.request(certificate_sha256="a" * 64), index=1))
            self.reviewed(lambda: self.use(self.request(certificate_sha256="b" * 64)))
            # Rotation replaces the old certificate, rather than accumulating trust.
            self.reviewed(lambda: self.use(self.request(certificate_sha256="a" * 64)))

    def test_known_pin_still_obeys_results_https_and_global_review(self):
        self.approve([self.item()])
        self.workspace.set_review_action("read_results", False)
        worker = self.workspace.session(self.vaults[0]).worker
        workflow = self.request(certificate_sha256="a" * 64)
        def once(ticket):
            self.assertFalse(ticket.trusts_certificate)
        with patch.object(worker, "use", side_effect=self.fake_worker):
            self.reviewed(lambda: self.use(workflow))
            for operation in ("read_results", "use_https"):
                self.workspace.set_review_action(operation, True)
                self.reviewed(lambda: self.use(workflow), inspect=once)
                self.workspace.set_review_action(operation, False)
            self.workspace.set_review_usage(True)
            self.reviewed(lambda: self.use(workflow), inspect=once)

    def test_wrong_peer_no_dispatch_does_not_remember_certificate(self):
        identifier = self.approve([self.item()])
        self.workspace.set_review_action("read_results", False)
        worker = self.workspace.session(self.vaults[0]).worker
        workflow = self.request(certificate_sha256="a" * 64)
        with patch.object(worker, "use", return_value={"outcome": "failed"}):
            self.reviewed(lambda: self.use(workflow))
        self.assertEqual(self.grants.records[identifier].scope[0].result_certificates, ())
        with patch.object(worker, "use", side_effect=self.fake_worker):
            self.reviewed(lambda: self.use(workflow))

    def test_permission_change_discards_remembered_certificates(self):
        from uuid import uuid4
        identifier = self.approve([self.item()])
        self.workspace.set_review_action("read_results", False)
        worker = self.workspace.session(self.vaults[0]).worker
        workflow = self.request(certificate_sha256="a" * 64)
        with patch.object(worker, "use", side_effect=self.fake_worker):
            self.reviewed(lambda: self.use(workflow))
            change_id = str(uuid4())
            self.invoke("request_access", request={"identity": "Fixture agent 0", "project": "Fixture",
                        "items": [self.item()], "change_id": change_id})
            change = self.grants.records[identifier].pending_change
            self.grants.decide(identifier, [self.grants.choices(item)[0] for item in change.items], change_id=change_id)
            self.assertEqual(self.grants.records[identifier].scope[0].result_certificates, ())
            self.reviewed(lambda: self.use(workflow))

    def test_revocation_between_login_and_resource_send_blocks_data(self):
        identifier = self.approve([self.item(("https_results", "https_body"))])
        worker = self.workspace.session(self.vaults[0]).worker
        calls = []
        def revoke(action, gate, *, allow_username=False):
            self.assertTrue(gate(lambda: calls.append("login")))
            self.grants.transition(identifier, "disabled")
            if not gate(lambda: calls.append("resource")):
                raise ListingError("revoked")
            self.fail("A revoked workflow reached its resource request")
        with patch.object(worker, "use", side_effect=revoke):
            with self.assertRaises(ListingError) as error:
                self.reviewed(lambda: self.use(self.request(login=True)))
        self.assertEqual(error.exception.code, "revoked")
        self.assertEqual(calls, ["login"])

    def test_failed_final_result_release_is_not_audited_as_delivered_success(self):
        self.approve([self.item()])
        worker = self.workspace.session(self.vaults[0]).worker
        with patch.object(worker, "use", side_effect=self.fake_worker):
            result = self.reviewed(lambda: self.use(self.request(), before=lambda: self.workspace.pause()))
        self.assertIsNone(result)
        event, = self.activity.rows(action="Read HTTPS Results")
        self.assertEqual(event["outcome"], "Results Not Delivered")
        self.assertEqual(event["status"], 200)

    def test_stored_username_release_authority_comes_from_scope_not_descriptor(self):
        self.approve([self.item(metadata=True, username=True)])
        worker = self.workspace.session(self.vaults[0]).worker
        def receive(action, gate, *, allow_username=False):
            self.assertTrue(allow_username)
            self.assertTrue(gate(lambda: None))
            return {"outcome": "succeeded", "http_status": 200, "data": [{"vmid": 814, "node": "node-fresh"}]}
        with patch.object(worker, "use", side_effect=receive):
            self.reviewed(lambda: self.use(self.request()))
        self.assert_code("invalid_request", "use_password", entry=self.entry, vault=self.vaults[0],
                         usage=self.request(allow_username=True))
