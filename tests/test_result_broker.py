"""Result release needs explicit scope, review and live guards at every step."""

from concurrent.futures import ThreadPoolExecutor
from time import monotonic, sleep
import unittest
from unittest.mock import patch

import test_scoped_broker as base
from keepassxc_agent_access.protocol import ListingError


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

    def test_pin_still_needs_review_after_owner_enables_auto_result_release(self):
        self.approve([self.item()])
        self.workspace.set_review_action("read_results", False)
        self.assertFalse(self.workspace.requires_review("read_results"))
        worker = self.workspace.session(self.vaults[0]).worker
        with patch.object(worker, "use", side_effect=self.fake_worker):
            self.assertEqual(self.use(self.request())["data"][0]["vmid"], 814)
            result = self.reviewed(lambda: self.use(self.request(certificate_sha256="a" * 64)))
            self.assertEqual(result["data"][0]["vmid"], 814)

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
