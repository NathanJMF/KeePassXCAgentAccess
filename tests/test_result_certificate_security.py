"""Concurrent certificate approvals, protected dispatch and agent-visible scope."""

from concurrent.futures import ThreadPoolExecutor
from time import monotonic, sleep
import unittest
from unittest.mock import patch

import test_result_broker as result_fixture
from keepassxc_agent_access.protocol import ListingError


PIN_A = "a" * 64
PIN_B = "b" * 64


class ResultCertificateSecurityTests(unittest.TestCase):
    invoke = result_fixture.ResultBrokerTests.invoke
    enroll = result_fixture.ResultBrokerTests.enroll
    approve = result_fixture.ResultBrokerTests.approve
    assert_code = result_fixture.ResultBrokerTests.assert_code
    item = result_fixture.ResultBrokerTests.item
    request = result_fixture.ResultBrokerTests.request
    use = result_fixture.ResultBrokerTests.use
    fake_worker = result_fixture.ResultBrokerTests.fake_worker
    reviewed = result_fixture.ResultBrokerTests.reviewed

    def setUp(self):
        result_fixture.ResultBrokerTests.setUp(self)
        self.workspace.set_review_action("read_results", False)
        self.approve([self.item(("https_results", "https_body"))])
        self.worker = self.workspace.session(self.vaults[0]).worker
        self.engine.approvals.timeout = 3

    def read(self, pin, **kwargs):
        return self.use(self.request(certificate_sha256=pin), **kwargs)

    def wait_for_ticket(self, note):
        deadline = monotonic() + 2
        while monotonic() < deadline:
            for ticket in self.engine.approvals.pending():
                if ticket.context.note == note:
                    return ticket
            sleep(.01)
        self.fail("Expected an owner approval ticket for " + note)

    def test_conflicting_pending_approval_cannot_restore_a_replaced_pin(self):
        with patch.object(self.worker, "use", side_effect=self.fake_worker), ThreadPoolExecutor(2) as pool:
            first = pool.submit(self.read, PIN_A, context={"note": "First certificate"})
            first_ticket = self.wait_for_ticket("First certificate")
            second = pool.submit(self.read, PIN_B, context={"note": "Second certificate"})
            second_ticket = self.wait_for_ticket("Second certificate")
            self.assertTrue(self.engine.approvals.resolve(second_ticket.id, True))
            self.assertEqual(second.result(2)["outcome"], "succeeded")
            self.engine.approvals.resolve(first_ticket.id, True)
            with self.assertRaises(ListingError) as rejected:
                first.result(2)
            self.assertEqual(rejected.exception.code, "revoked")
            with patch.object(self.engine.approvals, "wait", side_effect=AssertionError("Lost current trust")):
                self.assertEqual(self.read(PIN_B)["outcome"], "succeeded")

    def test_identical_first_trust_shows_one_popup_and_denial_releases_reservation(self):
        with patch.object(self.worker, "use", side_effect=self.fake_worker), ThreadPoolExecutor(1) as pool:
            first = pool.submit(self.read, PIN_A, context={"note": "First read"})
            ticket = self.wait_for_ticket("First read")
            with self.assertRaises(ListingError) as duplicate:
                self.read(PIN_A)
            self.assertEqual(duplicate.exception.code, "busy")
            self.assertEqual(self.engine.approvals.pending(), (ticket,))
            self.engine.approvals.resolve(ticket.id, False)
            with self.assertRaises(ListingError) as denied:
                first.result(2)
            self.assertEqual(denied.exception.code, "declined")
            self.reviewed(lambda: self.read(PIN_A))
            with patch.object(self.engine.approvals, "wait", side_effect=AssertionError("Duplicated pin review")):
                self.assertEqual(self.read(PIN_A)["outcome"], "succeeded")

    def test_rotation_withholds_an_old_result_at_final_delivery(self):
        with patch.object(self.worker, "use", side_effect=self.fake_worker):
            self.reviewed(lambda: self.read(PIN_A))
            result = self.read(PIN_A, before=lambda: self.reviewed(lambda: self.read(PIN_B)))
            self.assertIsNone(result)
            rows = self.activity.rows(action="Read HTTPS Results", outcome="Results Not Delivered")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["status"], 200)

    def test_rotation_cancels_a_cached_two_step_workflow_before_second_send(self):
        calls = []
        with patch.object(self.worker, "use", side_effect=self.fake_worker):
            self.reviewed(lambda: self.read(PIN_A))

        def dispatch(action, gate, *, allow_username=False):
            if PIN_B in action.result_request:
                return self.fake_worker(action, gate, allow_username=allow_username)
            self.assertTrue(gate(lambda: calls.append("login")))
            self.reviewed(lambda: self.read(PIN_B))
            if not gate(lambda: calls.append("resource")):
                raise ListingError("revoked")
            self.fail("A replaced certificate authorized a second dispatch")

        with patch.object(self.worker, "use", side_effect=dispatch), self.assertRaises(ListingError) as rejected:
            self.use(self.request(login=True, certificate_sha256=PIN_A))
        self.assertEqual(rejected.exception.code, "revoked")
        self.assertEqual(calls, ["login"])

    def test_agent_cannot_read_or_set_persisted_certificate_trust(self):
        with patch.object(self.worker, "use", side_effect=self.fake_worker):
            self.reviewed(lambda: self.read(PIN_A))
        public = self.invoke("access_status", details=True)
        for item in public["requested_items"] + public["scope"]:
            self.assertNotIn("result_certificates", item)
        forged_scope = self.item(result_certificates=[[self.item()["origins"][0], PIN_B]])
        self.assert_code("invalid_request", "request_access", index=1, request={
            "identity": "Second agent", "project": "Fixture", "items": [forged_scope]})
        self.assert_code("invalid_request", "use_password", entry=self.entry, vault=self.vaults[0],
                         usage=self.request(result_certificates=forged_scope["result_certificates"]))
