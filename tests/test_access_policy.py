from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from time import monotonic, sleep
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from keepassxc_agent_access.access import AccessEngine, Request
from keepassxc_agent_access.access_settings import AccessMode, AccessStore, Action, VaultPolicy
from keepassxc_agent_access.activity import ActivityError, ActivityStore
from keepassxc_agent_access.approvals import ApprovalQueue
from keepassxc_agent_access.protocol import LIST_REQUEST, ListingError, decode, encode


class FixtureSession:
    def __init__(self):
        self.identity = str(uuid4())
        self.rows = [{"id": str(uuid4()), "title": title, "group_path": ["Sandbox"]}
                     for title in ("Available", "Protected")]
        self.dispatched = 0

    def list_entries(self):
        return encode({"entries": self.rows})

    def entry(self, identifier):
        return next((row for row in self.rows if row["id"] == identifier), None)

    def use(self, _action, gate):
        def send():
            self.dispatched += 1
        if not gate(send):
            raise ListingError("revoked")
        return {"outcome": "succeeded", "http_status": 204}


class AccessPolicyTests(TestCase):
    def setUp(self):
        root = TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.settings = AccessStore(Path(root.name) / "access.json")
        self.activity = ActivityStore(Path(root.name) / "activity.sqlite")
        self.activity.recover(30)
        self.session = FixtureSession()
        self.approvals = ApprovalQueue(timeout=1)
        self.engine = AccessEngine(self.settings, self.activity, self.approvals)
        executor = ThreadPoolExecutor(max_workers=4)
        self.addCleanup(executor.shutdown)
        self.submit = executor.submit

    def settings_for(self, mode):
        first, second = (row["id"] for row in self.session.rows)
        policy = VaultPolicy(frozenset({first}), (
            Action("one", "Check one", first, "https://fixture.invalid/one"),
            Action("two", "Check two", second, "https://fixture.invalid/two"),
        ))
        self.settings.write(replace(self.settings.read(), mode=mode, vaults=((self.session.identity, policy),)))

    def request(self, payload, live=lambda: True, dispatch=None, deliver=None):
        captured = []
        body = self.engine(
            payload, 1234, self.session, live, dispatch or (lambda effect: not effect()),
            deliver or (lambda frame: not captured.append(decode(frame))),
        )
        return decode(body) if body is not None else captured[0]

    def use(self, number):
        return {"version": 1, "operation": "use_password",
                "entry": self.session.rows[number]["id"], "action": ("one", "two")[number]}

    def ticket(self):
        deadline = monotonic() + 1
        while monotonic() < deadline:
            pending = self.approvals.pending()
            if pending:
                return pending[0]
            sleep(.01)
        self.fail("Approval was not queued")

    def test_modes_gate_use_and_filter_list(self):
        self.settings_for(AccessMode.ALLOW)
        self.assertEqual(self.request(self.use(1))["http_status"], 204)
        self.assertEqual(self.request(LIST_REQUEST)["entries"], self.session.rows)
        with self.assertRaisesRegex(ListingError, "unavailable"):
            self.request({**self.use(1), "action": "missing"})
        self.assertFalse(self.approvals.pending())

        self.settings_for(AccessMode.REVIEW)
        reviewed = self.submit(self.request, LIST_REQUEST)
        ticket = self.ticket()
        self.assertEqual(ticket.scope, ("Sandbox / Available", "Sandbox / Protected"))
        self.assertFalse(reviewed.done())
        self.assertTrue(self.approvals.resolve(ticket.id, False))
        self.assertFalse(self.approvals.resolve(ticket.id, True))
        with self.assertRaisesRegex(ListingError, "declined"):
            reviewed.result(timeout=2)

        self.settings_for(AccessMode.SMART)
        self.assertEqual(self.request(LIST_REQUEST)["entries"], self.session.rows[:1])
        self.assertEqual(self.request(self.use(0))["outcome"], "succeeded")
        protected = self.submit(self.request, self.use(1))
        ticket = self.ticket()
        self.assertEqual(ticket.destination, "https://fixture.invalid:443/two")
        self.assertTrue(self.approvals.resolve(ticket.id, True))
        self.assertFalse(self.approvals.resolve(ticket.id, True))
        self.assertEqual(protected.result(timeout=2)["outcome"], "succeeded")

        extended = self.submit(self.request, {**LIST_REQUEST, "include_reviewed": True})
        self.approvals.resolve(self.ticket().id, True)
        self.assertEqual(extended.result(timeout=2)["entries"], self.session.rows)
        self.assertEqual(self.session.dispatched, 3)
        self.assertIn("Declined", [event["outcome"] for event in self.activity.rows()])

    def test_pending_does_not_block_another_request_and_expires(self):
        self.settings_for(AccessMode.SMART)
        pending = self.submit(self.request, self.use(1))
        self.ticket()
        self.assertEqual(self.request(LIST_REQUEST)["entries"], self.session.rows[:1])
        with self.assertRaisesRegex(ListingError, "timed out"):
            pending.result(timeout=2)

    def test_disconnect_or_changed_session_revokes_unconsumed_approval(self):
        self.settings_for(AccessMode.REVIEW)
        connected = Event()
        connected.set()
        pending = self.submit(self.request, self.use(1), connected.is_set)
        ticket = self.ticket()
        connected.clear()
        self.approvals.resolve(ticket.id, True)
        with self.assertRaises(ListingError) as error:
            pending.result(timeout=2)
        self.assertEqual(error.exception.code, "revoked")
        self.assertEqual(self.session.dispatched, 0)

    def test_storage_and_final_dispatch_fail_closed(self):
        self.settings_for(AccessMode.ALLOW)
        with patch.object(self.activity, "authorize", side_effect=ActivityError()):
            for payload in (self.use(0), LIST_REQUEST):
                with self.assertRaises(ListingError) as error:
                    self.request(payload, deliver=lambda _: self.fail("Unaudited listing"))
                self.assertEqual(error.exception.code, "audit_unavailable")
        with self.assertRaises(ListingError) as error:
            self.request(self.use(0), dispatch=lambda _: False)
        self.assertEqual(error.exception.code, "revoked")
        self.assertEqual(self.session.dispatched, 0)
        with self.assertRaises(ListingError) as error:
            self.request(LIST_REQUEST, deliver=lambda _: False)
        self.assertEqual(error.exception.code, "revoked")
        self.assertEqual(self.activity.rows()[0]["outcome"], "Revoked")

    def test_route_override_and_ambiguous_type_are_rejected(self):
        for payload in ({**self.use(0), "url": "https://override.invalid/"},
                        {**LIST_REQUEST, "include_reviewed": "true"},
                        {**LIST_REQUEST, "version": True}):
            with self.assertRaises(ListingError) as error:
                Request.parse(payload)
            self.assertEqual(error.exception.code, "invalid_request")
