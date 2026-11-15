from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from keepassxc_agent_access.access_settings import Action
from keepassxc_agent_access.activity import ActivityStore, Attribution
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.protocol import ListingError, decode
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.vault import VaultTarget
from keepassxc_agent_access.workspace import Registration, Unlocked, Workspace


class Worker:
    available = True

    def __init__(self, entry):
        self.row = {"id": entry, "title": "Example entry", "group_path": ["Example group"]}

    def scoped_entries(self, identifiers):
        return {"entries": [self.row] if self.row["id"] in identifiers else []}

    def entry(self, _):
        return self.row

    def use(self, action, gate):
        if not gate(lambda: None):
            raise ListingError("revoked")
        return {"outcome": "succeeded", "http_status": 200}


class ScopedBrokerTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.workspace = Workspace(directory.name, None)
        self.activity = ActivityStore(self.workspace.directory / "activity.sqlite")
        self.activity.recover(30)
        self.grants = Grants(self.workspace, self.activity)
        self.engine = ScopedBroker(self.workspace, self.grants, self.activity)
        self.entry = str(uuid4())
        self.vaults = [str(uuid4()), str(uuid4())]
        self.secrets = ["0a" * 32, "0b" * 32, "0c" * 32]
        self.action = Action("check", "Check", self.entry, "https://example.test/")
        for index, vault in enumerate(self.vaults):
            self.workspace.registrations[vault] = Registration(vault, str(index), VaultTarget(Path(f"fixture-{index}.kdbx")), None, None)
            worker = Worker(self.entry)
            self.workspace.sessions[vault] = Unlocked(worker, (), (worker.row,))
        self.workspace.save_binding(self.vaults[0], self.action)
        self.workspace.pause(False)

    def invoke(self, operation, index=0, before=None, uid=1500, **fields):
        data = {"version": 1, "operation": operation, "credential": self.secrets[index], **fields}
        output = []

        def deliver(frame, guard):
            if before:
                before()
            return guard(lambda: output.append(decode(frame)) or True)

        def live(effect=lambda: None):
            effect()
            return True

        immediate = self.engine(data, uid, None, live, live, deliver)
        return decode(immediate) if immediate else (output[0] if output else None)

    def enroll(self, items, index=0):
        return self.invoke("request_access", index, request={"identity": "Fixture agent", "project": "Fixture",
                                                            "items": items})

    def approve(self, items, index=0, select=lambda choices: choices[0]):
        self.assertEqual(self.enroll(items, index), {"status": "pending"})
        with self.workspace.mutex:
            record = self.grants.authenticate(self.secrets[index], 1500)
            self.grants.decide(record.id, [select(self.grants.choices(item)) for item in record.items])
        return record.id

    def assert_code(self, code, operation, *args, **kwargs):
        with self.assertRaises(ListingError) as error:
            self.invoke(operation, *args, **kwargs)
        self.assertEqual(error.exception.code, code)

    def test_pending_duplicate_reference_resolution_and_revocation(self):
        item = {"label": "Example entry", "metadata": True}
        self.assertEqual(self.enroll([item]), self.enroll([item]))
        self.assertEqual(len(self.grants.rows()), 1)
        self.assert_code("ineligible", "list_vaults")
        self.assert_code("ineligible", "access_status", uid=1501)
        pending = self.grants.rows()[0]
        choices = self.grants.choices(pending.items[0])
        self.assertEqual(len(choices), 2)
        self.grants.decide(pending.id, [choices[0]])
        other = self.approve([item], 1, select=lambda choices: choices[1])
        self.assertEqual([v["id"] for v in self.invoke("list_vaults")["vaults"]], self.vaults[:1])
        self.assert_code("ineligible", "list_entries", vault=self.vaults[1])
        self.assertEqual(self.invoke("list_entries", 1)["entries"][0]["id"], self.entry)
        with self.assertRaises(ListingError):
            self.enroll([{**item, "action": "check"}])
        self.grants.transition(pending.id, "disabled")
        self.assert_code("ineligible", "list_entries")
        self.assertTrue(self.invoke("list_entries", 1)["entries"])
        self.grants.transition(pending.id, "active")
        self.assertTrue(self.invoke("list_entries")["entries"])
        self.grants.transition(pending.id, "removed")
        self.assert_code("ineligible", "list_entries")
        with self.assertRaises(ListingError):
            self.enroll([item])
        self.activity.rows(agent="fixture", outcome="succeeded")
        self.assertTrue(self.grants.records[other].last_used)
        self.assertNotIn(self.secrets[0].encode(), self.grants.path.read_bytes())
        self.assertEqual(Grants(self.workspace, self.activity).records[pending.id].status, "removed")

    def test_cross_vault_scope_and_stale_action(self):
        one, two = self.vaults
        use = {"vault": one, "entry": self.entry, "action": "check"}
        metadata = {"vault": two, "entry": self.entry, "metadata": True}
        self.approve([use, metadata])
        self.assertEqual(len(self.invoke("list_vaults")["vaults"]), 2)
        self.assert_code("select_vault", "list_entries")
        self.assertEqual(self.invoke("list_entries", vault=one), {"entries": []})
        self.assertTrue(self.invoke("list_entries", vault=two)["entries"])
        self.assert_code("ineligible", "use_password", vault=two, entry=self.entry, action="check")
        self.assert_code("invalid_request", "use_password", vault=one, entry=self.entry, action="check", url="override")
        self.assertEqual(self.invoke("use_password", vault=one, entry=self.entry, action="check")["http_status"], 200)
        self.workspace.save_binding(one, Action("check", "Check", self.entry, "https://example.test/new"), "check")
        self.assert_code("ineligible", "use_password", vault=one, entry=self.entry, action="check")
        self.assertTrue(self.invoke("list_entries", vault=two)["entries"])

    def test_revoke_at_delivery_and_dispatch(self):
        vault = self.vaults[0]
        item = {"vault": vault, "entry": self.entry, "metadata": True, "action": "check"}
        identifier = self.approve([item])
        self.assert_code("revoked", "list_entries", before=lambda: (self.workspace.pause(), self.workspace.pause(False)))
        self.assertIsNone(self.grants.records[identifier].last_used)
        worker = self.workspace.session(vault).worker

        def use(_action, gate):
            self.grants.transition(identifier, "disabled")
            self.grants.transition(identifier, "active")
            self.assertFalse(gate(lambda: self.fail("Dispatched after revocation")))
            raise ListingError("revoked")

        with patch.object(worker, "use", use):
            self.assert_code("revoked", "use_password", entry=self.entry, action="check")
        self.assertEqual(len(self.activity.rows(outcome="revoked")), 2)

    def test_review_rejects_stale_choice_and_denied_token(self):
        self.enroll([{"label": "Example entry", "action": "check"}])
        pending = self.grants.rows()[0]
        choices = self.grants.choices(pending.items[0])
        self.workspace.save_binding(self.vaults[0], Action("check", "Check", self.entry, "https://example.test/new"), "check")
        with self.assertRaises(ValueError):
            self.grants.decide(pending.id, choices)
        self.grants.decide(pending.id, None)
        self.assertEqual(self.invoke("access_status"), {"status": "denied"})
        self.assertEqual(self.grants.rows(), [])
        self.assert_code("ineligible", "list_vaults")
