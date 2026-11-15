import json
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
        self.rows = [self.row]

    def scoped_entries(self, identifiers):
        return {"entries": [row for row in self.rows if row["id"] in identifiers]}

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
            owner_row = {**worker.row, "username": f"fixture-user-{index}", "url": f"https://fixture-{index}.example.test",
                         "password": "fixture-password", "notes": "fixture-notes"}
            self.workspace.sessions[vault] = Unlocked(worker, (), (owner_row,))
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

    def test_credential_audit_snapshots_only_known_target_labels(self):
        vault = self.vaults[0]
        self.approve([{"vault": vault, "entry": self.entry, "action": "check"}])
        self.assertEqual(self.invoke("use_password", vault=vault, entry=self.entry, action="check"),
                         {"outcome": "succeeded", "http_status": 200})
        self.assert_code("ineligible", "use_password", vault=vault, entry=self.entry, action="unknown")
        denied, use = self.activity.rows(action="Use password")
        self.assertEqual((use["vault"], use["folder"], use["entry_title"], use["entry"]),
                         ("0", "Example group", "Example entry", self.entry))
        self.assertIsNone(denied["entry_title"])
        self.assertIsNone(denied["folder"])
        self.assertNotIn("fixture-password", repr(use))

        session = self.workspace.session(vault)
        changed = {**session.entries[0], "title": "", "group_path": []}
        self.workspace.sessions[vault] = Unlocked(session.worker, session.groups, (changed,))
        self.invoke("use_password", vault=vault, entry=self.entry, action="check")
        new, _, previous = self.activity.rows(action="Use password")
        self.assertEqual((new["folder"], new["entry_title"]), ("Root", "(Untitled entry)"))
        self.assertEqual((previous["folder"], previous["entry_title"]), ("Example group", "Example entry"))

    def test_token_lifecycle_describes_exact_and_multi_vault_scopes(self):
        vault, other = self.vaults
        identifier = self.approve([
            {"vault": vault, "entry": self.entry, "metadata": True},
            {"vault": vault, "entry": self.entry, "action": "check"},
        ])
        self.grants.transition(identifier, "disabled")
        self.grants.transition(identifier, "active")
        self.grants.transition(identifier, "removed")
        for action in ("Approve token", "Disable token", "Re-enable token", "Remove token"):
            actual, = self.activity.rows(action=action)
            self.assertEqual((actual["vault"], actual["vault_id"], actual["folder"], actual["entry_title"]),
                             ("0", vault, "Example group", "Example entry"))
        enrollment, = self.activity.rows(action="Request token")
        self.assertEqual((enrollment["vault"], enrollment["folder"], enrollment["entry_title"]), (None, None, None))

        self.approve([
            {"vault": vault, "entry": self.entry, "metadata": True},
            {"vault": other, "entry": self.entry, "metadata": True},
        ], 1)
        latest = self.activity.rows(action="Approve token")[0]
        self.assertEqual((latest["vault"], latest["folder"], latest["entry_title"]),
                         ("Multiple vaults", None, "Multiple keys"))
        self.assertIsNone(latest["vault_id"])
        self.assertIsNone(latest["entry"])

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

    def test_optional_metadata_requires_discovery_and_explicit_permission(self):
        vault = self.vaults[0]
        item = {"vault": vault, "entry": self.entry, "metadata": True}
        for invalid in ({"metadata": False, "username": True, "action": "check"},
                        {"url": "true"}, {"username": 1}, {"password": True}):
            with self.subTest(invalid=invalid), self.assertRaises(ListingError) as error:
                self.enroll([{**item, **invalid}])
            self.assertEqual(error.exception.code, "invalid_request")

        self.approve([item])
        self.approve([{**item, "username": True}], index=1)
        self.approve([{**item, "url": True}], index=2)
        basic = self.workspace.session(vault).worker.row
        fields = ["username", "url"]
        self.assertEqual(self.invoke("list_entries", fields=fields), {"entries": [basic]})
        self.assertEqual(self.invoke("list_entries", 1), {"entries": [basic]})
        self.assertEqual(self.invoke("list_entries", 1, fields=fields),
                         {"entries": [{**basic, "username": "fixture-user-0"}]})
        self.assertEqual(self.invoke("list_entries", 2, fields=fields),
                         {"entries": [{**basic, "url": "https://fixture-0.example.test"}]})
        for invalid in ("username", [True], ["password"], ["url", "url"]):
            with self.subTest(invalid=invalid):
                self.assert_code("invalid_request", "list_entries", fields=invalid)
        history = repr(self.activity.rows())
        self.assertIn("(metadata, username)", history)
        self.assertIn("(metadata, url)", history)
        self.assertIn("Requested entry fields · username, url", history)
        for value in ("fixture-user-0", "https://fixture-0.example.test", "fixture-password", "fixture-notes"):
            self.assertNotIn(value, history)

    def test_listing_does_not_forward_unapproved_worker_fields_or_identifiers(self):
        vault = self.vaults[0]
        self.approve([{"vault": vault, "entry": self.entry, "metadata": True, "username": True}])
        worker = self.workspace.session(vault).worker
        selected = {**worker.row, "password": "fixture-password", "url": "https://unapproved.example.test"}
        unselected = {**selected, "id": str(uuid4())}
        with patch.object(worker, "scoped_entries", return_value={"entries": [selected, unselected]}):
            self.assertEqual(self.invoke("list_entries", fields=["username", "url"]),
                             {"entries": [{**worker.row, "username": "fixture-user-0"}]})

    def test_metadata_is_scoped_by_entry_and_vault(self):
        first, second = self.vaults
        session = self.workspace.session(first)
        worker = session.worker
        another = {"id": str(uuid4()), "title": "Second entry", "group_path": []}
        worker.rows.append(another)
        self.workspace.sessions[first] = Unlocked(
            worker, (), (*session.entries, {**another, "username": "other-user", "url": "https://other.example.test"}),
        )
        self.approve([
            {"vault": first, "entry": self.entry, "metadata": True, "username": True},
            {"vault": first, "entry": another["id"], "metadata": True},
            {"vault": second, "entry": self.entry, "metadata": True, "url": True},
        ])
        fields = ["username", "url"]
        self.assertEqual(self.invoke("list_entries", vault=first, fields=fields),
                         {"entries": [{**worker.row, "username": "fixture-user-0"}, another]})
        self.assertEqual(self.invoke("list_entries", vault=second, fields=fields),
                         {"entries": [{**worker.row, "url": "https://fixture-1.example.test"}]})

    def test_legacy_grants_do_not_share_new_fields(self):
        item = {"vault": self.vaults[0], "entry": self.entry, "metadata": True}
        identifier = self.approve([item])
        saved = json.loads(self.grants.path.read_text())
        for row in (*saved["grants"][0]["items"], *saved["grants"][0]["scope"]):
            del row["username"], row["url"]
        self.grants.path.write_text(json.dumps(saved))
        self.grants = Grants(self.workspace, self.activity)
        self.engine.grants = self.grants
        self.assertEqual(self.enroll([item]), {"status": "active"})
        scope, = self.grants.records[identifier].scope
        self.assertFalse(scope.username or scope.url)
        self.assertEqual(self.invoke("list_entries", fields=["username", "url"]),
                         {"entries": [self.workspace.session(self.vaults[0]).worker.row]})
        with self.assertRaises(ListingError) as error:
            self.enroll([{**item, "url": True}])
        self.assertEqual(error.exception.code, "ineligible")

    def test_metadata_delivery_revokes_after_session_replacement(self):
        vault = self.vaults[0]
        identifier = self.approve([{"vault": vault, "entry": self.entry, "metadata": True, "url": True}])
        session = self.workspace.session(vault)
        replacement = Unlocked(session.worker, (), ({**session.entries[0], "url": "https://updated.example.test"},))

        def replace():
            self.workspace.sessions[vault] = replacement

        self.assert_code("revoked", "list_entries", fields=["url"], before=replace)
        self.assertIsNone(self.grants.records[identifier].last_used)
        self.assertEqual(self.invoke("list_entries", fields=["url"])["entries"][0]["url"],
                         "https://updated.example.test")

    def test_review_rejects_a_stale_displayed_metadata_value(self):
        vault = self.vaults[0]
        self.enroll([{"vault": vault, "entry": self.entry, "metadata": True, "url": True}])
        record, = self.grants.rows()
        choice, = self.grants.choices(record.items[0])
        self.assertEqual(choice.url, "https://fixture-0.example.test")
        self.assertIsNone(choice.username)

        session = self.workspace.session(vault)
        changed = {**session.entries[0], "url": "https://updated.example.test"}
        self.workspace.sessions[vault] = Unlocked(session.worker, (), (changed,))
        with self.assertRaises(ValueError):
            self.grants.decide(record.id, (choice,))
        self.assertEqual(self.invoke("access_status"), {"status": "pending"})

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
