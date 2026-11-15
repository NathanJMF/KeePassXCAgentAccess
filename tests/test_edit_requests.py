from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from pykeepass import PyKeePass, create_database

from keepassxc_agent_access.access_settings import Action, ActionType
from keepassxc_agent_access.activity import ActivityStore, Attribution
from keepassxc_agent_access.edit_requests import EditRequests
from keepassxc_agent_access.grants import Grants
from keepassxc_agent_access.protocol import ListingError, decode
from keepassxc_agent_access.scoped_broker import ScopedBroker
from keepassxc_agent_access.vault import VaultError, VaultTarget
from keepassxc_agent_access.workspace import Workspace


class EditRequestsTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / "fixture.kdbx"
        self.unlock = "Synthetic fixture unlock"
        self.fixture = create_database(self.path, self.unlock)
        group = self.fixture.add_group(self.fixture.root_group, "First folder")
        root = self.fixture.root_group
        self.root_id = str(root.uuid)
        self.group_id = str(group.uuid)
        self.entry_id = str(self.fixture.add_entry(
            group, "Scoped entry", "sample user", "Synthetic original entry secret", notes="Keep notes",
        ).uuid)
        self.unscoped = str(self.fixture.add_entry(
            root, "Unscoped entry", "another user", "Synthetic unrelated entry secret",
        ).uuid)
        self.fixture.save()
        self.workspace = Workspace(self.root, None)
        self.addCleanup(self.workspace.lock_all)
        self.vault = self.workspace.add(VaultTarget(self.path), self.unlock, False)
        self.activity = ActivityStore(self.root / "activity.sqlite")
        self.activity.recover(30)
        self.grants = Grants(self.workspace, self.activity)
        self.workspace.save_binding(self.vault, Action("basic", "Basic", self.entry_id, "https://example.test/"))
        self.workspace.save_binding(self.vault, Action(
            "bearer", "Bearer", self.entry_id, "https://example.test/", kind=ActionType.BEARER,
        ))
        self.edits = EditRequests(self.workspace, self.grants, self.activity)
        self.engine = ScopedBroker(self.workspace, self.grants, self.activity, edits=self.edits)
        self.credential = "4b" * 32
        self.other_credential = "4c" * 32
        self.token = self._grant(self.credential)
        self.other = self._grant(self.other_credential)
        self.workspace.pause(False)

    def _grant(self, credential):
        items = [{"vault": self.vault, "entry": self.entry_id, "metadata": True}] + [
            {"vault": self.vault, "entry": self.entry_id, "action": action} for action in ("basic", "bearer")
        ]
        self.grants.enroll(credential, 123, {"identity": "Synthetic agent", "project": "Fixture project",
                                            "items": items}, Attribution(model="Fixture model"))
        pending = self.grants.authenticate(credential, 123)
        self.grants.decide(pending.id, [self.grants.choices(item)[0] for item in pending.items])
        return self.grants.authenticate(credential, 123)

    def _request(self, operation, **values):
        return {"id": str(uuid4()), "operation": operation, "vault": self.vault, **values}

    def _submit(self, operation, **values):
        request = self._request(operation, **values)
        result = self.edits.submit(self.token, request)
        self.assertEqual(result, {"id": request["id"], "status": "pending"})
        return request

    def _apply(self, operation, **values):
        request = self._submit(operation, **values)
        review = self.edits.preview(self.token.id, request["id"])
        return review, self.edits.approve(review)

    def _wire(self, operation, credential=None, **values):
        output = []

        def live(effect=lambda: None):
            effect()
            return True

        def deliver(frame, guard):
            return guard(lambda: output.append(decode(frame)) or True)

        direct = self.engine({"version": 1, "operation": operation,
                              "credential": credential or self.credential, **values},
                             123, None, live, live, deliver)
        return decode(direct) if direct else output[0]

    def test_submission_does_not_probe_resources_and_is_isolated_per_token(self):
        real = self._request("update_entry", entry=self.unscoped, fields={"title": "Unscoped update"})
        absent = self._request("update_entry", vault=str(uuid4()), entry=str(uuid4()), fields={"title": "Other"})
        self.workspace.pause()
        for payload in (real, absent):
            self.assertEqual(self._wire("request_edit", request=payload), {"id": payload["id"], "status": "pending"})
            self.assertEqual(self._wire("request_edit", request=dict(payload)), self._wire("edit_status", id=payload["id"]))
            with self.assertRaises(ListingError) as cross_token:
                self._wire("edit_status", credential=self.other_credential, id=payload["id"])
            self.assertEqual(cross_token.exception.code, "ineligible")

        impossible = dict(real, entry="*")
        with self.assertRaises(ListingError) as invalid_target:
            self._wire("request_edit", request=impossible)
        self.assertEqual(invalid_target.exception.code, "invalid_request")
        for raw in (dict(real, password="Never persisted"), dict(real, fields={"password": "Never persisted"})):
            with self.assertRaises(ListingError) as invalid_fields:
                self._wire("request_edit", request=raw)
            self.assertEqual(invalid_fields.exception.code, "invalid_request")

        with self.assertRaisesRegex(VaultError, "unavailable"):
            self.edits.preview(self.token.id, absent["id"])
        review = self.edits.preview(self.token.id, real["id"])
        self.assertEqual(review.old, (("title", "Unscoped entry"),))
        self.assertEqual(review.new, (("title", "Unscoped update"),))
        with self.assertRaisesRegex(VaultError, "Resume"):
            self.edits.approve(review)
        self.workspace.pause(False)
        self.assertEqual(self.edits.approve(review), {"id": real["id"], "status": "applied"})
        self.assertEqual(self._wire("list_entries")["entries"], [
            {"id": self.entry_id, "title": "Scoped entry", "group_path": ["First folder"]},
        ])
        self.assertNotIn("Never persisted", self.activity.path.read_bytes().decode("utf8", errors="replace"))

    def test_operations_preview_exact_paths_values_subtrees_and_result(self):
        review, result = self._apply("create_group", parent=self.root_id, fields={"name": "New folder"})
        self.assertEqual(review.new, (("name", "New folder"),))
        folder = result["result"]
        self.assertEqual(self._wire("request_edit", request={
            "id": result["id"], "operation": "create_group", "vault": self.vault, "parent": self.root_id,
            "fields": {"name": "New folder"},
        }), result)
        self.assertEqual(sum(group["id"] == folder for group in self.workspace.session(self.vault).groups), 1)
        review, result = self._apply("create_entry", parent=folder, fields={"title": "New entry"})
        self.assertEqual(review.destination_path[-1], "New folder")
        created = result["result"]
        review, _ = self._apply("rename_group", group=folder, fields={"name": "Renamed folder"})
        self.assertEqual(review.old, (("name", "New folder"),))
        self.assertEqual(review.target_path[-1], "New folder")
        review, _ = self._apply("move_entry", entry=self.unscoped, parent=folder)
        self.assertEqual(review.target_path[-1], "Unscoped entry")
        self.assertEqual(review.destination_path[-1], "Renamed folder")
        review, _ = self._apply("move_group", group=folder, parent=self.group_id)
        self.assertEqual((review.group_count, review.entry_count), (1, 2))
        self.assertEqual(review.destination_path[-1], "First folder")
        review, _ = self._apply("recycle_entry", entry=created)
        self.assertEqual(review.destination_path[-1], "Recycle Bin")
        review, _ = self._apply("recycle_group", group=folder)
        self.assertEqual((review.group_count, review.entry_count), (1, 1))
        self.assertEqual(review.target_path[-2:], ("First folder", "Renamed folder"))
        self.assertEqual(review.destination_path[-1], "Recycle Bin")
        self.assertEqual({entry["id"] for entry in self.workspace.session(self.vault).entries}, {self.entry_id})

    def test_credential_edits_invalidate_bound_actions_and_never_audit_password(self):
        retained = tuple(self.workspace.registrations[self.vault].bindings)
        self._apply("update_entry", entry=self.entry_id, fields={"title": "Renamed"})
        self.assertEqual(self.workspace.registrations[self.vault].bindings, retained)
        review, _ = self._apply("update_entry", entry=self.entry_id, fields={"username": "New owner-reviewed value"})
        self.assertEqual(review.old, (("username", "sample user"),))
        updated = tuple(self.workspace.registrations[self.vault].bindings)
        self.assertNotEqual(updated, retained)
        for action in ("basic", "bearer"):
            with self.assertRaises(ListingError) as unapproved:
                self._wire("use_password", vault=self.vault, entry=self.entry_id, action=action)
            self.assertEqual(unapproved.exception.code, "ineligible")
        owner_password = "Synthetic owner replacement password"
        request = self._submit("replace_password", entry=self.entry_id, password_source="owner")
        review = self.edits.preview(self.token.id, request["id"])
        self.assertEqual(review.password_source, "owner")
        self.assertEqual((review.old, review.new), ((), ()))
        result = self.edits.approve(review, password=owner_password)
        self.assertEqual(result, {"id": request["id"], "status": "applied"})
        current = PyKeePass(self.path, password=self.unlock).find_entries(uuid=UUID(self.entry_id), first=True)
        self.assertEqual(current.password, owner_password)
        self.assertEqual(current.notes, "Keep notes")
        self.assertNotIn(owner_password.encode(), self.activity.path.read_bytes())
        self.assertNotEqual(tuple(self.workspace.registrations[self.vault].bindings), updated)
        _, result = self._apply("replace_password", entry=self.entry_id, password_source="generate")
        self.assertEqual(set(result), {"id", "status"})
        current = PyKeePass(self.path, password=self.unlock).find_entries(uuid=UUID(self.entry_id), first=True)
        self.assertNotEqual(current.password, owner_password)
        self.assertGreaterEqual(len(current.password), 40)
        self.assertNotIn(current.password.encode(), self.activity.path.read_bytes())
        self.assertTrue(self.activity.rows(action="Apply edit", outcome="Succeeded"))

    def test_stale_review_does_not_apply_and_gate_checks_revocation_and_pause(self):
        request = self._submit("create_group", parent=self.group_id, fields={"name": "Delayed group"})
        review = self.edits.preview(self.token.id, request["id"])
        self.workspace.put_group(self.vault, self.root_id, group=self.group_id, name="Externally changed selection")
        with self.assertRaisesRegex(VaultError, "submit a fresh request"):
            self.edits.approve(review)
        self.assertEqual(self._wire("edit_status", id=request["id"])["status"], "stale")
        self.assertTrue(self.activity.rows(action="Apply edit", outcome="Stale"))
        request = self._submit("create_group", parent=self.group_id, fields={"name": "Delayed group"})
        review = self.edits.preview(self.token.id, request["id"])
        self.assertEqual(review.destination_path[-1], "Externally changed selection")
        before = self.path.read_bytes()
        live_worker = self.workspace.session(self.vault).worker
        original = live_worker.owner_edit

        def pause_before_publish(change, gate):
            def revoked(publish):
                self.workspace.pause()
                self.workspace.pause(False)
                return gate(publish)
            return original(change, revoked)

        with patch.object(live_worker, "owner_edit", side_effect=pause_before_publish):
            with self.assertRaisesRegex(VaultError, "access changed"):
                self.edits.approve(review)
        self.assertEqual(self._wire("edit_status", id=request["id"])["status"], "stale")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(live_worker.available)

        request = self._submit("create_group", parent=self.group_id, fields={"name": "Revoked group"})
        review = self.edits.preview(self.token.id, request["id"])

        def revoke_before_publish(change, gate):
            def revoked(publish):
                self.grants.transition(self.token.id, "disabled")
                self.grants.transition(self.token.id, "active")
                return gate(publish)
            return original(change, revoked)

        with patch.object(live_worker, "owner_edit", side_effect=revoke_before_publish):
            with self.assertRaisesRegex(VaultError, "access changed"):
                self.edits.approve(review)
        self.assertEqual(self._wire("edit_status", id=request["id"])["status"], "stale")
        self.assertEqual(self.path.read_bytes(), before)

    def test_audit_preserves_submission_attribution_and_omits_values(self):
        fields = {"title": "Synthetic proposed title", "username": "Synthetic proposed username"}
        request = self._request("update_entry", entry=self.entry_id, fields=fields)
        context = {"model": "Edit model", "chat": "Edit submission chat", "chat_id": "edit-chat"}
        self._wire("request_edit", request=request, context=context)
        self.edits.deny(self.token.id, request["id"])
        rows = self.activity.rows(chat=context["chat"])
        self.assertEqual({row["outcome"] for row in rows}, {"Pending review", "Denied"})
        for row in rows:
            self.assertEqual((row["model"], row["chat_id"]), (context["model"], context["chat_id"]))
            self.assertIn("Fields title, username", row["scope"])
            for value in fields.values():
                self.assertNotIn(value, str(row))

        create = self._request("create_group", parent=self.root_id, fields={"name": "Synthetic new folder"})
        self._wire("request_edit", request=create, context=context)
        self.edits.approve(self.edits.preview(self.token.id, create["id"]))
        success = self.activity.rows(chat=context["chat"], action="Apply edit", outcome="Succeeded")[0]
        self.assertIn(f"Destination group {self.root_id}", success["scope"])

    def test_activity_snapshots_reviewed_titles_folders_and_destinations(self):
        request = self._submit("update_entry", entry=self.entry_id, fields={"title": "Approved new title"})
        queued, = self.activity.rows(action="Request edit")
        self.assertEqual((queued["vault"], queued["folder"], queued["entry_title"]), (None, None, None))
        preview = self.edits.preview(self.token.id, request["id"])
        self.edits.approve(preview)
        updated, = self.activity.rows(action="Apply edit · Update entry", outcome="Succeeded")
        self.assertEqual((updated["vault"], updated["folder"], updated["entry_title"], updated["entry"]),
                         (preview.vault_name, "First folder", "Scoped entry", self.entry_id))
        self.assertNotIn("Approved new title", repr(updated))

        _, result = self._apply("create_entry", parent=self.root_id, fields={"title": "Approved creation"})
        created, = self.activity.rows(action="Apply edit · Create entry", outcome="Succeeded")
        self.assertEqual((created["folder"], created["entry_title"], created["entry"], created["destination"]),
                         ("Root", "Approved creation", result["result"], "Root"))

        self._apply("move_entry", entry=self.entry_id, parent=self.root_id)
        moved, = self.activity.rows(action="Apply edit · Move entry", outcome="Succeeded")
        self.assertEqual((moved["folder"], moved["entry_title"], moved["destination"]),
                         ("First folder", "Approved new title", "Root"))

        request = self._submit("recycle_group", group=self.group_id)
        review = self.edits.preview(self.token.id, request["id"])
        self.edits.deny(self.token.id, request["id"], preview=review)
        denied, = self.activity.rows(action="Deny edit", outcome="Denied")
        self.assertEqual((denied["folder"], denied["entry_title"], denied["destination"]),
                         ("First folder", None, "Recycle Bin"))

    def test_reenabled_token_cannot_apply_an_earlier_pending_edit(self):
        request = self._submit("create_group", parent=self.root_id, fields={"name": "Revoked"})
        self.grants.transition(self.token.id, "disabled")
        self.grants.transition(self.token.id, "active")
        self.assertEqual(self._wire("edit_status", id=request["id"]), {"id": request["id"], "status": "stale"})
        self.assertFalse(self.edits.rows())
        self.assertTrue(self.activity.rows(action="Cancel edit", outcome="Stale"))

    def test_restart_keeps_idempotence_and_never_retries_unconfirmed_edits(self):
        requests = [self._submit("create_group", parent=self.root_id, fields={"name": name})
                    for name in ("Denied group", "Dispatched group", "Applying group", "Pending group")]
        denied, dispatched, applying, pending = requests
        self.edits.deny(self.token.id, denied["id"])
        for request in (dispatched, applying):
            row = self.edits.preview(self.token.id, request["id"]).record
            self.edits._status(row, "pending", "applying")
            if request is dispatched:
                self.edits._status(row, "applying", "dispatched")
        before = self.path.read_bytes()
        reopened = EditRequests(self.workspace, self.grants, self.activity)
        for request, status in zip(requests, ("denied", "interrupted", "stale", "pending")):
            expected = {"id": request["id"], "status": status}
            self.assertEqual(reopened.status(self.token, request["id"]), expected)
            self.assertEqual(reopened.submit(self.token, request), expected)
        with self.assertRaises(ListingError) as altered_replay:
            reopened.submit(self.token, dict(dispatched, fields={"name": "Different group"}))
        self.assertEqual(altered_replay.exception.code, "invalid_request")
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
