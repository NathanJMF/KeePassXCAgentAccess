"""Verify event-time labels and optional current Activity context."""

from threading import RLock
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

import gi

gi.require_version("Gtk", "3.0")
from keepassxc_agent_access.activity_grouping import activity_groups, activity_matches
from keepassxc_agent_access.workspace_views import (
    activity_edit_fields, activity_execution, activity_location,
)


class ActivityLocationTests(TestCase):
    def workspace(self, entries=(), *, groups=(), available=True):
        records = {"vault-a": SimpleNamespace(name="Current archive"),
                   "vault-b": SimpleNamespace(name="Different vault")}
        session = SimpleNamespace(entries=entries, groups=groups) if available else None
        return SimpleNamespace(mutex=RLock(), registrations=records, owner_session=Mock(return_value=session))

    def test_preserves_snapshot_after_a_rename_without_looking_up_current_names(self):
        workspace = self.workspace()
        row = {"vault": "Original archive", "vault_id": "vault-a", "entry": "entry-a",
               "folder": "Original folder", "entry_title": "Original title"}
        self.assertEqual(dict(activity_location(row, workspace)),
                         {"Vault": "Original archive", "Group": "Original folder", "Key": "Original title"})
        workspace.owner_session.assert_not_called()

    def test_legacy_fallback_uses_only_the_exact_unlocked_vault_and_entry(self):
        workspace = self.workspace((
            {"id": "entry-b", "title": "Unrelated", "group_path": ["Different location"]},
            {"id": "entry-a", "title": "Registry", "group_path": ["Build", ""],
             "password": "synthetic-password", "username": "synthetic-username",
             "url": "https://ignored.example.test/"},
        ))
        row = {"vault_id": "vault-a", "entry": "entry-a"}
        self.assertEqual(dict(activity_location(row, workspace)),
                         {"Vault": "Current archive (current)",
                          "Group": "Build / (Untitled folder) (current)", "Key": "Registry (current)"})
        workspace.owner_session.assert_called_once_with("vault-a")
        self.assertEqual(row, {"vault_id": "vault-a", "entry": "entry-a"})

    def test_group_only_target_resolves_without_inventing_a_key(self):
        workspace = self.workspace(groups=(
            {"id": "root", "parent": None, "name": "Vault root"},
            {"id": "group-a", "parent": "root", "name": "Engineering"},
            {"id": "group-b", "parent": "group-a", "name": "Build"},
        ))
        row = {"vault_id": "vault-a", "group_id": "group-b"}
        self.assertEqual(dict(activity_location(row, workspace)),
                         {"Vault": "Current archive (current)", "Group": "Engineering / Build (current)",
                          "Key": None})

    def test_historical_details_work_with_no_available_session(self):
        workspace = self.workspace(available=False)
        row = {"vault": "Recorded vault", "vault_id": "vault-a", "entry": "entry-a"}
        expected = {"Vault": "Recorded vault", "Group": None, "Key": None}
        self.assertEqual(dict(activity_location(row, workspace)), expected)
        self.assertEqual(dict(activity_location(row, None)), expected)
        workspace.owner_session.assert_called_once_with("vault-a")

    def test_removal_does_not_fall_back_to_a_different_available_vault(self):
        workspace = self.workspace(({"id": "entry-a", "title": "Different title", "group_path": []},))
        row = {"vault_id": "removed-vault", "entry": "entry-a"}
        self.assertEqual(dict(activity_location(row, workspace)), {"Vault": None, "Group": None, "Key": None})
        workspace.owner_session.assert_not_called()


class ActivityExecutionTests(TestCase):
    def test_edit_fields_use_recognized_names_only(self):
        values = {"scope": "Edit request synthetic-id · Fields title, url, title, synthetic-secret",
                  "outcome": "Succeeded"}
        self.assertEqual(activity_edit_fields({**values, "action": "Apply edit · Rename entry"}),
                         ("Changed Fields", "Title, URL"))
        self.assertEqual(activity_edit_fields({**values, "action": "Request edit · Rename entry"}),
                         ("Proposed Fields", "Title, URL"))
        self.assertIsNone(activity_edit_fields({**values, "action": "List entries"}))
        self.assertIsNone(activity_edit_fields({**values, "action": "Apply edit", "scope": "Fields synthetic-secret"}))

    def test_equal_display_times_are_shown_once(self):
        row = {"action": "List entries", "requested": 1_700_000_000,
               "decided": 1_700_000_001, "completed": 1_700_000_001.2}
        execution = dict(activity_execution(row))
        self.assertIsNone(execution["Decided"])
        self.assertIsNotNone(execution["Completed"])
        other = dict(activity_execution({**row, "completed": row["requested"] + .1}))
        self.assertIsNone(other["Completed"])
        self.assertIsNotNone(other["Decided"])


class ActivityGroupingTests(TestCase):
    def test_edit_history_links_legacy_and_structured_rows_by_token_and_request(self):
        request = "dc9a7ad8-0771-4fb9-be75-df5612e4d727"
        base = {"requested": 10.0, "token": "token-a", "outcome": "Pending review",
                "action": "Request edit · Update entry", "scope": f"Edit request {request}"}
        rows = [
            dict(base, id=1),
            dict(base, id=2, requested=12.0, completed=14.0, edit_request_id=request,
                 action="Apply edit · Update entry", outcome="Succeeded", scope=None),
            dict(base, id=3, token="token-b"),
            dict(base, id=4, scope="Edit request not-a-uuid"),
        ]
        groups = activity_groups(rows)
        title, events = groups["edit", "token-a", request]
        self.assertEqual(title, "Update entry")
        self.assertEqual([row["id"] for row in events], [2, 1])
        self.assertEqual(events[0]["outcome"], "Succeeded")
        self.assertEqual(len(groups), 3)

    def test_repeat_operations_require_exact_chat_and_resource(self):
        base = {"action": "List entries", "chat_id": "chat-a", "outcome": "Paused",
                "uid": 1000, "vault_id": "vault-a", "token": "token-a", "requested": 3.0}
        rows = [dict(base, id=1, completed=8.0), dict(base, id=2, requested=4.0, outcome="Succeeded"),
                dict(base, id=3, chat_id=None), dict(base, id=4, chat_id="chat-b"),
                dict(base, id=5, vault_id="vault-b")]
        groups = activity_groups(rows)
        first = next(iter(groups.values()))[1]
        self.assertEqual([row["id"] for row in first], [1, 2])
        self.assertEqual(len(groups), 4)

    def test_filters_match_resolved_resource_and_exact_references(self):
        row = {"id": 1, "entry": "entry-id", "outcome": "Pending review"}
        resource = ("Example", "Build / Deploy", "Registry sign-in")
        self.assertTrue(activity_matches(row, resource, {"group": "deploy", "key": "registry"}))
        self.assertTrue(activity_matches(row, resource, {"key": "entry-id"}))
        self.assertFalse(activity_matches(row, resource, {"key": "registry", "outcome": "succeeded"}))
