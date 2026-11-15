"""Verify event-time labels and optional current Activity context."""

from threading import RLock
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock

import gi

gi.require_version("Gtk", "3.0")
from keepassxc_agent_access.workspace_views import (
    activity_edit_fields, activity_execution, activity_location, activity_target,
)


class ActivityLocationTests(TestCase):
    def workspace(self, entries=(), *, available=True):
        records = {"vault-a": SimpleNamespace(name="Current archive"),
                   "vault-b": SimpleNamespace(name="Different vault")}
        return SimpleNamespace(mutex=RLock(), registrations=records,
                               owner_session=Mock(return_value=SimpleNamespace(entries=entries) if available else None))

    def test_target_formats_recorded_folder_and_entry(self):
        self.assertEqual(activity_target({"folder": "Engineering / Build", "entry_title": "Registry"}),
                         "Engineering / Build / Registry")
        self.assertEqual(activity_target({"folder": "Root", "entry_title": "Service"}), "Root / Service")
        self.assertEqual(activity_target({"folder": "Engineering"}), "Engineering")
        self.assertEqual(activity_target({"entry_title": "Registry"}), "Registry")
        self.assertEqual(activity_target({"entry": "entry-a", "folder": None}), "—")

    def test_preserves_snapshot_after_a_rename_without_looking_up_current_names(self):
        workspace = self.workspace()
        row = {"vault": "Original archive", "vault_id": "vault-a", "entry": "entry-a",
               "folder": "Original folder", "entry_title": "Original title"}
        self.assertEqual(dict(activity_location(row, workspace)),
                         {"Vault": "Original archive", "Folder": "Original folder", "Entry": "Original title"})
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
                          "Folder": "Build / (Untitled folder) (current)", "Entry": "Registry (current)"})
        workspace.owner_session.assert_called_once_with("vault-a")
        self.assertEqual(row, {"vault_id": "vault-a", "entry": "entry-a"})
        self.assertEqual(activity_target(row), "—")

    def test_historical_details_work_with_no_available_session(self):
        workspace = self.workspace(available=False)
        row = {"vault": "Recorded vault", "vault_id": "vault-a", "entry": "entry-a"}
        expected = {"Vault": "Recorded vault", "Folder": None, "Entry": None}
        self.assertEqual(dict(activity_location(row, workspace)), expected)
        self.assertEqual(dict(activity_location(row, None)), expected)
        workspace.owner_session.assert_called_once_with("vault-a")

    def test_removal_does_not_fall_back_to_a_different_available_vault(self):
        workspace = self.workspace(({"id": "entry-a", "title": "Different title", "group_path": []},))
        row = {"vault_id": "removed-vault", "entry": "entry-a"}
        self.assertEqual(dict(activity_location(row, workspace)), {"Vault": None, "Folder": None, "Entry": None})
        workspace.owner_session.assert_not_called()


class ActivityExecutionTests(TestCase):
    def test_edit_fields_use_recognized_names_only(self):
        values = {"scope": "Edit request synthetic-id · Fields title, url, title, synthetic-secret",
                  "outcome": "Succeeded"}
        self.assertEqual(activity_edit_fields({**values, "action": "Apply edit · Rename entry"}),
                         ("Changed fields", "Title, URL"))
        self.assertEqual(activity_edit_fields({**values, "action": "Request edit · Rename entry"}),
                         ("Proposed fields", "Title, URL"))
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
