from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from keepassxc_agent_access.review_popups import ReviewPopups
from keepassxc_agent_access.settings import SettingsError
from keepassxc_agent_access.workspace_app import Gtk, WorkspaceApplication
from keepassxc_agent_access.workspace_views import AccessView, locked_review_vaults


class ReviewPopupTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="keeper-popups-test-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "desktop-notifications.json"
        self.popups = ReviewPopups(self.path)

    def test_pending_requests_are_shown_once_and_in_order(self):
        grant = ("grant", "grant-id")
        edit = ("edit", "token/edit-id")
        self.assertEqual(self.popups.next_request((grant, edit)), grant)
        self.popups.mark_reviewed(*grant)
        self.assertEqual(self.popups.next_request((grant, edit)), edit)
        self.popups.mark_reviewed(*edit)
        self.assertIsNone(self.popups.next_request((grant, edit)))
        self.assertIsNone(self.popups.next_request(()))

    def test_toggle_keeps_the_existing_private_notification_preference(self):
        grant = ("grant", "grant-id")
        self.popups.load()
        self.assertTrue(self.popups.enabled)
        self.assertFalse(self.path.exists())
        self.popups.set_enabled(False)
        self.assertIsNone(self.popups.next_request((grant,)))

        reopened = ReviewPopups(self.path)
        reopened.load()
        self.assertFalse(reopened.enabled)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        reopened.set_enabled(True)
        self.assertEqual(reopened.next_request((grant,)), grant)

    def test_bad_settings_disable_popups_and_failed_save_keeps_choice(self):
        self.path.write_text('{"desktop_notifications": "false"}', encoding="utf-8")
        with self.assertRaisesRegex(SettingsError, "request pop-up setting"):
            self.popups.load()
        self.assertFalse(self.popups.enabled)
        with patch("keepassxc_agent_access.review_popups.write_private_json",
                   side_effect=SettingsError("save failed")):
            with self.assertRaises(SettingsError):
                self.popups.set_enabled(True)
        self.assertFalse(self.popups.enabled)

    def test_manual_review_opens_the_expiring_request_even_if_popups_are_off(self):
        late = SimpleNamespace(id=7, expires=50)
        early = SimpleNamespace(id=8, expires=20)
        grant = SimpleNamespace(id="grant", status="pending", pending_change=None)
        app = SimpleNamespace(grants=SimpleNamespace(rows=lambda: (grant,)), pending_edits=lambda: (),
                              usage_approvals=SimpleNamespace(pending=lambda: (late, early)), dialog=None, busy=False)
        app._review_requests = lambda: WorkspaceApplication._review_requests(app)
        self.assertEqual(app._review_requests(), (("usage", "8"), ("usage", "7"), ("grant", "grant")))
        self.popups.enabled = False
        self.assertIsNone(self.popups.next_request(app._review_requests()))
        view = SimpleNamespace(app=app, open_record=Mock())
        AccessView._open_next(view)
        view.open_record.assert_called_once_with("8", "usage")

    def test_unlock_from_review_only_reopens_the_visible_owner_request(self):
        dialog = Mock()
        app = SimpleNamespace(dialog=dialog, unlock_record=Mock())
        record = SimpleNamespace(name="Synthetic Vault")
        control = Mock()
        box = Mock()
        feedback = Mock()
        with patch.object(Gtk, "Button", return_value=control), patch.object(Gtk, "Box", return_value=box), \
                patch("keepassxc_agent_access.workspace_app._label", return_value=feedback), \
                patch("keepassxc_agent_access.workspace_app.styled", return_value=feedback):
            self.assertIs(WorkspaceApplication.unlock_review_button(app, record, dialog), box)
        _, clicked = control.connect.call_args.args
        clicked()
        self.assertEqual(app.unlock_record.call_args.args, (record,))
        self.assertIs(app.unlock_record.call_args.kwargs["parent"], dialog)
        finished = app.unlock_record.call_args.kwargs["finished"]
        finished(False, "")
        dialog.response.assert_not_called()
        feedback.show.assert_not_called()
        finished(False, "Incorrect password")
        feedback.set_text.assert_called_once_with("Incorrect password")
        feedback.show.assert_called_once()
        finished(True, "")
        dialog.response.assert_called_once_with(Gtk.ResponseType.APPLY)
        app.dialog = Mock()
        finished(True, "")
        dialog.response.assert_called_once()

    def test_unqualified_requests_offer_a_choice_of_locked_vaults(self):
        workspace = SimpleNamespace(registrations={"a": "First Vault", "b": "Second Vault", "c": "Open Vault"},
                                    session=lambda identifier: object() if identifier == "c" else None)
        self.assertEqual(list(locked_review_vaults(workspace, [SimpleNamespace(vault=None)])),
                         ["First Vault", "Second Vault"])
        self.assertEqual(list(locked_review_vaults(workspace, [SimpleNamespace(vault="a")])), ["First Vault"])
