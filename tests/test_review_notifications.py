from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from keepassxc_agent_access import review_notifications
from keepassxc_agent_access.review_notifications import ReviewNotifications
from keepassxc_agent_access.settings import SettingsError


class ReviewNotificationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="keeper-notification-test-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "preferences.json"
        self.application = Mock()
        self.notifications = ReviewNotifications(self.application, self.path)

    def test_notification_click_and_review_button_target_the_same_request(self):
        notification = Mock()
        gio = SimpleNamespace(Notification=Mock())
        gio.Notification.new.return_value = notification
        with patch.object(review_notifications, "Gio", gio):
            result = review_notifications.review_notification("edit", "token/edit-id")
        self.assertIs(result, notification)
        gio.Notification.new.assert_called_once_with("Keeper edit request")
        notification.set_body.assert_called_once_with("Open Keeper to review this request.")
        action, target = notification.set_default_action_and_target.call_args.args
        label, button_action, button_target = notification.add_button_with_target.call_args.args
        self.assertEqual(action, "app.review-request")
        self.assertEqual(target.get_type_string(), "(ss)")
        self.assertEqual(target.unpack(), ("edit", "token/edit-id"))
        self.assertEqual((label, button_action, button_target), ("Review request", action, target))

    def test_pending_requests_are_published_once_and_withdrawn_when_resolved(self):
        grant = ("grant", "grant-id")
        edit = ("edit", "token/edit-id")
        self.notifications.sync((grant, edit, grant))
        self.notifications.sync((edit, grant))
        identifiers = [call.args[0] for call in self.application.send_notification.call_args_list]
        self.assertCountEqual(identifiers, ["grant:grant-id", "edit:token/edit-id"])
        self.application.withdraw_notification.assert_not_called()
        self.notifications.sync((edit,))
        self.notifications.sync(())
        self.notifications.sync(())
        self.assertEqual([call.args[0] for call in self.application.withdraw_notification.call_args_list],
                         ["grant:grant-id", "edit:token/edit-id"])

    def test_toggle_persists_privately_and_withdraws_existing_notifications(self):
        pending = (("grant", "grant-id"),)
        self.notifications.load()
        self.assertTrue(self.notifications.enabled)
        self.assertFalse(self.path.exists())
        self.notifications.sync(pending)
        self.notifications.set_enabled(False)
        self.application.withdraw_notification.assert_called_once_with("grant:grant-id")
        self.notifications.sync(pending)
        self.application.send_notification.assert_called_once()

        reopened = ReviewNotifications(self.application, self.path)
        reopened.load()
        self.assertFalse(reopened.enabled)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        reopened.set_enabled(True)
        reopened.sync(pending)
        self.assertEqual(self.application.send_notification.call_count, 2)

    def test_corrupt_preferences_disable_notifications_and_failed_save_keeps_choice(self):
        self.path.write_text('{"desktop_notifications": "false"}', encoding="utf-8")
        with self.assertRaisesRegex(SettingsError, "desktop notification setting"):
            self.notifications.load()
        self.assertFalse(self.notifications.enabled)

        with patch.object(review_notifications, "write_private_json", side_effect=SettingsError("save failed")):
            with self.assertRaises(SettingsError):
                self.notifications.set_enabled(True)
        self.notifications.sync((("grant", "grant-id"),))
        self.application.send_notification.assert_not_called()
