from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from keepassxc_agent_access.review_popups import ReviewPopups
from keepassxc_agent_access.settings import SettingsError


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
