from unittest import TestCase
from unittest.mock import Mock, patch

from gi.repository import GLib

from keepassxc_agent_access.desktop import DesktopSession


class DesktopSessionTests(TestCase):
    def setUp(self):
        acquisition = patch("keepassxc_agent_access.desktop.Gio.bus_get_sync",
                            side_effect=GLib.Error("Synthetic unavailable bus"))
        acquisition.start()
        self.addCleanup(acquisition.stop)

    def session(self, *, gnome=None, logind=None):
        session = DesktopSession.__new__(DesktopSession)
        session.on_lock = Mock()
        session.on_exit = Mock()
        session.locked = True
        session.initializing = False
        session.states = {"gnome": gnome, "logind": logind}
        session.logind_lock_requested = False
        session.session_bus = session.system_bus = None
        session.session_id = "fixture"
        session.logind_path = "/fixture"
        session.subscriptions = []
        session._set_state("gnome", gnome)
        return session

    def test_unknown_lock_state_blocks_access_and_service_loss_locks(self):
        session = self.session()
        self.assertTrue(session.locked)
        self.assertFalse(session.available)
        session._set_state("gnome", False)
        self.assertFalse(session.locked)
        session._owner_changed(None, None, None, None, None,
                               GLib.Variant("(sss)", ("org.gnome.ScreenSaver", "old", "")))
        self.assertTrue(session.locked)
        self.assertFalse(session.available)
        session.on_lock.assert_called_once()
        session.session_bus = Mock()
        session.session_bus.is_closed.return_value = False
        session.session_bus.call_sync.return_value = GLib.Variant("(b)", (False,))
        session._poll()
        self.assertTrue(session.available)
        self.assertFalse(session.locked)

    def test_logind_fallback_tracks_locked_hint_and_lock_requests(self):
        session = self.session()
        session.system_bus = Mock()
        session.system_bus.is_closed.return_value = False
        session.system_bus.call_sync.return_value = GLib.Variant("(v)", (GLib.Variant("b", False),))
        session._poll()
        self.assertFalse(session.locked)
        session._logind_lock()
        self.assertTrue(session.locked)
        session._poll()
        self.assertTrue(session.locked)
        session.on_lock.assert_called_once()
        session.system_bus.call_sync.side_effect = GLib.Error("Unavailable")
        session._poll()
        self.assertTrue(session.locked)
        session.system_bus.call_sync.side_effect = None
        session.system_bus.call_sync.return_value = GLib.Variant("(v)", (GLib.Variant("b", True),))
        session._poll()
        self.assertTrue(session.locked)
        session.system_bus.call_sync.return_value = GLib.Variant("(v)", (GLib.Variant("b", False),))
        session._poll()
        self.assertFalse(session.locked)

    def test_either_monitor_can_report_a_locked_session(self):
        session = self.session(gnome=False, logind=True)
        self.assertTrue(session.locked)
        session._set_state("logind", False)
        self.assertFalse(session.locked)
        session._gnome_signal(None, None, None, None, None, GLib.Variant("(b)", (True,)))
        self.assertTrue(session.locked)

    def test_missing_bus_recovers_and_installs_monitor_subscriptions(self):
        session = self.session()
        bus = Mock()
        bus.is_closed.return_value = False
        bus.call_sync.return_value = GLib.Variant("(b)", (False,))
        session.session_id = None
        with patch("keepassxc_agent_access.desktop.Gio.bus_get_sync", side_effect=None, return_value=bus):
            session._poll()
            self.assertFalse(session.locked)
            count = bus.signal_subscribe.call_count
            session._poll()
            self.assertEqual(bus.signal_subscribe.call_count, count)

    def test_closed_system_bus_resubscribes_to_session_lock_events(self):
        session = self.session()
        session.session_bus = Mock()
        session.session_bus.is_closed.return_value = False
        session.session_bus.call_sync.return_value = GLib.Variant("(b)", (False,))
        old_bus = Mock()
        old_bus.is_closed.return_value = True
        session.system_bus = old_bus
        session.subscriptions = [(old_bus, 12)]
        replacement = Mock()
        replacement.is_closed.return_value = False
        replacement.call_sync.side_effect = [
            GLib.Variant("(o)", ("/replacement",)),
            GLib.Variant("(v)", (GLib.Variant("b", False),)),
        ]
        with patch("keepassxc_agent_access.desktop.Gio.bus_get_sync", return_value=replacement, side_effect=None):
            session._poll()
        old_bus.signal_unsubscribe.assert_called_once_with(12)
        self.assertEqual(session.logind_path, "/replacement")
        signals = [call.args[2] for call in replacement.signal_subscribe.call_args_list]
        self.assertIn("Lock", signals)
        self.assertIn("Unlock", signals)

    def test_monitor_failure_at_startup_keeps_vaults_locked(self):
        with patch("keepassxc_agent_access.desktop.Gio.bus_get_sync", side_effect=GLib.Error("Unavailable")), \
             patch("keepassxc_agent_access.desktop.GLib.timeout_add_seconds", return_value=99):
            callback = Mock()
            session = DesktopSession(callback, Mock())
        self.assertTrue(session.locked)
        self.assertFalse(session.available)
        callback.assert_not_called()
