import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import gi

from keepassxc_agent_access.access_settings import AccessSettings, AccessStore
from keepassxc_agent_access.tray import Gdk, Gtk, VaultApplication
from keepassxc_agent_access.workspace_app import WorkspaceApplication


REPO_SRC = str(Path(__file__).resolve().parents[1] / "src")


class StartupTests(unittest.TestCase):
    def test_entrypoint_disables_legacy_autoinit_before_importing_gtk(self):
        script = """
import gi
import keepassxc_agent_access.__main__
if hasattr(gi, "disable_legacy_autoinit"):
    assert gi.get_option("legacy_autoinit") is False
"""
        if os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY"):
            script += """
import os
for key in ("_TEST_WAYLAND_DISPLAY", "_TEST_DISPLAY"):
    value = os.environ.pop(key, None)
    if value is not None:
        os.environ[key.removeprefix("_TEST_")] = value
from gi.repository import Gio, Gtk
class ProbeApp(Gtk.Application):
    def do_activate(self):
        window = Gtk.ApplicationWindow(application=self, title="probe")
        assert window is not None
        self.quit()
app = ProbeApp(application_id="io.github.keepassxcagentaccess.StartupProbe", flags=Gio.ApplicationFlags.NON_UNIQUE)
raise SystemExit(app.run([]))
"""
        env = dict(os.environ)
        for key in ("WAYLAND_DISPLAY", "DISPLAY"):
            if key in env:
                env[f"_TEST_{key}"] = env.pop(key)
        env["PYTHONPATH"] = REPO_SRC
        result = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workspace_startup_fails_fast_without_display(self):
        with TemporaryDirectory() as directory, \
             patch("keepassxc_agent_access.workspace_app.Gtk.Application.do_startup"), \
             patch("keepassxc_agent_access.workspace_app.Gdk.Display.get_default", return_value=None):
            app = WorkspaceApplication(directory=Path(directory), keyring=Mock())
            app.hold = Mock()
            app.quit = Mock()
            app.do_startup()
            self.assertTrue(app.startup_failed)
            self.assertTrue(app.exiting)
            app.hold.assert_not_called()
            app.quit.assert_called_once_with()
            with patch("keepassxc_agent_access.workspace_app.Gtk.Application.do_shutdown"):
                app.do_shutdown()

    def test_workspace_activate_fails_fast_when_window_build_raises(self):
        with TemporaryDirectory() as directory:
            app = WorkspaceApplication(directory=Path(directory), keyring=Mock())
            app.desktop = Mock()
            app._quit = Mock()
            app._build_window = Mock(side_effect=RuntimeError("Gtk couldn't be initialized."))
            app.do_activate()
            self.assertTrue(app.startup_failed)
            app._quit.assert_called_once_with()

    def test_vault_application_startup_fails_fast_without_display(self):
        with TemporaryDirectory() as directory, \
             patch("keepassxc_agent_access.tray.SettingsStore") as store_cls, \
             patch("keepassxc_agent_access.tray.SystemKeyring"), \
             patch("keepassxc_agent_access.tray.Gtk.Application.do_startup"), \
             patch("keepassxc_agent_access.tray.Gdk.Display.get_default", return_value=None):
            store_cls.return_value.path = Path(directory) / "settings.json"
            app = VaultApplication()
            app.hold = Mock()
            app.quit = Mock()
            app.do_startup()
            self.assertTrue(app.startup_failed)
            self.assertTrue(app.exiting)
            app.hold.assert_not_called()
            app.quit.assert_called_once_with()
            with patch("keepassxc_agent_access.tray.Gtk.Application.do_shutdown"):
                app.do_shutdown()

    def test_workspace_startup_pauses_in_memory_without_overwriting_saved_state_when_desktop_locked(self):
        from gi.repository import GLib

        with TemporaryDirectory() as directory:
            store = AccessStore(Path(directory) / "access.json")
            store.write(AccessSettings(agent_paused=False))
            broker = Mock(config=None)
            with patch("keepassxc_agent_access.workspace_app.Gtk.Application.do_startup"), \
                 patch("keepassxc_agent_access.workspace_app.Gdk.Display.get_default", return_value=Mock()), \
                 patch("keepassxc_agent_access.workspace_app.installed_connection", return_value=None), \
                 patch("keepassxc_agent_access.workspace_app.ListingBroker", return_value=broker), \
                 patch.object(GLib, "timeout_add", return_value=1), \
                 patch.object(GLib, "timeout_add_seconds", return_value=2), \
                 patch.object(GLib, "unix_signal_add", return_value=3):
                app = WorkspaceApplication(directory=Path(directory), keyring=Mock(),
                                           desktop_factory=lambda *_: Mock(locked=True))
                app.hold = Mock()
                app.do_startup()
                self.assertTrue(app.workspace.paused)
                self.assertFalse(store.read().agent_paused)

    def test_desktop_unlock_respects_unlock_and_resume_settings(self):
        from gi.repository import GLib

        with TemporaryDirectory() as directory:
            store = AccessStore(Path(directory) / "access.json")
            store.write(AccessSettings(agent_paused=False, unlock_on_desktop_unlock=True,
                                       resume_on_desktop_unlock=True))
            broker = Mock(config=None, enabled=True)
            desktop = Mock(locked=True)
            with patch("keepassxc_agent_access.workspace_app.Gtk.Application.do_startup"), \
                 patch("keepassxc_agent_access.workspace_app.Gdk.Display.get_default", return_value=Mock()), \
                 patch("keepassxc_agent_access.workspace_app.installed_connection", return_value=None), \
                 patch("keepassxc_agent_access.workspace_app.ListingBroker", return_value=broker), \
                 patch.object(GLib, "timeout_add", return_value=1), \
                 patch.object(GLib, "timeout_add_seconds", return_value=2), \
                 patch.object(GLib, "unix_signal_add", return_value=3):
                app = WorkspaceApplication(directory=Path(directory), keyring=Mock(),
                                           desktop_factory=lambda *_: desktop)
                app.hold = Mock()
                app.do_startup()
                app._unlock_all = Mock()
                self.assertTrue(app.workspace.paused)
                desktop.locked = False
                desktop.on_unlock()
                app._unlock_all.assert_called_once_with(cleanup=True)
                self.assertFalse(app.workspace.paused)
                self.assertFalse(store.read().agent_paused)

                # If owner had intentionally paused access before lock, desktop unlock keeps it paused.
                app.workspace.pause(True)
                app.workspace.pause(True, persist=False)
                desktop.on_unlock()
                self.assertTrue(app.workspace.paused)


if __name__ == "__main__":
    unittest.main()
