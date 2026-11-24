import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import gi

from keepassxc_agent_access.access_settings import AccessSettings, AccessStore
from keepassxc_agent_access.broker import BrokerConfig
from keepassxc_agent_access.keyring import KeyringError
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

    def test_legacy_tray_exit_schedules_appindicator_fallback_without_immediate_present(self):
        from gi.repository import GLib

        with TemporaryDirectory() as directory:
            app = WorkspaceApplication(directory=Path(directory), keyring=Mock())
            app.window = Mock()
            app.window.get_visible.return_value = False
            app.legacy_tray = Mock()
            app.tray_connected = True
            app._present = Mock()

            def build_indicator():
                app.indicator = Mock()

            with patch.object(app, "_build_appindicator", side_effect=build_indicator) as build_mock, \
                 patch.object(GLib, "timeout_add", return_value=42) as timeout_add, \
                 patch.object(GLib, "source_remove") as source_remove:
                app._on_legacy_tray_exit()
                build_mock.assert_called_once_with()
                app._present.assert_not_called()
                timeout_add.assert_called_once_with(650, app._fallback)
                self.assertEqual(app._fallback_source, 42)

                app._tray_status(None, True)
                source_remove.assert_called_once_with(42)
                self.assertIsNone(app._fallback_source)
                app._present.assert_not_called()

                app._schedule_fallback(650)
                app.tray_connected = False
                self.assertEqual(app._fallback(), GLib.SOURCE_REMOVE)
                self.assertIsNone(app._fallback_source)
                app._present.assert_called_once_with()

                app._schedule_fallback(650)
                with patch("keepassxc_agent_access.workspace_app.Gtk.Application.do_shutdown"):
                    app.do_shutdown()
                self.assertIsNone(app._fallback_source)

    def test_keyboard_handles_ctrl_q_and_ignores_ctrl_shift_q(self):
        with TemporaryDirectory() as directory:
            app = WorkspaceApplication(directory=Path(directory), keyring=Mock())
            app._quit = Mock()
            app.stack = Mock()
            app.entry_search = Mock()

            for keyval in (Gdk.KEY_q, Gdk.KEY_Q):
                event = SimpleNamespace(
                    state=Gdk.ModifierType.CONTROL_MASK | Gdk.ModifierType.SHIFT_MASK,
                    keyval=keyval,
                )
                self.assertFalse(app._keyboard(None, event))
            app._quit.assert_not_called()

            for keyval in (Gdk.KEY_q, Gdk.KEY_Q):
                event = SimpleNamespace(state=Gdk.ModifierType.CONTROL_MASK, keyval=keyval)
                self.assertTrue(app._keyboard(None, event))
            self.assertEqual(app._quit.call_count, 2)

    def test_unlock_all_prompt_does_not_retry_failed_saved_unlock(self):
        with TemporaryDirectory() as directory:
            app = WorkspaceApplication(directory=Path(directory), keyring=Mock())
            app.desktop = Mock(locked=False)
            record = SimpleNamespace(id="v1", name="Main", item="keyring-item")
            app.workspace = Mock(owner_generation=1, registrations={"v1": record}, pending=())
            app.workspace.owner_session.return_value = None
            app.workspace.unlock.side_effect = KeyringError("Keyring locked")
            app._refresh = Mock()

            def sync_background(operation, *, select=False, after=None, finished=None):
                value = operation()
                if after:
                    after(value)
                if finished:
                    finished(True, "")

            app._background = sync_background
            app.run_dialog = Mock(return_value=Gtk.ResponseType.CANCEL)
            dialog_body = Mock()
            with patch("keepassxc_agent_access.workspace_app._dialog", return_value=(Mock(), dialog_body)), \
                 patch("keepassxc_agent_access.workspace_app._label", side_effect=lambda text: text) as label_mock, \
                 patch("keepassxc_agent_access.workspace_app.password_entry", return_value=Mock()):
                app._unlock_all(prompt=True)

            app.workspace.unlock.assert_called_once_with("v1", cycle=1)
            app.run_dialog.assert_called_once()
            label_mock.assert_called_once_with("Keyring locked")

    def test_broker_settings_page_handles_corrupt_access_json_and_restores_fallback(self):
        with TemporaryDirectory(dir="/tmp") as directory:
            access_path = Path(directory) / "access.json"
            access_path.write_text("{corrupt")
            store = AccessStore(access_path)

            app = WorkspaceApplication(directory=Path(directory), keyring=Mock())
            app.workspace = Mock(legacy_access=store)
            app.broker = Mock(config=None)
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            app._broker_settings_page(body)
            children = body.get_children()
            spin = next(widget for widget in children if isinstance(widget, Gtk.SpinButton))
            status = children[-1]
            self.assertEqual(spin.get_value_as_int(), AccessSettings().retention_days)
            self.assertTrue(status.get_visible())
            self.assertIn("Access settings could not be read.", status.get_text())

            custom_uid = os.geteuid() + 1
            fallback_uid = os.geteuid() + 2
            store.write(AccessSettings(endpoint=str(Path(directory) / "custom.sock"), uid=custom_uid))
            fallback = BrokerConfig(Path(directory) / "fallback.sock", fallback_uid)

            app.broker = Mock(config=BrokerConfig(Path(directory) / "custom.sock", custom_uid))
            app.broker.update.side_effect = lambda save, config: save()
            app._refresh = Mock()
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            app._broker_settings_page(body)
            children = body.get_children()
            entries = [widget for widget in children if type(widget) is Gtk.Entry]
            save_button = next(widget for widget in children if isinstance(widget, Gtk.Button))
            endpoint_entry, uid_entry = entries
            endpoint_entry.set_text("")
            uid_entry.set_text("")

            with patch.object(BrokerConfig, "from_environment", return_value=None), \
                 patch("keepassxc_agent_access.workspace_app.installed_connection", return_value=fallback):
                save_button.clicked()

            self.assertEqual(app.broker.update.call_args.args[1], fallback)
            app.broker.start.assert_called_once_with()
            self.assertIsNone(store.read().endpoint)
            self.assertIsNone(store.read().uid)
            self.assertEqual(endpoint_entry.get_text(), str(fallback.path))
            self.assertEqual(uid_entry.get_text(), str(fallback.agent_uid))

    def test_connect_agent_page_shows_json_snippet_antigravity_skill_and_runner_update(self):
        from gi.repository import GLib

        with TemporaryDirectory() as directory:
            app = WorkspaceApplication(directory=Path(directory), keyring=Mock())
            config = BrokerConfig(Path(directory) / "broker.sock", os.geteuid() + 1)
            app.broker = Mock(config=config, enabled=True)
            app.workspace = Mock(paused=False)

            page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            install_dir = Path(directory) / "app"
            installation = Mock(app=install_dir)
            installation.connection_update_needed.side_effect = [True, False]

            with patch("keepassxc_agent_access.workspace_app.skill_destination",
                       return_value=Path(directory) / "Documents/Skills/Keeper/SKILL.md"), \
                 patch("keepassxc_agent_access.workspace_app.antigravity_skill_destination",
                       return_value=Path(directory) / ".gemini/config/skills/keeper/SKILL.md"), \
                 patch("keepassxc_agent_access.workspace_app.installed_connection", return_value=config), \
                 patch("keepassxc_agent_access.workspace_app.connection_socket") as sock_fn, \
                 patch("keepassxc_agent_access.workspace_app.Installation", return_value=installation):
                sock_fn.return_value.is_socket.return_value = True
                app._connect_agent_page(page)

            cards = page.get_children()
            entries = [
                widget.get_text()
                for card in cards
                for child in card.get_children()
                if isinstance(child, Gtk.Box)
                for widget in child.get_children()
                if type(widget) is Gtk.Entry
            ]
            self.assertIn(str(Path(directory) / ".gemini/config/skills/keeper/SKILL.md"), entries)
            self.assertIn(str(install_dir / "keeper-connect"), entries)

            text_views = [
                widget.get_child()
                for card in cards
                for widget in card.get_children()
                if isinstance(widget, Gtk.ScrolledWindow) and isinstance(widget.get_child(), Gtk.TextView)
            ]
            self.assertEqual(len(text_views), 1)
            buf = text_views[0].get_buffer()
            snippet_text = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
            self.assertIn("keeper-connect", snippet_text)
            self.assertIn("mcpServers", snippet_text)

            update_button = next(
                widget
                for card in cards
                for widget in card.get_children()
                if isinstance(widget, Gtk.Button) and widget.get_label() == "Update Local Runner…"
            )
            idle_callbacks = []

            class SyncThread:
                def __init__(self, target, daemon=True):
                    self.target = target

                def start(self):
                    self.target()

            with patch("keepassxc_agent_access.workspace_app.administer_connection") as admin, \
                 patch("keepassxc_agent_access.workspace_app.Thread", SyncThread), \
                 patch("keepassxc_agent_access.workspace_app.Installation", return_value=installation), \
                 patch.object(GLib, "idle_add", side_effect=lambda fn, *args: idle_callbacks.append((fn, args))):
                update_button.clicked()
                admin.assert_called_once_with("install", config)
                self.assertEqual(len(idle_callbacks), 1)
                fn, args = idle_callbacks[0]
                self.assertEqual(fn(*args), GLib.SOURCE_REMOVE)
            self.assertFalse(update_button.get_sensitive())


if __name__ == "__main__":
    unittest.main()
