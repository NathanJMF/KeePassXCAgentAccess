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
from keepassxc_agent_access.launcher import AgentClient
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

            ag_skill = Path(directory) / ".gemini/config/skills/keeper/SKILL.md"
            ag_skill.parent.mkdir(parents=True)
            ag_skill.write_text("skill")
            ag_mcp = Path(directory) / ".gemini/config/mcp_config.json"
            ag_mcp.write_text(json.dumps({"mcpServers": {"keeper": {"command": "x"}}}))
            ag_client = AgentClient("antigravity", "Antigravity", ag_skill, ag_mcp, "json")

            with patch("keepassxc_agent_access.workspace_app.skill_destination",
                       return_value=Path(directory) / "Documents/Skills/Keeper/SKILL.md"), \
                 patch("keepassxc_agent_access.workspace_app.detected_agent_clients", return_value=[ag_client]), \
                 patch("keepassxc_agent_access.workspace_app.codex_skill_destination", return_value=None), \
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

    def test_connect_agent_page_install_button_switches_to_copy_and_shows_codex_toml(self):
        with TemporaryDirectory() as directory:
            app = WorkspaceApplication(directory=Path(directory), keyring=Mock())
            config = BrokerConfig(Path(directory) / "broker.sock", os.geteuid() + 1)
            app.broker = Mock(config=config, enabled=True)
            app.workspace = Mock(paused=False)

            ag_skill = Path(directory) / ".gemini/config/skills/keeper/SKILL.md"
            ag_skill.parent.mkdir(parents=True)
            ag_skill.write_text("skill")
            ag_mcp = Path(directory) / ".gemini/config/mcp_config.json"
            ag_mcp.write_text(json.dumps({"mcpServers": {"keeper": {"command": "x"}}}))
            codex_skill = Path(directory) / ".codex/skills/keeper/SKILL.md"
            codex_mcp = Path(directory) / ".codex/config.toml"

            clients = [
                AgentClient("antigravity", "Antigravity", ag_skill, ag_mcp, "json"),
                AgentClient("codex", "Codex", codex_skill, codex_mcp, "toml"),
            ]
            install_dir = Path(directory) / "app"
            installation = Mock(app=install_dir)
            installation.connection_update_needed.return_value = False
            installation.install_client_integration.side_effect = [
                ValueError("Install failed"),
                {"skill_installed": True, "mcp_configured": True},
            ]

            page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            with patch("keepassxc_agent_access.workspace_app.skill_destination",
                       return_value=Path(directory) / "Documents/Skills/Keeper/SKILL.md"), \
                 patch("keepassxc_agent_access.workspace_app.detected_agent_clients", return_value=clients), \
                 patch("keepassxc_agent_access.workspace_app.codex_skill_destination", return_value=codex_skill), \
                 patch("keepassxc_agent_access.workspace_app.installed_connection", return_value=config), \
                 patch("keepassxc_agent_access.workspace_app.connection_socket") as sock_fn, \
                 patch("keepassxc_agent_access.workspace_app.Installation", return_value=installation):
                sock_fn.return_value.is_socket.return_value = True
                app._connect_agent_page(page)

            cards = page.get_children()
            buttons = [
                widget
                for card in cards
                for child in card.get_children()
                for widget in (child.get_children() if isinstance(child, Gtk.Box) else [child])
                if isinstance(widget, Gtk.Button)
            ]
            install_btn = next(btn for btn in buttons if btn.get_label() == "Install")
            self.assertEqual(install_btn.get_accessible().get_name(), "Install Codex")
            copy_ag = next(btn for btn in buttons if btn.get_accessible().get_name() == "Copy Antigravity Skill")
            self.assertEqual(copy_ag.get_label(), "Copy")

            # Codex MCP TOML card appears alongside MCP Config JSON.
            text_views = [
                widget.get_child()
                for card in cards
                for widget in card.get_children()
                if isinstance(widget, Gtk.ScrolledWindow) and isinstance(widget.get_child(), Gtk.TextView)
            ]
            self.assertEqual(len(text_views), 2)
            toml_buf = text_views[1].get_buffer()
            toml_text = toml_buf.get_text(toml_buf.get_start_iter(), toml_buf.get_end_iter(), False)
            self.assertIn("[mcp_servers.keeper]", toml_text)
            self.assertTrue(any(btn.get_label() == "Copy TOML" for btn in buttons))

            with patch("keepassxc_agent_access.workspace_app.Installation", return_value=installation):
                install_btn.clicked()
                self.assertEqual(install_btn.get_label(), "Install")
                codex_card = install_btn.get_parent().get_parent()
                status = codex_card.get_children()[-1]
                self.assertTrue(status.get_visible())
                self.assertEqual(status.get_text(), "Install failed")

                install_btn.clicked()
                installation.install_client_integration.assert_called_with("codex")
                self.assertEqual(install_btn.get_label(), "Copy")
                self.assertEqual(install_btn.get_accessible().get_name(), "Copy Codex Skill")
                self.assertEqual(status.get_text(), "Installed")

    def test_hidden_window_polling_skips_heavy_ui_refreshes_and_present_syncs(self):
        with TemporaryDirectory() as directory:
            app = WorkspaceApplication(directory=Path(directory), keyring=Mock())
            app.desktop = Mock(locked=False, available=True)
            app.workspace = Mock(paused=True)
            app.broker = Mock(enabled=True)
            app.grants = Mock(rows=Mock(return_value=()))
            app.pending_edits = Mock(return_value=())
            app.usage_approvals = Mock(pending=Mock(return_value=()))
            app.password_clipboard = Mock()
            app.legacy_tray = Mock()
            app.indicator = Mock()
            app.window = Mock()
            app.window.get_visible.return_value = False
            app.stack = Mock()
            app.stack.get_visible_child_name.return_value = "access"
            app.notice = Mock()
            app.pause_button = Mock()
            app.pause_labels = Mock()
            app.usage_button = Mock()
            app.access_button = Mock()
            app.access_view = Mock()
            app.activity_view = Mock()
            app._refresh_tree = Mock()
            app._refresh_vault_lock = Mock()
            app._browse = Mock()
            app._schedule_request_popup = Mock()
            app._sync_pending_notification = Mock()

            app._refresh()
            app.password_clipboard.check.assert_called_once_with()
            app.legacy_tray.set_state.assert_called_once_with(True, pending=0)
            app.indicator.set_title.assert_called_once()
            app.indicator.set_icon_full.assert_called_once()
            app._schedule_request_popup.assert_called_once_with(())
            app._sync_pending_notification.assert_called_once_with(())
            app._refresh_tree.assert_not_called()
            app._refresh_vault_lock.assert_not_called()
            app._browse.assert_not_called()
            app.access_view.refresh.assert_not_called()
            app.activity_view.refresh.assert_not_called()

            # When visible on "access", _browse stays skipped while access_view refreshes.
            app.window.get_visible.return_value = True
            app._refresh()
            app._refresh_tree.assert_called_once_with()
            app._refresh_vault_lock.assert_called_once_with()
            app._browse.assert_not_called()
            app.access_view.refresh.assert_called_once_with()

            # _present() presents the window and immediately triggers _refresh().
            app._refresh = Mock()
            app._present()
            app.window.present.assert_called_once_with()
            app._refresh.assert_called_once_with()

    def test_password_clipboard_cleared_resets_notice_banner(self):
        with TemporaryDirectory() as directory:
            app = WorkspaceApplication(directory=Path(directory), keyring=Mock())
            app.desktop = Mock(available=True)
            app.notice = Mock()
            app.message = "Password copied."
            app._password_clipboard_cleared()
            self.assertIsNone(app.message)
            app.notice.set_text.assert_called_once_with("")
            app.notice.hide.assert_called_once_with()

            app.notice.reset_mock()
            app.message = "Other warning"
            app._password_clipboard_cleared()
            self.assertEqual(app.message, "Other warning")
            app.notice.set_text.assert_not_called()

    def test_window_closed_prompts_when_active_or_pending_and_quits_when_idle(self):
        with TemporaryDirectory() as directory:
            app = WorkspaceApplication(directory=Path(directory), keyring=Mock())
            app.desktop = Mock(locked=False)
            app.window = Gtk.Window()
            app.workspace = Mock(paused=False, sessions={})
            app._review_requests = Mock(return_value=())
            app._minimize = Mock()
            app._quit = Mock()

            # Active tray session -> prompts; Minimize to Tray (ACCEPT) calls _minimize.
            app.tray_connected = True
            app.run_dialog = Mock(return_value=Gtk.ResponseType.ACCEPT)
            self.assertTrue(app._window_closed())
            app.run_dialog.assert_called_once()
            app._minimize.assert_called_once_with()
            app._quit.assert_not_called()

            # Quit Keeper (REJECT) calls _quit.
            app.run_dialog.reset_mock()
            app._minimize.reset_mock()
            app.run_dialog.return_value = Gtk.ResponseType.REJECT
            self.assertTrue(app._window_closed())
            app._quit.assert_called_once_with()

            # Cancel (CANCEL) keeps running without minimizing or quitting.
            app._quit.reset_mock()
            app.run_dialog.return_value = Gtk.ResponseType.CANCEL
            self.assertTrue(app._window_closed())
            app._minimize.assert_not_called()
            app._quit.assert_not_called()

            # Idle (paused, no sessions, no pending) -> quits immediately without prompt.
            app.workspace = Mock(paused=True, sessions={})
            app.run_dialog.reset_mock()
            self.assertTrue(app._window_closed())
            app.run_dialog.assert_not_called()
            app._quit.assert_called_once_with()

    def test_pending_notifications_are_secret_free_deduplicated_and_withdrawn(self):
        with TemporaryDirectory() as directory:
            app = WorkspaceApplication(directory=Path(directory), keyring=Mock())
            app.window = Mock()
            app.window.get_visible.return_value = True
            app.review_popups.enabled = False
            app.send_notification = Mock()
            app.withdraw_notification = Mock()

            pending = (("grant", "secret-token-id"), ("usage", "42"))
            app._sync_pending_notification(pending)
            app.send_notification.assert_called_once()
            note_id, notification = app.send_notification.call_args.args
            self.assertEqual(note_id, "pending-requests")
            self.assertIsNotNone(notification)

            # Duplicate set does not re-notify.
            app._sync_pending_notification(pending)
            app.send_notification.assert_called_once()

            # Changed set sends updated notification.
            app._sync_pending_notification((("grant", "secret-token-id"),))
            self.assertEqual(app.send_notification.call_count, 2)

            # Empty pending withdraws the notification.
            app._sync_pending_notification(())
            app.withdraw_notification.assert_called_once_with("pending-requests")


if __name__ == "__main__":
    unittest.main()
