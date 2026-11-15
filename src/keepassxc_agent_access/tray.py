"""Desktop entry point and owner-only GTK controls."""

import ctypes
from pathlib import Path
import signal
import sys
from threading import Thread

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gio, GLib, Gtk

from .access import AccessEngine
from .access_settings import AccessStore
from .activity import ActivityError, ActivityStore
from .approvals import ApprovalQueue
from .broker import BrokerConfig, ListingBroker
from .controller import VaultController, VaultState
from .desktop import DesktopSession
from .keyring import KeyringError, SystemKeyring
from .owner_views import ApprovalPresenter, OwnerViews
from .protocol import ListingError
from .settings import SettingsError, SettingsStore
from .setup import VaultSetup
from .vault import UnlockCancelled, VaultError, VaultTarget


APP_ID = "io.github.keepassxcagentaccess.Tray"
APP_TITLE = "KeePassXC Agent Access"
ICONS = {
    VaultState.SETUP: "dialog-password",
    VaultState.LOCKED: "changes-prevent",
    VaultState.UNLOCKED: "changes-allow",
}


def password_entry():
    entry = Gtk.Entry(visibility=False, activates_default=True)
    entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
    entry.set_placeholder_text("Database password")
    return entry


class SetupDialog(Gtk.Dialog):
    def __init__(self, window, target):
        super().__init__(title="Set up a KeePass database", transient_for=window, modal=True)
        self.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Verify and save", Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        self.database = Gtk.FileChooserButton(title="Choose a KeePass database")
        database_filter = Gtk.FileFilter()
        database_filter.set_name("KeePass databases (*.kdbx)")
        database_filter.add_pattern("*.[kK][dD][bB][xX]")
        self.database.add_filter(database_filter)
        self.key_file = Gtk.FileChooserButton(title="Choose a key file")
        self.key_file_enabled = Gtk.CheckButton(label="Use a key file")
        self.key_file_enabled.connect("toggled", self._toggle_key_file)
        self.password = password_entry()
        self.remember = Gtk.CheckButton(label="Remember on this device")
        self.remember.set_tooltip_text("Save the password in the OS keyring.")
        box = self.get_content_area()
        box.set_border_width(16)
        box.set_spacing(10)
        for widget in (Gtk.Label(label="KeePass database", xalign=0), self.database,
                       self.key_file_enabled, self.key_file, self.password, self.remember):
            box.pack_start(widget, False, False, 0)
        if target:
            self.database.set_filename(str(target.database))
            if target.key_file:
                self.key_file.set_filename(str(target.key_file))
                self.key_file_enabled.set_active(True)
        self._toggle_key_file()
        self.show_all()

    def _toggle_key_file(self, *_):
        self.key_file.set_sensitive(self.key_file_enabled.get_active())

    def selection(self):
        database = self.database.get_filename()
        if not database:
            raise VaultError("Select a KeePass database.")
        key_file = self.key_file.get_filename() if self.key_file_enabled.get_active() else None
        if self.key_file_enabled.get_active() and not key_file:
            raise VaultError("Select the database key file.")
        return VaultTarget(Path(database), Path(key_file) if key_file else None)


class VaultApplication(Gtk.Application):
    def __init__(self, setup=None, desktop_factory=DesktopSession, show_window=False):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.setup = setup or VaultSetup(SettingsStore(), SystemKeyring(), VaultController())
        directory = self.setup.store.path.parent
        self.access_store = AccessStore(directory / "access.json")
        self.activity_store = ActivityStore(directory / "activity.sqlite")
        self.approvals = ApprovalQueue()
        self.approval_ui = ApprovalPresenter(self, self.approvals)
        self.owner_views = OwnerViews(self)
        self.fallback_config = BrokerConfig.from_environment()
        self.message = ""
        try:
            settings = self.access_store.read()
            config = settings.broker_config(self.fallback_config)
        except SettingsError as error:
            config = None
            self.message = str(error)
        handler = AccessEngine(self.access_store, self.activity_store, self.approvals,
                               lambda: not (self.exiting or self.desktop.locked))
        self.broker = ListingBroker(config, self.setup.controller.current_session, handler)
        self.desktop_factory = desktop_factory
        self.show_window = show_window
        self.window = None
        self.dialog = None
        self.indicator = None
        self.tray_connected = False
        self.busy = False
        self.exiting = False

    def do_startup(self):
        Gtk.Application.do_startup(self)
        self.hold()
        self.desktop = self.desktop_factory(self._desktop_lock, self._quit)
        try:
            self.activity_store.recover(self.access_store.read().retention_days)
        except (SettingsError, ActivityError):
            self.message = "Local activity could not be initialized."
        self.approval_poll = GLib.timeout_add(125, self.approval_ui.poll)
        self.activity_prune = GLib.timeout_add_seconds(3600, self._prune_activity)
        for signum in (signal.SIGINT, signal.SIGTERM):
            GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signum, self._quit)

    def do_activate(self):
        if self.window is None:
            self._build_window()
            self._build_tray()
            self._refresh()
            if self.show_window or self.setup.controller.state(self._target() is not None) is VaultState.SETUP:
                self._present()
            else:
                GLib.timeout_add(600, self._show_without_tray)
        else:
            self._present()

    def _build_window(self):
        self.window = Gtk.ApplicationWindow(application=self, title=APP_TITLE)
        self.window.set_default_size(480, 270)
        self.window.connect("delete-event", self._window_closed)
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin=20)
        self.window.add(body)
        self.status = Gtk.Label(xalign=0)
        self.status.get_style_context().add_class("title")
        self.details = Gtk.Label(xalign=0, wrap=True)
        self.notice = Gtk.Label(xalign=0, wrap=True)
        self.notice.set_selectable(True)
        for label in (self.status, self.details, self.notice):
            body.pack_start(label, False, False, 0)
        self.buttons = {}
        actions = (
            ("setup", "Setup", self._configure_dialog),
            ("unlock", "Unlock", self._unlock),
            ("manual", "Enter password…", self._manual_unlock),
            ("lock", "Lock now", self._lock),
            ("enable_listing", "Enable agent access", self._enable_listing),
            ("stop_listing", "Stop agent access", self._stop_listing),
            ("access", "Access…", lambda *_: self._owner_view("access")),
            ("actions", "Actions…", lambda *_: self._owner_view("actions")),
            ("activity", "Activity…", lambda *_: self._owner_view("activity")),
            ("forget", "Forget saved password", self._forget),
            ("retry", "Retry keyring cleanup", self._retry_cleanup),
            ("quit", "Quit", self._quit),
        )
        for name, label, handler in actions:
            button = Gtk.Button(label=label, halign=Gtk.Align.START)
            button.connect("clicked", handler)
            body.pack_start(button, False, False, 0)
            self.buttons[name] = button
        body.show_all()

    def _build_tray(self):
        try:
            gi.require_version("AyatanaAppIndicator3", "0.1")
            from gi.repository import AyatanaAppIndicator3
        except (ImportError, ValueError):
            return
        self.indicator = AyatanaAppIndicator3.Indicator.new(
            "keepassxc-agent-access", ICONS[VaultState.SETUP],
            AyatanaAppIndicator3.IndicatorCategory.APPLICATION_STATUS,
        )
        self.menu = Gtk.Menu()
        self.menu_items = {}
        for key, label, callback in (
            ("status", "Setup required", None),
            ("setup", "Setup", self._configure_dialog),
            ("unlock", "Unlock", self._unlock),
            ("lock", "Lock now", self._lock),
            ("enable_listing", "Enable agent access", self._enable_listing),
            ("stop_listing", "Stop agent access", self._stop_listing),
            ("pending", "Pending requests", self._show_pending),
            ("activity", "Activity", lambda *_: self._owner_view("activity")),
            ("settings", "Settings", self._present),
            ("quit", "Quit", self._quit),
        ):
            item = Gtk.MenuItem(label=label)
            if callback:
                item.connect("activate", callback)
            else:
                item.set_sensitive(False)
            self.menu.append(item)
            self.menu_items[key] = item
        self.menu.show_all()
        self.indicator.set_menu(self.menu)
        self.indicator.connect("connection-changed", self._tray_changed)
        self.indicator.set_status(AyatanaAppIndicator3.IndicatorStatus.ACTIVE)

    def _tray_changed(self, _indicator, connected):
        self.tray_connected = connected
        if not connected and not self.exiting:
            self._present()

    def _show_without_tray(self):
        if not self.tray_connected and not self.exiting:
            self._present()
        return GLib.SOURCE_REMOVE

    def _window_closed(self, *_):
        if self.tray_connected:
            self.window.hide()
        else:
            self._quit()
        return True

    def _target(self):
        try:
            return self.setup.store.read().target
        except SettingsError:
            return None

    def _refresh(self):
        try:
            settings = self.setup.store.read()
            target, active_item, pending = settings.target, settings.active_item, settings.pending_items
        except SettingsError as error:
            target, active_item, pending = None, None, ()
            self.message = str(error)
        state = self.setup.controller.state(target is not None)
        self.status.set_text(state.value)
        if target:
            detail = target.database.name
            detail += " · Password saved in OS keyring" if active_item else " · Password required to unlock"
        else:
            detail = "Choose an existing KeePass database to get started."
        if pending:
            detail += "\nKeyring cleanup pending."
        listing = self.broker.enabled
        if listing:
            detail += "\nAgent access enabled."
        self.details.set_text(detail)
        message = self.message
        if state is VaultState.UNLOCKED and self.setup.controller.source == "keyring":
            message = message or "Unlocked using the saved password from the OS keyring."
        self.notice.set_text(message)
        available = {
            "setup": True, "unlock": state is VaultState.LOCKED,
            "manual": state is VaultState.LOCKED and active_item is not None,
            "lock": state is VaultState.UNLOCKED or self.busy,
            "enable_listing": state is VaultState.UNLOCKED and self.broker.config is not None and not listing,
            "stop_listing": listing,
            "access": True, "actions": True, "activity": True,
            "forget": active_item is not None,
            "retry": bool(pending), "quit": True,
        }
        self.buttons["setup"].set_label("Change vault or password" if target else "Setup")
        for key, button in self.buttons.items():
            button.set_visible(available[key])
            button.set_sensitive(not self.busy or key in ("lock", "quit", "stop_listing"))
        if self.indicator is not None:
            self.indicator.set_icon_full(ICONS[state], state.value)
            tray_status = state.value
            if state is VaultState.UNLOCKED and self.setup.controller.source == "keyring":
                tray_status += " · OS keyring"
            if listing:
                tray_status += " · Agent access enabled"
            self.menu_items["status"].set_label(tray_status)
            for key in ("setup", "unlock", "lock", "enable_listing", "stop_listing"):
                visible = target is None if key == "setup" else available[key]
                self.menu_items[key].set_visible(visible)
                self.menu_items[key].set_sensitive(not self.busy or key in ("lock", "stop_listing"))

    def save_access_settings(self, settings):
        config = settings.broker_config(self.fallback_config)
        self.broker.update(lambda: self.access_store.write(settings), config)
        self._prune_activity()
        self._refresh()

    def _prune_activity(self):
        try:
            self.activity_store.prune(self.access_store.read().retention_days)
        except (SettingsError, ActivityError):
            self.message = "Local activity cleanup is unavailable."
        return GLib.SOURCE_CONTINUE

    def _owner_view(self, view):
        if not self._ready():
            return
        self._present()
        try:
            getattr(self.owner_views, view)()
        except SettingsError as error:
            self.message = str(error)
            self._refresh()

    def _show_pending(self, *_):
        self.approval_ui.poll()
        if self.approval_ui.dialog is not None:
            self.approval_ui.dialog.present()
        else:
            self.message = "No pending requests."
            self._present()

    def _present(self, *_):
        if not self.desktop.locked:
            self.window.present()
            self._refresh()

    def _ready(self):
        return not (self.busy or self.dialog is not None or self.desktop.locked or self.exiting)

    def _configure_dialog(self, *_):
        if not self._ready():
            return
        dialog = SetupDialog(self.window, self._target())
        self.dialog = dialog
        response = dialog.run()
        password = dialog.password.get_text() if response == Gtk.ResponseType.OK else None
        dialog.password.set_text("")
        try:
            if password is not None:
                target = dialog.selection()
                remember = dialog.remember.get_active()
                self.broker.stop()
                attempt = self.setup.controller.begin()
                self._run(self.setup.configure, attempt, target, password, remember,
                          success="Vault verified and setup saved.", cleanup=True)
        except VaultError as error:
            self.message = str(error)
            self._present()
        finally:
            self.dialog = None
            dialog.destroy()

    def _unlock(self, *_):
        if not self._ready():
            return
        try:
            saved = self.setup.store.read().active_item
        except SettingsError as error:
            self.message = str(error)
            self._present()
            return
        if saved:
            self._run(self.setup.unlock, self.setup.controller.begin(), unlock=True)
        else:
            self._manual_unlock()

    def _manual_unlock(self, *_):
        if not self._ready():
            return
        dialog = Gtk.Dialog(title="Unlock KeePass", transient_for=self.window, modal=True)
        dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Unlock", Gtk.ResponseType.OK)
        dialog.set_default_response(Gtk.ResponseType.OK)
        entry = password_entry()
        dialog.get_content_area().set_border_width(16)
        dialog.get_content_area().pack_start(entry, False, False, 0)
        self.dialog = dialog
        dialog.show_all()
        response = dialog.run()
        password = entry.get_text() if response == Gtk.ResponseType.OK else None
        entry.set_text("")
        self.dialog = None
        dialog.destroy()
        if password is not None:
            self._run(self.setup.unlock, self.setup.controller.begin(), password, unlock=True)

    def _run(self, operation, *args, success="", unlock=False, cleanup=False):
        self.busy = True
        self.message = ""
        self._refresh()

        def work():
            try:
                result = operation(*args)
                message = success if not cleanup or result else "Keyring cleanup is pending. Retry from Settings."
                error = False
            except UnlockCancelled:
                message, error = "", False
            except (KeyringError, SettingsError, VaultError) as failure:
                message, error = str(failure), True
            except Exception:
                message, error = "The operation could not be completed.", True
            GLib.idle_add(self._completed, message, error, unlock)

        Thread(target=work, daemon=True).start()

    def _completed(self, message, error, unlock):
        if self.exiting:
            return GLib.SOURCE_REMOVE
        self.busy = False
        self.message = message
        if error and not self.desktop.locked:
            if unlock:
                self.message += " To recover, enter the password manually or verify a replacement in Settings."
            self._present()
        self._refresh()
        return GLib.SOURCE_REMOVE

    def _desktop_lock(self):
        self.owner_views.close()
        if self.dialog is not None:
            self.dialog.response(Gtk.ResponseType.CANCEL)
        self._lock()

    def _lock(self, *_):
        self.broker.stop()
        self.approval_ui.close()
        self.owner_views.close()
        self.setup.controller.lock()
        self.message = ""
        if self.window is not None:
            self._refresh()

    def _forget(self, *_):
        if self._ready():
            self.broker.stop()
            self._run(self.setup.forget, success="Saved password forgotten.", cleanup=True)

    def _enable_listing(self, *_):
        if not self._ready():
            return
        try:
            self.broker.start()
            self.message = ""
        except ListingError:
            self.message = "Agent access could not start. Check the broker endpoint and agent account."
            self._present()
        self._refresh()

    def _stop_listing(self, *_):
        self.broker.stop()
        self.approval_ui.close()
        self._refresh()

    def _retry_cleanup(self, *_):
        if self._ready():
            self._run(self.setup.retry_cleanup, success="Keyring cleanup complete.", cleanup=True)

    def _quit(self, *_):
        self.exiting = True
        self._desktop_lock()
        self.quit()
        return GLib.SOURCE_REMOVE

    def do_shutdown(self):
        self.broker.stop()
        self.approval_ui.close()
        self.owner_views.close()
        GLib.source_remove(self.approval_poll)
        GLib.source_remove(self.activity_prune)
        self.setup.controller.lock()
        self.desktop.close()
        Gtk.Application.do_shutdown(self)


def main():
    # Disable core dumps for the UI and the password-handling threads.
    if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0):
        raise SystemExit("Could not protect the desktop process from core dumps.")
    show_window = "--show-window" in sys.argv
    return VaultApplication(show_window=show_window).run([arg for arg in sys.argv if arg != "--show-window"])
