"""The owner desktop and tray for the multi-vault workspace."""

from dataclasses import replace
from pathlib import Path
import pwd
import signal
from threading import Thread

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gio, GLib, Gtk

from .activity import ActivityError, ActivityStore
from .broker import BrokerConfig, ListingBroker
from .desktop import DesktopSession
from .grants import Grants
from .keyring import KeyringError, SystemKeyring
from .owner_views import _dialog, _label, _scroll, _table
from .protocol import ListingError
from .scoped_broker import ScopedBroker
from .settings import SettingsError, SettingsStore
from .tray import APP_ID, APP_TITLE, SetupDialog, password_entry
from .vault import UnlockCancelled, VaultError
from .workspace import Workspace
from .workspace_views import AccessView, ActivityView, add_label, button, entry_details


OWNER_ERRORS = (ActivityError, KeyringError, ListingError, OSError, SettingsError, ValueError, VaultError)


class WorkspaceApplication(Gtk.Application):
    def __init__(self, directory=None, keyring=None, desktop_factory=DesktopSession, show_window=False):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.directory = directory or SettingsStore().path.parent
        self.keyring = keyring or SystemKeyring()
        self.desktop_factory = desktop_factory
        self.show_window = show_window
        self.workspace = None
        self.grants = None
        self.broker = None
        self.window = None
        self.dialog = None
        self.indicator = None
        self.tray_connected = False
        self.message = ""
        self.exiting = False
        self.busy = False
        self.selection = None
        self.tree_signature = None
        self.entry_rows = {}

    def do_startup(self):
        Gtk.Application.do_startup(self)
        self.hold()
        self.desktop = self.desktop_factory(self._desktop_lock, self._quit)
        self.activity = ActivityStore(Path(self.directory) / "activity.sqlite")
        try:
            self.workspace = Workspace(self.directory, self.keyring)
            previous = self.workspace.legacy_access.read()
            self.activity.recover(previous.retention_days)
            self.grants = Grants(self.workspace, self.activity)
            engine = ScopedBroker(self.workspace, self.grants, self.activity)
            self.broker = ListingBroker(previous.broker_config(BrokerConfig.from_environment()), lambda: engine, engine)
            if self.broker.config:
                self.broker.start()
        except OWNER_ERRORS as error:
            self.message = str(error) or "Could not initialize the workspace."
        if self.workspace and self.workspace.pending:
            self._background(self.workspace.cleanup)
        self.poll = GLib.timeout_add(500, self._refresh)
        self.prune = GLib.timeout_add_seconds(3600, self._prune)
        for signum in (signal.SIGINT, signal.SIGTERM):
            GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signum, self._quit)

    def do_activate(self):
        if self.window:
            self._present()
            return
        self._build_window()
        self._build_tray()
        self._refresh()
        if self.show_window or not self.workspace or not self.workspace.registrations:
            self._present()
        else:
            GLib.timeout_add(650, self._fallback)

    def _fallback(self):
        if not self.tray_connected:
            self._present()
        return GLib.SOURCE_REMOVE

    def _present(self, *_):
        if self.window and not self.desktop.locked and not self.exiting:
            self.window.present()

    def _build_window(self):
        self.window = Gtk.ApplicationWindow(application=self, title=APP_TITLE)
        self.window.set_default_size(1040, 660)
        self.window.connect("delete-event", self._window_closed)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin=12)
        self.window.add(outer)
        toolbar = Gtk.Box(spacing=8)
        outer.pack_start(toolbar, False, False, 0)
        button(toolbar, "Add vault…", lambda *_: self._configure())
        button(toolbar, "Broker settings…", self._broker_settings)
        self.pause_button = button(toolbar, "Resume agent access", self._toggle_pause)
        self.notice = _label("")
        outer.pack_start(self.notice, False, False, 0)
        pane = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL, position=260)
        outer.pack_start(pane, True, True, 0)

        self.tree = Gtk.TreeView(model=Gtk.TreeStore(str, str, str))
        self.tree.append_column(Gtk.TreeViewColumn("Vaults", Gtk.CellRendererText(), text=0))
        self.tree.get_selection().connect("changed", self._select)
        self.tree.connect("button-release-event", self._tree_click)
        self.tree.connect("row-activated", lambda *_: self._select(self.tree.get_selection()))
        pane.pack1(_scroll(self.tree), resize=False, shrink=False)

        self.stack = Gtk.Stack()
        pane.pack2(self.stack, resize=True, shrink=False)
        self.browser = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin_start=10)
        self.stack.add_named(self.browser, "browse")
        self.browse_title = _label("")
        self.browser.pack_start(self.browse_title, False, False, 0)
        self.vault_tools = Gtk.Box(spacing=6)
        self.browser.pack_start(self.vault_tools, False, False, 0)
        self.vault_buttons = {}
        controls = (
            ("unlock", "Unlock", lambda *_: self._unlock(use_saved=True)),
            ("manual", "Enter password…", lambda *_: self._unlock()),
            ("lock", "Lock vault", self._lock_selected),
            ("rename", "Rename…", self._rename),
            ("relink", "Relink…", lambda *_: self._configure(self._record())),
            ("forget", "Forget password", self._forget),
            ("remove", "Remove…", self._remove),
        )
        for name, title, handler in controls:
            self.vault_buttons[name] = button(self.vault_tools, title, handler)
        self.entries = _table(Gtk.ListStore(str, str, str, str), ("Title", "Username", "URL"))
        self.entries.connect("row-activated", self._entry)
        self.entry_scroll = _scroll(self.entries)
        self.browser.pack_start(self.entry_scroll, True, True, 0)

        self.access_view = AccessView(self)
        self.activity_view = ActivityView(self)
        self.stack.add_named(self.access_view, "access")
        self.stack.add_named(self.activity_view, "activity")
        footer = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        outer.pack_start(footer, False, False, 0)
        self.activity_button = button(footer, "Activity", lambda *_: self._view("activity"))
        self.access_button = button(footer, "Access", lambda *_: self._view("access"))
        # Keep the first activation under control of the launcher/tray settings.
        outer.show_all()
        self._view("browse")

    def _build_tray(self):
        try:
            gi.require_version("AyatanaAppIndicator3", "0.1")
            from gi.repository import AyatanaAppIndicator3
        except (ImportError, ValueError):
            return
        self.indicator = AyatanaAppIndicator3.Indicator.new(
            "keepassxc-agent-access", "changes-prevent", AyatanaAppIndicator3.IndicatorCategory.APPLICATION_STATUS,
        )
        self.menu = Gtk.Menu()
        self.tray_items = {}
        for key, name, callback in (
            ("open", "Open workspace", self._present),
            ("pause", "Resume agent access", self._toggle_pause),
            ("lock", "Lock all vaults", self._lock_all),
            ("access", "Access", lambda *_: self._tray_access()),
            ("quit", "Quit", self._quit),
        ):
            item = Gtk.MenuItem(label=name)
            item.connect("activate", callback)
            self.menu.append(item)
            self.tray_items[key] = item
        self.menu.show_all()
        self.indicator.set_menu(self.menu)
        self.indicator.connect("connection-changed", self._tray_status)
        self.indicator.set_status(AyatanaAppIndicator3.IndicatorStatus.ACTIVE)

    def _tray_status(self, _indicator, connected):
        self.tray_connected = connected
        if not connected:
            self._present()

    def _tray_access(self):
        self._present()
        if not self.desktop.locked:
            self._view("access")

    def _window_closed(self, *_):
        if self.tray_connected:
            self.window.hide()
        else:
            self._quit()
        return True

    def _view(self, name):
        self.stack.set_visible_child_name(name)
        if name == "access":
            self.access_view.refresh()
        elif name == "activity":
            self.activity_view.refresh()

    def _refresh(self):
        if self.window and not self.exiting:
            if self.workspace:
                self._refresh_tree()
            self._browse()
            self.notice.set_text(self.message)
            self.notice.set_visible(bool(self.message))
            paused = not self.workspace or self.workspace.paused
            pause_label = "Resume agent access" if paused else "Pause agent access"
            self.pause_button.set_label(pause_label)
            self.pause_button.set_sensitive(bool(self.broker and self.broker.enabled and not self.desktop.locked))
            count = sum(row.status == "pending" for row in self.grants.rows()) if self.grants else 0
            access_label = f"Access ({count})" if count else "Access"
            self.access_button.set_label(access_label)
            if self.indicator:
                self.tray_items["pause"].set_label(pause_label)
                self.tray_items["pause"].set_sensitive(self.pause_button.get_sensitive())
                self.tray_items["access"].set_label(access_label)
                self.indicator.set_icon("changes-prevent" if paused else "changes-allow")
            if self.stack.get_visible_child_name() == "access":
                self.access_view.refresh()
            elif self.stack.get_visible_child_name() == "activity":
                self.activity_view.refresh()
        return GLib.SOURCE_CONTINUE

    def _refresh_tree(self):
        with self.workspace.mutex:
            records = [(record, self.workspace.session(record.id)) for record in self.workspace.registrations.values()]
        signature = [(record.id, record.name, id(session) if session else None) for record, session in records]
        if signature == self.tree_signature:
            return
        self.tree_signature = signature
        model = self.tree.get_model()
        expanded = set()

        def save_expanded(_tree, path):
            expanded.add(tuple(model[path][1:3]))

        self.tree.map_expanded_rows(save_expanded)
        desired = self.selection
        self.rebuilding = True
        model.clear()
        nodes = {}
        for record, session in records:
            identifier = record.id
            root = model.append(None, (record.name if session else f"{record.name} · Locked", identifier, ""))
            nodes[identifier, ""] = root
            if session:
                children = {}
                for group in session.groups:
                    children.setdefault(group["parent"], []).append(group)
                todo = [(root, group) for top in children.get(None, ()) for group in reversed(children.get(top["id"], ()))]
                while todo:
                    parent, group = todo.pop()
                    node = model.append(parent, (group["name"] or "(Untitled group)", identifier, group["id"]))
                    nodes[identifier, group["id"]] = node
                    todo.extend((node, child) for child in reversed(children.get(group["id"], ())))
        for key in expanded:
            if key in nodes:
                self.tree.expand_to_path(model.get_path(nodes[key]))
        keep = desired if desired in nodes else (desired[0], "") if desired and (desired[0], "") in nodes else None
        self.selection = keep or next(iter(nodes), None)
        if self.selection:
            path = model.get_path(nodes[self.selection])
            if path.get_depth() > 1:
                self.tree.expand_to_path(path)
            self.tree.get_selection().select_path(path)
        self.rebuilding = False

    def _select(self, selection):
        if getattr(self, "rebuilding", False):
            return
        model, row = selection.get_selected()
        if row:
            self.selection = tuple(model[row][1:3])
            self._view("browse")
            self._browse()

    def _tree_click(self, _tree, event):
        if event.button == 1 and self.tree.get_path_at_pos(int(event.x), int(event.y)):
            self._select(self.tree.get_selection())
        return False

    def _record(self):
        return self.workspace.registrations.get(self.selection[0]) if self.workspace and self.selection else None

    def _browse(self):
        record = self._record()
        session = self.workspace.session(record.id) if record else None
        group_id = self.selection[1] if record else ""
        rows = []
        if session:
            group = next((group for group in session.groups if group["id"] == group_id
                          or not group_id and group["parent"] is None), None)
            title = record.name if not group_id or group is None else f"{record.name} / {group['name']}"
            rows = [row for row in session.entries if group and row["group"] == group["id"]]
        else:
            title = f"{record.name} · Locked" if record else "Add a KeePass vault to begin"
        self.browse_title.set_text(title)
        self.entry_scroll.set_visible(bool(session))
        self.entry_rows = {row["id"]: row for row in rows}
        model = self.entries.get_model()
        values = [(row["title"] or "(Untitled entry)", row["username"], row["url"], row["id"]) for row in rows]
        if list(map(tuple, model)) != values:
            model.clear()
            for value in values:
                model.append(value)
        for key, control in self.vault_buttons.items():
            visible = {
                "unlock": bool(record and record.item and not session), "manual": bool(record and not session),
                "lock": bool(session), "rename": bool(record), "relink": bool(record),
                "forget": bool(record and record.item), "remove": bool(record),
            }[key]
            control.set_visible(visible)
            control.set_sensitive(not self.busy and not self.desktop.locked)

    def _entry(self, _table, path, _column):
        if not self.desktop.locked and self.selection:
            identifier = self.entries.get_model()[path][3]
            if identifier in self.entry_rows:
                entry_details(self, self.selection[0], self.entry_rows[identifier])

    def run_dialog(self, dialog):
        if self.desktop.locked or self.exiting:
            dialog.destroy()
            return Gtk.ResponseType.CANCEL
        self.dialog = dialog
        dialog.show_all()
        try:
            return dialog.run()
        finally:
            self.dialog = None
            dialog.hide()
            # Let the caller read submitted controls before disposing of the dialog.
            GLib.idle_add(dialog.destroy)

    def confirm(self, title, detail):
        dialog = Gtk.MessageDialog(transient_for=self.window, modal=True, text=title,
                                   secondary_text=detail, buttons=Gtk.ButtonsType.OK_CANCEL)
        return self.run_dialog(dialog) == Gtk.ResponseType.OK

    def owner_operation(self, operation):
        if self.desktop.locked or self.exiting:
            return
        try:
            operation()
            self.message = ""
        except OWNER_ERRORS as error:
            self.message = str(error) or "The operation could not be completed."
        self._refresh()

    def _background(self, operation, *, select=False):
        if self.busy or self.exiting or self.desktop.locked:
            return
        self.busy = True

        def work():
            identifier, message = None, ""
            try:
                identifier = operation()
            except UnlockCancelled:
                pass
            except OWNER_ERRORS as error:
                message = str(error) or "The operation could not be completed."
            GLib.idle_add(done, identifier, message)

        def done(identifier, message):
            self.busy = False
            if not self.exiting:
                self.message = message
                if select and identifier and not self.desktop.locked:
                    self.selection = (identifier, "")
                    self.tree_signature = None
                    self._view("browse")
                self._refresh()

        Thread(target=work, daemon=True).start()
        self._refresh()

    def _configure(self, record=None):
        if not self.workspace or self.busy or self.desktop.locked:
            return
        dialog = SetupDialog(self.window, record.target if record else None)
        dialog.set_title("Relink vault" if record else "Add KeePass vault")
        if record and record.item:
            dialog.remember.set_active(True)
        response = self.run_dialog(dialog)
        password = dialog.password.get_text()
        dialog.password.set_text("")
        if response != Gtk.ResponseType.OK:
            return
        try:
            target = dialog.selection()
        except VaultError as error:
            self.message = str(error)
            self._refresh()
            return
        remember = dialog.remember.get_active()
        cycle = self.workspace.owner_generation
        if record:
            self._background(lambda: self.workspace.relink(record.id, target, password, remember, cycle=cycle), select=True)
        else:
            self._background(lambda: self.workspace.add(target, password, remember, cycle=cycle), select=True)

    def _unlock(self, use_saved=False):
        record = self._record()
        if not record or self.busy or self.desktop.locked:
            return
        cycle = self.workspace.owner_generation
        if use_saved and record.item:
            self._background(lambda: self.workspace.unlock(record.id, cycle=cycle))
            return
        dialog, body = _dialog(self, f"Unlock {record.name}", 445, 175)
        dialog.set_modal(True)
        dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Unlock", Gtk.ResponseType.OK)
        field = password_entry()
        body.pack_start(field, False, False, 0)
        remember = Gtk.CheckButton(label="Remember in the OS keyring", active=bool(record.item))
        body.pack_start(remember, False, False, 0)
        response = self.run_dialog(dialog)
        password, save = field.get_text(), remember.get_active()
        field.set_text("")
        if response == Gtk.ResponseType.OK:
            self._background(lambda: self.workspace.unlock(record.id, password, save, cycle=cycle))

    def _lock_selected(self, *_):
        record = self._record()
        if record:
            self.owner_operation(lambda: self.workspace.lock(record.id))

    def _lock_all(self, *_):
        if self.workspace:
            self.workspace.lock_all()
            self._refresh()

    def _rename(self, *_):
        record = self._record()
        if not record or self.desktop.locked:
            return
        dialog, body = _dialog(self, "Rename vault", 410, 140)
        dialog.set_modal(True)
        dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Rename", Gtk.ResponseType.OK)
        name = Gtk.Entry(text=record.name, activates_default=True)
        body.pack_start(name, False, False, 0)
        if self.run_dialog(dialog) == Gtk.ResponseType.OK:
            self.owner_operation(lambda: self.workspace.rename(record.id, name.get_text().strip()))

    def _remove(self, *_):
        record = self._record()
        if record and self.confirm(f"Remove {record.name} from this workspace?", "The KeePass file stays on disk."):
            self._background(lambda: self.workspace.remove(record.id))

    def _forget(self, *_):
        record = self._record()
        if record and self.confirm("Forget this vault's saved password?", "Future unlocks will ask for the password."):
            self._background(lambda: self.workspace.forget(record.id))

    def _toggle_pause(self, *_):
        if self.broker and self.broker.enabled and not self.desktop.locked:
            self.workspace.pause(not self.workspace.paused)
            self._refresh()

    def _broker_settings(self, *_):
        if not self.broker or self.desktop.locked:
            return
        settings = self.workspace.legacy_access.read()
        config = self.broker.config
        dialog, body = _dialog(self, "Broker settings", 540, 260)
        dialog.set_modal(True)
        dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Save", Gtk.ResponseType.OK)
        endpoint = Gtk.Entry(text=str(config.path) if config else "")
        uid = Gtk.Entry(text=str(config.agent_uid) if config else "")
        retention = Gtk.SpinButton.new_with_range(1, 365, 1)
        retention.set_value(settings.retention_days)
        for label, widget in (("Absolute broker socket path", endpoint), ("Isolated runner account or UID", uid),
                              ("Activity retention (days)", retention)):
            add_label(body, label)
            body.pack_start(widget, False, False, 0)

        def save():
            path, account = endpoint.get_text().strip(), uid.get_text().strip()
            if bool(path) != bool(account):
                raise ValueError("Provide both the socket path and runner account, or clear both.")
            try:
                peer = (int(account) if account.isdecimal() else pwd.getpwnam(account).pw_uid) if account else None
            except KeyError:
                raise ValueError("The runner account could not be found.") from None
            updated = replace(settings, endpoint=path or None, uid=peer, retention_days=retention.get_value_as_int())
            config = updated.broker_config()
            self.workspace.pause()
            self.broker.update(lambda: self.workspace.legacy_access.write(updated), config)
            if config:
                self.broker.start()

        if self.run_dialog(dialog) == Gtk.ResponseType.OK:
            self.owner_operation(save)

    def _desktop_lock(self, *_):
        if self.dialog:
            self.dialog.response(Gtk.ResponseType.CANCEL)
        self._lock_all()
        if self.window:
            self._view("browse")

    def _prune(self):
        if self.workspace:
            try:
                self.activity.prune(self.workspace.legacy_access.read().retention_days)
            except (SettingsError, ActivityError):
                self.message = "Local activity cleanup is unavailable."
        return GLib.SOURCE_CONTINUE

    def _quit(self, *_):
        self.exiting = True
        self._desktop_lock()
        self.quit()
        return GLib.SOURCE_REMOVE

    def do_shutdown(self):
        if self.broker:
            self.broker.stop()
        if self.workspace:
            self.workspace.lock_all()
        self.desktop.close()
        GLib.source_remove(self.poll)
        GLib.source_remove(self.prune)
        Gtk.Application.do_shutdown(self)
