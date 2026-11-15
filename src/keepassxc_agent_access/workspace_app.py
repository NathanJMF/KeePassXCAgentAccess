"""The owner desktop and tray for the multi-vault workspace."""

from dataclasses import replace
import json
from pathlib import Path
import pwd
import signal
from threading import Thread

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, Gio, GLib, Gtk, Pango

from .activity import ActivityError, ActivityStore
from .broker import BrokerConfig, ListingBroker
from .desktop import DesktopSession
from .edit_requests import EditRequests
from .grants import Grants
from .keyring import KeyringError, SystemKeyring
from .owner_views import _dialog, _label, _scroll, table_time
from .protocol import ListingError
from .scoped_broker import ScopedBroker
from .settings import SettingsError, SettingsStore
from .tray import APP_ID, APP_TITLE, SetupDialog, password_entry
from .vault import UnlockCancelled, VaultError
from .workspace import Workspace, ordered_groups
from .workspace_context import DELETE_LABEL, attach_row_context
from .workspace_editor import delete_entry, delete_group, edit_entry, edit_group
from .workspace_style import install_style, styled
from .workspace_views import (
    AccessView, ActivityView, add_label, button, empty_state, entry_details, fill_table, pane_table, section_heading,
)


OWNER_ERRORS = (ActivityError, KeyringError, ListingError, OSError, SettingsError, ValueError, VaultError)
ENTRY_FOLDER_COLUMN = 5
ENTRY_ID_COLUMN = 6
TRAY_ICON_DIRECTORY = Path(__file__).resolve().with_name("icons")
TRAY_PAUSED_ICON = "keeper-agent-access-paused"
TRAY_ACTIVE_ICON = "keeper-agent-access-active"


class WorkspaceApplication(Gtk.Application):
    def __init__(self, directory=None, keyring=None, desktop_factory=DesktopSession, show_window=False):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.directory = directory or SettingsStore().path.parent
        self.keyring = keyring or SystemKeyring()
        self.desktop_factory = desktop_factory
        self.show_window = show_window
        self.workspace = None
        self.grants = None
        self.edit_requests = None
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
        self.tree_open_vaults = set()
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
            self.edit_requests = EditRequests(self.workspace, self.grants, self.activity)
            engine = ScopedBroker(self.workspace, self.grants, self.activity, edits=self.edit_requests)
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
        self.window.set_default_size(1120, 700)
        self.window.connect("delete-event", self._window_closed)
        self.window.connect("key-press-event", self._keyboard)
        self.style = install_style(self.window)
        self._build_header()

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.window.add(outer)
        pane = styled(Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL, position=236), "keeper-divider")
        outer.pack_start(pane, True, True, 0)
        pane.pack1(self._build_sidebar(), resize=False, shrink=False)

        main = styled(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16), "keeper-pane")
        main.set_border_width(24)
        pane.pack2(main, resize=True, shrink=False)
        self.notice = styled(_label(""), "keeper-notice")
        main.pack_start(self.notice, False, False, 0)
        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE, transition_duration=120)
        main.pack_start(self.stack, True, True, 0)
        self._build_browser()

        self.access_view = AccessView(self)
        self.activity_view = ActivityView(self)
        attach_row_context(self.activity_view.table, self._activity_context)
        self.stack.add_named(self.access_view, "access")
        self.stack.add_named(self.activity_view, "activity")
        footer = styled(Gtk.Box(spacing=8), "keeper-footer")
        outer.pack_start(footer, False, False, 0)
        self.entry_count = styled(Gtk.Label(xalign=0), "keeper-muted")
        footer.pack_start(self.entry_count, False, False, 0)
        footer.pack_start(Gtk.Box(hexpand=True), True, True, 0)
        self.activity_button = button(footer, "Activity", lambda *_: self._view("activity"),
                                      icon="document-open-recent-symbolic")
        self.access_button = button(footer, "Access", lambda *_: self._view("access"), icon="changes-prevent-symbolic")
        outer.show_all()
        self._view("browse")

    def _build_header(self):
        header = styled(Gtk.HeaderBar(title=APP_TITLE, show_close_button=True), "keeper-header")
        header.set_custom_title(Gtk.Box())
        self.window.set_titlebar(header)
        self.window.set_title(APP_TITLE)
        brand = styled(Gtk.Box(spacing=7, valign=Gtk.Align.CENTER), "keeper-brand")
        badge = styled(Gtk.Box(valign=Gtk.Align.CENTER), "keeper-brand-mark")
        badge.pack_start(Gtk.Image.new_from_icon_name("dialog-password-symbolic", Gtk.IconSize.BUTTON),
                         False, False, 0)
        brand.pack_start(badge, False, False, 0)
        brand.pack_start(Gtk.Label(label=APP_TITLE, xalign=0), False, False, 0)
        header.pack_start(brand)
        add = styled(Gtk.Button(label="Add vault…", always_show_image=True), "keeper-control")
        add.set_image(Gtk.Image.new_from_icon_name("list-add-symbolic", Gtk.IconSize.BUTTON))
        add.connect("clicked", lambda *_: self._configure())
        header.pack_start(add)
        settings = styled(Gtk.MenuButton(), "keeper-control", "keeper-quiet")
        settings.set_tooltip_text("Keeper settings")
        settings.get_accessible().set_name("Keeper settings")
        settings.set_image(Gtk.Image.new_from_icon_name("open-menu-symbolic", Gtk.IconSize.BUTTON))
        settings_menu = Gtk.Menu()
        for label, action in (("Broker settings…", self._broker_settings), ("Lock all vaults", self._lock_all)):
            item = Gtk.MenuItem(label=label)
            item.connect("activate", action)
            settings_menu.append(item)
        settings_menu.show_all()
        settings.set_popup(settings_menu)
        header.pack_end(settings)
        self.pause_button = styled(Gtk.Button(label="Resume agent access", always_show_image=True),
                                   "keeper-control", "keeper-paused")
        self.pause_icon = Gtk.Image.new_from_icon_name("changes-prevent-symbolic", Gtk.IconSize.BUTTON)
        self.pause_button.set_image(self.pause_icon)
        self.pause_button.connect("clicked", self._toggle_pause)
        header.pack_end(self.pause_button)
        header.show_all()

    def _build_sidebar(self):
        sidebar = styled(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=11), "keeper-sidebar")
        sidebar.set_size_request(165, -1)
        heading = styled(Gtk.Label(label="Vaults", xalign=0, margin_top=24, margin_start=18),
                         "keeper-sidebar-title")
        sidebar.pack_start(heading, False, False, 0)
        self.tree = Gtk.TreeView(model=Gtk.TreeStore(str, str, str, str), headers_visible=False)
        self.tree.set_level_indentation(5)
        labels = Gtk.CellRendererText(ellipsize=Pango.EllipsizeMode.END, ypad=9)
        icons = Gtk.CellRendererPixbuf(xpad=6)
        column = Gtk.TreeViewColumn("Vaults")
        column.pack_start(icons, False)
        column.add_attribute(icons, "icon-name", 3)
        column.pack_start(labels, True)
        column.add_attribute(labels, "text", 0)

        def vault_weight(_column, cell, model, row, _data):
            selected = self.tree.get_selection().iter_is_selected(row)
            emphasized = selected or not model[row][2]
            cell.set_property("weight", Pango.Weight.SEMIBOLD if emphasized else Pango.Weight.NORMAL)

        column.set_cell_data_func(labels, vault_weight)
        self.tree.append_column(column)
        self.tree.get_selection().connect("changed", self._select)
        self.tree.connect("button-release-event", self._tree_click)
        self.tree.connect("row-activated", lambda *_: self._select(self.tree.get_selection()))
        attach_row_context(self.tree, self._vault_context)
        scroll = _scroll(self.tree)
        scroll.set_shadow_type(Gtk.ShadowType.NONE)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_margin_start(9)
        scroll.set_margin_end(9)
        sidebar.pack_start(scroll, True, True, 0)
        return sidebar

    def _build_browser(self):
        self.browser = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        self.stack.add_named(self.browser, "browse")
        header, titles, self.browse_title, self.browse_icon = section_heading("Vaults", "drive-harddisk-symbolic")
        self.browse_path = styled(
            Gtk.Label(xalign=0, ellipsize=Pango.EllipsizeMode.START, single_line_mode=True), "keeper-muted",
        )
        titles.pack_start(self.browse_path, False, False, 0)
        titles.reorder_child(self.browse_path, 0)
        self.browser.pack_start(header, False, False, 0)

        self.vault_tools = styled(Gtk.Box(spacing=6, valign=Gtk.Align.CENTER), "keeper-vault-tools")
        header.pack_end(self.vault_tools, False, False, 0)
        self.vault_buttons = {}
        for name, title, handler in (
            ("unlock", "Unlock", self._unlock),
            ("lock", "Lock vault", self._lock_selected),
        ):
            self.vault_buttons[name] = button(self.vault_tools, title, handler)
        styled(self.vault_buttons["unlock"], "suggested-action")

        self.new_item = styled(Gtk.MenuButton(label="New", always_show_image=True), "keeper-primary")
        self.new_item.set_image(Gtk.Image.new_from_icon_name("list-add-symbolic", Gtk.IconSize.BUTTON))
        new_menu = Gtk.Menu()
        self.new_group_item = Gtk.MenuItem(label="Group…")
        self.new_group_item.connect("activate", lambda *_: self._new_group())
        new_menu.append(self.new_group_item)
        self.new_entry_item = Gtk.MenuItem(label="Entry…")
        self.new_entry_item.connect("activate", lambda *_: self._new_entry())
        new_menu.append(self.new_entry_item)
        new_menu.show_all()
        self.new_item.set_popup(new_menu)
        self.vault_tools.pack_start(self.new_item, False, False, 0)
        button_heights = Gtk.SizeGroup(mode=Gtk.SizeGroupMode.VERTICAL)
        for control in (*self.vault_buttons.values(), self.new_item):
            button_heights.add_widget(control)

        card = styled(Gtk.Box(orientation=Gtk.Orientation.VERTICAL), "keeper-card")
        self.browser.pack_start(card, True, True, 0)
        self.entry_tools = styled(Gtk.Box(), "keeper-card-toolbar")
        self.entry_search = styled(Gtk.SearchEntry(placeholder_text="Filter entries", width_chars=28,
                                                 max_width_chars=36, halign=Gtk.Align.START), "keeper-search")
        self.entry_search.connect("changed", lambda *_: self._browse())
        self.entry_tools.pack_start(self.entry_search, False, False, 0)
        card.pack_start(self.entry_tools, False, False, 0)

        self.entries, self.entry_scroll = pane_table(
            Gtk.ListStore(str, str, str, str, str, str, str, object, object),
            ("Title", "Username", "URL", "Created", "Modified", "Folder"), (152, 96, 115, 125, 125, 110),
            lead_icon="dialog-password-symbolic", expand_columns=(0, 1, 2, ENTRY_FOLDER_COLUMN),
            muted_columns=(1, 2, 3, 4, ENTRY_FOLDER_COLUMN), time_columns={3: 7, 4: 8},
        )
        self.folder_column = self.entries.get_column(ENTRY_FOLDER_COLUMN)
        created, modified = (self.entries.get_column(index) for index in (3, 4))
        self.entries.move_column_after(created, None)
        self.entries.move_column_after(modified, created)
        self.entries.move_column_after(self.folder_column, modified)
        self.entries.connect("row-activated", self._entry)
        attach_row_context(self.entries, self._entry_context)
        card.pack_start(self.entry_scroll, True, True, 0)
        self.empty_state, self.empty_entries, self.empty_icon = empty_state("drive-harddisk-symbolic", "")
        area = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.FILL, halign=Gtk.Align.FILL)
        area.set_center_widget(self.empty_state)
        card.pack_start(area, True, True, 0)
        self.empty_area = area

    def _keyboard(self, _window, event):
        if (event.state & Gtk.accelerator_get_default_mod_mask() == Gdk.ModifierType.CONTROL_MASK
                and event.keyval in (Gdk.KEY_f, Gdk.KEY_F)
                and self.stack.get_visible_child_name() == "browse" and self.entry_search.get_visible()):
            self.entry_search.grab_focus()
            return True
        return False

    def _build_tray(self):
        try:
            gi.require_version("AyatanaAppIndicator3", "0.1")
            from gi.repository import AyatanaAppIndicator3
        except (ImportError, ValueError):
            return
        self.indicator = AyatanaAppIndicator3.Indicator.new_with_path(
            "keepassxc-agent-access", TRAY_PAUSED_ICON, AyatanaAppIndicator3.IndicatorCategory.APPLICATION_STATUS,
            str(TRAY_ICON_DIRECTORY),
        )
        self.indicator.set_title(APP_TITLE)
        self.menu = Gtk.Menu()
        self.tray_items = {}
        for key, name, callback in (
            ("open", f"Open {APP_TITLE}", self._present),
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
        if name == "access" and self.stack.get_visible_child_name() != name:
            self.access_view.table.collapse_all()
        self.stack.set_visible_child_name(name)
        for view, button in (("access", self.access_button), ("activity", self.activity_button)):
            style = button.get_style_context()
            if name == view:
                style.add_class("keeper-current")
            else:
                style.remove_class("keeper-current")
        self.entry_count.set_visible(name == "browse")
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
            if self.pause_button.get_label() != pause_label:
                self.pause_button.set_label(pause_label)
                icon = "changes-prevent-symbolic" if paused else "changes-allow-symbolic"
                self.pause_icon.set_from_icon_name(icon, Gtk.IconSize.BUTTON)
                style = self.pause_button.get_style_context()
                style.add_class("keeper-paused" if paused else "keeper-live")
                style.remove_class("keeper-live" if paused else "keeper-paused")
            self.pause_button.set_sensitive(bool(self.broker and self.broker.enabled and not self.desktop.locked))
            count = sum(row.status == "pending" for row in self.grants.rows()) if self.grants else 0
            count += sum(row.status == "pending" for row in self.pending_edits())
            access_label = f"Access ({count})" if count else "Access"
            self.access_button.set_label(access_label)
            if self.indicator:
                self.tray_items["pause"].set_label(pause_label)
                self.tray_items["pause"].set_sensitive(self.pause_button.get_sensitive())
                self.tray_items["access"].set_label(access_label)
                self.indicator.set_icon_full(
                    TRAY_PAUSED_ICON if paused else TRAY_ACTIVE_ICON,
                    "Agent access paused" if paused else "Agent access active",
                )
            if self.stack.get_visible_child_name() == "access":
                self.access_view.refresh()
            elif self.stack.get_visible_child_name() == "activity":
                self.activity_view.refresh()
        return GLib.SOURCE_CONTINUE

    def pending_edits(self):
        if self.edit_requests:
            try:
                return self.edit_requests.rows()
            except ActivityError:
                self.message = "Agent edit requests are temporarily unavailable."
        return []

    def _refresh_tree(self):
        with self.workspace.mutex:
            records = [(record, self.workspace.owner_session(record.id)) for record in self.workspace.registrations.values()]
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
            root = model.append(None, (record.name if session else f"{record.name} · Locked", identifier, "",
                                       "drive-harddisk-symbolic" if session else "changes-prevent-symbolic"))
            nodes[identifier, ""] = root
            if session:
                for group, path in ordered_groups(session.groups):
                    parent = nodes.get((identifier, group["parent"]), root)
                    node = model.append(parent, (path[-1], identifier, group["id"], "folder-symbolic"))
                    nodes[identifier, group["id"]] = node
        open_vaults = {record.id for record, session in records if session}
        expanded.update((identifier, "") for identifier in open_vaults - self.tree_open_vaults)
        self.tree_open_vaults = open_vaults
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
            selection = tuple(model[row][1:3])
            changed = selection != self.selection
            self.selection = selection
            if changed and self.entry_search.get_text():
                self.entry_search.set_text("")
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
        session = self.workspace.owner_session(record.id) if record else None
        group_id = self.selection[1] if record else ""
        title, path, empty = "Vaults", "", "Add a KeePass vault to begin."
        symbol = "drive-harddisk-symbolic"
        search = ""
        matches, total = [], 0
        if session:
            group = next((group for group in session.groups if group["id"] == group_id), None) if group_id else None
            if group_id and group:
                symbol = "folder-open-symbolic"
                title = group["name"] or "(Untitled group)"
                groups = {item["id"]: item for item in session.groups}
                ancestors = []
                parent = group["parent"]
                while parent in groups and groups[parent]["parent"] is not None:
                    ancestor = groups[parent]
                    ancestors.append(ancestor["name"] or "(Untitled group)")
                    parent = ancestor["parent"]
                path = " / ".join((record.name, *reversed(ancestors)))
            else:
                title = record.name
            rows = [row for row in session.entries if row["group"] == group_id] if group_id else session.entries
            total = len(rows)
            search = self.entry_search.get_text().strip().casefold()
            matches = []
            for row in rows:
                folder = "" if group_id else " / ".join(part or "(Untitled group)" for part in row["group_path"]) or "Root"
                fields = (row["title"], row["username"], row["url"], folder)
                if not search or any(search in field.casefold() for field in fields):
                    matches.append((row, folder))
            empty = "This group has no entries." if group_id else "This vault has no entries."
            if search:
                empty = "No entries match this filter."
        elif record:
            symbol = "changes-prevent-symbolic"
            title = f"{record.name} · Locked"
            empty = "Unlock this vault to view its groups and entries."
        self.browse_title.set_text(title)
        self.browse_path.set_text(path or " ")
        self.entry_tools.set_visible(bool(session))
        self.entry_search.set_visible(bool(session))
        self.entry_search.set_tooltip_text("Filter the selected group (Ctrl+F)" if group_id else "Filter this vault (Ctrl+F)")
        self.folder_column.set_visible(bool(session and not group_id))
        self.entry_scroll.set_visible(bool(matches))
        self.empty_entries.set_text(empty)
        self.empty_area.set_visible(not matches)
        current, _ = self.browse_icon.get_icon_name()
        if current != symbol:
            self.browse_icon.set_from_icon_name(symbol, Gtk.IconSize.LARGE_TOOLBAR)
        empty_symbol = "system-search-symbolic" if search else symbol
        current, _ = self.empty_icon.get_icon_name()
        if current != empty_symbol:
            self.empty_icon.set_from_icon_name(empty_symbol, Gtk.IconSize.DIALOG)
        count = "1 entry" if total == 1 else f"{total} entries"
        self.entry_count.set_text(f"{len(matches)} of {count}" if session and len(matches) != total
                                  else count if session else "")
        self.entry_rows = {row["id"]: row for row, _ in matches}
        values = []
        for row, folder in matches:
            created, modified = row.get("created"), row.get("modified")
            values.append((row["title"] or "(Untitled entry)", row["username"], row["url"],
                           table_time(created), table_time(modified),
                           folder, row["id"], created, modified))
        fill_table(self.entries, values, ENTRY_ID_COLUMN)
        self.new_item.set_visible(bool(session))
        self.new_item.set_sensitive(not self.busy and not self.desktop.locked)
        for key, control in self.vault_buttons.items():
            visible = {
                "unlock": bool(record and not session),
                "lock": bool(session),
            }[key]
            control.set_visible(visible)
            control.set_sensitive(not self.busy and not self.desktop.locked)

    def _actions_for(self, target, sections):
        def invoke(action):
            if self.selection == target and not self.busy and not self.desktop.locked:
                action()

        return [[(label, lambda action=action: invoke(action)) for label, action in section] for section in sections]

    def _vault_context(self, row):
        target = tuple(row[1:3])
        if self.busy or self.desktop.locked or not self.workspace:
            return []
        self._select(self.tree.get_selection())
        vault, group = target
        record = self.workspace.registrations.get(vault)
        if record is None:
            return []
        session = self.workspace.owner_session(vault)
        create = [("New entry…", self._new_entry)]
        if group:
            if not session:
                return []
            return self._actions_for(target, [
                create,
                [("Edit group…", self._edit_group), ("Copy group reference", self._copy_group_reference)],
                [(DELETE_LABEL, self._delete_group)],
            ])
        create.append(("New group…", self._new_group))
        if session:
            session_actions = [("Lock vault", self._lock_selected)]
        else:
            session_actions = [("Unlock", self._unlock)]
        management = [("Rename vault…", self._rename), ("Relink vault…", lambda: self._configure(self._record()))]
        if record.item:
            management.append(("Forget saved password…", self._forget))
        if session:
            management.append(("Copy root group reference", self._copy_group_reference))
        return self._actions_for(target, [
            session_actions, create if session else [], management, [("Remove from Keeper…", self._remove)],
        ])

    def _entry_context(self, row):
        target = self.selection
        identifier = row[ENTRY_ID_COLUMN]
        if not target or self.busy or self.desktop.locked or identifier not in self.entry_rows:
            return []
        vault, group = target

        def with_entry(action):
            entry = self.entry_rows.get(identifier)
            if entry:
                action(entry)

        return self._actions_for(target, [
            [("View entry details…", lambda: with_entry(lambda entry: entry_details(self, vault, entry))),
             ("Edit entry…", lambda: with_entry(lambda entry: edit_entry(self, vault, group, entry))),
             ("Copy entry reference", lambda: with_entry(lambda _: self.copy_reference(vault, "entry", identifier)))],
            [(DELETE_LABEL, lambda: with_entry(lambda entry: delete_entry(self, vault, group, entry)))],
        ])

    def _activity_context(self, row):
        identifier = row[self.activity_view.RECORD_ID]
        return [[("View details…", lambda: self.activity_view.open_record(identifier))]]

    def copy_reference(self, vault, field, identifier):
        if not self.desktop.locked and self.workspace.owner_session(vault):
            reference = json.dumps({"vault": vault, field: identifier})
            Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(reference, -1)

    def _copy_group_reference(self, *_):
        record = self._record()
        session = self.workspace.owner_session(record.id) if record else None
        if session:
            group = self.selection[1] or next(item["id"] for item in session.groups if item["parent"] is None)
            self.copy_reference(record.id, "parent", group)

    def _show_group(self, identifier, group):
        self.selection = (identifier, group)
        self.entry_search.set_text("")
        self.tree_signature = None
        self._view("browse")

    def _new_entry(self):
        if self.selection:
            edit_entry(self, *self.selection)

    def _new_group(self):
        if self.selection:
            edit_group(self, self.selection[0], None)

    def _edit_group(self, *_):
        if self.selection and self.selection[1]:
            edit_group(self, *self.selection)

    def _delete_group(self, *_):
        if self.selection and self.selection[1]:
            delete_group(self, *self.selection)

    def _entry(self, _table, path, _column):
        if not self.busy and not self.desktop.locked and self.selection:
            identifier = self.entries.get_model()[path][ENTRY_ID_COLUMN]
            if identifier in self.entry_rows:
                entry_details(self, self.selection[0], self.entry_rows[identifier])

    def run_dialog(self, dialog):
        if self.desktop.locked or self.exiting:
            dialog.destroy()
            return Gtk.ResponseType.CANCEL
        previous = self.dialog
        self.dialog = dialog
        dialog.show_all()
        try:
            return dialog.run()
        finally:
            self.dialog = previous
            dialog.hide()
            # Let the caller read submitted controls before disposing of the dialog.
            GLib.idle_add(dialog.destroy)

    def confirm(self, title, detail, *, delete=False):
        buttons = Gtk.ButtonsType.NONE if delete else Gtk.ButtonsType.OK_CANCEL
        dialog = Gtk.MessageDialog(transient_for=self.window, modal=True, text=title,
                                   secondary_text=detail, buttons=buttons)
        if delete:
            dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Delete", Gtk.ResponseType.OK)
            styled(dialog.get_widget_for_response(Gtk.ResponseType.OK), "destructive-action")
            dialog.set_default_response(Gtk.ResponseType.CANCEL)
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

    def _background(self, operation, *, select=False, after=None, finished=None):
        if self.busy or self.exiting or self.desktop.locked:
            return
        self.busy = True

        def work():
            value, message, completed = None, "", False
            try:
                value = operation()
                completed = True
            except UnlockCancelled:
                pass
            except OWNER_ERRORS as error:
                message = str(error) or "The operation could not be completed."
            GLib.idle_add(done, value, message, completed)

        def done(value, message, completed):
            self.busy = False
            if not self.exiting:
                self.message = message
                if not self.desktop.locked:
                    if completed:
                        if select and value:
                            self._show_group(value, "")
                        elif after:
                            after(value)
                    if finished:
                        finished(completed, message)
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

    def _unlock(self, *_):
        self.unlock_record(self._record())

    def unlock_record(self, record, *, parent=None, finished=None):
        if not record or self.busy or self.desktop.locked or self.exiting:
            return False
        cycle = self.workspace.owner_generation

        def can_prompt():
            return (not self.desktop.locked and not self.exiting and self.workspace.owner_generation == cycle
                    and (parent is None or parent.get_visible()))

        def prompt(reason=""):
            if not can_prompt():
                return False
            dialog, body = _dialog(self, f"Unlock {record.name}", 445, 175)
            if parent is not None:
                dialog.set_transient_for(parent)
            dialog.set_modal(True)
            dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Unlock", Gtk.ResponseType.OK)
            dialog.set_default_response(Gtk.ResponseType.OK)
            if reason:
                body.pack_start(_label(reason), False, False, 0)
            field = password_entry()
            field.set_activates_default(True)
            body.pack_start(field, False, False, 0)
            remember = Gtk.CheckButton(label="Remember in the OS keyring", active=bool(record.item))
            body.pack_start(remember, False, False, 0)
            field.grab_focus()
            response = self.run_dialog(dialog)
            password, save = field.get_text(), remember.get_active()
            field.set_text("")
            if response != Gtk.ResponseType.OK or not can_prompt():
                return False
            self._background(lambda: self.workspace.unlock(record.id, password, save, cycle=cycle), finished=finished)
            return True

        if not record.item:
            return prompt()

        def saved_finished(completed, message):
            if not completed and message and prompt(message):
                return
            if finished:
                finished(completed, "")

        self._background(lambda: self.workspace.unlock(record.id, cycle=cycle), finished=saved_finished)
        return True

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
        if self.workspace:
            self.set_agent_paused(not self.workspace.paused)

    def set_agent_paused(self, paused):
        if self.broker and self.broker.enabled and not self.desktop.locked:
            self.workspace.pause(paused)
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
        dialog = self.dialog
        while isinstance(dialog, Gtk.Dialog):
            parent = dialog.get_transient_for()
            dialog.response(Gtk.ResponseType.CANCEL)
            dialog = parent
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
        if self.window:
            Gtk.StyleContext.remove_provider_for_screen(self.window.get_screen(), self.style)
        GLib.source_remove(self.poll)
        GLib.source_remove(self.prune)
        Gtk.Application.do_shutdown(self)
