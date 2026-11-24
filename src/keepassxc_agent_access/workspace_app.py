"""The owner desktop and tray for the multi-vault workspace."""

from dataclasses import replace
import json
import os
from pathlib import Path
import pwd
import signal
from threading import Thread
from time import monotonic
import traceback
from uuid import uuid4

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, Gio, GLib, Gtk, Pango

from .access_settings import (GUEST_AUTO_APPROVAL_OPTIONS, REVIEW_ACTIONS, SCOPED_AUTO_APPROVAL_OPTIONS,
                              TOKEN_AUTO_APPROVAL_OPTIONS)
from .activity import ActivityError, ActivityStore
from .agent_connection import connection_socket, installed_connection
from .approvals import ApprovalQueue
from .broker import BrokerConfig, ListingBroker
from .desktop import DesktopSession
from .edit_requests import EditRequests
from .grants import Grants
from .installation import Installation
from .keyring import KeyringError, SystemKeyring
from .launcher import skill_destination
from .legacy_tray import ACTIVE_ICON as TRAY_ACTIVE_ICON, ICON_DIRECTORY as TRAY_ICON_DIRECTORY
from .legacy_tray import PAUSED_ICON as TRAY_PAUSED_ICON, LegacyTray
from .owner_views import _dialog, _label, _scroll, table_time
from .protocol import ListingError
from .review_popups import ReviewPopups
from .scoped_broker import ScopedBroker
from .settings import SettingsError, SettingsStore
from .tray import APP_ID, APP_TITLE, SetupDialog, password_entry
from .updates import UpdateError, check_for_update, start_update, update_result
from .vault import UnlockCancelled, VaultError
from .workspace import Workspace, ordered_groups
from .workspace_clipboard import PasswordClipboard
from .workspace_context import DELETE_LABEL, attach_row_context
from .workspace_editor import delete_entry, delete_group, edit_entry, edit_group
from .workspace_style import install_style, styled
from .workspace_views import (
    AccessView, ActivityView, add_label, button, empty_state, entry_details, fill_table, pane_table, section_heading,
)


OWNER_ERRORS = (ActivityError, KeyringError, ListingError, OSError, SettingsError, ValueError, VaultError)
ENTRY_FOLDER_COLUMN = 5
ENTRY_ID_COLUMN = 6


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
        self.start_unlocked = True
        self.usage_approvals = ApprovalQueue()
        self.broker = None
        self.window = None
        self.dialog = None
        self.indicator = None
        self.legacy_tray = None
        self.tray_connected = False
        self.message = ""
        self.exiting = False
        self.startup_failed = False
        self.busy = False
        self.desktop = None
        self.poll = None
        self.prune = None
        self.style = None
        self.selection = None
        self.tree_signature = None
        self.tree_open_vaults = set()
        self.entry_rows = {}
        self.password_clipboard = None
        self.review_popups = ReviewPopups(Path(self.directory) / "desktop-notifications.json")
        self.popup_source = None

    def do_startup(self):
        Gtk.Application.do_startup(self)
        if Gdk.Display.get_default() is None:
            self.startup_failed = True
            self.exiting = True
            self.quit()
            return
        self.hold()
        self.desktop = self.desktop_factory(self._desktop_lock, self._quit)
        try:
            self.review_popups.load()
        except SettingsError as error:
            self.message = str(error)
        self.activity = ActivityStore(Path(self.directory) / "activity.sqlite")
        try:
            self.workspace = Workspace(self.directory, self.keyring)
            previous = self.workspace.legacy_access.read()
            self.start_unlocked = previous.start_unlocked
            self.activity.recover(previous.retention_days)
            self.grants = Grants(self.workspace, self.activity)
            self.edit_requests = EditRequests(self.workspace, self.grants, self.activity)
            engine = ScopedBroker(self.workspace, self.grants, self.activity, edits=self.edit_requests,
                                  approvals=self.usage_approvals)
            fallback = BrokerConfig.from_environment() or installed_connection()
            self.broker = ListingBroker(previous.broker_config(fallback), lambda: engine, engine)
            if self.broker.config:
                self.broker.start()
        except OWNER_ERRORS as error:
            self.message = str(error) or "Could not initialize the workspace."
        if self.workspace and not self.desktop.locked:
            if self.start_unlocked:
                self._unlock_all(cleanup=True)
            elif self.workspace.pending:
                self._background(self.workspace.cleanup)
        self.poll = GLib.timeout_add(500, self._refresh)
        self.prune = GLib.timeout_add_seconds(3600, self._prune)
        for signum in (signal.SIGINT, signal.SIGTERM):
            GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signum, self._quit)

    def do_activate(self):
        if self.startup_failed:
            return
        if self.window:
            self._present()
            return
        try:
            self._build_window()
        except Exception:
            traceback.print_exc()
            self.startup_failed = True
            self._quit()
            return
        self._build_tray()
        self._refresh()
        if self.show_window or not self.workspace or not self.workspace.registrations:
            self._present()
        else:
            GLib.timeout_add(650, self._fallback)

    def _fallback(self):
        if self.legacy_tray and not self.tray_connected:
            return GLib.SOURCE_CONTINUE
        if not self.tray_connected:
            self._present()
        return GLib.SOURCE_REMOVE

    def _present(self, *_):
        if self.window and not self.exiting and (
            not self.desktop.locked or not getattr(self.desktop, "available", True)
        ):
            self.window.present()

    def _build_window(self):
        self.window = Gtk.ApplicationWindow(application=self, title=APP_TITLE)
        self.password_clipboard = PasswordClipboard(self.window.get_screen())
        self.window.set_default_size(1120, 700)
        self.window.connect("delete-event", self._window_closed)
        self.window.connect("key-press-event", self._keyboard)
        self.window.set_name("keeper-workspace")
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
        header.set_decoration_layout(":maximize,close")
        self.minimize_button = styled(Gtk.Button(valign=Gtk.Align.CENTER), "titlebutton", "minimize")
        self.minimize_button.set_image(
            Gtk.Image.new_from_icon_name("window-minimize-symbolic", Gtk.IconSize.MENU)
        )
        self.minimize_button.set_tooltip_text("Minimize")
        self.minimize_button.get_accessible().set_name("Minimize")
        self.minimize_button.connect("clicked", self._minimize)
        header.pack_end(self.minimize_button)
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
        self.add_vault_button = styled(Gtk.Button(), "keeper-control")
        self.add_vault_button.add(self._toolbar_content("Add Vault…", "list-add-symbolic"))
        self.add_vault_button.get_accessible().set_name("Add Vault…")
        self.add_vault_button.connect("clicked", lambda *_: self._configure())
        header.pack_start(self.add_vault_button)
        self.vault_lock_button = styled(Gtk.Button(), "keeper-control")
        self.vault_lock_labels = self._toolbar_labels(
            self.vault_lock_button, ("Lock All Vaults", "changes-prevent-symbolic"),
            ("Unlock All Vaults", "changes-allow-symbolic"),
        )
        self.vault_lock_button.connect("clicked", self._toggle_all_vaults)
        header.pack_start(self.vault_lock_button)
        self.settings_button = styled(Gtk.Button(), "keeper-control", "keeper-quiet")
        self.settings_button.set_tooltip_text("Keeper Settings")
        self.settings_button.get_accessible().set_name("Keeper Settings")
        self.settings_button.set_image(Gtk.Image.new_from_icon_name("open-menu-symbolic", Gtk.IconSize.BUTTON))
        self.settings_button.connect("clicked", self._show_settings)
        header.pack_end(self.settings_button)
        self.pause_button = styled(Gtk.Button(), "keeper-control", "keeper-paused")
        self.pause_labels = self._toolbar_labels(
            self.pause_button, ("Resume Agent Access", "changes-prevent-symbolic"),
            ("Pause Agent Access", "changes-allow-symbolic"),
        )
        self.pause_button.connect("clicked", self._toggle_pause)
        header.pack_end(self.pause_button)
        self.usage_button = styled(Gtk.ToggleButton(), "keeper-control")
        self.usage_labels = self._toolbar_labels(self.usage_button, ("Auto Approve: On",), ("Auto Approve: Off",))
        self._style_usage_policy()
        self.usage_button.connect("toggled", self._set_usage_policy)
        header.pack_end(self.usage_button)
        header.show_all()

    @classmethod
    def _toolbar_labels(cls, button, *states):
        stack = Gtk.Stack(hhomogeneous=True, vhomogeneous=True)
        for label, *icon in states:
            stack.add_named(cls._toolbar_content(label, *icon), label)
        stack.show_all()
        button.get_accessible().set_name(stack.get_visible_child_name())
        button.add(stack)
        return stack

    @staticmethod
    def _toolbar_content(label, icon_name=None):
        content = Gtk.Box(spacing=6, halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
        if icon_name:
            icon = Gtk.Image.new_from_icon_name(icon_name, Gtk.IconSize.BUTTON)
            icon.set_pixel_size(16)
            content.pack_start(icon, False, False, 0)
        content.pack_start(Gtk.Label(label=label), False, False, 0)
        return content

    @staticmethod
    def _show_toolbar_label(button, stack, label):
        stack.set_visible_child_name(label)
        button.get_accessible().set_name(label)

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
        header, self.browse_path, self.browse_title, self.browse_icon = section_heading("Vaults", "drive-harddisk-symbolic")
        self.browser.pack_start(header, False, False, 0)

        self.vault_tools = styled(Gtk.Box(spacing=6, valign=Gtk.Align.CENTER), "keeper-vault-tools")
        header.pack_end(self.vault_tools, False, False, 0)
        self.vault_buttons = {}
        for name, title, handler in (
            ("unlock", "Unlock", self._unlock),
            ("lock", "Lock Vault", self._lock_selected),
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
        self.entry_search = styled(Gtk.SearchEntry(placeholder_text="Filter Entries", width_chars=28,
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
        if event.state & Gdk.ModifierType.CONTROL_MASK and event.keyval == Gdk.KEY_q:
            self._quit()
            return True
        if (event.state & Gtk.accelerator_get_default_mod_mask() == Gdk.ModifierType.CONTROL_MASK
                and event.keyval in (Gdk.KEY_f, Gdk.KEY_F)
                and self.stack.get_visible_child_name() == "browse" and self.entry_search.get_visible()):
            self.entry_search.grab_focus()
            return True
        return False

    def _build_tray(self):
        if os.environ.get("DISPLAY"):
            try:
                self.legacy_tray = LegacyTray(
                    self._present, lambda: self._tray_status(None, True), self._on_legacy_tray_exit,
                )
                return
            except GLib.Error:
                pass
        self._build_appindicator()

    def _on_legacy_tray_exit(self):
        was_connected = self.tray_connected
        self.legacy_tray = None
        self.tray_connected = False
        if not self.exiting:
            self._build_appindicator()
            if was_connected:
                self._present()

    def _build_appindicator(self):
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
        # AppIndicator exports activation over the owner session bus.
        # Keep settings and authorization controls in the desktop window.
        show = Gtk.MenuItem(label=f"Open {APP_TITLE}")
        show.connect("activate", self._present)
        self.menu.append(show)
        self.menu.show_all()
        self.indicator.set_menu(self.menu)
        self.indicator.set_secondary_activate_target(show)
        self.indicator.connect("connection-changed", self._tray_status)
        self.indicator.set_status(AyatanaAppIndicator3.IndicatorStatus.ACTIVE)

    def _tray_status(self, _indicator, connected):
        self.tray_connected = connected
        if not connected:
            self._present()

    def _minimize(self, *_):
        if self.tray_connected:
            self.window.hide()
        else:
            self.window.iconify()

    def _window_closed(self, *_):
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
        if self.password_clipboard:
            self.password_clipboard.check()
        if self.window and not self.exiting:
            if self.workspace:
                self._refresh_tree()
            self._refresh_vault_lock()
            self._browse()
            notice = self.message
            if not getattr(self.desktop, "available", True):
                notice = "Desktop lock status is unavailable. Vaults stay locked until monitoring recovers."
            self.notice.set_text(notice)
            self.notice.set_visible(bool(notice))
            paused = not self.workspace or self.workspace.paused
            pause_label = "Resume Agent Access" if paused else "Pause Agent Access"
            if self.pause_labels.get_visible_child_name() != pause_label:
                self._show_toolbar_label(self.pause_button, self.pause_labels, pause_label)
                style = self.pause_button.get_style_context()
                style.add_class("keeper-paused" if paused else "keeper-live")
                style.remove_class("keeper-live" if paused else "keeper-paused")
            self.pause_button.set_sensitive(bool(self.broker and self.broker.enabled and not self.desktop.locked))
            self.usage_button.set_sensitive(bool(self.workspace and not self.desktop.locked))
            pending = self._review_requests()
            count = len(pending)
            access_label = f"Access ({count})" if count else "Access"
            self.access_button.set_label(access_label)
            if self.indicator:
                self.indicator.set_icon_full(
                    TRAY_PAUSED_ICON if paused else TRAY_ACTIVE_ICON,
                    "Agent access paused" if paused else "Agent access active",
                )
            if self.legacy_tray:
                self.legacy_tray.set_paused(paused)
            if self.stack.get_visible_child_name() == "access":
                self.access_view.refresh()
            elif self.stack.get_visible_child_name() == "activity":
                self.activity_view.refresh()
            self._schedule_request_popup(pending)
        return GLib.SOURCE_CONTINUE

    def _review_requests(self):
        grants = self.grants.rows() if self.grants else ()
        waiting = sorted(self.usage_approvals.pending(), key=lambda ticket: (ticket.expires, ticket.id))
        return (
            *(("usage", str(ticket.id)) for ticket in waiting),
            *(("grant", grant.id) for grant in grants if grant.status == "pending"),
            *(("grant-change", f"{grant.id}/{grant.change.id}") for grant in grants if grant.pending_change),
            *(("edit", f"{edit.token_id}/{edit.id}") for edit in self.pending_edits() if edit.status == "pending"),
        )

    def _style_usage_policy(self):
        review = bool(self.workspace and self.workspace.review_usage)
        self.usage_button.set_active(not review)
        self._show_toolbar_label(self.usage_button, self.usage_labels,
                                 "Auto Approve: Off" if review else "Auto Approve: On")
        self.usage_button.set_tooltip_text(
            "Ask for approval on each agent action" if review else "Auto approve enabled actions within token permissions"
        )
        style = self.usage_button.get_style_context()
        style.add_class("keeper-usage-review" if review else "keeper-usage-allow")
        style.remove_class("keeper-usage-allow" if review else "keeper-usage-review")

    def _set_usage_policy(self, item):
        review = not item.get_active()
        if not self.workspace or self.workspace.review_usage == review:
            return
        if self.desktop.locked:
            item.set_active(not self.workspace.review_usage)
            return
        try:
            self.workspace.set_review_usage(review)
            self.message = ""
        except OWNER_ERRORS as error:
            self.message = str(error) or "Could not save the Auto Approve setting."
            item.set_active(not self.workspace.review_usage)
        self._style_usage_policy()
        self._refresh()

    def _set_request_popups(self, item):
        enabled = item.get_active()
        if enabled == self.review_popups.enabled:
            return
        try:
            self.review_popups.set_enabled(enabled)
            self.message = ""
        except SettingsError as error:
            self.message = str(error)
            item.set_active(self.review_popups.enabled)
        self._refresh()

    def _can_open_request_popup(self):
        return (self.review_popups.enabled and not self.exiting and not self.desktop.locked
                and self.dialog is None and not self.busy)

    def _schedule_request_popup(self, pending):
        request = self.review_popups.next_request(pending)
        if request and self.popup_source is None and self._can_open_request_popup():
            self.popup_source = GLib.idle_add(self._open_request_popup, request)

    def _open_request_popup(self, request):
        self.popup_source = None
        if not self._can_open_request_popup() or request != self.review_popups.next_request(self._review_requests()):
            return GLib.SOURCE_REMOVE
        kind, identifier = request
        self.access_view.open_record(identifier, kind, automatic=True)
        return GLib.SOURCE_REMOVE

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
        create = [("New Entry…", self._new_entry)]
        if group:
            if not session:
                return []
            return self._actions_for(target, [
                create,
                [("Edit Group…", self._edit_group), ("Copy Group Reference", self._copy_group_reference)],
                [(DELETE_LABEL, self._delete_group)],
            ])
        create.append(("New Group…", self._new_group))
        if session:
            session_actions = [("Lock Vault", self._lock_selected)]
        else:
            session_actions = [("Unlock", self._unlock)]
        management = [("Rename Vault…", self._rename), ("Relink Vault…", lambda: self._configure(self._record()))]
        if record.item:
            management.append(("Forget Saved Password…", self._forget))
        if session:
            management.append(("Copy Root Group Reference", self._copy_group_reference))
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
            [("View Entry Details…", lambda: with_entry(lambda entry: entry_details(self, vault, entry))),
             ("Edit Entry…", lambda: with_entry(lambda entry: edit_entry(self, vault, group, entry))),
             ("Copy Password", lambda: with_entry(lambda _: self._copy_password(vault, identifier))),
             ("Copy Entry Reference", lambda: with_entry(lambda _: self.copy_reference(vault, "entry", identifier)))],
            [(DELETE_LABEL, lambda: with_entry(lambda entry: delete_entry(self, vault, group, entry)))],
        ])

    def _activity_context(self, row):
        identifier = row[self.activity_view.RECORD_ID]
        return [[("View Details…", lambda: self.activity_view.open_record(identifier))]]

    def _copy_password(self, vault, identifier):
        session = self.workspace.session(vault)
        if not session:
            return

        def is_current():
            return not self.exiting and not self.desktop.locked and self.workspace.session(vault) is session

        def copy(password):
            if not is_current():
                self.message = "The vault changed before the password could be copied."
            elif not password:
                self.message = "This entry has no password."
            elif self.password_clipboard.copy(password, is_current):
                self.message = "Password copied."
            else:
                self.message = "Could not copy the entry password."

        self._background(lambda: session.worker.owner_entry_password(identifier), after=copy)

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

    def run_dialog(self, dialog, *, standalone=False):
        if self.desktop.locked or self.exiting:
            dialog.destroy()
            return Gtk.ResponseType.CANCEL
        if standalone:
            dialog.set_transient_for(None)
            dialog.set_destroy_with_parent(False)
            dialog.set_position(Gtk.WindowPosition.CENTER)
        previous = self.dialog
        self.dialog = dialog
        dialog.show_all()
        if standalone:
            dialog.present()
        try:
            return dialog.run()
        finally:
            self.dialog = previous
            dialog.hide()
            # Let the caller read submitted controls before disposing of the dialog.
            GLib.idle_add(dialog.destroy)

    def confirm(self, title, detail, *, delete=False):
        buttons = Gtk.ButtonsType.NONE if delete else Gtk.ButtonsType.OK_CANCEL
        dialog = styled(Gtk.MessageDialog(transient_for=self.window, modal=True, text=title,
                                          secondary_text=detail, buttons=buttons), "keeper-dialog")
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
        dialog.set_title("Relink Vault" if record else "Add KeePass Vault")
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

    def unlock_review_button(self, record, dialog):
        controls = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        button = Gtk.Button(label=f"Unlock {record.name}…", halign=Gtk.Align.START)
        feedback = styled(_label(""), "keeper-notice")
        feedback.set_no_show_all(True)
        controls.pack_start(button, False, False, 0)
        controls.pack_start(feedback, False, False, 0)

        def reopen(completed, message):
            if self.dialog is not dialog or not dialog.get_visible():
                return
            if completed:
                dialog.response(Gtk.ResponseType.APPLY)
            elif message:
                feedback.set_text(message)
                feedback.show()

        def unlock(*_):
            feedback.hide()
            self.unlock_record(record, parent=dialog, finished=reopen)

        button.connect("clicked", unlock)
        return controls

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
            remember = Gtk.CheckButton(label="Remember in the OS Keyring", active=bool(record.item))
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

    def _any_vault_unlocked(self):
        return any(self.workspace.owner_session(identifier) for identifier in self.workspace.registrations) if self.workspace else False

    def _refresh_vault_lock(self):
        unlocked = self._any_vault_unlocked()
        label = "Lock All Vaults" if unlocked else "Unlock All Vaults"
        self._show_toolbar_label(self.vault_lock_button, self.vault_lock_labels, label)
        self.vault_lock_button.set_sensitive(bool(self.workspace and self.workspace.registrations
                                                  and not self.desktop.locked and (unlocked or not self.busy)))

    def _toggle_all_vaults(self, *_):
        if self._any_vault_unlocked():
            self._lock_all()
        else:
            self._unlock_all(prompt=True)

    def _unlock_all(self, *, prompt=False, cleanup=False):
        workspace = self.workspace
        if workspace is None or not workspace.registrations and not (cleanup and workspace.pending):
            return
        cycle = workspace.owner_generation
        records = tuple(record for record in workspace.registrations.values() if not workspace.owner_session(record.id))

        def unlock_saved():
            if cleanup and workspace.pending:
                workspace.cleanup()
            pending = []
            for record in records:
                if workspace.owner_generation != cycle:
                    raise UnlockCancelled
                if record.item:
                    try:
                        workspace.unlock(record.id, cycle=cycle)
                        continue
                    except OWNER_ERRORS:
                        pass
                pending.append(record)
            return pending

        def finish(pending):
            if workspace.owner_generation != cycle:
                return
            if prompt:
                unlock_next(iter(pending))
            elif pending:
                self.message = "Some vaults need a password before they can be unlocked."

        def unlock_next(pending):
            if workspace.owner_generation != cycle or self.desktop.locked or self.exiting:
                return
            for record in pending:
                if self.unlock_record(record, finished=lambda *_: unlock_next(pending)):
                    return

        self._background(unlock_saved, after=finish)

    def _lock_all(self, *_):
        if self.workspace:
            self.workspace.lock_all()
            self._refresh()

    def _rename(self, *_):
        record = self._record()
        if not record or self.desktop.locked:
            return
        dialog, body = _dialog(self, "Rename Vault", 410, 140)
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

    def _show_settings(self, *_):
        if self.workspace and not self.desktop.locked:
            self.run_dialog(self._settings_dialog())

    def _settings_dialog(self):
        dialog, body = _dialog(self, "Keeper Settings", 1080, 826, fit_monitor=True)
        dialog.set_name("keeper-settings")
        dialog.set_modal(True)
        body.set_border_width(0)
        body.set_spacing(0)
        # This window uses only the title-bar close button.
        action_box = dialog.get_action_area().get_parent()
        action_box.set_no_show_all(True)
        action_box.hide()
        panel = Gtk.Box()
        stack = Gtk.Stack(hexpand=True, vexpand=True, hhomogeneous=False, vhomogeneous=False, margin=20)
        stack.set_name("keeper-settings-pages")
        sidebar = styled(Gtk.StackSidebar(stack=stack), "keeper-settings-nav")
        sidebar.set_size_request(180, -1)
        panel.pack_start(sidebar, False, False, 0)
        divider = styled(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL), "keeper-settings-divider")
        panel.pack_start(divider, False, False, 0)
        panel.pack_start(stack, True, True, 0)
        body.pack_start(panel, True, True, 0)

        def page(name, title, icon):
            rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14, margin_end=6)
            heading = Gtk.Box(spacing=11)
            mark = Gtk.Image.new_from_icon_name(icon, Gtk.IconSize.LARGE_TOOLBAR)
            heading.pack_start(styled(mark, "keeper-settings-mark"), False, False, 0)
            heading.pack_start(styled(_label(title), "keeper-settings-title"), True, True, 0)
            rows.pack_start(heading, False, False, 0)
            scroll = Gtk.ScrolledWindow(overlay_scrolling=False)
            scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            scroll.add(rows)
            stack.add_titled(scroll, name, title)
            return rows

        approvals = page("auto-approve", "Auto Approve", "changes-prevent-symbolic")
        self._settings_switch(self._settings_card(approvals), "Request Pop-Ups", self.review_popups.enabled,
                              self._set_request_popups, "request-popups",
                              "Show a review dialog when an agent request needs your decision.")
        self._settings_switch(
            self._settings_card(approvals), "Enable Auto Approve", not self.workspace.review_usage,
            self._set_usage_policy, "auto-approve-usage",
            "Apply the automatic approval switches below.",
        )
        actions = self._settings_card(approvals)
        actions.set_spacing(7)
        actions.pack_start(styled(_label("Auto Approve These Requests"), "keeper-settings-caption"), False, False, 0)
        actions.pack_start(styled(_label("These switches apply to actions within approved permissions. Results - Read automatic approval starts off: enabling it trusts approved servers and the fields requested by agents."),
                                 "keeper-settings-description"), False, False, 0)
        for operation, caption in REVIEW_ACTIONS.items():
            actions.pack_start(Gtk.Separator(), False, False, 0)
            self._settings_switch(actions, caption, operation not in self.workspace.review_actions,
                                  lambda control, operation=operation: self._set_action_auto_approval(control, operation),
                                  operation,
                                  "Trust the approved endpoint and requested fields when releasing results."
                                  if operation == "read_results" else None)
        for operation, caption in GUEST_AUTO_APPROVAL_OPTIONS.items():
            actions.pack_start(Gtk.Separator(), False, False, 0)
            self._settings_switch(actions, caption, operation in self.workspace.auto_approve_guest_actions,
                                  lambda control, operation=operation: self._set_guest_auto_approval(control, operation),
                                  operation, "Allow another command at an endpoint you approved for a limited time."
                                  if operation == "guest_run" else
                                  "Allow an agent to reuse a connection you approved for a limited time.")
        scoped = self._settings_card(approvals)
        scoped.pack_start(styled(_label("Use Approved Access"), "keeper-settings-caption"), False, False, 0)
        scoped.pack_start(styled(_label("Requires Auto Approve, HTTPS Requests and Results - Read to be enabled."),
                                 "keeper-settings-description"), False, False, 0)
        for operation, (caption, description) in SCOPED_AUTO_APPROVAL_OPTIONS.items():
            scoped.pack_start(Gtk.Separator(), False, False, 0)
            self._settings_switch(scoped, caption, operation in self.workspace.auto_approve_scoped_actions,
                                  lambda control, operation=operation: self._set_scoped_auto_approval(control, operation),
                                  operation, description)
        self._token_auto_approval_settings(approvals)
        vaults = page("vaults", "Vaults", "drive-harddisk-symbolic")
        self._settings_switch(self._settings_card(vaults), "Start Unlocked", self.start_unlocked, self._set_start_unlocked,
                              "start-unlocked", "Use saved keyring passwords to unlock vaults when Keeper starts.")
        updates = page("updates", "Updates", "system-software-update-symbolic")
        self._updates_settings_page(self._settings_card(updates))
        connect = page("connect-agent", "Connect an Agent", "network-wired-symbolic")
        self._connect_agent_page(connect)
        broker = page("broker", "Broker Settings", "network-server-symbolic")
        self._broker_settings_page(self._settings_card(broker))
        stack.set_visible_child_name("auto-approve")
        return dialog

    def _connect_agent_page(self, page):
        def field(title, value, description):
            card = self._settings_card(page)
            card.pack_start(styled(_label(title), "keeper-settings-caption"), False, False, 0)
            card.pack_start(styled(_label(description), "keeper-settings-description"), False, False, 0)
            row = Gtk.Box(spacing=8)
            entry = Gtk.Entry(text=str(value), editable=False, hexpand=True)
            entry.get_accessible().set_name(title)
            row.pack_start(entry, True, True, 0)
            copy = Gtk.Button(label="Copy")
            copy.get_accessible().set_name(f"Copy {title}")
            copy.connect("clicked", lambda *_: Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(str(value), -1))
            row.pack_start(copy, False, False, 0)
            card.pack_start(row, False, False, 0)

        field("Keeper Skill", skill_destination(), "Give this file to your agent for instructions on using Keeper.")
        configured = installed_connection()
        if not configured or not connection_socket(os.getuid()).is_socket():
            card = self._settings_card(page)
            card.pack_start(styled(_label("Run ./install --connect-agent once to enable the local MCP connection."),
                                               "keeper-settings-description"), False, False, 0)
            return
        if not self.broker or self.broker.config != configured:
            card = self._settings_card(page)
            card.pack_start(styled(_label("The active broker differs from the installed connection. "
                                          "Check Broker Settings before connecting an agent."),
                                               "keeper-settings-description"), False, False, 0)
            return
        if not self.broker.enabled:
            card = self._settings_card(page)
            card.pack_start(styled(_label("The Keeper broker is unavailable. Check Broker Settings."),
                                               "keeper-settings-description"), False, False, 0)
            return
        field("MCP Command", Installation().app / "keeper-connect",
              "Add this command as a local standard input/output MCP server in your agent client.")
        if Installation().connection_update_needed():
            card = self._settings_card(page)
            card.pack_start(styled(_label("To update the local runner, run ./install --connect-agent from your "
                                          "trusted Keeper checkout."), "keeper-settings-description"), False, False, 0)
        if self.workspace.paused:
            card = self._settings_card(page)
            card.pack_start(styled(_label("Agent Access is paused. Resume it in Keeper when you are ready."),
                                               "keeper-settings-description"), False, False, 0)

    def _token_auto_approval_settings(self, page):
        card = self._settings_card(page)
        card.pack_start(styled(_label("Token Auto-Approval"), "keeper-settings-caption"), False, False, 0)
        suspended = styled(_label("Previous token settings are suspended until you acknowledge this warning "
                                  "and choose which switches to enable."), "keeper-settings-description")
        suspended.set_no_show_all(True)
        suspended.set_visible(not self.workspace.token_auto_approval_acknowledged
                              and (self.workspace.auto_approve_tokens or self.workspace.auto_approve_token_changes))

        revealer = Gtk.Revealer(transition_type=Gtk.RevealerTransitionType.NONE,
                                reveal_child=self.workspace.token_auto_approval_acknowledged)
        revealer.set_name("token-auto-approval-options")
        options = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
        options.pack_start(styled(_label("Danger"), "keeper-settings-caption", "keeper-settings-danger"),
                           False, False, 0)
        switches = {}
        for setting, caption in TOKEN_AUTO_APPROVAL_OPTIONS.items():
            options.pack_start(Gtk.Separator(), False, False, 0)
            switches[setting] = self._settings_switch(
                options, caption, getattr(self.workspace, setting),
                lambda control, setting=setting: self._set_token_auto_approval(control, setting),
                setting, danger=True,
            )
        revealer.add(options)

        def acknowledge(control):
            requested = control.get_active()
            if requested != self.workspace.token_auto_approval_acknowledged:
                self.owner_operation(lambda: self.workspace.acknowledge_token_auto_approval(requested))
            acknowledged = self.workspace.token_auto_approval_acknowledged
            control.set_active(acknowledged)
            for setting, switch in switches.items():
                switch.set_active(getattr(self.workspace, setting))
            revealer.set_reveal_child(acknowledged)
            suspended.set_visible(not acknowledged
                                  and (self.workspace.auto_approve_tokens or self.workspace.auto_approve_token_changes))

        self._settings_switch(
            card, "I Understand", self.workspace.token_auto_approval_acknowledged, acknowledge,
            "token-auto-approval-acknowledged",
            "These settings can automatically give agents access to more secrets or edits without individual "
            "review.\nThey apply only when the toolbar’s Auto Approve is on.", danger=True,
        )
        card.pack_start(suspended, False, False, 0)
        card.pack_start(revealer, False, False, 0)

    @staticmethod
    def _settings_card(page):
        card = styled(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=9), "keeper-settings-card")
        page.pack_start(card, False, False, 0)
        return card

    @staticmethod
    def _settings_switch(page, caption, enabled, changed, name, detail=None, *, danger=False):
        row = Gtk.Box(spacing=16)
        labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        title = _label(caption)
        if detail:
            styled(title, "keeper-settings-caption")
        if danger:
            styled(title, "keeper-settings-danger")
        labels.pack_start(title, False, False, 0)
        if detail:
            labels.pack_start(styled(_label(detail), "keeper-settings-description"), False, False, 0)
        toggle = Gtk.Switch(active=enabled, valign=Gtk.Align.CENTER)
        toggle.set_name(name)
        toggle.get_accessible().set_name(caption)
        toggle.connect("notify::active", lambda control, _: changed(control))
        row.pack_start(labels, True, True, 0)
        row.pack_end(toggle, False, False, 0)
        page.pack_start(row, False, False, 0)
        return toggle

    def _updates_settings_page(self, card):
        installation = Installation()
        _, previous_result = update_result(installation)
        status = styled(_label(previous_result or "Check the configured Git upstream for a newer Keeper version."),
                        "keeper-settings-description")
        card.pack_start(status, False, False, 0)
        controls = Gtk.Box(spacing=8)
        card.pack_start(controls, False, False, 0)
        candidate = None

        def run(operation, finished):
            def work():
                try:
                    result, error = operation(), None
                except UpdateError as failure:
                    result, error = None, str(failure)
                GLib.idle_add(deliver, result, error)

            def deliver(result, error):
                if card.get_parent() is not None:
                    finished(result, error)
                return GLib.SOURCE_REMOVE

            Thread(target=work, daemon=True).start()

        def checked(result, error):
            nonlocal candidate
            candidate = result
            check.set_sensitive(True)
            available = bool(result and result.target != result.installed)
            apply.set_sensitive(available)
            status.set_text(error or (f"Update available · {result.target[:12]}" if available
                                      else "Keeper is up to date."))

        def check_updates(*_):
            check.set_sensitive(False)
            apply.set_sensitive(False)
            status.set_text("Checking for updates…")
            run(lambda: check_for_update(installation), checked)

        def install_update(*_):
            if candidate is None or self.desktop.locked:
                return
            if self.busy:
                status.set_text("Wait for Keeper to finish its current task, then try again.")
                return
            check.set_sensitive(False)
            apply.set_sensitive(False)
            status.set_text("Applying update. Keeper will reopen when ready.")
            attempt = str(uuid4())
            deadline = monotonic() + 325

            def poll():
                if card.get_parent() is None:
                    return GLib.SOURCE_REMOVE
                identifier, message = update_result(installation)
                if identifier != attempt and monotonic() < deadline:
                    return GLib.SOURCE_CONTINUE
                status.set_text(message if identifier == attempt else "Update status is unavailable. Check again.")
                check.set_sensitive(True)
                return GLib.SOURCE_REMOVE

            def started(_, error):
                if error:
                    status.set_text(error)
                    check.set_sensitive(True)
                    apply.set_sensitive(True)
                else:
                    GLib.timeout_add_seconds(1, poll)

            run(lambda: start_update(candidate, attempt), started)

        check = Gtk.Button(label="Check for Updates")
        check.connect("clicked", check_updates)
        controls.pack_start(check, False, False, 0)
        apply = styled(Gtk.Button(label="Apply Update", sensitive=False), "keeper-settings-save")
        apply.connect("clicked", install_update)
        controls.pack_start(apply, False, False, 0)

    def _set_action_auto_approval(self, control, operation):
        previous = operation not in self.workspace.review_actions
        enabled = control.get_active()
        if enabled == previous:
            return
        try:
            self.workspace.set_review_action(operation, not enabled)
            self.message = ""
        except OWNER_ERRORS as error:
            self.message = str(error) or "Could not save the action’s auto approval setting."
            control.set_active(previous)
        self._refresh()

    def _set_guest_auto_approval(self, control, operation):
        previous = operation in self.workspace.auto_approve_guest_actions
        enabled = control.get_active()
        if enabled == previous:
            return
        try:
            self.workspace.set_guest_auto_approval(operation, enabled)
            self.message = ""
        except OWNER_ERRORS as error:
            self.message = str(error) or "Could not save the guest auto approval setting."
            control.set_active(previous)
        self._refresh()

    def _set_scoped_auto_approval(self, control, operation):
        self.owner_operation(lambda: self.workspace.set_scoped_auto_approval(operation, control.get_active()))
        control.set_active(operation in self.workspace.auto_approve_scoped_actions)

    def _set_token_auto_approval(self, control, setting):
        previous = getattr(self.workspace, setting)
        enabled = control.get_active()
        if enabled == previous:
            return
        self.owner_operation(lambda: self.workspace.set_token_auto_approval(setting, enabled))
        control.set_active(getattr(self.workspace, setting))

    def _set_start_unlocked(self, control):
        enabled = control.get_active()
        if enabled == self.start_unlocked:
            return
        try:
            store = self.workspace.legacy_access
            store.write(replace(store.read(), start_unlocked=enabled))
            self.start_unlocked = enabled
            self.message = ""
        except OWNER_ERRORS as error:
            self.message = str(error) or "Could not save the vault startup setting."
            control.set_active(self.start_unlocked)
        self._refresh()

    def _broker_settings_page(self, body):
        if not self.broker:
            add_label(body, "The broker is unavailable.")
            return
        config = self.broker.config
        endpoint = Gtk.Entry(text=str(config.path) if config else "")
        uid = Gtk.Entry(text=str(config.agent_uid) if config else "")
        retention = Gtk.SpinButton.new_with_range(1, 365, 1)
        retention.set_value(self.workspace.legacy_access.read().retention_days)
        for label, widget in (("Absolute Broker Socket Path", endpoint), ("Isolated Runner Account or UID", uid),
                              ("Activity Retention (Days)", retention)):
            body.pack_start(styled(_label(label), "keeper-settings-caption"), False, False, 0)
            body.pack_start(widget, False, False, 0)
        status = styled(_label(""), "keeper-settings-description")
        status.set_no_show_all(True)

        def save(*_):
            try:
                path, account = endpoint.get_text().strip(), uid.get_text().strip()
                if bool(path) != bool(account):
                    raise ValueError("Provide both the socket path and runner account, or clear both.")
                try:
                    peer = (int(account) if account.isdecimal() else pwd.getpwnam(account).pw_uid) if account else None
                except KeyError:
                    raise ValueError("The runner account could not be found.") from None
                store = self.workspace.legacy_access
                updated = replace(store.read(), endpoint=path or None, uid=peer, retention_days=retention.get_value_as_int())
                config = updated.broker_config()
                self.workspace.pause()
                self.broker.update(lambda: store.write(updated), config)
                if config:
                    self.broker.start()
                status.set_text("Broker settings saved.")
            except OWNER_ERRORS as error:
                status.set_text(str(error) or "Could not save the broker settings.")
            status.show()
            self._refresh()

        save_button = styled(Gtk.Button(label="Save Broker Settings", halign=Gtk.Align.START),
                             "keeper-settings-save")
        save_button.set_margin_top(5)
        save_button.connect("clicked", save)
        body.pack_start(save_button, False, False, 0)
        body.pack_start(status, False, False, 0)

    def _desktop_lock(self, *_):
        if self.password_clipboard:
            self.password_clipboard.clear()
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
                if self.edit_requests:
                    self.edit_requests.prune(self.workspace.legacy_access.read().retention_days)
            except (SettingsError, ActivityError):
                self.message = "Local activity cleanup is unavailable."
        return GLib.SOURCE_CONTINUE

    def _quit(self, *_):
        self.exiting = True
        self._desktop_lock()
        self.quit()
        return GLib.SOURCE_REMOVE

    def do_shutdown(self):
        if self.password_clipboard:
            self.password_clipboard.close()
        if self.legacy_tray:
            self.legacy_tray.close()
        if self.popup_source is not None:
            GLib.source_remove(self.popup_source)
            self.popup_source = None
        if self.broker:
            self.broker.stop()
        if self.workspace:
            self.workspace.lock_all()
        if self.desktop:
            self.desktop.close()
        if self.window and self.style:
            Gtk.StyleContext.remove_provider_for_screen(self.window.get_screen(), self.style)
        if self.poll is not None:
            GLib.source_remove(self.poll)
        if self.prune is not None:
            GLib.source_remove(self.prune)
        Gtk.Application.do_shutdown(self)
