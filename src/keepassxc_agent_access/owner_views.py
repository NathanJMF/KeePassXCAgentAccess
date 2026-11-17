"""Owner-only GTK settings, approvals, and activity views."""

from dataclasses import replace
from datetime import datetime
import pwd
from threading import Thread

from gi.repository import Gdk, GLib, Gtk

from .access_settings import AccessMode, Action
from .activity import ActivityError
from .protocol import ListingError, decode
from .settings import SettingsError
from .workspace_style import styled


def _label(text):
    return Gtk.Label(label=text, xalign=0, wrap=True, selectable=True)


def _scroll(widget):
    scroll = Gtk.ScrolledWindow()
    scroll.set_shadow_type(Gtk.ShadowType.IN)
    scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    scroll.add(widget)
    return scroll


def _text_area(text):
    view = Gtk.TextView(editable=False, cursor_visible=False, wrap_mode=Gtk.WrapMode.WORD_CHAR)
    view.get_buffer().set_text(text)
    return _scroll(view)


def _table(model, titles):
    table = Gtk.TreeView(model=model)
    for index, title in enumerate(titles):
        table.append_column(Gtk.TreeViewColumn(title, Gtk.CellRendererText(), text=index))
    return table


def _dialog(app, title, width=680, height=460, *, fit_monitor=False):
    if fit_monitor and (window := app.window.get_window()):
        if monitor := window.get_display().get_monitor_at_window(window):
            workarea = monitor.get_workarea()
            # Leave room for the dialog title bar and the desktop shell.
            width = min(width, max(1, workarea.width - 48))
            height = min(height, max(1, workarea.height - 80))
    dialog = styled(Gtk.Dialog(title=title, transient_for=app.window, destroy_with_parent=True), "keeper-dialog")
    dialog.set_default_size(width, height)
    content = dialog.get_content_area()
    content.set_border_width(14)
    content.set_spacing(10)
    return dialog, content


def mouse_click():
    event = Gtk.get_current_event()
    if event is None or event.type != Gdk.EventType.BUTTON_RELEASE:
        return False
    is_button, button = event.get_button()
    if not is_button or button != Gdk.BUTTON_PRIMARY:
        return False
    device = event.get_source_device()
    return device is not None and device.get_source() in (
        Gdk.InputSource.MOUSE, Gdk.InputSource.TOUCHPAD, Gdk.InputSource.TRACKPOINT,
    )


def require_mouse_decisions(dialog):
    decisions = (Gtk.ResponseType.ACCEPT, Gtk.ResponseType.REJECT)
    for decision in decisions:
        dialog.get_widget_for_response(decision).set_can_focus(False)

    def reject_non_mouse_response(widget, response):
        if response in decisions and not mouse_click():
            widget.stop_emission_by_name("response")

    dialog.connect("response", reject_non_mouse_response)


class ApprovalPresenter:
    def __init__(self, app, queue):
        self.app = app
        self.queue = queue
        self.dialog = None
        self.identifier = None

    def close(self):
        if self.dialog is not None:
            dialog, self.dialog = self.dialog, None
            self.identifier = None
            dialog.destroy()

    def poll(self):
        if self.app.exiting or self.app.desktop.locked:
            self.close()
            return GLib.SOURCE_CONTINUE
        pending = self.queue.pending()
        if self.identifier is not None and not any(item.id == self.identifier for item in pending):
            self.close()
        if self.dialog is None and pending:
            self._show(pending[0])
        return GLib.SOURCE_CONTINUE

    def _show(self, request):
        dialog, content = _dialog(self.app, "Agent request", 560, 350)
        self.dialog, self.identifier = dialog, request.id
        approve_label = "Approve and Trust Certificate" if request.trusts_certificate else "Approve once"
        dialog.add_buttons("Decline", Gtk.ResponseType.REJECT, approve_label, Gtk.ResponseType.ACCEPT)
        dialog.set_default_response(Gtk.ResponseType.REJECT)
        lines = [request.action, f"Agent OS UID {request.uid}"]
        if request.destination:
            lines.append("GET " + request.destination)
        if request.context.model:
            lines.append("Model · " + request.context.model + " (agent-reported)")
        if request.context.chat:
            lines.append("Chat · " + request.context.chat + " (agent-reported)")
        content.pack_start(_label("\n".join(lines)), False, False, 0)
        content.pack_start(_text_area("\n".join(request.scope) or "No entries"), True, True, 0)

        def answer(_dialog, response):
            self.queue.resolve(request.id, response == Gtk.ResponseType.ACCEPT)
            self.close()

        def dismiss(*_):
            answer(dialog, Gtk.ResponseType.REJECT)
            return True

        dialog.connect("response", answer)
        dialog.connect("delete-event", dismiss)
        dialog.show_all()
        dialog.present()


class OwnerViews:
    def __init__(self, app):
        self.app = app
        self.dialog = None

    def close(self):
        if self.dialog is not None:
            dialog, self.dialog = self.dialog, None
            dialog.destroy()

    def _open(self, title, width=680, height=460):
        self.close()
        dialog, content = _dialog(self.app, title, width, height)
        self.dialog = dialog
        dialog.connect("delete-event", self._delete)
        return dialog, content

    def _delete(self, *_):
        self.close()
        return True

    def _settings(self):
        return self.app.access_store.read()

    def _save(self, edited):
        self.app.save_access_settings(edited)

    def _load_entries(self, session, dialog, status, use_rows):
        if session is None:
            status.set_text("Unlock the vault to view entries.")
            return

        def apply(rows, message):
            if self.dialog is dialog and self.app.setup.controller.current_session() is session:
                status.set_text(message)
                use_rows(rows)
            return GLib.SOURCE_REMOVE

        def work():
            try:
                listing = decode(session.list_entries())
                if "entries" not in listing:
                    raise ValueError
                rows = sorted(listing["entries"], key=lambda row: (row["group_path"], row["title"]))
                GLib.idle_add(apply, rows, "")
            except (ListingError, ValueError):
                GLib.idle_add(apply, [], "Entries are unavailable.")

        status.set_text("Loading entries…")
        Thread(target=work, daemon=True).start()

    def access(self):
        settings = self._settings()
        session = self.app.setup.controller.current_session()
        original = settings.for_vault(session.identity) if session else None
        dialog, content = self._open("Access")
        dialog.add_buttons("Close", Gtk.ResponseType.CLOSE, "Save", Gtk.ResponseType.APPLY)
        form = Gtk.Grid(column_spacing=10, row_spacing=8)
        content.pack_start(form, False, False, 0)

        mode = Gtk.ComboBoxText()
        mode.set_name("access-mode")
        for item in AccessMode:
            mode.append(item.value, item.value)
        mode.set_active_id(settings.mode.value)
        config = self.app.broker.config
        endpoint = Gtk.Entry(text=str(config.path) if config else "")
        account = Gtk.Entry(text=str(config.agent_uid) if config else "")
        days = Gtk.SpinButton.new_with_range(1, 365, 1)
        days.set_value(settings.retention_days)
        for index, (text, widget) in enumerate((
            ("Access mode", mode), ("Broker socket path", endpoint),
            ("Agent account or UID", account), ("Activity retention (days)", days),
        )):
            form.attach(_label(text), 0, index, 1, 1)
            widget.set_hexpand(True)
            form.attach(widget, 1, index, 1, 1)

        status = _label("")
        content.pack_start(status, False, False, 0)
        model = Gtk.ListStore(bool, str, str)
        table = Gtk.TreeView(model=model)
        table.set_name("entry-review")
        toggle = Gtk.CellRendererToggle()
        toggle.connect("toggled", lambda _cell, path: model.set_value(
            model.get_iter(path), 0, not model[path][0]))
        table.append_column(Gtk.TreeViewColumn("Require approval", toggle, active=0))
        table.append_column(Gtk.TreeViewColumn("Entry", Gtk.CellRendererText(), text=1))
        content.pack_start(_scroll(table), True, True, 0)

        def receive(rows):
            for row in rows:
                model.append([row["id"] not in original.automatic, _entry_name(row), row["id"]])

        def save(_dialog, response):
            if response != Gtk.ResponseType.APPLY:
                self.close()
                return
            try:
                name, path = account.get_text().strip(), endpoint.get_text().strip()
                if bool(name) != bool(path):
                    raise ValueError("Enter both a socket path and an agent account.")
                uid = (int(name) if name.isascii() and name.isdecimal() else pwd.getpwnam(name).pw_uid) if name else None
                vaults = dict(settings.vaults)
                if session is not None and len(model):
                    if self.app.setup.controller.current_session() is not session:
                        raise ValueError("Unlock the vault again to edit entry flags.")
                    automatic = set(original.automatic)
                    for approval, _title, identifier in model:
                        automatic.discard(identifier) if approval else automatic.add(identifier)
                    vaults[session.identity] = replace(original, automatic=frozenset(automatic))
                self._save(replace(settings, mode=AccessMode(mode.get_active_id()),
                                   endpoint=path or None, uid=uid, retention_days=days.get_value_as_int(),
                                   vaults=tuple(vaults.items())))
                self.close()
            except KeyError:
                status.set_text("The agent account does not exist.")
            except (SettingsError, ValueError, ListingError, OSError) as error:
                status.set_text(str(error) if isinstance(error, (SettingsError, ValueError)) else
                                "The broker socket path or account is unavailable.")

        dialog.connect("response", save)
        dialog.show_all()
        self._load_entries(session, dialog, status, receive)

    def actions(self):
        settings = self._settings()
        session = self.app.setup.controller.current_session()
        dialog, content = self._open("Actions")
        dialog.add_button("Close", Gtk.ResponseType.CLOSE)
        dialog.connect("response", lambda *_: self.close())
        status = _label("")
        content.pack_start(status, False, False, 0)
        policy = settings.for_vault(session.identity) if session else None
        if policy is None:
            status.set_text("Unlock the vault to manage actions.")
            dialog.show_all()
            return

        items = {item.id: item for item in policy.actions}
        existing = Gtk.ComboBoxText()
        existing.set_name("configured-actions")
        existing.append("", "New action")
        for item in items.values():
            existing.append(item.id, item.name)
        form = Gtk.Grid(column_spacing=10, row_spacing=8)
        content.pack_start(form, False, False, 0)
        identifier, name, url = (Gtk.Entry() for _ in range(3))
        entry = Gtk.ComboBoxText()
        for widget, name_id in ((identifier, "action-id"), (name, "action-name"),
                                (url, "action-url"), (entry, "action-entry")):
            widget.set_name(name_id)
        enabled = Gtk.CheckButton(label="Enabled", active=True)
        for index, (title, widget) in enumerate((
            ("Action", existing), ("Action ID", identifier), ("Display name", name),
            ("Entry", entry), ("HTTPS URL", url), ("", enabled),
        )):
            form.attach(_label(title), 0, index, 1, 1)
            widget.set_hexpand(True)
            form.attach(widget, 1, index, 1, 1)
        controls = Gtk.Box(spacing=8)
        content.pack_start(controls, False, False, 0)
        save = Gtk.Button(label="Save action")
        remove = Gtk.Button(label="Remove action")
        controls.pack_start(save, False, False, 0)
        controls.pack_start(remove, False, False, 0)

        def select(*_):
            action = items.get(existing.get_active_id())
            identifier.set_text(action.id if action else "")
            identifier.set_sensitive(action is None)
            name.set_text(action.name if action else "")
            url.set_text(action.url if action else "")
            entry.set_active_id(action.entry) if action else entry.set_active(-1)
            enabled.set_active(action.enabled if action else True)
            remove.set_sensitive(action is not None)

        def commit(_button, deleting=False):
            try:
                if self.app.setup.controller.current_session() is not session:
                    raise ValueError("Unlock the vault again to edit actions.")
                update = dict(items)
                if deleting:
                    update.pop(existing.get_active_id(), None)
                else:
                    if not entry.get_active_id():
                        raise ValueError("Select a KeePass entry.")
                    action = Action(identifier.get_text().strip(), name.get_text().strip(),
                                    entry.get_active_id(), url.get_text().strip(), enabled.get_active())
                    if existing.get_active_id() == "" and action.id in update:
                        raise ValueError("That action ID is already in use.")
                    update[action.id] = action
                vaults = dict(settings.vaults)
                vaults[session.identity] = replace(policy, actions=tuple(update.values()))
                self._save(replace(settings, vaults=tuple(vaults.items())))
                self.actions()
            except (SettingsError, ListingError, OSError, ValueError) as error:
                status.set_text(str(error) if isinstance(error, (SettingsError, ValueError))
                                else "The action could not be saved.")

        existing.connect("changed", select)
        existing.set_active_id("")
        save.connect("clicked", commit)
        remove.connect("clicked", commit, True)

        def receive(rows):
            for row in rows:
                entry.append(row["id"], _entry_name(row))
            selected = items.get(existing.get_active_id())
            if selected:
                entry.set_active_id(selected.entry)

        dialog.show_all()
        self._load_entries(session, dialog, status, receive)

    def activity(self):
        dialog, content = self._open("Activity", 850, 470)
        dialog.add_button("Close", Gtk.ResponseType.CLOSE)
        dialog.connect("response", lambda *_: self.close())
        filters = Gtk.Box(spacing=8)
        controls = []
        for key in ("Model", "Chat", "Action", "Outcome"):
            control = Gtk.Entry(placeholder_text=key)
            controls.append(control)
            filters.pack_start(control, True, True, 0)
        refresh = Gtk.Button(label="Refresh")
        filters.pack_start(refresh, False, False, 0)
        content.pack_start(filters, False, False, 0)
        model = Gtk.ListStore(str, str, str, str, str, object)
        table = _table(model, ["Time", "Model", "Chat", "Action", "Outcome"])
        content.pack_start(_scroll(table), True, True, 0)
        detail = _label("")
        content.pack_start(detail, False, False, 0)

        def reload(*_):
            try:
                rows = self.app.activity_store.rows(**{
                    key: control.get_text() for key, control in
                    zip(("model", "chat", "action", "outcome"), controls)
                })
                model.clear()
                for row in rows:
                    model.append([table_time(row["requested"]), row["model"] or "Unavailable",
                                  row["chat"] or "Unavailable", row["action"], row["outcome"], row])
                detail.set_text("" if rows else "No matching activity.")
            except ActivityError:
                detail.set_text("Local activity could not be read.")

        def show(selection):
            selected_model, iterator = selection.get_selected()
            if iterator is None:
                return
            row = selected_model[iterator][5]
            lines = [
                f'Agent OS UID {row["uid"]}',
                'Model and chat · Agent-reported when present',
                f'Authorization · {row["decision"] or "None recorded"}',
                f'Requested · {_time(row["requested"])}',
                f'Decided · {_time(row["decided"])}',
                f'Completed · {_time(row["completed"])}',
            ]
            if row["destination"]:
                lines.append("Destination · " + row["destination"])
            if row["entry"]:
                lines.append("Entry UUID · " + row["entry"])
            if row["status"] is not None:
                lines.append(f'HTTP status · {row["status"]}')
            detail.set_text("\n".join(lines))

        table.get_selection().connect("changed", show)
        refresh.connect("clicked", reload)
        for control in controls:
            control.connect("changed", reload)
        reload()
        dialog.show_all()


def _entry_name(row):
    return " / ".join([*row["group_path"], row["title"]])


def table_time(timestamp):
    if timestamp is None:
        return "—"
    return datetime.fromtimestamp(timestamp).strftime("%H:%M · %d-%m-%y")


def _time(timestamp):
    return datetime.fromtimestamp(timestamp).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z") if timestamp is not None else "—"
