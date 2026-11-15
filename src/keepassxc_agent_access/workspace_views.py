"""GTK views for request review, entry actions, and local activity."""

from gi.repository import Gtk

from .access_settings import Action
from .activity import ActivityError
from .owner_views import _dialog, _label, _scroll, _table, _time


def reported(value):
    return f"{value} (reported)" if value else "—"


def add_label(container, text):
    container.pack_start(_label(text), False, False, 0)


def button(container, label, callback):
    widget = Gtk.Button(label=label)
    widget.connect("clicked", callback)
    container.pack_start(widget, False, False, 0)
    return widget


def selected_key(table, column):
    model, row = table.get_selection().get_selected()
    return model[row][column] if row else None


def fill_table(table, rows, key_column):
    selected = selected_key(table, key_column)
    model = table.get_model()
    if list(map(tuple, model)) == rows:
        return
    model.clear()
    for values in rows:
        row = model.append(values)
        if values[key_column] == selected:
            table.get_selection().select_iter(row)


class AccessView(Gtk.Box):
    TITLES = ("Requested", "Identity", "Project", "Status", "Last used")

    def __init__(self, app):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.app = app
        add_label(self, "Agent access")
        self.table = _table(Gtk.ListStore(*([str] * 6)), self.TITLES)
        self.table.connect("row-activated", self._open)
        self.pack_start(_scroll(self.table), True, True, 0)
        button(self, "Review or manage selected token", self._open)

    def refresh(self):
        rows = self.app.grants.rows() if self.app.grants else []
        fill_table(self.table, [(_time(row.requested), reported(row.identity), reported(row.project),
                                 row.status.capitalize(), _time(row.last_used), row.id) for row in rows], 5)

    def _open(self, *_):
        identifier = selected_key(self.table, 5)
        if not identifier or self.app.desktop.locked:
            return
        grant = self.app.grants.records[identifier]
        if grant.status == "pending":
            self._review(grant)
        else:
            self._manage(grant)

    def _header(self, title, grant):
        dialog, body = _dialog(self.app, title, 640, 430)
        dialog.set_modal(True)
        for value in (f"Requested  {_time(grant.requested)}", f"OS identity  UID {grant.uid} (verified)",
                      f"Identity  {reported(grant.identity)}", f"Project  {reported(grant.project)}",
                      f"Token record  {grant.id}"):
            add_label(body, value)
        return dialog, body

    def _review(self, grant):
        dialog, body = self._header("Review access request", grant)
        dialog.add_buttons("Close", Gtk.ResponseType.CLOSE, "Deny", Gtk.ResponseType.REJECT,
                           "Approve", Gtk.ResponseType.ACCEPT)
        items = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin=10)
        body.pack_start(_scroll(items), True, True, 0)
        controls = []

        def changed(*_):
            dialog.set_response_sensitive(Gtk.ResponseType.ACCEPT,
                                          bool(controls) and all(combo.get_active() >= 0 for combo, _ in controls))

        for item in grant.items:
            operations = ["Entry metadata"] if item.metadata else []
            if item.action:
                operations.append(f"HTTPS Basic-auth GET · {item.action}")
            selector = item.label or f"{item.vault} / {item.entry}"
            add_label(items, f"{selector}\nRequested operations  {', '.join(operations)}")
            choices = self.app.grants.choices(item)
            combo = Gtk.ComboBoxText()
            for choice in choices:
                combo.append_text(f"{choice.vault_name} · {' / '.join(choice.path)} [{choice.scope.entry}]")
            detail = _label("")
            items.pack_start(combo, False, False, 0)
            items.pack_start(detail, False, False, 0)
            controls.append((combo, choices))

            def show_choice(widget, options=choices, label=detail):
                index = widget.get_active()
                if index < 0:
                    label.set_text("Select the exact match." if options else "No eligible match in the unlocked vaults.")
                else:
                    choice = options[index]
                    vault = self.app.workspace.registrations.get(choice.scope.vault)
                    source = f"\nDatabase  {vault.target.database}" if vault else ""
                    label.set_text(f"Vault  {choice.scope.vault}{source}\nEntry  {choice.scope.entry}" +
                                   (f"\nGET  {choice.destination}" if choice.destination else ""))
                changed()

            combo.connect("changed", show_choice)
            if len(choices) == 1:
                combo.set_active(0)
            else:
                show_choice(combo)
        changed()
        response = self.app.run_dialog(dialog)
        if response in (Gtk.ResponseType.REJECT, Gtk.ResponseType.ACCEPT):
            self.app.owner_operation(lambda: self.app.grants.decide(
                grant.id, [options[combo.get_active()] for combo, options in controls]
                if response == Gtk.ResponseType.ACCEPT else None,
            ))

    def _manage(self, grant):
        dialog, body = self._header("Manage access token", grant)
        dialog.add_buttons("Close", Gtk.ResponseType.CLOSE, "Remove", Gtk.ResponseType.REJECT)
        if grant.status == "active":
            dialog.add_button("Disable", Gtk.ResponseType.APPLY)
        elif grant.status == "disabled":
            dialog.add_button("Re-enable", Gtk.ResponseType.APPLY)
        add_label(body, f"{grant.status.capitalize()} · Last used  {_time(grant.last_used)}")
        scope_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8, margin=8)
        body.pack_start(_scroll(scope_box), True, True, 0)
        for scope in grant.scope:
            record = self.app.workspace.registrations.get(scope.vault)
            session = self.app.workspace.session(scope.vault)
            entry = next((row for row in session.entries if row["id"] == scope.entry), None) if session else None
            title = " / ".join([*entry["group_path"], entry["title"]]) if entry else scope.entry
            operations = ["Entry metadata"] if scope.metadata else []
            if scope.action:
                binding = record.binding(scope.entry, scope.action) if record else None
                current = binding and binding.revision == scope.revision and binding.action.enabled
                operations.append(f"{scope.action} · {binding.action.url if current else 'Unavailable binding'}")
            add_label(scope_box, f"{record.name if record else 'Removed vault'} · {title}\n" +
                      f"{', '.join(operations)}\n{scope.vault} / {scope.entry}")
        response = self.app.run_dialog(dialog)
        if response == Gtk.ResponseType.REJECT:
            if self.app.confirm("Remove this token?", "The runner will need a fresh request and approval."):
                self.app.owner_operation(lambda: self.app.grants.transition(grant.id, "removed"))
        elif response == Gtk.ResponseType.APPLY:
            status = "disabled" if grant.status == "active" else "active"
            self.app.owner_operation(lambda: self.app.grants.transition(grant.id, status))


class ActivityView(Gtk.Box):
    TITLES = ("Time", "Model", "Chat", "Action", "Outcome")

    def __init__(self, app):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.app = app
        self.rows = {}
        filters = Gtk.Grid(column_spacing=8, row_spacing=6)
        self.filters = {}
        for index, name in enumerate(("Vault", "Agent", "Model", "Chat", "Action", "Outcome")):
            field = Gtk.SearchEntry(placeholder_text=name, hexpand=True)
            field.connect("search-changed", self.refresh)
            filters.attach(field, index % 3, index // 3, 1, 1)
            self.filters[name.lower()] = field
        self.pack_start(filters, False, False, 0)
        self.table = _table(Gtk.ListStore(str, str, str, str, str, str), self.TITLES)
        self.table.connect("row-activated", self._details)
        self.pack_start(_scroll(self.table), True, True, 0)

    def refresh(self, *_):
        try:
            rows = self.app.activity.rows(**{name: field.get_text() for name, field in self.filters.items()})
        except ActivityError:
            rows = []
        self.rows = {str(row["id"]): row for row in rows}
        fill_table(self.table, [(_time(row["requested"]), reported(row["model"]), reported(row["chat"]),
                                 row["action"], row["outcome"], str(row["id"])) for row in rows], 5)

    def _details(self, *_):
        row = self.rows.get(selected_key(self.table, 5))
        if not row or self.app.desktop.locked:
            return
        dialog, body = _dialog(self.app, "Activity details", 660, 460)
        dialog.add_button("Close", Gtk.ResponseType.CLOSE)
        details = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, margin=8)
        body.pack_start(_scroll(details), True, True, 0)
        for title, value in (
            ("Action", row["action"]), ("Outcome", row["outcome"]), ("OS UID (verified)", row["uid"]),
            ("Model", reported(row["model"])), ("Chat", reported(row["chat"])), ("Chat ID", reported(row["chat_id"])),
            ("Agent", reported(row["agent"])), ("Project", reported(row["project"])),
            ("Vault", row["vault"]), ("Vault ID", row["vault_id"]), ("Token record", row["token"]),
            ("Entry", row["entry"]), ("Destination", row["destination"]), ("Requested", _time(row["requested"])),
            ("Authorization", row["decision"]), ("Decided", _time(row["decided"])),
            ("Completed", _time(row["completed"])), ("HTTP status", row["status"]), ("Scope", row["scope"]),
        ):
            add_label(details, f"{title}  {value if value is not None else '—'}")
        self.app.run_dialog(dialog)


def entry_details(app, vault, entry):
    while app.workspace.session(vault) and not app.desktop.locked:
        record = app.workspace.registrations[vault]
        dialog, body = _dialog(app, entry["title"] or "(Untitled entry)", 650, 390)
        dialog.set_modal(True)
        dialog.add_buttons("Close", Gtk.ResponseType.CLOSE, "Add action", Gtk.ResponseType.APPLY,
                           "Edit action", Gtk.ResponseType.ACCEPT, "Remove action", Gtk.ResponseType.REJECT)
        add_label(body, f"{record.name} · {' / '.join(entry['group_path']) or 'Root'}\nEntry  {entry['id']}")
        add_label(body, f"Username  {entry['username'] or '—'}\nURL  {entry['url'] or '—'}")
        add_label(body, "Credential actions · HTTPS Basic-auth GET")
        store = Gtk.ListStore(str, str, str, str)
        for binding in record.bindings:
            action = binding.action
            if action.entry == entry["id"]:
                store.append((action.id, action.name, action.url, "Enabled" if action.enabled else "Disabled"))
        table = _table(store, ("ID", "Name", "Destination", "Status"))
        body.pack_start(_scroll(table), True, True, 0)
        for code in (Gtk.ResponseType.ACCEPT, Gtk.ResponseType.REJECT):
            dialog.set_response_sensitive(code, False)

        def selection(*_):
            for code in (Gtk.ResponseType.ACCEPT, Gtk.ResponseType.REJECT):
                dialog.set_response_sensitive(code, selected_key(table, 0) is not None)

        table.get_selection().connect("changed", selection)
        table.connect("row-activated", lambda *_: dialog.response(Gtk.ResponseType.ACCEPT))
        response = app.run_dialog(dialog)
        identifier = selected_key(table, 0)
        if response == Gtk.ResponseType.REJECT and identifier:
            if app.confirm("Remove this action?", "Existing tokens will lose permission to run this binding."):
                app.owner_operation(lambda: app.workspace.remove_binding(vault, entry["id"], identifier))
        elif response in (Gtk.ResponseType.ACCEPT, Gtk.ResponseType.APPLY):
            previous = record.binding(entry["id"], identifier) if response == Gtk.ResponseType.ACCEPT else None
            edit_binding(app, vault, entry["id"], previous)
        else:
            return


def edit_binding(app, vault, entry, previous):
    dialog, body = _dialog(app, "HTTPS Basic-auth GET", 560, 250)
    dialog.set_modal(True)
    dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Save", Gtk.ResponseType.OK)
    fields = []
    for title, default in (("Action ID", "health-check"), ("Name", "Health check"), ("Destination", "")):
        add_label(body, title)
        field = Gtk.Entry(text=default)
        body.pack_start(field, False, False, 0)
        fields.append(field)
    enabled = Gtk.CheckButton(label="Enabled", active=True)
    body.pack_start(enabled, False, False, 0)
    if previous:
        action = previous.action
        for field, value in zip(fields, (action.id, action.name, action.url)):
            field.set_text(value)
        enabled.set_active(action.enabled)
    response = app.run_dialog(dialog)
    if response == Gtk.ResponseType.OK:
        def save():
            identifier, name, url = (field.get_text() for field in fields)
            action = Action(identifier, name, entry, url, enabled.get_active())
            app.workspace.save_binding(vault, action, previous.action.id if previous else None)
        app.owner_operation(save)
