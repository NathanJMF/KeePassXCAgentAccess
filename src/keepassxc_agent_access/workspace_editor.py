"""Owner dialogs for editing entries and groups inside one unlocked vault."""

from gi.repository import Gtk

from .owner_views import _dialog
from .tray import password_entry


def _form(app, title):
    dialog, content = _dialog(app, title, 500, 250)
    dialog.set_modal(True)
    dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Save", Gtk.ResponseType.OK)
    dialog.get_widget_for_response(Gtk.ResponseType.OK).get_style_context().add_class("suggested-action")
    dialog.set_default_response(Gtk.ResponseType.OK)
    fields = Gtk.Grid(row_spacing=12, column_spacing=14)
    content.pack_start(fields, True, True, 0)
    return dialog, fields


def _require_name(dialog, field):
    def validate(*_):
        dialog.set_response_sensitive(Gtk.ResponseType.OK, bool(field.get_text().strip()))
    field.connect("changed", validate)
    validate()


def _field(grid, row, label, widget):
    caption = Gtk.Label(label=label, xalign=0, mnemonic_widget=widget, use_underline=True)
    widget.set_hexpand(True)
    grid.attach(caption, 0, row, 1, 1)
    grid.attach(widget, 1, row, 1, 1)
    return widget


def _locations(app, vault, current, moving_group=None):
    """Return the root and a chooser whose destinations stay inside this vault."""
    session = app.workspace.owner_session(vault)
    names = {group["id"]: group for group in session.groups}
    root, = (group["id"] for group in session.groups if group["parent"] is None)
    options = [(app.workspace.registrations[vault].name, root)]
    for identifier, group in names.items():
        if identifier in (root, moving_group):
            continue
        path = [group["name"] or "(Untitled group)"]
        parent = group["parent"]
        while parent in names and parent not in (root, moving_group):
            ancestor = names[parent]
            path.append(ancestor["name"] or "(Untitled group)")
            parent = ancestor["parent"]
        if parent == root:
            options.append((" / ".join(reversed(path)), identifier))
    combo = Gtk.ComboBoxText()
    combo.set_name("group-location")
    combo.append(root, options[0][0])
    for name, identifier in sorted(options[1:], key=lambda option: option[0].casefold()):
        combo.append(identifier, name)
    if not combo.set_active_id(current or root):
        combo.set_active(0)
    return root, combo


def edit_entry(app, vault, group, entry=None):
    if app.busy or app.desktop.locked or not app.workspace.owner_session(vault):
        return
    dialog, grid = _form(app, "Edit entry" if entry else "New entry")
    fields = {}
    for index, (name, label) in enumerate((("title", "_Title"), ("username", "_Username"), ("url", "_URL"))):
        control = Gtk.Entry(text=entry[name] if entry else "", activates_default=True)
        control.set_name(f"entry-{name}")
        fields[name] = _field(grid, index, label, control)
    root, location = _locations(app, vault, entry["group"] if entry else group)
    _field(grid, 3, "_Group", location)

    change_password = Gtk.CheckButton(label="Replace saved password", no_show_all=not bool(entry))
    grid.attach(change_password, 1, 4, 1, 1)
    password = password_entry()
    password.set_name("entry-password")
    password.set_placeholder_text("Entry password")
    password.set_sensitive(entry is None)
    _field(grid, 5, "_Password", password)

    def change(box):
        password.set_sensitive(box.get_active())
        if not box.get_active():
            password.set_text("")

    change_password.connect("toggled", change)
    _require_name(dialog, fields["title"])
    fields["title"].grab_focus()
    response = app.run_dialog(dialog)
    updated_password = password.get_text() if entry is None or change_password.get_active() else None
    password.set_text("")
    if response != Gtk.ResponseType.OK:
        return
    destination = location.get_active_id()
    values = {name: field.get_text() for name, field in fields.items()}
    app._background(
        lambda: app.workspace.put_entry(vault, destination, **values, password=updated_password,
                                        entry=entry["id"] if entry else None),
        after=lambda _: app._show_group(vault, "" if destination == root else destination),
    )


def edit_group(app, vault, group, *, parent=None):
    if app.busy or app.desktop.locked:
        return
    session = app.workspace.owner_session(vault)
    if not session:
        return
    existing = next((row for row in session.groups if row["id"] == group), None) if group else None
    if group and not existing:
        return
    dialog, grid = _form(app, "Edit group" if existing else "New group")
    name = Gtk.Entry(text=existing["name"] if existing else "", activates_default=True)
    name.set_name("group-name")
    _field(grid, 0, "_Name", name)
    _, location = _locations(app, vault, existing["parent"] if existing else parent, moving_group=group)
    _field(grid, 1, "_Parent", location)
    _require_name(dialog, name)
    name.grab_focus()
    if app.run_dialog(dialog) != Gtk.ResponseType.OK:
        return
    destination, title = location.get_active_id(), name.get_text()
    app._background(lambda: app.workspace.put_group(vault, destination, name=title, group=group),
                    after=lambda identifier: app._show_group(vault, identifier))


def recycle_entry(app, vault, group, entry):
    if app.busy or not app.confirm("Move entry to the recycle bin?", entry["title"] or "(Untitled entry)"):
        return
    app._background(lambda: app.workspace.remove_entry(vault, entry["id"]),
                    after=lambda _: app._show_group(vault, group))


def recycle_group(app, vault, group):
    if app.busy:
        return
    session = app.workspace.owner_session(vault)
    if not session:
        return
    item = next((row for row in session.groups if row["id"] == group and row["parent"]), None)
    if item is None or not app.confirm(
        "Move group to the recycle bin?", "This moves the group and all its entries and subgroups.",
    ):
        return
    root, = (row["id"] for row in session.groups if row["parent"] is None)
    parent = item["parent"]
    app._background(lambda: app.workspace.remove_group(vault, group),
                    after=lambda _: app._show_group(vault, "" if root == parent else parent))
