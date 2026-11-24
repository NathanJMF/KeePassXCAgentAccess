"""Owner dialogs for editing entries and groups inside one unlocked vault."""

from gi.repository import Gtk

from .owner_views import _dialog
from .tray import password_entry
from .workspace import ordered_groups


def _form(app, title):
    dialog, content = _dialog(app, title, 500, 250)
    dialog.set_modal(True)
    dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Save", Gtk.ResponseType.OK)
    dialog.get_widget_for_response(Gtk.ResponseType.OK).get_style_context().add_class("suggested-action")
    dialog.set_default_response(Gtk.ResponseType.OK)
    fields = Gtk.Grid(row_spacing=12, column_spacing=14)
    content.pack_start(fields, True, True, 0)
    return dialog, fields


def _require_name(dialog, field, *, group_choice=None, destination=None):
    def validate(*_):
        has_destination = destination is None or destination() is not None
        dialog.set_response_sensitive(Gtk.ResponseType.OK, bool(field.get_text().strip()) and has_destination)
    field.connect("changed", validate)
    if group_choice is not None:
        group_choice.connect("changed", validate)
    validate()


def _field(grid, row, label, widget, *, focus=None):
    caption = Gtk.Label(label=label, xalign=0, mnemonic_widget=focus or widget, use_underline=True)
    if focus is not None:
        caption.set_valign(Gtk.Align.START)
    widget.set_hexpand(True)
    grid.attach(caption, 0, row, 1, 1)
    grid.attach(widget, 1, row, 1, 1)
    return widget


def _entry_locations(app, dialog, grid, vault, group, *, creating):
    workspace = app.workspace
    with workspace.mutex:
        locations = {}
        for record in workspace.registrations.values():
            if creating or record.id == vault:
                session = workspace.owner_session(record.id)
                locations[record.id] = (record.name, session.groups if session else None)
    if vault not in locations or locations[vault][1] is None:
        return None

    vault_choice = Gtk.ComboBoxText()
    vault_choice.set_name("entry-vault")
    for identifier, (name, groups) in sorted(locations.items(), key=lambda item: item[1][0].casefold()):
        vault_choice.append(identifier, f"{name} · Locked" if groups is None else name)
    vault_choice.set_active_id(vault)
    vault_choice.set_sensitive(creating)

    group_choice = Gtk.ComboBoxText()
    group_choice.set_name("group-location")
    unlock = Gtk.Button(label="Unlock Vault", no_show_all=True)
    unlock.set_name("entry-unlock-vault")
    error = Gtk.Label(xalign=0, wrap=True, no_show_all=True)
    error.set_name("entry-unlock-error")

    def populate(widget, selected=None):
        group_choice.remove_all()
        active = widget.get_active_id()
        groups = locations[active][1] if active in locations else None
        unlock.set_visible(creating and active in locations and groups is None)
        error.hide()
        choices = list(ordered_groups(groups)) if groups is not None else []
        group_choice.set_sensitive(bool(choices))
        if not choices:
            group_choice.append_text("Vault is locked" if groups is None else "No groups")
            group_choice.set_active(0)
            return

        for item, path in choices:
            group_choice.append(item["id"], " / ".join(path))
        if not creating and any(item["id"] == selected and item["parent"] is None for item in groups):
            group_choice.set_active(-1)
        elif not selected or not group_choice.set_active_id(selected):
            group_choice.set_active(0)

    def destination():
        active = vault_choice.get_active_id()
        session = workspace.owner_session(active)
        if session is None or locations[active][1] is None:
            return None
        return group_choice.get_active_id() or next(item["id"] for item in session.groups if item["parent"] is None)

    def unlock_selected(_):
        identifier = vault_choice.get_active_id()
        record = workspace.registrations.get(identifier)
        if record is None:
            return
        vault_choice.set_sensitive(False)
        unlock.set_sensitive(False)
        error.hide()

        def finished(completed, message):
            if not dialog.get_visible():
                return
            vault_choice.set_sensitive(True)
            unlock.set_sensitive(True)
            session = workspace.owner_session(identifier) if completed else None
            if session:
                locations[identifier] = (record.name, session.groups)
                model = vault_choice.get_model()
                model[vault_choice.get_active_iter()][0] = record.name
                populate(vault_choice)
            elif message:
                error.set_text(message)
                error.show()

        if not app.unlock_record(record, parent=dialog, finished=finished):
            vault_choice.set_sensitive(True)
            unlock.set_sensitive(True)

    vault_line = Gtk.Box(spacing=6)
    vault_line.pack_start(vault_choice, True, True, 0)
    vault_line.pack_start(unlock, False, False, 0)
    vault_controls = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    vault_controls.pack_start(vault_line, False, False, 0)
    vault_controls.pack_start(error, False, False, 0)
    populate(vault_choice, group)
    vault_choice.connect("changed", populate)
    unlock.connect("clicked", unlock_selected)
    _field(grid, 0, "_Vault", vault_controls, focus=vault_choice)
    _field(grid, 1, "_Group", group_choice)
    return vault_choice, group_choice, destination


def edit_entry(app, vault, group, entry=None):
    if app.busy or app.desktop.locked or not app.workspace.owner_session(vault):
        return
    if entry is None:
        _entry_form(app, vault, group, None, "")
        return
    app._background(lambda: app.workspace.entry_notes(vault, entry["id"]),
                    after=lambda notes: _entry_form(app, vault, group, entry, notes))


def _entry_form(app, vault, group, entry, saved_notes):
    if not app.workspace.owner_session(vault):
        return
    dialog, grid = _form(app, "Edit Entry" if entry else "New Entry")
    locations = _entry_locations(app, dialog, grid, vault, entry["group"] if entry else group, creating=entry is None)
    if locations is None:
        dialog.destroy()
        return
    vault_choice, group_choice, destination = locations
    fields = {}
    for index, (name, label) in enumerate((("title", "_Title"), ("url", "U_RL"), ("username", "_Username")), 2):
        control = Gtk.Entry(text=entry[name] if entry else "", activates_default=True)
        control.set_name(f"entry-{name}")
        fields[name] = _field(grid, index, label, control)

    change_password = Gtk.CheckButton(label="Replace Saved Password", no_show_all=not bool(entry))
    grid.attach(change_password, 1, 5, 1, 1)
    password = password_entry()
    password.set_name("entry-password")
    password.set_placeholder_text("Entry Password")
    password.set_sensitive(entry is None)
    _field(grid, 6, "_Password", password)

    notes = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD_CHAR, accepts_tab=False,
                         left_margin=8, right_margin=8, top_margin=6, bottom_margin=6)
    notes.set_name("entry-notes")
    notes_buffer = notes.get_buffer()
    if saved_notes is None:
        notes.set_editable(False)
        notes.set_cursor_visible(False)
        notes_buffer.set_text("These notes are too large to display.")
    else:
        notes_buffer.set_text(saved_notes)
    notes_scroll = Gtk.ScrolledWindow(vexpand=True, min_content_height=90, shadow_type=Gtk.ShadowType.IN)
    notes_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    notes_scroll.add(notes)
    _field(grid, 7, "_Notes", notes_scroll, focus=notes)

    def change(box):
        password.set_sensitive(box.get_active())
        if not box.get_active():
            password.set_text("")

    change_password.connect("toggled", change)
    if entry is not None:
        affected_grants = []
        if app.grants is not None:
            auto_rotate = app.workspace.token_auto_approval_enabled("auto_approve_token_rotations")
            entry_id = entry["id"]
            with app.workspace.mutex:
                for grant in app.grants.records.values():
                    if grant.status not in ("active", "disabled"):
                        continue
                    if any(
                        (scope.vault, scope.entry) == (vault, entry_id)
                        and (scope.uses or scope.action is not None)
                        and (not auto_rotate or scope.action is not None or grant.workflow is not None)
                        for scope in grant.scope
                    ):
                        affected_grants.append(grant)
        count_text = "1 approved token" if len(affected_grants) == 1 else f"{len(affected_grants)} approved tokens"
        warning = Gtk.Label(
            label=f"Saving a new username or password will require fresh approval for {count_text}.",
            xalign=0, wrap=True, no_show_all=True,
        )
        warning.set_name("entry-grant-warning")
        warning.get_style_context().add_class("keeper-warning")
        # Keep the warning outside Gtk.Grid so grid caption assertions stay unchanged.
        dialog.get_content_area().pack_start(warning, False, False, 0)

        def update_warning(*_):
            changed = change_password.get_active() or fields["username"].get_text() != entry["username"]
            warning.set_visible(bool(affected_grants) and changed)

        change_password.connect("toggled", update_warning)
        fields["username"].connect("changed", update_warning)
        update_warning()
    _require_name(dialog, fields["title"], group_choice=group_choice, destination=destination)
    fields["title"].grab_focus()
    response = app.run_dialog(dialog)
    updated_password = password.get_text() if entry is None or change_password.get_active() else None
    password.set_text("")
    updated_notes = None
    if response == Gtk.ResponseType.OK and saved_notes is not None:
        value = notes_buffer.get_text(*notes_buffer.get_bounds(), True)
        if entry is None or value != saved_notes:
            updated_notes = value
    notes_buffer.set_text("")
    if response != Gtk.ResponseType.OK:
        return
    destination_vault = vault_choice.get_active_id()
    destination_group = destination()
    if destination_vault is None or destination_group is None:
        return
    selection = group_choice.get_active_id() or ""
    values = {name: field.get_text() for name, field in fields.items()}
    app._background(
        lambda: app.workspace.put_entry(destination_vault, destination_group, **values, password=updated_password,
                                        notes=updated_notes, entry=entry["id"] if entry else None),
        after=lambda _: app._show_group(destination_vault, selection),
    )


def edit_group(app, vault, group):
    if app.busy or app.desktop.locked:
        return
    session = app.workspace.owner_session(vault)
    if not session:
        return
    existing = next((row for row in session.groups if row["id"] == group), None) if group else None
    if group and not existing:
        return
    dialog, grid = _form(app, "Edit Group" if existing else "New Group")
    name = Gtk.Entry(text=existing["name"] if existing else "", activates_default=True)
    name.set_name("group-name")
    _field(grid, 0, "_Name", name)
    parent = existing["parent"] if existing else next(row["id"] for row in session.groups if row["parent"] is None)
    _require_name(dialog, name)
    name.grab_focus()
    if app.run_dialog(dialog) != Gtk.ResponseType.OK:
        return
    title = name.get_text()
    app._background(lambda: app.workspace.put_group(vault, parent, name=title, group=group),
                    after=lambda identifier: app._show_group(vault, identifier))


def delete_entry(app, vault, group, entry):
    title = entry["title"] or "(Untitled entry)"
    if app.busy or not app.confirm("Delete entry?", f"“{title}” will be permanently deleted.", delete=True):
        return
    app._background(lambda: app.workspace.delete_entry(vault, entry["id"]),
                    after=lambda _: app._show_group(vault, group))


def delete_group(app, vault, group):
    if app.busy:
        return
    session = app.workspace.owner_session(vault)
    if not session:
        return
    item = next((row for row in session.groups if row["id"] == group and row["parent"]), None)
    if item is None:
        return
    name = item["name"] or "(Untitled group)"
    if not app.confirm("Delete group?", f"“{name}” and all of its contents will be permanently deleted.", delete=True):
        return
    root, = (row["id"] for row in session.groups if row["parent"] is None)
    parent = item["parent"]
    app._background(lambda: app.workspace.delete_group(vault, group),
                    after=lambda _: app._show_group(vault, "" if root == parent else parent))
