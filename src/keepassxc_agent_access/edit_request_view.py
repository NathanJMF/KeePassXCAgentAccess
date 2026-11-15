"""Owner review for one-time agent edits."""

from gi.repository import Gtk

from .activity import ActivityError
from .owner_views import _dialog, _label, _scroll, _time
from .tray import password_entry
from .vault import VaultError


OPERATION_LABELS = {
    "create_entry": "Create entry",
    "update_entry": "Edit entry metadata",
    "create_group": "Create group",
    "rename_group": "Rename group",
    "move_entry": "Move entry",
    "move_group": "Move group",
    "recycle_entry": "Recycle entry",
    "recycle_group": "Recycle group",
    "replace_password": "Replace entry password",
}
FIELD_LABELS = {"name": "Name", "title": "Title", "username": "Username", "url": "Stored URL"}


def _add(container, text):
    container.pack_start(_label(text), False, False, 0)


def _path(parts):
    return " / ".join(parts) or "Root"


def _values(container, review):
    if not review.new:
        return
    previous = dict(review.old)
    grid = Gtk.Grid(column_spacing=16, row_spacing=10)
    container.pack_start(grid, False, False, 0)
    for column, title in enumerate(("Field", "Current", "Proposed")):
        label = Gtk.Label(label=title, xalign=0)
        label.get_style_context().add_class("heading")
        grid.attach(label, column, 0, 1, 1)
    for row, (field, value) in enumerate(review.new, 1):
        if field not in FIELD_LABELS:
            continue
        before = previous.get(field)
        for column, text in enumerate((FIELD_LABELS[field], "—" if before is None else before or "(empty)",
                                       "(empty)" if value == "" else str(value))):
            widget = _label(text)
            widget.set_max_width_chars(36)
            grid.attach(widget, column, row, 1, 1)


def review_edit(app, record):
    if app.desktop.locked or app.busy or record.status != "pending":
        return
    operation = record.request.operation
    dialog, body = _dialog(app, OPERATION_LABELS[operation], 700, 465)
    dialog.set_modal(True)
    dialog.add_buttons("Close", Gtk.ResponseType.CLOSE, "Deny", Gtk.ResponseType.REJECT,
                       "Approve and apply", Gtk.ResponseType.ACCEPT)
    dialog.set_default_response(Gtk.ResponseType.CLOSE)
    dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT).get_style_context().add_class("suggested-action")
    _add(body, f"Requested  {_time(record.requested)}")
    _add(body, f"Agent  {record.identity} (reported)    Project  {record.project} (reported)")
    grant = app.grants.records.get(record.token_id)
    if grant:
        _add(body, f"OS identity  UID {grant.uid} (verified)")
    panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin=10)
    body.pack_start(_scroll(panel), True, True, 0)

    preview = None
    owner_password = None
    try:
        preview = app.edit_requests.preview(record.token_id, record.id)
    except VaultError as error:
        _add(panel, str(error))
    except ActivityError:
        _add(panel, "Keeper could not read the edit request.")
    else:
        _add(panel, f"Vault  {preview.vault_name}")
        _add(panel, f"Vault ID  {record.request.vault}")
        if preview.target_path:
            _add(panel, f"Target  {_path(preview.target_path)}")
        if record.request.entry or record.request.group:
            _add(panel, f"Target ID  {record.request.entry or record.request.group}")
        if preview.destination_path is not None:
            _add(panel, f"Destination  {_path(preview.destination_path)}")
        if record.request.parent:
            _add(panel, f"Destination group ID  {record.request.parent}")
        _values(panel, preview)
        if operation in ("move_group", "recycle_group"):
            entries = "1 entry" if preview.entry_count == 1 else f"{preview.entry_count} entries"
            groups = max(0, preview.group_count - 1)
            subgroups = "1 subgroup" if groups == 1 else f"{groups} subgroups"
            _add(panel, f"Affected contents  {entries} · {subgroups}")
        if preview.password_source == "generate":
            _add(panel, "Keeper will generate and save a new password.")
        elif preview.password_source == "owner":
            _add(panel, "Enter the replacement password.")
            owner_password = password_entry()
            owner_password.set_name("edit-owner-password")
            owner_password.set_placeholder_text("Replacement password")
            panel.pack_start(owner_password, False, False, 0)
        if operation == "replace_password" or any(field == "username" for field, _ in preview.new):
            _add(panel, "Existing credential action approvals for this entry will require fresh approval.")
    if app.workspace.paused:
        _add(panel, "Agent access is paused. Resume it to apply this edit.")

    def update(*_):
        dialog.set_response_sensitive(
            Gtk.ResponseType.ACCEPT, bool(preview) and not app.workspace.paused
            and (owner_password is None or bool(owner_password.get_text())),
        )

    if owner_password is not None:
        owner_password.connect("changed", update)
    update()
    try:
        response = app.run_dialog(dialog)
        value = owner_password.get_text() if owner_password is not None and response == Gtk.ResponseType.ACCEPT else None
    finally:
        if owner_password is not None:
            owner_password.set_text("")
    if response == Gtk.ResponseType.REJECT:
        app.owner_operation(lambda: app.edit_requests.deny(record.token_id, record.id))
    elif response == Gtk.ResponseType.ACCEPT and preview is not None:
        app._background(lambda: app.edit_requests.approve(preview, value))
