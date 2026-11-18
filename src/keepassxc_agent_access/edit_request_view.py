"""Owner review for one-time agent edits."""

from gi.repository import Gtk, Pango

from .activity import ActivityError
from .owner_views import _dialog, _label, _scroll, _time, mouse_click, require_mouse_decisions
from .tray import password_entry
from .vault import VaultError
from .workspace_style import styled


OPERATION_LABELS = {
    "create_entry": "Create Entry",
    "update_entry": "Edit Entry Metadata",
    "create_group": "Create Group",
    "rename_group": "Rename Group",
    "move_entry": "Move Entry",
    "move_group": "Move Group",
    "recycle_entry": "Recycle Entry",
    "recycle_group": "Recycle Group",
    "replace_password": "Replace Entry Password",
}
FIELD_LABELS = {"name": "Name", "title": "Title", "username": "Username", "url": "Stored URL"}


def _add(container, text, *classes):
    label = styled(_label(text), *classes)
    label.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
    label.set_max_width_chars(70)
    container.pack_start(label, False, False, 0)
    return label


def _path(parts):
    return " / ".join(parts) or "Root"


def _values(container, review):
    previous = dict(review.old)
    for field, value in review.new:
        if field not in FIELD_LABELS:
            continue
        _add(container, FIELD_LABELS[field], "keeper-review-label")
        columns = Gtk.Box(spacing=12, homogeneous=True)
        container.pack_start(columns, False, False, 0)
        displays = []
        if field in previous:
            displays.append(("Current", previous[field]))
        displays.append(("Proposed", value))
        for caption, content in displays:
            cell = styled(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5), "keeper-review-value")
            if caption == "Proposed":
                styled(cell, "keeper-review-proposed")
            columns.pack_start(cell, True, True, 0)
            _add(cell, caption, "keeper-review-muted")
            _add(cell, str(content) if content else "(empty)").set_max_width_chars(32)


def _request_details(container, app, record, preview):
    details = Gtk.Expander(label="Request Details")
    fields = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5, margin_top=8, margin_start=12)
    details.add(fields)
    _add(fields, f"Requested  {_time(record.requested)}")
    _add(fields, "Agent name and project are reported by the runner.")
    grant = app.grants.records.get(record.token_id)
    if grant:
        _add(fields, f"Linux UID  {grant.uid} (verified)")
    _add(fields, f"Request ID  {record.id}")
    _add(fields, f"Vault ID  {record.request.vault}")
    if record.request.entry or record.request.group:
        _add(fields, f"Target ID  {record.request.entry or record.request.group}")
    if preview is not None and record.request.parent:
        _add(fields, f"Destination group ID  {record.request.parent}")
    container.pack_start(details, False, False, 0)


def review_edit(app, record, *, standalone=False):
    if app.desktop.locked or app.busy or record.status != "pending":
        return
    operation = record.request.operation
    title = OPERATION_LABELS[operation]
    approve_label = "Approve and Apply"
    if record.request.password_source == "owner":
        if operation == "create_entry":
            approve_label = "Save Entry"
        elif operation == "replace_password":
            title = "Save Password in Keeper"
            approve_label = "Save Password"
    dialog, body = _dialog(app, title, 640, -1)
    dialog.set_name("keeper-edit-review")
    dialog.set_position(Gtk.WindowPosition.CENTER_ON_PARENT)
    dialog.set_modal(True)
    dialog.add_buttons("Close", Gtk.ResponseType.CLOSE, "Deny", Gtk.ResponseType.REJECT,
                       approve_label, Gtk.ResponseType.ACCEPT)
    dialog.set_default_response(Gtk.ResponseType.CLOSE)
    require_mouse_decisions(dialog)
    styled(dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT), "suggested-action")

    preview, error = None, None
    try:
        preview = app.edit_requests.preview(record.token_id, record.id)
    except VaultError as fault:
        error = str(fault)
    except ActivityError:
        error = "Keeper could not read the edit request."
    title_only = operation == "update_entry" and preview and tuple(key for key, _ in preview.new) == ("title",)
    _add(body, "Rename this entry?" if title_only else f"{title}?",
         "keeper-review-title")
    _add(body, f"Requested by {record.identity} · {record.project}", "keeper-review-muted")

    panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin_bottom=4)
    scroll = _scroll(panel)
    scroll.set_shadow_type(Gtk.ShadowType.NONE)
    scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scroll.set_propagate_natural_height(True)
    scroll.set_max_content_height(420)
    body.pack_start(scroll, True, True, 0)

    owner_password = None
    if preview:
        location = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        panel.pack_start(location, False, False, 0)
        _add(location, preview.vault_name, "keeper-review-label")
        if preview.target_path:
            _add(location, _path(preview.target_path), "keeper-review-muted")
        if preview.destination_path is not None:
            _add(location, f"Destination  {_path(preview.destination_path)}", "keeper-review-muted")
        _values(panel, preview)
        if operation in ("move_group", "recycle_group"):
            entries = "1 entry" if preview.entry_count == 1 else f"{preview.entry_count} entries"
            groups = max(0, preview.group_count - 1)
            subgroups = "1 subgroup" if groups == 1 else f"{groups} subgroups"
            _add(panel, f"Affected contents  {entries} · {subgroups}")
        if preview.password_source == "generate":
            _add(panel, "Keeper will generate and save a password in the vault. This does not change the password on the service.")
        elif preview.password_source == "owner":
            _add(panel, "Paste the account’s current password. Keeper saves it here and does not change the account’s login.")
            owner_password = password_entry()
            owner_password.set_name("edit-owner-password")
            owner_password.set_placeholder_text("Current Account Password")
            panel.pack_start(owner_password, False, False, 0)
        if operation == "replace_password" or (operation == "update_entry" and any(
                field == "username" for field, _ in preview.new)):
            _add(panel, "Existing credential action approvals for this entry will require fresh approval.")
    elif error:
        _add(panel, error)
        vault = app.workspace.registrations.get(record.request.vault)
        if vault and not app.workspace.session(vault.id):
            panel.pack_start(app.unlock_review_button(vault, dialog), False, False, 0)
    _request_details(panel, app, record, preview)

    blocker = styled(Gtk.Box(spacing=10, valign=Gtk.Align.CENTER), "keeper-review-blocker")
    icon = Gtk.Image.new_from_icon_name("changes-prevent-symbolic", Gtk.IconSize.BUTTON)
    blocker.pack_start(icon, False, False, 0)
    explanation = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
    blocker.pack_start(explanation, True, True, 0)
    _add(explanation, "Agent access is paused", "keeper-review-label")
    reason = _add(explanation, "Resuming lets all approved tokens run again.", "keeper-review-muted")
    resume = Gtk.Button(label="Resume Agent Access", valign=Gtk.Align.CENTER)
    resume.set_can_focus(False)
    resume.connect("clicked", lambda *_: app.set_agent_paused(False) if mouse_click() else None)
    blocker.pack_end(resume, False, False, 0)
    body.pack_start(blocker, False, False, 0)
    blocker.show_all()
    blocker.set_no_show_all(True)

    def update(*_):
        paused = app.workspace.paused
        can_resume = app.pause_button.get_sensitive()
        blocker.set_visible(paused)
        resume.set_sensitive(can_resume)
        reason.set_text("Resuming lets all approved tokens run again." if can_resume
                        else "Close this review and check Broker settings.")
        dialog.set_response_sensitive(
            Gtk.ResponseType.ACCEPT, bool(preview) and not paused
            and (owner_password is None or bool(owner_password.get_text())),
        )

    if owner_password is not None:
        owner_password.connect("changed", update)
    signals = (
        (app.pause_labels, app.pause_labels.connect("notify::visible-child-name", update)),
        (app.pause_button, app.pause_button.connect("notify::sensitive", update)),
    )
    update()
    try:
        response = app.run_dialog(dialog, standalone=standalone)
        value = owner_password.get_text() if owner_password is not None and response == Gtk.ResponseType.ACCEPT else None
    finally:
        for widget, signal in signals:
            widget.disconnect(signal)
        if owner_password is not None:
            owner_password.set_text("")
    if response == Gtk.ResponseType.APPLY:
        identifier = f"{record.token_id}/{record.id}"
        if ("edit", identifier) in app._review_requests():
            app.access_view.open_record(identifier, "edit", automatic=standalone)
    elif response == Gtk.ResponseType.REJECT:
        app.owner_operation(lambda: app.edit_requests.deny(record.token_id, record.id, preview=preview))
    elif response == Gtk.ResponseType.ACCEPT and preview is not None:
        app._background(lambda: app.edit_requests.approve(preview, value))
