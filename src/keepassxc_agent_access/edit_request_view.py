"""Owner review for one-time agent edits."""

from gi.repository import Gtk, Pango

from .activity import ActivityError
from .owner_views import _dialog, _label, _scroll, _time
from .tray import password_entry
from .vault import VaultError
from .workspace_style import styled


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
    details = Gtk.Expander(label="Request details")
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


def review_edit(app, record):
    if app.desktop.locked or app.busy or record.status != "pending":
        return
    operation = record.request.operation
    dialog, body = _dialog(app, OPERATION_LABELS[operation], 640, -1)
    dialog.set_name("keeper-edit-review")
    dialog.set_modal(True)
    dialog.add_buttons("Close", Gtk.ResponseType.CLOSE, "Deny", Gtk.ResponseType.REJECT,
                       "Approve and apply", Gtk.ResponseType.ACCEPT)
    dialog.set_default_response(Gtk.ResponseType.CLOSE)
    styled(dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT), "suggested-action")

    preview, error = None, None
    try:
        preview = app.edit_requests.preview(record.token_id, record.id)
    except VaultError as fault:
        error = str(fault)
    except ActivityError:
        error = "Keeper could not read the edit request."
    title_only = operation == "update_entry" and preview and tuple(key for key, _ in preview.new) == ("title",)
    _add(body, "Rename this entry?" if title_only else f"{OPERATION_LABELS[operation]}?",
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
            _add(panel, "Keeper will generate and save a new password.")
        elif preview.password_source == "owner":
            _add(panel, "Enter the replacement password.")
            owner_password = password_entry()
            owner_password.set_name("edit-owner-password")
            owner_password.set_placeholder_text("Replacement password")
            panel.pack_start(owner_password, False, False, 0)
        if operation == "replace_password" or any(field == "username" for field, _ in preview.new):
            _add(panel, "Existing credential action approvals for this entry will require fresh approval.")
    elif error:
        _add(panel, error)
    _request_details(panel, app, record, preview)

    blocker = styled(Gtk.Box(spacing=10, valign=Gtk.Align.CENTER), "keeper-review-blocker")
    icon = Gtk.Image.new_from_icon_name("changes-prevent-symbolic", Gtk.IconSize.BUTTON)
    blocker.pack_start(icon, False, False, 0)
    explanation = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
    blocker.pack_start(explanation, True, True, 0)
    _add(explanation, "Agent access is paused", "keeper-review-label")
    reason = _add(explanation, "Resuming lets all approved tokens run again.", "keeper-review-muted")
    resume = Gtk.Button(label="Resume agent access", valign=Gtk.Align.CENTER)
    resume.connect("clicked", lambda *_: app.set_agent_paused(False))
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
    signals = [app.pause_button.connect(signal, update) for signal in ("notify::label", "notify::sensitive")]
    update()
    try:
        response = app.run_dialog(dialog)
        value = owner_password.get_text() if owner_password is not None and response == Gtk.ResponseType.ACCEPT else None
    finally:
        for signal in signals:
            app.pause_button.disconnect(signal)
        if owner_password is not None:
            owner_password.set_text("")
    if response == Gtk.ResponseType.REJECT:
        app.owner_operation(lambda: app.edit_requests.deny(record.token_id, record.id))
    elif response == Gtk.ResponseType.ACCEPT and preview is not None:
        app._background(lambda: app.edit_requests.approve(preview, value))
