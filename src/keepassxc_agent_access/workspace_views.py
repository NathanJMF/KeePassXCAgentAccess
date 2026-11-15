"""GTK views for request review, entry actions, and local activity."""

from datetime import datetime

from gi.repository import Gtk, Pango

from .access_settings import Action, ActionType
from .activity import ActivityError
from .edit_request_view import review_edit
from .owner_views import _dialog, _label, _scroll, _table, _time
from .workspace_editor import edit_entry, recycle_entry
from .workspace_style import styled


def reported(value):
    return f"{value} (reported)" if value else "—"


def table_time(timestamp, *, include_year=False):
    if timestamp is None:
        return "—"
    pattern = "%Y-%m-%d · %H:%M" if include_year else "%b %d · %H:%M:%S"
    return datetime.fromtimestamp(timestamp).astimezone().strftime(pattern)


def add_label(container, text):
    container.pack_start(_label(text), False, False, 0)


def button(container, label, callback, *, icon=None):
    widget = Gtk.Button(label=label)
    if icon:
        widget.set_image(Gtk.Image.new_from_icon_name(icon, Gtk.IconSize.BUTTON))
        widget.set_always_show_image(True)
    widget.connect("clicked", callback)
    container.pack_start(widget, False, False, 0)
    return widget


def selected_key(table, column):
    model, row = table.get_selection().get_selected()
    return model[row][column] if row else None


def fill_table(table, rows, key_column):
    sorting = table.keeper_sort
    rows = list(rows)
    if sorting.rows != rows or sorting.key_column != key_column:
        sorting.rows = rows
        sorting.key_column = key_column
        _replace_rows(table, sorting.visible_rows(), key_column)


def _replace_rows(table, rows, key_column):
    selected = selected_key(table, key_column)
    model = table.get_model()
    if list(map(tuple, model)) == rows:
        return
    model.clear()
    for values in rows:
        row = model.append(values)
        if values[key_column] == selected:
            table.get_selection().select_iter(row)


def sorted_table_rows(rows, key_column, descending=False, group_column=None):
    batches = {}
    for row in rows:
        group = row[group_column] if group_column is not None else None
        known, blank = batches.setdefault(group, ([], []))
        value = row[key_column]
        if isinstance(value, str):
            value = value.strip().casefold()
        if value is None or value in ("", "—"):
            blank.append(row)
        else:
            known.append((value, row))

    result = []
    for known, blank in batches.values():
        known.sort(key=lambda item: item[0], reverse=descending)
        result.extend(row for _, row in known)
        result.extend(blank)
    return result


class TableSort:
    def __init__(self, sort_keys, sort_group):
        self.sort_keys = sort_keys or {}
        self.sort_group = sort_group
        self.rows = []
        self.key_column = None
        self.active = None
        self.sort_column = None
        self.descending = False

    def visible_rows(self):
        if self.sort_column is None:
            return self.rows
        return sorted_table_rows(self.rows, self.sort_column, self.descending, self.sort_group)

    def click(self, column, table, model_index):
        if column != self.active:
            self.active = column
            self.sort_column = self.sort_keys.get(model_index, model_index)
            self.descending = False
        elif not self.descending:
            self.descending = True
        else:
            self.active = None
            self.sort_column = None
            self.descending = False
        for header in table.get_columns():
            header.set_sort_indicator(header == self.active)
        if self.active is not None:
            self.active.set_sort_order(Gtk.SortType.DESCENDING if self.descending else Gtk.SortType.ASCENDING)
        if self.key_column is not None:
            _replace_rows(table, self.visible_rows(), self.key_column)


def section_heading(title, icon):
    header = Gtk.Box(spacing=13)
    mark = styled(Gtk.Box(valign=Gtk.Align.CENTER), "keeper-section-icon")
    image = Gtk.Image.new_from_icon_name(icon, Gtk.IconSize.LARGE_TOOLBAR)
    mark.pack_start(image, False, False, 0)
    header.pack_start(mark, False, False, 0)
    titles = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1, valign=Gtk.Align.CENTER)
    header.pack_start(titles, True, True, 0)
    label = styled(Gtk.Label(label=title, xalign=0, ellipsize=Pango.EllipsizeMode.END), "keeper-title")
    titles.pack_start(label, False, False, 0)
    return header, titles, label, image


def empty_state(icon, text):
    block = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, halign=Gtk.Align.CENTER,
                    valign=Gtk.Align.CENTER, margin=18)
    image = styled(Gtk.Image.new_from_icon_name(icon, Gtk.IconSize.DIALOG), "keeper-empty-icon")
    image.set_pixel_size(30)
    label = styled(Gtk.Label(label=text, wrap=True, justify=Gtk.Justification.CENTER), "keeper-muted")
    block.pack_start(image, False, False, 0)
    block.pack_start(label, False, False, 0)
    return block, label, image


def pane_table(model, titles, widths, *, lead_icon=None, status=None, expand_columns=(1, 2), muted_columns=(),
               sort_keys=None, sort_group=None):
    table = styled(Gtk.TreeView(model=model), "keeper-table")
    table.keeper_sort = TableSort(sort_keys, sort_group)
    table.set_grid_lines(Gtk.TreeViewGridLines.HORIZONTAL)
    for index, title in enumerate(titles):
        column = Gtk.TreeViewColumn(title)
        column.set_clickable(True)
        column.connect("clicked", table.keeper_sort.click, table, index)
        column.set_resizable(True)
        column.set_expand(index in expand_columns)
        column.set_min_width(widths[index])
        text = Gtk.CellRendererText(xpad=10, ypad=9, ellipsize=Pango.EllipsizeMode.END)
        colored = status is not None and index == status[0]
        if colored or (index == 0 and lead_icon):
            icon = Gtk.CellRendererPixbuf(xpad=5, stock_size=Gtk.IconSize.MENU)
            column.pack_start(icon, False)
            if colored:
                column.set_cell_data_func(icon, _status_icon, status)
            else:
                icon.set_property("icon-name", lead_icon)
            text.set_property("xpad", 3)
            text.set_property("weight", Pango.Weight.SEMIBOLD)
        column.pack_start(text, True)
        column.add_attribute(text, "text", index)
        if colored or index in muted_columns:
            column.set_cell_data_func(text, _table_text_color, (table, status if colored else None))
        table.append_column(column)
    scroll = _scroll(table)
    scroll.set_shadow_type(Gtk.ShadowType.NONE)
    return table, scroll


def _status_icon(_column, cell, model, row, status):
    symbol, _ = status[1].get(model[row][status[0]], (None, None))
    cell.set_property("icon-name", symbol)


def _table_text_color(_column, cell, model, row, context):
    table, status = context
    palette = "keeper_muted"
    if status:
        _, palette = status[1].get(model[row][status[0]], (None, palette))
    found, color = table.get_style_context().lookup_color(palette)
    tint = found and not table.get_selection().iter_is_selected(row)
    if tint:
        cell.set_property("foreground-rgba", color)
    cell.set_property("foreground-set", tint)


ACCESS_STATES = {
    "Pending": ("appointment-soon-symbolic", "keeper_warning"),
    "Edit pending": ("appointment-soon-symbolic", "keeper_warning"),
    "Applying edit": ("content-loading-symbolic", "keeper_accent"),
    "Active": ("emblem-default-symbolic", "keeper_success"),
    "Disabled": ("action-unavailable-symbolic", "keeper_muted"),
}
ACTIVITY_STATES = {
    "Approved": ("emblem-ok-symbolic", "keeper_success"),
    "Succeeded": ("emblem-ok-symbolic", "keeper_success"),
    "Pending approval": ("appointment-soon-symbolic", "keeper_warning"),
    "Pending review": ("appointment-soon-symbolic", "keeper_warning"),
    "Stale": ("action-unavailable-symbolic", "keeper_muted"),
    "Failed": ("dialog-error-symbolic", "keeper_failure"),
    "Denied": ("action-unavailable-symbolic", "keeper_failure"),
    "Paused": ("media-playback-pause-symbolic", "keeper_warning"),
    "Revoked": ("action-unavailable-symbolic", "keeper_muted"),
}


def table_card(scroll, empty):
    card = styled(Gtk.Box(orientation=Gtk.Orientation.VERTICAL), "keeper-card")
    overlay = Gtk.Overlay()
    overlay.add(scroll)
    overlay.add_overlay(empty)
    overlay.set_overlay_pass_through(empty, True)
    card.pack_start(overlay, True, True, 0)
    return card


def metadata_labels(permission):
    return [label for field, label in (("metadata", "Entry metadata"), ("username", "Username"),
                                       ("url", "Stored URL")) if getattr(permission, field)]


class AccessView(Gtk.Box):
    TITLES = ("Requested", "Identity", "Project", "Status", "Last used")
    REQUESTED_TIME, LAST_USED_TIME, REVIEW_GROUP = 7, 8, 9

    def __init__(self, app):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        self.app = app
        header, _, _, _ = section_heading("Agent access", "changes-prevent-symbolic")
        tools = Gtk.Box(valign=Gtk.Align.CENTER)
        header.pack_end(tools, False, False, 0)
        self.review_button = button(tools, "Review or manage", self._open, icon="view-reveal-symbolic")
        self.review_button.set_sensitive(False)
        self.pack_start(header, False, False, 0)
        self.table, scroll = pane_table(
            Gtk.ListStore(*([str] * 7), object, object, bool), self.TITLES, (138, 122, 122, 119, 136),
            status=(3, ACCESS_STATES), muted_columns=(0, 4),
            sort_keys={0: self.REQUESTED_TIME, 4: self.LAST_USED_TIME}, sort_group=self.REVIEW_GROUP,
        )
        self.table.connect("row-activated", self._open)
        self.table.get_selection().connect("changed", lambda *_: self.review_button.set_sensitive(
            selected_key(self.table, 5) is not None))
        self.empty, _, _ = empty_state("changes-prevent-symbolic", "No access requests or tokens")
        self.pack_start(table_card(scroll, self.empty), True, True, 0)

    def refresh(self):
        grants = self.app.grants.rows() if self.app.grants else []
        edits = self.app.pending_edits()
        rows = []
        for grant in grants:
            other = grant.status != "pending"
            rows.append((other, -grant.requested,
                         (table_time(grant.requested), reported(grant.identity), reported(grant.project),
                          grant.status.capitalize(), table_time(grant.last_used), grant.id, "grant",
                          grant.requested, grant.last_used, other)))
        for edit in edits:
            state = "Edit pending" if edit.status == "pending" else "Applying edit"
            rows.append((False, -edit.requested,
                         (table_time(edit.requested), reported(edit.identity), reported(edit.project),
                          state, "—", f"{edit.token_id}/{edit.id}", "edit", edit.requested, None, False)))
        rows.sort()
        fill_table(self.table, [columns for _, _, columns in rows], 5)
        self.empty.set_visible(not rows)

    def _open(self, *_):
        model, selected = self.table.get_selection().get_selected()
        if selected is not None:
            self.open_record(*model[selected][5:7])

    def open_record(self, identifier, kind):
        if self.app.desktop.locked:
            return
        if kind == "edit":
            token_id, request_id = identifier.split("/")
            record = next((edit for edit in self.app.pending_edits()
                           if edit.token_id == token_id and edit.id == request_id), None)
            if record is not None:
                review_edit(self.app, record)
            return
        grant = self.app.grants.records.get(identifier)
        if grant:
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
            operations = metadata_labels(item)
            if item.action:
                operations.append(f"Credential action · {item.action}")
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
                    values = [f"Vault  {choice.scope.vault}{source}", f"Entry  {choice.scope.entry}"]
                    if choice.kind:
                        values.append(choice.kind.label)
                    for field, caption in ((choice.username, "Username"), (choice.url, "Stored URL"),
                                           (choice.destination, "GET")):
                        if field is not None:
                            values.append(f"{caption}  {field or '—'}")
                    label.set_text("\n".join(values))
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
            operations = metadata_labels(scope)
            if scope.action:
                binding = record.binding(scope.entry, scope.action) if record else None
                current = binding and binding.revision == scope.revision and binding.action.enabled
                if current:
                    operations.append(f"{scope.action} · {binding.action.kind.label} · {binding.action.url}")
                else:
                    operations.append(f"{scope.action} · Unavailable binding")
            add_label(scope_box, f"{record.name if record else 'Removed vault'} · {title}\n" +
                      f"{', '.join(operations)}\n{scope.vault} / {scope.entry}")
        response = self.app.run_dialog(dialog)
        if response == Gtk.ResponseType.REJECT:
            if self.app.confirm("Remove this token?", "The runner will need a fresh request and approval."):
                self.app.owner_operation(lambda: self.app.grants.transition(grant.id, "removed"))
        elif response == Gtk.ResponseType.APPLY:
            status = "disabled" if grant.status == "active" else "active"
            self.app.owner_operation(lambda: self.app.grants.transition(grant.id, status))


def activity_target(row):
    parts = (row.get("folder"), row.get("entry_title"))
    return " / ".join(part for part in parts if part) or "—"


def activity_location(row, workspace):
    """Prefer event-time labels and use exact current references for older rows."""
    fields = (("vault", "Vault"), ("folder", "Folder"), ("entry_title", "Entry"))
    values = {key: row.get(key) for key, _ in fields}
    vault_id, entry_id = row.get("vault_id"), row.get("entry")
    if workspace is not None and vault_id:
        with workspace.mutex:
            record = workspace.registrations.get(vault_id)
            if not values["vault"] and record:
                values["vault"] = f"{record.name} (current)"
            if record and entry_id and not (values["entry_title"] and values["folder"]):
                session = workspace.owner_session(vault_id)
                if session:
                    entry = next((item for item in session.entries if item["id"] == entry_id), None)
                    if entry:
                        path = " / ".join(name or "(Untitled folder)" for name in entry["group_path"]) or "Root"
                        values["folder"] = values["folder"] or f"{path} (current)"
                        title = entry["title"] or "(Untitled entry)"
                        values["entry_title"] = values["entry_title"] or f"{title} (current)"
    return tuple((caption, values[key]) for key, caption in fields)


def activity_facts(pairs):
    fields = tuple((caption, value) for caption, value in pairs if value is not None and value != "")
    if not fields:
        return None
    grid = Gtk.Grid(column_spacing=18, row_spacing=7)
    for index, (caption, value) in enumerate(fields):
        label = styled(Gtk.Label(label=caption, xalign=0, valign=Gtk.Align.START), "keeper-event-caption")
        label.set_width_chars(14)
        content = _label(str(value))
        content.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
        content.set_max_width_chars(56)
        content.set_hexpand(True)
        grid.attach(label, 0, index, 1, 1)
        grid.attach(content, 1, index, 1, 1)
    return grid


def add_activity_section(container, heading, pairs):
    facts = activity_facts(pairs)
    if facts is None:
        return
    section = styled(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8), "keeper-event-section")
    section.pack_start(styled(Gtk.Label(label=heading, xalign=0), "keeper-event-section-title"), False, False, 0)
    section.pack_start(facts, False, False, 0)
    container.pack_start(section, False, False, 0)


EDIT_FIELD_LABELS = {"title": "Title", "username": "Username", "url": "URL", "name": "Name"}


def activity_edit_fields(row):
    stage = row["action"].partition(" · ")[0]
    if stage not in ("Request edit", "Apply edit", "Deny edit", "Cancel edit"):
        return None
    for part in (row.get("scope") or "").split(" · "):
        if part.startswith("Fields "):
            fields = part.removeprefix("Fields ").split(",")
            labels = [EDIT_FIELD_LABELS[field.strip()] for field in fields if field.strip() in EDIT_FIELD_LABELS]
            if labels:
                caption = "Changed fields" if stage == "Apply edit" and row["outcome"] == "Succeeded" else "Proposed fields"
                return caption, ", ".join(dict.fromkeys(labels))
    return None


def activity_execution(row):
    requested, decided, completed = (_time(row[key]) if row.get(key) is not None else None
                                      for key in ("requested", "decided", "completed"))
    fields = activity_edit_fields(row)
    facts = (
        ("Destination", row.get("destination")), ("Authorization", row.get("decision")),
        ("HTTP status", row.get("status")), ("Decided", decided if decided not in (requested, completed) else None),
        ("Completed", completed if completed != requested else None),
    )
    return (fields, *facts) if fields else facts


def activity_dialog(app, row):
    dialog, body = _dialog(app, "Activity details", 640, -1)
    dialog.set_name("keeper-activity-detail")
    dialog.set_modal(True)
    dialog.add_button("Close", Gtk.ResponseType.CLOSE)
    dialog.set_default_response(Gtk.ResponseType.CLOSE)
    body.set_border_width(18)
    body.set_spacing(14)

    action = styled(_label(row["action"]), "keeper-event-title")
    action.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
    action.set_max_width_chars(52)
    body.pack_start(action, False, False, 0)
    timestamp = styled(_label(_time(row["requested"])), "keeper-event-caption")
    symbol, tone = ACTIVITY_STATES.get(row["outcome"], ("dialog-information-symbolic", "keeper_muted"))
    badge = styled(Gtk.Box(spacing=5), "keeper-event-badge", tone.replace("_", "-"))
    badge.pack_start(Gtk.Image.new_from_icon_name(symbol, Gtk.IconSize.BUTTON), False, False, 0)
    badge.pack_start(_label(row["outcome"]), False, False, 0)
    summary = Gtk.Box(spacing=10)
    summary.pack_start(badge, False, False, 0)
    summary.pack_start(timestamp, True, True, 0)
    body.pack_start(summary, False, False, 0)

    details = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=9, margin_end=6)
    scroll = _scroll(details)
    scroll.set_shadow_type(Gtk.ShadowType.NONE)
    scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scroll.set_propagate_natural_height(True)
    scroll.set_max_content_height(480)
    body.pack_start(scroll, True, True, 0)

    add_activity_section(details, "Target", activity_location(row, app.workspace))
    add_activity_section(details, "Request", (
        (caption, reported(row[key]) if row.get(key) else None)
        for key, caption in (("agent", "Agent"), ("project", "Project"), ("model", "Model"), ("chat", "Chat"))
    ))
    add_activity_section(details, "Execution", activity_execution(row))
    technical = activity_facts((
        ("Linux UID (verified)", row.get("uid")), ("Chat ID", row.get("chat_id")), ("Vault ID", row.get("vault_id")),
        ("Entry ID", row.get("entry")), ("Token record", row.get("token")), ("Recorded scope", row.get("scope")),
    ))
    if technical is not None:
        technical.set_margin_start(10)
        technical.set_margin_top(8)
        disclosure = Gtk.Expander(label="Technical details")
        disclosure.set_margin_top(3)
        disclosure.add(technical)
        technical.show_all()
        technical.set_no_show_all(True)
        technical.hide()
        disclosure.connect("notify::expanded", lambda control, _: technical.set_visible(control.get_expanded()))
        details.pack_start(disclosure, False, False, 0)
    return dialog


class ActivityView(Gtk.Box):
    TITLES = ("Time", "Model", "Chat", "Action", "Vault", "Target", "Outcome")
    RECORD_ID = len(TITLES)
    REQUESTED_TIME = RECORD_ID + 1

    def __init__(self, app):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        self.app = app
        self.rows = {}
        header, _, _, _ = section_heading("Activity", "document-open-recent-symbolic")
        tools = Gtk.Box(valign=Gtk.Align.CENTER)
        header.pack_end(tools, False, False, 0)
        filters = Gtk.Grid(column_spacing=8, row_spacing=8, margin=12)
        self.filters = {}
        for index, name in enumerate(("Vault", "Agent", "Model", "Chat", "Action", "Outcome")):
            field = styled(Gtk.SearchEntry(placeholder_text=name, hexpand=True), "keeper-search")
            field.connect("search-changed", self.refresh)
            filters.attach(field, index % 3, index // 3, 1, 1)
            self.filters[name.lower()] = field
        self.filter_panel = styled(Gtk.Revealer(transition_type=Gtk.RevealerTransitionType.SLIDE_DOWN), "keeper-card")
        self.filter_panel.add(filters)
        filters.show_all()
        self.filter_panel.set_visible(False)
        self.filter_panel.set_no_show_all(True)
        self.filter_panel.connect("notify::child-revealed", self._filters_revealed)
        button(tools, "Filters", self._toggle_filters, icon="system-search-symbolic")
        self.pack_start(header, False, False, 0)
        self.pack_start(self.filter_panel, False, False, 0)
        self.table, scroll = pane_table(
            Gtk.ListStore(*([str] * (self.RECORD_ID + 1)), object), self.TITLES,
            (140, 70, 68, 104, 75, 174, 147), status=(6, ACTIVITY_STATES),
            expand_columns=(1, 2, 3, 4, 5), muted_columns=(0,), sort_keys={0: self.REQUESTED_TIME},
        )
        self.table.connect("row-activated", self._details)
        self.empty, self.empty_label, _ = empty_state("document-open-recent-symbolic", "No activity recorded")
        self.pack_start(table_card(scroll, self.empty), True, True, 0)

    def _toggle_filters(self, *_):
        opened = self.filter_panel.get_reveal_child()
        self.filter_panel.set_visible(True)
        self.filter_panel.set_reveal_child(not opened)
        if not opened:
            self.filters["vault"].grab_focus()

    def _filters_revealed(self, panel, _property):
        if not panel.get_reveal_child() and not panel.get_child_revealed():
            panel.hide()

    def refresh(self, *_):
        try:
            rows = self.app.activity.rows(**{name: field.get_text() for name, field in self.filters.items()})
        except ActivityError:
            rows = []
        self.rows = {str(row["id"]): row for row in rows}
        fill_table(self.table, [
            (table_time(row["requested"]), reported(row["model"]), reported(row["chat"]), row["action"],
             row.get("vault") or "—", activity_target(row), row["outcome"], str(row["id"]), row["requested"])
            for row in rows
        ], self.RECORD_ID)
        filtered = any(field.get_text() for field in self.filters.values())
        self.empty_label.set_text("No activity matches these filters" if filtered else "No activity recorded")
        self.empty.set_visible(not rows)

    def _details(self, *_):
        self.open_record(selected_key(self.table, self.RECORD_ID))

    def open_record(self, identifier):
        row = self.rows.get(identifier)
        if row and not self.app.desktop.locked:
            self.app.run_dialog(activity_dialog(self.app, row))


EDIT_ENTRY_RESPONSE = 1
RECYCLE_ENTRY_RESPONSE = 2


def entry_details(app, vault, entry):
    group = app.selection[1]
    while app.workspace.owner_session(vault) and not app.desktop.locked and not app.busy:
        record = app.workspace.registrations[vault]
        dialog, body = _dialog(app, entry["title"] or "(Untitled entry)", 710, 420)
        dialog.set_modal(True)
        dialog.add_buttons("Close", Gtk.ResponseType.CLOSE, "Add action", Gtk.ResponseType.APPLY,
                           "Edit action", Gtk.ResponseType.ACCEPT, "Remove action", Gtk.ResponseType.REJECT)
        add_label(body, f"{record.name} · {' / '.join(entry['group_path']) or 'Root'}\nEntry  {entry['id']}")
        add_label(body, f"Username  {entry['username'] or '—'}\nURL  {entry['url'] or '—'}")
        add_label(body, f"Created  {_time(entry.get('created'))}\nModified  {_time(entry.get('modified'))}")
        entry_actions = Gtk.Box(spacing=8)
        button(entry_actions, "Copy entry reference", lambda *_: app.copy_reference(vault, "entry", entry["id"]))
        button(entry_actions, "Edit entry…", lambda *_: dialog.response(EDIT_ENTRY_RESPONSE))
        button(entry_actions, "Move entry to recycle bin…", lambda *_: dialog.response(RECYCLE_ENTRY_RESPONSE))
        body.pack_start(entry_actions, False, False, 0)
        add_label(body, "Credential actions")
        store = Gtk.ListStore(str, str, str, str, str)
        for binding in record.bindings:
            action = binding.action
            if action.entry == entry["id"]:
                store.append((action.id, action.name, action.kind.label, action.url,
                              "Enabled" if action.enabled else "Disabled"))
        table = _table(store, ("ID", "Name", "Type", "Destination", "Status"))
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
        if response == EDIT_ENTRY_RESPONSE:
            edit_entry(app, vault, entry["group"], entry)
            return
        if response == RECYCLE_ENTRY_RESPONSE:
            recycle_entry(app, vault, group, entry)
            return
        if response == Gtk.ResponseType.REJECT and identifier:
            if app.confirm("Remove this action?", "Existing tokens will lose permission to run this binding."):
                app.owner_operation(lambda: app.workspace.remove_binding(vault, entry["id"], identifier))
        elif response in (Gtk.ResponseType.ACCEPT, Gtk.ResponseType.APPLY):
            previous = record.binding(entry["id"], identifier) if response == Gtk.ResponseType.ACCEPT else None
            edit_binding(app, vault, entry["id"], previous)
        else:
            return


def edit_binding(app, vault, entry, previous):
    dialog, body = _dialog(app, "Credential action", 560, 300)
    dialog.set_modal(True)
    dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Save", Gtk.ResponseType.OK)
    add_label(body, "Type")
    kind = Gtk.ComboBoxText()
    kind.set_name("action-kind")
    for option in ActionType:
        kind.append(option.value, option.label)
    kind.set_active_id(previous.action.kind.value if previous else ActionType.BASIC.value)
    body.pack_start(kind, False, False, 0)
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
            action = Action(identifier, name, entry, url, enabled.get_active(), kind=kind.get_active_id())
            app.workspace.save_binding(vault, action, previous.action.id if previous else None)
        app.owner_operation(save)
