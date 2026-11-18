"""GTK views for request review, entry actions, and local activity."""

from collections import Counter
from dataclasses import dataclass
from math import ceil
from shlex import join, split
from time import monotonic

from gi.repository import GLib, Gtk, Pango

from .access_settings import Action, ActionType, BrowserForm, HTTPS_METHODS, HTTPS_WRITE_METHODS
from .activity import ActivityError
from .activity_grouping import EDIT_STAGES, ActivityResources, activity_groups, activity_matches, event_time
from .command_action import executable_digest
from .edit_request_view import review_edit
from .grants import CREDENTIAL_USES, EDIT_PERMISSIONS, group_location
from .owner_views import _dialog, _label, _scroll, _table, _time, require_mouse_decisions, table_time
from .workspace_context import DELETE_LABEL, attach_row_context
from .workspace_editor import delete_entry, edit_entry
from .workspace_style import styled


def reported(value):
    return f"{value} (reported)" if value else "—"


def add_label(container, text):
    container.pack_start(_label(text), False, False, 0)


def locked_review_vaults(workspace, items):
    requested = {item.vault for item in items}
    return (record for identifier, record in workspace.registrations.items()
            if (None in requested or identifier in requested) and workspace.session(identifier) is None)


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
        sorting.replace_rows(table, sorting.visible_rows(), key_column)


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
    def __init__(self, sort_keys, sort_group, replace_rows=_replace_rows):
        self.sort_keys = sort_keys or {}
        self.sort_group = sort_group
        self.replace_rows = replace_rows
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
            self.replace_rows(table, self.visible_rows(), self.key_column)


def section_heading(title, icon):
    header = Gtk.Box(spacing=13)
    mark = styled(Gtk.Box(valign=Gtk.Align.CENTER), "keeper-section-icon")
    image = Gtk.Image.new_from_icon_name(icon, Gtk.IconSize.LARGE_TOOLBAR)
    mark.pack_start(image, False, False, 0)
    header.pack_start(mark, False, False, 0)
    titles = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1, valign=Gtk.Align.CENTER)
    header.pack_start(titles, True, True, 0)
    breadcrumb = styled(
        Gtk.Label(label=" ", xalign=0, ellipsize=Pango.EllipsizeMode.START, single_line_mode=True), "keeper-muted",
    )
    titles.pack_start(breadcrumb, False, False, 0)
    label = styled(Gtk.Label(label=title, xalign=0, ellipsize=Pango.EllipsizeMode.END), "keeper-title")
    titles.pack_start(label, False, False, 0)
    return header, breadcrumb, label, image


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
               time_columns=None, text_renderers=None, icon_columns=None, full_text_columns=(),
               indent_rows=False, sort_group=None, replace_rows=_replace_rows):
    time_columns = time_columns or {}
    text_renderers = text_renderers or {}
    icon_columns = icon_columns or {}
    table = styled(Gtk.TreeView(model=model), "keeper-table")
    table.keeper_sort = TableSort(time_columns, sort_group, replace_rows)
    table.set_grid_lines(Gtk.TreeViewGridLines.HORIZONTAL)
    for index, title in enumerate(titles):
        column = Gtk.TreeViewColumn(title)
        column.set_clickable(True)
        column.connect("clicked", table.keeper_sort.click, table, index)
        column.set_resizable(True)
        column.set_expand(index in expand_columns)
        column.set_min_width(widths[index])
        if indent_rows and index != 0:
            spacer = Gtk.CellRendererPixbuf(visible=False)
            column.pack_start(spacer, False)
            column.set_cell_data_func(spacer, _indent_cell, table)
        full_text = index in time_columns or index in full_text_columns
        ellipsize = Pango.EllipsizeMode.NONE if full_text else Pango.EllipsizeMode.END
        renderer = text_renderers.get(index, Gtk.CellRendererText)
        text = renderer(xpad=10, ypad=9, ellipsize=ellipsize)
        colored = status is not None and index == status[0]
        leading = index == 0 and lead_icon
        if colored or leading or index in icon_columns:
            icon = Gtk.CellRendererPixbuf(xpad=5, stock_size=Gtk.IconSize.MENU)
            column.pack_start(icon, False)
            if colored:
                column.set_cell_data_func(icon, _status_icon, status)
            elif index in icon_columns:
                column.add_attribute(icon, "icon-name", icon_columns[index])
            else:
                icon.set_property("icon-name", lead_icon)
            text.set_property("xpad", 3)
            if colored or leading:
                text.set_property("weight", Pango.Weight.SEMIBOLD)
        column.pack_start(text, True)
        column.add_attribute(text, "text", index)
        if colored or index in muted_columns:
            column.set_cell_data_func(text, _table_text_color, (table, status if colored else None))
        table.append_column(column)
    scroll = _scroll(table)
    scroll.set_shadow_type(Gtk.ShadowType.NONE)
    return table, scroll


def _indent_cell(_column, spacer, model, row, table):
    is_child = model.iter_parent(row) is not None
    spacer.set_visible(is_child)
    if is_child:
        # Match one level of GTK 3 indentation in the expander column.
        step = table.style_get_property("expander-size") + table.style_get_property("horizontal-separator") // 2
        spacer.set_fixed_size(step + table.get_level_indentation(), 0)


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
    "Permission Change Pending": ("appointment-soon-symbolic", "keeper_warning"),
    "Edit Pending": ("appointment-soon-symbolic", "keeper_warning"),
    "Applying Edit": ("content-loading-symbolic", "keeper_accent"),
    "Usage Pending": ("appointment-soon-symbolic", "keeper_warning"),
    "Active": ("emblem-default-symbolic", "keeper_success"),
    "Disabled": ("action-unavailable-symbolic", "keeper_muted"),
}
ACTIVITY_STATES = {
    "Approved": ("emblem-ok-symbolic", "keeper_success"),
    "Succeeded": ("emblem-ok-symbolic", "keeper_success"),
    "Acknowledged · result unavailable": ("dialog-warning-symbolic", "keeper_warning"),
    "Results Not Delivered": ("dialog-warning-symbolic", "keeper_warning"),
    "Dispatched": ("mail-send-symbolic", "keeper_accent"),
    "Pending approval": ("appointment-soon-symbolic", "keeper_warning"),
    "Pending review": ("appointment-soon-symbolic", "keeper_warning"),
    "Expired": ("appointment-soon-symbolic", "keeper_muted"),
    "Stale": ("action-unavailable-symbolic", "keeper_muted"),
    "Failed": ("dialog-error-symbolic", "keeper_failure"),
    "Denied": ("action-unavailable-symbolic", "keeper_failure"),
    "Paused": ("media-playback-pause-symbolic", "keeper_warning"),
    "Disabled": ("action-unavailable-symbolic", "keeper_muted"),
    "Removed": ("user-trash-symbolic", "keeper_muted"),
    "Released": ("changes-prevent-symbolic", "keeper_muted"),
    "Revoked": ("action-unavailable-symbolic", "keeper_muted"),
    "Rate limited": ("appointment-soon-symbolic", "keeper_warning"),
}


ACTIVITY_ACTION_ICONS = {
    "List vaults": "drive-harddisk-symbolic",
    "List entries": "view-list-symbolic",
    "Use password": "dialog-password-symbolic",
    "Request token": "dialog-question-symbolic",
    "Approve token": "changes-allow-symbolic",
    "Deny token": "changes-prevent-symbolic",
    "Request token permissions": "dialog-question-symbolic",
    "Approve token permissions": "changes-allow-symbolic",
    "Deny token permissions": "changes-prevent-symbolic",
    "Disable token": "changes-prevent-symbolic",
    "Re-enable token": "changes-allow-symbolic",
    "Remove token": "user-trash-symbolic",
    "Release entry access": "changes-prevent-symbolic",
}


def table_card(scroll, empty):
    card = styled(Gtk.Box(orientation=Gtk.Orientation.VERTICAL), "keeper-card", "keeper-table-card")
    overlay = Gtk.Overlay()
    overlay.add(scroll)
    overlay.add_overlay(empty)
    overlay.set_overlay_pass_through(empty, True)
    card.pack_start(overlay, True, True, 0)
    return card


def metadata_labels(permission):
    return [label for field, label in (("metadata", "Entry Metadata"), ("username", "Username"),
                                       ("url", "Stored URL")) if getattr(permission, field)]


def credential_use_labels(permission):
    result = []
    for use in permission.uses:
        if use == "local_command":
            detail = "Runs isolated with no writable host files or network. Command output and exit status stay private."
        elif use == "https":
            detail = ("Can authenticate reads, writes and deletes at these destinations, within the credential’s service permissions.\n"
                      + "\n".join(permission.origins))
        elif use == "https_body":
            detail = ("The credential can be sent in an API request body and may be stored or published by the approved service.\n"
                      + "\n".join(permission.origins))
        elif use == "https_results":
            detail = ("Releases selected scalar fields from the approved service. Resource writes also require HTTPS-use permission. Login responses and captured authentication tickets stay private. Approve only endpoints and fields you trust.\n"
                      + "\n".join(permission.origins))
        elif use == "networked_command":
            detail = ("Can send the credential to these approved TCP peers and ports. The command controls protocol and TLS verification. Shared addresses can host multiple services or tenants. Command output and exit status stay private.\n"
                      + "\n".join(permission.origins))
        else:
            detail = "Approved Destinations:\n" + "\n".join(permission.origins)
        result.append((CREDENTIAL_USES[use], detail))
    return tuple(result)


def token_permissions(record, scopes):
    labels = []
    for scope in scopes:
        labels.extend(metadata_labels(scope))
        labels.extend(EDIT_PERMISSIONS[operation] for operation in scope.edits)
        labels.extend(CREDENTIAL_USES[use] for use in scope.uses)
        if scope.uses and (record is None or scope.use_revision != record.credential_revision(scope.entry)):
            labels.append("Credential Changed — Owner Review Required")
        if scope.origins:
            labels.append("Approved Destinations: " + "; ".join(scope.origins))
        if scope.action:
            binding = record.binding(scope.entry, scope.action) if record else None
            if binding and binding.revision == scope.revision and binding.action.enabled:
                labels.append(f"{binding.action.name} ({binding.action.type_label})")
            else:
                labels.append(f"{scope.action} (action unavailable)")
    return ", ".join(dict.fromkeys(labels))


@dataclass(frozen=True)
class ApprovedResource:
    key: tuple
    parent: tuple | None
    name: str
    icon: str
    permissions: str = ""


def approved_resources(workspace, scopes, snapshots):
    by_vault = {}
    for scope in scopes:
        target = ("group", scope.group) if scope.group is not None else ("entry", scope.entry)
        by_vault.setdefault(scope.vault, {}).setdefault(target, []).append(scope)

    resources = {}
    needs_unlock = False
    with workspace.mutex:
        for vault_id, permissions in by_vault.items():
            if vault_id not in snapshots:
                record = workspace.registrations.get(vault_id)
                session = workspace.owner_session(vault_id) if record else None
                entries = {row["id"]: row for row in session.entries} if session else {}
                groups = {row["id"]: row for row in session.groups} if session else {}
                snapshots[vault_id] = record, bool(session), entries, groups
            record, unlocked, entries, groups = snapshots[vault_id]
            locked = record is not None and not unlocked
            needs_unlock |= locked
            title = record.name if record else "Removed database"
            if locked:
                title += " · Locked"
            vault = ("vault", vault_id)
            resources[vault] = ApprovedResource(vault, None, title, "drive-harddisk-symbolic")
            for index, ((kind, identifier), approved) in enumerate(permissions.items(), 1):
                if kind == "group":
                    if identifier in groups:
                        name = " / ".join(group_location(tuple(groups.values()), identifier)) or "Root"
                    else:
                        name = f"Group {index}" if locked else "Group unavailable"
                    key = ("group-scope", vault_id, identifier)
                    resources[key] = ApprovedResource(key, vault, name, "folder-symbolic", token_permissions(record, approved))
                    continue
                entry_id = identifier
                entry = entries.get(entry_id)
                parent = vault
                if entry is None:
                    name = f"Entry {index}" if locked else "Entry unavailable"
                else:
                    path = []
                    group = groups.get(entry["group"])
                    while group and group["parent"] is not None:
                        path.append(group)
                        group = groups.get(group["parent"])
                    for group in reversed(path):
                        key = ("group", vault_id, group["id"])
                        if key not in resources:
                            name = group["name"] or "(Untitled group)"
                            resources[key] = ApprovedResource(key, parent, name, "folder-symbolic")
                        parent = key
                    name = entry["title"] or "(Untitled entry)"
                key = ("entry", vault_id, entry_id)
                resources[key] = ApprovedResource(
                    key, parent, name, "dialog-password-symbolic", token_permissions(record, approved),
                )
    return tuple(resources.values()), needs_unlock


def approved_entries_tree(workspace, scopes):
    resources, needs_unlock = approved_resources(workspace, scopes, {})
    model = Gtk.TreeStore(str, str, str)
    nodes = {}
    for item in resources:
        nodes[item.key] = model.append(nodes.get(item.parent), (item.name, item.permissions, item.icon))

    tree = Gtk.TreeView(model=model, enable_tree_lines=True)
    tree.get_selection().set_mode(Gtk.SelectionMode.NONE)
    target = Gtk.TreeViewColumn("Database / Group / Entry")
    icon = Gtk.CellRendererPixbuf(xpad=5)
    target.pack_start(icon, False)
    target.add_attribute(icon, "icon-name", 2)
    name = Gtk.CellRendererText(ypad=6, ellipsize=Pango.EllipsizeMode.END)
    target.pack_start(name, True)
    target.add_attribute(name, "text", 0)
    target.set_min_width(255)
    target.set_resizable(True)
    target.set_expand(True)
    tree.append_column(target)
    permissions = Gtk.CellRendererText(ypad=6, wrap_width=295, wrap_mode=Pango.WrapMode.WORD_CHAR)
    tree.append_column(Gtk.TreeViewColumn("Permissions", permissions, text=1))
    tree.expand_all()
    return tree, needs_unlock


class AccessIdentityRenderer(Gtk.CellRendererText):
    inline_scope = False

    def do_render(self, cr, widget, background_area, cell_area, flags):
        if not self.inline_scope:
            Gtk.CellRendererText.do_render(self, cr, widget, background_area, cell_area, flags)


class AccessView(Gtk.Box):
    TITLES = ("Requested", "Last Used", "Identity", "Model", "Project", "Chat", "Status")
    IDENTITY, PROJECT = 2, 4
    STATUS, RECORD_ID, KIND = 6, 7, 8
    REQUESTED_TIME, LAST_USED_TIME, REVIEW_GROUP = 9, 10, 11
    ROW_KEY, SEPARATOR_OFFSETS = 12, 13
    REMOVE = "Remove Token…"

    def __init__(self, app):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        self.app = app
        header, _, _, _ = section_heading("Agent Access", "changes-prevent-symbolic")
        tools = Gtk.Box(valign=Gtk.Align.CENTER)
        header.pack_end(tools, False, False, 0)
        self.next_review = button(tools, "Review Next", self._open_next, icon="appointment-soon-symbolic")
        self.next_review.set_sensitive(False)
        self.review_button = button(tools, "Open Details", self._open, icon="view-reveal-symbolic")
        self.review_button.set_sensitive(False)
        self.pack_start(header, False, False, 0)
        self.table, scroll = pane_table(
            Gtk.TreeStore(*([str] * 9), object, object, bool, object, object, object),
            self.TITLES, (138, 138, 122, 106, 109, 106, 119),
            status=(self.STATUS, ACCESS_STATES), muted_columns=(0, 1), expand_columns=(2, 3, 4, 5),
            time_columns={0: self.REQUESTED_TIME, 1: self.LAST_USED_TIME},
            text_renderers={self.IDENTITY: AccessIdentityRenderer}, full_text_columns=(self.STATUS,), indent_rows=True,
            sort_group=self.REVIEW_GROUP, replace_rows=replace_tree_rows,
        )
        self.table.set_enable_tree_lines(True)
        self.table.set_expander_column(self.table.get_column(0))
        identity = self.table.get_column(self.IDENTITY)
        identity.set_cell_data_func(identity.get_cells()[-1], self._scope_label)
        self.table.connect_after("draw", self._draw_scope_labels)
        self.table.connect("row-activated", self._open)
        attach_row_context(self.table, self._context, destructive_labels=(self.REMOVE,))
        self.table.get_selection().connect("changed", lambda *_: self.review_button.set_sensitive(
            bool(selected_key(self.table, self.RECORD_ID))))
        self.empty, _, _ = empty_state("changes-prevent-symbolic", "No access requests or tokens")
        self.pack_start(table_card(scroll, self.empty), True, True, 0)

    def refresh(self):
        grants = self.app.grants.rows() if self.app.grants else []
        edits = self.app.pending_edits()
        rows = []
        snapshots = {}
        for grant in grants:
            change = grant.pending_change
            other = grant.status != "pending" and not change
            scope = self._scope_rows(grant, snapshots) if grant.status == "active" or other else ()
            requested = change.requested if change else grant.requested
            context = change.context if change else grant.context
            state = "Permission Change Pending" if change else grant.status.capitalize()
            identifier, kind = (f"{grant.id}/{change.id}", "grant-change") if change else (grant.id, "grant")
            rows.append((bool(other), -requested,
                         (table_time(requested), table_time(grant.last_used),
                          reported(grant.identity), reported(context.model), reported(grant.project),
                          reported(context.chat), state, identifier, kind,
                          requested, grant.last_used, bool(other), ("grant", grant.id), (), scope)))
        for edit in edits:
            state = "Edit Pending" if edit.status == "pending" else "Applying Edit"
            rows.append((False, -edit.requested,
                         (table_time(edit.requested), "—", reported(edit.identity),
                          reported(edit.context.model if edit.context else None), reported(edit.project),
                          reported(edit.context.chat if edit.context else None),
                          state, f"{edit.token_id}/{edit.id}", "edit", edit.requested, None,
                          False, ("edit", edit.token_id, edit.id), (), ())))
        for ticket in self.app.usage_approvals.pending():
            identifier = str(ticket.id)
            rows.append((False, -ticket.requested,
                         (table_time(ticket.requested), "—", reported(ticket.identity),
                          reported(ticket.context.model), reported(ticket.project), reported(ticket.context.chat),
                          "Usage Pending", identifier, "usage", ticket.requested, None,
                          False, ("usage", identifier), (), ())))
        rows.sort()
        fill_table(self.table, [columns for _, _, columns in rows], self.ROW_KEY)
        self.empty.set_visible(not rows)
        pending = len(self.app._review_requests())
        self.next_review.set_sensitive(bool(pending) and not self.app.busy and not self.app.desktop.locked)
        self.next_review.set_label(f"Review Next ({pending})" if pending else "Review Next")

    def _scope_label(self, _column, cell, model, iterator, *_):
        cell.inline_scope = model[iterator][self.KIND] == "scope"

    def _draw_scope_labels(self, table, cr):
        window = table.get_bin_window()
        visible = table.get_visible_range()
        if not window or not visible or not Gtk.cairo_should_draw_window(cr, window):
            return
        first, last = visible
        first_token = first.get_indices()[0]

        # Scope rows have no timestamps. Draw their accessible path across those
        # empty cells up to Project, where the approved permissions are shown.
        cr.save()
        Gtk.cairo_transform_to_window(cr, table, window)
        selection = table.get_selection()
        context = table.get_style_context()
        found, surface = context.lookup_color("keeper_surface")
        light_surface = found and (0.2126 * surface.red + 0.7152 * surface.green + 0.0722 * surface.blue) >= 0.5
        palette = "keeper_separator_on_light" if light_surface else "keeper_separator_on_dark"
        found, green = context.lookup_color(palette)
        separator_rgb = tuple(round(channel * 65535) for channel in (green.red, green.green, green.blue)) if found else None
        first_column, project = table.get_column(0), table.get_column(self.PROJECT)
        for token in table.get_model():
            path = token.path
            if path.compare(last) > 0:
                break
            if path.get_indices()[0] < first_token or not table.row_expanded(path):
                continue
            for row in token.iterchildren():
                path = row.path
                if path.compare(first) < 0 or path.compare(last) > 0:
                    continue
                line = table.get_cell_area(path, first_column)
                cell = table.get_cell_area(path, project)
                x = line.x + 6
                width = cell.x - x - 10
                if width <= 0:
                    continue
                layout = table.create_pango_layout(row[self.IDENTITY])
                if separator_rgb is not None:
                    attributes = Pango.AttrList()
                    for offset in row[self.SEPARATOR_OFFSETS]:
                        color = Pango.attr_foreground_new(*separator_rgb)
                        color.start_index, color.end_index = offset, offset + 1
                        attributes.insert(color)
                    layout.set_attributes(attributes)
                layout.set_width(width * Pango.SCALE)
                layout.set_ellipsize(Pango.EllipsizeMode.END)
                layout.set_single_paragraph_mode(True)
                _, height = layout.get_pixel_size()
                state = table.get_state_flags()
                if selection.iter_is_selected(row.iter):
                    state |= Gtk.StateFlags.SELECTED
                context.save()
                context.set_state(state)
                Gtk.render_layout(context, cr, x, cell.y + (cell.height - height) // 2, layout)
                context.restore()
        cr.restore()

    def _scope_rows(self, grant, snapshots):
        resources, _ = approved_resources(self.app.workspace, grant.scope, snapshots)
        paths = {}
        rows = []
        for item in resources:
            parent = paths.get(item.parent, ())
            if item.key[0] not in ("entry", "group-scope"):
                paths[item.key] = (*parent, item.name)
                continue
            vault, *groups = parent
            prefix = vault if item.key[0] == "group-scope" else f"{vault} > {' / '.join(groups) or '—'}"
            label = f"{prefix} > {item.name}"
            parts = (vault,) if item.key[0] == "group-scope" else (vault, prefix)
            separators = tuple(len(part.encode("utf-8")) + 1 for part in parts)
            rows.append(("", "", label, "", item.permissions, "", "", "", "scope", None, None, True,
                         (grant.id, *item.key), separators, ()))
        return tuple(rows)

    def _open(self, *_):
        model, selected = self.table.get_selection().get_selected()
        if selected is not None:
            row = model[selected]
            if row[self.RECORD_ID]:
                self.open_record(row[self.RECORD_ID], row[self.KIND])

    def _open_next(self, *_):
        pending = self.app._review_requests()
        if pending and not self.app.busy and self.app.dialog is None:
            kind, identifier = pending[0]
            self.open_record(identifier, kind)

    def _context(self, row):
        state = row[self.STATUS]
        if self.app.desktop.locked or state == "Applying Edit":
            return []
        identifier, kind = row[self.RECORD_ID], row[self.KIND]
        if not identifier:
            return []

        def open_selected():
            self.open_record(identifier, kind)

        if kind == "edit":
            return [[("Review Edit…", open_selected)]]
        if kind == "grant-change":
            grant_id, _, _ = identifier.partition("/")
            def current_permissions():
                self.open_record(grant_id, "grant")
            return [
                [("Review Permission Change…", open_selected), ("View Current Permissions…", current_permissions)],
                [("Disable Token", lambda: self._update_token(grant_id, "disabled")),
                 (self.REMOVE, lambda: self._update_token(grant_id, "removed"))],
            ]
        if state in ("Pending", "Usage Pending"):
            return [[("Review Request…", open_selected)]]
        change = "disabled" if state == "Active" else "active"
        label = "Disable Token" if state == "Active" else "Re-enable Token"
        return [
            [("View Permissions…", open_selected), (label, lambda: self._update_token(identifier, change))],
            [(self.REMOVE, lambda: self._update_token(identifier, "removed"))],
        ]

    def open_record(self, identifier, kind, *, automatic=False):
        if self.app.desktop.locked:
            return
        if kind == "usage":
            ticket = next((request for request in self.app.usage_approvals.pending()
                           if str(request.id) == identifier), None)
            if ticket:
                self.app.review_popups.mark_reviewed(kind, identifier)
                self._review_usage(ticket, standalone=automatic)
            return
        if kind == "edit":
            token_id, _, request_id = identifier.partition("/")
            record = next((edit for edit in self.app.pending_edits()
                           if edit.token_id == token_id and edit.id == request_id), None)
            if record is not None and record.status == "pending" and not self.app.busy:
                self.app.review_popups.mark_reviewed(kind, identifier)
                review_edit(self.app, record, standalone=automatic)
            return
        grant_id, _, change_id = identifier.partition("/")
        grant = self.app.grants.records.get(grant_id) if self.app.grants else None
        if kind == "grant-change":
            if grant and grant.pending_change and grant.pending_change.id == change_id:
                self.app.review_popups.mark_reviewed(kind, identifier)
                self._review(grant, grant.pending_change, standalone=automatic)
            return
        if grant:
            if grant.status == "pending":
                self.app.review_popups.mark_reviewed(kind, identifier)
                self._review(grant, standalone=automatic)
            elif not automatic:
                self._manage(grant)

    def _review_usage(self, ticket, *, standalone=False):
        queue = self.app.usage_approvals
        if ticket.opens_console:
            title = "Review Guest Console"
        elif ticket.guest_command:
            title = "Review Guest Commands"
        elif ticket.workflow_review:
            title = "Review Workflow"
        else:
            title = "Review HTTPS Write" if ticket.write_once else "Review Agent Usage"
        dialog, body = _dialog(self.app, title, 620, -1)
        dialog.set_name("keeper-access-review")
        dialog.set_position(Gtk.WindowPosition.CENTER_ON_PARENT)
        dialog.set_modal(True)
        if ticket.reuse_minutes:
            approve_label = f"Allow for {ticket.reuse_minutes} min"
        elif ticket.opens_console:
            approve_label = "Open Console"
        elif ticket.guest_command:
            approve_label = "Run Command Once"
        elif ticket.workflow_review:
            approve_label = "Approve Workflow"
        else:
            approve_label = "Approve Write Once" if ticket.write_once else (
                "Approve and Trust Certificate" if ticket.trusts_certificate else "Approve Once")
        dialog.add_buttons("Deny", Gtk.ResponseType.REJECT, approve_label, Gtk.ResponseType.ACCEPT)
        dialog.connect("key-press-event", lambda *_: True)
        dialog.connect("key-release-event", lambda *_: True)
        require_mouse_decisions(dialog)
        styled(dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT), "keeper-access-approve")
        styled(dialog.get_widget_for_response(Gtk.ResponseType.REJECT), "keeper-access-deny")
        add_label(body, "Requested by · agent-reported")
        body.pack_start(styled(_label(ticket.identity), "keeper-access-agent"), False, False, 0)
        add_label(body, ticket.project)
        if ticket.opens_console:
            add_label(body, "Allow screenshots and input for the guest shown below.")
        elif ticket.guest_command:
            add_label(body, "Allow any command at this endpoint during the approved window." if ticket.reuse_minutes else
                      "Run the command shown below and allow the agent to check its result.")
        elif ticket.write_once:
            add_label(body, "This request changes data on the destination. Review the method, path and request body below.")
        if ticket.write_once or ticket.opens_console or ticket.guest_command or ticket.workflow_review:
            if ticket.context.note:
                add_label(body, ticket.context.note)
        details = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        add_activity_section(details, ticket.action, (("Scope", "\n".join(ticket.scope) or "No vaults in scope"),
                                                     ("Destination", ticket.destination)))
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_propagate_natural_height(True)
        scroll.set_max_content_height(360)
        scroll.add(details)
        body.pack_start(scroll, True, True, 0)
        if ticket.opens_console:
            add_label(body, "The same connection can be reopened during this window. "
                      "Pause agent access or lock the vault before reassigning this console target."
                      if ticket.reuse_minutes else "Approval applies to this console session.")
        elif ticket.guest_command:
            add_label(body, "The command approval also covers its status checks and the listed result fields.")
        elif ticket.workflow_review:
            add_label(body, "The agent can run the listed operations after approval.")
        else:
            add_label(body, "Approves this operation and remembers its verified certificate for this token and resource."
                      if ticket.trusts_certificate else "Approval applies to this operation only.")
        remaining = Gtk.Label(xalign=0)
        body.pack_start(styled(remaining, "keeper-event-caption"), False, False, 0)

        def check_pending():
            if ticket not in queue.pending():
                dialog.response(Gtk.ResponseType.CANCEL)
            else:
                remaining.set_text(f"Expires in {max(0, ceil(ticket.expires - monotonic()))} seconds")
            return GLib.SOURCE_CONTINUE

        check_pending()
        watch = GLib.timeout_add(200, check_pending)
        try:
            response = self.app.run_dialog(dialog, standalone=standalone)
        finally:
            GLib.source_remove(watch)
        if response in (Gtk.ResponseType.ACCEPT, Gtk.ResponseType.REJECT):
            queue.resolve(ticket.id, response == Gtk.ResponseType.ACCEPT)
            self.app._refresh()

    def _review(self, grant, change=None, *, standalone=False):
        request = change or grant
        title = "Review Token Permission Change" if change else "Review Access Request"
        dialog, body = _dialog(self.app, title, 620, -1)
        dialog.set_name("keeper-access-review")
        dialog.set_position(Gtk.WindowPosition.CENTER_ON_PARENT)
        dialog.set_modal(True)
        dialog.add_buttons("Deny", Gtk.ResponseType.REJECT, "Approve", Gtk.ResponseType.ACCEPT)
        dialog.connect("key-press-event", lambda *_: True)
        dialog.connect("key-release-event", lambda *_: True)
        require_mouse_decisions(dialog)
        approve = styled(dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT), "keeper-access-approve")
        styled(dialog.get_widget_for_response(Gtk.ResponseType.REJECT), "keeper-access-deny")
        styled(dialog.get_action_area(), "keeper-access-footer")
        resume_label = "Resume Access and Approve"

        body.set_border_width(20)
        body.set_spacing(14)
        requester = Gtk.Box(spacing=12)
        badge = Gtk.Image.new_from_icon_name("avatar-default-symbolic", Gtk.IconSize.LARGE_TOOLBAR)
        badge.set_valign(Gtk.Align.CENTER)
        requester.pack_start(styled(badge, "keeper-access-agent-icon"), False, False, 0)
        identity = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        requester.pack_start(identity, True, True, 0)
        identity.pack_start(styled(_label("Requested by · agent-reported"), "keeper-event-caption"), False, False, 0)
        identity.pack_start(styled(_label(grant.identity), "keeper-access-agent"), False, False, 0)
        project = styled(_label(grant.project), "keeper-event-caption")
        project.set_tooltip_text("Reported project")
        identity.pack_start(project, False, False, 0)
        body.pack_start(requester, False, False, 0)

        if change:
            add_label(body, "Approving replaces this token’s current permissions with the scope below.")
        count = len(request.items)
        review = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        if count > 1:
            caption = "Requested Resources" if any(item.group for item in request.items) else "Requested Entries"
            heading = styled(_label(f"{caption} ({count})"), "keeper-access-caption")
            review.pack_start(heading, False, False, 0)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_propagate_natural_height(True)
        scroll.set_max_content_height(440)
        scroll.add(review)
        body.pack_start(scroll, True, True, 0)
        pause_notice = Gtk.Box(spacing=10)
        pause_icon = Gtk.Image.new_from_icon_name("changes-prevent-symbolic", Gtk.IconSize.MENU)
        pause_notice.pack_start(pause_icon, False, False, 0)
        pause_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        pause_text.pack_start(styled(_label("Agent access is paused"), "keeper-access-caption"), False, False, 0)
        add_label(pause_text, "Approving also resumes access for all approved agents.")
        pause_notice.pack_start(pause_text, True, True, 0)
        styled(pause_notice, "keeper-access-notice").show_all()
        pause_notice.set_no_show_all(True)
        body.pack_start(pause_notice, False, False, 0)

        technical = Gtk.Expander(label="Technical Details")
        details = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin_top=8)
        details.pack_start(activity_facts((
            ("Requested", table_time(request.requested)),
            ("Agent Account", f"UID {grant.uid} (verified)"),
            ("Project", reported(grant.project)),
            ("Model", reported(request.context.model)),
            ("Chat", reported(request.context.chat)),
            ("Token Record", grant.id),
        )), False, False, 0)
        technical.add(details)
        styled(technical, "keeper-access-technical")

        controls = [self._review_entry(review, details, item) for item in request.items]
        for record in locked_review_vaults(self.app.workspace, request.items):
            body.pack_start(self.app.unlock_review_button(record, dialog), False, False, 0)

        def changed(*_):
            paused = self.app.workspace.paused
            approve.set_label(resume_label if paused else "Approve")
            pause_notice.set_visible(paused)
            ready = bool(controls) and all(combo.get_active() >= 0 for combo, _ in controls)
            can_resume = self.app.broker and self.app.broker.enabled
            approve.set_sensitive(ready and (not paused or bool(can_resume)))
            return GLib.SOURCE_CONTINUE

        for combo, _ in controls:
            combo.connect("changed", changed)
        changed()
        review.pack_start(technical, False, False, 0)

        watch = GLib.timeout_add(250, changed)
        try:
            response = self.app.run_dialog(dialog, standalone=standalone)
        finally:
            GLib.source_remove(watch)
        change_id = change.id if change else None
        if response == Gtk.ResponseType.APPLY:
            kind = "grant-change" if change else "grant"
            identifier = f"{grant.id}/{change.id}" if change else grant.id
            if (kind, identifier) in self.app._review_requests():
                self.open_record(identifier, kind, automatic=standalone)
        elif response == Gtk.ResponseType.REJECT:
            self.app.owner_operation(lambda: self.app.grants.decide(grant.id, None, change_id=change_id))
        elif response == Gtk.ResponseType.ACCEPT:
            choices = [options[combo.get_active()] for combo, options in controls]
            resume = approve.get_label() == resume_label

            def approve_request():
                if resume and not (self.app.broker and self.app.broker.enabled):
                    raise ValueError("Agent access is unavailable. Reopen the request when the broker is running.")
                with self.app.workspace.mutex:
                    if self.app.workspace.paused and not resume:
                        raise ValueError("Agent access was paused. Reopen the request to review your options.")
                    self.app.grants.decide(grant.id, choices, change_id=change_id)
                    if resume:
                        self.app.workspace.pause(False)

            self.app.owner_operation(approve_request)

    def _review_entry(self, review, details, item):
        choices = self.app.grants.choices(item)
        card = styled(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12), "keeper-access-resource")
        review.pack_start(card, False, False, 0)
        combo = Gtk.ComboBoxText()
        paths = [" › ".join((choice.vault_name, *choice.path)) for choice in choices]
        matches = Counter(paths)
        for choice, path in zip(choices, paths):
            if matches[path] > 1:
                resource_id = choice.scope.entry or choice.scope.group
                path = f"{path} · {choice.scope.vault[:8]} / {resource_id[:8]}"
            combo.append_text(path)

        resource = Gtk.Box(spacing=10)
        icon_name = "folder-symbolic" if item.group else "dialog-password-symbolic"
        resource_icon = Gtk.Image.new_from_icon_name(icon_name, Gtk.IconSize.LARGE_TOOLBAR)
        resource_icon.set_valign(Gtk.Align.CENTER)
        resource.pack_start(styled(resource_icon, "keeper-access-resource-icon"), False, False, 0)
        resource_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        title = styled(_label(""), "keeper-access-entry")
        location = styled(_label(""), "keeper-event-caption")
        resource_text.pack_start(title, False, False, 0)
        resource_text.pack_start(location, False, False, 0)
        resource.pack_start(resource_text, True, True, 0)
        card.pack_start(resource, False, False, 0)

        if len(choices) > 1:
            for renderer in combo.get_cells():
                renderer.set_property("ellipsize", Pango.EllipsizeMode.MIDDLE)
            card.pack_start(combo, False, False, 0)

        permissions = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        permission_section = styled(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8),
                                    "keeper-access-permissions")
        permission_section.pack_start(styled(_label("Permissions if Approved"), "keeper-access-caption"), False, False, 0)
        permission_section.pack_start(permissions, False, False, 0)
        card.pack_start(permission_section, False, False, 0)
        references = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        details.pack_start(references, False, False, 0)

        def show_choice(widget):
            for box in (permissions, references):
                for child in box.get_children():
                    box.remove(child)
            index = widget.get_active()
            choice = choices[index] if index >= 0 else None
            vault_id, entry_id = (choice.scope.vault, choice.scope.entry) if choice else (item.vault, item.entry)
            vault = self.app.workspace.registrations.get(vault_id)
            if choice:
                title.set_text(choice.path[-1])
                location.set_text(" › ".join((choice.vault_name, *choice.path[:-1])))
            elif choices:
                title.set_text(item.label or "Choose an entry")
                location.set_text("Choose the exact entry before approving.")
            elif vault and not self.app.workspace.session(vault_id):
                title.set_text(item.label or vault.name)
                location.set_text(f"{vault.name} is locked. Unlock it to review this request." if item.label
                                  else "Unlock the vault to review this request.")
            else:
                resource = "group" if item.group else "entry"
                title.set_text(item.label or f"{resource.capitalize()} unavailable")
                location.set_text(f"No matching {resource} in the unlocked vaults.")
            location_style = location.get_style_context()
            if choice:
                location_style.remove_class("keeper-access-unresolved")
            else:
                location_style.add_class("keeper-access-unresolved")
            if item.metadata:
                access_permission(permissions, "Read Entry Details", "Entry ID, title and group path")
            if item.username:
                access_permission(permissions, "Read Username", (choice.username or "—") if choice else None)
            if item.url:
                access_permission(permissions, "Read Stored URL", (choice.url or "—") if choice else None)
            for operation in item.edits:
                access_permission(permissions, EDIT_PERMISSIONS[operation])
            for caption, description in credential_use_labels(item):
                access_permission(permissions, caption, description)
            if item.uses:
                access_permission(permissions, "Owner Review Required for This Permission",
                                  "These reusable permissions and destinations require your review before use. "
                                  "After approval, your Auto Approve settings control individual uses.")
            if item.action:
                binding = vault.binding(entry_id, item.action) if choice else None
                action = binding.action if binding else None
                name = f"Run {action.name}" if action else f"Run credential action {item.action}"
                destination = f"{action.type_label} · {action.destination}" if action else None
                if action and action.browser:
                    destination += "\n" + action.browser.description
                elif action and action.request_json:
                    destination += "\nFixed JSON body · " + action.request_json
                access_permission(permissions, name, destination)
            facts = activity_facts((
                ("Vault ID", vault_id),
                ("Entry ID", entry_id),
                ("Group ID", item.group),
                ("Database", str(vault.target.database) if vault else None),
                ("Action ID", item.action),
            ))
            if facts:
                references.pack_start(facts, False, False, 0)
            permissions.show_all()
            references.show_all()

        combo.connect("changed", show_choice)
        if len(choices) == 1:
            combo.set_active(0)
        else:
            show_choice(combo)
        return combo, choices

    def _manage(self, grant):
        dialog, body = _dialog(self.app, "Access Token", 690, -1)
        dialog.set_name("keeper-access-detail")
        dialog.set_modal(True)
        dialog.add_buttons("Close", Gtk.ResponseType.CLOSE, "Remove Token…", Gtk.ResponseType.REJECT)
        styled(dialog.get_widget_for_response(Gtk.ResponseType.REJECT), "keeper-delete")
        dialog.set_default_response(Gtk.ResponseType.CLOSE)
        if grant.status == "active":
            dialog.add_button("Disable", Gtk.ResponseType.APPLY)
        elif grant.status == "disabled":
            dialog.add_button("Re-enable", Gtk.ResponseType.APPLY)

        status = styled(_label(grant.status.capitalize()), "keeper-event-title")
        body.pack_start(status, False, False, 0)
        body.pack_start(activity_facts((
            ("Identity", reported(grant.identity)), ("Project", reported(grant.project)),
            ("Model", reported(grant.context.model)), ("Chat", reported(grant.context.chat)),
            ("Requested", table_time(grant.requested)),
            ("Last Used", table_time(grant.last_used) if grant.last_used is not None else "Never"),
        )), False, False, 0)
        body.pack_start(styled(Gtk.Label(label="Approved Entries", xalign=0), "keeper-event-section-title"),
                        False, False, 0)
        if grant.scope:
            tree, needs_unlock = approved_entries_tree(self.app.workspace, grant.scope)
            scroll = _scroll(tree)
            scroll.set_propagate_natural_height(True)
            scroll.set_min_content_height(95)
            scroll.set_max_content_height(335)
            body.pack_start(scroll, True, True, 0)
            if needs_unlock:
                add_label(body, "Unlock a database to see its group and entry names.")
        else:
            add_label(body, "This token has no approved entries or groups.")
        technical = Gtk.Expander(label="Technical Details")
        technical.add(activity_facts((("Verified Linux UID", grant.uid), ("Token Record", grant.id))))
        body.pack_start(technical, False, False, 0)

        response = self.app.run_dialog(dialog)
        if response == Gtk.ResponseType.REJECT:
            self._update_token(grant.id, "removed")
        elif response == Gtk.ResponseType.APPLY:
            self._update_token(grant.id, "disabled" if grant.status == "active" else "active")

    def _update_token(self, identifier, status):
        if self.app.desktop.locked:
            return
        if status == "removed" and not self.app.confirm(
            "Remove this token?", "The runner will need a fresh request and approval.",
        ):
            return
        self.app.owner_operation(lambda: self.app.grants.transition(identifier, status))


def access_permission(container, title, detail=None):
    row = Gtk.Box(spacing=8)
    icon = Gtk.Image.new_from_icon_name("object-select-symbolic", Gtk.IconSize.MENU)
    icon.set_valign(Gtk.Align.START)
    row.pack_start(styled(icon, "keeper-access-permission-icon"), False, False, 0)
    text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    text.pack_start(styled(_label(title), "keeper-access-permission-name"), False, False, 0)
    if detail is not None:
        description = _label(detail)
        description.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
        text.pack_start(styled(description, "keeper-event-caption"), False, False, 0)
    row.pack_start(text, True, True, 0)
    container.pack_start(row, False, False, 0)


def activity_location(row, workspace):
    labels = ActivityResources(workspace, mark_current=True).labels(row)
    return tuple(zip(("Vault", "Group", "Key"), labels))


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
    if stage not in EDIT_STAGES:
        return None
    for part in (row.get("scope") or "").split(" · "):
        if part.startswith("Fields "):
            fields = part.removeprefix("Fields ").split(",")
            labels = [EDIT_FIELD_LABELS[field.strip()] for field in fields if field.strip() in EDIT_FIELD_LABELS]
            if labels:
                caption = "Changed Fields" if stage == "Apply edit" and row["outcome"] == "Succeeded" else "Proposed Fields"
                return caption, ", ".join(dict.fromkeys(labels))
    return None


def activity_execution(row):
    requested, decided, completed = (_time(row[key]) if row.get(key) is not None else None
                                      for key in ("requested", "decided", "completed"))
    fields = activity_edit_fields(row)
    facts = (
        ("Destination", row.get("destination")), ("Authorization", row.get("decision")),
        ("Workflow Step", row.get("workflow_step")),
        ("HTTP Status", row.get("status")), ("Decided", decided if decided not in (requested, completed) else None),
        ("Completed", completed if completed != requested else None),
    )
    return (fields, *facts) if fields else facts


def activity_dialog(app, row):
    dialog, body = _dialog(app, "Activity Details", 860, 740, fit_monitor=True)
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
    scroll.set_max_content_height(600)
    body.pack_start(scroll, True, True, 0)

    add_activity_section(details, "Resource", activity_location(row, app.workspace))
    context = [(caption, reported(row[key])) for key, caption in
               (("project", "Project"), ("model", "Model"), ("chat", "Chat")) if row.get(key)]
    identity = row.get("identity") or row.get("agent")
    add_activity_section(details, "Request", (("Identity", reported(identity) if identity else None), *context))
    add_activity_section(details, "Execution", activity_execution(row))
    add_activity_section(details, "Audit Note", (("Agent Note", row.get("note") or "No note provided."),))
    technical = activity_facts((
        ("Linux UID (verified)", row.get("uid")), ("Chat ID", row.get("chat_id")), ("Vault ID", row.get("vault_id")),
        ("Group ID", row.get("group_id")), ("Entry ID", row.get("entry")),
        ("Token Record", row.get("token")), ("Edit Request ID", row.get("edit_request_id")),
        ("Recorded Scope", row.get("scope")),
    ))
    if technical is not None:
        technical.set_margin_start(10)
        technical.set_margin_top(8)
        disclosure = Gtk.Expander(label="Technical Details")
        disclosure.set_margin_top(3)
        disclosure.add(technical)
        technical.show_all()
        technical.set_no_show_all(True)
        technical.hide()
        disclosure.connect("notify::expanded", lambda control, _: technical.set_visible(control.get_expanded()))
        details.pack_start(disclosure, False, False, 0)
    return dialog


def replace_tree_rows(table, rows, key_column):
    model = table.get_model()
    if list(map(tuple, model)) == rows:
        return
    selected = selected_key(table, key_column)
    expanded = set()
    table.map_expanded_rows(lambda _, path: expanded.add(model[path][key_column]))
    model.clear()
    restored = None
    for values in rows:
        parent = model.append(None, values)
        for child in values[-1]:
            node = model.append(parent, child)
            if child[key_column] == selected:
                restored = node
        if values[key_column] in expanded:
            table.expand_row(model.get_path(parent), False)
        if values[key_column] == selected:
            restored = parent
    if restored is not None:
        table.get_selection().select_iter(restored)


class ActivityView(Gtk.Box):
    TITLES = ("Time", "Action", "Identity", "Vault", "Group", "Key", "Outcome")
    ACTION = TITLES.index("Action")
    OUTCOME = TITLES.index("Outcome")
    RECORD_ID = len(TITLES)
    ACTION_ICON = RECORD_ID + 1
    TIME = ACTION_ICON + 1
    ROW_KEY = TIME + 1

    def __init__(self, app):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        self.app = app
        self.rows = {}
        header, _, _, _ = section_heading("Activity", "document-open-recent-symbolic")
        tools = Gtk.Box(valign=Gtk.Align.CENTER)
        header.pack_end(tools, False, False, 0)
        filters = Gtk.Grid(column_spacing=8, row_spacing=8, margin=12)
        self.filters = {}
        for index, name in enumerate(("Vault", "Group", "Key", "Identity", "Model", "Chat", "Action", "Outcome")):
            field = styled(Gtk.SearchEntry(placeholder_text=name, hexpand=True), "keeper-search")
            field.connect("search-changed", self.refresh)
            filters.attach(field, index % 4, index // 4, 1, 1)
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
            Gtk.TreeStore(*([str] * (self.ACTION_ICON + 1)), object, object, object), self.TITLES,
            (144, 144, 110, 78, 86, 84, 180), status=(self.OUTCOME, ACTIVITY_STATES),
            expand_columns=(1, 2, 3, 4, 5), muted_columns=(0,), time_columns={0: self.TIME},
            icon_columns={self.ACTION: self.ACTION_ICON}, full_text_columns=(self.OUTCOME,),
            indent_rows=True, replace_rows=replace_tree_rows,
        )
        self.table.set_enable_tree_lines(True)
        self.table.set_expander_column(self.table.get_column(0))
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
        filters = {name: field.get_text().strip().casefold() for name, field in self.filters.items()
                   if field.get_text().strip()}
        try:
            rows = self.app.activity.rows()
        except ActivityError:
            rows = []
        records = self.app.grants.records if self.app.grants else {}
        for row in rows:
            record = records.get(row.get("token"))
            row["identity"] = row.get("agent") or (record.identity if record else None)
        self.rows = {str(row["id"]): row for row in rows}
        lookup = ActivityResources(self.app.workspace)
        resources = {row["id"]: lookup.labels(row) for row in rows}
        visible = []
        for key, (label, events) in activity_groups(rows).items():
            if filters and not any(
                activity_matches(event, resources[event["id"]], filters) for event in events
            ):
                continue
            latest = events[0]
            if len(events) == 1:
                visible.append(self._values(latest, resources[latest["id"]], key))
                continue
            children = tuple(
                self._values(event, resources[event["id"]], ("event", event["id"])) for event in events
            )
            visible.append(self._values(
                latest, resources[latest["id"]], key, action=f"{label} ({len(events)})", children=children,
            ))
        fill_table(self.table, visible, self.ROW_KEY)
        self.empty_label.set_text("No activity matches these filters" if filters else "No activity recorded")
        self.empty.set_visible(not visible)

    @staticmethod
    def _values(row, resource, key, *, action=None, children=()):
        timestamp = event_time(row)
        stage = row["action"].partition(" · ")[0]
        if children and key[0] == "token":
            icon = "changes-allow-symbolic"
        elif stage in EDIT_STAGES:
            icon = "document-edit-symbolic"
        else:
            icon = ACTIVITY_ACTION_ICONS.get(stage, "document-open-recent-symbolic")
        return (table_time(timestamp), action or row["action"], reported(row["identity"]),
                *(value or "—" for value in resource), row["outcome"], str(row["id"]),
                icon, timestamp, key, children)

    def _details(self, table, path, _column):
        self.open_record(table.get_model()[path][self.RECORD_ID])

    def open_record(self, identifier):
        row = self.rows.get(identifier)
        if row and not self.app.desktop.locked:
            self.app.run_dialog(activity_dialog(self.app, row))


EDIT_ENTRY_RESPONSE = 1
DELETE_ENTRY_RESPONSE = 2


def entry_details(app, vault, entry):
    group = app.selection[1]
    while app.workspace.owner_session(vault) and not app.desktop.locked and not app.busy:
        record = app.workspace.registrations[vault]
        dialog, body = _dialog(app, entry["title"] or "(Untitled entry)", 710, 420)
        dialog.set_modal(True)
        dialog.add_buttons("Close", Gtk.ResponseType.CLOSE, "Add Action", Gtk.ResponseType.APPLY,
                           "Edit Action", Gtk.ResponseType.ACCEPT, "Remove Action", Gtk.ResponseType.REJECT)
        add_label(body, f"{record.name} · {' / '.join(entry['group_path']) or 'Root'}\nEntry  {entry['id']}")
        add_label(body, f"Username  {entry['username'] or '—'}\nURL  {entry['url'] or '—'}")
        created = table_time(entry.get("created"))
        modified = table_time(entry.get("modified"))
        add_label(body, f"Created  {created}\nModified  {modified}")
        entry_actions = Gtk.Box(spacing=8)
        button(entry_actions, "Copy Entry Reference", lambda *_: app.copy_reference(vault, "entry", entry["id"]))
        button(entry_actions, "Edit Entry…", lambda *_: dialog.response(EDIT_ENTRY_RESPONSE))
        styled(button(entry_actions, DELETE_LABEL, lambda *_: dialog.response(DELETE_ENTRY_RESPONSE)), "keeper-delete")
        body.pack_start(entry_actions, False, False, 0)
        add_label(body, "Credential Actions")
        store = Gtk.ListStore(str, str, str, str, str)
        for binding in record.bindings:
            action = binding.action
            if action.entry == entry["id"]:
                store.append((action.id, action.name, action.type_label, action.destination,
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
        if response == DELETE_ENTRY_RESPONSE:
            delete_entry(app, vault, group, entry)
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
    dialog, body = _dialog(app, "Credential Action", 560, 300)
    dialog.set_modal(True)
    dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Save", Gtk.ResponseType.OK)
    add_label(body, "Type")
    kind = Gtk.ComboBoxText()
    kind.set_name("action-kind")
    for option in ActionType:
        if option not in (ActionType.TEMPLATE, ActionType.RESULTS):
            kind.append(option.value, option.label)
    kind.set_active_id(previous.action.kind.value if previous else ActionType.BASIC.value)
    body.pack_start(kind, False, False, 0)
    fields = []
    for title, default in (("Action ID", "health-check"), ("Name", "Health check")):
        add_label(body, title)
        field = Gtk.Entry(text=default)
        body.pack_start(field, False, False, 0)
        fields.append(field)
    target_label = _label("")
    target = Gtk.Entry()
    target.set_name("action-destination")
    body.pack_start(target_label, False, False, 0)
    body.pack_start(target, False, False, 0)
    fields.append(target)

    network = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
    network.set_no_show_all(True)
    add_label(network, "Approved HTTPS Origin")
    network_url = Gtk.Entry(placeholder_text="https://example.com")
    network.pack_start(network_url, False, False, 0)
    add_label(network, "The command controls the path and verifies TLS.")
    add_label(network, "Credential Prompt Variable")
    prompt = Gtk.Entry(placeholder_text="GIT_ASKPASS")
    network.pack_start(prompt, False, False, 0)
    accepts_input = Gtk.CheckButton(label="Allow an input file at /input")
    network.pack_start(accepts_input, False, False, 0)
    body.pack_start(network, False, False, 0)

    https = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
    https.set_no_show_all(True)
    add_label(https, "HTTP Method")
    method = Gtk.ComboBoxText()
    method.set_name("action-method")
    for verb in HTTPS_METHODS:
        method.append(verb, verb)
    method.set_active_id(previous.action.method if previous else "GET")
    https.pack_start(method, False, False, 0)
    add_label(https, "Fixed JSON Body")
    request_json = Gtk.Entry(placeholder_text="Optional JSON object. Keep secrets out of this field.")
    request_json.set_name("action-request-json")
    if previous:
        request_json.set_text(previous.action.request_json)
    https.pack_start(request_json, False, False, 0)
    body.pack_start(https, False, False, 0)

    browser = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
    browser.set_no_show_all(True)
    browser_fields = {}
    profile = previous.action.browser if previous else None
    for field_name, caption, hint in (
        ("submit_url", "Form Submit URL", "https://example.com/session"),
        ("form_id", "Form ID", "sign-in"),
        ("username_field", "Username Input Name", "username"),
        ("password_field", "Password Input Name", "password"),
        ("success_id", "Success Element ID", "account-home"),
        ("success_url", "Success Redirect URL (Optional)", "https://example.com/account"),
    ):
        add_label(browser, caption)
        field = Gtk.Entry(text=getattr(profile, field_name, ""), placeholder_text=hint)
        field.set_name("browser-" + field_name)
        browser.pack_start(field, False, False, 0)
        browser_fields[field_name] = field
    body.pack_start(browser, False, False, 0)

    def update_target(*_):
        selected = ActionType(kind.get_active_id())
        command = selected in (ActionType.STDIN, ActionType.NETWORK_PROMPT)
        is_browser = selected == ActionType.BROWSER
        if is_browser:
            target_label.set_text("HTTPS Sign-in Page")
            for child in browser.get_children():
                child.show_all()
            browser.show()
        else:
            target_label.set_text("Executable and Arguments" if command else "HTTPS Endpoint")
            browser.hide()
        if command or is_browser:
            https.hide()
        else:
            for child in https.get_children():
                child.show_all()
            https.show()
        request_json.set_sensitive(method.get_active_id() in HTTPS_WRITE_METHODS)
        target.set_placeholder_text("/usr/bin/example" if command else "https://example.com/sign-in"
                                    if is_browser else "https://example.com/status")
        if selected == ActionType.NETWORK_PROMPT:
            for child in network.get_children():
                child.show_all()
            network.show()
        else:
            network.hide()

    kind.connect("changed", update_target)
    method.connect("changed", update_target)
    update_target()
    enabled = Gtk.CheckButton(label="Enabled", active=True)
    body.pack_start(enabled, False, False, 0)
    if previous:
        action = previous.action
        for field, value in zip(fields, (action.id, action.name, join(action.command) if action.command else action.url)):
            field.set_text(value)
        enabled.set_active(action.enabled)
        network_url.set_text(action.url if action.kind == ActionType.NETWORK_PROMPT else "")
        prompt.set_text(action.prompt_variable)
        accepts_input.set_active(action.accepts_input)
    response = app.run_dialog(dialog)
    if response == Gtk.ResponseType.OK:
        def save():
            identifier, name, url = (field.get_text() for field in fields)
            chosen_kind = ActionType(kind.get_active_id())
            if chosen_kind in (ActionType.STDIN, ActionType.NETWORK_PROMPT):
                command = tuple(split(url))
                routed = chosen_kind == ActionType.NETWORK_PROMPT
                action = Action(identifier, name, entry, network_url.get_text() if routed else "",
                                enabled.get_active(), kind=chosen_kind,
                                command=command, executable_sha256=executable_digest(command),
                                prompt_variable=prompt.get_text() if routed else "",
                                accepts_input=routed and accepts_input.get_active())
            elif chosen_kind == ActionType.BROWSER:
                profile = BrowserForm(**{key: field.get_text() for key, field in browser_fields.items()})
                action = Action(identifier, name, entry, url, enabled.get_active(), kind=chosen_kind, browser=profile)
            else:
                verb = method.get_active_id()
                action = Action(identifier, name, entry, url, enabled.get_active(), kind=chosen_kind, method=verb,
                                request_json=request_json.get_text() if verb in HTTPS_WRITE_METHODS else "")
            app.workspace.save_binding(vault, action, previous.action.id if previous else None)
        app.owner_operation(save)
