"""Keeper's desktop palette and widget styles, derived from the GTK theme."""

from gi.repository import Gtk


CSS = b"""
@define-color keeper_canvas mix(@theme_base_color, @theme_fg_color, 0.025);
@define-color keeper_sidebar mix(@theme_base_color, @theme_fg_color, 0.052);
@define-color keeper_surface @theme_base_color;
@define-color keeper_line alpha(@theme_fg_color, 0.13);
@define-color keeper_muted mix(@theme_fg_color, @theme_base_color, 0.33);
@define-color keeper_cobalt #456de7;
@define-color keeper_accent mix(@theme_fg_color, @keeper_cobalt, 0.66);
@define-color keeper_selection mix(@theme_base_color, @keeper_cobalt, 0.20);
@define-color keeper_success mix(@theme_fg_color, #31a777, 0.62);
@define-color keeper_separator_on_dark #45e780;
@define-color keeper_separator_on_light #007a39;
@define-color keeper_warning mix(@theme_fg_color, #b38436, 0.66);
@define-color keeper_failure mix(@theme_fg_color, #d44f5e, 0.62);

#keeper-workspace {
    background-color: @keeper_canvas;
    color: @theme_fg_color;
}
#keeper-workspace .keeper-header {
    background-image: none;
    background-color: @keeper_surface;
    border-bottom: 1px solid @keeper_line;
    box-shadow: none;
    padding: 8px 14px;
}
#keeper-workspace .keeper-brand {
    margin-right: 8px;
}
#keeper-workspace .keeper-brand label {
    font-size: 1.16em;
    font-weight: 800;
}
#keeper-workspace .keeper-brand-mark {
    color: white;
    background-color: #3f63d4;
    border-radius: 8px;
    padding: 6px;
}
#keeper-workspace .keeper-control,
#keeper-workspace .keeper-pane button,
#keeper-workspace .keeper-footer button {
    background-image: none;
    background-color: @keeper_surface;
    color: @theme_fg_color;
    border: 1px solid @keeper_line;
    border-radius: 8px;
    min-height: 22px;
    padding: 5px 10px;
    box-shadow: none;
    text-shadow: none;
}
#keeper-workspace .keeper-control:hover,
#keeper-workspace .keeper-pane button:hover,
#keeper-workspace .keeper-footer button:hover {
    background-color: mix(@keeper_surface, @theme_fg_color, 0.075);
}
#keeper-workspace .keeper-control:active,
#keeper-workspace .keeper-pane button:active,
#keeper-workspace .keeper-footer button:active {
    background-color: mix(@keeper_surface, @theme_fg_color, 0.12);
}
#keeper-workspace .keeper-control:disabled,
#keeper-workspace .keeper-pane button:disabled,
#keeper-workspace .keeper-footer button:disabled {
    opacity: 0.52;
}
#keeper-workspace .keeper-control:focus,
#keeper-workspace .keeper-pane button:focus,
#keeper-workspace .keeper-footer button:focus {
    outline: 2px solid @keeper_accent;
    outline-offset: -3px;
}
#keeper-workspace .keeper-quiet {
    background-color: transparent;
    border-color: transparent;
}
#keeper-workspace .keeper-vault-tools button {
    margin: 0;
}
#keeper-workspace button.keeper-primary {
    color: @keeper_accent;
}
menuitem.keeper-delete,
menuitem.keeper-delete label,
button.keeper-delete {
    color: @keeper_failure;
}
#keeper-workspace .keeper-paused {
    background-color: mix(@keeper_surface, @keeper_warning, 0.12);
    border-color: alpha(@keeper_warning, 0.28);
    color: @keeper_warning;
}
#keeper-workspace .keeper-paused:hover {
    background-color: mix(@keeper_surface, @keeper_warning, 0.19);
}
#keeper-workspace .keeper-live {
    background-color: mix(@keeper_surface, @keeper_success, 0.12);
    border-color: alpha(@keeper_success, 0.28);
    color: @keeper_success;
}
#keeper-workspace .keeper-live:hover {
    background-color: mix(@keeper_surface, @keeper_success, 0.19);
}
#keeper-workspace .keeper-sidebar {
    background-color: @keeper_sidebar;
}
#keeper-workspace .keeper-sidebar-title {
    color: @keeper_muted;
    font-weight: 700;
    font-size: 0.91em;
}
#keeper-workspace .keeper-sidebar treeview {
    background-color: transparent;
}
#keeper-workspace .keeper-sidebar treeview:selected {
    background-color: @keeper_selection;
    border-radius: 7px;
    color: @theme_fg_color;
}
#keeper-workspace .keeper-sidebar treeview:selected:focus {
    background-color: mix(@keeper_selection, @keeper_cobalt, 0.14);
}
#keeper-workspace .keeper-divider > separator {
    min-width: 1px;
    background-color: transparent;
    background-image: linear-gradient(to right, transparent 44%, @keeper_line 44%, @keeper_line 56%, transparent 56%);
}
#keeper-workspace .keeper-pane {
    background-color: @keeper_canvas;
}
#keeper-workspace .keeper-title {
    font-size: 1.86em;
    font-weight: 800;
}
#keeper-workspace .keeper-muted {
    color: @keeper_muted;
}
#keeper-workspace .keeper-section-icon {
    color: @keeper_accent;
    background-color: mix(@keeper_surface, @keeper_cobalt, 0.15);
    border: 1px solid alpha(@keeper_cobalt, 0.26);
    border-radius: 13px;
    padding: 11px;
}
#keeper-workspace .keeper-card {
    background-color: @keeper_surface;
    border: 1px solid alpha(@theme_fg_color, 0.23);
    border-radius: 10px;
    padding: 3px;
}
#keeper-workspace .keeper-card-toolbar {
    padding: 8px 10px;
}
#keeper-workspace .keeper-search {
    color: @theme_fg_color;
    background-image: none;
    background-color: @keeper_canvas;
    border: 1px solid @keeper_line;
    border-radius: 7px;
    box-shadow: none;
    min-height: 25px;
    padding: 3px 8px;
}
#keeper-workspace .keeper-search:focus {
    border-color: @keeper_accent;
    box-shadow: 0 0 0 1px @keeper_accent;
}
#keeper-workspace .keeper-table {
    background-color: @keeper_surface;
}
#keeper-workspace .keeper-table:selected {
    background-color: @keeper_selection;
    color: @theme_fg_color;
}
#keeper-workspace .keeper-table:selected:focus {
    background-color: mix(@keeper_selection, @keeper_cobalt, 0.13);
}
#keeper-workspace .keeper-table header button {
    padding: 7px 10px;
    font-weight: 700;
    font-size: 0.88em;
    border-radius: 0;
    border-width: 1px 0;
    border-color: @keeper_line;
    background-image: none;
    background-color: @keeper_canvas;
    box-shadow: none;
    color: @keeper_muted;
}
#keeper-workspace .keeper-table-card .keeper-table header button {
    border-top-width: 0;
}
#keeper-workspace .keeper-table header button:hover {
    background-color: mix(@keeper_canvas, @theme_fg_color, 0.065);
}
#keeper-workspace .keeper-empty-icon {
    color: @keeper_muted;
}
#keeper-workspace .keeper-footer {
    padding: 8px 18px;
    border-top: 1px solid @keeper_line;
    background-color: @keeper_surface;
}
#keeper-workspace .keeper-footer button {
    border-color: transparent;
    color: @keeper_muted;
    font-weight: 700;
}
#keeper-workspace .keeper-footer button.keeper-current {
    color: @keeper_accent;
    border-color: alpha(@keeper_cobalt, 0.3);
    background-color: mix(@keeper_surface, @keeper_cobalt, 0.11);
}
#keeper-workspace .keeper-footer button.keeper-current:hover {
    background-color: mix(@keeper_surface, @keeper_cobalt, 0.18);
}
#keeper-workspace .keeper-notice {
    color: @theme_fg_color;
    background-color: mix(@keeper_surface, @keeper_warning, 0.12);
    border: 1px solid alpha(@keeper_warning, 0.34);
    border-radius: 9px;
    padding: 9px 12px;
}
#keeper-edit-review .keeper-review-title {
    font-size: 1.45em;
    font-weight: 800;
}
#keeper-edit-review .keeper-review-label {
    font-weight: 700;
}
#keeper-edit-review .keeper-review-muted {
    color: @keeper_muted;
}
#keeper-edit-review .keeper-review-value,
#keeper-edit-review .keeper-review-blocker {
    border-radius: 8px;
    border: 1px solid @keeper_line;
    padding: 10px 12px;
}
#keeper-edit-review .keeper-review-value {
    background-color: @keeper_canvas;
}
#keeper-edit-review .keeper-review-proposed {
    background-color: mix(@keeper_surface, @keeper_cobalt, 0.085);
    border-color: alpha(@keeper_cobalt, 0.24);
}
#keeper-edit-review .keeper-review-blocker {
    background-color: mix(@keeper_surface, @keeper_warning, 0.12);
    border-color: alpha(@keeper_warning, 0.34);
}
#keeper-edit-review .keeper-review-blocker image {
    color: @keeper_warning;
}
#keeper-access-review {
    background-color: @keeper_surface;
}
#keeper-access-review .keeper-access-agent-icon,
#keeper-access-review .keeper-access-resource-icon {
    min-width: 40px;
    min-height: 40px;
    border-radius: 10px;
    color: @keeper_accent;
    background-color: mix(@keeper_surface, @keeper_cobalt, 0.14);
}
#keeper-access-review .keeper-access-agent {
    font-size: 1.5em;
    font-weight: 800;
}
#keeper-access-review .keeper-access-entry {
    font-size: 1.17em;
    font-weight: 800;
}
#keeper-access-review .keeper-access-resource {
    padding: 14px;
    border: 1px solid @keeper_line;
    border-radius: 12px;
    background-color: @keeper_canvas;
}
#keeper-access-review .keeper-access-permissions {
    padding: 10px 11px;
    border-radius: 8px;
    background-color: mix(@keeper_canvas, @keeper_cobalt, 0.08);
}
#keeper-access-review .keeper-access-caption,
#keeper-access-review .keeper-access-permission-name {
    font-weight: 700;
}
#keeper-access-review .keeper-access-permission-icon {
    color: @keeper_accent;
}
#keeper-access-review .keeper-access-technical {
    color: @keeper_muted;
    padding: 4px 0;
}
#keeper-access-review .keeper-access-notice {
    padding: 10px 12px;
    border: 1px solid alpha(@keeper_warning, 0.40);
    border-radius: 9px;
    background-color: mix(@keeper_surface, @keeper_warning, 0.12);
}
#keeper-access-review .keeper-access-notice image,
#keeper-access-review label.keeper-access-unresolved {
    color: @keeper_warning;
}
#keeper-access-review .keeper-access-footer {
    padding: 0 12px 12px;
}
#keeper-access-review .keeper-access-footer button {
    min-height: 25px;
    padding: 5px 17px;
    border-radius: 7px;
}
#keeper-access-review .keeper-access-approve {
    color: white;
    background-image: none;
    background-color: #3f63d4;
    border-color: #3f63d4;
    font-weight: 700;
    text-shadow: none;
}
#keeper-access-review .keeper-access-approve:hover {
    background-color: #3558c5;
}
#keeper-access-review .keeper-access-approve:active {
    background-color: #304fad;
}
#keeper-access-review .keeper-access-approve:disabled {
    color: @keeper_muted;
    background-color: @keeper_canvas;
    border-color: @keeper_line;
}
#keeper-access-review .keeper-access-deny {
    color: @keeper_failure;
}
#keeper-access-detail .keeper-event-title,
#keeper-activity-detail .keeper-event-title {
    font-size: 1.45em;
    font-weight: 800;
}
#keeper-access-review .keeper-event-caption,
#keeper-access-detail .keeper-event-caption,
#keeper-activity-detail .keeper-event-caption {
    color: @keeper_muted;
}
#keeper-activity-detail .keeper-event-section {
    border-radius: 9px;
    border: 1px solid @keeper_line;
    background-color: @keeper_canvas;
    padding: 10px 12px;
}
#keeper-access-detail .keeper-event-section-title,
#keeper-activity-detail .keeper-event-section-title {
    font-weight: 800;
}
#keeper-activity-detail .keeper-event-badge {
    border-radius: 7px;
    border: 1px solid @keeper_line;
    background-color: @keeper_canvas;
    padding: 4px 7px;
    font-weight: 700;
}
#keeper-activity-detail .keeper-event-badge.keeper-success {
    color: @keeper_success;
}
#keeper-activity-detail .keeper-event-badge.keeper-failure {
    color: @keeper_failure;
}
#keeper-activity-detail .keeper-event-badge.keeper-warning {
    color: @keeper_warning;
}
#keeper-activity-detail .keeper-event-badge.keeper-accent {
    color: @keeper_accent;
}

"""


def styled(widget, *classes):
    context = widget.get_style_context()
    for name in classes:
        context.add_class(name)
    return widget


def install_style(window):
    window.set_name("keeper-workspace")
    provider = Gtk.CssProvider()
    provider.load_from_data(CSS)
    Gtk.StyleContext.add_provider_for_screen(window.get_screen(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    return provider
