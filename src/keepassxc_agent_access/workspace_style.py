"""Theme-aware styling for the desktop workspace."""

from gi.repository import Gtk


CSS = b"""
#keeper-workspace .keeper-header {
    padding: 6px 12px;
}
#keeper-workspace .keeper-header button,
#keeper-workspace .keeper-footer button,
#keeper-workspace .keeper-pane button {
    border-radius: 8px;
}
#keeper-workspace .keeper-sidebar {
    background-color: shade(@theme_bg_color, 0.98);
    border-right: 1px solid alpha(@theme_fg_color, 0.12);
}
#keeper-workspace .keeper-sidebar treeview {
    background-color: transparent;
}
#keeper-workspace .keeper-sidebar treeview:selected {
    background-color: @theme_selected_bg_color;
    color: @theme_selected_fg_color;
}
#keeper-workspace .keeper-sidebar-title {
    font-size: 0.95em;
    font-weight: bold;
}
#keeper-workspace .keeper-pane {
    background-color: @theme_base_color;
}
#keeper-workspace .keeper-title {
    font-size: 1.45em;
    font-weight: bold;
}
#keeper-workspace .keeper-muted {
    opacity: 0.75;
}
#keeper-workspace .keeper-footer {
    padding: 10px 18px;
    border-top: 1px solid alpha(@theme_fg_color, 0.12);
    background-color: @theme_bg_color;
}
#keeper-workspace .keeper-table header button {
    padding: 7px 10px;
    font-weight: bold;
    border-radius: 0;
    border-width: 0 0 1px;
    border-color: alpha(@theme_fg_color, 0.14);
    background-image: none;
    background-color: alpha(@theme_fg_color, 0.035);
    box-shadow: none;
    color: @theme_fg_color;
}
#keeper-workspace .keeper-notice {
    background-color: alpha(@warning_color, 0.12);
    border: 1px solid alpha(@warning_color, 0.26);
    border-radius: 8px;
    padding: 9px 12px;
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
