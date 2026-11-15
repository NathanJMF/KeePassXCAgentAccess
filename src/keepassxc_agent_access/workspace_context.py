"""Pointer and keyboard context menus for GTK tree and table rows."""

from gi.repository import Gdk, GLib, Gtk


DELETE_LABEL = "Delete…"


def attach_row_context(tree, actions):
    def show(path, event):
        model = tree.get_model()
        if path is None or model is None:
            return False
        tree.get_selection().select_path(path)
        # Read the selected row again after the selection callback updates the view.
        model, selected = tree.get_selection().get_selected()
        if selected is None:
            return False
        sections = [section for section in actions(model[selected]) if section]
        if not sections:
            return False
        menu = Gtk.Menu()
        menu.attach_to_widget(tree, None)
        for index, section in enumerate(sections):
            if index:
                menu.append(Gtk.SeparatorMenuItem())
            for label, action in section:
                item = Gtk.MenuItem(label=label)
                if label == DELETE_LABEL:
                    item.get_style_context().add_class("keeper-delete")
                item.connect("activate", lambda _, callback=action: callback())
                menu.append(item)
        menu.connect("selection-done", lambda widget: GLib.idle_add(widget.destroy))
        menu.show_all()
        if event is not None:
            menu.popup_at_pointer(event)
        else:
            path = model.get_path(selected)
            column = next((item for item in tree.get_columns() if item.get_visible()), None)
            rect = tree.get_cell_area(path, column)
            menu.popup_at_rect(tree.get_bin_window(), rect, Gdk.Gravity.SOUTH_WEST, Gdk.Gravity.NORTH_WEST,
                               Gtk.get_current_event())
        return True

    def pointer(_tree, event):
        if event.button != Gdk.BUTTON_SECONDARY or event.window != tree.get_bin_window():
            return False
        hit = tree.get_path_at_pos(int(event.x), int(event.y))
        if not hit:
            return False
        tree.grab_focus()
        return show(hit[0], event)

    def keyboard(_tree):
        model, selected = tree.get_selection().get_selected()
        return show(model.get_path(selected), None) if selected is not None else False

    tree.connect("button-press-event", pointer)
    tree.connect("popup-menu", keyboard)
