"""Use an X11 tray icon without putting the Keeper window on X11."""

import os
from pathlib import Path
import sys

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gio, GLib, Gtk


ICON_DIRECTORY = Path(__file__).resolve().with_name("icons")
PAUSED_ICON = "keeper-agent-access-paused"
ACTIVE_ICON = "keeper-agent-access-active"
EMBED_TIMEOUT_MS = 1000


class LegacyTray:
    def __init__(self, on_open, on_connected, on_exit):
        # Only the icon and its Open Keeper menu live on the X11 connection.
        # The private pipes carry pause state and the open/connected events.
        launcher = Gio.SubprocessLauncher.new(
            Gio.SubprocessFlags.STDIN_PIPE | Gio.SubprocessFlags.STDOUT_PIPE
        )
        launcher.setenv("GDK_BACKEND", "x11", True)
        bootstrap = Path(__file__).resolve().parent.parent / "keeper_bootstrap.py"
        self.process = launcher.spawnv(
            ("/usr/bin/python3", "-I", str(bootstrap), "keepassxc_agent_access.legacy_tray")
        )
        self.on_open = on_open
        self.on_connected = on_connected
        self.on_exit = on_exit
        self.paused = True
        self.stopping = False
        self._listen(self.process.get_stdout_pipe())

    def _listen(self, stream):
        stream.read_bytes_async(128, GLib.PRIORITY_DEFAULT, None, self._received)

    def _received(self, stream, result):
        if self.stopping:
            return
        try:
            events = stream.read_bytes_finish(result).get_data()
        except GLib.Error:
            events = b""
        if not events:
            self.close()
            self.on_exit()
            return
        for event in events:
            if event == ord("O"):
                self.on_open()
            elif event == ord("C"):
                self.on_connected()
        self._listen(stream)

    def set_paused(self, paused):
        if self.paused != paused:
            self.paused = paused
            try:
                self.process.get_stdin_pipe().write_all(b"P" if paused else b"A", None)
            except GLib.Error:
                pass

    def close(self):
        self.stopping = True
        self.process.force_exit()


def main():
    initialized, _ = Gtk.init_check()
    if not initialized:
        return

    import cairo
    gi.require_version("GdkX11", "3.0")
    from gi.repository import Gdk, GdkX11

    icon = Gtk.StatusIcon()
    icon.set_title("Keeper")
    icon.set_name("Keeper")
    menu = Gtk.Menu()
    show = Gtk.MenuItem(label="Open Keeper")
    menu.append(show)
    menu.show_all()

    def send(event):
        sys.stdout.buffer.write(event)
        sys.stdout.flush()

    def shape_icon():
        if not icon.is_embedded():
            return GLib.SOURCE_REMOVE
        window = GdkX11.X11Window.lookup_for_display(Gdk.Display.get_default(), icon.get_x11_window_id())
        if window is None or window.get_visual().get_depth() == 32:
            return GLib.SOURCE_REMOVE
        tray = next((widget for widget in Gtk.Window.list_toplevels() if widget.get_window() == window), None)
        if tray is None:
            return GLib.SOURCE_REMOVE

        # A legacy tray host may give GTK a window without an alpha channel.
        # Use the same scaled icon surface GTK uses to paint the window.
        image = tray.get_child()
        surface = image.get_property("surface") if isinstance(image, Gtk.Image) else None
        if surface is None:
            return GLib.SOURCE_REMOVE
        scale_x, scale_y = surface.get_device_scale()
        width = round(surface.get_width() / scale_x)
        height = round(surface.get_height() / scale_y)
        mask = cairo.ImageSurface(cairo.FORMAT_ARGB32, width, height)
        context = cairo.Context(mask)
        context.set_source_surface(surface)
        context.paint()
        region = Gdk.cairo_region_create_from_surface(mask)
        if not region.is_empty():
            x = (window.get_width() - width) // 2
            y = (window.get_height() - height) // 2
            window.shape_combine_region(region, x, y)
        return GLib.SOURCE_REMOVE

    def size_changed(*_):
        GLib.idle_add(shape_icon)
        return False

    def set_icon(paused):
        name = PAUSED_ICON if paused else ACTIVE_ICON
        icon.set_from_file(str(ICON_DIRECTORY / f"{name}.png"))
        icon.set_tooltip_text("Keeper · " + ("Agent access paused" if paused else "Agent access active"))
        GLib.idle_add(shape_icon)

    def embedded(*_):
        if icon.is_embedded():
            GLib.idle_add(shape_icon)
            send(b"C")
        else:
            Gtk.main_quit()

    def check_embedded():
        if not icon.is_embedded():
            Gtk.main_quit()
        return GLib.SOURCE_REMOVE

    def update_state(stream, _condition):
        status = os.read(stream.fileno(), 128)
        if not status:
            Gtk.main_quit()
            return GLib.SOURCE_REMOVE
        set_icon(status[-1:] == b"P")
        return GLib.SOURCE_CONTINUE

    icon.connect("activate", lambda *_: send(b"O"))
    show.connect("activate", lambda *_: send(b"O"))
    icon.connect("popup-menu", lambda *_: menu.popup_at_pointer(None))
    icon.connect("notify::embedded", embedded)
    icon.connect("size-changed", size_changed)
    set_icon(True)
    GLib.timeout_add(EMBED_TIMEOUT_MS, check_embedded)
    GLib.io_add_watch(sys.stdin, GLib.PRIORITY_DEFAULT, GLib.IO_IN | GLib.IO_HUP, update_state)
    if icon.is_embedded():
        send(b"C")
    Gtk.main()


if __name__ == "__main__":
    main()
