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


def _parse_tray_state(text, paused=True, pending=0):
    """Parse legacy bare P/A updates and '<P|A> <pending>' lines."""
    for raw_line in text.replace("\r", "\n").split("\n"):
        parts = raw_line.strip().split()
        if not parts:
            continue
        flag = parts[0]
        if flag in ("P", "A"):
            paused = flag == "P"
            if len(parts) >= 2:
                try:
                    pending = max(0, int(parts[1]))
                except ValueError:
                    pass
            else:
                pending = 0
        elif len(parts) == 1 and set(flag) <= {"P", "A"}:
            paused = flag[-1] == "P"
            pending = 0
    return paused, pending


class LegacyTray:
    def __init__(self, on_open, on_connected=None, on_exit=None, on_toggle_pause=None):
        # Only the icon and its Open Keeper menu live on the X11 connection.
        # The private pipes carry pause state and the open/connected/toggle events.
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
        self.on_toggle_pause = on_toggle_pause
        self.paused = True
        self.pending = 0
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
            if self.on_exit is not None:
                self.on_exit()
            return
        for event in events:
            if event == ord("O"):
                self.on_open()
            elif event == ord("C") and self.on_connected is not None:
                self.on_connected()
            elif event == ord("T") and self.on_toggle_pause is not None:
                self.on_toggle_pause()
        self._listen(stream)

    def set_state(self, paused, pending=0):
        pending = max(0, int(pending))
        if self.paused != paused or self.pending != pending:
            self.paused = paused
            self.pending = pending
            try:
                self.process.get_stdin_pipe().write_all(
                    f"{'P' if paused else 'A'} {pending}\n".encode("ascii"), None
                )
            except GLib.Error:
                pass

    def set_paused(self, paused):
        self.set_state(paused, self.pending)

    def close(self):
        self.stopping = True
        self.process.force_exit()


def _x11_shape(display):
    from ctypes import (CDLL, POINTER, Structure, c_int, c_short, c_ulong, c_ushort, c_void_p,
                        py_object, pythonapi)

    class XRectangle(Structure):
        _fields_ = [("x", c_short), ("y", c_short), ("width", c_ushort), ("height", c_ushort)]

    capsule_pointer = pythonapi.PyCapsule_GetPointer
    capsule_pointer.argtypes = [py_object, c_void_p]
    capsule_pointer.restype = c_void_p
    get_xdisplay = CDLL("libgdk-3.so.0").gdk_x11_display_get_xdisplay
    get_xdisplay.argtypes = [c_void_p]
    get_xdisplay.restype = c_void_p
    xdisplay = get_xdisplay(capsule_pointer(display.__gpointer__, None))
    combine = CDLL("libXext.so.6").XShapeCombineRectangles
    combine.argtypes = [c_void_p, c_ulong, c_int, c_int, c_int, POINTER(XRectangle), c_int, c_int, c_int]
    combine.restype = None

    def apply(window, region, x, y, scale):
        rectangles = [
            XRectangle(rect.x * scale, rect.y * scale, rect.width * scale, rect.height * scale)
            for rect in (region.get_rectangle(index) for index in range(region.num_rectangles()))
        ]
        array = (XRectangle * len(rectangles))(*rectangles)
        # GTK can omit the native shape update after the tray host embeds the plug.
        # Apply ShapeBounding / ShapeSet / Unsorted on GTK's own X11 connection.
        display.error_trap_push()
        try:
            combine(xdisplay, window, 0, x * scale, y * scale, array, len(array), 0, 0)
        finally:
            display.error_trap_pop_ignored()
        display.flush()

    return apply


def main():
    initialized, _ = Gtk.init_check()
    if not initialized:
        return

    import cairo
    gi.require_version("GdkX11", "3.0")
    from gi.repository import Gdk, GdkX11

    display = Gdk.Display.get_default()
    apply_shape = _x11_shape(display) if display.supports_shapes() else None
    icon = Gtk.StatusIcon()
    icon.set_title("Keeper")
    icon.set_name("Keeper")
    menu = Gtk.Menu()
    show = Gtk.MenuItem(label="Open Keeper")
    toggle = Gtk.MenuItem(label="Resume Agent Access")
    menu.append(show)
    menu.append(toggle)
    menu.show_all()

    def send(event):
        sys.stdout.buffer.write(event)
        sys.stdout.flush()

    def shape_icon():
        if apply_shape is None or not icon.is_embedded():
            return GLib.SOURCE_REMOVE
        xid = icon.get_x11_window_id()
        window = GdkX11.X11Window.lookup_for_display(display, xid)
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
            apply_shape(xid, region, x, y, window.get_scale_factor())
            # Some panels paint the opaque XEmbed socket behind our plug.
            # It is dedicated to this tray icon and has the same dimensions.
            socket = tray.get_socket_window() if isinstance(tray, Gtk.Plug) else None
            if socket is not None and socket.get_visual().get_depth() == 24:
                plug_x, plug_y, plug_width, plug_height = window.get_geometry()
                _, _, socket_width, socket_height = socket.get_geometry()
                if (plug_x, plug_y, plug_width, plug_height) == (0, 0, socket_width, socket_height):
                    apply_shape(socket.get_xid(), region, x, y, socket.get_scale_factor())
        return GLib.SOURCE_REMOVE

    def size_changed(*_):
        GLib.idle_add(shape_icon)
        return False

    tray_state = {"paused": True, "pending": 0, "buffer": b""}

    def set_icon(paused, pending=0):
        name = PAUSED_ICON if paused else ACTIVE_ICON
        icon.set_from_file(str(ICON_DIRECTORY / f"{name}.png"))
        toggle.set_label("Resume Agent Access" if paused else "Pause Agent Access")
        state_text = "Agent access paused" if paused else "Agent access active"
        if pending > 0:
            icon.set_tooltip_text(f"Keeper · {pending} pending · {state_text}")
        else:
            icon.set_tooltip_text(f"Keeper · {state_text}")
        GLib.idle_add(shape_icon)

    def embedded(*_):
        if icon.is_embedded():
            GLib.idle_add(shape_icon)
            GLib.timeout_add(100, shape_icon)
            send(b"C\n")
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
        chunk = tray_state["buffer"] + status
        if chunk.endswith(b"\n") or (not tray_state["buffer"] and set(status) <= {ord("P"), ord("A")}):
            complete, tray_state["buffer"] = chunk, b""
        elif b"\n" in chunk:
            head, _, tray_state["buffer"] = chunk.rpartition(b"\n")
            complete = head + b"\n"
        else:
            tray_state["buffer"] = chunk
            return GLib.SOURCE_CONTINUE
        paused, pending = _parse_tray_state(
            complete.decode("ascii", "ignore"), tray_state["paused"], tray_state["pending"]
        )
        tray_state["paused"], tray_state["pending"] = paused, pending
        set_icon(paused, pending)
        return GLib.SOURCE_CONTINUE

    icon.connect("activate", lambda *_: send(b"O\n"))
    show.connect("activate", lambda *_: send(b"O\n"))
    toggle.connect("activate", lambda *_: send(b"T\n"))
    icon.connect("popup-menu", lambda *_: menu.popup_at_pointer(None))
    icon.connect("notify::embedded", embedded)
    icon.connect("size-changed", size_changed)
    set_icon(True, 0)
    GLib.timeout_add(EMBED_TIMEOUT_MS, check_embedded)
    GLib.io_add_watch(sys.stdin, GLib.PRIORITY_DEFAULT, GLib.IO_IN | GLib.IO_HUP, update_state)
    if icon.is_embedded():
        send(b"C\n")
    Gtk.main()


if __name__ == "__main__":
    main()
