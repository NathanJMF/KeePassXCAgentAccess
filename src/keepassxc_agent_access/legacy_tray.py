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

    def set_icon(paused):
        name = PAUSED_ICON if paused else ACTIVE_ICON
        icon.set_from_file(str(ICON_DIRECTORY / f"{name}.png"))
        icon.set_tooltip_text("Keeper · " + ("Agent access paused" if paused else "Agent access active"))

    def embedded(*_):
        if icon.is_embedded():
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
    set_icon(True)
    GLib.timeout_add(EMBED_TIMEOUT_MS, check_embedded)
    GLib.io_add_watch(sys.stdin, GLib.PRIORITY_DEFAULT, GLib.IO_IN | GLib.IO_HUP, update_state)
    if icon.is_embedded():
        send(b"C")
    Gtk.main()


if __name__ == "__main__":
    main()
