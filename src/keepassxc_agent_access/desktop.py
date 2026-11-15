"""GNOME and logind desktop lifecycle notifications."""

import os

from gi.repository import Gio, GLib


class DesktopSession:
    def __init__(self, on_lock, on_exit):
        self.on_lock = on_lock
        self.on_exit = on_exit
        self.locked = False
        self.subscriptions = []
        self.session_id = os.environ.get("XDG_SESSION_ID")
        try:
            self._watch_gnome(Gio.bus_get_sync(Gio.BusType.SESSION, None))
        except GLib.Error:
            pass
        try:
            self._watch_logind(Gio.bus_get_sync(Gio.BusType.SYSTEM, None))
        except GLib.Error:
            pass

    def _subscribe(self, bus, name, interface, member, path, callback):
        subscription = bus.signal_subscribe(
            name, interface, member, path, None, Gio.DBusSignalFlags.NONE, callback
        )
        self.subscriptions.append((bus, subscription))

    def _watch_gnome(self, bus):
        name = "org.gnome.ScreenSaver"
        path = "/org/gnome/ScreenSaver"
        self._subscribe(bus, name, name, "ActiveChanged", path, self._gnome_signal)
        result = bus.call_sync(
            name, path, name, "GetActive", None, GLib.VariantType.new("(b)"),
            Gio.DBusCallFlags.NO_AUTO_START, 500, None,
        )
        self.locked = result.unpack()[0]

    def _gnome_signal(self, _bus, _sender, _path, _interface, _member, params):
        self.locked = params.unpack()[0]
        if self.locked:
            self.on_lock()

    def _watch_logind(self, bus):
        name = "org.freedesktop.login1"
        manager = "/org/freedesktop/login1"
        self._subscribe(bus, name, name + ".Manager", "PrepareForShutdown", manager, self._manager_signal)
        if self.session_id:
            self._subscribe(bus, name, name + ".Manager", "SessionRemoved", manager, self._manager_signal)
            result = bus.call_sync(
                name, manager, name + ".Manager", "GetSession", GLib.Variant("(s)", (self.session_id,)),
                GLib.VariantType.new("(o)"), Gio.DBusCallFlags.NONE, 500, None,
            )
            path = result.unpack()[0]
            self._subscribe(bus, name, name + ".Session", "Lock", path, self._logind_lock)

    def _manager_signal(self, _bus, _sender, _path, _interface, member, params):
        value = params.unpack()[0]
        if (member == "PrepareForShutdown" and value) or (
            member == "SessionRemoved" and value == self.session_id
        ):
            self.on_exit()

    def _logind_lock(self, *_):
        self.on_lock()

    def close(self):
        for bus, subscription in self.subscriptions:
            bus.signal_unsubscribe(subscription)
        self.subscriptions.clear()
