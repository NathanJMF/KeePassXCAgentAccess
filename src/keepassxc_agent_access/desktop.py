"""GNOME and logind desktop lifecycle notifications."""

import os

from gi.repository import Gio, GLib


class DesktopSession:
    def __init__(self, on_lock, on_exit, on_unlock=None):
        self.on_lock = on_lock
        self.on_exit = on_exit
        self.on_unlock = on_unlock
        self.locked = True
        self.states = {"gnome": None, "logind": None}
        self.subscriptions = []
        self.session_id = os.environ.get("XDG_SESSION_ID")
        self.session_bus = self.system_bus = None
        self.logind_path = None
        self.initializing = True
        self.logind_lock_requested = False
        try:
            self.session_bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            self._watch_gnome(self.session_bus)
        except GLib.Error:
            pass
        try:
            self.system_bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
            self._watch_logind(self.system_bus)
        except GLib.Error:
            pass
        self._poll()
        self.initializing = False
        self.poll = GLib.timeout_add_seconds(2, self._poll)

    @property
    def available(self):
        return any(value is not None for value in self.states.values())

    def _set_state(self, source, value):
        previous = self.locked
        self.states[source] = value
        self.locked = not self.available or any(value is True for value in self.states.values())
        on_unlock = getattr(self, "on_unlock", None)
        if self.locked and not previous and not self.initializing:
            self.on_lock()
        elif not self.locked and previous and not self.initializing and on_unlock:
            on_unlock()

    def _subscribe(self, bus, name, interface, member, path, callback):
        subscription = bus.signal_subscribe(
            name, interface, member, path, None, Gio.DBusSignalFlags.NONE, callback
        )
        self.subscriptions.append((bus, subscription))

    def _watch_gnome(self, bus):
        name = "org.gnome.ScreenSaver"
        self._subscribe(bus, name, name, "ActiveChanged", "/org/gnome/ScreenSaver", self._gnome_signal)
        self._subscribe(bus, "org.freedesktop.DBus", "org.freedesktop.DBus", "NameOwnerChanged",
                        "/org/freedesktop/DBus", self._owner_changed)

    def _owner_changed(self, _bus, _sender, _path, _interface, _member, params):
        name, _, owner = params.unpack()
        if name == "org.gnome.ScreenSaver":
            self._set_state("gnome", None)
            if owner:
                self._poll()

    def _poll(self):
        for attribute, bus_type, watch in (
            ("session_bus", Gio.BusType.SESSION, self._watch_gnome),
            ("system_bus", Gio.BusType.SYSTEM, self._watch_logind),
        ):
            bus = getattr(self, attribute)
            if bus is None or bus.is_closed():
                for connection, subscription in tuple(self.subscriptions):
                    if connection is bus:
                        connection.signal_unsubscribe(subscription)
                        self.subscriptions.remove((connection, subscription))
                if attribute == "system_bus":
                    self.logind_path = None
                try:
                    bus = Gio.bus_get_sync(bus_type, None)
                    setattr(self, attribute, bus)
                    watch(bus)
                except GLib.Error:
                    setattr(self, attribute, None)
        state = None
        if self.session_bus is not None:
            try:
                result = self.session_bus.call_sync(
                    "org.gnome.ScreenSaver", "/org/gnome/ScreenSaver", "org.gnome.ScreenSaver",
                    "GetActive", None, GLib.VariantType.new("(b)"),
                    Gio.DBusCallFlags.NO_AUTO_START, 500, None,
                )
                state = result.unpack()[0]
            except GLib.Error:
                pass
        self._set_state("gnome", state)
        state = None
        if self.system_bus is not None and self.session_id:
            try:
                if self.logind_path is None:
                    result = self.system_bus.call_sync(
                        "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
                        "GetSession", GLib.Variant("(s)", (self.session_id,)), GLib.VariantType.new("(o)"),
                        Gio.DBusCallFlags.NO_AUTO_START, 500, None,
                    )
                    self.logind_path = result.unpack()[0]
                    self._subscribe(self.system_bus, "org.freedesktop.login1", "org.freedesktop.login1.Session",
                                    "Lock", self.logind_path, self._logind_lock)
                    self._subscribe(self.system_bus, "org.freedesktop.login1", "org.freedesktop.login1.Session",
                                    "Unlock", self.logind_path, self._logind_unlock)
                result = self.system_bus.call_sync(
                    "org.freedesktop.login1", self.logind_path, "org.freedesktop.DBus.Properties",
                    "Get", GLib.Variant("(ss)", ("org.freedesktop.login1.Session", "LockedHint")),
                    GLib.VariantType.new("(v)"), Gio.DBusCallFlags.NO_AUTO_START, 500, None,
                )
                state = result.unpack()[0]
                if state:
                    self.logind_lock_requested = False
                state = state or self.logind_lock_requested
            except GLib.Error:
                pass
        self._set_state("logind", True if self.logind_lock_requested else state)
        return GLib.SOURCE_CONTINUE

    def _gnome_signal(self, _bus, _sender, _path, _interface, _member, params):
        self._set_state("gnome", params.unpack()[0])

    def _watch_logind(self, bus):
        name = "org.freedesktop.login1"
        manager = "/org/freedesktop/login1"
        self._subscribe(bus, name, name + ".Manager", "PrepareForShutdown", manager, self._manager_signal)
        if self.session_id:
            self._subscribe(bus, name, name + ".Manager", "SessionRemoved", manager, self._manager_signal)

    def _manager_signal(self, _bus, _sender, _path, _interface, member, params):
        value = params.unpack()[0]
        if (member == "PrepareForShutdown" and value) or (
            member == "SessionRemoved" and value == self.session_id
        ):
            self.on_exit()

    def _logind_lock(self, *_):
        self.logind_lock_requested = True
        self._set_state("logind", True)

    def _logind_unlock(self, *_):
        self.logind_lock_requested = False
        self._poll()

    def close(self):
        GLib.source_remove(self.poll)
        for bus, subscription in self.subscriptions:
            bus.signal_unsubscribe(subscription)
        self.subscriptions.clear()
