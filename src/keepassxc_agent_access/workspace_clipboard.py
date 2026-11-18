"""Temporary clipboard ownership for passwords copied by the desktop user."""

from gi.repository import Gdk, GLib, Gtk


PASSWORD_CLIPBOARD_TIMEOUT_MS = 30_000


class PasswordClipboard:
    def __init__(self, screen):
        self._widget = Gtk.Invisible.new_for_screen(screen)
        self._text = None
        self._is_current = None
        self._timer = None
        # Advertise text without asking a clipboard manager to save it.
        for target in ("UTF8_STRING", "text/plain;charset=utf-8", "text/plain"):
            Gtk.selection_add_target(self._widget, Gdk.SELECTION_CLIPBOARD, Gdk.Atom.intern(target, False), 0)
        self._widget.connect("selection-get", self._provide)
        self._widget.connect("selection-clear-event", self._forget)

    def copy(self, text, is_current):
        if not Gtk.selection_owner_set(self._widget, Gdk.SELECTION_CLIPBOARD, Gtk.get_current_event_time()):
            return False
        self._forget()
        self._text = text
        self._is_current = is_current
        self._timer = GLib.timeout_add(PASSWORD_CLIPBOARD_TIMEOUT_MS, self._expire)
        return True

    def _provide(self, _widget, data, _info, _timestamp):
        if self._is_current and self._is_current():
            data.set_text(self._text, -1)

    def _forget(self, *_):
        if self._timer is not None:
            GLib.source_remove(self._timer)
            self._timer = None
        self._text = self._is_current = None
        return False

    def _expire(self):
        self._timer = None
        self.clear()
        return GLib.SOURCE_REMOVE

    def check(self):
        if self._is_current and not self._is_current():
            self.clear()

    def clear(self):
        owned = self._text is not None
        self._forget()
        if owned and Gdk.selection_owner_get_for_display(
            self._widget.get_display(), Gdk.SELECTION_CLIPBOARD
        ) == self._widget.get_window():
            Gtk.selection_owner_set(None, Gdk.SELECTION_CLIPBOARD, Gdk.CURRENT_TIME)

    def close(self):
        self.clear()
        self._widget.destroy()
