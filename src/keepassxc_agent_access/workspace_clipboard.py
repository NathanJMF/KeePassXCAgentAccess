"""Temporary clipboard ownership for passwords copied by the desktop user."""

from gi.repository import Gdk, GLib, Gtk


PASSWORD_CLIPBOARD_TIMEOUT_MS = 30_000


class PasswordClipboard:
    def __init__(self, screen):
        self._clipboard = Gtk.Clipboard.get_for_display(screen.get_display(), Gdk.SELECTION_CLIPBOARD)
        self._buffer = Gtk.TextBuffer()
        # Use GTK's clipboard backend, including its Wayland data-device integration.
        self._buffer.add_selection_clipboard(self._clipboard)
        self._is_current = None
        self._timer = None

    def copy(self, text, is_current):
        self.clear()
        self._buffer.set_text(text)
        self._buffer.select_range(*self._buffer.get_bounds())
        if self._clipboard.get_owner() is not self._buffer:
            self._buffer.set_text("")
            return False
        self._is_current = is_current
        self._timer = GLib.timeout_add(PASSWORD_CLIPBOARD_TIMEOUT_MS, self._expire)
        return True

    def _expire(self):
        self._timer = None
        self.clear()
        return GLib.SOURCE_REMOVE

    def check(self):
        if self._is_current and (self._clipboard.get_owner() is not self._buffer or not self._is_current()):
            self.clear()

    def clear(self):
        if self._timer is not None:
            GLib.source_remove(self._timer)
            self._timer = None
        self._is_current = None
        self._buffer.set_text("")

    def close(self):
        self.clear()
        self._buffer.remove_selection_clipboard(self._clipboard)
