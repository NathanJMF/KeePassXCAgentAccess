"""Desktop notifications for requests awaiting the owner's review."""

import json
from pathlib import Path

from gi.repository import Gio, GLib

from .settings import SettingsError, write_private_json


REVIEW_ACTION = "review-request"
TITLES = {"grant": "Keeper access request", "edit": "Keeper edit request"}


def notification_id(kind, identifier):
    return f"{kind}:{identifier}"


def review_notification(kind, identifier):
    notification = Gio.Notification.new(TITLES[kind])
    notification.set_body("Open Keeper to review this request.")
    target = GLib.Variant("(ss)", (kind, identifier))
    action = f"app.{REVIEW_ACTION}"
    notification.set_default_action_and_target(action, target)
    notification.add_button_with_target("Review request", action, target)
    return notification


class ReviewNotifications:
    def __init__(self, application, path):
        self._application = application
        self._path = Path(path)
        self.enabled = True
        self._sent = set()

    def load(self):
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            enabled = data["desktop_notifications"]
            if type(enabled) is not bool:
                raise ValueError
        except FileNotFoundError:
            enabled = True
        except (OSError, ValueError, TypeError, KeyError):
            self.enabled = False
            raise SettingsError("Could not read the desktop notification setting.") from None
        self.enabled = enabled

    def set_enabled(self, enabled):
        write_private_json(self._path, {"desktop_notifications": enabled})
        self.enabled = enabled
        if not enabled:
            self.sync(())

    def sync(self, pending):
        current = set(pending) if self.enabled else set()
        for kind, identifier in sorted(self._sent - current):
            self._application.withdraw_notification(notification_id(kind, identifier))
        for kind, identifier in sorted(current - self._sent):
            self._application.send_notification(notification_id(kind, identifier), review_notification(kind, identifier))
        self._sent = current
