"""Preferences and display tracking for automatic request reviews."""

import json
from pathlib import Path

from .settings import SettingsError, write_private_json


class ReviewPopups:
    def __init__(self, path):
        self._path = Path(path)
        self.enabled = True
        self._reviewed = set()

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
            raise SettingsError("Could not read the request pop-up setting.") from None
        self.enabled = enabled

    def set_enabled(self, enabled):
        # Keep the preference saved by versions that used desktop notifications.
        write_private_json(self._path, {"desktop_notifications": enabled})
        self.enabled = enabled

    def next_request(self, pending):
        self._reviewed.intersection_update(pending)
        if self.enabled:
            return next((request for request in pending if request not in self._reviewed), None)
        return None

    def mark_reviewed(self, kind, identifier):
        self._reviewed.add((kind, identifier))
