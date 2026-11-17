"""Names and references available before an agent requests a grant."""

import json

from .access_settings import uuid_text
from .settings import SettingsError, write_private_json


def snapshot(groups, entries):
    def text(value):
        if not isinstance(value, str):
            raise ValueError("Catalog names must be text.")
        return value

    return {
        "groups": [{"id": uuid_text(row["id"]), "name": text(row["name"]),
                    "parent": uuid_text(row["parent"]) if row["parent"] is not None else None}
                   for row in groups],
        "entries": [{"id": uuid_text(row["id"]), "title": text(row["title"]), "group": uuid_text(row["group"])}
                    for row in entries],
    }


class DiscoveryCatalog:
    def __init__(self, path):
        self.path = path
        self.snapshots = {}
        try:
            saved = json.loads(path.read_text())
            if saved["version"] != 1:
                return
            self.snapshots = {uuid_text(key): snapshot(value["groups"], value["entries"])
                              for key, value in saved["vaults"].items()}
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            self.snapshots = {}

    def remember(self, identifier, groups, entries):
        self.snapshots[identifier] = snapshot(groups, entries)
        self.save()

    def forget(self, identifier):
        self.snapshots.pop(identifier, None)
        self.save()

    def save(self):
        try:
            write_private_json(self.path, {"version": 1, "vaults": self.snapshots})
        except SettingsError:
            # Cache persistence cannot turn a committed vault edit into a failure.
            # A previously saved catalog is always described as cached.
            pass

    def references(self, workspace):
        return tuple(item for record in workspace.registrations.values()
                     for item in (record, workspace.session(record.id), self.snapshots.get(record.id)))

    def read(self, workspace, *, vault=None, summary=False):
        rows = []
        for record in workspace.registrations.values():
            if vault is not None and record.id != vault:
                continue
            session = workspace.session(record.id)
            cached = self.snapshots.get(record.id)
            data = snapshot(session.groups, session.entries) if session and not summary else cached
            rows.append({
                "id": record.id, "name": record.name, "locked": session is None,
                "cached": session is None and cached is not None, "available": session is not None or data is not None,
                "groups": data["groups"] if data and not summary else [],
                "entries": data["entries"] if data and not summary else [],
            })
        return {"vaults": rows}
