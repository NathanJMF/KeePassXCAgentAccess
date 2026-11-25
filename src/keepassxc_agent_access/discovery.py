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
                     for item in (record, workspace.owner_session(record.id), self.snapshots.get(record.id)))

    @staticmethod
    def _filter_snapshot(data, query):
        groups_by_id = {group["id"]: group for group in data["groups"]}
        chains = {}

        def group_chain(identifier):
            if identifier in chains:
                return chains[identifier]
            chain = []
            visited = set()
            current = identifier
            while current is not None and current not in visited:
                visited.add(current)
                group = groups_by_id.get(current)
                if group is None:
                    break
                chain.append(group)
                current = group["parent"]
            chain.reverse()
            chains[identifier] = chain
            return chain

        matched_groups = set()
        for group in data["groups"]:
            chain = group_chain(group["id"])
            names = [item["name"] for item in chain if item["name"]]
            slash_path = "/".join(names).casefold()
            spaced_path = " / ".join(names).casefold()
            if query in group["name"].casefold() or query in slash_path or query in spaced_path:
                matched_groups.add(group["id"])

        matched_entries = [
            entry for entry in data["entries"]
            if query in entry["title"].casefold() or entry["group"] in matched_groups
        ]
        if not matched_groups and not matched_entries:
            return None

        included_groups = set()
        for gid in matched_groups:
            included_groups.update(item["id"] for item in group_chain(gid))
        for entry in matched_entries:
            included_groups.update(item["id"] for item in group_chain(entry["group"]))

        return {
            "groups": [group for group in data["groups"] if group["id"] in included_groups],
            "entries": matched_entries,
        }

    def read(self, workspace, *, vault=None, summary=False, query=None):
        needle = None
        if query is not None:
            if not isinstance(query, str) or not query.strip() or len(query) > 128 or not query.isprintable():
                raise ValueError("Invalid discovery query.")
            needle = query.casefold()
        rows = []
        for record in workspace.registrations.values():
            if vault is not None and record.id != vault:
                continue
            session = workspace.owner_session(record.id)
            cached = self.snapshots.get(record.id)
            data = snapshot(session.groups, session.entries) if session and (not summary or needle is not None) else cached
            if needle is not None:
                vault_matches = needle in record.name.casefold()
                if not vault_matches:
                    if not data:
                        continue
                    data = self._filter_snapshot(data, needle)
                    if data is None:
                        continue
            rows.append({
                "id": record.id, "name": record.name, "locked": session is None,
                "cached": session is None and cached is not None, "available": session is not None or data is not None,
                "groups": data["groups"] if data and not summary else [],
                "entries": data["entries"] if data and not summary else [],
            })
        return {"vaults": rows}
