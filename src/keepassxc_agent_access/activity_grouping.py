"""Relationships and resources for the desktop Activity view."""

from .access_settings import uuid_text
from .activity import entry_label, folder_label


EDIT_STAGES = frozenset(("Request edit", "Apply edit", "Deny edit", "Cancel edit"))
TOKEN_EVENTS = frozenset(("Request token", "Approve token", "Deny token", "Disable token", "Re-enable token", "Remove token"))


def edit_reference(row, prefix):
    """Read a UUID field from the older edit audit format."""
    if row.get("action", "").partition(" · ")[0] in EDIT_STAGES:
        for part in (row.get("scope") or "").split(" · "):
            if part.startswith(prefix):
                try:
                    return uuid_text(part.removeprefix(prefix))
                except ValueError:
                    return None
    return None


def event_time(row):
    return next(row[key] for key in ("completed", "decided", "requested") if row.get(key) is not None)


def event_relationship(row):
    action = row["action"]
    stage, _, operation = action.partition(" · ")
    if token := row.get("token"):
        if stage in EDIT_STAGES:
            request = row.get("edit_request_id") or edit_reference(row, "Edit request ")
            if request:
                return ("edit", token, request), operation or "Edit request"
        if action in TOKEN_EVENTS:
            return ("token", token), "Access token"

        chat = row.get("chat_id")
        vault, entry = row.get("vault_id"), row.get("entry")
        comparable = (action == "List vaults" or action == "List entries" and vault
                      or stage == "Use password" and vault and entry and row.get("destination"))
        if chat and comparable:
            key = ("operation", token, row.get("uid"), chat, action, vault, entry, row.get("destination"),
                   row.get("scope"))
            return key, action
    return ("event", row["id"]), action


def activity_groups(rows):
    groups = {}
    for row in sorted(rows, key=lambda event: (event_time(event), event["id"]), reverse=True):
        key, title = event_relationship(row)
        if key not in groups:
            groups[key] = (title, [])
        groups[key][1].append(row)
    return groups


class ActivityResources:
    def __init__(self, workspace, *, mark_current=False):
        self.workspace = workspace
        self.mark_current = mark_current
        self.snapshots = {}

    def _snapshot(self, vault):
        if vault not in self.snapshots:
            entries, groups = {}, {}
            session = self.workspace.owner_session(vault)
            if session:
                entries = {row["id"]: row for row in session.entries}
                groups = {row["id"]: row for row in session.groups}
            self.snapshots[vault] = (entries, groups)
        return self.snapshots[vault]

    def labels(self, row):
        values = [row.get(key) for key in ("vault", "folder", "entry_title")]
        vault, entry = row.get("vault_id"), row.get("entry")
        group = row.get("group_id") or edit_reference(row, "Group ")
        if group is None and not entry:
            group = edit_reference(row, "Destination group ")
        if not self.workspace or not vault:
            return tuple(values)

        def current(value):
            return f"{value} (current)" if self.mark_current else value

        with self.workspace.mutex:
            record = self.workspace.registrations.get(vault)
            if record is None:
                return tuple(values)
            values[0] = values[0] or current(record.name)
            if (not values[2] and entry) or (not values[1] and (entry or group)):
                entries, groups = self._snapshot(vault)
                target = entries.get(entry)
                if target:
                    values[2] = values[2] or current(entry_label(target["title"]))
                if not values[1] and group in groups:
                    segments = []
                    while group in groups and groups[group]["parent"] is not None:
                        segments.append(groups[group]["name"])
                        group = groups[group]["parent"]
                    values[1] = current(folder_label(reversed(segments)))
                elif not values[1] and target:
                    values[1] = current(folder_label(target["group_path"]))
        return tuple(values)


RESOURCE_REFS = {"vault": "vault_id", "group": "group_id", "key": "entry"}


def activity_matches(row, resource, filters):
    labels = dict(zip(RESOURCE_REFS, resource))
    for field, query in filters.items():
        value = labels.get(field) if field in RESOURCE_REFS else row.get(field)
        reference = row.get(RESOURCE_REFS.get(field, ""))
        searchable = " ".join(str(part) for part in (value, reference) if part)
        if query not in searchable.casefold():
            return False
    return True
