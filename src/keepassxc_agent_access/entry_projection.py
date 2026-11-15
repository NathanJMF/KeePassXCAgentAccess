"""Serialize owner snapshots and scoped agent entry metadata."""

from base64 import b64decode
from datetime import datetime, timezone
from struct import error as StructError
from uuid import UUID

from .protocol import RESPONSE_LIMIT, encode


def _recycle_id(vault):
    configured = vault.tree.findtext("Meta/RecycleBinUUID")
    return UUID(bytes=b64decode(configured)) if configured else None


def _project(entry, recycle_id):
    group = entry.group
    group_path = []
    while group is not None and not group.is_root_group:
        if group.uuid == recycle_id:
            return None
        group_path.append(group.name or "")
        group = group.parentgroup
    return {"id": str(entry.uuid), "title": entry.title or "", "group_path": list(reversed(group_path))}


def active_entry(vault, identifier):
    entry = vault.find_entries(uuid=UUID(identifier), first=True)
    row = _project(entry, _recycle_id(vault)) if entry is not None else None
    return (entry, row) if row is not None else (None, None)


def entry_listing(vault, identifiers=None):
    recycle_id = _recycle_id(vault)
    output = bytearray(b'{"entries":[')
    separator = b""
    for entry in vault.entries:
        if identifiers is not None and str(entry.uuid) not in identifiers:
            continue
        projected = _project(entry, recycle_id)
        if projected is None:
            continue
        row = encode(projected)[:-1]
        if len(output) + len(separator) + len(row) + 3 > RESPONSE_LIMIT:
            return encode({"error": "too_large"})
        output.extend(separator)
        output.extend(row)
        separator = b","
    output.extend(b"]}\n")
    return bytes(output)

def _active_group(group, recycle_id):
    while group is not None:
        if group.uuid == recycle_id:
            return False
        group = group.parentgroup
    return True


def active_group(vault, identifier):
    group = vault.find_groups(uuid=UUID(identifier), first=True)
    return group if group is not None and _active_group(group, _recycle_id(vault)) else None


def _entry_timestamp(entry, field):
    try:
        value = getattr(entry, field, None)
        if not isinstance(value, datetime):
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    except (OverflowError, OSError, StructError, ValueError):
        return None


def owner_snapshot(vault):
    recycle_id = _recycle_id(vault)
    groups = [{"id": str(group.uuid), "name": group.name or "",
               "parent": None if group.is_root_group else str(group.parentgroup.uuid)}
              for group in vault.groups if _active_group(group, recycle_id)]
    entries = []
    for entry in vault.entries:
        row = _project(entry, recycle_id)
        if row is not None:
            entries.append(dict(row, group=str(entry.group.uuid),
                                username=entry.username or "", url=entry.url or "",
                                created=_entry_timestamp(entry, "ctime"),
                                modified=_entry_timestamp(entry, "mtime")))
    recycle_group = next((group for group in vault.groups if group.uuid == recycle_id), None)
    if recycle_group is None:
        recycle_path = [vault.root_group.name or "", "Recycle Bin"]
    else:
        recycle_path = []
        while recycle_group is not None:
            recycle_path.append(recycle_group.name or "")
            recycle_group = recycle_group.parentgroup
        recycle_path.reverse()
    recycle_bin = {
        "enabled": vault.tree.findtext("Meta/RecycleBinEnabled") == "True",
        "path": recycle_path,
    }
    response = encode({"groups": groups, "entries": entries, "recycle_bin": recycle_bin})
    return response if len(response) <= RESPONSE_LIMIT else encode({"error": "too_large"})
