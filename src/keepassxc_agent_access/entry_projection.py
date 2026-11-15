"""Serialize only the entry fields the agent is allowed to receive."""

from base64 import b64decode
from uuid import UUID

from .protocol import RESPONSE_LIMIT, encode


def entry_listing(vault):
    configured_bin = vault.tree.findtext("Meta/RecycleBinUUID")
    recycle_id = UUID(bytes=b64decode(configured_bin)) if configured_bin else None
    output = bytearray(b'{"entries":[')
    separator = b""
    for entry in vault.entries:
        group = entry.group
        group_path = []
        while group is not None and not group.is_root_group:
            if group.uuid == recycle_id:
                break
            group_path.append(group.name or "")
            group = group.parentgroup
        else:
            row = encode({
                "id": str(entry.uuid),
                "title": entry.title or "",
                "group_path": list(reversed(group_path)),
            })[:-1]
            if len(output) + len(separator) + len(row) + 3 > RESPONSE_LIMIT:
                return encode({"error": "too_large"})
            output.extend(separator)
            output.extend(row)
            separator = b","
    output.extend(b"]}\n")
    return bytes(output)
