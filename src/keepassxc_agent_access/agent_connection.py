"""Read the administrator-installed Keeper connection for this desktop account."""

import json
import os
from pathlib import Path
import stat

from .broker import BrokerConfig


def connection_record(owner):
    return Path(f"/etc/keeper/connection-{owner}.json")


def connection_socket(owner):
    return Path(f"/run/keeper-connect-{owner}.sock")


def installed_connection(owner=None):
    owner = os.getuid() if owner is None else owner
    path = connection_record(owner)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 4096:
                return None
            record = json.load(stream)
        endpoint, uid = record["endpoint"], record["uid"]
        if (record["owner"] != owner or record["version"] != 1 or not isinstance(endpoint, str)
                or not Path(endpoint).is_absolute() or type(uid) is not int or not 0 < uid < 2**32 - 1
                or uid == owner):
            return None
        return BrokerConfig(Path(endpoint), uid)
    except (OSError, KeyError, TypeError, ValueError):
        return None
