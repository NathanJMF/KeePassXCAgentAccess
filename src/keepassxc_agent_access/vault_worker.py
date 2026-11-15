"""Private worker protocol over inherited pipes."""

import ctypes
import json
from http.client import HTTPException
import os
from select import select
import sys
from threading import Thread

from .entry_projection import active_entry, entry_listing
from .https_action import authenticate, failure, prepare_https
from .protocol import REQUEST_LIMIT, encode


def load_vault():
    from pykeepass import PyKeePass
    from pykeepass.exceptions import CredentialsError

    request = json.loads(sys.stdin.buffer.readline())
    try:
        # Passing a read-only stream prevents the session from saving the database.
        with open(request["database"], "rb") as database:
            vault = PyKeePass(database, password=request["password"], keyfile=request["key_file"])
    except CredentialsError:
        print("credentials", flush=True)
        return
    finally:
        request.pop("password", None)
    vault.password = None
    print("ready", vault.root_group.uuid, flush=True)
    while line := sys.stdin.buffer.readline(REQUEST_LIMIT):
        if line == b"list_entries\n":
            reply(entry_listing(vault))
            continue
        data = json.loads(line)
        entry, metadata = active_entry(vault, data["entry"])
        if data["operation"] == "entry":
            reply(encode({"entry": metadata}))
        elif data["operation"] == "use_password":
            use(entry, data["url"])
        else:
            return


def reply(data):
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def use(entry, url):
    if entry is None:
        reply(encode(failure()))
        return
    try:
        with prepare_https(url) as (connection, path):
            reply(encode({"ready": True}))
            decision = sys.stdin.buffer.readline(16)
            result = authenticate(connection, path, entry) if decision == b"dispatch\n" else failure()
            reply(encode(result))
    except (OSError, HTTPException, ValueError):
        reply(encode(failure()))


def main():
    libc = ctypes.CDLL(None)
    # Disable dumps of the process holding the decrypted database.
    if libc.prctl(4, 0, 0, 0, 0):
        return
    owner_pid = int(sys.argv[1])
    if os.getppid() != owner_pid:
        return
    owner = os.pidfd_open(owner_pid)
    if os.getppid() != owner_pid:
        os.close(owner)
        return

    def watch_owner():
        # A pidfd follows the desktop process even when its unlock thread ends.
        select([owner], [], [])
        os._exit(0)

    Thread(target=watch_owner, daemon=True).start()
    try:
        load_vault()
    except Exception:
        print("invalid", flush=True)


if __name__ == "__main__":
    main()
