"""Private worker protocol over inherited pipes."""

import ctypes
import json
import os
from select import select
import sys
from threading import Thread

from .entry_projection import entry_listing


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
    print("ready", flush=True)
    # The pipe is private to the owning desktop process.
    while sys.stdin.buffer.readline(64) == b"list_entries\n":
        sys.stdout.buffer.write(entry_listing(vault))
        sys.stdout.buffer.flush()


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
