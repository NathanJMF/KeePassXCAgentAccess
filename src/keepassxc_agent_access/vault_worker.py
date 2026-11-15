"""Private worker protocol over inherited pipes."""

import ctypes
import json
import os
import signal
import sys

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
    # Linux prctl: disable dumps and terminate if the owning desktop process exits.
    if libc.prctl(4, 0, 0, 0, 0) or libc.prctl(1, signal.SIGKILL, 0, 0, 0):
        return
    if os.getppid() != int(sys.argv[1]):
        return
    try:
        load_vault()
    except Exception:
        print("invalid", flush=True)


if __name__ == "__main__":
    main()
