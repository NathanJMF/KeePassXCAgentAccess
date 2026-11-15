"""Read-only access to a KeePass database in a disposable worker process."""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from select import select
import subprocess
import sys
from threading import Event


class VaultError(Exception):
    """A safe, user-facing vault error."""


class UnlockCancelled(Exception):
    """An unlock request was invalidated."""


@dataclass(frozen=True)
class VaultTarget:
    database: Path
    key_file: Path | None = None


class VaultSession:
    def __init__(self, process):
        self._process = process

    def close(self):
        process, self._process = self._process, None
        if process is None:
            return
        # Discard the worker's entire address space, including decrypted data.
        process.kill()
        process.wait()
        process.stdin.close()
        process.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def open_vault(target: VaultTarget, password: str, cancelled: Event) -> VaultSession:
    if cancelled.is_set():
        raise UnlockCancelled
    for label, path in (("database", target.database), ("key file", target.key_file)):
        if path is not None and not path.is_file():
            raise VaultError(f"The {label} is missing or unreadable.")

    try:
        process = subprocess.Popen(
            [sys.executable, "-m", "keepassxc_agent_access.vault_worker", str(os.getpid())],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        raise VaultError("The KeePass worker could not start.") from None

    session = VaultSession(process)
    try:
        request = json.dumps({
            "database": str(target.database),
            "key_file": str(target.key_file) if target.key_file else None,
            "password": password,
        })
        process.stdin.write(request.encode("ascii") + b"\n")
        process.stdin.flush()
        del request, password
        while not cancelled.is_set():
            readable, _, _ = select([process.stdout], [], [], 0.05)
            if readable:
                response = process.stdout.readline(64)
                if response == b"ready\n":
                    if cancelled.is_set():
                        break
                    return session
                if response == b"credentials\n":
                    raise VaultError("The database rejected the password or key file.")
                raise VaultError("The database could not be opened. Check the files and format.")
        raise UnlockCancelled
    except OSError:
        session.close()
        raise VaultError("The KeePass worker stopped unexpectedly.") from None
    except BaseException:
        session.close()
        raise
