"""Access to a KeePass database in a disposable worker process."""

from contextlib import contextmanager
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from select import select
import subprocess
import sys
from threading import Event, Lock
from time import monotonic, sleep

from .protocol import ListingError, RESPONSE_LIMIT, WORKER_TIMEOUT, decode, encode, read_frame, remaining
from .vault_edits import EDIT_LIMIT, EDIT_TIMEOUT


DYNAMIC_LOCAL_WINDOW = 12
DYNAMIC_NETWORK_WINDOW = 28


class VaultError(Exception):
    """A safe, user-facing vault error."""


class VaultChanged(VaultError):
    """The database changed outside the current session."""


class UnlockCancelled(Exception):
    """An unlock request was invalidated."""


@dataclass(frozen=True)
class VaultTarget:
    database: Path
    key_file: Path | None = None


class VaultSession:
    def __init__(self, process):
        self._process = process
        self.identity = None
        self.fingerprint = None
        self._state = Lock()
        self._requests = Lock()

    def close(self):
        with self._state:
            process, self._process = self._process, None
        if process is None:
            return
        # Discard the worker's entire address space, including decrypted data.
        process.kill()
        process.wait()
        process.stdin.close()
        process.stdout.close()

    @property
    def available(self):
        with self._state:
            return self._process is not None and self._process.poll() is None

    @contextmanager
    def _exchange(self, request, timeout):
        if not self._requests.acquire(timeout=WORKER_TIMEOUT):
            raise ListingError("busy")
        deadline = monotonic() + timeout
        read_fd = None
        try:
            with self._state:
                if self._process is None:
                    raise ListingError()
                read_fd = os.dup(self._process.stdout.fileno())
            self._send(request)

            def read(size):
                readable, _, _ = select([read_fd], [], [], remaining(deadline))
                if not readable:
                    raise TimeoutError
                return os.read(read_fd, size)

            yield lambda: read_frame(read, RESPONSE_LIMIT)
        except (OSError, EOFError, ValueError):
            # The worker exchange cannot be resumed after a transport error.
            self.close()
            raise ListingError() from None
        finally:
            if read_fd is not None:
                os.close(read_fd)
            self._requests.release()

    def _send(self, request):
        with self._state:
            if self._process is None:
                raise ListingError("revoked")
            self._process.stdin.write(request)
            self._process.stdin.flush()

    def list_entries(self):
        with self._exchange(b"list_entries\n", WORKER_TIMEOUT) as read:
            return read()

    def scoped_entries(self, entries):
        request = encode({"operation": "scoped_entries", "entries": sorted(entries)})
        with self._exchange(request, WORKER_TIMEOUT) as read:
            return decode(read())

    def owner_snapshot(self):
        request = encode({"operation": "owner_snapshot"})
        try:
            with self._exchange(request, WORKER_TIMEOUT) as read:
                snapshot = decode(read())
                if "error" in snapshot:
                    raise ListingError(snapshot["error"])
                return snapshot
        except (ListingError, ValueError):
            raise VaultError("Could not load the vault groups and entries.") from None

    def owner_entry_notes(self, identifier):
        request = encode({"operation": "owner_entry_notes", "entry": identifier})
        try:
            with self._exchange(request, WORKER_TIMEOUT) as read:
                response = decode(read())
                if isinstance(response.get("notes"), str):
                    return response["notes"]
                if response.get("error") == "too_large":
                    return None
        except (ListingError, ValueError, AttributeError):
            pass
        raise VaultError("Could not load the entry notes.")

    def owner_edit(self, change, gate):
        request = encode({"operation": "owner_edit", **change})
        if len(request) > EDIT_LIMIT:
            raise VaultError("The edit is too large.")
        try:
            with self._exchange(request, EDIT_TIMEOUT) as read:
                response = decode(read())
                if response == {"ready": True}:
                    attempted = False

                    def publish():
                        nonlocal attempted, response
                        attempted = True
                        self._send(b"commit\n")
                        response = decode(read())

                    try:
                        # The workspace can keep its final authorization guard held
                        # until publication is confirmed by the edit worker.
                        accepted = gate(publish)
                    finally:
                        if not attempted:
                            try:
                                self._send(b"abort\n")
                                read()
                            except (ListingError, OSError, EOFError, ValueError):
                                self.close()
                    if not accepted:
                        raise VaultError("The vault locked or access changed before the edit could be saved.")
        except ListingError as error:
            if error.code == "busy":
                raise VaultError("Another operation is using this vault. Try again.") from None
            raise VaultError("Could not confirm the edit. Reopen the vault to check it.") from None
        error = response.get("error")
        if error == "changed":
            raise VaultChanged("The KeePass file changed on disk. Unlock it again before editing.")
        if error:
            messages = {
                "invalid": "The name, entry, or destination group is invalid.",
                "cycle": "Choose a destination outside the group you are moving.",
                "read_only": "This vault file is read-only.",
                "recycle_disabled": "Enable the vault’s recycle bin before removing items.",
                "version": "Keeper edits KDBX 4 vaults. This vault remains read-only.",
                "busy": "Another process is saving this vault. Try again.",
                "cancelled": "The vault locked before the edit could be saved.",
                "too_large": "The resulting vault snapshot is too large.",
            }
            raise VaultError(messages.get(error, "Could not save the vault."))
        return response

    def entry(self, identifier):
        request = encode({"operation": "entry", "entry": identifier})
        with self._exchange(request, WORKER_TIMEOUT) as read:
            return decode(read())["entry"]

    def use(self, action, gate, *, input_path=None, allow_username=False):
        request = encode({"operation": "use_password", "entry": action.entry,
                          "url": action.url, "kind": action.kind, "command": action.command,
                          "method": action.method, "request_json": action.request_json,
                          "result_request": action.result_request, "allow_username": bool(allow_username),
                          "headers": action.headers, "query": action.query, "opaque": action.opaque, "environment": action.environment, "prompt_contains": action.prompt_contains,
                          "browser": asdict(action.browser) if action.browser else None,
                          "executable_sha256": action.executable_sha256, "prompt_variable": action.prompt_variable,
                          "input_path": str(input_path) if input_path is not None else None})
        if action.result_request:
            return self._result_exchange(request, gate, 2 if "login" in json.loads(action.result_request) else 1)
        timeout = 33 if action.browser else 25 if action.prompt_variable else 12
        window = (DYNAMIC_NETWORK_WINDOW if action.prompt_variable else DYNAMIC_LOCAL_WINDOW) if action.opaque else 0
        with self._exchange(request, timeout) as read:
            deadline = monotonic() + window
            # Keep the serialized vault request occupied for the common window,
            # including subprocess teardown, so another scoped request cannot
            # turn the child-controlled runtime into an exit/timing oracle.
            try:
                response = decode(read())
                if response != {"ready": True}:
                    return response
                dispatched = False
                attempted = False

                def send():
                    nonlocal attempted
                    attempted = True
                    self._send(b"dispatch\n")

                try:
                    dispatched = gate(send)
                except (OSError, EOFError, ValueError, ListingError):
                    if not action.opaque or not attempted:
                        raise
                    self.close()
                    return {"outcome": "dispatched"}
                finally:
                    if not dispatched and not attempted:
                        try:
                            self._send(b"abort\n")
                            read()
                        except (OSError, EOFError, ValueError, ListingError):
                            self.close()
                if not dispatched:
                    raise ListingError("revoked")
                try:
                    response = decode(read())
                except (OSError, EOFError, ValueError, ListingError):
                    if not action.opaque:
                        raise
                    self.close()
                    return {"outcome": "dispatched"}
                # Dynamic code can encode the secret in exit status, stdout,
                # stderr or runtime. None of those become an agent result.
                if action.opaque:
                    private = response.get("outcome") if isinstance(response, dict) else None
                    return {"outcome": "dispatched",
                            "_execution_outcome": private if private in ("succeeded", "failed", "uncertain") else "unknown"}
                return response
            finally:
                if window:
                    sleep(max(0, deadline - monotonic()))

    def _result_exchange(self, request, gate, steps):
        # Each request that can carry authentication has its own owner guard.
        # The login response and captures remain inside the worker throughout.
        with self._exchange(request, 30) as read:
            response = decode(read())
            sent = 0
            while response == {"ready": True}:
                if sent >= steps:
                    self.close()
                    raise ListingError("invalid_response")
                dispatched = False
                try:
                    dispatched = gate(lambda: self._send(b"dispatch\n"))
                finally:
                    if not dispatched:
                        try:
                            self._send(b"abort\n")
                            read()
                        except (OSError, EOFError, ValueError, ListingError):
                            self.close()
                if not dispatched:
                    raise ListingError("revoked")
                sent += 1
                response = decode(read())
            return response

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def open_vault(target: VaultTarget, password: str, cancelled: Event, *, writable=False) -> VaultSession:
    if cancelled.is_set():
        raise UnlockCancelled
    for label, path in (("database", target.database), ("key file", target.key_file)):
        if path is not None and not path.is_file():
            raise VaultError(f"The {label} is missing or unreadable.")

    try:
        process = subprocess.Popen(
            [sys.executable, "-I", str(Path(__file__).resolve().parents[1] / "keeper_bootstrap.py"),
             "keepassxc_agent_access.vault_worker", str(os.getpid())],
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
            "writable": writable,
        })
        process.stdin.write(request.encode("ascii") + b"\n")
        process.stdin.flush()
        del request, password
        while not cancelled.is_set():
            readable, _, _ = select([process.stdout], [], [], 0.05)
            if readable:
                response = process.stdout.readline(128)
                if response.startswith(b"ready "):
                    if cancelled.is_set():
                        break
                    _, session.identity, session.fingerprint = response.decode("ascii").split()
                    return session
                if response == b"ambiguous\n":
                    raise VaultError("The database has duplicate entry or group IDs.")
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
