"""Private worker protocol over inherited pipes."""

import ctypes
from hashlib import file_digest
from http.client import HTTPException
import json
import os
from select import select
import subprocess
import sys
from threading import Thread

from .access_settings import ActionType, BrowserForm, Destination
from .browser_action import prepare_browser
from .command_action import deliver_credential, deliver_prompt, prepare_command
from .entry_projection import active_entry, entry_listing, owner_snapshot
from .https_action import authenticate, failure, prepare_https
from .protocol import RESPONSE_LIMIT, decode, encode
from .result_delivery import deliver_results, parse_result_usage
from .vault_edits import EDIT_LIMIT, EditError, database_file, file_stamp, stage_edit


def load_vault():
    from pykeepass import PyKeePass
    from pykeepass.exceptions import CredentialsError

    request = json.loads(sys.stdin.buffer.readline())
    path = request["database"]
    writable = request.get("writable") is True
    try:
        with (database_file(path) if writable else open(path, "rb")) as database:
            stamp = file_stamp(os.fstat(database.fileno()))
            fingerprint = file_digest(database, "sha256").hexdigest()
            database.seek(0)
            vault = PyKeePass(database, password=request["password"], keyfile=request["key_file"])
            if file_stamp(os.fstat(database.fileno())) != stamp:
                return
    except CredentialsError:
        print("credentials", flush=True)
        return
    finally:
        request.pop("password", None)
    vault.password = None
    for resources in (vault.entries, vault.groups):
        if len({item.uuid for item in resources}) != len(resources):
            print("ambiguous", flush=True)
            return
    print("ready", vault.root_group.uuid, fingerprint, flush=True)
    while line := sys.stdin.buffer.readline(EDIT_LIMIT):
        if line == b"list_entries\n":
            reply(entry_listing(vault))
            continue
        data = json.loads(line)
        if data["operation"] == "owner_edit":
            if not writable:
                reply(encode({"error": "read_only"}))
                continue
            try:
                vault, stamp, response = stage_edit(
                    vault, path, stamp, data, lambda: reply(encode({"ready": True})),
                    lambda: sys.stdin.buffer.readline(16) == b"commit\n",
                )
            except EditError as error:
                response = encode({"error": str(error)})
            except Exception:
                response = encode({"error": "save_failed"})
            finally:
                data.pop("password", None)
                data.pop("notes", None)
            reply(response)
            continue
        if data["operation"] == "owner_snapshot":
            reply(owner_snapshot(vault))
            continue
        if data["operation"] == "scoped_entries":
            reply(entry_listing(vault, frozenset(data["entries"])))
            continue
        entry, metadata = active_entry(vault, data["entry"])
        if data["operation"] == "entry":
            reply(encode({"entry": metadata}))
        elif data["operation"] == "owner_entry_notes":
            reply(entry_notes_frame(entry))
        elif data["operation"] == "use_password":
            if data["kind"] == ActionType.RESULTS:
                use_results(entry, data["result_request"], data["url"], allow_username=data.get("allow_username") is True)
            elif data["kind"] == ActionType.STDIN:
                use_command(entry, data["command"], data["executable_sha256"])
            elif data["kind"] == ActionType.NETWORK_PROMPT:
                use_command(entry, data["command"], data["executable_sha256"],
                            destination=Destination.parse(data["url"]), prompt_variable=data["prompt_variable"],
                            input_path=data["input_path"], generic_prompt=data.get("opaque", False),
                            environment=data.get("environment", ()), prompt_contains=data.get("prompt_contains", ""))
            elif data["kind"] == ActionType.BROWSER:
                use_browser(entry, data["url"], BrowserForm(**data["browser"]))
            else:
                use(entry, data["url"], ActionType(data["kind"]), data["method"], data["request_json"],
                    headers=data.get("headers", ()), query=data.get("query", ()))
        else:
            return


def entry_notes_frame(entry):
    if entry is None:
        return encode({"error": "unavailable"})
    notes = entry.notes or ""
    if len(notes) <= RESPONSE_LIMIT:
        frame = encode({"notes": notes})
        if len(frame) <= RESPONSE_LIMIT:
            return frame
    return encode({"error": "too_large"})


def reply(data):
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def use(entry, url, kind, method, request_json, *, headers=(), query=()):
    if entry is None:
        reply(encode(failure()))
        return
    try:
        with prepare_https(url, query=query) as (connection, path):
            reply(encode({"ready": True}))
            decision = sys.stdin.buffer.readline(16)
            result = failure()
            if decision == b"dispatch\n":
                result = authenticate(connection, path, entry, kind, method=method, request_json=request_json, headers=headers)
            reply(encode(result))
    except (OSError, HTTPException, ValueError):
        reply(encode(failure()))


def use_results(entry, descriptor, origin, *, allow_username=False):
    if entry is None:
        reply(encode(failure()))
        return
    try:
        request = parse_result_usage(decode(descriptor.encode("utf-8")))
        if request.origin != origin:
            raise ValueError
        def dispatch():
            reply(encode({"ready": True}))
            return sys.stdin.buffer.readline(16) == b"dispatch\n"
        reply(encode(deliver_results(request, entry, dispatch, allow_username=allow_username)))
    except (OSError, HTTPException, ValueError, TypeError, KeyError):
        reply(encode(failure()))


def use_browser(entry, url, profile):
    if entry is None:
        reply(encode(failure()))
        return
    try:
        with prepare_browser(url, profile, entry) as submit:
            reply(encode({"ready": True}))
            result = submit() if sys.stdin.buffer.readline(16) == b"dispatch\n" else failure()
            reply(encode(result))
    except (OSError, HTTPException, ValueError, subprocess.SubprocessError):
        reply(encode(failure()))


def use_command(entry, command, digest, **profile):
    if entry is None:
        reply(encode(failure()))
        return
    result = failure()
    try:
        with prepare_command(command, digest, **profile) as process:
            reply(encode({"ready": True}))
            if sys.stdin.buffer.readline(16) == b"dispatch\n":
                if "destination" in profile:
                    outcome = deliver_prompt(process, entry.password)
                else:
                    outcome = "succeeded" if deliver_credential(process, entry.password) else "failed"
                result = {"outcome": outcome}
        # Complete scope/relay cleanup before releasing the serialized worker
        # request. A child-controlled teardown must not affect the next call.
        reply(encode(result))
    except (OSError, ValueError):
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
