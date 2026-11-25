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
from time import monotonic

from .access_settings import ActionType, BrowserForm, Destination
from .browser_action import prepare_browser
from .command_action import deliver_credential, deliver_prompt, prepare_command
from .console_request import open_console
from .console_transport import ConsoleTimeoutError
from .entry_projection import active_entry, entry_listing, owner_snapshot
from .https_action import authenticate, failure, prepare_https
from .protocol import RESPONSE_LIMIT, decode, encode, sanitize_error_detail
from .result_delivery import GuestLoginCache, deliver_results, parse_result_usage
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
    consoles = {}
    guest_logins = GuestLoginCache()
    while line := sys.stdin.buffer.readline(EDIT_LIMIT):
        if line == b"list_entries\n":
            reply(entry_listing(vault))
            continue
        data = json.loads(line)
        if data["operation"] == "forget_guest_login":
            guest_logins.forget(data["key"])
            reply(encode({"forgotten": True}))
            continue
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
        if data["operation"] == "ssh_credentials":
            reply(encode(ssh_credentials_payload(vault, data)))
            continue
        entry, metadata = active_entry(vault, data["entry"])
        if data["operation"] == "entry":
            reply(encode({"entry": metadata}))
        elif data["operation"] == "owner_entry_notes":
            reply(entry_text_frame(entry, "notes"))
        elif data["operation"] == "owner_entry_password":
            reply(entry_text_frame(entry, "password"))
        elif data["operation"] in ("console_open", "console_view", "console_input", "console_close"):
            reply(encode(use_console(consoles, data, entry)))
        elif data["operation"] == "use_password":
            if data["kind"] == ActionType.RESULTS:
                provision = data.get("provision")
                account = active_entry(vault, provision["entry"])[0] if provision and provision["entry"] != data["entry"] else None
                use_results(entry, data["result_request"], data["url"],
                            allow_username=data.get("allow_username") is True, private_result=data.get("private_result"),
                            login_context=data.get("login_context"), login_cache=guest_logins,
                            provision=provision, account=account)
            elif data["kind"] == ActionType.STDIN:
                use_command(entry, data["command"], data["executable_sha256"], opaque=data.get("opaque", False))
            elif data["kind"] == ActionType.NETWORK_PROMPT:
                use_command(entry, data["command"], data["executable_sha256"],
                            opaque=data.get("opaque", False),
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


def entry_text_frame(entry, field):
    if entry is None:
        return encode({"error": "unavailable"})
    value = getattr(entry, field) or ""
    if len(value) <= RESPONSE_LIMIT:
        frame = encode({field: value})
        if len(frame) <= RESPONSE_LIMIT:
            return frame
    return encode({"error": "too_large"})


def _safe_active_entry(vault, identifier):
    if not isinstance(identifier, str):
        return None
    try:
        return active_entry(vault, identifier)[0]
    except ValueError:
        return None


def _looks_like_private_key(text):
    return isinstance(text, str) and "-----BEGIN" in text and "PRIVATE KEY-----" in text


def _decode_private_key_bytes(raw):
    if not isinstance(raw, (bytes, bytearray)):
        return None
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if _looks_like_private_key(text) else None


def _read_attachment_key(attachment):
    from pykeepass.exceptions import BinaryError

    try:
        return _decode_private_key_bytes(attachment.data)
    except BinaryError:
        return None


def ssh_credentials_payload(vault, data):
    entry = _safe_active_entry(vault, data.get("entry"))
    if entry is None:
        return {"error": "unavailable"}

    username = entry.username or ""
    password = entry.password or ""
    props = entry.custom_properties or {}
    private_key = None
    attachment_name = data.get("attachment")
    attachments = entry.attachments or ()

    if attachment_name is not None:
        if not isinstance(attachment_name, str) or not attachment_name:
            return {"error": "unavailable"}
        for attachment in attachments:
            if attachment.filename == attachment_name:
                private_key = _read_attachment_key(attachment)
                if private_key is not None:
                    break
        if private_key is None:
            return {"error": "unavailable"}
    else:
        for attachment in attachments:
            private_key = _read_attachment_key(attachment)
            if private_key is not None:
                break
        if private_key is None:
            prop_key = props.get("ssh_private_key")
            if _looks_like_private_key(prop_key):
                private_key = prop_key
            elif _looks_like_private_key(password):
                private_key = password
                password = props.get("ssh_passphrase") or ""

    sudo_password = None
    sudo_entry_id = data.get("sudo_entry")
    if sudo_entry_id is not None:
        sudo_entry = _safe_active_entry(vault, sudo_entry_id)
        if sudo_entry is None:
            return {"error": "unavailable"}
        sudo_password = sudo_entry.password or ""

    return {
        "username": username,
        "password": password,
        "private_key": private_key,
        "sudo_password": sudo_password,
    }


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


def use_results(entry, descriptor, origin, *, allow_username=False, private_result=None, login_context=None,
                login_cache=None, provision=None, account=None):
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
        reply(encode(deliver_results(request, entry, dispatch, allow_username=allow_username, private_result=private_result,
                                     login_context=login_context, login_cache=login_cache,
                                     provision=provision, account=account)))
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


def use_console(consoles, data, entry):
    for handle, console in tuple(consoles.items()):
        if monotonic() >= console.expires:
            consoles.pop(handle).close()
    identifier, operation = data["console"], data["operation"]

    def dispatch():
        reply(encode({"ready": True}))
        return sys.stdin.buffer.readline(16) == b"dispatch\n"

    try:
        if operation == "console_open":
            if entry is None or identifier in consoles or len(consoles) >= 4:
                return {"error": "console_failed"}
            consoles[identifier] = open_console(data["request"], entry, dispatch, expires_at=data.get("expires_at"))
            return {"outcome": "succeeded"}
        console = consoles.get(identifier)
        if console is None:
            return {"error": "console_closed"}
        if not dispatch():
            raise PermissionError
        if operation == "console_close":
            consoles.pop(identifier).close()
        elif entry is None:
            raise ValueError
        elif operation == "console_view":
            return console.view(status_only=data.get("status_only") is True)
        else:
            console.input(data["events"])
        return {"outcome": "succeeded"}
    except ConsoleTimeoutError:
        return {"error": "console_timeout"}
    except (OSError, EOFError, HTTPException, ValueError, TypeError, KeyError, ImportError):
        console = consoles.pop(identifier, None)
        if console is not None:
            console.close()
        return {"error": "console_failed"}


def use_command(entry, command, digest, *, opaque=False, **profile):
    if entry is None:
        reply(encode({"error": "unavailable", "detail": "The entry is unavailable."} if opaque else failure()))
        return
    result = failure()
    ready = False
    try:
        with prepare_command(command, digest, **profile) as process:
            reply(encode({"ready": True}))
            ready = True
            if sys.stdin.buffer.readline(16) == b"dispatch\n":
                if "destination" in profile:
                    outcome = deliver_prompt(process, entry.password)
                else:
                    outcome = "succeeded" if deliver_credential(process, entry.password) else "failed"
                result = {"outcome": outcome}
        # Complete scope/relay cleanup before releasing the serialized worker
        # request. A child-controlled teardown must not affect the next call.
        reply(encode(result))
    except (OSError, ValueError) as error:
        if opaque and not ready:
            reply(encode({"error": "unavailable", "detail": sanitize_error_detail(str(error))}))
        else:
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
