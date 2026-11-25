"""The one-request JSON protocol used by the entry-listing CLI."""

import json
import re
from time import monotonic


REQUEST_LIMIT = 131072
UPLOAD_LIMIT = 8 * 1024**2
RESPONSE_LIMIT = 1024 * 1024
CONSOLE_OPERATIONS = frozenset({"console_open", "console_view", "console_input", "console_close"})
CONSOLE_SECONDS = 900
MAX_CONSOLE_REUSE_MINUTES = 60
GUEST_OPERATIONS = frozenset({"guest_run", "guest_status", "guest_release"})
MAX_GUEST_REUSE_MINUTES = 60
MAX_GUEST_TEXT = 2048
SSH_OPERATIONS = frozenset({"ssh_exec", "ssh_upload", "ssh_download"})
MAX_SSH_TIMEOUT = 120
MAX_SSH_REUSE_MINUTES = 60
MAX_WAIT_SECONDS = 60
MAX_TOKEN_LIFESPAN_DAYS = 365
WORKFLOW_OPERATIONS = frozenset({"workflow_request", "workflow_run", "workflow_status"})
REQUEST_TIMEOUT = 5
WORKER_TIMEOUT = 3
APPROVAL_TIMEOUT = 60
CLIENT_TIMEOUT = APPROVAL_TIMEOUT + 35
_MAX_ARGS = 32
_MAX_ARG_BYTES = 4096
ENTRY_FIELDS = ("username", "url", "notes", "has_totp", "custom_attribute_keys", "attachments")
LIST_REQUEST = {"version": 1, "operation": "list_entries"}
ERRORS = {
    "unavailable": "Agent access is unavailable. Ask the vault owner to check broker access.",
    "invalid_request": "The broker rejected the request.",
    "invalid_response": "The broker returned an invalid response.",
    "declined": "The owner declined the request.",
    "expired": "The approval request timed out.",
    "revoked": "Agent access changed before the request completed.",
    "busy": "The broker is busy.",
    "ineligible": "The requested operation is unavailable for this token.",
    "choose_entry_group": "Choose a named group for the entry. Agents cannot create or move entries directly under the vault root.",
    "write_approval_required": "This token allows reads here. Set approve_write_once to true on the protected HTTPS write to request approval for just that operation.",
    "receipt_exists": "This write is already tracked. Check its receipt instead of submitting it again.",
    "receipt_conflict": "This receipt ID already refers to another write. Check the original receipt.",
    "receipt_limit": "This token has reached its write receipt limit. Ask the vault owner for a new task token.",
    "console_closed": "This console is closed or unavailable to this token. Request a new console if you still need it.",
    "console_timeout": "The console did not respond in time. The session is still open; retry viewing or sending input.",
    "console_failed": "Keeper could not complete the console operation. Check the approved endpoint and certificate or reopen the console.",
    "guest_job_unavailable": "This guest job is unavailable to the profile. Check its write receipt and verify the remote state before submitting again.",
    "workflow_unavailable": "This reviewed workflow is unavailable to the profile. Check the individual write receipts before requesting new approval.",
    "dependency_unavailable": "An earlier workflow step has not supplied the expected result. Check its receipt and the remote state.",
    "wait_elapsed": "The wait ended before Keeper received a status response. Check the existing operation again without resubmitting it.",
    "credential_changed": "That entry's credential changed after approval. Request a permission change for owner review.",
    "token_change_pending": "This token already has a permission change awaiting review.",
    "token_extension_pending": "This token already has a life span extension awaiting review.",
    "identity_in_use": "That identity is already in use. Choose a different identity and retry the request.",
    "token_required": "An approved access token is required. Request access through this runner.",
    "paused": "The owner has paused agent access.",
    "select_vault": "Choose a vault with --vault using your scoped vault catalog.",
    "token_storage": "The runner token file is unavailable or unsafe.",
    "audit_unavailable": "The broker could not verify settings or record the decision.",
    "too_large": "The request or response exceeds the size limit.",
    "host_key_mismatch": "The SSH server presented a host key that does not match the expected fingerprint.",
    "ssh_failed": "The SSH operation could not be completed.",
}


def sanitize_error_detail(detail):
    if not isinstance(detail, str):
        return None
    cleaned = " ".join(part for part in "".join(
        char if char.isprintable() else " " for char in detail
    ).split())
    if not cleaned:
        return None
    return cleaned[:240]


class ListingError(Exception):
    def __init__(self, code="unavailable", detail=None):
        self.code = code
        self.detail = sanitize_error_detail(detail)
        message = f"{ERRORS[code]} {self.detail}" if self.detail else ERRORS[code]
        super().__init__(message)


def validate_command(command):
    if (not isinstance(command, (tuple, list)) or not 1 <= len(command) <= _MAX_ARGS + 1
            or any(not isinstance(arg, str) or "\0" in arg or len(arg.encode("utf-8")) > _MAX_ARG_BYTES
                   or arg and not arg.isprintable() for arg in command)
            or not re.fullmatch(r"/usr/bin/[A-Za-z0-9._+-]+", command[0])
            or command[0].endswith(("/.", "/..")) or len(encode(command)) > 16384):
        raise ValueError("Choose an executable in /usr/bin and a short list of literal arguments.")
    return tuple(command)


def validate_upload(info):
    if (not isinstance(info, dict) or set(info) != {"size", "sha256"}
            or type(info["size"]) is not int or not 0 < info["size"] <= UPLOAD_LIMIT
            or not isinstance(info["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", info["sha256"])):
        raise ValueError("Invalid input file description.")
    return info


def encode(message):
    return json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate JSON member")
        result[name] = value
    return result


def decode(frame):
    return json.loads(frame.decode("utf-8"), object_pairs_hook=_unique_object)


def remaining(deadline):
    seconds = deadline - monotonic()
    if seconds <= 0:
        raise TimeoutError
    return seconds


def read_frame(read, limit):
    data = bytearray()
    while len(data) < limit:
        chunk = read(min(65536, limit - len(data)))
        if not chunk:
            raise EOFError
        data.extend(chunk)
        newline = data.find(b"\n", len(data) - len(chunk))
        if newline >= 0:
            if newline != len(data) - 1:
                raise ValueError("Trailing data after frame")
            return bytes(data)
    raise ListingError("too_large")


def receive(connection, limit, deadline):
    def read(size):
        connection.settimeout(remaining(deadline))
        return connection.recv(size)

    return read_frame(read, limit)
