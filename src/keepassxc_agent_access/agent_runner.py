"""Expose Keeper's scoped CLI operations over a trusted stdio MCP runner."""

import argparse
from base64 import b64decode
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from uuid import UUID

from .agent_cli import (EDIT_OPERATIONS, ENTRY_FIELDS, CREDENTIAL_USE_TYPES, USE_TYPES,
                        edit_request, edit_uuid, endpoint_target, usage_request)
from .protocol import (CLIENT_TIMEOUT, ERRORS, ListingError, MAX_CONSOLE_REUSE_MINUTES, MAX_GUEST_REUSE_MINUTES,
                       MAX_GUEST_TEXT, MAX_SSH_REUSE_MINUTES, MAX_SSH_TIMEOUT, MAX_TOKEN_LIFESPAN_DAYS,
                       MAX_WAIT_SECONDS, REQUEST_LIMIT, SSH_OPERATIONS, UPLOAD_LIMIT,
                       decode, encode, sanitize_error_detail, validate_command)
from .runner_token import UninitializedProfile, open_profile


CLI = Path(__file__).resolve().parents[2] / "keepassxc-agent"
MAX_MESSAGE = 4 * ((UPLOAD_LIMIT + 2) // 3) + REQUEST_LIMIT * 4
PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
PROFILE_NAME = r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"
CHAT_META_KEYS = ("threadId", "conversationId", "sessionId", "chatId")
SERVER_INSTRUCTIONS = (
    "Start with discover (with a short note) to find vault and entry UUIDs. "
    "On shared MCP connections without automatic thread IDs (such as Antigravity), pass a stable "
    "per-task profile (for example your conversation ID or a fresh UUID) on every Keeper tool call "
    "so this task keeps an isolated token across reconnects. Request only needed permissions with "
    "request_access, check approval with access_status, and use approved secrets without printing credentials."
)


def tool(name, description, properties=None, *, required=(), read_only=True):
    properties = dict(properties or {})
    properties["profile"] = {
        "type": "string",
        "pattern": f"^{PROFILE_NAME}$",
        "description": "Optional per-task profile ID (such as your conversation ID) on shared MCP connections. Reuse the same value across calls for this task.",
    }
    if name not in ("access_status", "edit_status", "write_status", "guest_status", "guest_wait", "console_wait",
                    "workflow_status"):
        properties["note"] = {"type": "string", "minLength": 1, "maxLength": 180,
                              "description": "Short audit reason. Keep credentials and private values out of notes."}
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": list(required),
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": read_only},
    }


REFERENCE = {"type": "string", "format": "uuid"}
FIELDS = {"type": "array", "items": {"enum": list(ENTRY_FIELDS)},
          "maxItems": len(ENTRY_FIELDS), "uniqueItems": True}
ENROLLMENT = {
    "type": "object",
    "properties": {
        "identity": {"type": "string", "description": "Required when creating a token; optional when updating with change_id."},
        "project": {"type": "string", "description": "Required when creating a token; optional when updating with change_id."},
        "change_id": {**REFERENCE, "description": "A new UUID to update this active token’s scope. Reuse it to check the change."},
        "mode": {"enum": ["replace", "add"],
                 "description": "Permission change mode: 'replace' (default) replaces scope, 'add' merges with existing approved scope (requires change_id)."},
        "items": {"type": "array", "minItems": 1, "maxItems": 32, "items": {
            "type": "object",
            "properties": {
                "vault": REFERENCE,
                "entry": REFERENCE,
                "group": REFERENCE,
                "edits": {"type": "array", "items": {"enum": [*EDIT_OPERATIONS, "move_into"]},
                          "minItems": 1, "uniqueItems": True},
                "label": {"type": "string"},
                "metadata": {"type": "boolean"},
                "username": {"type": "boolean"},
                "url": {"type": "boolean"},
                "notes": {"type": "boolean"},
                "action": {"type": "string", "description": "Optional legacy configured action ID."},
                "uses": {"type": "array", "items": {"enum": sorted(CREDENTIAL_USE_TYPES)}, "minItems": 1, "uniqueItems": True},
                "origins": {"type": "array", "items": {"type": "string"}, "maxItems": 16, "uniqueItems": True,
                            "description": "Explicit destinations the owner must approve (https://, ssh://, or tcp://host:port)."},
            },
            "additionalProperties": False,
        }},
    },
    "required": ["items"],
    "additionalProperties": False,
}
EDIT_REQUEST = {
    "type": "object",
    "properties": {
        "id": REFERENCE,
        "operation": {"enum": list(EDIT_OPERATIONS)},
        "vault": REFERENCE,
        "entry": REFERENCE,
        "group": REFERENCE,
        "parent": REFERENCE,
        "fields": {
            "type": "object",
            "properties": {key: {"type": "string"} for key in ("title", "username", "url", "notes", "name")},
            "additionalProperties": False,
        },
        "password_source": {"enum": ["owner", "generate"]},
    },
    "required": ["id", "operation", "vault"],
    "additionalProperties": False,
}
USAGE = {
    "type": "object",
    "properties": {"type": {"enum": sorted(USE_TYPES)}},
    "required": ["type"],
    "oneOf": [
        {
            "type": "object",
            "properties": {
                "type": {"enum": ["local_command"]},
                "command": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 33,
                            "description": "Executable in /usr/bin and literal arguments."},
            },
            "required": ["type", "command"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                "type": {"enum": ["networked_command"]},
                "command": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 33,
                            "description": "Executable in /usr/bin and literal arguments."},
                "origin": {"type": "string", "description": "Approved origin (for example https://host/ or tcp://host:port)."},
                "prompt_variable": {"type": "string", "description": "Prompt variable name ending in _ASKPASS."},
                "prompt_contains": {"type": "string", "minLength": 1, "maxLength": 80,
                                    "description": "Literal substring identifying the prompt; defaults to password."},
                "environment": {"type": "object", "additionalProperties": {"type": "string"}, "maxProperties": 16,
                                "description": "Optional nonsecret environment variables."},
            },
            "required": ["type", "command", "origin", "prompt_variable"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                "type": {"enum": ["https"]},
                "url": {"type": "string", "description": "Approved HTTPS target URL without query or fragment."},
                "auth": {"enum": ["basic", "bearer", "template"]},
                "method": {"enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]},
                "json": {"type": ["object", "string"]},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "query": {"type": "object", "additionalProperties": {"type": "string"}},
                "certificate_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$",
                                       "description": "Optional lowercase hex SHA-256 certificate pin for private-CA or self-signed endpoints."},
            },
            "required": ["type", "url", "auth"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                "type": {"enum": ["https_results"]},
                "origin": {"type": "string", "description": "Approved HTTPS origin."},
                "certificate_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$",
                                       "description": "Optional lowercase hex SHA-256 certificate pin for private-CA or self-signed endpoints."},
                "login": {
                    "type": "object",
                    "description": "Optional private POST authentication and named captures (JSON pointers, header:<Name>, or cookie:<Name>).",
                    "properties": {
                        "path": {"type": "string"},
                        "method": {"enum": ["POST"]},
                        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                        "form": {"type": "object", "additionalProperties": {"type": "string"}},
                        "json": {"type": ["object", "string"]},
                        "capture": {"type": "object", "additionalProperties": {"type": "string"},
                                    "minProperties": 1, "maxProperties": 4},
                    },
                    "required": ["path", "capture"],
                    "additionalProperties": False,
                },
                "request": {
                    "type": "object",
                    "description": "Same-origin protected resource request; session placeholders remain private. Custom headers are allowed on basic/bearer (except Authorization).",
                    "properties": {
                        "path": {"type": "string"},
                        "auth": {"enum": ["basic", "bearer", "template", "session"]},
                        "method": {"enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]},
                        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                        "query": {"type": "object", "additionalProperties": {"type": "string"}},
                        "json": {"type": ["object", "string"]},
                        "form": {"type": "object", "additionalProperties": {"type": "string"}},
                    },
                    "required": ["path", "auth"],
                    "additionalProperties": False,
                },
                "approve_write_once": {"type": "boolean", "description": "Ask the owner to approve this exact protected HTTPS write once."},
                "result": {
                    "type": "object",
                    "description": "JSON pointer, scalar columns or dot-paths, and optional safe response headers list.",
                    "properties": {
                        "path": {"type": "string"},
                        "columns": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 32},
                        "scalar": {"type": "string"},
                        "headers": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 8},
                    },
                    "additionalProperties": False,
                },
            },
            "required": ["type", "origin", "request", "result"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                "type": {"enum": ["browser"]},
                "url": {"type": "string"},
                "submit_url": {"type": "string"},
                "form_id": {"type": "string"},
                "username_field": {"type": "string"},
                "password_field": {"type": "string"},
                "success_id": {"type": "string"},
                "success_url": {"type": "string"},
            },
            "required": ["type", "url", "submit_url", "form_id", "username_field", "password_field", "success_id"],
            "additionalProperties": False,
        },
    ],
    "description": "Agent-supplied credential operation. No configured action ID needed. Commands return a dispatch receipt only.",
}
OPERATIONS = {
    "discover": (("discover",), tool("discover", "List all vaults, groups and entry names before requesting access. Returns only names, references and cache/lock status.",
        {"vault": REFERENCE,
         "summary": {"type": "boolean", "description": "List vault names and status only; use a vault UUID to fetch its groups and entry names separately."},
         "query": {"type": "string", "minLength": 1, "maxLength": 128,
                   "description": "Optional case-insensitive substring filter across vault names, group paths, and entry titles."}})),
    "access_status": (("access", "status"), tool(
        "access_status", "Check this token profile's status; request details to see its identity and permissions.",
        {"details": {"type": "boolean"}},
    )),
    "request_access": (("access", "request"), tool(
        "request_access", "Request a scoped token or update this token’s scope using a change_id (mode 'replace' or 'add').",
        {"request": ENROLLMENT}, required=("request",), read_only=False,
    )),
    "extend_access": (("access", "extend"), tool(
        "extend_access", "Request to extend this active token's life span or refresh its window up to the owner's configured default.",
        {"days": {"type": "integer", "minimum": 1, "maximum": MAX_TOKEN_LIFESPAN_DAYS,
                  "description": "Optional requested life span in days (defaults to the owner's setting)."},
         "extension_id": {**REFERENCE, "description": "Optional extension request UUID for idempotent retries."}},
        read_only=False,
    )),
    "release_entry": (("access", "release"), tool(
        "release_entry", "Immediately give up this token's access to one entry. A new owner grant is required to regain it.",
        {"vault": REFERENCE, "entry": REFERENCE}, required=("vault", "entry"), read_only=False,
    )),
    "request_edit": (("edits", "request"), tool(
        "request_edit", "Queue one vault edit for owner review. For password replacements pass only the password source.",
        {"request": EDIT_REQUEST}, required=("request",), read_only=False,
    )),
    "edit_status": (("edits", "status"), tool(
        "edit_status", "Check an edit request by its UUID.",
        {"id": REFERENCE}, required=("id",),
    )),
    "write_status": (("results", "status"), tool(
        "write_status", "Check a protected HTTPS write receipt without repeating the write.",
        {"receipt": REFERENCE}, required=("receipt",),
    )),
    "guest_run": (("guest", "run"), tool(
        "guest_run", "Submit a command to an owner-approved guest endpoint and retain its write receipt.",
        {"vault": REFERENCE, "entry": REFERENCE, "receipt": REFERENCE,
         "workflow": {
             "type": "object",
             "description": "Pinned command and status request template from the Keeper skill.",
             "properties": {
                 "origin": {"type": "string", "description": "Approved HTTPS origin."},
                 "certificate_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$",
                                        "description": "Optional lowercase hex SHA-256 certificate pin."},
                 "login": {"type": "object", "description": "Optional private POST login and captures."},
                 "body_type": {"enum": ["form", "json"]},
                 "command_field": {"type": "string", "description": "Unassigned submit body field name for the command."},
                 "job_query": {"type": "string", "description": "Unassigned poll query parameter name for the job ID."},
                 "argument_prefix": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 8,
                                     "description": "Optional fixed JSON argument prefix before the command."},
                 "submit": {"type": "object", "properties": {"request": {"type": "object"}, "job_path": {"type": "string"}},
                            "required": ["request", "job_path"], "additionalProperties": False},
                 "poll": {"type": "object", "properties": {"request": {"type": "object"}, "result": {"type": "object"}},
                          "required": ["request", "result"], "additionalProperties": False},
             },
             "required": ["origin", "submit", "poll", "body_type", "command_field", "job_query"],
             "additionalProperties": False,
         },
         "guest_command": {"type": "string", "minLength": 1, "maxLength": MAX_GUEST_TEXT},
         "reuse_minutes": {"type": "integer", "minimum": 1, "maximum": MAX_GUEST_REUSE_MINUTES}},
        required=("vault", "entry", "receipt", "workflow", "guest_command"), read_only=False,
    )),
    "guest_status": (("guest", "status"), tool(
        "guest_status", "Check the result fields approved for this guest job.",
        {"receipt": REFERENCE}, required=("receipt",),
    )),
    "guest_release": (("guest", "release"), tool(
        "guest_release", "Give up this guest job's status handle. The write receipt stays available.",
        {"receipt": REFERENCE}, required=("receipt",), read_only=False,
    )),
    "guest_wait": (("guest", "wait"), tool(
        "guest_wait", "Wait for a selected status field on an approved guest job.",
        {"receipt": REFERENCE, "until": {"type": "string"}, "equals": {"type": ["null", "boolean", "integer", "number", "string"]},
         "timeout": {"type": "integer", "minimum": 1, "maximum": MAX_WAIT_SECONDS}},
        required=("receipt", "until", "equals"),
    )),
    "console_open": (("console", "open"), tool(
        "console_open", "Open an approved guest console using the pinned connection descriptor.",
        {"vault": REFERENCE, "entry": REFERENCE,
         "request": {
             "type": "object",
             "description": "Pinned console connection descriptor.",
             "properties": {
                 "origin": {"type": "string", "description": "Approved HTTPS origin."},
                 "certificate_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$",
                                        "description": "Optional lowercase hex SHA-256 certificate pin."},
                 "login": {"type": "object", "description": "Private POST authentication and captures."},
                 "connect": {"type": "object", "description": "POST request to create the console session and capture ticket/port/password."},
                 "socket": {"type": "object", "description": "WebSocket path, headers, query, and optional RFB password placeholder."},
             },
             "required": ["origin", "login", "connect", "socket"],
             "additionalProperties": False,
         },
         "reuse_minutes": {"type": "integer", "minimum": 1, "maximum": MAX_CONSOLE_REUSE_MINUTES}},
        required=("vault", "entry", "request"), read_only=False,
    )),
    "console_view": (("console", "view"), tool(
        "console_view", "Check for console changes. Set image to true to request an image.",
        {"console": REFERENCE, "image": {"type": "boolean"}}, required=("console",),
    )),
    "console_wait": (("console", "wait"), tool(
        "console_wait", "Wait for a console frame to change without returning any pixels.",
        {"console": REFERENCE, "timeout": {"type": "integer", "minimum": 1, "maximum": MAX_WAIT_SECONDS}},
        required=("console",),
    )),
    "console_input": (("console", "input"), tool(
        "console_input", "Send an ordered list of key, text or pointer events to an approved guest console.",
        {"console": REFERENCE,
         "events": {
             "type": "array", "minItems": 1, "maxItems": 16,
             "description": "Ordered list of 1 to 16 key, text, or left-click events.",
             "items": {
                 "type": "object",
                 "properties": {
                     "key": {"type": "string", "description": "Named key (Enter, Tab, Escape, arrows, F1-F12), printable ASCII key, or modifier combo (Ctrl+C, Ctrl+D, Ctrl+Alt+Del)."},
                     "text": {"type": "string", "minLength": 1, "maxLength": 160, "description": "Printable ASCII text to type."},
                     "x": {"type": "integer", "minimum": 0, "maximum": 2047, "description": "Framebuffer X coordinate for left click."},
                     "y": {"type": "integer", "minimum": 0, "maximum": 2047, "description": "Framebuffer Y coordinate for left click."},
                 },
             },
         }},
        required=("console", "events"), read_only=False,
    )),
    "console_close": (("console", "close"), tool(
        "console_close", "Close this profile's approved guest console.",
        {"console": REFERENCE}, required=("console",), read_only=False,
    )),
    "workflow_request": (("workflows", "request"), tool(
        "workflow_request", "Ask the owner to review a bounded set of fixed HTTPS writes, guest commands and console opens.",
        {"request": {
             "type": "object",
             "description": "Pinned HTTPS workflow manifest from the Keeper skill.",
             "properties": {
                 "id": REFERENCE,
                 "vault": REFERENCE,
                 "entry": REFERENCE,
                 "origin": {"type": "string", "description": "Approved HTTPS origin."},
                 "certificate_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$",
                                        "description": "Optional lowercase hex SHA-256 certificate pin."},
                 "login": {"type": "object", "description": "Optional shared private POST authentication and captures."},
                 "minutes": {"type": "integer", "minimum": 1, "maximum": 60,
                             "description": "Authorization window in minutes (1-60)."},
                 "steps": {
                     "type": "array", "minItems": 1, "maxItems": 8,
                     "items": {
                         "type": "object",
                         "properties": {
                             "name": {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,31}$"},
                             "kind": {"enum": ["write", "console", "guest"]},
                             "request": {"type": "object"},
                             "result": {"type": "object"},
                             "capture_id": {"type": "boolean"},
                             "expected_id": {"type": ["integer", "string"],
                                             "description": "Optional expected positive integer or string ID when capturing."},
                             "command": {"type": "string", "description": "Command string for a guest step."},
                         },
                         "required": ["name", "request"],
                         "additionalProperties": False,
                     },
                 },
             },
             "required": ["id", "vault", "entry", "origin", "steps"],
             "additionalProperties": False,
         },
         "registration": {"type": "object", "properties": {"identity": {"type": "string"}, "project": {"type": "string"}},
                          "required": ["identity", "project"], "additionalProperties": False}},
        required=("request",), read_only=False,
    )),
    "workflow_status": (("workflows", "status"), tool(
        "workflow_status", "Check a reviewed workflow and its write receipts.",
        {"workflow": REFERENCE}, required=("workflow",),
    )),
    "workflow_run": (("workflows", "run"), tool(
        "workflow_run", "Run one named step in an approved workflow.",
        {"workflow": REFERENCE, "step": {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,31}$"}},
        required=("workflow", "step"), read_only=False,
    )),
    "provision_account": (("accounts", "provision"), tool(
        "provision_account", "Ask the owner to apply a separate stored account password in one approved HTTPS write.",
        {"vault": REFERENCE, "entry": REFERENCE, "account": REFERENCE, "receipt": REFERENCE,
         "workflow": {"type": "object", "description": "Exact pinned https_results write with approve_write_once: true."},
         "body_type": {"enum": ["form", "json"]},
         "fields": {
             "type": "object",
             "description": "Destination body field names for the account password (required) and optional username.",
             "properties": {
                 "password": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_-]{0,63}$"},
                 "username": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_-]{0,63}$"},
             },
             "required": ["password"],
             "additionalProperties": False,
         }},
        required=("vault", "entry", "account", "receipt", "workflow", "body_type", "fields"), read_only=False,
    )),
    "list_vaults": (("vaults", "list"), tool("list_vaults", "List vaults available to the active token.")),
    "list_entries": (("entries", "list"), tool(
        "list_entries", "List approved entry metadata and optionally request approved username, URL, notes, or capability fields.",
        {"vault": REFERENCE, "fields": FIELDS},
    )),
    "use_password": (("use",), tool(
        "use_password", "Use an approved secret with a supplied command, HTTPS request, or browser form. Credential values and command output are not returned.",
        {"vault": REFERENCE, "entry": REFERENCE, "usage": USAGE, "action": {"type": "string", "description": "Legacy configured action; mutually exclusive with usage."},
         "receipt": {**REFERENCE, "description": "Track one protected HTTPS write under this UUID."},
         "command": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 33,
                     "description": "The exact approved executable and arguments for an isolated command."},
         "input_path": {"type": "string", "description": "Optional local file path read and base64-encoded by keeper-connect for a networked command (mutually exclusive with input_base64)."},
         "input_base64": {"type": "string", "description": "Optional base64 input file for a command that permits it."}},
        required=("entry",), read_only=False,
    )),
    "ssh_exec": (("ssh", "exec"), tool(
        "ssh_exec", "Run a command on an approved ssh:// host using stored credentials without exposing secrets.",
        {"vault": REFERENCE, "entry": REFERENCE,
         "origin": {"type": "string", "description": "Approved SSH origin (for example ssh://host:22)."},
         "command": {"type": "string", "minLength": 1, "maxLength": 8192, "description": "Remote shell command to execute."},
         "sudo": {"type": "boolean", "description": "Run command with sudo."},
         "sudo_entry": {**REFERENCE, "description": "Optional separate entry UUID for the sudo password."},
         "attachment": {"type": "string", "minLength": 1, "maxLength": 160, "description": "Optional entry attachment filename for an SSH private key."},
         "host_key_sha256": {"type": "string", "description": "Optional expected SSH host key fingerprint (64-hex or SHA256:<b64>)."},
         "timeout": {"type": "integer", "minimum": 1, "maximum": MAX_SSH_TIMEOUT},
         "reuse_minutes": {"type": "integer", "minimum": 1, "maximum": MAX_SSH_REUSE_MINUTES}},
        required=("vault", "entry", "origin", "command"), read_only=False,
    )),
    "ssh_upload": (("ssh", "upload"), tool(
        "ssh_upload", "Upload a file to an approved ssh:// host over SFTP without exposing credentials.",
        {"vault": REFERENCE, "entry": REFERENCE,
         "origin": {"type": "string", "description": "Approved SSH origin (for example ssh://host:22)."},
         "remote_path": {"type": "string", "minLength": 1, "maxLength": 1024, "description": "Destination file path on the remote host."},
         "mode": {"type": "string", "pattern": "^[0-7]{3,4}$", "description": "Optional POSIX file mode (default 0600)."},
         "attachment": {"type": "string", "minLength": 1, "maxLength": 160},
         "host_key_sha256": {"type": "string", "description": "Optional expected SSH host key fingerprint (64-hex or SHA256:<b64>)."},
         "timeout": {"type": "integer", "minimum": 1, "maximum": MAX_SSH_TIMEOUT},
         "reuse_minutes": {"type": "integer", "minimum": 1, "maximum": MAX_SSH_REUSE_MINUTES},
         "input_path": {"type": "string", "description": "Optional local file path read and base64-encoded by keeper-connect (mutually exclusive with input_base64 and content_base64)."},
         "input_base64": {"type": "string", "description": "Base64 file content (up to 8 MiB decoded)."},
         "content_base64": {"type": "string", "description": "Base64 file content (up to 8 MiB decoded; mutually exclusive with input_path and input_base64)."}},
        required=("vault", "entry", "origin", "remote_path"), read_only=False,
    )),
    "ssh_download": (("ssh", "download"), tool(
        "ssh_download", "Download a bounded file from an approved ssh:// host over SFTP without exposing credentials.",
        {"vault": REFERENCE, "entry": REFERENCE,
         "origin": {"type": "string", "description": "Approved SSH origin (for example ssh://host:22)."},
         "remote_path": {"type": "string", "minLength": 1, "maxLength": 1024, "description": "Source file path on the remote host."},
         "encoding": {"enum": ["text", "base64"], "description": "Output encoding: text (default) or base64."},
         "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576},
         "attachment": {"type": "string", "minLength": 1, "maxLength": 160},
         "host_key_sha256": {"type": "string", "description": "Optional expected SSH host key fingerprint (64-hex or SHA256:<b64>)."},
         "timeout": {"type": "integer", "minimum": 1, "maximum": MAX_SSH_TIMEOUT},
         "reuse_minutes": {"type": "integer", "minimum": 1, "maximum": MAX_SSH_REUSE_MINUTES}},
        required=("vault", "entry", "origin", "remote_path"),
    )),
}


def _require_uuid(value, field):
    try:
        return edit_uuid(value)
    except ValueError:
        raise ValueError(f"Expected a valid UUID for {field}.") from None


def invocation(name, arguments):
    """Build a fixed CLI argument vector and optional request JSON."""
    if not isinstance(name, str) or name not in OPERATIONS:
        raise ValueError("Unknown Keeper tool.")
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be a JSON object.")
    tokens, definition = OPERATIONS[name]
    schema = definition["inputSchema"]
    missing = set(schema["required"]) - arguments.keys()
    if missing:
        raise ValueError("Missing required arguments: " + ", ".join(sorted(missing)) + ".")
    extra = arguments.keys() - schema["properties"].keys()
    if extra:
        raise ValueError("Unexpected tool arguments.")
    if name in ("use_password", "ssh_upload") and "input_path" in arguments:
        raise ValueError("input_path requires connecting through keeper-connect; pass input_base64 when calling keeper-agent-runner directly.")
    if "note" in arguments:
        note = arguments["note"]
        if not isinstance(note, str) or not note.strip() or len(note) > 180 or not note.isprintable():
            raise ValueError("note must be a printable string of 1 to 180 characters.")
    if "profile" in arguments:
        profile = arguments["profile"]
        if not isinstance(profile, str) or not re.fullmatch(PROFILE_NAME, profile):
            raise ValueError("profile must be 1 to 64 letters, numbers, underscores, or hyphens.")
    usage = None
    if name == "use_password":
        if ("action" in arguments) == ("usage" in arguments):
            raise ValueError("Provide either usage or action, not both.")
        if "usage" in arguments:
            if "command" in arguments:
                raise ValueError("Pass command inside usage instead of as a top-level argument.")
            try:
                usage = usage_request(arguments["usage"])
            except ValueError as error:
                raise ValueError(str(error) or "Invalid usage descriptor.") from None
            if "input_base64" in arguments and usage["type"] != "networked_command":
                raise ValueError("input_base64 is only valid with a networked_command usage.")
    local_command = validate_command(arguments["command"]) if name == "use_password" and "command" in arguments else None
    if usage is not None and "input_base64" in arguments:
        local_command = validate_command(usage["command"])
    command = [CLI, "run" if local_command is not None else tokens[0], *tokens[1:], "--json"]
    for key in ("vault", "entry", "console", "account"):
        if key in arguments:
            command.append(f"--{key}={_require_uuid(arguments[key], key)}")
    if "timeout" in arguments:
        timeout = arguments["timeout"]
        max_timeout = MAX_SSH_TIMEOUT if name in SSH_OPERATIONS else MAX_WAIT_SECONDS
        if type(timeout) is not int or not 1 <= timeout <= max_timeout:
            raise ValueError(f"timeout must be an integer between 1 and {max_timeout}.")
        command.append(f"--timeout={timeout}")
    if name == "guest_wait":
        until, expected = arguments["until"], arguments["equals"]
        if not isinstance(until, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", until):
            raise ValueError("until must be a valid status field name.")
        if expected is not None and type(expected) not in (str, bool, int, float):
            raise ValueError("equals must be a JSON scalar or null.")
        command.extend((f"--until={until}", "--equals-json=" + encode(expected).decode("ascii").rstrip()))
    if name == "console_view":
        image = arguments.get("image", False)
        if type(image) is not bool:
            raise ValueError("image must be a boolean.")
        if not image:
            command[command.index("--json")] = "--status"
    if "reuse_minutes" in arguments:
        minutes = arguments["reuse_minutes"]
        maximum = (MAX_CONSOLE_REUSE_MINUTES if name == "console_open"
                   else MAX_SSH_REUSE_MINUTES if name in SSH_OPERATIONS
                   else MAX_GUEST_REUSE_MINUTES)
        if type(minutes) is not int or not 1 <= minutes <= maximum:
            raise ValueError(f"reuse_minutes must be an integer between 1 and {maximum}.")
        command.append(f"--reuse-for={minutes}")
    for flag in ("summary", "details"):
        if flag in arguments:
            if type(arguments[flag]) is not bool:
                raise ValueError(f"{flag} must be a boolean.")
            if arguments[flag]:
                command.append(f"--{flag}")
    if name == "discover" and "query" in arguments:
        query = arguments["query"]
        if not isinstance(query, str) or not query.strip() or len(query) > 128 or not query.isprintable():
            raise ValueError("query must be a non-empty printable string of at most 128 characters.")
        command.append(f"--query={query}")
    if name == "edit_status":
        command.append(f"--request={_require_uuid(arguments['id'], 'id')}")
    if name == "extend_access":
        if "days" in arguments:
            days = arguments["days"]
            if type(days) is not int or not 1 <= days <= MAX_TOKEN_LIFESPAN_DAYS:
                raise ValueError(f"days must be an integer between 1 and {MAX_TOKEN_LIFESPAN_DAYS}.")
            command.append(f"--days={days}")
        if "extension_id" in arguments:
            command.append(f"--id={_require_uuid(arguments['extension_id'], 'extension_id')}")
    if "receipt" in arguments:
        if name == "use_password" and (usage is None or usage["type"] != "https_results"
                or usage["request"].get("method") not in ("POST", "PUT", "PATCH", "DELETE")):
            raise ValueError("receipt requires an https_results write (POST, PUT, PATCH, or DELETE).")
        command.append(f"--receipt={_require_uuid(arguments['receipt'], 'receipt')}")
    if name in ("workflow_run", "workflow_status"):
        command.append(f"--workflow={_require_uuid(arguments['workflow'], 'workflow')}")
    if name == "workflow_run":
        step = arguments["step"]
        if not isinstance(step, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", step):
            raise ValueError("Invalid workflow step name.")
        command.append(f"--step={step}")
    if "action" in arguments:
        action = arguments["action"]
        if not isinstance(action, str) or not action or len(action) > 160 or not action.isprintable():
            raise ValueError("action must be a non-empty printable string of at most 160 characters.")
        command.append(f"--action={action}")
    if name == "list_entries" and "fields" in arguments:
        fields = arguments["fields"]
        if (not isinstance(fields, list) or len(fields) > len(ENTRY_FIELDS)
                or any(field not in ENTRY_FIELDS for field in fields)):
            raise ValueError(f"fields must be a list of allowed entry metadata fields ({', '.join(ENTRY_FIELDS)}).")
        command.extend(f"--field={field}" for field in dict.fromkeys(fields))
    request = arguments.get("request")
    if "request" in arguments and not isinstance(request, dict):
        raise ValueError("request must be a JSON object.")
    if name == "request_access":
        if "mode" in request and request["mode"] not in ("replace", "add"):
            raise ValueError("mode must be 'replace' or 'add'.")
        if request.get("mode") == "add" and "change_id" not in request:
            raise ValueError("mode 'add' requires change_id.")
        if "change_id" not in request and (
                not isinstance(request.get("identity"), str) or not isinstance(request.get("project"), str)):
            raise ValueError("request must include identity and project strings when creating a new token.")
    if name == "request_edit":
        try:
            request = edit_request(request)
        except ValueError as error:
            raise ValueError(str(error) or "Invalid vault edit request.") from None
    if name == "workflow_request" and "registration" in arguments:
        registration = arguments["registration"]
        if not isinstance(registration, dict) or set(registration) != {"identity", "project"} or "registration" in request:
            raise ValueError("registration must contain only identity and project, and not duplicate request.registration.")
        request = {**request, "registration": registration}
        command.append("--register")
    if name == "guest_run":
        if not isinstance(arguments["workflow"], dict) or not isinstance(arguments["guest_command"], str):
            raise ValueError("guest_run requires a workflow object and guest_command string.")
        request = {"workflow": arguments["workflow"], "command": arguments["guest_command"]}
    if name == "provision_account":
        if not isinstance(arguments["fields"], dict) or arguments["body_type"] not in ("json", "form"):
            raise ValueError("provision_account requires body_type ('json' or 'form'), fields object, and workflow object.")
        try:
            workflow_usage = usage_request(arguments["workflow"])
        except ValueError as error:
            raise ValueError(str(error) or "Invalid workflow usage descriptor.") from None
        request = {"workflow": workflow_usage, "body_type": arguments["body_type"],
                   "fields": arguments["fields"]}
    if name == "console_input":
        if not isinstance(arguments["events"], list):
            raise ValueError("events must be a list of console input events.")
        request = arguments["events"]
    ssh_upload_bytes = None
    if name in SSH_OPERATIONS:
        try:
            origin = endpoint_target(arguments["origin"], allowed_schemes=("ssh",), origin=True)
        except ValueError:
            raise ValueError("origin must be a valid ssh:// origin.") from None
        command.append(f"--origin={origin}")
        if "attachment" in arguments:
            attachment = arguments["attachment"]
            if (not isinstance(attachment, str) or not attachment or len(attachment) > 160
                    or not attachment.isprintable() or attachment in (".", "..")
                    or "/" in attachment or "\\" in attachment):
                raise ValueError("attachment must be a short printable filename.")
            command.append(f"--attachment={attachment}")
        if "host_key_sha256" in arguments:
            fp = arguments["host_key_sha256"]
            if not isinstance(fp, str) or not fp or len(fp) > 128 or not fp.isprintable():
                raise ValueError("host_key_sha256 must be a valid SSH host key fingerprint.")
            command.append(f"--host-key-sha256={fp}")
        if name == "ssh_exec":
            cmd_text = arguments["command"]
            if not isinstance(cmd_text, str) or not 1 <= len(cmd_text) <= 8192 or "\0" in cmd_text:
                raise ValueError("command must be a non-empty string of at most 8192 characters.")
            sudo = arguments.get("sudo", False)
            if type(sudo) is not bool:
                raise ValueError("sudo must be a boolean.")
            if sudo:
                command.append("--sudo")
            if "sudo_entry" in arguments:
                if not sudo:
                    raise ValueError("sudo_entry requires sudo=true.")
                command.append(f"--sudo-entry={_require_uuid(arguments['sudo_entry'], 'sudo_entry')}")
            request = {"command": cmd_text}
        elif name == "ssh_upload":
            remote_path = arguments["remote_path"]
            if (not isinstance(remote_path, str) or not 1 <= len(remote_path) <= 1024
                    or "\0" in remote_path or any(ord(c) < 32 or ord(c) == 127 for c in remote_path)):
                raise ValueError("remote_path must be a printable path up to 1024 characters.")
            command.append(f"--remote-path={remote_path}")
            if "mode" in arguments:
                mode = arguments["mode"]
                if not isinstance(mode, str) or not re.fullmatch(r"[0-7]{3,4}", mode):
                    raise ValueError("mode must be a 3- or 4-digit octal string.")
                command.append(f"--mode={mode}")
            if ("input_base64" in arguments) == ("content_base64" in arguments):
                raise ValueError("Provide either input_base64 or content_base64 for ssh_upload.")
            raw_b64 = arguments.get("input_base64", arguments.get("content_base64"))
            if not isinstance(raw_b64, str):
                raise ValueError("Upload content must be a base64 string.")
            try:
                decoded = b64decode(raw_b64, validate=True)
            except ValueError:
                raise ValueError("Upload content must be valid base64.") from None
            if len(decoded) > UPLOAD_LIMIT:
                raise ValueError("Decoded upload exceeds the 8 MiB limit.")
            if decoded:
                ssh_upload_bytes = decoded
                command.append("--input")
            elif "input_base64" in arguments:
                raise ValueError("Decoded input_base64 must be between 1 byte and 8 MiB.")
            else:
                command.append("--content-base64=")
        else:
            remote_path = arguments["remote_path"]
            if (not isinstance(remote_path, str) or not 1 <= len(remote_path) <= 1024
                    or "\0" in remote_path or any(ord(c) < 32 or ord(c) == 127 for c in remote_path)):
                raise ValueError("remote_path must be a printable path up to 1024 characters.")
            command.append(f"--remote-path={remote_path}")
            encoding = arguments.get("encoding", "text")
            if encoding not in ("text", "base64"):
                raise ValueError("encoding must be 'text' or 'base64'.")
            if "encoding" in arguments:
                command.append(f"--encoding={encoding}")
            if "max_bytes" in arguments:
                max_bytes = arguments["max_bytes"]
                limit = 524288 if encoding == "base64" else 1048576
                if type(max_bytes) is not int or not 1 <= max_bytes <= limit:
                    raise ValueError(f"max_bytes must be an integer between 1 and {limit}.")
                command.append(f"--max-bytes={max_bytes}")
    data = encode(request) if request is not None else encode(usage) if usage is not None else b""
    if usage is not None and "input_base64" in arguments:
        command.extend((f"--origin={usage['origin']}", f"--prompt-variable={usage['prompt_variable']}"))
        if "prompt_contains" in usage:
            command.append("--prompt-contains=" + usage["prompt_contains"])
        if "environment" in usage:
            command.append("--environment-json=" + json.dumps(usage["environment"], separators=(",", ":")))
    if ssh_upload_bytes is not None:
        data = ssh_upload_bytes
    elif "input_base64" in arguments:
        if local_command is None or not isinstance(arguments["input_base64"], str):
            raise ValueError("input_base64 must be a base64 string for a networked command.")
        try:
            data = b64decode(arguments["input_base64"], validate=True)
        except ValueError:
            raise ValueError("input_base64 must be valid base64.") from None
        if not 0 < len(data) <= UPLOAD_LIMIT:
            raise ValueError("Decoded input_base64 must be between 1 byte and 8 MiB.")
        command.append("--input")
    elif len(data) >= REQUEST_LIMIT:
        raise ValueError("Request payload exceeds maximum size limit.")
    if local_command is not None:
        command.extend(("--", *local_command))
    return command, data


def tool_result(message, error=False):
    return {"content": [{"type": "text", "text": message}], "isError": error}


def inherited_directory_fds(socket, profile, supplied):
    """Accept only directory descriptors used by the two configured paths."""
    expected = set()
    for path in (socket, profile):
        parts = path.parts
        if parts[:4] != ("/", "proc", "self", "fd"):
            continue
        if len(parts) < 6 or not parts[4].isascii() or not parts[4].isdigit() or ".." in parts[5:]:
            raise ValueError
        fd = int(parts[4])
        if fd < 3 or parts[4] != str(fd):
            raise ValueError
        expected.add(fd)
    if len(supplied) != len(expected) or set(supplied) != expected:
        raise ValueError
    for fd in expected:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise ValueError
    return tuple(sorted(expected))


class AgentRunner:
    def __init__(self, socket, profile, *, pass_fds=(), chat_id=None):
        self.pass_fds = pass_fds
        self.environment = {
            "PATH": "/usr/bin:/bin",
            "KEEPASSXC_AGENT_SOCKET": str(socket),
            "KEEPASSXC_AGENT_TOKEN_FILE": str(profile / "token"),
        }
        for key in ("KEEPASSXC_AGENT_MODEL", "KEEPASSXC_AGENT_CHAT", "KEEPASSXC_AGENT_CHAT_ID",
                    "KEEPASSXC_AGENT_IDENTITY", "KEEPASSXC_AGENT_PROJECT"):
            if key in os.environ:
                self.environment[key] = os.environ[key]
        if chat_id is not None:
            self.environment["KEEPASSXC_AGENT_CHAT_ID"] = chat_id

    def call_tool(self, params):
        try:
            arguments = params.get("arguments", {})
            command, data = invocation(params.get("name"), arguments)
        except (TypeError, ValueError, RecursionError) as error:
            msg = str(error)
            if msg and len(msg) <= 240 and msg.isascii() and msg.isprintable():
                return tool_result(f"Invalid Keeper tool or arguments. {msg}", True)
            return tool_result("Invalid Keeper tool or arguments.", True)
        try:
            environment = self.environment
            if "note" in arguments:
                environment = {**environment, "KEEPASSXC_AGENT_NOTE": arguments["note"]}
            run_timeout = (MAX_SSH_TIMEOUT + CLIENT_TIMEOUT) if params.get("name") in SSH_OPERATIONS else (CLIENT_TIMEOUT + 2)
            result = subprocess.run(command, input=data, capture_output=True, cwd="/",
                                    env=environment, pass_fds=self.pass_fds,
                                    timeout=run_timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return tool_result("Could not run the Keeper CLI.", True)
        if result.stdout:
            try:
                reply = decode(result.stdout)
                if isinstance(reply, dict):
                    if params.get("name") == "console_view" and arguments.get("image") is True and not result.returncode:
                        image = reply.pop("png_base64")
                        content = tool_result(encode(reply).decode("ascii").rstrip())
                        content["content"].append({"type": "image", "data": image, "mimeType": "image/png"})
                        return content
                    return tool_result(encode(reply).decode("ascii").rstrip(), bool(result.returncode))
            except (ValueError, RecursionError, KeyError):
                pass
        try:
            diagnostic = result.stderr.decode("utf-8").strip()
        except ValueError:
            diagnostic = ""
        matched = None
        for prefix in (*ERRORS.values(), str(UninitializedProfile())):
            if diagnostic == prefix:
                matched = prefix
                break
            if diagnostic.startswith(f"{prefix} "):
                detail = sanitize_error_detail(diagnostic[len(prefix) + 1:])
                matched = f"{prefix} {detail}"[:400] if detail else prefix
                break
        if matched is None:
            matched = "Keeper could not complete the request."
        return tool_result(matched, True)

    def serve(self, source, sink):
        while frame := source.readline(MAX_MESSAGE + 1):
            if len(frame) > MAX_MESSAGE:
                while not frame.endswith(b"\n"):
                    chunk = source.readline(65536)
                    if not chunk:
                        break
                    frame = chunk
                sink.write(encode({
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "Message exceeds maximum size limit."},
                    "id": None,
                }))
                sink.flush()
                continue
            try:
                message = decode(frame)
            except (ValueError, RecursionError):
                response = {"error": {"code": -32700, "message": "Parse error"}, "id": None}
            else:
                response = self.dispatch(message)
            if response is not None:
                sink.write(encode({"jsonrpc": "2.0", **response}))
                sink.flush()

    def dispatch(self, message):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return {"error": {"code": -32600, "message": "Invalid request"}, "id": None}
        if "id" not in message:
            return None
        identifier = message["id"]
        method, params = message.get("method"), message.get("params", {})
        if not isinstance(params, dict):
            return {"error": {"code": -32602, "message": "Invalid params"}, "id": identifier}
        if method == "initialize":
            version = params.get("protocolVersion")
            result = {
                "protocolVersion": version if version in PROTOCOLS else PROTOCOLS[0],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "Keeper", "version": "1"},
                "instructions": SERVER_INSTRUCTIONS,
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": [definition for _, definition in OPERATIONS.values()]}
        elif method == "tools/call":
            result = self.call_tool(params)
        else:
            return {"error": {"code": -32601, "message": "Method not found"}, "id": identifier}
        return {"result": result, "id": identifier}


class ProjectRunner(AgentRunner):
    """Route a project's MCP calls to runner-owned profiles by host-supplied chat ID."""

    def __init__(self, socket, profiles, *, connection_profile=None):
        self.socket = socket
        self.profiles = profiles
        self.connection_profile = connection_profile
        self.named_profile = None
        self.initialized = False

    def dispatch(self, message):
        if self.connection_profile is not None and isinstance(message, dict):
            method = message.get("method")
            if method == "keeper/profile" and "id" not in message and not self.initialized:
                params = message.get("params")
                name = params.get("name") if isinstance(params, dict) else None
                if isinstance(name, str) and re.fullmatch(PROFILE_NAME, name):
                    self.named_profile = self.profiles / sha256(("connection:" + name).encode("ascii")).hexdigest()
                return None
            if method in ("initialize", "tools/call"):
                self.initialized = True
        return super().dispatch(message)

    def call_tool(self, params):
        metadata = params.get("_meta")
        chat_id = None
        if isinstance(metadata, dict):
            for key in CHAT_META_KEYS:
                if key in metadata:
                    chat_id = metadata[key]
                    break
        arguments = params.get("arguments", {})
        requested_profile = arguments.get("profile") if isinstance(arguments, dict) else None
        if requested_profile is not None and (
                not isinstance(requested_profile, str) or not re.fullmatch(PROFILE_NAME, requested_profile)):
            return tool_result("Invalid Keeper tool or arguments.", True)
        ephemeral = False
        if chat_id is not None:
            if not isinstance(chat_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", chat_id):
                return tool_result("Keeper needs a valid client thread or conversation ID on this project connection.", True)
            profile = self.profiles / sha256(chat_id.encode("ascii")).hexdigest()
        elif self.connection_profile is not None and requested_profile is not None:
            profile = self.profiles / sha256(("task:" + requested_profile).encode("ascii")).hexdigest()
            chat_id = requested_profile
        elif self.connection_profile is not None:
            if self.named_profile is not None:
                profile = self.named_profile
            else:
                profile = self.connection_profile
                ephemeral = True
        else:
            return tool_result("Keeper needs the client thread or conversation ID on this project connection.", True)
        if not isinstance(params.get("name"), str) or params["name"] not in OPERATIONS:
            return tool_result("Invalid Keeper tool or arguments.", True)
        if ephemeral and (
            params["name"] == "request_access"
            or (params["name"] == "workflow_request" and isinstance(arguments, dict) and "registration" in arguments)
        ):
            return tool_result(
                "Pass a persistent profile parameter (or connect with keeper-connect --profile NAME) before requesting access on a shared MCP connection.",
                True,
            )
        try:
            profile.mkdir(mode=0o700, exist_ok=True)
            os.close(open_profile(profile))
        except (OSError, ListingError):
            return tool_result("Keeper runner profile is unavailable or unsafe.", True)
        return AgentRunner(self.socket, profile, chat_id=chat_id).call_tool(params)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="keeper-agent-runner", description=__doc__)
    parser.add_argument("--socket", required=True, type=Path, help="Absolute path to the owner's broker socket")
    profiles = parser.add_mutually_exclusive_group(required=True)
    profiles.add_argument("--profile-dir", type=Path, help="Absolute runner-owned profile directory")
    profiles.add_argument("--project-profiles", type=Path, help="Private profile root for a trusted project MCP connection")
    parser.add_argument("--connection-profiles", action="store_true", help="Support MCP clients without thread metadata")
    parser.add_argument("--inherit-directory-fd", type=int, action="append", default=[],
                        help="Trusted launcher directory descriptor referenced by a configured path")
    options = parser.parse_args(argv)
    profile_path = options.profile_dir or options.project_profiles
    if not options.socket.is_absolute() or not profile_path.is_absolute():
        parser.error("Socket and profile paths must be absolute.")
    if options.project_profiles and options.inherit_directory_fd:
        parser.error("Project connections require fixed socket and profile paths.")
    if options.connection_profiles and not options.project_profiles:
        parser.error("Connection profiles require a private project profile root.")
    try:
        pass_fds = inherited_directory_fds(options.socket, profile_path, options.inherit_directory_fd)
    except (OSError, OverflowError, ValueError):
        parser.error("Inherit only open directories referenced by the socket and profile paths.")
    try:
        profile_path.mkdir(mode=0o700, exist_ok=True)
        os.close(open_profile(profile_path))
    except (OSError, ListingError):
        parser.exit(1, "Keeper runner profile is unavailable or unsafe. Use a private runner-owned directory.\n")
    if options.connection_profiles:
        with TemporaryDirectory(prefix="connection-", dir=profile_path) as connection:
            ProjectRunner(options.socket, profile_path, connection_profile=Path(connection)).serve(
                sys.stdin.buffer, sys.stdout.buffer)
        return 0
    runner = (ProjectRunner(options.socket, profile_path) if options.project_profiles
              else AgentRunner(options.socket, profile_path, pass_fds=pass_fds))
    runner.serve(sys.stdin.buffer, sys.stdout.buffer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
