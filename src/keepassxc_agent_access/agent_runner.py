"""Expose Keeper's scoped CLI operations over a trusted stdio MCP runner."""

import argparse
from base64 import b64decode
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from uuid import UUID

from .agent_cli import EDIT_OPERATIONS, ENTRY_FIELDS, CREDENTIAL_USE_TYPES, USE_TYPES, edit_request, edit_uuid, usage_request
from .protocol import (CLIENT_TIMEOUT, ERRORS, ListingError, MAX_CONSOLE_REUSE_MINUTES, MAX_GUEST_REUSE_MINUTES,
                       MAX_GUEST_TEXT, MAX_WAIT_SECONDS, REQUEST_LIMIT, UPLOAD_LIMIT, decode, encode, validate_command)
from .runner_token import UninitializedProfile, open_profile


CLI = Path(__file__).resolve().parents[2] / "keepassxc-agent"
MAX_MESSAGE = 4 * ((UPLOAD_LIMIT + 2) // 3) + REQUEST_LIMIT * 4
PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")


def tool(name, description, properties=None, *, required=(), read_only=True):
    properties = dict(properties or {})
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
        "identity": {"type": "string"},
        "project": {"type": "string"},
        "change_id": {**REFERENCE, "description": "A new UUID to replace this active token’s scope. Reuse it to check the change."},
        "items": {"type": "array", "minItems": 1, "items": {
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
                "action": {"type": "string", "description": "Optional legacy configured action ID."},
                "uses": {"type": "array", "items": {"enum": sorted(CREDENTIAL_USE_TYPES)}, "minItems": 1, "uniqueItems": True},
                "origins": {"type": "array", "items": {"type": "string"}, "maxItems": 8, "uniqueItems": True,
                            "description": "Explicit HTTPS origins the owner must approve for network use."},
            },
            "additionalProperties": False,
        }},
    },
    "required": ["identity", "project", "items"],
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
            "properties": {key: {"type": "string"} for key in ("title", "username", "url", "name")},
            "additionalProperties": False,
        },
        "password_source": {"enum": ["owner", "generate"]},
    },
    "required": ["id", "operation", "vault"],
    "additionalProperties": False,
}
USAGE = {
    "type": "object",
    "properties": {
        "type": {"enum": sorted(USE_TYPES)},
        "command": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 33},
        "origin": {"type": "string"}, "prompt_variable": {"type": "string"},
        "prompt_contains": {"type": "string", "minLength": 1, "maxLength": 80},
        "environment": {"type": "object", "additionalProperties": {"type": "string"}, "maxProperties": 16},
        "certificate_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "login": {"type": "object", "description": "Private POST authentication and named JSON-pointer captures."},
        "request": {"type": "object", "description": "Same-origin protected resource request; session placeholders remain private."},
        "approve_write_once": {"type": "boolean", "description": "Ask the owner to approve this exact protected HTTPS write once."},
        "result": {"type": "object", "description": "JSON pointer and named result columns, or a scalar alias for a write result."},
        "url": {"type": "string"}, "auth": {"enum": ["basic", "bearer", "template"]},
        "method": {"enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]},
        "json": {"type": ["object", "string"]},
        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
        "query": {"type": "object", "additionalProperties": {"type": "string"}},
        **{key: {"type": "string"} for key in
           ("submit_url", "form_id", "username_field", "password_field", "success_id", "success_url")},
    },
    "required": ["type"], "additionalProperties": False,
    "description": "Agent-supplied credential operation. No configured action ID needed. Commands return a dispatch receipt only.",
}
OPERATIONS = {
    "discover": (("discover",), tool("discover", "List all vaults, groups and entry names before requesting access. Returns only names, references and cache/lock status.",
        {"vault": REFERENCE, "summary": {"type": "boolean", "description": "List vault names and status only; use a vault UUID to fetch its groups and entry names separately."}})),
    "access_status": (("access", "status"), tool(
        "access_status", "Check this token profile's status; request details to see its identity and permissions.",
        {"details": {"type": "boolean"}},
    )),
    "request_access": (("access", "request"), tool(
        "request_access", "Request a scoped token or replace this token’s scope using a change_id.",
        {"request": ENROLLMENT}, required=("request",), read_only=False,
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
         "workflow": {"type": "object", "description": "Pinned command and status request template from the Keeper skill."},
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
        {"vault": REFERENCE, "entry": REFERENCE, "request": {"type": "object"},
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
        {"console": REFERENCE, "events": {"type": "array", "items": {"type": "object"}}},
        required=("console", "events"), read_only=False,
    )),
    "console_close": (("console", "close"), tool(
        "console_close", "Close this profile's approved guest console.",
        {"console": REFERENCE}, required=("console",), read_only=False,
    )),
    "workflow_request": (("workflows", "request"), tool(
        "workflow_request", "Ask the owner to review a bounded set of fixed HTTPS writes, guest commands and console opens.",
        {"request": {"type": "object", "description": "Pinned HTTPS workflow manifest from the Keeper skill."},
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
         "workflow": {"type": "object", "description": "Exact pinned HTTPS results write with approve_write_once."},
         "body_type": {"enum": ["form", "json"]}, "fields": {"type": "object"}},
        required=("vault", "entry", "account", "receipt", "workflow", "body_type", "fields"), read_only=False,
    )),
    "list_vaults": (("vaults", "list"), tool("list_vaults", "List vaults available to the active token.")),
    "list_entries": (("entries", "list"), tool(
        "list_entries", "List approved entry metadata and optionally request approved username or URL fields.",
        {"vault": REFERENCE, "fields": FIELDS},
    )),
    "use_password": (("use",), tool(
        "use_password", "Use an approved secret with a supplied command, HTTPS request, or browser form. Credential values and command output are not returned.",
        {"vault": REFERENCE, "entry": REFERENCE, "usage": USAGE, "action": {"type": "string", "description": "Legacy configured action; mutually exclusive with usage."},
         "receipt": {**REFERENCE, "description": "Track one protected HTTPS write under this UUID."},
         "command": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 33,
                     "description": "The exact approved executable and arguments for an isolated command."},
         "input_base64": {"type": "string", "description": "Optional base64 input file for a command that permits it."}},
        required=("entry",), read_only=False,
    )),
}


def invocation(name, arguments):
    """Build a fixed CLI argument vector and optional request JSON."""
    if not isinstance(name, str) or name not in OPERATIONS or not isinstance(arguments, dict):
        raise ValueError
    tokens, definition = OPERATIONS[name]
    schema = definition["inputSchema"]
    if not set(schema["required"]) <= arguments.keys() <= schema["properties"].keys():
        raise ValueError
    if "note" in arguments:
        note = arguments["note"]
        if not isinstance(note, str) or not note.strip() or len(note) > 180 or not note.isprintable():
            raise ValueError
    usage = None
    if name == "use_password":
        if ("action" in arguments) == ("usage" in arguments):
            raise ValueError
        if "usage" in arguments:
            if "command" in arguments:
                raise ValueError
            usage = usage_request(arguments["usage"])
            if "input_base64" in arguments and usage["type"] != "networked_command":
                raise ValueError
    local_command = validate_command(arguments["command"]) if "command" in arguments else None
    if usage is not None and "input_base64" in arguments:
        local_command = validate_command(usage["command"])
    command = [CLI, "run" if local_command is not None else tokens[0], *tokens[1:], "--json"]
    for key in ("vault", "entry", "console", "account"):
        if key in arguments:
            value = arguments[key]
            if not isinstance(value, str) or len(value) > 36:
                raise ValueError
            command.append(f"--{key}={UUID(value)}")
    if "timeout" in arguments:
        timeout = arguments["timeout"]
        if type(timeout) is not int or not 1 <= timeout <= MAX_WAIT_SECONDS:
            raise ValueError
        command.append(f"--timeout={timeout}")
    if name == "guest_wait":
        until, expected = arguments["until"], arguments["equals"]
        if not isinstance(until, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", until):
            raise ValueError
        if expected is not None and type(expected) not in (str, bool, int, float):
            raise ValueError
        command.extend((f"--until={until}", "--equals-json=" + encode(expected).decode("ascii").rstrip()))
    if name == "console_view":
        image = arguments.get("image", False)
        if type(image) is not bool:
            raise ValueError
        if not image:
            command[command.index("--json")] = "--status"
    if "reuse_minutes" in arguments:
        minutes = arguments["reuse_minutes"]
        maximum = MAX_CONSOLE_REUSE_MINUTES if name == "console_open" else MAX_GUEST_REUSE_MINUTES
        if type(minutes) is not int or not 1 <= minutes <= maximum:
            raise ValueError
        command.append(f"--reuse-for={minutes}")
    for flag in ("summary", "details"):
        if flag in arguments:
            if type(arguments[flag]) is not bool:
                raise ValueError
            if arguments[flag]:
                command.append(f"--{flag}")
    if name == "edit_status":
        command.append(f"--request={edit_uuid(arguments['id'])}")
    if "receipt" in arguments:
        if name == "use_password" and (usage is None or usage["type"] != "https_results"
                or usage["request"].get("method") not in ("POST", "PUT", "PATCH", "DELETE")):
            raise ValueError
        command.append(f"--receipt={edit_uuid(arguments['receipt'])}")
    if name in ("workflow_run", "workflow_status"):
        command.append(f"--workflow={edit_uuid(arguments['workflow'])}")
    if name == "workflow_run":
        step = arguments["step"]
        if not isinstance(step, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", step):
            raise ValueError
        command.append(f"--step={step}")
    if "action" in arguments:
        action = arguments["action"]
        if not isinstance(action, str) or not action or len(action) > 160 or not action.isprintable():
            raise ValueError
        command.append(f"--action={action}")
    if name == "list_entries" and "fields" in arguments:
        fields = arguments["fields"]
        if (not isinstance(fields, list) or len(fields) > len(ENTRY_FIELDS)
                or any(field not in ENTRY_FIELDS for field in fields)):
            raise ValueError
        command.extend(f"--field={field}" for field in dict.fromkeys(fields))
    request = arguments.get("request")
    if "request" in arguments and not isinstance(request, dict):
        raise ValueError
    if name == "request_edit":
        request = edit_request(request)
    if name == "workflow_request" and "registration" in arguments:
        registration = arguments["registration"]
        if not isinstance(registration, dict) or set(registration) != {"identity", "project"} or "registration" in request:
            raise ValueError
        request = {**request, "registration": registration}
        command.append("--register")
    if name == "guest_run":
        if not isinstance(arguments["workflow"], dict) or not isinstance(arguments["guest_command"], str):
            raise ValueError
        request = {"workflow": arguments["workflow"], "command": arguments["guest_command"]}
    if name == "provision_account":
        if not isinstance(arguments["fields"], dict) or arguments["body_type"] not in ("json", "form"):
            raise ValueError
        request = {"workflow": usage_request(arguments["workflow"]), "body_type": arguments["body_type"],
                   "fields": arguments["fields"]}
    if name == "console_input":
        if not isinstance(arguments["events"], list):
            raise ValueError
        request = arguments["events"]
    data = encode(request) if request is not None else encode(usage) if usage is not None else b""
    if usage is not None and "input_base64" in arguments:
        command.extend((f"--origin={usage['origin']}", f"--prompt-variable={usage['prompt_variable']}"))
        if "prompt_contains" in usage:
            command.append("--prompt-contains=" + usage["prompt_contains"])
        if "environment" in usage:
            command.append("--environment-json=" + json.dumps(usage["environment"], separators=(",", ":")))
    if "input_base64" in arguments:
        if local_command is None or not isinstance(arguments["input_base64"], str):
            raise ValueError
        data = b64decode(arguments["input_base64"], validate=True)
        if not 0 < len(data) <= UPLOAD_LIMIT:
            raise ValueError
        command.append("--input")
    elif len(data) >= REQUEST_LIMIT:
        raise ValueError
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
    def __init__(self, socket, profile, *, pass_fds=()):
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

    def call_tool(self, params):
        try:
            arguments = params.get("arguments", {})
            command, data = invocation(params.get("name"), arguments)
        except (TypeError, ValueError, RecursionError):
            return tool_result("Invalid Keeper tool or arguments.", True)
        try:
            environment = self.environment
            if "note" in arguments:
                environment = {**environment, "KEEPASSXC_AGENT_NOTE": arguments["note"]}
            result = subprocess.run(command, input=data, capture_output=True, cwd="/",
                                    env=environment, pass_fds=self.pass_fds,
                                    timeout=CLIENT_TIMEOUT + 2, check=False)
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
        if diagnostic not in (*ERRORS.values(), str(UninitializedProfile())):
            diagnostic = "Keeper could not complete the request."
        return tool_result(diagnostic, True)

    def serve(self, source, sink):
        while frame := source.readline(MAX_MESSAGE + 1):
            if len(frame) > MAX_MESSAGE:
                break
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


def main(argv=None):
    parser = argparse.ArgumentParser(prog="keeper-agent-runner", description=__doc__)
    parser.add_argument("--socket", required=True, type=Path, help="Absolute path to the owner's broker socket")
    parser.add_argument("--profile-dir", required=True, type=Path, help="Absolute runner-owned profile directory")
    parser.add_argument("--inherit-directory-fd", type=int, action="append", default=[],
                        help="Trusted launcher directory descriptor referenced by a configured path")
    options = parser.parse_args(argv)
    if not options.socket.is_absolute() or not options.profile_dir.is_absolute():
        parser.error("Socket and profile paths must be absolute.")
    try:
        pass_fds = inherited_directory_fds(options.socket, options.profile_dir, options.inherit_directory_fd)
    except (OSError, OverflowError, ValueError):
        parser.error("Inherit only open directories referenced by the socket and profile paths.")
    try:
        options.profile_dir.mkdir(mode=0o700, exist_ok=True)
        os.close(open_profile(options.profile_dir))
    except (OSError, ListingError):
        parser.exit(1, "Keeper runner profile is unavailable or unsafe. Use a private runner-owned directory.\n")
    AgentRunner(options.socket, options.profile_dir, pass_fds=pass_fds).serve(sys.stdin.buffer, sys.stdout.buffer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
