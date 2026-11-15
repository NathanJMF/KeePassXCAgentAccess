"""Expose Keeper's scoped CLI operations over a trusted stdio MCP runner."""

import argparse
import os
from pathlib import Path
import stat
import subprocess
import sys
from uuid import UUID

from .agent_cli import EDIT_OPERATIONS, ENTRY_FIELDS, edit_request, edit_uuid
from .protocol import CLIENT_TIMEOUT, ERRORS, ListingError, REQUEST_LIMIT, decode, encode
from .runner_token import UninitializedProfile, open_profile


CLI = Path(__file__).resolve().parents[2] / "keepassxc-agent"
MAX_MESSAGE = REQUEST_LIMIT * 4
PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")


def tool(name, description, properties=None, *, required=(), read_only=True):
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties or {},
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
        "items": {"type": "array", "minItems": 1, "items": {
            "type": "object",
            "properties": {
                "vault": REFERENCE,
                "entry": REFERENCE,
                "label": {"type": "string"},
                "metadata": {"type": "boolean"},
                "username": {"type": "boolean"},
                "url": {"type": "boolean"},
                "action": {"type": "string"},
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
OPERATIONS = {
    "access_status": (("access", "status"), tool("access_status", "Check this token profile's status.")),
    "request_access": (("access", "request"), tool(
        "request_access", "Request a token for exact entries and permissions. Supply the scope as request.",
        {"request": ENROLLMENT}, required=("request",), read_only=False,
    )),
    "request_edit": (("edits", "request"), tool(
        "request_edit", "Queue one vault edit for owner review. For password replacements pass only the password source.",
        {"request": EDIT_REQUEST}, required=("request",), read_only=False,
    )),
    "edit_status": (("edits", "status"), tool(
        "edit_status", "Check an edit request by its UUID.",
        {"id": REFERENCE}, required=("id",),
    )),
    "list_vaults": (("vaults", "list"), tool("list_vaults", "List vaults available to the active token.")),
    "list_entries": (("entries", "list"), tool(
        "list_entries", "List approved entry metadata and optionally request approved username or URL fields.",
        {"vault": REFERENCE, "fields": FIELDS},
    )),
    "use_password": (("use",), tool(
        "use_password", "Use a credential through an owner-configured action. Return the action result.",
        {"vault": REFERENCE, "entry": REFERENCE, "action": {"type": "string"}},
        required=("entry", "action"), read_only=False,
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
    command = [CLI, *tokens, "--json"]
    for key in ("vault", "entry"):
        if key in arguments:
            value = arguments[key]
            if not isinstance(value, str) or len(value) > 36:
                raise ValueError
            command.append(f"--{key}={UUID(value)}")
    if name == "edit_status":
        command.append(f"--request={edit_uuid(arguments['id'])}")
    if "action" in arguments:
        action = arguments["action"]
        if not isinstance(action, str) or not action or len(action) > 160 or not action.isprintable():
            raise ValueError
        command.append(f"--action={action}")
    if "fields" in arguments:
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
    data = encode(request) if request is not None else b""
    if len(data) >= REQUEST_LIMIT:
        raise ValueError
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
        for key in ("KEEPASSXC_AGENT_MODEL", "KEEPASSXC_AGENT_CHAT", "KEEPASSXC_AGENT_CHAT_ID"):
            if key in os.environ:
                self.environment[key] = os.environ[key]

    def call_tool(self, params):
        try:
            command, data = invocation(params.get("name"), params.get("arguments", {}))
        except (TypeError, ValueError, RecursionError):
            return tool_result("Invalid Keeper tool or arguments.", True)
        try:
            result = subprocess.run(command, input=data, capture_output=True, cwd="/",
                                    env=self.environment, pass_fds=self.pass_fds,
                                    timeout=CLIENT_TIMEOUT + 2, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return tool_result("Could not run the Keeper CLI.", True)
        if result.stdout:
            try:
                reply = decode(result.stdout)
                if isinstance(reply, dict):
                    return tool_result(encode(reply).decode("ascii").rstrip(), bool(result.returncode))
            except (ValueError, RecursionError):
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
