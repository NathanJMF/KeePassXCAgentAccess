"""Agent-side command. This module needs only the Python standard library."""

import argparse
import ipaddress
import math
import re
from hashlib import sha256
import os
import socket
import sys
from time import monotonic
from uuid import UUID
from urllib.parse import urlsplit

from .runner_token import UninitializedProfile, credential
from .protocol import (
    CLIENT_TIMEOUT, ERRORS, LIST_REQUEST, ListingError, REQUEST_LIMIT, REQUEST_TIMEOUT, RESPONSE_LIMIT, UPLOAD_LIMIT,
    decode, encode, receive, remaining, validate_command,
)


ENTRY_FIELDS = ("username", "url")
USE_TYPES = frozenset(("local_command", "networked_command", "https", "https_results", "browser"))
CREDENTIAL_USE_TYPES = USE_TYPES | {"https_body"}
EDIT_STATUSES = ("pending", "applying", "applied", "denied", "stale", "interrupted", "failed")
EDIT_OPERATIONS = {
    "create_entry": (("parent",), {"title"}, {"username", "url"}),
    "update_entry": (("entry",), set(), {"title", "username", "url"}),
    "create_group": (("parent",), {"name"}, set()),
    "rename_group": (("group",), {"name"}, set()),
    "move_entry": (("entry", "parent"), set(), set()),
    "move_group": (("group", "parent"), set(), set()),
    "recycle_entry": (("entry",), set(), set()),
    "recycle_group": (("group",), set(), set()),
    "replace_password": (("entry",), set(), set()),
}


def edit_uuid(value):
    if not isinstance(value, str) or len(value) > 36:
        raise ValueError
    return str(UUID(value))


def _request_id(value):
    try:
        return edit_uuid(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Expected a request UUID.") from None


def edit_request(data):
    """Validate the writable fields before giving the request to the broker."""
    if not isinstance(data, dict) or not isinstance(operation := data.get("operation"), str):
        raise ValueError
    if operation not in EDIT_OPERATIONS:
        raise ValueError
    references, mandatory_fields, extra_fields = EDIT_OPERATIONS[operation]
    required = {"id", "operation", "vault", *references}
    if operation == "replace_password":
        required.add("password_source")
        if data.get("password_source") not in ("owner", "generate"):
            raise ValueError
    if not required <= data.keys() <= required | {"fields"}:
        raise ValueError
    fields = data.get("fields", {})
    if (
        not isinstance(fields, dict)
        or not mandatory_fields <= fields.keys() <= mandatory_fields | extra_fields
        or not all(isinstance(value, str) for value in fields.values())
        or any(not fields[key].strip() for key in ("title", "name") if key in fields)
        or operation == "update_entry" and not fields
    ):
        raise ValueError
    normalized = {key: edit_uuid(data[key]) for key in ("id", "vault", *references)}
    return {**data, **normalized}


def https_target(value, *, origin=False):
    """Validate agent-side HTTPS syntax without importing owner-side modules."""
    if (not isinstance(value, str) or not re.fullmatch(r"[!-~]{1,2048}", value)
            or any(char in value for char in "?#\\")):
        raise ValueError
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or "@" in parts.netloc or "%" in parts.netloc:
        raise ValueError
    host = parts.hostname
    authority = r"\[[0-9a-fA-F:.]+\](?::[0-9]+)?" if ":" in host else r"[A-Za-z0-9.-]+(?::[0-9]+)?"
    if not re.fullmatch(authority, parts.netloc):
        raise ValueError
    port = 443 if parts.port is None else parts.port
    if not 0 < port <= 65535:
        raise ValueError
    if ":" in host:
        host = str(ipaddress.IPv6Address(host))
    elif not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
        raise ValueError
    path = parts.path or "/"
    if path.startswith("//") or origin and path != "/":
        raise ValueError
    authority = f"[{host}]" if ":" in host else host
    return f"https://{authority}:{port}{path}"


def result_pointer(value):
    if not isinstance(value, str) or len(value) > 256 or value and not value.startswith("/"):
        raise ValueError
    if value and (len(value.split("/")) > 17 or re.search(r"~(?![01])", value) or not value.isprintable()):
        raise ValueError
    return value


RESULT_PRIVATE_COLUMNS = frozenset(("password", "passwd", "secret", "token", "ticket", "csrfpreventiontoken",
                                    "authorization", "cookie", "setcookie", "session", "apikey", "privatekey",
                                    "accesstoken", "refreshtoken", "csrftoken", "credential", "credentials"))


def result_columns(value):
    if (not isinstance(value, list) or not 0 < len(value) <= 16
            or any(not isinstance(column, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", column)
                   or re.sub(r"[_-]", "", column).lower() in RESULT_PRIVATE_COLUMNS
                   for column in value) or len(set(value)) != len(value)):
        raise ValueError
    return value


def _result_path(value):
    if (not isinstance(value, str) or not re.fullmatch(r"[!-~]{1,2048}", value)
            or not value.startswith("/") or value.startswith("//")
            or any(part in value for part in ("?", "#", "\\", "{{"))):
        raise ValueError


def _result_map(value, limit):
    if (not isinstance(value, dict) or len(value) > limit
            or any(not isinstance(key, str) or not key or not key.isprintable() or not isinstance(item, str)
                   or not item.isprintable() or len(key) > 256 or len(item) > 2048 for key, item in value.items())):
        raise ValueError


def result_usage_request(data):
    required = {"type", "origin", "request", "result"}
    if not required <= data.keys() <= required | {"certificate_sha256", "login"}:
        raise ValueError
    https_target(data["origin"], origin=True)
    if "certificate_sha256" in data and (not isinstance(data["certificate_sha256"], str)
                                           or not re.fullmatch(r"[0-9a-f]{64}", data["certificate_sha256"])):
        raise ValueError
    captures = set()
    login = data.get("login")
    if "login" in data:
        if (not isinstance(login, dict) or not {"path", "capture"} <= login.keys() <= {"path", "capture", "method", "form", "json"}
                or login.get("method", "POST") != "POST" or ("form" in login) == ("json" in login)):
            raise ValueError
        _result_path(login["path"])
        capture = login["capture"]
        if (not isinstance(capture, dict) or not 0 < len(capture) <= 4
                or any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", key)
                       for key in capture)):
            raise ValueError
        for pointer in capture.values():
            result_pointer(pointer)
        captures = set(capture)
        if "form" in login:
            _result_map(login["form"], 16)
        elif not isinstance(login["json"], (dict, str)):
            raise ValueError
    request = data["request"]
    if (not isinstance(request, dict) or not {"path", "auth"} <= request.keys() <=
            {"path", "auth", "method", "headers", "query", "json", "form"}
            or request["auth"] not in ("basic", "bearer", "template", "session")
            or request.get("method", "GET") not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
            or "form" in request and "json" in request):
        raise ValueError
    _result_path(request["path"])
    if request["auth"] == "session" and not captures:
        raise ValueError
    if "headers" in request:
        _result_map(request["headers"], 16)
        if request["headers"] and request["auth"] not in ("session", "template"):
            raise ValueError
    if "query" in request:
        _result_map(request["query"], 32)
    for key in ("form", "json"):
        if key in request:
            if request.get("method", "GET") not in ("POST", "PUT", "PATCH", "DELETE"):
                raise ValueError
            if key == "form":
                _result_map(request[key], 16)
            elif not isinstance(request[key], (dict, str)):
                raise ValueError
            if "{{" in encode(request[key]).decode("ascii"):
                raise ValueError
    result = data["result"]
    if not isinstance(result, dict) or not {"columns"} <= result.keys() <= {"path", "columns"}:
        raise ValueError
    result_pointer(result.get("path", ""))
    result_columns(result["columns"])
    if len(encode(data)) >= REQUEST_LIMIT:
        raise ValueError
    return data


def usage_request(data):
    """Check descriptor shape; the owner broker independently compiles and authorizes it."""
    if not isinstance(data, dict) or data.get("type") not in USE_TYPES:
        raise ValueError
    kind = data["type"]
    if kind == "https_results":
        return result_usage_request(data)
    if kind in ("local_command", "networked_command"):
        keys = {"type", "command"}
        if kind == "networked_command":
            keys |= {"origin", "prompt_variable"}
        optional = {"environment", "prompt_contains"} if kind == "networked_command" else set()
        if not keys <= data.keys() <= keys | optional:
            raise ValueError
        command = validate_command(data["command"])
        if kind == "networked_command":
            https_target(data["origin"], origin=True)
            expected_prompt = data.get("prompt_contains", "password")
            if (not isinstance(expected_prompt, str) or not expected_prompt.strip()
                    or not expected_prompt.isprintable() or len(expected_prompt) > 80):
                raise ValueError
            environment = data.get("environment", {})
            if (not isinstance(environment, dict) or len(environment) > 16
                    or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name)
                           or not isinstance(value, str) or len(value) > 1024 or value and not value.isprintable()
                           for name, value in environment.items())
                    or sum(len(name) + len(value) for name, value in environment.items()) > 4096):
                raise ValueError
            if (not isinstance(data["prompt_variable"], str)
                    or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,39}_ASKPASS", data["prompt_variable"])):
                raise ValueError
        return {**data, "command": list(command)}
    if kind == "https":
        if not {"type", "url", "auth"} <= data.keys() <= {"type", "url", "auth", "method", "json", "headers", "query"}:
            raise ValueError
        if (data["auth"] not in ("basic", "bearer", "template")
                or data.get("method", "GET") not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")):
            raise ValueError
        https_target(data["url"])
        if "json" in data and not isinstance(data["json"], (dict, str)):
            raise ValueError
        for key in ("headers", "query"):
            if key in data and (not isinstance(data[key], dict) or len(data[key]) > (32 if key == "query" else 16)
                    or any(not isinstance(name, str) or not name or not isinstance(value, str)
                           for name, value in data[key].items())):
                raise ValueError
    else:
        keys = {"type", "url", "submit_url", "form_id", "username_field", "password_field", "success_id"}
        if not keys <= data.keys() <= keys | {"success_url"} or any(not isinstance(value, str) for value in data.values()):
            raise ValueError
        for key in ("url", "submit_url", "success_url"):
            if data.get(key):
                https_target(data[key])
    if len(encode(data)) >= REQUEST_LIMIT:
        raise ValueError
    return data


def _validate_access_details(reply):
    required = {"status", "identity", "project", "model", "chat", "chat_id", "scope", "requested_items", "pending_change"}
    if set(reply) != required:
        raise ValueError
    for key in ("identity", "project", "model", "chat", "chat_id"):
        value = reply[key]
        if value is not None and (not isinstance(value, str) or not value or len(value) > 160 or not value.isprintable()):
            raise ValueError
    if reply["identity"] is None or reply["project"] is None:
        raise ValueError

    def items(values, *, requested=False):
        fields = {"vault", "entry", "group", "metadata", "username", "url", "action", "edits"}
        if requested:
            fields.add("label")
        if not isinstance(values, list) or len(values) > 16:
            raise ValueError
        for value in values:
            if (not isinstance(value, dict) or not fields <= value.keys() <= fields | {"uses", "origins"}
                    or bool({"uses", "origins"} & value.keys()) and not {"uses", "origins"} <= value.keys()):
                raise ValueError
            uses, origins = value.get("uses", []), value.get("origins", [])
            if (not isinstance(uses, list) or any(not isinstance(use, str) or use not in CREDENTIAL_USE_TYPES for use in uses)
                    or len(set(uses)) != len(uses) or "https_body" in uses and not {"https", "https_results"} & set(uses)
                    or not isinstance(origins, list) or len(origins) > 8
                    or any(https_target(origin, origin=True) != origin for origin in origins)
                    or len(set(origins)) != len(origins)
                    or bool(set(uses) - {"local_command"}) != bool(origins)
                    or value.get("group") is not None and uses):
                raise ValueError
            for key in ("vault", "entry", "group"):
                if value[key] is not None and edit_uuid(value[key]) != value[key]:
                    raise ValueError
            if any(type(value[key]) is not bool for key in ("metadata", "username", "url")):
                raise ValueError
            if (value["username"] or value["url"]) and not value["metadata"]:
                raise ValueError
            action = value["action"]
            if action is not None and (not isinstance(action, str) or not action or len(action) > 160 or not action.isprintable()):
                raise ValueError
            if requested:
                label = value["label"]
                if label is not None and (not isinstance(label, str) or not label or len(label) > 160 or not label.isprintable()):
                    raise ValueError
            edits = value["edits"]
            allowed_edits = {"create_entry", "create_group", "rename_group", "move_group", "recycle_group", "move_into"} if value["group"] else {
                "update_entry", "move_entry", "recycle_entry", "replace_password"}
            if (not isinstance(edits, list) or any(not isinstance(edit, str) or edit not in allowed_edits for edit in edits)
                    or len(set(edits)) != len(edits)):
                raise ValueError

    items(reply["scope"])
    items(reply["requested_items"], requested=True)
    pending = reply["pending_change"]
    if pending is not None:
        if not isinstance(pending, dict) or set(pending) != {"id", "items"} or edit_uuid(pending["id"]) != pending["id"]:
            raise ValueError
        items(pending["items"], requested=True)


def _validate(reply, payload):
    operation = payload["operation"]
    if not isinstance(reply, dict):
        raise ListingError("invalid_response")
    if set(reply) == {"error"}:
        error = reply["error"]
        if isinstance(error, str) and error in ERRORS:
            raise ListingError(error)
    if operation in ("request_access", "access_status"):
        if reply.get("status") not in ("pending", "active", "disabled", "denied", "removed"):
            raise ListingError("invalid_response")
        if operation == "access_status" and payload.get("details"):
            try:
                _validate_access_details(reply)
            except (ValueError, TypeError, KeyError):
                raise ListingError("invalid_response") from None
        elif set(reply) != {"status"}:
            raise ListingError("invalid_response")
        return reply
    if operation in ("request_edit", "edit_status"):
        edit = payload["request"] if operation == "request_edit" else None
        expected_id = edit["id"] if edit is not None else payload["id"]
        if (
            not {"id", "status"} <= reply.keys() <= {"id", "status", "result"}
            or reply["id"] != expected_id
            or reply["status"] not in EDIT_STATUSES
            or "result" in reply and (
                reply["status"] != "applied"
                or edit is not None and edit["operation"] not in ("create_entry", "create_group")
                or edit_uuid(reply["result"]) != reply["result"]
            )
        ):
            raise ListingError("invalid_response")
        return reply
    if operation == "discover":
        if set(reply) != {"vaults"} or not isinstance(reply["vaults"], list):
            raise ListingError("invalid_response")
        for vault in reply["vaults"]:
            if (not isinstance(vault, dict)
                    or set(vault) != {"id", "name", "locked", "cached", "available", "groups", "entries"}
                    or not isinstance(vault["name"], str)
                    or any(type(vault[key]) is not bool for key in ("locked", "cached", "available"))
                    or not isinstance(vault["groups"], list) or not isinstance(vault["entries"], list)):
                raise ListingError("invalid_response")
            edit_uuid(vault["id"])
            for group in vault["groups"]:
                if (not isinstance(group, dict) or set(group) != {"id", "name", "parent"}
                        or not isinstance(group["name"], str)):
                    raise ListingError("invalid_response")
                edit_uuid(group["id"])
                if group["parent"] is not None:
                    edit_uuid(group["parent"])
            for entry in vault["entries"]:
                if (not isinstance(entry, dict) or set(entry) != {"id", "title", "group"}
                        or not isinstance(entry["title"], str)):
                    raise ListingError("invalid_response")
                edit_uuid(entry["id"])
                edit_uuid(entry["group"])
        return reply
    if operation == "list_vaults":
        if set(reply) != {"vaults"} or not isinstance(reply["vaults"], list):
            raise ListingError("invalid_response")
        for row in reply["vaults"]:
            if (not isinstance(row, dict) or set(row) != {"id", "name"}
                    or not isinstance(row["id"], str) or not isinstance(row["name"], str)
                    or str(UUID(row["id"])) != row["id"]):
                raise ListingError("invalid_response")
        return reply
    if operation == "use_password":
        if payload.get("usage", {}).get("type") == "https_results":
            if reply.get("outcome") == "succeeded":
                if set(reply) != {"outcome", "http_status", "data"} or type(reply["http_status"]) is not int or not 200 <= reply["http_status"] < 300:
                    raise ListingError("invalid_response")
                rows = reply["data"]
                columns = result_columns(payload["usage"]["result"]["columns"])
                if not isinstance(rows, list) or len(rows) > 256:
                    raise ListingError("invalid_response")
                for row in rows:
                    if not isinstance(row, dict) or set(row) != set(columns):
                        raise ListingError("invalid_response")
                    for value in row.values():
                        if (value is not None and type(value) not in (str, bool, int, float)
                                or isinstance(value, str) and len(value) > 512
                                or type(value) is float and not math.isfinite(value)):
                            raise ListingError("invalid_response")
                return reply
            if (reply not in ({"outcome": "failed"}, {"outcome": "uncertain"})
                    and not (set(reply) == {"outcome", "http_status"} and reply["outcome"] == "failed"
                             and type(reply["http_status"]) is int and 100 <= reply["http_status"] <= 599)):
                raise ListingError("invalid_response")
            return reply
        if payload.get("usage", {}).get("type") in ("local_command", "networked_command"):
            if reply != {"outcome": "dispatched"}:
                raise ListingError("invalid_response")
            return reply
        if "command" in payload:
            if set(reply) != {"outcome"} or reply["outcome"] not in ("succeeded", "failed", "uncertain"):
                raise ListingError("invalid_response")
            return reply
        status = reply.get("http_status")
        if (
            "outcome" not in reply or set(reply) - {"outcome", "http_status"}
            or reply["outcome"] not in ("succeeded", "failed", "uncertain")
            or ("http_status" in reply and (type(status) is not int or not 100 <= status <= 599))
            or (reply["outcome"] == "succeeded" and (status is None or not 200 <= status < 300))
            or (reply["outcome"] == "uncertain" and status is not None)
        ):
            raise ListingError("invalid_response")
        return reply
    if set(reply) != {"entries"} or not isinstance(reply["entries"], list):
        raise ListingError("invalid_response")
    required = {"id", "title", "group_path"}
    fields = payload.get("fields", ())
    allowed = required | set(fields)
    for row in reply["entries"]:
        if (
            not isinstance(row, dict)
            or not required <= row.keys() <= allowed
            or any(field in row and not isinstance(row[field], str) for field in fields)
            or not isinstance(row["id"], str)
            or not isinstance(row["title"], str)
            or not isinstance(row["group_path"], list)
            or not all(isinstance(name, str) for name in row["group_path"])
        ):
            raise ListingError("invalid_response")
        try:
            if str(UUID(row["id"])) != row["id"]:
                raise ValueError
        except ValueError:
            raise ListingError("invalid_response") from None
    return reply


def request(endpoint, payload, *, input_data=None):
    if not endpoint or not os.path.isabs(endpoint):
        raise ListingError()

    deadline = monotonic() + CLIENT_TIMEOUT
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(REQUEST_TIMEOUT)
            connection.connect(endpoint)
            connection.settimeout(remaining(deadline))
            connection.sendall(encode(payload))
            response = receive(connection, RESPONSE_LIMIT, deadline)
            if input_data is not None and decode(response) == {"upload": True}:
                connection.settimeout(remaining(deadline))
                connection.sendall(input_data)
                response = receive(connection, RESPONSE_LIMIT, deadline)
    except (OSError, EOFError):
        raise ListingError() from None
    except (ValueError, RecursionError):
        raise ListingError("invalid_response") from None
    try:
        return _validate(decode(response), payload)
    except (ValueError, RecursionError):
        raise ListingError("invalid_response") from None


def list_entries(endpoint):
    return request(endpoint, LIST_REQUEST)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="keepassxc-agent")
    topics = parser.add_subparsers(required=True)
    discover = topics.add_parser("discover", help="List all vault, group and entry names before requesting access")
    discover.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    discover.add_argument("--vault", help="Return the catalog for one vault")
    discover.add_argument("--summary", action="store_true", help="List vault names and status without group or entry rows")
    discover.set_defaults(operation="discover")
    access = topics.add_parser("access", help="Request and check a scoped token")
    commands = access.add_subparsers(required=True)
    enrollment = commands.add_parser("request", help="Read a new token or permission-change request from stdin")
    enrollment.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    enrollment.set_defaults(operation="request_access")
    status = commands.add_parser("status", help="Check this profile's token")
    status.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    status.add_argument("--details", action="store_true", help="Show the registered identity, project, attribution, and permission scope")
    status.set_defaults(operation="access_status")
    edits = topics.add_parser("edits", help="Request an owner-reviewed vault edit")
    commands = edits.add_subparsers(required=True)
    submit = commands.add_parser("request", help="Read an edit request as JSON from stdin")
    submit.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    submit.set_defaults(operation="request_edit")
    progress = commands.add_parser("status", help="Check the status of an edit request")
    progress.add_argument("--request", required=True, type=_request_id, help="Request UUID")
    progress.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    progress.set_defaults(operation="edit_status")
    vaults = topics.add_parser("vaults", help="Discover vaults in this token's scope")
    catalog = vaults.add_subparsers(required=True).add_parser("list")
    catalog.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    catalog.set_defaults(operation="list_vaults")
    entries = topics.add_parser("entries", help="Read entry metadata")
    commands = entries.add_subparsers(required=True)
    listing = commands.add_parser("list", help="List approved entry metadata")
    listing.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    listing.add_argument("--vault", help="Scoped vault ID")
    listing.add_argument("--field", choices=ENTRY_FIELDS, action="append",
                         help="Include an additional approved metadata field")
    listing.add_argument("--include-reviewed", action="store_true", help=argparse.SUPPRESS)
    listing.set_defaults(operation="list_entries")
    use = topics.add_parser("use", help="Read a credential-use descriptor from stdin, or run a legacy configured action")
    use.add_argument("--vault", help="Scoped vault ID")
    use.add_argument("--entry", required=True, help="Entry UUID")
    use.add_argument("--action", help="Legacy owner-configured action ID; omit to read a usage descriptor")
    use.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    use.set_defaults(operation="use_password")
    run = topics.add_parser("run", help="Use a Keeper credential with an approved isolated command")
    run.add_argument("--vault", help="Scoped vault ID")
    run.add_argument("--entry", required=True, help="Entry UUID")
    run.add_argument("--action", help="Legacy approved command action ID")
    run.add_argument("--origin", help="The exact approved network destination")
    run.add_argument("--prompt-variable", help="Private credential prompt variable ending in _ASKPASS")
    run.add_argument("--prompt-contains", help="Literal text identifying the credential prompt; defaults to password")
    run.add_argument("--environment-json", help="Nonsecret JSON environment for a dynamic networked command")
    run.add_argument("--input", action="store_true", help="Read an approved input file from stdin")
    run.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    run.add_argument("command", nargs=argparse.REMAINDER, help="The exact approved executable and arguments")
    run.set_defaults(operation="use_password")
    options = parser.parse_args(argv)
    if hasattr(options, "command"):
        try:
            args = options.command[1:] if options.command[:1] == ["--"] else options.command
            options.command = validate_command(args)
        except ValueError as error:
            parser.error(str(error))
    payload = {"version": 1, "operation": options.operation}
    if options.operation == "use_password":
        payload["entry"] = options.entry
        if options.action:
            payload["action"] = options.action
        if hasattr(options, "command"):
            if options.action:
                if options.origin or options.prompt_variable or options.environment_json or options.prompt_contains:
                    parser.error("Use either a legacy action ID or a supplied network destination.")
                payload["command"] = options.command
            else:
                if bool(options.origin) != bool(options.prompt_variable):
                    parser.error("Networked commands need both --origin and --prompt-variable.")
                if (options.environment_json or options.prompt_contains) and not options.origin:
                    parser.error("Declared environment requires a dynamic network destination.")
                if options.input and not options.origin:
                    parser.error("Only networked commands accept an input artifact.")
                usage = {"type": "networked_command" if options.origin else "local_command",
                         "command": list(options.command)}
                if options.origin:
                    usage.update(origin=options.origin, prompt_variable=options.prompt_variable)
                try:
                    if options.prompt_contains:
                        usage["prompt_contains"] = options.prompt_contains
                    if options.environment_json:
                        usage["environment"] = decode(options.environment_json.encode("utf-8"))
                    payload["usage"] = usage_request(usage)
                except ValueError:
                    parser.error("Invalid credential-use command or destination.")
    elif getattr(options, "include_reviewed", False):
        payload["include_reviewed"] = True
    if options.operation == "edit_status":
        payload["id"] = options.request
    if getattr(options, "vault", None):
        payload["vault"] = options.vault
    if getattr(options, "field", None):
        payload["fields"] = list(dict.fromkeys(options.field))
    if getattr(options, "details", False):
        payload["details"] = True
    if getattr(options, "summary", False):
        payload["summary"] = True
    context = {}
    for key in ("model", "chat", "chat_id", "note"):
        raw = os.environ.get(f"KEEPASSXC_AGENT_{key.upper()}", "")
        value = "".join(char for char in raw[:640] if char.isprintable()).strip()[:180 if key == "note" else 160]
        if value:
            context[key] = value
    if context:
        payload["context"] = context

    try:
        input_data = None
        if getattr(options, "input", False):
            input_data = sys.stdin.buffer.read(UPLOAD_LIMIT + 1)
            if not 0 < len(input_data) <= UPLOAD_LIMIT:
                raise ListingError("too_large")
            payload["upload"] = {"size": len(input_data), "sha256": sha256(input_data).hexdigest()}
        if options.operation == "use_password" and "action" not in payload and "usage" not in payload:
            try:
                raw = sys.stdin.buffer.read(REQUEST_LIMIT)
                if len(raw) >= REQUEST_LIMIT:
                    raise ValueError
                payload["usage"] = usage_request(decode(raw))
            except (ValueError, TypeError, RecursionError):
                raise ListingError("invalid_request") from None
        token_file = os.environ.get("KEEPASSXC_AGENT_TOKEN_FILE")
        if options.operation in ("request_access", "request_edit"):
            try:
                raw = sys.stdin.buffer.read(REQUEST_LIMIT)
                if len(raw) >= REQUEST_LIMIT:
                    raise ValueError
                submitted = decode(raw)
                if options.operation == "request_access" and any(key in os.environ for key in
                        ("KEEPASSXC_AGENT_IDENTITY", "KEEPASSXC_AGENT_PROJECT")):
                    identity = os.environ.get("KEEPASSXC_AGENT_IDENTITY")
                    project = os.environ.get("KEEPASSXC_AGENT_PROJECT")
                    if not isinstance(submitted, dict) or not identity or not project:
                        raise ValueError
                    if (submitted.get("identity", identity) != identity or submitted.get("project", project) != project):
                        raise ValueError
                    submitted = {**submitted, "identity": identity, "project": project}
                payload["request"] = edit_request(submitted) if options.operation == "request_edit" else submitted
            except (ValueError, RecursionError):
                raise ListingError("invalid_request") from None
        if options.operation != "discover" and (token_file or options.operation in (
            "request_access", "access_status", "list_vaults", "request_edit", "edit_status",
        )):
            scope = payload.get("request")
            create = options.operation == "request_access" and isinstance(scope, dict) and "change_id" not in scope
            payload["credential"] = credential(token_file, create=create)
        if len(encode(payload)) > REQUEST_LIMIT:
            raise ListingError("too_large")
        result = request(os.environ.get("KEEPASSXC_AGENT_SOCKET"), payload, input_data=input_data)
        sys.stdout.buffer.write(encode(result))
    except UninitializedProfile as error:
        if options.operation == "access_status":
            result = {"status": "uninitialized"}
            if options.details:
                result.update({key: os.environ.get(f"KEEPASSXC_AGENT_{key.upper()}") for key in
                               ("identity", "project", "model", "chat", "chat_id")})
                result.update(scope=[], requested_items=[], pending_change=None)
            sys.stdout.buffer.write(encode(result))
            return 0
        print(error, file=sys.stderr)
        return 1
    except ListingError as error:
        print(error, file=sys.stderr)
        return 1
    return int(result.get("outcome") in ("failed", "uncertain"))


if __name__ == "__main__":
    raise SystemExit(main())
