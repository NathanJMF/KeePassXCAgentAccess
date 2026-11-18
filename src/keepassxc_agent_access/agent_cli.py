"""Agent-side command. This module needs only the Python standard library."""

import argparse
from base64 import b64decode
import ipaddress
import math
import re
from hashlib import sha256
import os
import socket
import sys
from time import monotonic, sleep
from uuid import UUID, uuid5
from urllib.parse import urlsplit

from .runner_token import UninitializedProfile, credential
from .protocol import (
    CLIENT_TIMEOUT, CONSOLE_OPERATIONS, CONSOLE_SECONDS, ERRORS, GUEST_OPERATIONS, LIST_REQUEST, ListingError,
    MAX_CONSOLE_REUSE_MINUTES, MAX_GUEST_REUSE_MINUTES, MAX_GUEST_TEXT, MAX_WAIT_SECONDS,
    REQUEST_LIMIT, REQUEST_TIMEOUT, RESPONSE_LIMIT, UPLOAD_LIMIT, WORKFLOW_OPERATIONS,
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
    if operation == "replace_password" or operation == "create_entry" and "password_source" in data:
        if data.get("password_source") not in ("owner", "generate"):
            raise ValueError
    optional = {"fields", "password_source"} if operation == "create_entry" else {"fields"}
    if not required <= data.keys() <= required | optional:
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
    if not required <= data.keys() <= required | {"certificate_sha256", "login", "approve_write_once"}:
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
    write = request.get("method", "GET") in ("POST", "PUT", "PATCH", "DELETE")
    if "approve_write_once" in data and (data["approve_write_once"] is not True or not write):
        raise ValueError
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
    if (not isinstance(result, dict) or set(result) - {"path", "columns", "scalar"}
            or ("columns" in result) == ("scalar" in result) or "scalar" in result and not write):
        raise ValueError
    result_pointer(result.get("path", ""))
    result_columns([result["scalar"]] if "scalar" in result else result["columns"])
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


def _validate_result_rows(rows, columns=None, *, scalar=False, text_limit=512):
    if not isinstance(rows, list) or len(rows) > 256 or scalar and len(rows) != 1:
        raise ListingError("invalid_response")
    for row in rows:
        if not isinstance(row, dict) or (columns is not None and set(row) != set(columns)):
            raise ListingError("invalid_response")
        if columns is None and row:
            result_columns(list(row))
        for value in row.values():
            if (value is not None and type(value) not in (str, bool, int, float)
                    or isinstance(value, str) and len(value) > text_limit
                    or type(value) is float and not math.isfinite(value)):
                raise ListingError("invalid_response")


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
    if operation == "release_entry":
        if (set(reply) != {"status", "cancelled_change"} or reply["status"] != "released"
                or type(reply["cancelled_change"]) is not bool):
            raise ListingError("invalid_response")
        return reply
    if operation == "write_status":
        status = reply.get("status")
        code = reply.get("http_status")
        if (not {"id", "status"} <= reply.keys() <= {"id", "status", "http_status"}
                or reply["id"] != payload["receipt"]
                or status not in ("pending", "dispatching", "not_sent", "succeeded", "failed", "uncertain", "acknowledged")
                or ("http_status" in reply and (type(code) is not int or not 100 <= code <= 599))
                or (status in ("succeeded", "acknowledged") and (code is None or not 200 <= code < 300))
                or (status not in ("succeeded", "acknowledged", "failed") and code is not None)):
            raise ListingError("invalid_response")
        return reply
    if operation in ("workflow_request", "workflow_status"):
        identifier = payload["request"]["id"] if operation == "workflow_request" else payload["workflow"]
        steps = reply.get("receipts")
        if (set(reply) != {"id", "expires_in", "receipts"} or reply["id"] != identifier
                or type(reply["expires_in"]) is not int or not 1 <= reply["expires_in"] <= 3600
                or not isinstance(steps, dict) or len(steps) > 8):
            raise ListingError("invalid_response")
        if any(not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", name)
               or receipt != str(uuid5(UUID(identifier), name)) for name, receipt in steps.items()):
            raise ListingError("invalid_response")
        if operation == "workflow_request" and set(steps) != {step["name"] for step in payload["request"]["steps"]
                                                               if step.get("kind") != "console"}:
            raise ListingError("invalid_response")
        return reply
    if operation == "workflow_run":
        if "console" in reply:
            return _validate(reply, {"operation": "console_open"})
        if "id" in reply:
            receipt = str(uuid5(UUID(payload["workflow"]), payload["step"]))
            return _validate(reply, {"operation": "guest_run", "receipt": receipt})
        outcome = reply.get("outcome")
        status = reply.get("http_status")
        if outcome == "succeeded":
            if set(reply) != {"outcome", "http_status", "data"} or type(status) is not int or not 200 <= status < 300:
                raise ListingError("invalid_response")
            _validate_result_rows(reply["data"])
        elif outcome == "acknowledged":
            if set(reply) != {"outcome", "http_status"} or type(status) is not int or not 200 <= status < 300:
                raise ListingError("invalid_response")
        elif (reply not in ({"outcome": "failed"}, {"outcome": "uncertain"})
              and not (set(reply) == {"outcome", "http_status"} and outcome == "failed"
                       and type(status) is int and 100 <= status <= 599)):
            raise ListingError("invalid_response")
        return reply
    if operation == "guest_release":
        if reply != {"id": payload["receipt"], "outcome": "released"}:
            raise ListingError("invalid_response")
        return reply
    if operation in GUEST_OPERATIONS:
        outcome = reply.get("outcome")
        code = reply.get("http_status")
        success = outcome in ("succeeded", "acknowledged")
        expected = {"id", "outcome"}
        if success or "http_status" in reply:
            expected.add("http_status")
        if outcome == "succeeded" and operation == "guest_status":
            expected.add("data")
            _validate_result_rows(reply.get("data"), text_limit=MAX_GUEST_TEXT)
        if payload.get("reuse_minutes"):
            expected.add("reuse_expires_in")
            reuse = reply.get("reuse_expires_in")
            if type(reuse) is not int or not 0 <= reuse <= MAX_GUEST_REUSE_MINUTES * 60:
                raise ListingError("invalid_response")
        if (set(reply) != expected or reply["id"] != payload["receipt"]
                or outcome not in ("succeeded", "acknowledged", "failed", "uncertain")
                or (code is not None and (type(code) is not int or not 100 <= code <= 599))
                or (success and (code is None or not 200 <= code < 300))
                or (outcome == "uncertain" and code is not None)
                or (operation == "guest_status" and outcome not in ("succeeded", "failed"))):
            raise ListingError("invalid_response")
        return reply
    if operation in CONSOLE_OPERATIONS:
        if operation == "console_open":
            expected = {"console", "expires_in"}
            if "reuse_minutes" in payload:
                expected.add("reuse_expires_in")
            if (set(reply) != expected or edit_uuid(reply["console"]) != reply["console"]
                    or type(reply["expires_in"]) is not int or not 1 <= reply["expires_in"] <= CONSOLE_SECONDS):
                raise ListingError("invalid_response")
            if "reuse_expires_in" in reply and (type(reply["reuse_expires_in"]) is not int
                    or not 0 <= reply["reuse_expires_in"] <= MAX_CONSOLE_REUSE_MINUTES * 60):
                raise ListingError("invalid_response")
        elif operation == "console_view":
            fields = {"width", "height"}
            status_only = payload.get("status_only") is True
            expected = fields | ({"changed"} if status_only else {"png_base64", "scale"})
            if (set(reply) != expected or type(reply["width"]) is not int or not 1 <= reply["width"] <= 2048
                    or type(reply["height"]) is not int or not 1 <= reply["height"] <= 1536):
                raise ListingError("invalid_response")
            if status_only:
                if type(reply["changed"]) is not bool:
                    raise ListingError("invalid_response")
                return reply
            if (type(reply["scale"]) is not int or reply["scale"] not in (1, 2, 4, 8)
                    or not isinstance(reply["png_base64"], str)):
                raise ListingError("invalid_response")
            png = b64decode(reply["png_base64"], validate=True)
            if not png.startswith(b"\x89PNG\r\n\x1a\n") or len(png) > 700_000:
                raise ListingError("invalid_response")
        elif reply != {"outcome": "succeeded"}:
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
                projection = payload["usage"]["result"]
                scalar = "scalar" in projection
                columns = result_columns([projection["scalar"]] if scalar else projection["columns"])
                _validate_result_rows(reply["data"], columns, scalar=scalar)
                return reply
            if (reply.get("outcome") == "acknowledged" and set(reply) == {"outcome", "http_status"}
                    and type(reply["http_status"]) is int and 200 <= reply["http_status"] < 300
                    and payload["usage"]["request"].get("method") in ("POST", "PUT", "PATCH", "DELETE")):
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


def request(endpoint, payload, *, input_data=None, deadline=None):
    if not endpoint or not os.path.isabs(endpoint):
        raise ListingError()

    bounded = deadline is not None
    deadline = monotonic() + CLIENT_TIMEOUT if not bounded else deadline
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(min(REQUEST_TIMEOUT, remaining(deadline)))
            connection.connect(endpoint)
            connection.settimeout(remaining(deadline))
            connection.sendall(encode(payload))
            response = receive(connection, RESPONSE_LIMIT, deadline)
            if input_data is not None and decode(response) == {"upload": True}:
                connection.settimeout(remaining(deadline))
                connection.sendall(input_data)
                response = receive(connection, RESPONSE_LIMIT, deadline)
    except TimeoutError:
        if bounded and monotonic() >= deadline:
            raise ListingError("wait_elapsed") from None
        raise ListingError() from None
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


def wait_status(endpoint, payload, seconds, *, field=None, expected=None):
    deadline = monotonic() + seconds
    delay = 1
    last = None
    while monotonic() < deadline:
        try:
            result = request(endpoint, payload, deadline=deadline)
        except ListingError as error:
            if error.code == "wait_elapsed":
                break
            if error.code != "busy":
                raise
        else:
            last = result
            if result.get("outcome") == "failed":
                return {**result, "wait": "failed"}
            if field is None:
                if result["changed"]:
                    return {**result, "wait": "changed"}
            elif any(field in row and type(row[field]) is type(expected) and row[field] == expected
                     for row in result["data"]):
                return {**result, "wait": "matched"}
        sleep(max(0, min(delay, deadline - monotonic())))
        delay = min(delay * 2, 5)
    if last is None:
        raise ListingError("wait_elapsed")
    return {**{key: value for key, value in last.items() if key != "data"}, "wait": "timed_out"}


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
    release = commands.add_parser("release", help="Give up this token's access to one entry")
    release.add_argument("--vault", required=True, type=_request_id)
    release.add_argument("--entry", required=True, type=_request_id)
    release.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    release.set_defaults(operation="release_entry")
    edits = topics.add_parser("edits", help="Request an owner-reviewed vault edit")
    commands = edits.add_subparsers(required=True)
    submit = commands.add_parser("request", help="Read an edit request as JSON from stdin")
    submit.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    submit.set_defaults(operation="request_edit")
    progress = commands.add_parser("status", help="Check the status of an edit request")
    progress.add_argument("--request", required=True, type=_request_id, help="Request UUID")
    progress.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    progress.set_defaults(operation="edit_status")
    results = topics.add_parser("results", help="Check a protected HTTPS write receipt")
    receipt_status = results.add_subparsers(required=True).add_parser("status")
    receipt_status.add_argument("--receipt", required=True, type=_request_id, help="Write receipt UUID")
    receipt_status.add_argument("--json", action="store_true", required=True)
    receipt_status.set_defaults(operation="write_status")
    workflows = topics.add_parser("workflows", help="Review and run a known group of operations together")
    commands = workflows.add_subparsers(required=True)
    submit = commands.add_parser("request", help="Read the workflow manifest from stdin")
    submit.set_defaults(operation="workflow_request")
    progress = commands.add_parser("status", help="Check the current workflow authorization and step receipts")
    progress.set_defaults(operation="workflow_status")
    step = commands.add_parser("run", help="Run a named step from the approved manifest")
    step.add_argument("--step", required=True)
    step.set_defaults(operation="workflow_run")
    for subcommand in (progress, step):
        subcommand.add_argument("--workflow", required=True, type=_request_id)
    for subcommand in (submit, progress, step):
        subcommand.add_argument("--json", action="store_true", required=True)
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
    use.add_argument("--receipt", type=_request_id, help="Track a protected HTTPS write under this UUID")
    use.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    use.set_defaults(operation="use_password")
    accounts = topics.add_parser("accounts", help="Privately provision an account from a Keeper entry")
    provision = accounts.add_subparsers(required=True).add_parser("provision")
    provision.add_argument("--vault", required=True, type=_request_id)
    provision.add_argument("--entry", required=True, type=_request_id, help="Approved administrative entry")
    provision.add_argument("--account", required=True, type=_request_id, help="Separate account entry in the same vault")
    provision.add_argument("--receipt", required=True, type=_request_id)
    provision.add_argument("--json", action="store_true", required=True)
    provision.set_defaults(operation="use_password", provision_account=True, action=None)
    console = topics.add_parser("console", help="Open or use an owner-approved guest console")
    commands = console.add_subparsers(required=True)
    opening = commands.add_parser("open", help="Read the console connection descriptor from stdin")
    opening.add_argument("--vault", required=True, type=_request_id)
    opening.add_argument("--entry", required=True, type=_request_id)
    opening.add_argument("--reuse-for", type=int, metavar="MINUTES",
                         help=f"Ask to reopen this pinned connection for up to {MAX_CONSOLE_REUSE_MINUTES} minutes")
    opening.add_argument("--json", action="store_true", required=True)
    opening.set_defaults(operation="console_open")
    for verb in ("view", "input", "close", "wait"):
        command = commands.add_parser(verb)
        command.add_argument("--console", required=True, type=_request_id)
        if verb == "view":
            output = command.add_mutually_exclusive_group(required=True)
            output.add_argument("--png", action="store_true")
            output.add_argument("--json", action="store_true")
            output.add_argument("--status", action="store_true", help="Report screen changes without returning an image")
        else:
            command.add_argument("--json", action="store_true", required=True)
        if verb == "wait":
            command.add_argument("--timeout", type=int, default=30, metavar="SECONDS")
            command.set_defaults(operation="console_view", status=True)
        else:
            command.set_defaults(operation="console_" + verb)
    guest = topics.add_parser("guest", help="Run or check commands at an approved guest endpoint")
    commands = guest.add_subparsers(required=True)
    command = commands.add_parser("run", help="Read a guest workflow and command from stdin as JSON")
    command.add_argument("--vault", required=True, type=_request_id)
    command.add_argument("--entry", required=True, type=_request_id)
    command.add_argument("--reuse-for", type=int, metavar="MINUTES",
                         help=f"Ask to reuse this endpoint for up to {MAX_GUEST_REUSE_MINUTES} minutes")
    command.set_defaults(operation="guest_run")
    status = commands.add_parser("status", help="Read the approved result fields for a guest job")
    status.set_defaults(operation="guest_status")
    release = commands.add_parser("release", help="Give up this profile's job status handle")
    release.set_defaults(operation="guest_release")
    wait = commands.add_parser("wait", help="Wait for a projected status field to equal a JSON scalar")
    wait.add_argument("--until", required=True, metavar="FIELD")
    wait.add_argument("--equals-json", required=True, metavar="VALUE")
    wait.add_argument("--timeout", type=int, default=30, metavar="SECONDS")
    wait.set_defaults(operation="guest_status")
    for subcommand in (command, status, release, wait):
        subcommand.add_argument("--receipt", required=True, type=_request_id)
        subcommand.add_argument("--json", action="store_true", required=True)
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
    timeout = getattr(options, "timeout", None)
    expected = None
    if timeout is not None:
        if not 1 <= timeout <= MAX_WAIT_SECONDS:
            parser.error(f"--timeout needs a duration from 1 to {MAX_WAIT_SECONDS} seconds")
        if options.operation == "guest_status":
            try:
                result_columns([options.until])
                if len(options.equals_json) > MAX_GUEST_TEXT:
                    raise ValueError
                expected = decode(options.equals_json.encode("utf-8"))
                if expected is not None and (type(expected) not in (str, int, float, bool)
                        or type(expected) is float and not math.isfinite(expected)):
                    raise ValueError
            except (ValueError, RecursionError):
                parser.error("Provide a result field and one JSON scalar.")
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
    if options.operation in ("workflow_run", "workflow_status"):
        payload["workflow"] = options.workflow
        if options.operation == "workflow_run":
            payload["step"] = options.step
    if getattr(options, "receipt", None):
        payload["receipt"] = options.receipt
    if options.operation in ("console_open", "release_entry", "guest_run"):
        payload["entry"] = options.entry
        if options.operation in ("console_open", "guest_run") and options.reuse_for is not None:
            maximum = MAX_CONSOLE_REUSE_MINUTES if options.operation == "console_open" else MAX_GUEST_REUSE_MINUTES
            if not 1 <= options.reuse_for <= maximum:
                parser.error(f"--reuse-for needs a duration from 1 to {maximum} minutes")
            payload["reuse_minutes"] = options.reuse_for
    elif options.operation in CONSOLE_OPERATIONS:
        payload["console"] = options.console
        if options.operation == "console_view" and options.status:
            payload["status_only"] = True
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
                descriptor = decode(raw)
                if getattr(options, "provision_account", False):
                    if not isinstance(descriptor, dict) or set(descriptor) != {"workflow", "body_type", "fields"}:
                        raise ValueError
                    payload["provision"] = {"entry": options.account, "body_type": descriptor["body_type"],
                                            "fields": descriptor["fields"]}
                    descriptor = descriptor["workflow"]
                payload["usage"] = usage_request(descriptor)
            except (ValueError, TypeError, RecursionError):
                raise ListingError("invalid_request") from None
        token_file = os.environ.get("KEEPASSXC_AGENT_TOKEN_FILE")
        if options.operation in ("console_open", "console_input"):
            try:
                raw = sys.stdin.buffer.read(REQUEST_LIMIT)
                if not raw or len(raw) >= REQUEST_LIMIT:
                    raise ValueError
                payload["request" if options.operation == "console_open" else "events"] = decode(raw)
            except (ValueError, RecursionError):
                raise ListingError("invalid_request") from None
        if options.operation == "guest_run":
            try:
                raw = sys.stdin.buffer.read(REQUEST_LIMIT)
                if not raw or len(raw) >= REQUEST_LIMIT:
                    raise ValueError
                guest = decode(raw)
                if not isinstance(guest, dict) or set(guest) != {"workflow", "command"}:
                    raise ValueError
                payload.update(guest)
            except (ValueError, RecursionError):
                raise ListingError("invalid_request") from None
        if options.operation in ("request_access", "request_edit", "workflow_request"):
            try:
                raw = sys.stdin.buffer.read(REQUEST_LIMIT)
                if not raw or len(raw) >= REQUEST_LIMIT:
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
                if options.operation == "workflow_request":
                    if not isinstance(submitted, dict) or "id" not in submitted:
                        raise ValueError
                    submitted["id"] = edit_uuid(submitted["id"])
                payload["request"] = edit_request(submitted) if options.operation == "request_edit" else submitted
            except (ValueError, RecursionError):
                raise ListingError("invalid_request") from None
        if options.operation != "discover" and (token_file or options.operation in GUEST_OPERATIONS | WORKFLOW_OPERATIONS
                or options.operation in (
            "request_access", "access_status", "release_entry", "list_vaults", "request_edit", "edit_status", "write_status",
        )):
            scope = payload.get("request")
            create = options.operation == "request_access" and isinstance(scope, dict) and "change_id" not in scope
            payload["credential"] = credential(token_file, create=create)
        if len(encode(payload)) > REQUEST_LIMIT:
            raise ListingError("too_large")
        endpoint = os.environ.get("KEEPASSXC_AGENT_SOCKET")
        if timeout is not None:
            result = wait_status(endpoint, payload, timeout, field=getattr(options, "until", None), expected=expected)
        else:
            result = request(endpoint, payload, input_data=input_data)
        sys.stdout.buffer.write(b64decode(result["png_base64"]) if getattr(options, "png", False) else encode(result))
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
    return int(result.get("outcome") in ("failed", "uncertain", "acknowledged"))


if __name__ == "__main__":
    raise SystemExit(main())
