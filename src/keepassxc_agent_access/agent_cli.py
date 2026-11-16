"""Agent-side command. This module needs only the Python standard library."""

import argparse
from hashlib import sha256
import os
import socket
import sys
from time import monotonic
from uuid import UUID

from .runner_token import UninitializedProfile, credential
from .protocol import (
    CLIENT_TIMEOUT, ERRORS, LIST_REQUEST, ListingError, REQUEST_LIMIT, REQUEST_TIMEOUT, RESPONSE_LIMIT, UPLOAD_LIMIT,
    decode, encode, receive, remaining, validate_command,
)


ENTRY_FIELDS = ("username", "url")
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


def _validate(reply, payload):
    operation = payload["operation"]
    if not isinstance(reply, dict):
        raise ListingError("invalid_response")
    if set(reply) == {"error"}:
        error = reply["error"]
        if isinstance(error, str) and error in ERRORS:
            raise ListingError(error)
    if operation in ("request_access", "access_status"):
        if set(reply) != {"status"} or reply["status"] not in ("pending", "active", "disabled", "denied", "removed"):
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
    access = topics.add_parser("access", help="Request and check a scoped token")
    commands = access.add_subparsers(required=True)
    enrollment = commands.add_parser("request", help="Read a new token or permission-change request from stdin")
    enrollment.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    enrollment.set_defaults(operation="request_access")
    status = commands.add_parser("status", help="Check this profile's token")
    status.add_argument("--json", action="store_true", required=True, help="Emit JSON")
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
    use = topics.add_parser("use", help="Use a credential through a configured action")
    use.add_argument("--vault", help="Scoped vault ID")
    use.add_argument("--entry", required=True, help="Entry UUID")
    use.add_argument("--action", required=True, help="Owner-configured action ID")
    use.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    use.set_defaults(operation="use_password")
    run = topics.add_parser("run", help="Use a Keeper credential with an approved isolated command")
    run.add_argument("--vault", help="Scoped vault ID")
    run.add_argument("--entry", required=True, help="Entry UUID")
    run.add_argument("--action", required=True, help="Approved command action ID")
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
        payload.update(entry=options.entry, action=options.action)
        if hasattr(options, "command"):
            payload["command"] = options.command
    elif getattr(options, "include_reviewed", False):
        payload["include_reviewed"] = True
    if options.operation == "edit_status":
        payload["id"] = options.request
    if getattr(options, "vault", None):
        payload["vault"] = options.vault
    if getattr(options, "field", None):
        payload["fields"] = list(dict.fromkeys(options.field))
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
        token_file = os.environ.get("KEEPASSXC_AGENT_TOKEN_FILE")
        if options.operation in ("request_access", "request_edit"):
            try:
                raw = sys.stdin.buffer.read(REQUEST_LIMIT)
                if len(raw) >= REQUEST_LIMIT:
                    raise ValueError
                submitted = decode(raw)
                payload["request"] = edit_request(submitted) if options.operation == "request_edit" else submitted
            except (ValueError, RecursionError):
                raise ListingError("invalid_request") from None
        if token_file or options.operation in (
            "request_access", "access_status", "list_vaults", "request_edit", "edit_status",
        ):
            scope = payload.get("request")
            create = options.operation == "request_access" and isinstance(scope, dict) and "change_id" not in scope
            payload["credential"] = credential(token_file, create=create)
        if len(encode(payload)) > REQUEST_LIMIT:
            raise ListingError("too_large")
        result = request(os.environ.get("KEEPASSXC_AGENT_SOCKET"), payload, input_data=input_data)
        sys.stdout.buffer.write(encode(result))
    except UninitializedProfile as error:
        if options.operation == "access_status":
            sys.stdout.buffer.write(encode({"status": "uninitialized"}))
            return 0
        print(error, file=sys.stderr)
        return 1
    except ListingError as error:
        print(error, file=sys.stderr)
        return 1
    return int(result.get("outcome") in ("failed", "uncertain"))


if __name__ == "__main__":
    raise SystemExit(main())
