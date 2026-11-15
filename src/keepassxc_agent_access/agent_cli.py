"""Agent-side command. This module needs only the Python standard library."""

import argparse
import os
import socket
import sys
from time import monotonic
from uuid import UUID

from .protocol import (
    CLIENT_TIMEOUT, ERRORS, LIST_REQUEST, ListingError, REQUEST_TIMEOUT, RESPONSE_LIMIT,
    decode, encode, receive, remaining,
)


def _validate(reply, operation):
    if not isinstance(reply, dict):
        raise ListingError("invalid_response")
    if set(reply) == {"error"}:
        error = reply["error"]
        if isinstance(error, str) and error in ERRORS:
            raise ListingError(error)
    if operation == "use_password":
        status = reply.get("http_status")
        if (
            "outcome" not in reply or set(reply) - {"outcome", "http_status"}
            or reply["outcome"] not in ("succeeded", "failed")
            or ("http_status" in reply and (type(status) is not int or not 100 <= status <= 599))
            or (reply["outcome"] == "succeeded" and (status is None or not 200 <= status < 300))
        ):
            raise ListingError("invalid_response")
        return reply
    if set(reply) != {"entries"} or not isinstance(reply["entries"], list):
        raise ListingError("invalid_response")
    for row in reply["entries"]:
        if (
            not isinstance(row, dict)
            or set(row) != {"id", "title", "group_path"}
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


def request(endpoint, payload):
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
    except (OSError, EOFError):
        raise ListingError() from None
    except ValueError:
        raise ListingError("invalid_response") from None
    try:
        return _validate(decode(response), payload["operation"])
    except (ValueError, RecursionError):
        raise ListingError("invalid_response") from None


def list_entries(endpoint):
    return request(endpoint, LIST_REQUEST)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="keepassxc-agent")
    topics = parser.add_subparsers(required=True)
    entries = topics.add_parser("entries", help="Read entry metadata")
    commands = entries.add_subparsers(required=True)
    listing = commands.add_parser("list", help="List entries in the owner's active vault")
    listing.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    listing.add_argument("--include-reviewed", action="store_true", help="Request protected rows in Smart access")
    listing.set_defaults(operation="list_entries")
    use = topics.add_parser("use", help="Use a credential through a configured action")
    use.add_argument("--entry", required=True, help="Entry UUID")
    use.add_argument("--action", required=True, help="Owner-configured action ID")
    use.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    use.set_defaults(operation="use_password")
    options = parser.parse_args(argv)
    payload = {"version": 1, "operation": options.operation}
    if options.operation == "use_password":
        payload.update(entry=options.entry, action=options.action)
    elif options.include_reviewed:
        payload["include_reviewed"] = True
    context = {}
    for key in ("model", "chat", "chat_id"):
        raw = os.environ.get(f"KEEPASSXC_AGENT_{key.upper()}", "")
        value = "".join(char for char in raw[:640] if char.isprintable()).strip()[:160]
        if value:
            context[key] = value
    if context:
        payload["context"] = context

    try:
        result = request(os.environ.get("KEEPASSXC_AGENT_SOCKET"), payload)
        sys.stdout.buffer.write(encode(result))
    except ListingError as error:
        print(error, file=sys.stderr)
        return 1
    return int(result.get("outcome") == "failed")


if __name__ == "__main__":
    raise SystemExit(main())
