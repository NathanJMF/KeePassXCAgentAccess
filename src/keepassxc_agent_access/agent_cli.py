"""Agent-side command. This module needs only the Python standard library."""

import argparse
import os
import socket
import sys
from time import monotonic
from uuid import UUID

from .protocol import (
    ERRORS, LIST_REQUEST, ListingError, REQUEST_TIMEOUT, RESPONSE_LIMIT,
    decode, encode, receive, remaining,
)


def _validate(reply):
    if not isinstance(reply, dict):
        raise ListingError("invalid_response")
    if set(reply) == {"error"}:
        error = reply["error"]
        if isinstance(error, str) and error in ERRORS:
            raise ListingError(error)
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


def list_entries(endpoint):
    if not endpoint or not os.path.isabs(endpoint):
        raise ListingError()

    deadline = monotonic() + REQUEST_TIMEOUT
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(remaining(deadline))
            connection.connect(endpoint)
            connection.settimeout(remaining(deadline))
            connection.sendall(encode(LIST_REQUEST))
            response = receive(connection, RESPONSE_LIMIT, deadline)
    except (OSError, EOFError):
        raise ListingError() from None
    except ValueError:
        raise ListingError("invalid_response") from None
    try:
        return _validate(decode(response))
    except (ValueError, RecursionError):
        raise ListingError("invalid_response") from None


def main(argv=None):
    parser = argparse.ArgumentParser(prog="keepassxc-agent")
    topics = parser.add_subparsers(required=True)
    entries = topics.add_parser("entries", help="Read entry metadata")
    commands = entries.add_subparsers(required=True)
    listing = commands.add_parser("list", help="List entries in the owner's active vault")
    listing.add_argument("--json", action="store_true", required=True, help="Emit JSON")
    parser.parse_args(argv)

    try:
        result = list_entries(os.environ.get("KEEPASSXC_AGENT_SOCKET"))
        sys.stdout.buffer.write(encode(result))
    except ListingError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
