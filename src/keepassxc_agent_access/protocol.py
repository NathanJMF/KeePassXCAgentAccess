"""The one-request JSON protocol used by the entry-listing CLI."""

import json
from time import monotonic


REQUEST_LIMIT = 4 * 1024
RESPONSE_LIMIT = 1024 * 1024
REQUEST_TIMEOUT = 5
WORKER_TIMEOUT = 3
APPROVAL_TIMEOUT = 60
CLIENT_TIMEOUT = APPROVAL_TIMEOUT + 20
LIST_REQUEST = {"version": 1, "operation": "list_entries"}
ERRORS = {
    "unavailable": "Agent access is unavailable. Ask the vault owner to check broker access.",
    "invalid_request": "The broker rejected the listing request.",
    "invalid_response": "The broker returned an invalid listing response.",
    "declined": "The owner declined the request.",
    "expired": "The approval request timed out.",
    "revoked": "Agent access changed before the request completed.",
    "busy": "The broker is busy.",
    "ineligible": "The requested action or entry is unavailable.",
    "audit_unavailable": "The broker could not verify settings or record the decision.",
    "too_large": "The vault listing exceeds the response size limit.",
}


class ListingError(Exception):
    def __init__(self, code="unavailable"):
        self.code = code
        super().__init__(ERRORS[code])


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
