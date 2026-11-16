"""Credential delivery in the trusted worker over direct verified TLS."""

from base64 import b64encode
from contextlib import contextmanager
from http.client import HTTPException, HTTPSConnection
import re

from .access_settings import ActionType, Destination, HTTPS_WRITE_METHODS


SOCKET_TIMEOUT = 4
# RFC 6750 section 2.1 permits these characters in a Bearer authorization token.
BEARER_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+=*")


def failure():
    return {"outcome": "failed"}


@contextmanager
def prepare_https(url):
    destination = Destination.parse(url)
    connection = HTTPSConnection(destination.host, destination.port, timeout=SOCKET_TIMEOUT)
    try:
        connection.connect()
        connection.auto_open = False
        yield connection, destination.path
    finally:
        connection.close()


def authenticate(connection, path, entry, kind=ActionType.BASIC, *, method="GET", request_json=""):
    password = entry.password
    if kind == ActionType.BEARER:
        if not isinstance(password, str) or not BEARER_TOKEN.fullmatch(password):
            return failure()
        authorization = f"Bearer {password}"
    elif kind == ActionType.BASIC:
        username = entry.username or ""
        if not password or ":" in username or any(ord(c) < 32 or ord(c) == 127 for c in username + password):
            return failure()
        credential = b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        authorization = f"Basic {credential}"
    else:
        return failure()

    headers = {"Authorization": authorization}
    body = None
    if request_json:
        body = request_json.encode("utf-8")
        headers["Content-Type"] = "application/json"

    try:
        connection.request(method, path, body=body, headers=headers)
        with connection.getresponse() as response:
            status = response.status
    except (OSError, HTTPException, ValueError):
        status = None
    write = method in HTTPS_WRITE_METHODS
    if status is not None and (200 if write else 100) <= status <= 599:
        return {"outcome": "succeeded" if 200 <= status < 300 else "failed", "http_status": status}
    return {"outcome": "uncertain"} if write else failure()
