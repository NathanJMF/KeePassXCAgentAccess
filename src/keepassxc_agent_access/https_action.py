"""Credential delivery in the trusted worker over direct verified TLS."""

from base64 import b64encode
from contextlib import contextmanager
from http.client import HTTPException, HTTPSConnection
import re

from .access_settings import ActionType, Destination


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


def authenticate(connection, path, entry, kind=ActionType.BASIC):
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

    try:
        connection.request("GET", path, headers={"Authorization": authorization})
        with connection.getresponse() as response:
            status = response.status
        if not 100 <= status <= 599:
            return failure()
        return {"outcome": "succeeded" if 200 <= status < 300 else "failed", "http_status": status}
    except (OSError, HTTPException, ValueError):
        return failure()
