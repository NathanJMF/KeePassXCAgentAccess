"""Credential delivery in the trusted worker over direct verified TLS."""

from base64 import b64encode
from contextlib import contextmanager
from http.client import HTTPException, HTTPSConnection

from .access_settings import Destination


SOCKET_TIMEOUT = 4


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


def authenticate(connection, path, entry):
    username, password = entry.username or "", entry.password
    if not password or ":" in username or any(ord(c) < 32 or ord(c) == 127 for c in username + password):
        return failure()
    credential = b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    try:
        connection.request("GET", path, headers={"Authorization": f"Basic {credential}"})
        with connection.getresponse() as response:
            status = response.status
        if not 100 <= status <= 599:
            return failure()
        return {"outcome": "succeeded" if 200 <= status < 300 else "failed", "http_status": status}
    except (OSError, HTTPException, ValueError):
        return failure()
