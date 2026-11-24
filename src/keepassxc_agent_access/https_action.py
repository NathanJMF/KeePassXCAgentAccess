"""Credential delivery in the trusted worker over direct verified TLS."""

from base64 import b64encode
from contextlib import contextmanager
from http.client import HTTPException, HTTPSConnection
import json
from urllib.parse import urlencode
import re

from .access_settings import ActionType, Destination, HTTPS_WRITE_METHODS, credential_headers, request_query


SOCKET_TIMEOUT = 4
# RFC 6750 section 2.1 permits these characters in a Bearer authorization token.
BEARER_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+=*")


def failure():
    return {"outcome": "failed"}


@contextmanager
def prepare_https(url, *, query=()):
    destination = Destination.parse(url)
    connection = HTTPSConnection(destination.host, destination.port, timeout=SOCKET_TIMEOUT)
    try:
        connection.connect()
        connection.auto_open = False
        yield connection, destination.path + ("?" + urlencode(request_query(query)) if query else "")
    finally:
        connection.close()


def authenticate(connection, path, entry, kind=ActionType.BASIC, *, method="GET", request_json="", headers=()):
    password = entry.password
    if kind == ActionType.TEMPLATE:
        return authenticate_template(connection, path, entry, method=method, request_json=request_json, headers=headers)
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

    request_headers = dict(credential_headers(headers))
    if any(name.lower() == "authorization" for name in request_headers):
        return failure()
    request_headers["Authorization"] = authorization
    body = None
    if request_json:
        body = request_json.encode("utf-8")
        request_headers = {key: value for key, value in request_headers.items() if key.lower() != "content-type"}
        request_headers["Content-Type"] = "application/json"

    try:
        connection.request(method, path, body=body, headers=request_headers)
        with connection.getresponse() as response:
            status = response.status
    except (OSError, HTTPException, ValueError):
        status = None
    write = method in HTTPS_WRITE_METHODS
    if status is not None and (200 if write else 100) <= status <= 599:
        return {"outcome": "succeeded" if 200 <= status < 300 else "failed", "http_status": status}
    return {"outcome": "uncertain"} if write else failure()


def authenticate_template(connection, path, entry, *, method="GET", request_json="", headers=()):
    """Render references only inside the trusted worker, never in returned data."""
    password, username = entry.password, entry.username or ""
    if not isinstance(password, str) or not password or len(password.encode("utf-8")) > 65536:
        return failure()

    def render(value):
        if isinstance(value, str):
            return re.sub(r"\{\{(password|username)\}\}",
                          lambda match: password if match[1] == "password" else username, value)
        if isinstance(value, dict):
            return {key: render(item) for key, item in value.items()}
        if isinstance(value, list):
            return [render(item) for item in value]
        return value

    try:
        result_headers = {key: render(value) for key, value in credential_headers(headers)}
        if any(any(ord(char) < 32 or ord(char) == 127 for char in value) or len(value.encode("utf-8")) > 65536
               for value in result_headers.values()):
            return failure()
        if sum(len(name.encode("ascii")) + len(value.encode("utf-8")) for name, value in result_headers.items()) > 65536:
            return failure()
        body = None
        if request_json:
            body = json.dumps(render(json.loads(request_json)), ensure_ascii=False, allow_nan=False,
                              separators=(",", ":"), sort_keys=True).encode("utf-8")
            if len(body) > 131072:
                return failure()
            result_headers = {key: value for key, value in result_headers.items() if key.lower() != "content-type"}
            result_headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=result_headers)
        with connection.getresponse() as response:
            status = response.status
    except (OSError, HTTPException, ValueError, TypeError):
        status = None
    write = method in HTTPS_WRITE_METHODS
    if status is not None and (200 if write else 100) <= status <= 599:
        return {"outcome": "succeeded" if 200 <= status < 300 else "failed", "http_status": status}
    return {"outcome": "uncertain"} if write else failure()
