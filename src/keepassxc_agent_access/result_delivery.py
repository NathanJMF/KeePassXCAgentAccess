"""Projected HTTPS results with private, one-use authentication exchanges.

The approved service supplies the selected fields.  Secret scanning is a final
check, not a proof that a malicious service cannot encode its credentials.
"""

from base64 import b64encode, urlsafe_b64encode
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from http.client import HTTPException, HTTPSConnection
import json
import math
import re
import socket
import ssl
from threading import Timer
from time import monotonic
from urllib.parse import quote, quote_plus, urlencode

from .access_settings import Destination, HTTPS_METHODS, HTTPS_WRITE_METHODS, credential_headers, request_query
from .command_network import approved_address


BODY_LIMIT = 256 * 1024
RESULT_LIMIT = 64 * 1024
MAX_ROWS = 256
MAX_COLUMNS = 16
WORKFLOW_SECONDS = 16
SOCKET_SECONDS = 4
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}")
_COLUMN = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}")
_REFERENCE = re.compile(r"\{\{(password|username|session\.[A-Za-z][A-Za-z0-9_]{0,31})\}\}")
_PRIVATE_COLUMNS = frozenset(("password", "passwd", "secret", "token", "ticket", "csrfpreventiontoken",
                              "authorization", "cookie", "setcookie", "session", "apikey", "privatekey",
                              "accesstoken", "refreshtoken", "csrftoken", "credential", "credentials"))


def _json(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _depth(value, depth=0):
    if depth > 24:
        raise ValueError("JSON nesting limit")
    if isinstance(value, dict):
        for item in value.values():
            _depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Nonfinite JSON")


def _decode(value):
    result = json.loads(value, object_pairs_hook=_unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("JSON constant")))
    _depth(result)
    return result


def _pointer(value):
    if not isinstance(value, str) or len(value) > 256 or value and (not value.startswith("/") or not value.isprintable()):
        raise ValueError("Use a short JSON pointer.")
    parts = value.split("/")[1:] if value else []
    if len(parts) > 16 or any(re.search(r"~(?![01])", part) for part in parts):
        raise ValueError("Use a valid JSON pointer.")
    return value


def _select(document, pointer):
    current = document
    for part in _pointer(pointer).split("/")[1:] if pointer else ():
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current[part]
        elif isinstance(current, list) and re.fullmatch(r"0|[1-9][0-9]*", part):
            current = current[int(part)]
        else:
            raise ValueError("The result path is unavailable.")
    return current


def _path(value):
    if (not isinstance(value, str) or not re.fullmatch(r"/[!-~]{0,2047}", value)
            or value.startswith("//") or any(mark in value for mark in ("?", "#", "\\", "{{", "}}"))):
        raise ValueError("Use a root-relative resource path without a query or credential.")
    return value


def _references(value, allowed):
    if isinstance(value, str):
        references = set(_REFERENCE.findall(value))
        rest = _REFERENCE.sub("", value)
        if not references <= allowed or "{{" in rest or "}}" in rest:
            raise ValueError("Unsupported credential reference.")
        return references
    if isinstance(value, dict):
        result = set()
        for key, item in value.items():
            if not isinstance(key, str) or "{{" in key or "}}" in key:
                raise ValueError("Credential references belong in values.")
            result.update(_references(item, allowed))
        return result
    if isinstance(value, list):
        result = set()
        for item in value:
            result.update(_references(item, allowed))
        return result
    return set()


def _body(data, *, allowed=()):
    if "form" in data and "json" in data:
        raise ValueError("Use either JSON or form values.")
    if "form" in data:
        form = data["form"]
        if (not isinstance(form, dict) or len(form) > 16
                or any(not isinstance(key, str) or not key or not key.isprintable()
                       or not isinstance(value, str) or not value.isprintable() for key, value in form.items())
                or len(urlencode(form).encode("ascii")) > 2048):
            raise ValueError("Use a small printable form map.")
        return {"form": dict(form)}, _references(form, set(allowed))
    if "json" in data:
        body = _decode(data["json"]) if isinstance(data["json"], str) else data["json"]
        _depth(body)
        if not isinstance(body, dict) or len(_json(body).encode("ascii")) > 2048:
            raise ValueError("Use a small JSON object.")
        return {"json": body}, _references(body, set(allowed))
    return {}, set()


def parse_result_usage(data):
    """Freeze a strict wire request; this is also re-run inside the worker."""
    required = {"type", "origin", "request", "result"}
    if not isinstance(data, dict) or not required <= data.keys() <= required | {"login", "certificate_sha256"} or data["type"] != "https_results":
        raise ValueError("Use a protected HTTPS result request.")
    origin = Destination.parse(data["origin"])
    if origin.path != "/":
        raise ValueError("Use an HTTPS origin without a resource path.")
    result = {"type": "https_results", "origin": origin.url}
    if "certificate_sha256" in data:
        pin = data["certificate_sha256"]
        if not isinstance(pin, str) or not re.fullmatch(r"[a-f0-9]{64}", pin):
            raise ValueError("Use a lowercase SHA-256 certificate fingerprint.")
        result["certificate_sha256"] = pin
    session_refs = set()
    if "login" in data:
        login = data["login"]
        if (not isinstance(login, dict) or not {"path", "capture"} <= login.keys() <= {"path", "capture", "method", "form", "json"}
                or login.get("method", "POST") != "POST"):
            raise ValueError("Use a private POST authentication exchange.")
        body, refs = _body(login, allowed={"password", "username"})
        capture = login["capture"]
        if not body or "password" not in refs or not isinstance(capture, dict) or not 1 <= len(capture) <= 4:
            raise ValueError("The private login needs a password reference and named captures.")
        for key, pointer in capture.items():
            if not isinstance(key, str) or not _NAME.fullmatch(key):
                raise ValueError("Use short private capture names.")
            _pointer(pointer)
        result["login"] = {"path": _path(login["path"]), "method": "POST", **body, "capture": dict(capture)}
        session_refs = {"session." + key for key in capture}
    request = data["request"]
    if (not isinstance(request, dict) or not {"path", "auth"} <= request.keys() <= {"path", "auth", "method", "headers", "query", "json", "form"}
            or request.get("method", "GET") not in HTTPS_METHODS or request["auth"] not in ("basic", "bearer", "template", "session")):
        raise ValueError("Use an HTTPS resource request and authentication method.")
    method, auth = request.get("method", "GET"), request["auth"]
    body, _ = _body(request)  # Resource data cannot embed credential or session references.
    if body and method not in HTTPS_WRITE_METHODS:
        raise ValueError("This resource method does not accept a body.")
    headers = dict(credential_headers(request.get("headers", {})))
    if auth in ("basic", "bearer") and headers:
        raise ValueError("Use template or session authentication for custom headers.")
    allowed = session_refs if auth == "session" else {"password", "username"} if auth == "template" else set()
    refs = _references(headers, allowed)
    if auth == "session" and (not session_refs or not refs) or auth == "template" and "password" not in refs:
        raise ValueError("The resource authentication must use its private credential.")
    query = dict(request_query(request.get("query", {})))
    _references(query, set())
    result["request"] = {"path": _path(request["path"]), "method": method, "auth": auth, **body}
    if headers:
        result["request"]["headers"] = headers
    if query:
        result["request"]["query"] = query
    projection = data["result"]
    if not isinstance(projection, dict) or not {"columns"} <= projection.keys() <= {"path", "columns"}:
        raise ValueError("Choose a result path and scalar columns.")
    columns = projection["columns"]
    if (not isinstance(columns, list) or not 1 <= len(columns) <= MAX_COLUMNS
            or any(not isinstance(name, str) or not _COLUMN.fullmatch(name)
                   or re.sub(r"[_-]", "", name).lower() in _PRIVATE_COLUMNS for name in columns)
            or len(set(columns)) != len(columns)):
        raise ValueError("Choose unique noncredential scalar field names.")
    result["result"] = {"path": _pointer(projection.get("path", "")), "columns": list(columns)}
    canonical = _json(result)
    if len(canonical.encode("ascii")) > 4096:
        raise ValueError("The protected result request exceeds the limit.")
    return ResultRequest(canonical)


@dataclass(frozen=True)
class ResultRequest:
    canonical_json: str

    @property
    def data(self):
        return _decode(self.canonical_json)

    @property
    def origin(self):
        return self.data["origin"]

    @property
    def summary(self):
        return "Protected result request · SHA-256 " + sha256(self.canonical_json.encode("ascii")).hexdigest()

    @property
    def description(self):
        data = self.data
        login = data.get("login")
        return (self.origin,
                *(("Certificate SHA-256: " + data["certificate_sha256"],) if data.get("certificate_sha256") else ()),
                *(('Private POST ' + login["path"] + ' · authentication response stays in Keeper',) if login else ()),
                data["request"]["method"] + " " + data["request"]["path"],
                "Return scalar fields: " + ", ".join(data["result"]["columns"]),
                "Approved endpoint supplies these fields. Credentials and private captures are excluded.")


def _render(value, values):
    if isinstance(value, str):
        return _REFERENCE.sub(lambda match: values[match[1]], value)
    if isinstance(value, dict):
        return {key: _render(item, values) for key, item in value.items()}
    if isinstance(value, list):
        return [_render(item, values) for item in value]
    return value


def _variants(values):
    result = set()
    for value in values:
        if not isinstance(value, str) or not value:
            continue
        raw = value.encode("utf-8")
        result.update((value, _json(value)[1:-1], quote(value, safe=""), quote_plus(value, safe=""),
                       b64encode(raw).decode("ascii"), urlsafe_b64encode(raw).decode("ascii"),
                       raw.hex(), raw.hex().upper()))
    return result


def _project(document, projection, forbidden):
    rows = _select(document, projection["path"])
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("Use a bounded array of result objects.")
    result = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("The selected result is not an object.")
        item = {}
        for field in projection["columns"]:
            value = row.get(field)
            if (type(value) not in (str, int, float, bool, type(None))
                    or isinstance(value, str) and (len(value) > 512 or not value.isprintable())
                    or isinstance(value, int) and not -(2**53) < value < 2**53
                    or isinstance(value, float) and not math.isfinite(value)):
                raise ValueError("Only bounded scalar result fields may be returned.")
            item[field] = value
        result.append(item)
    encoded = _json(result)
    if len(encoded.encode("ascii")) > RESULT_LIMIT or any(value in encoded for value in _variants(forbidden)):
        raise ValueError("The projected result is private or too large.")
    return result


def _close(connection):
    try:
        if connection.sock is not None:
            connection.sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    connection.close()


@contextmanager
def _connection(origin, pin, deadline):
    target = Destination.parse(origin)
    context = None
    if pin:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    connection = HTTPSConnection(target.host, target.port, context=context,
                                 timeout=max(.001, min(SOCKET_SECONDS, deadline - monotonic())))
    sockets = []
    def expire():
        for active in tuple(sockets):
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        _close(connection)
    timer = Timer(max(.001, deadline - monotonic()), expire)
    timer.daemon = True
    timer.start()
    try:
        # Resolve in a bounded helper rather than the platform's potentially
        # unbounded getaddrinfo. TLS still validates the original authority.
        address = approved_address(target.host)
        def create_socket(_target, timeout, source_address=None):
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError
            return socket.create_connection((str(address), target.port),
                                            timeout=min(timeout, remaining), source_address=source_address)
        connection._create_connection = create_socket
        connection.connect()
        if monotonic() >= deadline or connection.sock is None:
            raise TimeoutError
        sockets.append(connection.sock)
        connection.auto_open = False
        if pin and sha256(connection.sock.getpeercert(binary_form=True)).hexdigest() != pin:
            raise ValueError("The approved certificate changed.")
        yield connection
    finally:
        timer.cancel()
        _close(connection)


def _http(origin, pin, deadline, method, path, headers, body, dispatch, private_headers=None):
    if monotonic() >= deadline:
        raise TimeoutError
    with _connection(origin, pin, deadline) as connection:
        if monotonic() >= deadline or not dispatch():
            raise PermissionError("Authorization changed or expired.")
        if monotonic() >= deadline:
            raise TimeoutError
        connection.request(method, path, body=body, headers=headers)
        with connection.getresponse() as response:
            status = response.status
            if private_headers is not None:
                private_count = 0
                private_size = 0
                for name, value in response.getheaders():
                    if name.lower() in ("set-cookie", "authorization", "authentication-info", "x-auth-token", "x-csrf-token"):
                        private_count += 1
                        private_size += len(value)
                        if private_count > 16 or private_size > 16384:
                            raise ValueError("The private response headers exceed the limit.")
                        private_headers.append(value)
                        if name.lower() == "set-cookie":
                            pair = value.split(";", 1)[0]
                            if "=" in pair:
                                private_headers.append(pair.split("=", 1)[1])
            if not 200 <= status < 300:
                return status, None
            raw = bytearray()
            while True:
                if monotonic() >= deadline:
                    raise TimeoutError
                chunk = response.read1(min(16384, BODY_LIMIT + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > BODY_LIMIT:
                    raise ValueError("The result body exceeds the limit.")
            return status, _decode(bytes(raw).decode("utf-8"))


def _request_body(data, values):
    headers = {}
    body = None
    if "form" in data:
        body = urlencode(_render(data["form"], values)).encode("ascii")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif "json" in data:
        body = _json(_render(data["json"], values)).encode("ascii")
        headers["Content-Type"] = "application/json"
    if body is not None and len(body) > 65536:
        raise ValueError("The rendered request body exceeds the limit.")
    return headers, body


def _private_strings(document):
    result = []
    total = 0
    def visit(value):
        nonlocal total
        if isinstance(value, str) and value:
            if len(value.encode("utf-8")) > 4096 or len(result) >= 128:
                raise ValueError("The private authentication response exceeds the limit.")
            total += len(value.encode("utf-8"))
            if total > 65536:
                raise ValueError("The private authentication response exceeds the limit.")
            result.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(document)
    return result


def deliver_results(config, entry, dispatch, *, allow_username=False):
    """Release only the concrete approved projection; dispatch gates every send."""
    sent_write = False
    try:
        config = parse_result_usage(config.data if isinstance(config, ResultRequest) else config)
        data = config.data
        password, username = entry.password, entry.username or ""
        if type(allow_username) is not bool:
            return {"outcome": "failed"}
        if not isinstance(password, str) or not password or len(password.encode("utf-8")) > 65536:
            return {"outcome": "failed"}
        values = {"password": password, "username": username}
        forbidden = [password, username + ":" + password]
        if username and not allow_username:
            forbidden.append(username)
        deadline = monotonic() + WORKFLOW_SECONDS
        pin = data.get("certificate_sha256")
        if "login" in data:
            login = data["login"]
            headers, body = _request_body(login, values)
            forbidden.append(body.decode("ascii"))
            status, document = _http(data["origin"], pin, deadline, "POST", login["path"], headers, body, dispatch, forbidden)
            if not 200 <= status < 300:
                return {"outcome": "failed", "http_status": status}
            forbidden.extend(value for value in _private_strings(document)
                             if not allow_username or value != username)
            for key, pointer in login["capture"].items():
                value = _select(document, pointer)
                if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096 or not value.isprintable():
                    raise ValueError("The private authentication response is invalid.")
                values["session." + key] = value
                forbidden.append(value)
        request = data["request"]
        headers = dict(_render(request.get("headers", {}), values))
        if request["auth"] == "basic":
            if ":" in username or any(ord(char) < 32 or ord(char) == 127 for char in username + password):
                raise ValueError("Invalid Basic credential.")
            authorization = "Basic " + b64encode((username + ":" + password).encode("utf-8")).decode("ascii")
            headers["Authorization"] = authorization
            forbidden.extend((authorization, authorization.partition(" ")[2]))
        elif request["auth"] == "bearer":
            if not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", password):
                raise ValueError("Invalid Bearer credential.")
            headers["Authorization"] = "Bearer " + password
        if any(any(ord(char) < 32 or ord(char) == 127 for char in value)
               or len(value.encode("utf-8")) > 16384 for value in headers.values()):
            raise ValueError("Invalid rendered authentication header.")
        forbidden.extend(headers.values())
        body_headers, body = _request_body(request, values)
        for name, value in body_headers.items():
            headers = {key: item for key, item in headers.items() if key.lower() != name.lower()}
            headers[name] = value
        path = request["path"] + ("?" + urlencode(request["query"]) if request.get("query") else "")
        def gate():
            nonlocal sent_write
            permitted = dispatch()
            if permitted and request["method"] in HTTPS_WRITE_METHODS:
                sent_write = True
            return permitted
        status, document = _http(data["origin"], pin, deadline, request["method"], path, headers, body, gate, forbidden)
        if not 200 <= status < 300:
            return {"outcome": "failed", "http_status": status}
        projected = _project(document, data["result"], forbidden)
        return {"outcome": "succeeded", "http_status": status, "data": projected}
    except (OSError, HTTPException, ValueError, KeyError, IndexError, TypeError, AttributeError, RecursionError):
        return {"outcome": "uncertain" if sent_write else "failed"}
