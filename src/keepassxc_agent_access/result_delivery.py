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
from threading import Lock, Timer
from time import monotonic
from urllib.parse import quote, quote_plus, urlencode

from .account_provision import parse_provision, provision_body
from .access_settings import Destination, HTTPS_METHODS, HTTPS_WRITE_METHODS, credential_headers, request_query
from .command_network import approved_addresses
from .protocol import MAX_GUEST_TEXT


BODY_LIMIT = 256 * 1024
RESULT_LIMIT = 64 * 1024
MAX_ROWS = 256
MAX_COLUMNS = 16
WORKFLOW_SECONDS = 16
SOCKET_SECONDS = 4
GUEST_LOGIN_SECONDS = 60
GUEST_LOGIN_LIMIT = 32
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}")
_COLUMN = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}")
_REFERENCE = re.compile(r"\{\{(password|username|session\.[A-Za-z][A-Za-z0-9_]{0,31})\}\}")
_PRIVATE_COLUMNS = frozenset(("password", "passwd", "secret", "token", "ticket", "csrfpreventiontoken",
                              "authorization", "cookie", "setcookie", "session", "apikey", "privatekey",
                              "accesstoken", "refreshtoken", "csrftoken", "credential", "credentials"))
_PRIVATE_KEY_TOKENS = ("token", "secret", "ticket", "session", "cookie", "pass", "auth", "key")
_TRIVIAL_VALUES = frozenset(("/", "true", "false", "null", "none", "ok"))
_ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


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
    if not isinstance(data, dict) or not required <= data.keys() <= required | {"login", "certificate_sha256", "approve_write_once"} or data["type"] != "https_results":
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
    if "approve_write_once" in data:
        if data["approve_write_once"] is not True or method not in HTTPS_WRITE_METHODS:
            raise ValueError("One-time write approval requires an HTTPS write method.")
        result["approve_write_once"] = True
    body, _ = _body(request)  # Resource data cannot embed credential or session references.
    if body and method not in HTTPS_WRITE_METHODS:
        raise ValueError("This resource method does not accept a body.")
    headers = dict(credential_headers(request.get("headers", {})))
    if auth in ("basic", "bearer") and any(name.lower() == "authorization" for name in headers):
        raise ValueError("Basic and Bearer requests set Authorization automatically.")
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
    if (not isinstance(projection, dict) or set(projection) - {"path", "columns", "scalar"}
            or ("columns" in projection) == ("scalar" in projection)):
        raise ValueError("Choose a result path and scalar columns.")
    path = _pointer(projection.get("path", ""))
    scalar = "scalar" in projection
    columns = [projection["scalar"]] if scalar else projection["columns"]
    if (not isinstance(columns, list) or not 1 <= len(columns) <= MAX_COLUMNS
            or any(not isinstance(name, str) or not _COLUMN.fullmatch(name)
                   or re.sub(r"[_-]", "", name).lower() in _PRIVATE_COLUMNS for name in columns)
            or len(set(columns)) != len(columns)):
        raise ValueError("Choose unique noncredential scalar field names.")
    if scalar and any(re.sub(r"[_-]", "", key).lower() in _PRIVATE_COLUMNS for key in path.split("/")):
        raise ValueError("Named scalar results must come from a noncredential path.")
    result["result"] = {"path": path, **({"scalar": columns[0]} if scalar else {"columns": list(columns)})}
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
                "Return scalar fields: " + ", ".join(result_fields(data["result"])),
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


def result_fields(projection):
    return [projection["scalar"]] if "scalar" in projection else projection["columns"]


def _project(document, projection, forbidden, private_number=None, *, guest_output=False):
    rows = _select(document, projection["path"])
    if "scalar" in projection:
        rows = [{projection["scalar"]: rows}]
    elif isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("Use a bounded array of result objects.")
    result = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("The selected result is not an object.")
        item = {}
        for field in result_fields(projection):
            if guest_output and field not in row:
                continue
            value = row.get(field)
            if isinstance(value, str):
                if guest_output:
                    value = _ANSI_OSC.sub("", value)
                    value = _ANSI_CSI.sub("", value)
                    value = "".join(char for char in value if char.isprintable() or char in "\n\t\r")
                    if len(value) > MAX_GUEST_TEXT:
                        value = value[:MAX_GUEST_TEXT - 15] + "\n...[truncated]"
                elif not all(char.isprintable() or char in "\n\t\r" for char in value) or len(value) > 512:
                    raise ValueError("Only bounded text result fields may be returned.")
            if (type(value) not in (str, int, float, bool, type(None))
                    or isinstance(value, int) and not -(2**53) < value < 2**53
                    or isinstance(value, float) and not math.isfinite(value)):
                raise ValueError("Only bounded scalar result fields may be returned.")
            if private_number is not None and (type(value) in (int, float) and value == private_number
                    or isinstance(value, str) and re.search(rf"(?<![0-9]){private_number}(?![0-9])", value)):
                raise ValueError("The projected result contains a private job identifier.")
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
        addresses = approved_addresses(target.host)
        def create_socket(_target, timeout, source_address=None):
            last_error = None
            for address in addresses:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise TimeoutError
                try:
                    return socket.create_connection((str(address), target.port),
                                                    timeout=min(timeout, remaining), source_address=source_address)
                except OSError as error:
                    last_error = error
            raise last_error
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


def _http(origin, pin, deadline, method, path, headers, body, dispatch, private_headers=None, observed=None):
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
            if observed is not None:
                observed(status)
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


def _is_private_key(key):
    if not isinstance(key, str):
        return False
    normalized = re.sub(r"[_-]", "", key).lower()
    return normalized in _PRIVATE_COLUMNS or any(word in normalized for word in _PRIVATE_KEY_TOKENS)


def _is_secret_candidate(value, key):
    if _is_private_key(key):
        return True
    if len(value) < 8:
        return False
    lowered = value.strip().lower()
    if lowered in _TRIVIAL_VALUES or re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", lowered):
        return False
    return True


def _private_strings(document):
    result = []
    total = 0
    def visit(value, key=None):
        nonlocal total
        if isinstance(value, str) and value:
            if not _is_secret_candidate(value, key):
                return
            encoded_len = len(value.encode("utf-8"))
            if encoded_len > 4096 or len(result) >= 128:
                raise ValueError("The private authentication response exceeds the limit.")
            total += encoded_len
            if total > 65536:
                raise ValueError("The private authentication response exceeds the limit.")
            result.append(value)
        elif isinstance(value, dict):
            for child_key, item in value.items():
                visit(item, child_key)
        elif isinstance(value, list):
            for item in value:
                visit(item, key)
    visit(document)
    return result


class GuestLoginCache:
    """Private, non-sliding cache for sign-ins tied to a single guest job."""

    def __init__(self):
        self._lock = Lock()
        self._sessions = {}

    def get(self, key, signature):
        with self._lock:
            saved = self._sessions.get(key)
            if saved and saved[0] == signature and monotonic() < saved[1]:
                return saved[1:4]
        return None

    def forget(self, key, timer=None):
        with self._lock:
            saved = self._sessions.get(key)
            if saved and (timer is None or saved[-1] is timer):
                self._sessions.pop(key)[-1].cancel()

    def put(self, key, signature, stop, captured, forbidden):
        expires = min(stop, monotonic() + GUEST_LOGIN_SECONDS)
        if expires <= monotonic():
            return
        with self._lock:
            if key in self._sessions or len(self._sessions) >= GUEST_LOGIN_LIMIT:
                return
            timer = Timer(max(0, expires - monotonic()), lambda: self.forget(key, timer))
            timer.daemon = True
            self._sessions[key] = (signature, expires, dict(captured), tuple(forbidden), timer)
            timer.start()


def deliver_results(config, entry, dispatch, *, allow_username=False, private_result=None,
                    login_context=None, login_cache=None, provision=None, account=None):
    """Release only the concrete approved projection; dispatch gates every send."""
    sent_write = False
    write_status = None
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
        private_number = None
        if type(private_result) is int and 1 <= private_result < 2**53:
            private_number = private_result
        elif private_result is not None:
            if not isinstance(private_result, str) or not 16 <= len(private_result) <= 64:
                raise ValueError("Invalid private result value.")
            forbidden.append(private_result)
        if username and not allow_username:
            forbidden.append(username)
        deadline = monotonic() + WORKFLOW_SECONDS
        pin = data.get("certificate_sha256")
        request = data["request"]
        if provision is not None:
            if account is None or login_context is not None:
                raise ValueError("The approved account is unavailable.")
            provision = parse_provision(provision, data)
        cached = None
        signature = None
        if login_context and login_cache is not None and "login" in data:
            signature = _json([data["origin"], pin or "ca", data["login"], allow_username])
            if request["method"] == "GET" and login_context["reuse"]:
                cached = login_cache.get(login_context["key"], signature)
        new_capture = None
        if cached:
            cached_until, session, private_fields = cached
            deadline = min(deadline, cached_until)
            values.update(session)
            forbidden.extend(private_fields)
        elif "login" in data:
            login = data["login"]
            headers, body = _request_body(login, values)
            private_fields = [body.decode("ascii")]
            status, document = _http(data["origin"], pin, deadline, "POST", login["path"], headers, body, dispatch, private_fields)
            if not 200 <= status < 300:
                return {"outcome": "failed", "http_status": status}
            private_fields.extend(value for value in _private_strings(document) if not allow_username or value != username)
            session = {}
            for key, pointer in login["capture"].items():
                value = _select(document, pointer)
                if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096 or not value.isprintable():
                    raise ValueError("The private authentication response is invalid.")
                session["session." + key] = value
                private_fields.append(value)
            values.update(session)
            forbidden.extend(private_fields)
            if signature is not None:
                new_capture = (session, private_fields)
        raw_headers = request.get("headers", {})
        headers = dict(_render(raw_headers, values))
        rendered_auth_headers = [
            headers[name] for name, template in raw_headers.items() if _REFERENCE.search(template)
        ]
        if request["auth"] == "basic":
            if any(name.lower() == "authorization" for name in headers):
                raise ValueError("Basic requests set Authorization automatically.")
            if ":" in username or any(ord(char) < 32 or ord(char) == 127 for char in username + password):
                raise ValueError("Invalid Basic credential.")
            authorization = "Basic " + b64encode((username + ":" + password).encode("utf-8")).decode("ascii")
            headers["Authorization"] = authorization
            rendered_auth_headers.extend((authorization, authorization.partition(" ")[2]))
        elif request["auth"] == "bearer":
            if any(name.lower() == "authorization" for name in headers):
                raise ValueError("Bearer requests set Authorization automatically.")
            if not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", password):
                raise ValueError("Invalid Bearer credential.")
            authorization = "Bearer " + password
            headers["Authorization"] = authorization
            rendered_auth_headers.append(authorization)
        if any(any(ord(char) < 32 or ord(char) == 127 for char in value)
               or len(value.encode("utf-8")) > 16384 for value in headers.values()):
            raise ValueError("Invalid rendered authentication header.")
        forbidden.extend(rendered_auth_headers)
        if provision is None:
            body_headers, body = _request_body(request, values)
        else:
            body_headers, body = provision_body(request, provision, account, forbidden)
        for name, value in body_headers.items():
            headers = {key: item for key, item in headers.items() if key.lower() != name.lower()}
            headers[name] = value
        path = request["path"] + ("?" + urlencode(request["query"]) if request.get("query") else "")
        def gate():
            nonlocal sent_write
            if cached and monotonic() >= cached_until:
                return False
            permitted = dispatch()
            if permitted and request["method"] in HTTPS_WRITE_METHODS:
                sent_write = True
            return permitted

        def observe(status):
            nonlocal write_status
            if sent_write:
                write_status = status

        status, document = _http(data["origin"], pin, deadline, request["method"], path, headers, body, gate, forbidden, observe)
        if not 200 <= status < 300:
            if cached and status in (401, 403):
                login_cache.forget(login_context["key"])
            return {"outcome": "failed", "http_status": status}
        projected = _project(document, data["result"], forbidden, private_number, guest_output=private_result is not None)
        if new_capture:
            login_cache.put(login_context["key"], signature, login_context["expires"], *new_capture)
        return {"outcome": "succeeded", "http_status": status, "data": projected}
    except (OSError, HTTPException, ValueError, KeyError, IndexError, TypeError, AttributeError, RecursionError):
        if write_status is not None:
            outcome = "acknowledged" if 200 <= write_status < 300 else "failed"
            return {"outcome": outcome, "http_status": write_status}
        return {"outcome": "uncertain" if sent_write else "failed"}
