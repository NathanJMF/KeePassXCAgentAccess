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
import zlib

from .account_provision import parse_provision, provision_body
from .access_settings import Destination, HTTPS_METHODS, HTTPS_WRITE_METHODS, credential_headers, request_query
from .command_network import approved_addresses
from .protocol import MAX_GUEST_TEXT
from .totp import entry_custom_attr, entry_totp, otp_uri_secret


BODY_LIMIT = 2 * 1024 * 1024
RESULT_LIMIT = 256 * 1024
MAX_ROWS = 512
MAX_COLUMNS = 32
WORKFLOW_SECONDS = 45
SOCKET_SECONDS = 15
GUEST_LOGIN_SECONDS = 60
GUEST_LOGIN_LIMIT = 32
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}")
_COLUMN = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_HEADER_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
_SAFE_HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,64}")
_REFERENCE = re.compile(r"\{\{(password|username|totp|attr\.[A-Za-z0-9_.-]{1,64}|session\.[A-Za-z][A-Za-z0-9_]{0,31})\}\}")
_CREDENTIAL_ATTR_RESERVED = frozenset(("attr.otp",))
_PRIVATE_COLUMNS = frozenset(("password", "passwd", "secret", "token", "ticket", "csrfpreventiontoken",
                              "authorization", "cookie", "setcookie", "session", "apikey", "privatekey",
                              "accesstoken", "refreshtoken", "csrftoken", "credential", "credentials"))
_PRIVATE_RESPONSE_HEADERS = frozenset(("set-cookie", "authorization", "authentication-info", "x-auth-token", "x-csrf-token"))
_FORBIDDEN_RESULT_HEADERS = _PRIVATE_RESPONSE_HEADERS | frozenset(("proxy-authenticate", "www-authenticate", "cookie"))
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


def _is_allowed_ref(ref, allowed, allow_attrs):
    if ref in allowed:
        return True
    return allow_attrs and ref.startswith("attr.") and ref not in _CREDENTIAL_ATTR_RESERVED


def _has_credential_ref(refs):
    return any(ref in ("password", "totp") or ref.startswith("attr.") for ref in refs)


def _references(value, allowed, *, allow_attrs=False):
    if isinstance(value, str):
        references = set(_REFERENCE.findall(value))
        rest = _REFERENCE.sub("", value)
        if any(not _is_allowed_ref(ref, allowed, allow_attrs) for ref in references) or "{{" in rest or "}}" in rest:
            raise ValueError("Unsupported credential reference.")
        return references
    if isinstance(value, dict):
        result = set()
        for key, item in value.items():
            if not isinstance(key, str) or "{{" in key or "}}" in key:
                raise ValueError("Credential references belong in values.")
            result.update(_references(item, allowed, allow_attrs=allow_attrs))
        return result
    if isinstance(value, list):
        result = set()
        for item in value:
            result.update(_references(item, allowed, allow_attrs=allow_attrs))
        return result
    return set()


def _capture_target(value):
    """Validate a login capture target: JSON pointer, header:<Name>, or cookie:<Name>."""
    if not isinstance(value, str):
        raise ValueError("Use a JSON pointer, header:<name>, or cookie:<name> capture target.")
    if value.startswith("header:"):
        if not _HEADER_TOKEN.fullmatch(value[7:]):
            raise ValueError("Use a valid header capture name.")
        return value
    if value.startswith("cookie:"):
        if not _HEADER_TOKEN.fullmatch(value[7:]):
            raise ValueError("Use a valid cookie capture name.")
        return value
    return _pointer(value)


def _valid_column(name):
    """Return True when name is a valid non-private column or dot-path."""
    if not isinstance(name, str) or not _COLUMN.fullmatch(name):
        return False
    return all(segment and re.sub(r"[_-]", "", segment).lower() not in _PRIVATE_COLUMNS
               for segment in name.split("."))


def _body(data, *, allowed=(), allow_attrs=False):
    if "form" in data and "json" in data:
        raise ValueError("Use either JSON or form values.")
    if "form" in data:
        form = data["form"]
        if (not isinstance(form, dict) or len(form) > 16
                or any(not isinstance(key, str) or not key or not key.isprintable()
                       or not isinstance(value, str) or not value.isprintable() for key, value in form.items())
                or len(urlencode(form).encode("ascii")) > 65536):
            raise ValueError("Use a small printable form map.")
        return {"form": dict(form)}, _references(form, set(allowed), allow_attrs=allow_attrs)
    if "json" in data:
        body = _decode(data["json"]) if isinstance(data["json"], str) else data["json"]
        _depth(body)
        if not isinstance(body, dict) or len(_json(body).encode("ascii")) > 65536:
            raise ValueError("Use a small JSON object.")
        return {"json": body}, _references(body, set(allowed), allow_attrs=allow_attrs)
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
        if (not isinstance(login, dict) or not {"path", "capture"} <= login.keys() <= {"path", "capture", "method", "form", "json", "headers"}
                or login.get("method", "POST") != "POST"):
            raise ValueError("Use a private POST authentication exchange.")
        login_allowed = {"password", "username", "totp"}
        body, refs = _body(login, allowed=login_allowed, allow_attrs=True)
        login_headers = dict(credential_headers(login.get("headers", {})))
        refs = refs | _references(login_headers, login_allowed, allow_attrs=True)
        capture = login["capture"]
        if (not body and not login_headers) or not _has_credential_ref(refs) or not isinstance(capture, dict) or not 1 <= len(capture) <= 4:
            raise ValueError("The private login needs a credential reference and named captures.")
        for key, pointer in capture.items():
            if not isinstance(key, str) or not _NAME.fullmatch(key):
                raise ValueError("Use short private capture names.")
            _capture_target(pointer)
        login_entry = {"path": _path(login["path"]), "method": "POST", **body, "capture": dict(capture)}
        if login_headers:
            login_entry["headers"] = login_headers
        result["login"] = login_entry
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
    if auth == "session":
        allowed, allow_attrs = session_refs, False
    elif auth == "template":
        allowed, allow_attrs = {"password", "username", "totp"}, True
    else:
        allowed, allow_attrs = set(), False
    refs = _references(headers, allowed, allow_attrs=allow_attrs)
    if auth == "session" and (not session_refs or not refs) or auth == "template" and not _has_credential_ref(refs):
        raise ValueError("The resource authentication must use its private credential.")
    query = dict(request_query(request.get("query", {})))
    _references(query, set())
    result["request"] = {"path": _path(request["path"]), "method": method, "auth": auth, **body}
    if headers:
        result["request"]["headers"] = headers
    if query:
        result["request"]["query"] = query
    projection = data["result"]
    if (not isinstance(projection, dict) or set(projection) - {"path", "columns", "scalar", "headers"}
            or ("columns" in projection) == ("scalar" in projection)):
        raise ValueError("Choose a result path and scalar columns.")
    path = _pointer(projection.get("path", ""))
    scalar = "scalar" in projection
    columns = [projection["scalar"]] if scalar else projection["columns"]
    if (not isinstance(columns, list) or not 1 <= len(columns) <= MAX_COLUMNS
            or any(not _valid_column(name) for name in columns)
            or len(set(columns)) != len(columns)):
        raise ValueError("Choose unique noncredential scalar field names.")
    if scalar and any(re.sub(r"[_-]", "", key).lower() in _PRIVATE_COLUMNS for key in path.split("/")):
        raise ValueError("Named scalar results must come from a noncredential path.")
    result_entry = {"path": path, **({"scalar": columns[0]} if scalar else {"columns": list(columns)})}
    if "headers" in projection:
        req_headers = projection["headers"]
        if (not isinstance(req_headers, list) or not 1 <= len(req_headers) <= 8
                or any(not isinstance(name, str) or not _SAFE_HEADER_NAME.fullmatch(name)
                       or name.lower() in _FORBIDDEN_RESULT_HEADERS for name in req_headers)
                or len({name.lower() for name in req_headers}) != len(req_headers)):
            raise ValueError("Choose unique noncredential response header names.")
        result_entry["headers"] = list(req_headers)
    result["result"] = result_entry
    canonical = _json(result)
    if len(canonical.encode("ascii")) > 73728:
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


def _forbidden_variants(forbidden):
    variants = {variant for variant in _variants(forbidden) if len(variant) >= 4}
    for item in forbidden:
        if isinstance(item, str) and item:
            variants.add(item)
    return variants


def scrub_error_text(text, forbidden, max_len=512):
    """Strip control sequences, redact forbidden secrets longest-first, and bound length."""
    if not isinstance(text, str) or not text:
        return ""
    cleaned = _ANSI_OSC.sub("", text)
    cleaned = _ANSI_CSI.sub("", cleaned)
    cleaned = "".join(char for char in cleaned if char.isprintable() or char in "\n\t\r")
    secrets = _forbidden_variants(forbidden)
    if secrets:
        pattern = re.compile("|".join(re.escape(secret) for secret in sorted(secrets, key=len, reverse=True)))
        cleaned = pattern.sub("[REDACTED]", cleaned)
    cleaned = " ".join(cleaned.split())
    if not cleaned:
        return ""
    if len(cleaned) > max_len:
        if max_len <= 3:
            return cleaned[:max_len]
        return cleaned[:max_len - 3] + "..."
    return cleaned


def result_fields(projection):
    return [projection["scalar"]] if "scalar" in projection else projection["columns"]


def _resolve_field(row, field):
    if field in row:
        return True, row[field]
    if "." not in field:
        return False, None
    current = row
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _clean_scalar(value, forbidden_variants, private_number, *, guest_output=False):
    if isinstance(value, str):
        value = _ANSI_OSC.sub("", value)
        value = _ANSI_CSI.sub("", value)
        value = "".join(char for char in value if char.isprintable() or char in "\n\t\r")
        if any(secret in value for secret in forbidden_variants):
            raise ValueError("The projected result is private or too large.")
        if private_number is not None and re.search(rf"(?<![0-9]){private_number}(?![0-9])", value):
            raise ValueError("The projected result contains a private job identifier.")
        limit = MAX_GUEST_TEXT if guest_output else 4096
        if len(value) > limit:
            value = value[:limit - 15] + "\n...[truncated]"
        return value
    if (type(value) not in (int, float, bool, type(None))
            or isinstance(value, int) and not -(2**53) < value < 2**53
            or isinstance(value, float) and not math.isfinite(value)):
        raise ValueError("Only bounded scalar result fields may be returned.")
    if private_number is not None and type(value) in (int, float) and value == private_number:
        raise ValueError("The projected result contains a private job identifier.")
    return value


def _project(document, projection, forbidden, private_number=None, *, guest_output=False):
    rows = _select(document, projection["path"])
    if "scalar" in projection:
        rows = [{projection["scalar"]: rows}]
    elif isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("Use a bounded array of result objects.")
    forbidden_variants = _forbidden_variants(forbidden)
    result = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("The selected result is not an object.")
        item = {}
        for field in result_fields(projection):
            found, value = _resolve_field(row, field)
            if guest_output and not found:
                continue
            if isinstance(value, list):
                if len(value) > 64:
                    raise ValueError("Only bounded scalar result fields may be returned.")
                value = [_clean_scalar(entry, forbidden_variants, private_number, guest_output=guest_output)
                         for entry in value]
            else:
                value = _clean_scalar(value, forbidden_variants, private_number, guest_output=guest_output)
            item[field] = value
        result.append(item)
    encoded = _json(result)
    if len(encoded.encode("ascii")) > RESULT_LIMIT:
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


def _read_response_body(response, deadline, *, limit, allow_truncate=False):
    encoding = (response.getheader("Content-Encoding") or "").strip().lower()
    if encoding in ("", "identity"):
        mode = None
    elif encoding in ("gzip", "x-gzip"):
        mode = "gzip"
    elif encoding == "deflate":
        mode = "deflate"
    else:
        if allow_truncate:
            return b""
        raise ValueError("Unsupported content encoding.")

    out = bytearray()
    compressed_read = 0
    compressed_limit = limit if mode is None else (max(limit + 65536, limit * 2) if allow_truncate else BODY_LIMIT + 65536)
    decomp = zlib.decompressobj(16 + zlib.MAX_WBITS) if mode == "gzip" else None
    deflate_buf = bytearray()

    def feed_deflate(data):
        nonlocal decomp
        if decomp is not None:
            return decomp.decompress(data, max_length=limit + 1 - len(out))
        deflate_buf.extend(data)
        if len(deflate_buf) < 2:
            return b""
        initial = bytes(deflate_buf)
        deflate_buf.clear()
        try:
            candidate = zlib.decompressobj(zlib.MAX_WBITS)
            piece = candidate.decompress(initial, max_length=limit + 1 - len(out))
            decomp = candidate
            return piece
        except zlib.error:
            candidate = zlib.decompressobj(-zlib.MAX_WBITS)
            piece = candidate.decompress(initial, max_length=limit + 1 - len(out))
            decomp = candidate
            return piece

    try:
        while True:
            if monotonic() >= deadline:
                raise TimeoutError
            to_read = 16384 if mode is not None else min(16384, limit + 1 - len(out))
            if allow_truncate and mode is not None:
                to_read = min(4096, compressed_limit - compressed_read)
            if to_read <= 0:
                break
            chunk = response.read1(to_read)
            if not chunk:
                break
            compressed_read += len(chunk)
            if compressed_read > compressed_limit:
                if allow_truncate:
                    break
                raise ValueError("The result body exceeds the limit.")
            if mode is None:
                out.extend(chunk)
            elif mode == "gzip":
                out.extend(decomp.decompress(chunk, max_length=limit + 1 - len(out)))
            else:
                out.extend(feed_deflate(chunk))
            if len(out) > limit:
                if allow_truncate:
                    del out[limit:]
                    break
                raise ValueError("The result body exceeds the limit.")
            while not allow_truncate and decomp is not None and decomp.unconsumed_tail:
                extra = decomp.decompress(decomp.unconsumed_tail, max_length=limit + 1 - len(out))
                if not extra:
                    break
                out.extend(extra)
                if len(out) > limit:
                    raise ValueError("The result body exceeds the limit.")
            if allow_truncate and len(out) >= limit:
                break

        if mode == "deflate" and deflate_buf and not (allow_truncate and len(out) >= limit):
            initial = bytes(deflate_buf)
            deflate_buf.clear()
            try:
                candidate = zlib.decompressobj(zlib.MAX_WBITS)
                out.extend(candidate.decompress(initial, max_length=limit + 1 - len(out)))
                decomp = candidate
            except zlib.error:
                candidate = zlib.decompressobj(-zlib.MAX_WBITS)
                out.extend(candidate.decompress(initial, max_length=limit + 1 - len(out)))
                decomp = candidate
        if decomp is not None and not (allow_truncate and len(out) >= limit):
            tail = decomp.flush()
            if tail:
                out.extend(tail)
    except zlib.error as exc:
        if allow_truncate:
            return bytes(out[:limit])
        raise ValueError("Invalid compressed response body.") from exc

    if len(out) > limit:
        if allow_truncate:
            del out[limit:]
        else:
            raise ValueError("The result body exceeds the limit.")
    return bytes(out)


def _http(origin, pin, deadline, method, path, headers, body, dispatch, private_headers=None, observed=None,
          *, meta=None):
    if monotonic() >= deadline:
        raise TimeoutError
    send_headers = headers
    if not any(name.lower() == "accept-encoding" for name in headers):
        send_headers = dict(headers)
        send_headers["Accept-Encoding"] = "gzip, deflate"
    with _connection(origin, pin, deadline) as connection:
        if monotonic() >= deadline or not dispatch():
            raise PermissionError("Authorization changed or expired.")
        if monotonic() >= deadline:
            raise TimeoutError
        connection.request(method, path, body=body, headers=send_headers)
        with connection.getresponse() as response:
            status = response.status
            if observed is not None:
                observed(status)
            raw_headers = response.getheaders()
            if meta is not None:
                meta["headers"] = raw_headers
            if private_headers is not None:
                private_count = 0
                private_size = 0
                for name, value in raw_headers:
                    lowered = name.lower()
                    if lowered in _PRIVATE_RESPONSE_HEADERS:
                        private_count += 1
                        private_size += len(value)
                        if private_count > 16 or private_size > 16384:
                            raise ValueError("The private response headers exceed the limit.")
                        if lowered == "set-cookie":
                            pair = value.split(";", 1)[0]
                            if "=" in pair:
                                cookie_val = pair.split("=", 1)[1].strip()
                                if len(cookie_val) >= 12:
                                    private_headers.append(cookie_val)
                        elif len(value) >= 8:
                            private_headers.append(value)
            if not 200 <= status < 300:
                if meta is not None:
                    try:
                        err_raw = _read_response_body(response, deadline, limit=4096, allow_truncate=True)
                    except TimeoutError:
                        err_raw = b""
                    meta["error_text"] = err_raw.decode("utf-8", errors="replace")
                return status, None
            raw = _read_response_body(response, deadline, limit=BODY_LIMIT, allow_truncate=False)
            if not raw.strip():
                if meta is not None:
                    meta["empty"] = True
                return status, {}
            return status, _decode(raw.decode("utf-8"))


def _request_body(data, values):
    headers = {}
    body = None
    if "form" in data:
        body = urlencode(_render(data["form"], values)).encode("ascii")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif "json" in data:
        body = _json(_render(data["json"], values)).encode("ascii")
        headers["Content-Type"] = "application/json"
    if body is not None and len(body) > 69632:
        raise ValueError("The rendered request body exceeds the limit.")
    return headers, body


def _capture_value(document, raw_headers, target):
    if target.startswith("header:"):
        want = target[7:].lower()
        matches = [val for name, val in raw_headers if name.lower() == want]
        if not matches:
            raise ValueError("The private authentication response is invalid.")
        return matches[-1]
    if target.startswith("cookie:"):
        want = target[7:]
        matches = []
        for name, val in raw_headers:
            if name.lower() == "set-cookie":
                pair = val.split(";", 1)[0]
                if "=" in pair:
                    cookie_name, cookie_val = pair.split("=", 1)
                    if cookie_name.strip() == want:
                        matches.append(cookie_val.strip())
        if not matches:
            raise ValueError("The private authentication response is invalid.")
        return matches[-1]
    return _select(document, target)


def _export_headers(raw_headers, requested_names, forbidden):
    by_lower = {}
    wanted = {name.lower() for name in requested_names}
    for name, value in raw_headers:
        lowered = name.lower()
        if lowered in wanted:
            by_lower[lowered] = f"{by_lower[lowered]}, {value}" if lowered in by_lower else value
    exported = {}
    for req_name in requested_names:
        lowered = req_name.lower()
        if lowered in by_lower:
            exported[req_name] = scrub_error_text(by_lower[lowered], forbidden, max_len=1024)
    return exported


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


def _render_headers(raw_headers, values):
    headers = dict(_render(raw_headers, values))
    rendered_auth = [
        headers[name] for name, template in raw_headers.items() if _REFERENCE.search(template)
    ]
    if any(any(ord(char) < 32 or ord(char) == 127 for char in value)
           or len(value.encode("utf-8")) > 16384 for value in headers.values()):
        raise ValueError("Invalid rendered authentication header.")
    return headers, rendered_auth


def _used_credential_refs(data):
    refs = set()
    allowed = {"password", "username", "totp"}
    if "login" in data:
        login = data["login"]
        for key in ("form", "json", "headers"):
            if key in login:
                refs.update(_references(login[key], allowed, allow_attrs=True))
    request = data["request"]
    if request["auth"] == "template" and "headers" in request:
        refs.update(_references(request["headers"], allowed, allow_attrs=True))
    return refs


def deliver_results(config, entry, dispatch, *, allow_username=False, private_result=None,
                    login_context=None, login_cache=None, provision=None, account=None):
    """Release only the concrete approved projection; dispatch gates every send."""
    sent_write = False
    write_status = None
    forbidden = []
    if hasattr(entry, "password") and isinstance(entry.password, str) and entry.password:
        forbidden.append(entry.password)
    if hasattr(entry, "otp") and isinstance(entry.otp, str) and entry.otp:
        forbidden.append(entry.otp)
        raw_otp = otp_uri_secret(entry.otp)
        if raw_otp:
            forbidden.append(raw_otp)
    try:
        config = parse_result_usage(config.data if isinstance(config, ResultRequest) else config)
        data = config.data
        request = data["request"]
        used_refs = _used_credential_refs(data)
        password = getattr(entry, "password", None)
        username = getattr(entry, "username", None) or ""
        if type(allow_username) is not bool:
            return {"outcome": "failed"}
        needs_password = request["auth"] in ("basic", "bearer") or "password" in used_refs
        if needs_password and (not isinstance(password, str) or not password or len(password.encode("utf-8")) > 65536):
            return {"outcome": "failed"}
        password_text = password if isinstance(password, str) else ""
        values = {"password": password_text, "username": username}
        forbidden = []
        if password_text:
            forbidden.extend((password_text, username + ":" + password_text))
        if "totp" in used_refs:
            totp_code, otp_secret = entry_totp(entry)
            values["totp"] = totp_code
            forbidden.extend((totp_code, otp_secret))
            raw_otp = otp_uri_secret(otp_secret)
            if raw_otp:
                forbidden.append(raw_otp)
        for ref in sorted(used_refs):
            if ref.startswith("attr."):
                attr_val = entry_custom_attr(entry, ref[5:])
                values[ref] = attr_val
                forbidden.append(attr_val)
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
            headers, rendered_login_auth = _render_headers(login.get("headers", {}), values)
            body_headers, body = _request_body(login, values)
            for name, value in body_headers.items():
                headers = {key: item for key, item in headers.items() if key.lower() != name.lower()}
                headers[name] = value
            private_fields = list(rendered_login_auth)
            if body is not None:
                private_fields.append(body.decode("ascii"))
            login_meta = {}
            status, document = _http(data["origin"], pin, deadline, "POST", login["path"],
                                     headers, body, dispatch, private_fields, meta=login_meta)
            if not 200 <= status < 300:
                reply = {"outcome": "failed", "http_status": status}
                detail = scrub_error_text(login_meta.get("error_text", ""), [*forbidden, *private_fields], max_len=512)
                if detail:
                    reply["error_detail"] = detail
                return reply
            private_fields.extend(
                value for value in _private_strings(document)
                if (not allow_username or value != username) and len(value) >= 4
            )
            session = {}
            login_raw_headers = login_meta.get("headers", ())
            for key, pointer in login["capture"].items():
                value = _capture_value(document, login_raw_headers, pointer)
                if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096 or not value.isprintable():
                    raise ValueError("The private authentication response is invalid.")
                session["session." + key] = value
                private_fields.append(value)
            values.update(session)
            forbidden.extend(private_fields)
            if signature is not None:
                new_capture = (session, private_fields)
        raw_headers = request.get("headers", {})
        headers, rendered_auth_headers = _render_headers(raw_headers, values)
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
            if not re.fullmatch(r"[!-~]{1,8192}", password):
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

        resource_meta = {}
        status, document = _http(data["origin"], pin, deadline, request["method"], path,
                                 headers, body, gate, forbidden, observe, meta=resource_meta)
        if not 200 <= status < 300:
            if cached and status in (401, 403):
                login_cache.forget(login_context["key"])
            reply = {"outcome": "failed", "http_status": status}
            detail = scrub_error_text(resource_meta.get("error_text", ""), forbidden, max_len=512)
            if detail:
                reply["error_detail"] = detail
            return reply
        if status == 204 or resource_meta.get("empty"):
            projected = []
        else:
            projected = _project(document, data["result"], forbidden, private_number, guest_output=private_result is not None)
        if new_capture:
            login_cache.put(login_context["key"], signature, login_context["expires"], *new_capture)
        reply = {"outcome": "succeeded", "http_status": status, "data": projected}
        if "headers" in data["result"]:
            reply["headers"] = _export_headers(resource_meta.get("headers", ()), data["result"]["headers"], forbidden)
        return reply
    except (OSError, HTTPException, ValueError, KeyError, IndexError, TypeError, AttributeError, RecursionError) as exc:
        if write_status is not None:
            outcome = "acknowledged" if 200 <= write_status < 300 else "failed"
            reply = {"outcome": outcome, "http_status": write_status}
            if outcome == "failed":
                detail = scrub_error_text(str(exc) or type(exc).__name__, forbidden, max_len=240)
                if detail:
                    reply["error_detail"] = detail
            return reply
        reply = {"outcome": "uncertain" if sent_write else "failed"}
        detail = scrub_error_text(str(exc) or type(exc).__name__, forbidden, max_len=240)
        if detail:
            reply["error_detail"] = detail
        return reply
