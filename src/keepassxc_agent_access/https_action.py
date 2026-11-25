"""Credential delivery in the trusted worker over direct verified TLS."""

from base64 import b64encode
from contextlib import contextmanager
from hashlib import sha256
from http.client import HTTPException, HTTPSConnection
import json
import re
import ssl
from urllib.parse import urlencode
import zlib

from .access_settings import ActionType, Destination, HTTPS_WRITE_METHODS, credential_headers, request_query
from .protocol import sanitize_error_detail
from .totp import entry_custom_attr, entry_totp, otp_uri_secret


SOCKET_TIMEOUT = 15
BEARER_TOKEN = re.compile(r"[!-~]{1,8192}")
ERROR_BODY_LIMIT = 4096
ERROR_DETAIL_LIMIT = 512
_CERT_SHA256 = re.compile(r"[0-9a-f]{64}")
_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")
_TEMPLATE_REF = re.compile(r"\{\{(password|username|totp|attr\.[A-Za-z0-9_.-]{1,64})\}\}")


def failure():
    return {"outcome": "failed"}


def scrub_text(text, secrets=(), *, limit=ERROR_DETAIL_LIMIT):
    """Strip ANSI/control characters, redact secret strings, and bound length."""
    if not isinstance(text, str) or not text:
        return ""
    cleaned = _ANSI_ESCAPE.sub("", text)
    ordered = sorted({s for s in secrets if isinstance(s, str) and s}, key=len, reverse=True)
    for secret in ordered:
        cleaned = cleaned.replace(secret, "[REDACTED]")
    cleaned = " ".join("".join(char if char.isprintable() else " " for char in cleaned).split())
    for secret in ordered:
        normalized = " ".join("".join(char if char.isprintable() else " " for char in secret).split())
        if normalized:
            cleaned = cleaned.replace(normalized, "[REDACTED]")
    return cleaned[:limit]


def _decompress_error(raw, encoding):
    if encoding in ("", "identity"):
        return bytes(raw)
    if encoding == "gzip":
        wbits_options = (16 + zlib.MAX_WBITS,)
    elif encoding == "deflate":
        wbits_options = (zlib.MAX_WBITS, -zlib.MAX_WBITS)
    else:
        return b""
    for wbits in wbits_options:
        try:
            decompressor = zlib.decompressobj(wbits)
            out = decompressor.decompress(bytes(raw), ERROR_BODY_LIMIT)
            if len(out) < ERROR_BODY_LIMIT:
                out += decompressor.flush(ERROR_BODY_LIMIT - len(out))
            return out
        except zlib.error:
            continue
    return b""


def _read_error_body(response, secrets):
    try:
        raw = response.read(ERROR_BODY_LIMIT)
        if not isinstance(raw, (bytes, bytearray)) or not raw:
            return ""
        headers = getattr(response, "headers", None)
        raw_encoding = headers.get("Content-Encoding") if headers is not None and hasattr(headers, "get") else ""
        encoding = raw_encoding.strip().lower() if isinstance(raw_encoding, str) else ""
        data = _decompress_error(raw, encoding)
        if not data:
            return ""
        return scrub_text(data.decode("utf-8", errors="ignore"), secrets, limit=ERROR_DETAIL_LIMIT)
    except (OSError, HTTPException, ValueError):
        return ""


def _send_request(connection, method, path, body, request_headers, secrets):
    write = method in HTTPS_WRITE_METHODS
    detail = ""
    try:
        connection.request(method, path, body=body, headers=request_headers)
        with connection.getresponse() as response:
            status = response.status
            if (200 if write else 100) <= status <= 599 and not 200 <= status < 300:
                detail = _read_error_body(response, secrets)
    except (OSError, HTTPException, ValueError, TypeError) as error:
        status = None
        detail = sanitize_error_detail(scrub_text(str(error) or type(error).__name__, secrets, limit=240)) or ""
    if status is not None and (200 if write else 100) <= status <= 599:
        result = {"outcome": "succeeded" if 200 <= status < 300 else "failed", "http_status": status}
        if result["outcome"] == "failed" and detail:
            result["error_detail"] = detail
        return result
    result = {"outcome": "uncertain"} if write else failure()
    if detail:
        result["error_detail"] = detail
    return result


@contextmanager
def prepare_https(url, *, query=(), certificate_sha256: str | None = None):
    destination = Destination.parse(url)
    context = None
    if certificate_sha256 is not None:
        if not isinstance(certificate_sha256, str) or not _CERT_SHA256.fullmatch(certificate_sha256):
            raise ValueError("Use a lowercase SHA-256 certificate fingerprint.")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    connection = HTTPSConnection(destination.host, destination.port, context=context, timeout=SOCKET_TIMEOUT)
    try:
        connection.connect()
        connection.auto_open = False
        if certificate_sha256 is not None:
            peer = connection.sock.getpeercert(binary_form=True) if connection.sock is not None else None
            if not peer or sha256(peer).hexdigest() != certificate_sha256:
                raise ValueError("The approved certificate changed.")
        yield connection, destination.path + ("?" + urlencode(request_query(query)) if query else "")
    finally:
        connection.close()


def authenticate(connection, path, entry, kind=ActionType.BASIC, *, method="GET", request_json="", headers=()):
    password = entry.password
    if kind == ActionType.TEMPLATE:
        return authenticate_template(connection, path, entry, method=method, request_json=request_json, headers=headers)
    secrets = []
    if kind == ActionType.BEARER:
        if not isinstance(password, str) or not BEARER_TOKEN.fullmatch(password):
            return failure()
        authorization = f"Bearer {password}"
        secrets.extend((password, authorization))
    elif kind == ActionType.BASIC:
        username = entry.username or ""
        if not password or ":" in username or any(ord(c) < 32 or ord(c) == 127 for c in username + password):
            return failure()
        credential = b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        authorization = f"Basic {credential}"
        secrets.extend((password, f"{username}:{password}" if username else "", credential, authorization))
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

    return _send_request(connection, method, path, body, request_headers, secrets)


def _collect_template_refs(value):
    if isinstance(value, str):
        refs = set(_TEMPLATE_REF.findall(value))
        rest = _TEMPLATE_REF.sub("", value)
        if "{{" in rest or "}}" in rest or "attr.otp" in refs:
            raise ValueError("Unsupported credential reference.")
        return refs
    if isinstance(value, dict):
        refs = set()
        for key, item in value.items():
            if not isinstance(key, str) or "{{" in key or "}}" in key:
                raise ValueError("Credential references belong in JSON values, not object keys.")
            refs.update(_collect_template_refs(item))
        return refs
    if isinstance(value, list):
        refs = set()
        for item in value:
            refs.update(_collect_template_refs(item))
        return refs
    return set()


def authenticate_template(connection, path, entry, *, method="GET", request_json="", headers=()):
    """Render references only inside the trusted worker, never in returned data."""
    try:
        raw_headers = credential_headers(headers)
        parsed_json = json.loads(request_json) if request_json else None
        refs = _collect_template_refs([value for _, value in raw_headers])
        if parsed_json is not None:
            refs.update(_collect_template_refs(parsed_json))

        password = getattr(entry, "password", None)
        username = getattr(entry, "username", None) or ""
        if "password" in refs or not refs:
            if not isinstance(password, str) or not password or len(password.encode("utf-8")) > 65536:
                return failure()

        password_text = password if isinstance(password, str) else ""
        values = {"password": password_text, "username": username}
        secrets = []
        if password_text:
            secrets.append(password_text)
            if username:
                secrets.append(f"{username}:{password_text}")

        if "totp" in refs:
            totp_code, otp_secret = entry_totp(entry)
            values["totp"] = totp_code
            secrets.extend((totp_code, otp_secret))
            raw_otp_secret = otp_uri_secret(otp_secret)
            if raw_otp_secret:
                secrets.append(raw_otp_secret)

        for ref in sorted(refs):
            if ref.startswith("attr."):
                attr_val = entry_custom_attr(entry, ref[5:])
                values[ref] = attr_val
                secrets.append(attr_val)

        def render(value):
            if isinstance(value, str):
                return _TEMPLATE_REF.sub(lambda match: values[match[1]], value)
            if isinstance(value, dict):
                return {key: render(item) for key, item in value.items()}
            if isinstance(value, list):
                return [render(item) for item in value]
            return value

        result_headers = {key: render(value) for key, value in raw_headers}
        for (key, template), (_, rendered) in zip(raw_headers, result_headers.items()):
            if key.lower() == "authorization" or _TEMPLATE_REF.search(template):
                secrets.append(rendered)
        if any(any(ord(char) < 32 or ord(char) == 127 for char in value) or len(value.encode("utf-8")) > 65536
               for value in result_headers.values()):
            return failure()
        if sum(len(name.encode("ascii")) + len(value.encode("utf-8")) for name, value in result_headers.items()) > 65536:
            return failure()
        body = None
        if parsed_json is not None:
            body = json.dumps(render(parsed_json), ensure_ascii=False, allow_nan=False,
                              separators=(",", ":"), sort_keys=True).encode("utf-8")
            if len(body) > 131072:
                return failure()
            result_headers = {key: value for key, value in result_headers.items() if key.lower() != "content-type"}
            result_headers["Content-Type"] = "application/json"
    except (ValueError, TypeError):
        return failure()
    return _send_request(connection, method, path, body, result_headers, secrets)
