"""Validate and authenticate private console workflows inside the vault worker."""
from http.client import HTTPException
import re
from time import monotonic
from urllib.parse import urlencode

from .access_settings import credential_headers
from .console_transport import Console
from .protocol import decode, encode
from .result_delivery import _NAME, _http, _path, _pointer, _references, _render, _request_body, _select, parse_result_usage


CONSOLE_SECONDS = 900
OPEN_SECONDS = 20


def parse_console(data):
    required = {"origin", "login", "connect", "socket"}
    if not isinstance(data, dict) or not required <= data.keys() <= required | {"certificate_sha256"}:
        raise ValueError("Provide a private HTTPS login, console creation request and WebSocket path.")
    create = data["connect"]
    if not isinstance(create, dict) or "capture" not in create or create.get("method") != "POST":
        raise ValueError("Console creation must be a POST with private captures.")
    captures = create["capture"]
    if (not isinstance(captures, dict) or not 1 <= len(captures) <= 4
            or any(not isinstance(key, str) or not _NAME.fullmatch(key) for key in captures)):
        raise ValueError("Use named console captures.")
    for pointer in captures.values():
        _pointer(pointer)
    result = parse_result_usage({
        **{key: data[key] for key in data.keys() & {"origin", "login", "certificate_sha256"}},
        "type": "https_results", "request": {key: value for key, value in create.items() if key != "capture"},
        "result": {"columns": ["status"]},
    }).data
    login = result["login"]
    if result["request"]["auth"] != "session" or set(captures) & login["capture"].keys():
        raise ValueError("Console creation needs private session authentication and distinct captures.")
    socket = data["socket"]
    if not isinstance(socket, dict) or not {"path", "headers", "query"} <= socket.keys() <= {"path", "headers", "query", "password"}:
        raise ValueError("Provide an explicit console WebSocket target and authentication.")
    headers = dict(credential_headers(socket["headers"]))
    if any(name.lower() == "origin" or name.lower().startswith("sec-websocket-") for name in headers):
        raise ValueError("Reserved WebSocket header.")
    query = socket["query"]
    if (not isinstance(query, dict) or len(query) > 8
            or any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key)
                   or not isinstance(value, str) or len(value) > 256 or not value.isprintable()
                   for key, value in query.items())):
        raise ValueError("Invalid WebSocket query.")
    login_refs = {"session." + key for key in login["capture"]}
    console_refs = {"session." + key for key in captures}
    if not _references(headers, login_refs) or not _references(query, console_refs):
        raise ValueError("The WebSocket requires private login and console authorization.")
    password = socket.get("password")
    match = re.fullmatch(r"\{\{(session\.[A-Za-z][A-Za-z0-9_]{0,31})\}\}", password) if isinstance(password, str) else None
    if "password" in socket and (match is None or match[1] not in console_refs):
        raise ValueError("The RFB password must be a private console capture.")
    output = {"origin": result["origin"], "login": login,
              "connect": {**result["request"], "capture": captures},
              "socket": {"path": _path(socket["path"]), "headers": headers, "query": dict(query)}}
    if password:
        output["socket"]["password"] = password
    if "certificate_sha256" in result:
        output["certificate_sha256"] = result["certificate_sha256"]
    encoded = encode(output)
    if len(encoded) > 3500:
        raise ValueError("The console descriptor is too large.")
    return decode(encoded)


def _capture(document, pointers, values):
    for key, pointer in pointers.items():
        value = _select(document, pointer)
        if type(value) is int and 0 <= value <= 65535:
            value = str(value)
        if (not isinstance(value, str) or not 1 <= len(value) <= 2048
                or not value.isascii() or not value.isprintable()):
            raise ValueError("Invalid private console capture.")
        values["session." + key] = value


def open_console(config, entry, dispatch):
    config = parse_console(config)
    origin, pin = config["origin"], config.get("certificate_sha256")
    values = {"username": entry.username or "", "password": entry.password}
    if any(not isinstance(item, str) or not item or len(item.encode("utf-8")) > 4096 for item in values.values()):
        raise ValueError("The target requires a username and password.")
    deadline = monotonic() + OPEN_SECONDS
    for name in ("login", "connect"):
        stage = config[name]
        headers, body = _request_body(stage, values)
        if name == "connect":
            declared = {key: value for key, value in _render(stage.get("headers", {}), values).items()
                        if key.lower() != "content-type"}
            headers.update(dict(credential_headers(declared)))
            path = stage["path"] + ("?" + urlencode(stage["query"]) if stage.get("query") else "")
        else:
            path = stage["path"]
        status, document = _http(origin, pin, deadline, "POST", path, headers, body, dispatch)
        if not 200 <= status < 300:
            raise HTTPException("The private console setup failed.")
        _capture(document, stage["capture"], values)
    socket = config["socket"]
    return Console(origin, pin, monotonic() + CONSOLE_SECONDS, socket["path"],
                   _render(socket["headers"], values), _render(socket["query"], values),
                   _render(socket.get("password"), values), dispatch)
