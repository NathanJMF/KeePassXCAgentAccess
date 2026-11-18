"""Validate explicitly reviewed delivery of a second entry in an HTTPS body."""

import json
import re
from urllib.parse import urlencode

from .access_settings import uuid_text


_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")


def parse_provision(provision, usage):
    from .result_delivery import parse_result_usage

    if not isinstance(provision, dict) or set(provision) != {"entry", "body_type", "fields"}:
        raise ValueError("Provide an account entry and destination body fields.")
    fields = provision["fields"]
    body_type = provision["body_type"]
    if (body_type not in ("json", "form") or not isinstance(fields, dict)
            or not {"password"} <= fields.keys() <= {"username", "password"}
            or any(not isinstance(value, str) or not _FIELD.fullmatch(value) for value in fields.values())):
        raise ValueError("Bind the account password and optional username to named fields.")
    names = {name.casefold() for name in fields.values()}
    data = parse_result_usage(usage).data
    request = data["request"]
    if (request["method"] not in ("POST", "PUT") or "certificate_sha256" not in data
            or not data.get("approve_write_once")
            or ("form" if body_type == "json" else "json") in request
            or len(names) != len(fields)
            or names & {name.casefold() for name in request.get(body_type, {})}):
        raise ValueError("Use a pinned one-time write with unassigned account body fields.")
    return {"entry": uuid_text(provision["entry"]), "body_type": body_type, "fields": dict(fields)}


def provision_body(request, provision, account, forbidden):
    body_type, fields = provision["body_type"], provision["fields"]
    values = dict(request.get(body_type, {}))
    for key, field in fields.items():
        value = getattr(account, key, None)
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
            raise ValueError("The stored account fields are unavailable.")
        values[field] = value
        forbidden.append(value)
    if account.username:
        forbidden.extend((account.username, account.username + ":" + account.password))
    if body_type == "json":
        body = json.dumps(values, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("ascii")
        content_type = "application/json"
    else:
        body = urlencode(values).encode("ascii")
        content_type = "application/x-www-form-urlencoded"
    if len(body) > 65536:
        raise ValueError("The rendered provisioning body exceeds the limit.")
    forbidden.append(body.decode("ascii"))
    return {"Content-Type": content_type}, body
