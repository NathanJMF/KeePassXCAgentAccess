"""Strict agent-supplied credential operations, compiled inside the owner broker."""

import json

from .access_settings import Action, ActionType, BrowserForm, Destination, HTTPS_WRITE_METHODS, template_body_references
from .command_action import executable_digest


USE_TYPES = frozenset(("local_command", "networked_command", "https", "https_results", "browser"))


def usage_origin(url):
    """Normalize the HTTPS authority used by API/forms or a routed TCP peer."""
    target = Destination.parse(url)
    return Destination(target.host, target.port, "/").url


def usage_action(entry, data, *, accepts_input=False, pin_executable=True):
    """Validate a request without creating a saved action or trusting a hash."""
    if not isinstance(data, dict) or data.get("type") not in USE_TYPES or type(accepts_input) is not bool:
        raise ValueError("Choose a supported credential delivery type.")
    kind = data["type"]
    if kind == "local_command":
        if set(data) != {"type", "command"} or accepts_input:
            raise ValueError("Local command requests contain only a literal command.")
        command = data["command"]
        return Action("agent-request", "Local Command", entry, "", kind=ActionType.STDIN,
                      command=command, executable_sha256=executable_digest(command) if pin_executable else "0" * 64, opaque=True)
    if kind == "networked_command":
        if not {"type", "command", "origin", "prompt_variable"} <= data.keys() <= {"type", "command", "origin", "prompt_variable", "environment", "prompt_contains"}:
            raise ValueError("Networked requests need a command, destination and prompt variable.")
        command = data["command"]
        origin = Destination.parse(data["origin"])
        if origin.path != "/":
            raise ValueError("Choose a network destination without a resource path.")
        return Action("agent-request", "Networked Command", entry, origin.url, kind=ActionType.NETWORK_PROMPT,
                      command=command, executable_sha256=executable_digest(command) if pin_executable else "0" * 64,
                      prompt_variable=data["prompt_variable"], accepts_input=accepts_input, opaque=True,
                      environment=data.get("environment", ()), prompt_contains=data.get("prompt_contains", ""))
    if accepts_input:
        raise ValueError("Only networked commands accept an input artifact.")
    if kind == "https_results":
        from .result_delivery import parse_result_usage
        request = parse_result_usage(data)
        name = "Write via HTTPS" if request.data["request"]["method"] in HTTPS_WRITE_METHODS else "Read HTTPS Results"
        return Action("agent-request", name, entry, request.origin, kind=ActionType.RESULTS,
                      result_request=request.canonical_json)
    if kind == "https":
        if not {"type", "url", "auth"} <= data.keys() <= {"type", "url", "auth", "method", "json", "headers", "query"}:
            raise ValueError("Use an HTTPS URL, authentication type, method and optional JSON.")
        auth = {"basic": ActionType.BASIC, "bearer": ActionType.BEARER, "template": ActionType.TEMPLATE}.get(data["auth"])
        if auth is None:
            raise ValueError("Choose basic, bearer, or template authentication.")
        body = data.get("json", "")
        if isinstance(body, dict):
            body = json.dumps(body, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)
        return Action("agent-request", "HTTPS Request", entry, data["url"], kind=auth,
                      method=data.get("method", "GET"), request_json=body, headers=data.get("headers", ()), query=data.get("query", ()))
    required = {"type", "url", "submit_url", "form_id", "username_field", "password_field", "success_id"}
    if not required <= data.keys() <= required | {"success_url"}:
        raise ValueError("Use the login URL and explicit form and success selectors.")
    profile = BrowserForm(**{key: value for key, value in data.items() if key not in ("type", "url")})
    return Action("agent-request", "Browser Sign-in", entry, data["url"], kind=ActionType.BROWSER, browser=profile)


def requires_body_permission(action):
    """Classify rendered body disclosure separately from authentication headers."""
    if action.kind == ActionType.RESULTS:
        from .result_delivery import parse_result_usage
        return "login" in parse_result_usage(json.loads(action.result_request)).data
    if action.kind != ActionType.TEMPLATE or not action.request_json:
        return False
    return bool(template_body_references(action.request_json))


def requires_write_permission(action):
    """Reading selected data does not authorize a resource mutation."""
    if action.kind != ActionType.RESULTS:
        return False
    from .result_delivery import parse_result_usage
    request = parse_result_usage(json.loads(action.result_request))
    return request.data["request"]["method"] in HTTPS_WRITE_METHODS
