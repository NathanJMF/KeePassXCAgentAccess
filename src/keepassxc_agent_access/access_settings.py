"""Owner-only policy and action configuration."""

from dataclasses import asdict, dataclass
from enum import Enum
from hashlib import sha256
import ipaddress
import json
from pathlib import Path
import re
from shlex import join
from urllib.parse import urlsplit, urlencode
from uuid import UUID

from .protocol import decode, validate_command
from .settings import SettingsError, write_private_json


class AccessMode(str, Enum):
    ALLOW = "Allow all"
    REVIEW = "Review all"
    SMART = "Smart access"


CREDENTIAL_REVIEW_ACTIONS = {
    "use_https": "Passwords - HTTPS Requests",
    "use_local_command": "Passwords - Local Commands",
    "use_networked_command": "Passwords - Networked Commands",
    "use_browser": "Passwords - Browser Sign-ins",
}

TOKEN_AUTO_APPROVAL_OPTIONS = {
    "auto_approve_tokens": "Access Tokens - Create",
    "auto_approve_token_changes": "Access Tokens - Update Permissions",
}

GUEST_AUTO_APPROVAL_OPTIONS = {
    "console_open": "Guest Consoles - Open and Reconnect",
    "guest_run": "Guest Commands - Run",
}

REVIEW_ACTIONS = {
    "list_vaults": "Vaults - List",
    "create_group": "Groups - Create",
    "list_entries": "Groups and Entries - Read",
    "rename_group": "Groups - Update Name",
    "move_group": "Groups - Move",
    "recycle_group": "Groups - Delete (Move to Recycle Bin)",
    "create_entry": "Entries - Create",
    "update_entry": "Entries - Update",
    "move_entry": "Entries - Move",
    "recycle_entry": "Entries - Delete (Move to Recycle Bin)",
    **CREDENTIAL_REVIEW_ACTIONS,
    "replace_password": "Passwords - Replace",
    "read_results": "Results - Read",
}


HTTPS_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
HTTPS_WRITE_METHODS = frozenset(("POST", "PUT", "PATCH", "DELETE"))
HTTPS_BODY_LIMIT = 2048
HTTPS_JSON_DEPTH = 16


def valid_json_depth(value, depth=1):
    if depth > HTTPS_JSON_DEPTH:
        return False
    if isinstance(value, dict):
        return all(valid_json_depth(item, depth + 1) for item in value.values())
    if isinstance(value, list):
        return all(valid_json_depth(item, depth + 1) for item in value)
    return True


def canonical_request_json(body):
    if not isinstance(body, str) or len(body) > HTTPS_BODY_LIMIT:
        raise ValueError("Enter a fixed JSON object up to 2,048 UTF-8 bytes.")
    if not body:
        return ""
    try:
        value = decode(body.encode("utf-8"))
        if isinstance(value, dict) and valid_json_depth(value):
            canonical = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)
            if len(canonical.encode("utf-8")) <= HTTPS_BODY_LIMIT:
                return canonical
    except (ValueError, RecursionError):
        pass
    raise ValueError("Enter a valid, fixed JSON object up to 2,048 UTF-8 bytes.")


def command_environment(values):
    """Nonsecret declarations only; routing and bootstrap stay owner-controlled."""
    if isinstance(values, dict):
        values = tuple(values.items())
    if not isinstance(values, (list, tuple)) or len(values) > 16:
        raise ValueError("Use at most sixteen command environment values.")
    protected = {"PATH", "HOME", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY",
                 "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "SSH_AUTH_SOCK", "GCONV_PATH", "LOCPATH"}
    result = []
    seen = set()
    for pair in values:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise ValueError("Use environment name/value pairs.")
        name, value = pair
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name)
                or name.upper() in protected or name.upper().startswith(("KEEPER_", "LD_", "DYLD_", "PYTHON"))
                or name.upper().endswith("_ASKPASS") or name in seen
                or not isinstance(value, str) or len(value) > 1024 or (value and not value.isprintable())
                or "{{password}}" in value or "{{username}}" in value):
            raise ValueError("Use bounded nonsecret environment values without overriding credential delivery or routing.")
        seen.add(name)
        result.append((name, value))
    if sum(len(name) + len(value) for name, value in result) > 4096:
        raise ValueError("The command environment exceeds the size limit.")
    return tuple(result)


def template_body_references(body):
    """Collect effective credential references while keeping object keys fixed."""
    if not body:
        return frozenset()
    references = set()
    def visit(value):
        if isinstance(value, str):
            references.update(re.findall(r"\{\{(password|username)\}\}", value))
        elif isinstance(value, dict):
            for key, item in value.items():
                if re.search(r"\{\{(password|username)\}\}", key):
                    raise ValueError("Credential references belong in JSON values, not object keys.")
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(json.loads(body))
    return frozenset(references)


def request_query(values):
    if isinstance(values, dict):
        values = tuple(values.items())
    if not isinstance(values, (tuple, list)) or len(values) > 32:
        raise ValueError("Use at most thirty-two query parameters.")
    result = []
    for pair in values:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise ValueError("Use query name/value pairs.")
        name, value = pair
        if (not isinstance(name, str) or not name or not isinstance(value, str)
                or any(not part.isprintable() for part in pair)
                or "{{password}}" in name + value or "{{username}}" in name + value):
            raise ValueError("Query parameters must be printable text without credential references.")
        result.append((name, value))
    if len(urlencode(result).encode("ascii")) > 2048:
        raise ValueError("The query exceeds the size limit.")
    return tuple(result)


def credential_headers(values):
    if isinstance(values, dict):
        values = tuple(values.items())
    if not isinstance(values, (tuple, list)) or len(values) > 16:
        raise ValueError("Use at most sixteen credential headers.")
    headers = []
    seen = set()
    for pair in values:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError("Use header name/value pairs.")
        name, value = pair
        if (not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}", name)
                or name.lower() in seen or name.lower() in {
                    "host", "connection", "content-length", "transfer-encoding", "proxy-authorization", "proxy-connection", "upgrade", "te", "trailer"}
                or not isinstance(value, str) or len(value) > 2048
                or any(ord(char) < 32 or ord(char) > 126 for char in value)):
            raise ValueError("Use printable header values without routing or framing overrides.")
        seen.add(name.lower())
        headers.append((name, value))
    if sum(len(name) + len(value) for name, value in headers) > 4096:
        raise ValueError("Credential headers exceed the size limit.")
    return tuple(headers)


class ActionType(str, Enum):
    BASIC = "https_basic_get"
    BEARER = "https_bearer_get"
    STDIN = "local_command_stdin"
    NETWORK_PROMPT = "network_command_prompt"
    BROWSER = "browser_form_post"
    TEMPLATE = "https_credential_template"
    RESULTS = "https_result_workflow"

    @property
    def review_operation(self):
        if self == self.STDIN:
            return "use_local_command"
        if self == self.NETWORK_PROMPT:
            return "use_networked_command"
        if self == self.BROWSER:
            return "use_browser"
        if self == self.RESULTS:
            return "read_results"
        return "use_https"

    @property
    def label(self):
        return {
            self.BASIC: "HTTPS Basic Auth",
            self.BEARER: "HTTPS Bearer Token",
            self.STDIN: "Isolated command stdin",
            self.NETWORK_PROMPT: "Networked command prompt",
            self.BROWSER: "Browser Sign-in",
            self.TEMPLATE: "HTTPS Credential Template",
            self.RESULTS: "Read HTTPS Results",
        }[self]


def normalize_review_actions(actions):
    selected = frozenset(actions)
    if "use_password" in selected:
        selected = (selected - {"use_password"}) | CREDENTIAL_REVIEW_ACTIONS.keys()
    if not selected <= REVIEW_ACTIONS.keys():
        raise ValueError("Choose a supported action to review.")
    return frozenset(selected)


def uuid_text(value):
    return str(UUID(value))


def label(value, limit=160):
    if not isinstance(value, str) or not value or len(value) > limit or not value.isprintable():
        raise ValueError("Enter a short, printable label.")
    return value


def action_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
        raise ValueError("Action ID must contain letters, digits, dots, underscores, or hyphens.")
    return value


@dataclass(frozen=True)
class Destination:
    host: str
    port: int
    path: str

    @property
    def url(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"https://{host}:{self.port}{self.path}"

    @classmethod
    def parse(cls, url):
        error = ValueError("Enter an HTTPS endpoint with a host and path and without query, fragment, or credentials.")
        if not isinstance(url, str) or not re.fullmatch(r"[!-~]{1,2048}", url) or any(c in url for c in "?#\\"):
            raise error
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname or "@" in parts.netloc or "%" in parts.netloc:
            raise error
        host = parts.hostname
        authority = r"\[[0-9a-fA-F:.]+\](?::[0-9]+)?" if ":" in host else r"[A-Za-z0-9.-]+(?::[0-9]+)?"
        if not re.fullmatch(authority, parts.netloc):
            raise error
        port = 443 if parts.port is None else parts.port
        if not 0 < port <= 65535:
            raise error
        if ":" not in host and not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
            raise error
        if ":" in host:
            host = str(ipaddress.IPv6Address(host))
        path = parts.path or "/"
        if path.startswith("//"):
            raise error
        return cls(host, port, path)


@dataclass(frozen=True)
class BrowserForm:
    submit_url: str
    form_id: str
    username_field: str
    password_field: str
    success_id: str
    success_url: str = ""

    def __post_init__(self):
        for value in (self.form_id, self.username_field, self.password_field, self.success_id):
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:\[\]-]{0,79}", value):
                raise ValueError("Enter short HTML IDs and input names.")
        if self.username_field == self.password_field:
            raise ValueError("The username and password inputs must have different names.")
        object.__setattr__(self, "submit_url", Destination.parse(self.submit_url).url)
        if self.success_url != "":
            object.__setattr__(self, "success_url", Destination.parse(self.success_url).url)

    @property
    def description(self):
        result = f"Form ID {self.form_id} · Username input {self.username_field} · Password input {self.password_field}"
        return result + f" · Success element ID {self.success_id}"


@dataclass(frozen=True)
class Action:
    id: str
    name: str
    entry: str
    url: str
    enabled: bool = True
    kind: ActionType = ActionType.BASIC
    command: tuple[str, ...] = ()
    executable_sha256: str = ""
    prompt_variable: str = ""
    accepts_input: bool = False
    method: str = "GET"
    request_json: str = ""
    browser: BrowserForm | None = None
    opaque: bool = False
    headers: tuple[tuple[str, str], ...] = ()
    query: tuple[tuple[str, str], ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    prompt_contains: str = ""
    result_request: str = ""

    @property
    def is_command(self):
        return self.kind in (ActionType.STDIN, ActionType.NETWORK_PROMPT)

    @property
    def type_label(self):
        if self.method == "GET":
            if self.kind == ActionType.BASIC:
                return "HTTPS Basic-auth GET"
            if self.kind == ActionType.BEARER:
                return "HTTPS Bearer token GET"
        return self.kind.label

    @property
    def destination(self):
        if self.kind == ActionType.RESULTS:
            return f"Protected HTTPS result read · {self.url}"
        if self.kind == ActionType.STDIN:
            return f"Local stdin · {join(self.command)}"
        if self.kind == ActionType.NETWORK_PROMPT:
            return (f"{self.url} · {self.prompt_variable} · {join(self.command)}"
                    + (" · read-only input" if self.accepts_input else ""))
        if self.browser:
            result = f"GET {self.url} · POST {self.browser.submit_url}"
            return result + (f" · GET {self.browser.success_url}" if self.browser.success_url else "")
        url = self.url + ("?" + urlencode(self.query) if self.query else "")
        return url if self.method == "GET" else f"{self.method} {url}"

    @property
    def request_summary(self):
        if self.kind == ActionType.RESULTS:
            from .result_delivery import parse_result_usage
            return parse_result_usage(decode(self.result_request.encode("utf-8"))).summary
        if self.browser:
            return self.browser.description
        if self.request_json:
            body = self.request_json.encode("utf-8")
            return f"Fixed JSON body · {len(body)} bytes · SHA-256 {sha256(body).hexdigest()}"
        if self.method in HTTPS_WRITE_METHODS:
            return "No request body"
        return None

    @property
    def scope(self):
        return (self.kind, self.url, self.id, self.command, self.executable_sha256,
                self.prompt_variable, self.accepts_input, self.method, self.request_json, self.browser, self.opaque, self.headers, self.query, self.environment, self.prompt_contains, self.result_request)

    def __post_init__(self):
        action_id(self.id)
        label(self.name)
        if type(self.opaque) is not bool:
            raise ValueError("Invalid credential output policy.")
        if type(self.enabled) is not bool:
            raise ValueError("Invalid action setting.")
        try:
            kind = ActionType(self.kind)
        except ValueError:
            raise ValueError("Choose a supported credential action.") from None
        object.__setattr__(self, "entry", uuid_text(self.entry))
        if not isinstance(self.result_request, str):
            raise ValueError("Use a declared protected result workflow.")
        if kind == ActionType.RESULTS:
            if (not self.result_request
                    or self.opaque or self.command or self.executable_sha256 or self.prompt_variable
                    or self.accepts_input or self.request_json or self.browser or self.headers
                    or self.query or self.environment or self.prompt_contains or self.method != "GET"):
                raise ValueError("A protected result read contains only its declared workflow.")
            from .result_delivery import parse_result_usage
            request = parse_result_usage(decode(self.result_request.encode("utf-8")))
            if Destination.parse(self.url).url != request.origin:
                raise ValueError("The result workflow must match its approved origin.")
            object.__setattr__(self, "url", request.origin)
            object.__setattr__(self, "result_request", request.canonical_json)
            object.__setattr__(self, "kind", kind)
            return
        if self.result_request:
            raise ValueError("Choose a protected result read for a result workflow.")
        if self.opaque and kind not in (ActionType.STDIN, ActionType.NETWORK_PROMPT):
            raise ValueError("Dispatch-only output applies to commands.")
        headers = credential_headers(self.headers)
        if headers and kind != ActionType.TEMPLATE:
            raise ValueError("Choose HTTPS Credential Template for custom headers.")
        object.__setattr__(self, "headers", headers)
        query = request_query(self.query)
        if query and kind in (ActionType.STDIN, ActionType.NETWORK_PROMPT, ActionType.BROWSER):
            raise ValueError("Query parameters apply to HTTPS requests.")
        object.__setattr__(self, "query", query)
        environment = command_environment(self.environment)
        if environment and (not self.opaque or kind != ActionType.NETWORK_PROMPT):
            raise ValueError("Declared environment applies to dynamic networked commands.")
        object.__setattr__(self, "environment", environment)
        if (not isinstance(self.prompt_contains, str) or len(self.prompt_contains) > 80
                or self.prompt_contains and (not self.prompt_contains.isprintable()
                                            or not self.prompt_contains.strip()
                                            or not self.opaque or kind != ActionType.NETWORK_PROMPT)):
            raise ValueError("Use a short literal credential prompt match for a dynamic networked command.")
        if type(self.accepts_input) is not bool:
            raise ValueError("Invalid input file setting.")
        if kind == ActionType.BROWSER:
            profile = BrowserForm(**self.browser) if isinstance(self.browser, dict) else self.browser
            if not isinstance(profile, BrowserForm):
                raise ValueError("Configure a browser form first.")
            origin = Destination.parse(self.url)
            for url in (profile.submit_url, profile.success_url):
                if url:
                    target = Destination.parse(url)
                    if (target.host, target.port) != (origin.host, origin.port):
                        raise ValueError("Login, submit, and success pages must share the same HTTPS origin.")
            if self.method != "GET" or self.request_json:
                raise ValueError("Browser sign-ins use their configured form settings.")
            object.__setattr__(self, "browser", profile)
        elif self.browser is not None:
            raise ValueError("Choose Browser Sign-in to configure an HTML form.")
        if kind in (ActionType.STDIN, ActionType.NETWORK_PROMPT):
            if self.method != "GET" or self.request_json != "":
                raise ValueError("Command actions do not accept HTTP method or body settings.")
            if not isinstance(self.executable_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", self.executable_sha256):
                raise ValueError("Choose a pinned system executable.")
            object.__setattr__(self, "command", validate_command(self.command))
            if kind == ActionType.NETWORK_PROMPT:
                if not isinstance(self.prompt_variable, str) or not re.fullmatch(
                    r"[A-Z][A-Z0-9_]{0,39}_ASKPASS", self.prompt_variable
                ):
                    raise ValueError("Choose a credential prompt variable ending in _ASKPASS.")
                destination = Destination.parse(self.url)
                if destination.path != "/":
                    raise ValueError("Enter the approved HTTPS origin. Put the exact resource in the command.")
                object.__setattr__(self, "url", destination.url)
            elif self.url or self.prompt_variable or self.accepts_input:
                raise ValueError("Local stdin actions do not accept network or input settings.")
        else:
            if self.command or self.executable_sha256 or self.prompt_variable or self.accepts_input:
                raise ValueError("HTTPS actions do not accept command settings.")
            if self.method not in HTTPS_METHODS:
                raise ValueError("Choose a supported HTTPS method.")
            body = canonical_request_json(self.request_json)
            if body and self.method not in HTTPS_WRITE_METHODS:
                raise ValueError("Only POST, PUT, and PATCH accept a JSON body.")
            object.__setattr__(self, "request_json", body)
            if kind == ActionType.TEMPLATE:
                body_references = template_body_references(body)
                if body and any(name.lower() == "content-type" for name, _ in headers):
                    raise ValueError("JSON request bodies set their Content-Type automatically.")
                if not any("{{password}}" in value for _, value in headers) and "password" not in body_references:
                    raise ValueError("A credential template must reference {{password}} in a transmitted value.")
            object.__setattr__(self, "command", ())
            object.__setattr__(self, "url", Destination.parse(self.url).url)
        object.__setattr__(self, "kind", kind)


@dataclass(frozen=True)
class VaultPolicy:
    automatic: frozenset[str] = frozenset()
    actions: tuple[Action, ...] = ()

    def __post_init__(self):
        if len({action.id for action in self.actions}) != len(self.actions):
            raise ValueError("Action IDs must be unique within a vault.")


@dataclass(frozen=True)
class AccessSettings:
    mode: AccessMode = AccessMode.REVIEW
    endpoint: str | None = None
    uid: int | None = None
    retention_days: int = 30
    vaults: tuple[tuple[str, VaultPolicy], ...] = ()
    review_usage: bool = False
    review_actions: frozenset[str] = frozenset()
    start_unlocked: bool = True
    auto_approve_tokens: bool = False
    auto_approve_token_changes: bool = False
    token_auto_approval_acknowledged: bool = False
    review_results: bool = True
    auto_approve_guest_actions: frozenset[str] = frozenset()

    def for_vault(self, identity):
        return dict(self.vaults).get(identity, VaultPolicy())

    def broker_config(self, fallback=None):
        if self.endpoint is None:
            return fallback
        from .broker import BrokerConfig
        return BrokerConfig(Path(self.endpoint), self.uid)


class AccessStore:
    def __init__(self, path):
        self.path = Path(path)

    def read(self):
        try:
            data = json.loads(self.path.read_text())
            endpoint, uid = data.get("endpoint"), data.get("uid")
            if endpoint is not None:
                if not isinstance(endpoint, str) or not Path(endpoint).is_absolute() or type(uid) is not int:
                    raise ValueError
            elif uid is not None:
                raise ValueError
            retention = data["retention_days"]
            review_usage = data.get("review_usage", False)
            review_results = data.get("review_results", True)
            review_actions = data.get("review_actions", [])
            start_unlocked = data.get("start_unlocked", True)
            auto_approve_tokens = data.get("auto_approve_tokens", False)
            auto_approve_token_changes = data.get("auto_approve_token_changes", False)
            token_auto_approval_acknowledged = data.get("token_auto_approval_acknowledged", False)
            guest_actions = data.get("auto_approve_guest_actions", [])
            if (type(retention) is not int or not 1 <= retention <= 365 or type(review_usage) is not bool or type(review_results) is not bool
                    or type(start_unlocked) is not bool or type(auto_approve_tokens) is not bool
                    or type(auto_approve_token_changes) is not bool or type(token_auto_approval_acknowledged) is not bool
                    or not isinstance(review_actions, list)
                    or any(not isinstance(action, str) for action in review_actions)
                    or not isinstance(guest_actions, list)
                    or any(not isinstance(action, str) or action not in GUEST_AUTO_APPROVAL_OPTIONS
                           for action in guest_actions)):
                raise ValueError
            vaults = tuple(
                (uuid_text(identity), VaultPolicy(
                    frozenset(uuid_text(entry) for entry in policy["automatic"]),
                    tuple(Action(**action) for action in policy["actions"]),
                ))
                for identity, policy in data["vaults"].items()
            )
            return AccessSettings(AccessMode(data["mode"]), endpoint, uid, retention, vaults, review_usage,
                                  normalize_review_actions(review_actions), start_unlocked,
                                  auto_approve_tokens, auto_approve_token_changes, token_auto_approval_acknowledged,
                                  review_results, frozenset(guest_actions))
        except FileNotFoundError:
            return AccessSettings()
        except (OSError, AttributeError, ValueError, TypeError, KeyError):
            raise SettingsError("Access settings could not be read.") from None

    def write(self, settings):
        config = settings.broker_config()
        if config:
            config.validate()
        review_actions = normalize_review_actions(settings.review_actions) - {"read_results"}
        if type(settings.review_results) is not bool:
            raise ValueError("Choose whether result reads require review.")
        if not settings.auto_approve_guest_actions <= GUEST_AUTO_APPROVAL_OPTIONS.keys():
            raise ValueError("Choose a supported guest operation.")
        if not 1 <= settings.retention_days <= 365:
            raise ValueError("Choose a retention period between 1 and 365 days.")
        write_private_json(self.path, {
            "mode": settings.mode.value,
            "review_usage": settings.review_usage,
            "review_results": settings.review_results,
            "review_actions": sorted(review_actions),
            "auto_approve_guest_actions": sorted(settings.auto_approve_guest_actions),
            "start_unlocked": settings.start_unlocked,
            "auto_approve_tokens": settings.auto_approve_tokens,
            "auto_approve_token_changes": settings.auto_approve_token_changes,
            "token_auto_approval_acknowledged": settings.token_auto_approval_acknowledged,
            "endpoint": settings.endpoint,
            "uid": settings.uid,
            "retention_days": settings.retention_days,
            "vaults": {
                uuid_text(identity): {
                    "automatic": sorted(uuid_text(entry) for entry in policy.automatic),
                    "actions": [asdict(action) for action in policy.actions],
                }
                for identity, policy in settings.vaults
            },
        })
