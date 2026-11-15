"""Owner-only policy and action configuration."""

from dataclasses import asdict, dataclass
from enum import Enum
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
from uuid import UUID

from .settings import SettingsError, write_private_json


class AccessMode(str, Enum):
    ALLOW = "Allow all"
    REVIEW = "Review all"
    SMART = "Smart access"


REVIEW_ACTIONS = {
    "list_vaults": "Vaults - List",
    "create_group": "Groups - Create",
    "list_entries": "Groups and entries - Read",
    "rename_group": "Groups - Update name",
    "move_group": "Groups - Move",
    "recycle_group": "Groups - Delete (move to recycle bin)",
    "create_entry": "Entries - Create",
    "update_entry": "Entries - Update",
    "move_entry": "Entries - Move",
    "recycle_entry": "Entries - Delete (move to recycle bin)",
    "use_password": "Passwords - Use in actions",
    "replace_password": "Passwords - Replace",
}


class ActionType(str, Enum):
    BASIC = "https_basic_get"
    BEARER = "https_bearer_get"

    @property
    def label(self):
        return {
            self.BASIC: "HTTPS Basic-auth GET",
            self.BEARER: "HTTPS Bearer token GET",
        }[self]


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
class Action:
    id: str
    name: str
    entry: str
    url: str
    enabled: bool = True
    kind: ActionType = ActionType.BASIC

    def __post_init__(self):
        action_id(self.id)
        label(self.name)
        if type(self.enabled) is not bool:
            raise ValueError("Invalid action setting.")
        try:
            kind = ActionType(self.kind)
        except ValueError:
            raise ValueError("Choose a supported credential action.") from None
        object.__setattr__(self, "entry", uuid_text(self.entry))
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
            review_actions = data.get("review_actions", [])
            start_unlocked = data.get("start_unlocked", True)
            if (type(retention) is not int or not 1 <= retention <= 365 or type(review_usage) is not bool
                    or type(start_unlocked) is not bool or not isinstance(review_actions, list)
                    or any(not isinstance(action, str) or action not in REVIEW_ACTIONS for action in review_actions)):
                raise ValueError
            vaults = tuple(
                (uuid_text(identity), VaultPolicy(
                    frozenset(uuid_text(entry) for entry in policy["automatic"]),
                    tuple(Action(**action) for action in policy["actions"]),
                ))
                for identity, policy in data["vaults"].items()
            )
            return AccessSettings(AccessMode(data["mode"]), endpoint, uid, retention, vaults, review_usage,
                                  frozenset(review_actions), start_unlocked)
        except FileNotFoundError:
            return AccessSettings()
        except (OSError, AttributeError, ValueError, TypeError, KeyError):
            raise SettingsError("Access settings could not be read.") from None

    def write(self, settings):
        config = settings.broker_config()
        if config:
            config.validate()
        if not settings.review_actions <= REVIEW_ACTIONS.keys():
            raise ValueError("Choose a supported action to review.")
        if not 1 <= settings.retention_days <= 365:
            raise ValueError("Choose a retention period between 1 and 365 days.")
        write_private_json(self.path, {
            "mode": settings.mode.value,
            "review_usage": settings.review_usage,
            "review_actions": sorted(settings.review_actions),
            "start_unlocked": settings.start_unlocked,
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
