"""Persist vault paths and keyring references, without credentials."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import tempfile

from .vault import VaultTarget


class SettingsError(Exception):
    """A safe, user-facing settings error."""


@dataclass(frozen=True)
class Settings:
    target: VaultTarget | None = None
    active_item: str | None = None
    pending_items: tuple[str, ...] = ()


class SettingsStore:
    def __init__(self, path=None):
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        self.path = path or base / "keepassxc-agent-access" / "settings.json"

    def read(self):
        try:
            with self.path.open(encoding="utf-8") as stream:
                saved = json.load(stream)
            database = saved["database"]
            key_file = saved["key_file"]
            active = saved["active_item"]
            pending = saved["pending_items"]
            if not isinstance(pending, list) or not all(isinstance(item, str) for item in pending):
                raise ValueError
            if (active is not None and (not isinstance(active, str) or active in pending)
                    or database is None and (key_file is not None or active is not None)):
                raise ValueError
            target = VaultTarget(Path(database), Path(key_file) if key_file else None) if database else None
            return Settings(target, active, tuple(pending))
        except FileNotFoundError:
            return Settings()
        except (OSError, ValueError, TypeError, KeyError):
            raise SettingsError("Settings could not be read.") from None

    def write(self, settings):
        target = settings.target
        data = {
            "database": str(target.database) if target else None,
            "key_file": str(target.key_file) if target and target.key_file else None,
            "active_item": settings.active_item,
            "pending_items": list(settings.pending_items),
        }
        write_private_json(self.path, data)


def write_private_json(path, data):
    temporary = None
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError:
        raise SettingsError("Settings could not be saved.") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
