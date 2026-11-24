"""Install or remove Keeper's per-user desktop application."""

import argparse
from base64 import b64encode
from contextlib import contextmanager
from fcntl import LOCK_EX, flock
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
from shlex import join
import shutil
import signal
import stat
import subprocess
from tempfile import NamedTemporaryFile, TemporaryDirectory
from time import monotonic, sleep
import tomllib

from gi.repository import Gio, GLib

from .access_settings import AccessStore
from .agent_connection import installed_connection
from .agent_setup import RUNTIME
from .isolated_runner import broker_path, namespace, owned, subordinate_ids
from .keyring import KeyringError, SystemKeyring
from .launcher import (
    DESKTOP_ID, SKILL_PATH, antigravity_mcp_config_destination, antigravity_mcp_entry,
    antigravity_skill_destination, claude_mcp_config_destination, claude_skill_destination,
    codex_mcp_config_destination, codex_mcp_entry, codex_skill_destination, desktop_contents,
    desktop_icon, detected_agent_clients, normalize_desktop_icon, skill_destination,
    skill_launcher_contents,
)
from .settings import SettingsError, SettingsStore


APP = DESKTOP_ID.removesuffix(".desktop")
DESKTOP_SERVICE = "keeper.service"
SERVICE = "keeper-agent.service"
LEGACY_SERVICE = "keepassxc-agent-access.service"
CHECKOUT = Path(__file__).resolve().parents[2]
PROGRAMS = ("keeper-agent", "keeper-connect", "run-tray", "keepassxc-agent", "keeper-agent-runner",
            "keeper-run-agent", "keeper-open", "uninstall")


def digest(data):
    return sha256(data).hexdigest()


def regular_file(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Keeper requires a regular file at {path}")
    return path.read_bytes()


def publish(path, contents, *, mode=0o644):
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(contents)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def systemctl(*args, check=True):
    return subprocess.run(["systemctl", "--user", *args], check=check, capture_output=True, text=True)


def systemd_user_available():
    try:
        return systemctl("show-environment", check=False).returncode == 0
    except OSError:
        return False


def external_broker_active():
    try:
        return systemctl("is-active", "--quiet", LEGACY_SERVICE, check=False).returncode == 0
    except FileNotFoundError:
        return False


def external_broker_managed():
    try:
        return bool(systemctl("show", "--property=FragmentPath", "--value", LEGACY_SERVICE).stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        return False


def desktop_service_contents(app):
    if not str(app).isprintable():
        raise ValueError("The installation path contains unsupported characters.")
    quoted = str(app).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    return f"""[Unit]
Description=Keeper
PartOf=graphical-session.target
After=graphical-session.target

[Service]
Type=exec
ExecStart="{quoted}/run-tray"
Restart=on-failure
RestartSec=1

[Install]
WantedBy=graphical-session.target
""".encode()


def service_contents(app, uid):
    if not str(app).isprintable():
        raise ValueError("The installation path contains unsupported characters.")
    quoted = str(app).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    return f"""[Unit]
Description=Keeper Agent Broker
PartOf=graphical-session.target
After=graphical-session.target

[Service]
Type=exec
RuntimeDirectory=keeper-scoped-runner
RuntimeDirectoryMode=0700
Environment=KEEPASSXC_AGENT_SOCKET=%t/keeper-scoped-runner/broker.sock
Environment=KEEPASSXC_AGENT_UID={uid}
ExecStartPre="{quoted}/keeper-run-agent" --prepare-socket
ExecStart="{quoted}/run-tray"
Restart=on-failure
RestartSec=1

[Install]
WantedBy=graphical-session.target
""".encode()


def session_query():
    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    name, path = "org.freedesktop.DBus", "/org/freedesktop/DBus"
    app = GLib.Variant("(s)", (APP,))

    def call(method):
        return bus.call_sync(name, path, name, method, app, None, Gio.DBusCallFlags.NONE, 1500, None).unpack()[0]

    return call


def open_application():
    systemctl("start", SERVICE)
    present_application()


def present_application():
    call = session_query()
    deadline = monotonic() + 8
    while not call("NameHasOwner"):
        if monotonic() >= deadline:
            raise ValueError("Keeper did not start in the desktop session.")
        sleep(.1)
    subprocess.run(["gapplication", "launch", APP], check=True)


def stop_application():
    call = session_query()
    if not call("NameHasOwner"):
        return
    if call("GetConnectionUnixUser") != os.getuid():
        raise ValueError("Keeper is running under a different account.")
    pid = call("GetConnectionUnixProcessID")
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        signal.pidfd_send_signal(fd, signal.SIGTERM)
    except ProcessLookupError:
        return
    finally:
        os.close(fd)
    deadline = monotonic() + 8
    while call("NameHasOwner"):
        if monotonic() >= deadline:
            raise ValueError("Open Keeper and press Ctrl+Q, then try again.")
        sleep(.1)


def administer_connection(action, broker=None):
    owner = os.getuid()
    command = ["/usr/bin/pkexec", "/usr/bin/python3", "-I"]
    payload = None
    if action == "install":
        # Read and pin the release before authentication. The administrator process
        # never imports Python or opens payload files from the desktop checkout.
        helper = regular_file(CHECKOUT / "src/keepassxc_agent_access/agent_setup.py")
        files = {name: (helper if name == "agent-setup" else regular_file(CHECKOUT / name)) for name in RUNTIME}
        if any(data is None for data in files.values()):
            raise ValueError("Keeper's runner source is incomplete.")
        payload = json.dumps({name: b64encode(data).decode("ascii") for name, data in files.items()}).encode()
        command.extend(("-c", helper.decode("utf-8"), action, str(owner), "--payload-sha256", digest(payload)))
    else:
        helper_path = Path(f"/usr/local/lib/keeper-connect-{owner}/agent-setup")
        info = helper_path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("The installed administrator helper is unavailable or unsafe.")
        command.extend((str(helper_path), action, str(owner)))
    if broker is not None:
        command.extend(("--broker", str(broker.path), "--runner-uid", str(broker.agent_uid)))
    try:
        subprocess.run(command, input=payload, check=True)
    except subprocess.CalledProcessError:
        raise ValueError("Keeper's administrator setup did not complete.") from None


class Installation:
    def __init__(self):
        data = Path(GLib.get_user_data_dir())
        self.base = data / "keeper"
        self.app = self.base / "app"
        self.update_source = self.base / "update-source"
        self.manifest = self.base / "installation.json"
        self.launcher = data / "applications" / DESKTOP_ID
        config = Path(GLib.get_user_config_dir()) / "systemd/user"
        self.unit = config / SERVICE
        self.desktop_unit = config / DESKTOP_SERVICE

    @contextmanager
    def lock(self):
        self.base.mkdir(mode=0o700, parents=True, exist_ok=True)
        owned(self.base, private=True)
        fd = os.open(self.base / ".lock", os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            flock(fd, LOCK_EX)
            yield
        finally:
            os.close(fd)

    def installed(self):
        if not self.base.exists() and not self.base.is_symlink():
            return {}
        owned(self.base, private=True)
        data = regular_file(self.manifest)
        if data is None:
            if self.app.exists() or self.app.is_symlink():
                raise ValueError("An unmanaged app already exists at the Keeper installation path.")
            return {}
        state = json.loads(data)
        if not isinstance(state, dict) or state.get("version") != 1:
            raise ValueError("Keeper’s installation record could not be read.")
        return state

    def connection_update_needed(self, source=None):
        if not self.manages_system_connection() or not installed_connection():
            return False
        root = source or self.app
        runtime = Path(f"/usr/local/lib/keeper-connect-{os.getuid()}")
        try:
            for name in RUNTIME:
                app_path = "src/keepassxc_agent_access/agent_setup.py" if name == "agent-setup" else name
                if regular_file(runtime / name) != regular_file(root / app_path):
                    return True
        except (OSError, ValueError):
            return True
        return False

    def manages_system_connection(self):
        try:
            account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        except KeyError:
            return False
        return self.base.resolve() == (account_home / ".local/share/keeper").resolve()

    def agent_unit(self):
        try:
            if external_broker_managed():
                raise ValueError("An existing Keeper broker service is managed separately. "
                                 "Run ./install for desktop setup, or retire that service before using --agent.")
        except subprocess.CalledProcessError as error:
            raise ValueError("Agent setup requires the desktop account’s systemd user session.") from error
        uid, _ = subordinate_ids()
        endpoint = broker_path() / "broker.sock"
        saved = AccessStore(SettingsStore().path.parent / "access.json").read()
        if saved.endpoint is not None and (saved.endpoint, saved.uid) != (str(endpoint), uid):
            raise ValueError("An existing broker configuration uses a different socket or account. "
                             "Keep that configuration, or clear it in Keeper before enabling the bundled runner.")
        return service_contents(self.app, uid)

    _CLIENT_KEYS = ("antigravity", "codex", "claude")
    _MCP_MARKER_RE = re.compile(r"(?m)^# BEGIN KEEPER MCP\n.*?^# END KEEPER MCP(?:\n|$)", re.DOTALL)

    @staticmethod
    def _launcher_digest(data):
        return digest(normalize_desktop_icon(data.decode("utf-8", "replace")).encode("utf-8"))

    @staticmethod
    def _json_mcp_update(mcp_path, command, previous_entry):
        if mcp_path is None or mcp_path.is_symlink():
            return None
        try:
            old_bytes = regular_file(mcp_path)
            if old_bytes is None:
                data = {}
            else:
                data = json.loads(old_bytes.decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        servers = data.get("mcpServers")
        if "mcpServers" in data and not isinstance(servers, dict):
            return None
        servers = dict(servers or {})
        entry = antigravity_mcp_entry(command)
        existing = servers.get("keeper")
        if existing not in (None, previous_entry, entry):
            return None
        if existing == entry and old_bytes is not None:
            return (mcp_path, None, old_bytes, entry)
        servers["keeper"] = entry
        updated = (json.dumps({**data, "mcpServers": servers}, indent=2) + "\n").encode("utf-8")
        return (mcp_path, updated, old_bytes, entry)

    _antigravity_mcp_update = _json_mcp_update

    @classmethod
    def _codex_mcp_update(cls, mcp_path, command, previous_block):
        if mcp_path is None or mcp_path.is_symlink():
            return None
        block = codex_mcp_entry(command)
        try:
            old_bytes = regular_file(mcp_path)
        except (OSError, ValueError):
            return None
        if old_bytes is None:
            return (mcp_path, block.encode("utf-8"), None, block)
        try:
            text = old_bytes.decode("utf-8")
            data = tomllib.loads(text)
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            return None
        mcp_servers = data.get("mcp_servers")
        if "mcp_servers" in data and not isinstance(mcp_servers, dict):
            return None
        matches = list(cls._MCP_MARKER_RE.finditer(text))
        if len(matches) > 1:
            return None
        if matches:
            match = matches[0]
            existing_block = match.group(0)
            normalized = existing_block if existing_block.endswith("\n") else existing_block + "\n"
            if normalized == block:
                return (mcp_path, None, old_bytes, block)
            if previous_block is None or normalized != previous_block:
                return None
            new_text = text[:match.start()] + block + text[match.end():]
        else:
            if "# BEGIN KEEPER MCP" in text or "# END KEEPER MCP" in text:
                return None
            if isinstance(mcp_servers, dict) and "keeper" in mcp_servers:
                return None
            if not text:
                new_text = block
            elif text.endswith("\n\n"):
                new_text = text + block
            elif text.endswith("\n"):
                new_text = text + "\n" + block
            else:
                new_text = text + "\n\n" + block
        try:
            tomllib.loads(new_text)
        except tomllib.TOMLDecodeError:
            return None
        return (mcp_path, new_text.encode("utf-8"), old_bytes, block)

    @staticmethod
    def _previous_skill_state(previous, key):
        entry = (previous.get("client_skills") or {}).get(key)
        if isinstance(entry, dict):
            return entry.get("path"), entry.get("sha256")
        if key == "antigravity":
            return previous.get("antigravity_skill_path"), previous.get("antigravity_skill")
        return None, None

    @staticmethod
    def _previous_mcp_state(previous, key):
        entry = (previous.get("client_mcps") or {}).get(key)
        if isinstance(entry, dict):
            return entry
        if key == "antigravity" and previous.get("antigravity_mcp_path"):
            return {
                "path": previous.get("antigravity_mcp_path"),
                "format": "json",
                "entry": previous.get("antigravity_mcp_entry"),
                "created": bool(previous.get("antigravity_mcp_created")),
            }
        if key == "codex" and previous.get("codex_mcp_path"):
            return {
                "path": previous.get("codex_mcp_path"),
                "format": "toml",
                "block": previous.get("codex_mcp_block"),
                "created": bool(previous.get("codex_mcp_created")),
            }
        return None

    @staticmethod
    def _record_client_skill(state, key, skill_path, checksum):
        skills = dict(state.get("client_skills") or {})
        skills[key] = {"path": str(skill_path), "sha256": checksum}
        state["client_skills"] = skills
        if key == "antigravity":
            state.update(antigravity_skill_path=str(skill_path), antigravity_skill=checksum)

    @staticmethod
    def _record_client_mcp(state, key, mcp_path, mcp_format, value, created):
        mcps = dict(state.get("client_mcps") or {})
        record = {"path": str(mcp_path), "format": mcp_format, "created": bool(created)}
        if mcp_format == "toml":
            record["block"] = value
            state.update(codex_mcp_path=str(mcp_path), codex_mcp_block=value)
            if created:
                state["codex_mcp_created"] = True
        else:
            record["entry"] = value
            if key == "antigravity":
                state.update(antigravity_mcp_path=str(mcp_path), antigravity_mcp_entry=value)
                if created:
                    state["antigravity_mcp_created"] = True
        mcps[key] = record
        state["client_mcps"] = mcps

    @staticmethod
    def _client_targets():
        return (
            ("antigravity", antigravity_skill_destination(), antigravity_mcp_config_destination(), "json"),
            ("codex", codex_skill_destination(), codex_mcp_config_destination(), "toml"),
            ("claude", claude_skill_destination(), claude_mcp_config_destination(), "json"),
        )

    def install(self, enable_agent, *, stop_existing=False, connect_agent=False):
        previous = self.installed()
        if self.app.exists() or self.app.is_symlink():
            owned(self.app, private=True)
        old_launcher = regular_file(self.launcher)
        agent = enable_agent or "unit" in previous
        executable = "keeper-open" if agent else "run-tray"
        icon = desktop_icon(old_launcher.decode("utf-8", "ignore")) if old_launcher is not None else "dialog-password"
        launcher = desktop_contents(self.app / executable, icon=icon).encode()
        checkout_launcher = desktop_contents(CHECKOUT / "run-tray", icon=icon).encode()
        if old_launcher is not None:
            expected_digests = {self._launcher_digest(launcher), self._launcher_digest(checkout_launcher)}
            if (self._launcher_digest(old_launcher) not in expected_digests
                    and self._launcher_digest(old_launcher) != previous.get("launcher")
                    and digest(old_launcher) != previous.get("launcher")):
                raise ValueError("Keeper found a customized launcher. Move it aside before installing over it.")

        old_unit = regular_file(self.unit) if agent else None
        unit = self.agent_unit() if agent else None
        if agent:
            self.check_replaceable(old_unit, previous.get("unit"), (unit,), "service")

        manage_desktop_unit = bool(
            connect_agent and not agent and not external_broker_managed() and systemd_user_available()
        )
        old_desktop_unit = regular_file(self.desktop_unit) if (manage_desktop_unit or "desktop_unit" in previous) else None
        desktop_unit = desktop_service_contents(self.app) if manage_desktop_unit else None
        if manage_desktop_unit:
            self.check_replaceable(old_desktop_unit, previous.get("desktop_unit"), (desktop_unit,), "autostart service")

        skill = skill_destination()
        source_skill = (CHECKOUT / "skills" / SKILL_PATH).read_bytes()
        old_skill = regular_file(skill) if not skill.is_symlink() else b""
        legacy_skill = skill.parents[1] / SKILL_PATH
        legacy_contents = None
        if not legacy_skill.parent.is_symlink() and not legacy_skill.is_symlink() and legacy_skill.is_file():
            contents = regular_file(legacy_skill)
            if contents is not None and (
                contents == source_skill
                or (previous.get("skill_path") == str(legacy_skill) and previous.get("skill") == digest(contents))
            ):
                legacy_contents = contents
        manage_skill = old_skill is None or (
            previous.get("skill_path") == str(skill) and previous.get("skill") == digest(old_skill)
        )
        client_targets = self._client_targets()
        client_skill_writes = []
        for client_key, client_skill_path, _, _ in client_targets:
            if (client_skill_path is not None and not client_skill_path.parent.is_symlink()
                    and not client_skill_path.parent.parent.is_symlink()):
                old_client_skill = regular_file(client_skill_path) if not client_skill_path.is_symlink() else b""
                prev_path, prev_digest = self._previous_skill_state(previous, client_key)
                if old_client_skill is None or (prev_path == str(client_skill_path) and prev_digest == digest(old_client_skill)):
                    client_skill_writes.append((client_key, client_skill_path, old_client_skill))
        skill_launcher = skill.with_name("keeper-agent")
        source_skill_launcher = skill_launcher_contents(self.app / "keeper-agent")
        install_skill_launcher = agent or not connect_agent
        remove_old_skill_launcher = False
        old_skill_launcher = None
        if install_skill_launcher:
            if skill_launcher.is_symlink():
                raise ValueError("Keeper found a customized skill helper. Move keeper-agent beside the skill aside before installing.")
            old_skill_launcher = regular_file(skill_launcher)
            if old_skill_launcher is not None:
                helper_info = skill_launcher.stat()
                if helper_info.st_uid != os.geteuid() or helper_info.st_mode & 0o022:
                    raise ValueError("Keeper found a customized skill helper with unsafe ownership or permissions. Move it aside before installing.")
            self.check_replaceable(
                old_skill_launcher, previous.get("skill_launcher") if previous.get("skill_launcher_path") == str(skill_launcher) else None,
                (source_skill_launcher, skill_launcher_contents(CHECKOUT / "keeper-agent")), "skill helper",
            )
        elif previous.get("skill_launcher_path") == str(skill_launcher) and not skill_launcher.is_symlink():
            old_skill_launcher = regular_file(skill_launcher)
            if old_skill_launcher is not None and digest(old_skill_launcher) == previous.get("skill_launcher"):
                remove_old_skill_launcher = True
        mcp_updates = []
        if connect_agent and not agent:
            command = self.app / "keeper-connect"
            for client_key, _, client_mcp_path, mcp_format in client_targets:
                if client_mcp_path is None:
                    continue
                prev_mcp = self._previous_mcp_state(previous, client_key) or {}
                if mcp_format == "toml":
                    update = self._codex_mcp_update(client_mcp_path, command, prev_mcp.get("block"))
                else:
                    update = self._json_mcp_update(client_mcp_path, command, prev_mcp.get("entry"))
                if update is not None:
                    mcp_updates.append((client_key, mcp_format, bool(prev_mcp.get("created")), update))
        state = {"version": 1, "launcher": self._launcher_digest(launcher)}
        upstream = None
        if (CHECKOUT / ".git").exists():
            from .updates import UpdateError, git, revision, update_upstream

            try:
                state["revision"] = revision(CHECKOUT)
                state["source_dirty"] = bool(git(CHECKOUT, "status", "--porcelain", "--untracked-files=no"))
                if CHECKOUT == self.update_source.resolve():
                    state.update(update_url=previous["update_url"], update_ref=previous["update_ref"])
                else:
                    upstream = update_upstream(CHECKOUT, self.base)
                    state.update(update_url=upstream[0], update_ref=upstream[1])
            except UpdateError:
                # The desktop install can still be used without a configured upstream.
                pass
        writes = [(self.launcher, launcher, old_launcher, 0o644)]
        if manage_skill:
            state.update(skill_path=str(skill), skill=digest(source_skill))
            writes.append((skill, source_skill, old_skill, 0o644))
        for client_key, client_skill_path, old_client_skill in client_skill_writes:
            self._record_client_skill(state, client_key, client_skill_path, digest(source_skill))
            writes.append((client_skill_path, source_skill, old_client_skill, 0o644))
        if install_skill_launcher:
            state.update(skill_launcher_path=str(skill_launcher), skill_launcher=digest(source_skill_launcher))
            writes.append((skill_launcher, source_skill_launcher, old_skill_launcher, 0o755))
        for client_key, mcp_format, prev_created, (mcp_path, mcp_bytes, old_mcp_bytes, mcp_value) in mcp_updates:
            created = old_mcp_bytes is None or prev_created
            self._record_client_mcp(state, client_key, mcp_path, mcp_format, mcp_value, created)
            if mcp_bytes is not None:
                writes.append((mcp_path, mcp_bytes, old_mcp_bytes, 0o600))
        if agent:
            state["unit"] = digest(unit)
            writes.append((self.unit, unit, old_unit, 0o644))
        if desktop_unit is not None:
            state["desktop_unit"] = digest(desktop_unit)
            writes.append((self.desktop_unit, desktop_unit, old_desktop_unit, 0o644))

        self.base.mkdir(mode=0o700, parents=True, exist_ok=True)
        with TemporaryDirectory(dir=self.base) as temporary:
            staging, backup = Path(temporary) / "app", Path(temporary) / "previous"
            update_stage, old_update = Path(temporary) / "update", Path(temporary) / "previous-update"
            if upstream:
                from .updates import seed_update_checkout

                try:
                    seed_update_checkout(CHECKOUT, update_stage, state["revision"])
                except UpdateError:
                    raise ValueError("Keeper could not prepare its private update checkout.") from None
                if self.update_source.exists() or self.update_source.is_symlink():
                    owned(self.update_source, private=True)
            staging.mkdir(mode=0o700)
            shutil.copytree(CHECKOUT / "src", staging / "src", ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(CHECKOUT / "skills", staging / "skills")
            for name in PROGRAMS:
                shutil.copy2(CHECKOUT / name, staging / name)

            changed = []
            replaced_app = False
            replaced_update = False
            stopped_service = False
            enabled_service = False
            stopped_desktop_service = False
            enabled_desktop_service = False
            try:
                if old_unit is not None and "unit" in previous:
                    systemctl("stop", SERVICE)
                    stopped_service = True
                if "desktop_unit" in previous and old_desktop_unit is not None:
                    systemctl("stop", DESKTOP_SERVICE, check=False)
                    stopped_desktop_service = True
                if agent or ((previous or stop_existing) and not external_broker_active()):
                    stop_application()
                if self.app.exists():
                    self.app.rename(backup)
                staging.rename(self.app)
                replaced_app = True
                if upstream:
                    if self.update_source.exists():
                        self.update_source.rename(old_update)
                    update_stage.rename(self.update_source)
                    replaced_update = True
                for path, content, original, mode in writes:
                    original_mode = stat.S_IMODE(path.stat().st_mode) if original is not None else mode
                    publish(path, content, mode=mode)
                    changed.append((path, original, original_mode))
                if agent:
                    systemctl("daemon-reload")
                    enabled_service = True
                    systemctl("enable", "--now", SERVICE)
                if desktop_unit is not None:
                    systemctl("daemon-reload")
                    enabled_desktop_service = True
                    systemctl("enable", "--now", DESKTOP_SERVICE)
                elif stopped_desktop_service and "desktop_unit" in previous and self.desktop_unit.is_file():
                    if digest(self.desktop_unit.read_bytes()) == previous["desktop_unit"]:
                        systemctl("disable", "--now", DESKTOP_SERVICE, check=False)
                        self.desktop_unit.unlink(missing_ok=True)
                        changed.append((self.desktop_unit, old_desktop_unit, 0o644))
                        systemctl("daemon-reload", check=False)
                if remove_old_skill_launcher and self.remove_matching(skill_launcher, previous["skill_launcher"]):
                    changed.append((skill_launcher, old_skill_launcher, 0o755))
                if legacy_contents is not None and self.remove_matching(legacy_skill, digest(legacy_contents)):
                    changed.append((legacy_skill, legacy_contents, 0o644))
                publish(self.manifest, json.dumps(state).encode())
            except Exception:
                if enabled_service:
                    systemctl("disable", "--now", SERVICE, check=False)
                if enabled_desktop_service:
                    systemctl("disable", "--now", DESKTOP_SERVICE, check=False)
                for path, original, mode in reversed(changed):
                    if original is None:
                        path.unlink(missing_ok=True)
                    else:
                        publish(path, original, mode=mode)
                if replaced_update:
                    shutil.rmtree(self.update_source)
                if old_update.exists():
                    old_update.rename(self.update_source)
                if replaced_app:
                    shutil.rmtree(self.app)
                if backup.exists():
                    backup.rename(self.app)
                if agent or stopped_desktop_service:
                    systemctl("daemon-reload", check=False)
                if stopped_service:
                    systemctl("enable", "--now", SERVICE, check=False)
                if stopped_desktop_service and "desktop_unit" in previous:
                    systemctl("enable", "--now", DESKTOP_SERVICE, check=False)
                raise
        return self.launcher, self.app / "keeper-run-agent" if agent else None

    def install_client_integration(self, client_key):
        """Install SKILL.md and configure the MCP entry for one detected agent client."""
        if client_key not in self._CLIENT_KEYS:
            raise ValueError(f"Unsupported client integration: {client_key}")
        client = next((item for item in detected_agent_clients() if item.key == client_key), None)
        if client is None:
            raise ValueError(f"{client_key} was not detected.")
        with self.lock():
            state = self.installed()
            if not state:
                raise ValueError("Run ./install first to install Keeper.")
            source_skill = (CHECKOUT / "skills" / SKILL_PATH).read_bytes()
            source_digest = digest(source_skill)
            skill_installed = False
            skill_path = client.skill_path
            if (skill_path is not None and not skill_path.is_symlink()
                    and not skill_path.parent.is_symlink()
                    and not skill_path.parent.parent.is_symlink()):
                old_skill = regular_file(skill_path)
                prev_path, prev_digest = self._previous_skill_state(state, client_key)
                if old_skill is None or old_skill == source_skill or (
                    prev_path == str(skill_path) and prev_digest == digest(old_skill)
                ):
                    if old_skill != source_skill:
                        publish(skill_path, source_skill, mode=0o644)
                    self._record_client_skill(state, client_key, skill_path, source_digest)
                    skill_installed = True

            mcp_configured = False
            if client.mcp_path is not None:
                prev_mcp = self._previous_mcp_state(state, client_key) or {}
                command = self.app / "keeper-connect"
                if client.mcp_format == "toml":
                    update = self._codex_mcp_update(client.mcp_path, command, prev_mcp.get("block"))
                else:
                    update = self._json_mcp_update(client.mcp_path, command, prev_mcp.get("entry"))
                if update is not None:
                    mcp_path, mcp_bytes, old_mcp_bytes, mcp_value = update
                    if mcp_bytes is not None:
                        mode = stat.S_IMODE(mcp_path.stat().st_mode) if old_mcp_bytes is not None else 0o600
                        publish(mcp_path, mcp_bytes, mode=mode)
                    created = old_mcp_bytes is None or bool(prev_mcp.get("created"))
                    self._record_client_mcp(state, client_key, mcp_path, client.mcp_format, mcp_value, created)
                    mcp_configured = True

            publish(self.manifest, json.dumps(state).encode())
            return {"skill_installed": skill_installed, "mcp_configured": mcp_configured}

    @staticmethod
    def check_replaceable(original, saved, expected, title):
        if original is not None and original not in expected and digest(original) != saved:
            raise ValueError(f"Keeper found a customized {title}. Move it aside before installing over it.")

    @staticmethod
    def _prune_empty_dirs(paths):
        for directory in paths:
            try:
                if directory is not None and directory.is_dir() and not directory.is_symlink():
                    directory.rmdir()
            except OSError:
                pass

    @staticmethod
    def _remove_owned_tree(path):
        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
            return False
        shutil.rmtree(path, ignore_errors=True)
        return not path.exists()

    def _clear_runtime_and_state(self):
        removed = False
        real_home = self.manages_system_connection()
        if real_home or os.environ.get("XDG_RUNTIME_DIR"):
            try:
                runtime_runner = broker_path()
            except ValueError:
                runtime_runner = None
            if runtime_runner is not None:
                removed |= self._remove_owned_tree(runtime_runner)
        if real_home or os.environ.get("XDG_STATE_HOME"):
            state_home = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
            if state_home.is_absolute():
                removed |= self._remove_owned_tree(state_home / "keeper-agent-sessions")
                scoped = state_home / "keeper-scoped-runner"
                try:
                    info = scoped.lstat()
                except FileNotFoundError:
                    info = None
                if info is not None and stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == os.geteuid():
                    try:
                        uid, gid = subordinate_ids()
                        prefix = namespace(uid, gid)
                    except (OSError, ValueError):
                        prefix = None
                    if prefix is not None:
                        for anchor in scoped.iterdir():
                            profile = anchor / "profile"
                            if profile.exists() and not profile.is_symlink():
                                subprocess.run([*prefix, "/usr/bin/rm", "-rf", "--", str(profile)],
                                               cwd="/", env={"PATH": "/usr/bin:/bin"}, check=False, capture_output=True)
                    removed |= self._remove_owned_tree(scoped)
        if real_home:
            owner = os.geteuid()
            var_tmp = Path("/var/tmp")
            if var_tmp.is_dir():
                for candidate in var_tmp.glob("keeper-runtime-*"):
                    try:
                        info = candidate.lstat()
                    except OSError:
                        continue
                    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == owner:
                        shutil.rmtree(candidate, ignore_errors=True)
                        removed = True
        return removed

    def _clear_user_data(self):
        removed = False
        config_dir = self.unit.parents[2] / "keepassxc-agent-access"
        item_ids = set()
        try:
            saved = SettingsStore(config_dir / "settings.json").read()
            if saved.active_item:
                item_ids.add(saved.active_item)
            item_ids.update(saved.pending_items)
        except (OSError, SettingsError, ValueError):
            pass
        workspace_file = config_dir / "workspace.json"
        try:
            if not workspace_file.is_symlink() and workspace_file.is_file():
                data = json.loads(workspace_file.read_text(encoding="utf-8"))
                for vault_row in data.get("vaults", ()):
                    if isinstance(vault_row, dict) and isinstance(vault_row.get("item"), str):
                        item_ids.add(vault_row["item"])
        except (OSError, ValueError):
            pass
        if item_ids or self.manages_system_connection():
            try:
                keyring = SystemKeyring()
                for item_id in sorted(item_ids):
                    try:
                        keyring.remove(item_id)
                        removed = True
                    except KeyringError:
                        pass
                if self.manages_system_connection() and keyring.remove_all():
                    removed = True
            except (KeyringError, OSError):
                pass
        removed |= self._remove_owned_tree(config_dir)
        cache_dir = Path(GLib.get_user_cache_dir()) / "keepassxc-agent-access"
        removed |= self._remove_owned_tree(cache_dir)
        return removed

    def cleanup_empty_base(self):
        try:
            lock_file = self.base / ".lock"
            if not lock_file.is_symlink():
                lock_file.unlink(missing_ok=True)
            if self.base.exists() and not self.base.is_symlink():
                self.base.rmdir()
        except OSError:
            pass

    @staticmethod
    def _remove_json_mcp(mcp_path, mcp_entry, created):
        if mcp_entry is None or mcp_path.is_symlink() or mcp_path.parent.is_symlink():
            return
        try:
            raw = regular_file(mcp_path)
            data = json.loads(raw.decode("utf-8")) if raw is not None else None
        except (OSError, ValueError, UnicodeDecodeError):
            data = None
        if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict) and data["mcpServers"].get("keeper") == mcp_entry:
            servers = dict(data["mcpServers"])
            del servers["keeper"]
            if created and not servers and set(data) <= {"mcpServers"}:
                mcp_path.unlink(missing_ok=True)
            else:
                publish(mcp_path, (json.dumps({**data, "mcpServers": servers}, indent=2) + "\n").encode("utf-8"),
                        mode=stat.S_IMODE(mcp_path.stat().st_mode))

    @classmethod
    def _remove_codex_mcp(cls, mcp_path, expected_block, created):
        if expected_block is None or mcp_path.is_symlink() or mcp_path.parent.is_symlink():
            return
        try:
            raw = regular_file(mcp_path)
            if raw is None:
                return
            text = raw.decode("utf-8")
        except (OSError, ValueError, UnicodeDecodeError):
            return
        matches = list(cls._MCP_MARKER_RE.finditer(text))
        if len(matches) != 1:
            return
        match = matches[0]
        existing_block = match.group(0)
        normalized = existing_block if existing_block.endswith("\n") else existing_block + "\n"
        if normalized != expected_block:
            return
        before = text[:match.start()]
        after = text[match.end():]
        if not before.strip() and not after.strip():
            remaining = ""
        elif not after.strip():
            remaining = before.rstrip("\n") + "\n"
        elif not before.strip():
            remaining = after.lstrip("\n")
        else:
            remaining = before.rstrip("\n") + "\n\n" + after.lstrip("\n")
        if not remaining:
            if created:
                mcp_path.unlink(missing_ok=True)
            else:
                publish(mcp_path, b"", mode=stat.S_IMODE(mcp_path.stat().st_mode))
        else:
            publish(mcp_path, remaining.encode("utf-8"), mode=stat.S_IMODE(mcp_path.stat().st_mode))

    def uninstall(self, *, keep_data=False):
        state = self.installed()
        removed = bool(state)
        if state:
            if self.app.exists() or self.app.is_symlink():
                owned(self.app, private=True)
            if "unit" in state:
                unit = regular_file(self.unit)
                if unit is not None:
                    if digest(unit) != state["unit"]:
                        raise ValueError("Keeper’s user service was customized. Disable and remove it before uninstalling.")
                    systemctl("disable", "--now", SERVICE)
                    self.unit.unlink()
                    systemctl("daemon-reload")
            if "desktop_unit" in state:
                desktop_unit = regular_file(self.desktop_unit)
                if desktop_unit is not None:
                    if digest(desktop_unit) != state["desktop_unit"]:
                        raise ValueError("Keeper’s autostart service was customized. Disable and remove it before uninstalling.")
                    systemctl("disable", "--now", DESKTOP_SERVICE, check=False)
                    self.desktop_unit.unlink()
                    systemctl("daemon-reload", check=False)
            if not external_broker_active():
                stop_application()
            self.remove_matching(self.launcher, state.get("launcher"), normalize=True)
            skill = skill_destination()
            for path in (skill, skill.parents[1] / SKILL_PATH):
                if state.get("skill_path") == str(path) and not path.parent.is_symlink():
                    self.remove_matching(path, state.get("skill"))
            skill_entries = dict(state.get("client_skills") or {})
            if state.get("antigravity_skill_path") and "antigravity" not in skill_entries:
                skill_entries["antigravity"] = {
                    "path": state.get("antigravity_skill_path"),
                    "sha256": state.get("antigravity_skill"),
                }
            for entry in skill_entries.values():
                if not isinstance(entry, dict) or not entry.get("path"):
                    continue
                client_skill = Path(entry["path"])
                if not client_skill.parent.is_symlink():
                    self.remove_matching(client_skill, entry.get("sha256"))
                    self._prune_empty_dirs((
                        client_skill.parent,
                        client_skill.parent.parent if client_skill.parent.parent.name == "skills" else None,
                    ))
            mcp_entries = dict(state.get("client_mcps") or {})
            for key in self._CLIENT_KEYS:
                if key not in mcp_entries and (legacy := self._previous_mcp_state(state, key)):
                    mcp_entries[key] = legacy
            for entry in mcp_entries.values():
                if not isinstance(entry, dict) or not entry.get("path"):
                    continue
                mcp_path = Path(entry["path"])
                if entry.get("format") == "toml":
                    self._remove_codex_mcp(mcp_path, entry.get("block"), bool(entry.get("created")))
                else:
                    self._remove_json_mcp(mcp_path, entry.get("entry"), bool(entry.get("created")))
            skill_launcher = skill.with_name("keeper-agent")
            if state.get("skill_launcher_path") == str(skill_launcher) and not skill_launcher.parent.is_symlink():
                self.remove_matching(skill_launcher, state.get("skill_launcher"))
            self._prune_empty_dirs((skill.parent, skill.parent.parent if skill.parent.parent.name == "Skills" else None))
            if self.app.exists():
                shutil.rmtree(self.app)
            if self.update_source.exists() or self.update_source.is_symlink():
                owned(self.update_source, private=True)
                shutil.rmtree(self.update_source)
            self.manifest.unlink(missing_ok=True)
        update_result_file = self.base / "update-result.json"
        if not update_result_file.is_symlink() and update_result_file.exists():
            update_result_file.unlink(missing_ok=True)
            removed = True
        removed |= self._clear_runtime_and_state()
        if not keep_data:
            removed |= self._clear_user_data()
        return removed

    @staticmethod
    def remove_matching(path, checksum, *, normalize=False):
        if not path.is_symlink() and (content := regular_file(path)) is not None:
            matched = digest(content) == checksum or (
                normalize and Installation._launcher_digest(content) == checksum
            )
            if matched:
                path.unlink()
                return True
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("install")
    agent = install.add_mutually_exclusive_group()
    agent.add_argument("--agent", action="store_true")
    agent.add_argument("--connect-agent", action="store_true")
    agent.add_argument("--app-only", action="store_true")
    install.add_argument("--no-launch", action="store_true")
    uninstall_parser = commands.add_parser("uninstall")
    uninstall_parser.add_argument("--keep-data", action="store_true",
                                  help="Remove Keeper while keeping local settings, Activity, and saved OS keyring entries.")
    opening = commands.add_parser("open")
    opening.add_argument("--show-window", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.exit(1, "Run Keeper setup from your desktop account.\n")
    try:
        installation = Installation()
        if args.command == "open":
            open_application()
        elif args.command == "install":
            with installation.lock():
                previous = installation.installed()
                broker = None
                if args.agent:
                    enable_agent, connect_agent = True, False
                elif args.app_only:
                    enable_agent, connect_agent = False, False
                elif args.connect_agent:
                    enable_agent, connect_agent = False, True
                elif "unit" in previous:
                    enable_agent, connect_agent = True, False
                else:
                    enable_agent, connect_agent = False, True

                if connect_agent:
                    if "unit" in previous:
                        raise ValueError("This installation uses the legacy runner. Keep it for existing grants, "
                                         "or uninstall it before setting up the dedicated connection.")
                    saved = AccessStore(SettingsStore().path.parent / "access.json").read()
                    if not saved.endpoint and not installed_connection() and external_broker_managed():
                        raise ValueError("The separately managed broker has no saved endpoint. "
                                         "Save its current endpoint and runner in Keeper's Broker Settings before connecting.")
                    broker = saved.broker_config()
                elif enable_agent and "unit" not in previous and installed_connection():
                    raise ValueError("The dedicated Keeper connection is already installed. Use --connect-agent.")
                launcher, runner = installation.install(
                    enable_agent, stop_existing=connect_agent, connect_agent=connect_agent
                )
                runner_updated = False
                if connect_agent and installation.manages_system_connection():
                    existing_connection = installed_connection()
                    needs_admin = (
                        existing_connection is None
                        or installation.connection_update_needed(CHECKOUT)
                        or (broker is not None and broker != existing_connection)
                    )
                    if needs_admin:
                        administer_connection("install", broker)
                        runner_updated = True
            print("Keeper is installed. Open Keeper from the application menu.")
            if connect_agent and installation.manages_system_connection():
                if runner_updated:
                    print("Open Keeper Settings → Connect an Agent for the skill and MCP command.")
                else:
                    print("Local MCP runner is already up to date. Open Keeper Settings → Connect an Agent for details.")
            if runner:
                print(f"Agent skill: {skill_destination()}")
                print(f"Agent command: {skill_destination().with_name('keeper-agent')}")
                print("Advanced stdio runner: " + join([str(runner), "--profile", "CHOOSE_A_PROFILE"]))
            print(f"Uninstall command: {installation.app / 'uninstall'}")
            if not args.no_launch:
                launcher_info = Gio.DesktopAppInfo.new_from_filename(str(launcher))
                if not launcher_info or not launcher_info.launch([], None):
                    print("Open Keeper from the application menu to finish setup.")
        else:
            removed = False
            manage_connection = installation.manages_system_connection()
            keep_data = getattr(args, "keep_data", False)
            if installation.base.exists() or installation.base.is_symlink():
                with installation.lock():
                    if manage_connection and installed_connection():
                        administer_connection("remove")
                    removed = installation.uninstall(keep_data=keep_data)
                installation.cleanup_empty_base()
            else:
                if manage_connection and installed_connection():
                    administer_connection("remove")
                    removed = True
                if installation.uninstall(keep_data=keep_data):
                    removed = True
            if removed:
                if keep_data:
                    print("Keeper was removed. Vaults, keyring entries, settings and Activity were kept.")
                else:
                    print("Keeper and its local settings, Activity, and keyring entries were completely removed. "
                          "Your .kdbx vault files were not touched.")
            else:
                print("No managed Keeper installation was found.")
    except (OSError, ValueError, SettingsError, GLib.Error, subprocess.CalledProcessError) as error:
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            error = error.stderr.strip()
        parser.exit(1, f"Keeper setup: {error}\n")


if __name__ == "__main__":
    main()
