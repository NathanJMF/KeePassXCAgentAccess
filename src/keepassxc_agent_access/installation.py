"""Install or remove Keeper's per-user desktop application."""

import argparse
from base64 import b64encode
from contextlib import contextmanager
from fcntl import LOCK_EX, flock
from hashlib import sha256
import json
import os
from pathlib import Path
from shlex import join
import shutil
import signal
import stat
import subprocess
from tempfile import NamedTemporaryFile, TemporaryDirectory
from time import monotonic, sleep

from gi.repository import Gio, GLib

from .access_settings import AccessStore
from .agent_connection import installed_connection
from .agent_setup import RUNTIME
from .isolated_runner import broker_path, owned, subordinate_ids
from .launcher import (
    DESKTOP_ID, SKILL_PATH, antigravity_mcp_config_destination, antigravity_mcp_entry,
    antigravity_skill_destination, desktop_contents, desktop_icon, normalize_desktop_icon,
    skill_destination, skill_launcher_contents,
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
        if not installed_connection():
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

    @staticmethod
    def _launcher_digest(data):
        return digest(normalize_desktop_icon(data.decode("utf-8", "replace")).encode("utf-8"))

    @staticmethod
    def _antigravity_mcp_update(mcp_path, command, previous_entry):
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
        ag_skill = antigravity_skill_destination()
        old_ag_skill = None
        manage_ag_skill = False
        if (ag_skill is not None and not ag_skill.parent.is_symlink()
                and not ag_skill.parent.parent.is_symlink()):
            old_ag_skill = regular_file(ag_skill) if not ag_skill.is_symlink() else b""
            manage_ag_skill = old_ag_skill is None or (
                previous.get("antigravity_skill_path") == str(ag_skill)
                and previous.get("antigravity_skill") == digest(old_ag_skill)
            )
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
        mcp_update = None
        if connect_agent and not agent:
            mcp_update = self._antigravity_mcp_update(
                antigravity_mcp_config_destination(), self.app / "keeper-connect", previous.get("antigravity_mcp_entry")
            )
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
        if manage_ag_skill:
            state.update(antigravity_skill_path=str(ag_skill), antigravity_skill=digest(source_skill))
            writes.append((ag_skill, source_skill, old_ag_skill, 0o644))
        if install_skill_launcher:
            state.update(skill_launcher_path=str(skill_launcher), skill_launcher=digest(source_skill_launcher))
            writes.append((skill_launcher, source_skill_launcher, old_skill_launcher, 0o755))
        if mcp_update is not None:
            mcp_path, mcp_bytes, old_mcp_bytes, mcp_entry = mcp_update
            state.update(antigravity_mcp_path=str(mcp_path), antigravity_mcp_entry=mcp_entry)
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

    @staticmethod
    def check_replaceable(original, saved, expected, title):
        if original is not None and original not in expected and digest(original) != saved:
            raise ValueError(f"Keeper found a customized {title}. Move it aside before installing over it.")

    def uninstall(self):
        state = self.installed()
        if not state:
            return False
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
        if ag_path_text := state.get("antigravity_skill_path"):
            ag_path = Path(ag_path_text)
            if not ag_path.parent.is_symlink():
                self.remove_matching(ag_path, state.get("antigravity_skill"))
        if (mcp_path_text := state.get("antigravity_mcp_path")) and (mcp_entry := state.get("antigravity_mcp_entry")):
            mcp_path = Path(mcp_path_text)
            if not mcp_path.is_symlink() and not mcp_path.parent.is_symlink():
                try:
                    raw = regular_file(mcp_path)
                    data = json.loads(raw.decode("utf-8")) if raw is not None else None
                except (OSError, ValueError, UnicodeDecodeError):
                    data = None
                if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict) and data["mcpServers"].get("keeper") == mcp_entry:
                    servers = dict(data["mcpServers"])
                    del servers["keeper"]
                    publish(mcp_path, (json.dumps({**data, "mcpServers": servers}, indent=2) + "\n").encode("utf-8"),
                            mode=stat.S_IMODE(mcp_path.stat().st_mode))
        skill_launcher = skill.with_name("keeper-agent")
        if state.get("skill_launcher_path") == str(skill_launcher) and not skill_launcher.parent.is_symlink():
            self.remove_matching(skill_launcher, state.get("skill_launcher"))
        if self.app.exists():
            shutil.rmtree(self.app)
        if self.update_source.exists() or self.update_source.is_symlink():
            owned(self.update_source, private=True)
            shutil.rmtree(self.update_source)
        self.manifest.unlink()
        return True

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
    commands.add_parser("uninstall")
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
                if connect_agent:
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
            if connect_agent:
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
            if installation.base.exists() or installation.base.is_symlink():
                with installation.lock():
                    if installed_connection():
                        administer_connection("remove")
                    removed = installation.uninstall()
            elif installed_connection():
                administer_connection("remove")
                removed = True
            if removed:
                print("Keeper was removed. Vaults, keyring entries, settings and Activity were kept.")
            else:
                print("No managed Keeper installation was found.")
    except (OSError, ValueError, SettingsError, GLib.Error, subprocess.CalledProcessError) as error:
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            error = error.stderr.strip()
        parser.exit(1, f"Keeper setup: {error}\n")


if __name__ == "__main__":
    main()
