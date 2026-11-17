"""Install or remove Keeper's per-user desktop application."""

import argparse
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
from .isolated_runner import broker_path, owned, subordinate_ids
from .launcher import DESKTOP_ID, SKILL_PATH, desktop_contents, skill_destination, skill_launcher_contents
from .settings import SettingsError, SettingsStore


APP = DESKTOP_ID.removesuffix(".desktop")
SERVICE = "keeper-agent.service"
LEGACY_SERVICE = "keepassxc-agent-access.service"
CHECKOUT = Path(__file__).resolve().parents[2]
PROGRAMS = ("keeper-agent", "run-tray", "keepassxc-agent", "keeper-agent-runner", "keeper-run-agent", "keeper-open", "uninstall")


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


def external_broker_active():
    try:
        return systemctl("is-active", "--quiet", LEGACY_SERVICE, check=False).returncode == 0
    except FileNotFoundError:
        return False


def service_contents(app, uid):
    if not str(app).isprintable():
        raise ValueError("The installation path contains unsupported characters.")
    quoted = str(app).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    return f"""[Unit]
Description=Keeper Agent Broker
PartOf=graphical-session.target
After=graphical-session-pre.target

[Service]
Type=exec
RuntimeDirectory=keeper-scoped-runner
RuntimeDirectoryMode=0700
Environment=KEEPASSXC_AGENT_SOCKET=%t/keeper-scoped-runner/broker.sock
Environment=KEEPASSXC_AGENT_UID={uid}
ExecStartPre="{quoted}/keeper-run-agent" --prepare-socket
ExecStart="{quoted}/run-tray"
Restart=on-failure

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


class Installation:
    def __init__(self):
        data = Path(GLib.get_user_data_dir())
        self.base = data / "keeper"
        self.app = self.base / "app"
        self.update_source = self.base / "update-source"
        self.manifest = self.base / "installation.json"
        self.launcher = data / "applications" / DESKTOP_ID
        self.unit = Path(GLib.get_user_config_dir()) / "systemd/user" / SERVICE

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

    def agent_unit(self):
        try:
            legacy = systemctl("show", "--property=FragmentPath", "--value", LEGACY_SERVICE)
            if legacy.stdout.strip():
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

    def install(self, enable_agent):
        previous = self.installed()
        if self.app.exists() or self.app.is_symlink():
            owned(self.app, private=True)
        old_launcher = regular_file(self.launcher)
        agent = enable_agent or "unit" in previous
        executable = "keeper-open" if agent else "run-tray"
        launcher = desktop_contents(self.app / executable).encode()
        checkout_launcher = desktop_contents(CHECKOUT / "run-tray").encode()
        self.check_replaceable(old_launcher, previous.get("launcher"), (launcher, checkout_launcher), "launcher")

        old_unit = regular_file(self.unit) if agent else None
        unit = self.agent_unit() if agent else None
        if agent:
            self.check_replaceable(old_unit, previous.get("unit"), (unit,), "service")

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
        skill_launcher = skill.with_name("keeper-agent")
        source_skill_launcher = skill_launcher_contents(self.app / "keeper-agent")
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
        state = {"version": 1, "launcher": digest(launcher)}
        upstream = None
        if (CHECKOUT / ".git").exists():
            from .updates import UpdateError, git, revision, update_upstream

            try:
                state["revision"] = revision(CHECKOUT)
                state["source_dirty"] = bool(git(CHECKOUT, "status", "--porcelain", "--untracked-files=all"))
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
        state.update(skill_launcher_path=str(skill_launcher), skill_launcher=digest(source_skill_launcher))
        writes.append((skill_launcher, source_skill_launcher, old_skill_launcher, 0o755))
        if agent:
            state["unit"] = digest(unit)
            writes.append((self.unit, unit, old_unit, 0o644))

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
            try:
                if old_unit is not None and "unit" in previous:
                    systemctl("stop", SERVICE)
                    stopped_service = True
                if agent or (previous and not external_broker_active()):
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
                    original_mode = stat.S_IMODE(path.stat().st_mode) if original is not None else 0o644
                    publish(path, content, mode=mode)
                    changed.append((path, original, original_mode))
                if agent:
                    systemctl("daemon-reload")
                    enabled_service = True
                    systemctl("enable", "--now", SERVICE)
                if legacy_contents is not None and self.remove_matching(legacy_skill, digest(legacy_contents)):
                    changed.append((legacy_skill, legacy_contents, 0o644))
                publish(self.manifest, json.dumps(state).encode())
            except Exception:
                if enabled_service:
                    systemctl("disable", "--now", SERVICE, check=False)
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
                if agent:
                    systemctl("daemon-reload", check=False)
                if stopped_service:
                    systemctl("enable", "--now", SERVICE, check=False)
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
        if not external_broker_active():
            stop_application()
        self.remove_matching(self.launcher, state.get("launcher"))
        skill = skill_destination()
        for path in (skill, skill.parents[1] / SKILL_PATH):
            if state.get("skill_path") == str(path) and not path.parent.is_symlink():
                self.remove_matching(path, state.get("skill"))
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
    def remove_matching(path, checksum):
        if not path.is_symlink() and (content := regular_file(path)) is not None and digest(content) == checksum:
            path.unlink()
            return True
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("install")
    install.add_argument("--agent", action="store_true")
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
                launcher, runner = installation.install(args.agent)
            print("Keeper is installed. Open Keeper from the application menu.")
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
                    removed = installation.uninstall()
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
