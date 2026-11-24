"""Check and apply fast-forward updates from Keeper's configured Git checkout."""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

from gi.repository import GLib

from .installation import (
    DESKTOP_SERVICE, LEGACY_SERVICE, Installation, external_broker_active, present_application, systemctl,
)
from .isolated_runner import owned
from .settings import SettingsError, write_private_json


class UpdateError(Exception):
    """A user-facing update failure without subprocess output."""


def git(checkout, *arguments, timeout=12, failure="Keeper could not read its update checkout."):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(PATH="/usr/bin:/bin", GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="/bin/false",
                       GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1")
    try:
        return subprocess.run(["/usr/bin/git", "-c", "core.hooksPath=/dev/null",
                               "-c", "core.fsmonitor=false", "-C", str(checkout),
                               *arguments], env=environment,
                              capture_output=True, text=True, timeout=timeout, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        raise UpdateError(failure) from None


def revision(checkout):
    return git(checkout, "rev-parse", "--verify", "HEAD")


@dataclass(frozen=True)
class Candidate:
    checkout: Path
    remote: str
    ref: str
    installed: str
    target: str


def update_upstream(source, base):
    """Enroll an upstream only during an explicit install from a trusted checkout."""
    branch = git(source, "branch", "--show-current")
    if not branch:
        raise UpdateError("The Keeper checkout needs a branch with a configured upstream.")
    remote = git(source, "config", "--get", f"branch.{branch}.remote")
    ref = git(source, "config", "--get", f"branch.{branch}.merge")
    if remote == "." or not remote or remote.startswith("-") or not ref.startswith("refs/heads/"):
        raise UpdateError("The Keeper checkout needs a branch with a configured upstream.")
    url = git(source, "remote", "get-url", "--", remote)
    return trusted_remote(url, base), ref


def trusted_remote(url, base):
    if isinstance(url, str) and url.isprintable() and not url.startswith("-"):
        try:
            parsed = urlsplit(url)
            if parsed.scheme in ("https", "ssh") and parsed.hostname and not parsed.password:
                return url
        except ValueError:
            pass
        if re.fullmatch(r"(?:[\w.-]+@)?[\w.-]+:[\w./~-]+", url) and "::" not in url:
            return url
        path = Path(url)
        if path.is_absolute() and path.resolve().is_relative_to(base.resolve()):
            try:
                owned(base, private=True)
            except (OSError, ValueError):
                pass
            else:
                return str(path.resolve())
    raise UpdateError("Keeper requires a trusted HTTPS or SSH update upstream.")


def seed_update_checkout(source, destination, revision_id):
    # A local clone imports committed objects without copying the source Git config,
    # hooks, worktree files, or hardlinks. The caller explicitly chose this build.
    git(source, "clone", "--no-local", "--no-checkout", "--template=", "--",
        str(source), str(destination), timeout=90)
    destination.chmod(0o700)
    git(destination, "remote", "remove", "origin")
    git(destination, "checkout", "--detach", revision_id)


def check_for_update(installation):
    try:
        state = installation.installed()
        checkout = installation.update_source
        owned(installation.base, private=True)
        owned(checkout, private=True)
        if not (checkout / ".git").is_dir() or (checkout / ".git").is_symlink():
            raise ValueError
    except (OSError, ValueError):
        raise UpdateError("Run ./install from a trusted Keeper checkout to configure updates.") from None
    installed = state.get("revision")
    if state.get("source_dirty"):
        raise UpdateError("This installation includes local changes. Reinstall from a clean Keeper checkout to enable updates.")
    ref = state.get("update_ref")
    if not valid_revision(installed) or not isinstance(ref, str) or not ref.startswith("refs/heads/"):
        raise UpdateError("Run ./install from a trusted Keeper checkout to configure updates.")
    remote = trusted_remote(state.get("update_url"), installation.base)
    result = git(checkout, "ls-remote", "--exit-code", "--refs", "--", remote, ref,
                 failure="Keeper could not reach the update branch. Check your network and Git credentials.")
    target, _, reported_ref = result.partition("\t")
    if reported_ref != ref or not valid_revision(target):
        raise UpdateError("Keeper could not identify the remote revision.")
    return Candidate(checkout, remote, ref, installed, target)


def valid_revision(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", value))


def apply_update(installation, checked):
    try:
        fresh = check_for_update(installation)
        if fresh != checked:
            raise UpdateError("The update changed. Check for updates again.")
        if fresh.target == fresh.installed:
            return "Keeper is up to date."
        if git(checked.checkout, "status", "--porcelain", "--untracked-files=no"):
            raise UpdateError("The Keeper checkout has local changes. Commit or move them before applying the update.")
        git(checked.checkout, "fetch", "--no-tags", "--no-recurse-submodules", "--",
            checked.remote, checked.ref, timeout=90, failure="Keeper could not download the update.")
        fetched = git(checked.checkout, "rev-parse", "--verify", "FETCH_HEAD")
        if fetched != checked.target:
            raise UpdateError("The update changed while it was downloading. Check for updates again.")
        git(checked.checkout, "merge-base", "--is-ancestor", checked.installed, fetched,
            failure="The update cannot be fast-forwarded. Update the checkout manually.")
        git(checked.checkout, "merge-base", "--is-ancestor", "HEAD", fetched,
            failure="The update cannot be fast-forwarded. Update the checkout manually.")
        git(checked.checkout, "merge", "--ff-only", "--no-edit", fetched,
            failure="Keeper could not fast-forward the checkout.")
        state = installation.installed()
        options = ["--agent"] if "unit" in state else ["--app-only"]
        subprocess.run([str(checked.checkout / "install"), "--no-launch", *options], cwd=checked.checkout,
                       capture_output=True, check=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        command = "./install --agent" if "unit" in installation.installed() else "./install"
        raise UpdateError(f"Installation could not finish. Run {command} from a trusted Keeper checkout "
                          "in a terminal to install any missing packages and see details.") from None

    state = installation.installed()
    if external_broker_active():
        service = systemctl("show", "--property=ExecStart", "--value", LEGACY_SERVICE)
        if f"path={installation.app / 'run-tray'} ;" not in service.stdout:
            return "Update installed. Restart your separately managed Keeper service to use it."
        systemctl("restart", LEGACY_SERVICE)
        present_application()
    elif "unit" in state:
        present_application()
    elif "desktop_unit" in state:
        systemctl("restart", DESKTOP_SERVICE)
        present_application()
    else:
        detached([str(installation.app / "run-tray"), "--show-window"])
    check_connection = getattr(installation, "connection_update_needed", None)
    if callable(check_connection) and check_connection():
        return "Keeper was updated. Open Settings → Connect an Agent to update the local runner."
    return "Keeper was updated."


def update_result(installation):
    try:
        result = json.loads((installation.base / "last-update.json").read_text())
        return result["id"], result["message"]
    except (OSError, ValueError, TypeError, KeyError):
        return None, ""


def detached(program, *options):
    environment = ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
                   "XDG_CURRENT_DESKTOP", "XDG_SESSION_ID", "DBUS_SESSION_BUS_ADDRESS", "DISPLAY",
                   "WAYLAND_DISPLAY", "XAUTHORITY", "GDK_BACKEND", "SSH_AUTH_SOCK")
    subprocess.run(
        ["systemd-run", "--user", "--collect", "--quiet", *options,
         *(f"--setenv={name}={os.environ[name]}" for name in environment if name in os.environ),
         "--", *program], check=True, capture_output=True, timeout=10,
    )


def start_update(candidate, attempt):
    program = ["/usr/bin/python3", "-I", str(Path(__file__).resolve().parents[1] / "keeper_bootstrap.py"),
               "keepassxc_agent_access.updates", attempt,
               str(candidate.checkout), candidate.remote, candidate.ref, candidate.installed, candidate.target]
    try:
        detached(program, "--unit=keeper-update")
    except (OSError, subprocess.SubprocessError):
        raise UpdateError("Keeper could not start the updater. Check that your systemd user session is running.") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt")
    parser.add_argument("checkout", type=Path)
    for field in ("remote", "ref", "installed", "target"):
        parser.add_argument(field)
    args = parser.parse_args()
    installation = Installation()
    candidate = Candidate(args.checkout, args.remote, args.ref, args.installed, args.target)
    installed = False
    try:
        message = apply_update(installation, candidate)
        installed = True
    except UpdateError as error:
        message = str(error)
    except (OSError, SettingsError, GLib.Error, subprocess.SubprocessError):
        message = "The updater could not finish. Open the application menu or run ./install in the Keeper checkout."
    write_private_json(installation.base / "last-update.json", {"id": args.attempt, "message": message})
    return 0 if installed else 1


if __name__ == "__main__":
    raise SystemExit(main())
