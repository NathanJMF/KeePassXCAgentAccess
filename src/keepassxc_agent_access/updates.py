"""Check and apply fast-forward updates from Keeper's configured Git checkout."""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess

from gi.repository import GLib

from .installation import (
    CHECKOUT, LEGACY_SERVICE, Installation, external_broker_active, present_application, systemctl,
)
from .settings import SettingsError, write_private_json


class UpdateError(Exception):
    """A user-facing update failure without subprocess output."""


def git(checkout, *arguments, timeout=12, failure="Keeper could not read its update checkout."):
    environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false",
                   "GIT_OPTIONAL_LOCKS": "0"}
    try:
        return subprocess.run(["git", "-C", str(checkout), *arguments], env=environment,
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


def check_for_update(installation):
    try:
        state = installation.installed()
    except (OSError, ValueError):
        raise UpdateError("Keeper could not read its installation record.") from None
    source = state.get("checkout", str(CHECKOUT))
    if not isinstance(source, str):
        raise UpdateError("Keeper could not read its installation record.")
    checkout = Path(source)
    if not checkout.is_absolute() or not (checkout / ".git").exists():
        raise UpdateError("The update checkout is unavailable. Run ./install from your Keeper checkout.")
    installed = state.get("revision") or revision(checkout)
    branch = git(checkout, "branch", "--show-current")
    no_upstream = "The Keeper checkout needs a branch with a configured upstream."
    if not branch:
        raise UpdateError(no_upstream)
    remote = git(checkout, "config", "--get", f"branch.{branch}.remote", failure=no_upstream)
    ref = git(checkout, "config", "--get", f"branch.{branch}.merge", failure=no_upstream)
    if remote == "." or not remote or remote.startswith("-") or not ref.startswith("refs/heads/"):
        raise UpdateError(no_upstream)
    result = git(checkout, "ls-remote", "--exit-code", "--refs", "--", remote, ref,
                 failure="Keeper could not reach the update branch. Check your network and Git credentials.")
    target, _, reported_ref = result.partition("\t")
    if reported_ref != ref or not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", target):
        raise UpdateError("Keeper could not identify the remote revision.")
    return Candidate(checkout, remote, ref, installed, target)


def apply_update(installation, checked):
    try:
        fresh = check_for_update(installation)
        if fresh != checked:
            raise UpdateError("The update changed. Check for updates again.")
        if fresh.target == fresh.installed:
            return "Keeper is up to date."
        if git(checked.checkout, "status", "--porcelain"):
            raise UpdateError("The Keeper checkout has local changes. Commit or move them before applying the update.")
        git(checked.checkout, "fetch", "--no-tags", "--no-recurse-submodules", "--",
            checked.remote, checked.ref, timeout=90, failure="Keeper could not download the update.")
        fetched = git(checked.checkout, "rev-parse", "--verify", "FETCH_HEAD")
        if fetched != checked.target:
            raise UpdateError("The update changed while it was downloading. Check for updates again.")
        git(checked.checkout, "merge-base", "--is-ancestor", "HEAD", fetched,
            failure="The update cannot be fast-forwarded. Update the checkout manually.")
        git(checked.checkout, "-c", "core.hooksPath=/dev/null", "merge", "--ff-only", "--no-edit", fetched,
            failure="Keeper could not fast-forward the checkout.")
        subprocess.run([str(checked.checkout / "install"), "--no-launch"], cwd=checked.checkout,
                       capture_output=True, check=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        raise UpdateError("Installation could not finish. Run ./install in the Keeper checkout for details.") from None

    if external_broker_active():
        service = systemctl("show", "--property=ExecStart", "--value", LEGACY_SERVICE)
        if f"path={checked.checkout / 'run-tray'} ;" not in service.stdout:
            return "Update installed. Restart your separately managed Keeper service to use it."
        systemctl("restart", LEGACY_SERVICE)
        present_application()
    elif "unit" in installation.installed():
        present_application()
    else:
        detached([str(installation.app / "run-tray"), "--show-window"])
    return "Keeper was updated."


def update_result(installation):
    try:
        result = json.loads((installation.base / "last-update.json").read_text())
        return result["id"], result["message"]
    except (OSError, ValueError, TypeError, KeyError):
        return None, ""


def detached(program, *options):
    environment = ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
                   "XDG_CURRENT_DESKTOP", "DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY",
                   "XAUTHORITY", "GDK_BACKEND", "SSH_AUTH_SOCK")
    subprocess.run(
        ["systemd-run", "--user", "--collect", "--quiet", *options,
         *(f"--setenv={name}={os.environ[name]}" for name in environment if name in os.environ),
         "--", *program], check=True, capture_output=True, timeout=10,
    )


def start_update(candidate, attempt):
    program = ["/usr/bin/python3", "-m", "keepassxc_agent_access.updates", attempt,
               str(candidate.checkout), candidate.remote, candidate.ref, candidate.installed, candidate.target]
    try:
        detached(program, "--unit=keeper-update", f"--setenv=PYTHONPATH={Path(__file__).resolve().parents[1]}")
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
