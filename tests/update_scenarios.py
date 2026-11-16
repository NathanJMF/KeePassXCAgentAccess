"""Exercise the real updater, managed installer, and reopened app in the test desktop."""

import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from uuid import uuid4

def git(root, *arguments):
    return subprocess.run(["git", "-C", str(root), *arguments], check=True, capture_output=True, text=True).stdout.strip()


def commit(root):
    git(root, "add", ".")
    git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "Fixture release")
    return git(root, "rev-parse", "HEAD")


def main(root):
    os.environ["XDG_DATA_HOME"] = str(root / "data")
    os.environ["XDG_CONFIG_HOME"] = str(root / "config")
    from gi.repository import GLib

    from launcher_scenarios import app_pid, stop, wait_for
    from keepassxc_agent_access.installation import CHECKOUT, PROGRAMS, Installation
    from keepassxc_agent_access.updates import check_for_update, start_update, update_result

    base = root / "data/keeper"
    base.mkdir(mode=0o700, parents=True)
    publisher = base / "upstream"
    publisher.mkdir()
    git(publisher, "init", "--initial-branch=main")
    shutil.copytree(CHECKOUT / "src", publisher / "src", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(CHECKOUT / "skills", publisher / "skills")
    for filename in (*PROGRAMS, "install", ".gitignore"):
        shutil.copy2(CHECKOUT / filename, publisher / filename)
    first = commit(publisher)
    checkout = root / "Keeper checkout"
    git(root, "clone", str(publisher), str(checkout))
    # The private test desktop has no systemd user manager. Run the same helper and
    # app in separate process sessions so stopping the old app leaves the updater alive.
    bin_dir = root / "bin"
    bin_dir.mkdir()
    systemd_run = bin_dir / "systemd-run"
    systemd_run.write_text("""#!/usr/bin/python3
import os
import subprocess
import sys

separator = sys.argv.index("--")
environment = os.environ.copy()
for option in sys.argv[1:separator]:
    if option.startswith("--setenv="):
        name, value = option.removeprefix("--setenv=").split("=", 1)
        environment[name] = value
subprocess.Popen(sys.argv[separator + 1:], env=environment, start_new_session=True,
                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
""")
    systemd_run.chmod(0o755)
    os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ["PATH"]

    installation = Installation()
    assert installation.base == root / "data/keeper"
    subprocess.run([checkout / "install", "--no-launch"], check=True, capture_output=True)
    assert installation.installed()["update_url"] == str(publisher)
    assert installation.update_source != checkout
    assert git(installation.update_source, "rev-parse", "HEAD") == first
    assert not git(installation.update_source, "remote")
    (checkout / "worktree-only").touch()
    initial = check_for_update(installation)
    assert initial.installed == initial.target == first
    initial_process = subprocess.Popen([installation.app / "run-tray", "--show-window"])
    try:
        old_pid = wait_for(app_pid)
        (publisher / "src/keepassxc_agent_access/release-fixture").write_text("second")
        second = commit(publisher)
        available = check_for_update(installation)
        assert (available.installed, available.target) == (first, second)
        assert git(checkout, "rev-parse", "HEAD") == first
        attempt = str(uuid4())
        start_update(available, attempt)
        wait_for(lambda: update_result(installation)[0] == attempt)
        assert update_result(installation)[1] == "Keeper was updated.", update_result(installation)[1]
        assert wait_for(app_pid) != old_pid
        assert check_for_update(installation).installed == second
        assert git(checkout, "rev-parse", "HEAD") == first
        assert (installation.app / "src/keepassxc_agent_access/release-fixture").read_text() == "second"
        assert initial_process.wait(timeout=5) == 0
    finally:
        if initial_process.poll() is None:
            initial_process.terminate()
            initial_process.wait(timeout=5)
        try:
            pid = app_pid()
        except GLib.Error:
            pass
        else:
            stop(pid)
    print("Update scenario passed: Git check, pinned apply, managed install and app restart.", flush=True)


if __name__ == "__main__":
    with TemporaryDirectory(prefix="keeper-update-") as root:
        main(Path(root))
