"""Launch a Keeper MCP runner under one host subordinate UID and GID."""

import argparse
from fcntl import LOCK_EX, flock
import os
from pathlib import Path
import re
from shutil import copyfile
import stat
import subprocess
from tempfile import TemporaryDirectory


DIRECTORY = os.O_DIRECTORY | os.O_NOFOLLOW
MODULES = ("__init__.py", "agent_cli.py", "agent_runner.py", "protocol.py", "runner_token.py")
ATTRIBUTION = ("KEEPASSXC_AGENT_MODEL", "KEEPASSXC_AGENT_CHAT", "KEEPASSXC_AGENT_CHAT_ID")


def namespace(uid, gid, *, confined=True):
    arguments = [
        "/usr/bin/unshare", "--user", f"--map-users=0:{uid}:1", f"--map-groups=0:{gid}:1",
        "--setuid", "0", "--setgid", "0",
    ]
    if confined:
        arguments.extend(("/usr/bin/setpriv", "--clear-groups", "--no-new-privs", "--bounding-set=-all",
                          "--inh-caps=-all", "--ambient-caps=-all"))
    return arguments


def subordinate_ids():
    import pwd

    identity = pwd.getpwuid(os.getuid()).pw_name
    ids = []
    for options, own in (([], os.getuid()), (["-g"], os.getgid())):
        result = subprocess.run(["/usr/bin/getsubids", *options, identity],
                                capture_output=True, text=True)
        ranges = [line.split() for line in result.stdout.splitlines()]
        candidate = next((int(parts[-2]) for parts in ranges if len(parts) >= 4
                          and parts[-2].isdigit() and parts[-1].isdigit() and int(parts[-1]) > 0), 0)
        if result.returncode or not 0 < candidate < 2**32 - 1 or candidate == own:
            raise ValueError("The desktop account needs subordinate UID and GID mappings. See the Ubuntu uidmap setup.")
        ids.append(candidate)
    return tuple(ids)


def owned(path, *, private=False):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise ValueError("Keeper requires an owner-controlled directory.")
    if info.st_mode & (0o077 if private else 0o067):
        raise ValueError("Keeper's directory permissions are too broad.")


def alter_acl(path, *flags):
    subprocess.run(["/usr/bin/setfacl", *flags, "--", path], check=True)


def broker_path():
    runtime = Path(os.environ["XDG_RUNTIME_DIR"])
    if not runtime.is_absolute():
        raise ValueError("Use an absolute desktop runtime directory.")
    owned(runtime, private=True)
    return runtime / "keeper-scoped-runner"


def prepare_socket(directory, uid):
    directory.mkdir(mode=0o700, exist_ok=True)
    owned(directory)
    alter_acl(directory, "-m", f"u:{uid}:--x")
    alter_acl(directory, "-d", "-m", f"u:{uid}:rw-,u::rwx,g::---,o::---")


def profile_anchor(name):
    state = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state").absolute()
    base = state / "keeper-scoped-runner"
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    owned(base, private=True)
    anchor = base / name
    anchor.mkdir(mode=0o700, exist_ok=True)
    owned(anchor)
    return anchor


def provision_profile(anchor, anchor_fd, uid, gid, prefix):
    profile = anchor / "profile"
    flock(anchor_fd, LOCK_EX)
    try:
        # Temporary directory creation permission is limited to the selected anchor.
        if not profile.exists():
            alter_acl(anchor, "-m", f"u:{uid}:rwx")
            try:
                subprocess.run([*prefix, "/usr/bin/mkdir", "-m", "700", "--",
                                f"/proc/self/fd/{anchor_fd}/profile"], cwd="/", env={"PATH": "/usr/bin:/bin"},
                               pass_fds=(anchor_fd,), check=True)
            finally:
                alter_acl(anchor, "-m", f"u:{uid}:--x")
        info = profile.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("The Keeper profile needs the configured owner, group, and mode 0700.")
        alter_acl(anchor, "-m", f"u:{uid}:--x")
    finally:
        os.close(anchor_fd)


def stage_runtime(checkout, stage):
    stage.chmod(0o711)
    launcher_dir = stage / "runtime"
    launcher_dir.mkdir(mode=0o755)
    package = launcher_dir / "src" / "keepassxc_agent_access"
    package.mkdir(mode=0o755, parents=True)
    for component in (launcher_dir, package.parent, package):
        component.chmod(0o755)
    bootstrap = package.parent / "keeper_bootstrap.py"
    copyfile(checkout / "src" / bootstrap.name, bootstrap)
    bootstrap.chmod(0o644)
    for name in MODULES:
        destination = package / name
        copyfile(checkout / "src" / "keepassxc_agent_access" / name, destination)
        destination.chmod(0o644)
    for name in ("keeper-agent-runner", "keepassxc-agent"):
        destination = launcher_dir / name
        copyfile(checkout / name, destination)
        destination.chmod(0o755)
    return launcher_dir / "keeper-agent-runner"


def launch(directory, checkout, profile, uid, gid):
    owned(directory)
    if not directory.joinpath("broker.sock").is_socket():
        raise ValueError("Keeper's broker socket is unavailable. Open Keeper first.")
    anchor = profile_anchor(profile)
    prefix = namespace(uid, gid)
    provision_profile(anchor, os.open(anchor, os.O_RDONLY | DIRECTORY), uid, gid, prefix)
    fd_socket = os.open(directory, os.O_PATH | DIRECTORY)
    try:
        fd_profile = os.open(anchor, os.O_PATH | DIRECTORY)
        try:
            environment = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
            environment.update({key: os.environ[key] for key in ATTRIBUTION if key in os.environ})
            with TemporaryDirectory(prefix="keeper-runtime-", dir="/var/tmp") as staged:
                runner = stage_runtime(checkout, Path(staged))
                return subprocess.run(
                    [*prefix, runner, "--socket", f"/proc/self/fd/{fd_socket}/broker.sock",
                     "--profile-dir", f"/proc/self/fd/{fd_profile}/profile",
                     "--inherit-directory-fd", str(fd_socket), "--inherit-directory-fd", str(fd_profile)],
                    pass_fds=(fd_socket, fd_profile), cwd="/", env=environment, check=False,
                ).returncode
        finally:
            os.close(fd_profile)
    finally:
        os.close(fd_socket)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="default", help="Private profile name for this agent")
    parser.add_argument("--prepare-socket", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        uid, gid = subordinate_ids()
        directory = broker_path()
        if args.prepare_socket:
            prepare_socket(directory, uid)
            return 0
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.profile):
            raise ValueError("Choose a short profile name using letters, digits, underscores, or hyphens.")
        return launch(directory, Path(__file__).resolve().parents[2], args.profile, uid, gid)
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Keeper runner could not start. {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
