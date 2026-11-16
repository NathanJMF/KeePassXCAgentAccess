"""Start an offline agent execution host with only its scoped Keeper connection."""

import argparse
import os
import signal
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory, mkdtemp
from uuid import uuid4

from .command_action import executable_digest, stop_scope, syscall_filter, verify_scope_limits
from .isolated_runner import alter_acl, namespace, owned, prepare_socket, stage_runtime, subordinate_ids


HOST_MEMORY = 1024**3
HOST_TASKS = 128


def host_directory(directory):
    if directory.parent != Path("/var/tmp") or not directory.name.startswith("keeper-agent-host-"):
        raise ValueError("Use a dedicated agent host directory created by --prepare.")
    owned(directory)
    owned(directory / "broker")
    info = (directory / "broker" / "broker.sock").lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
        raise ValueError("The dedicated Keeper socket is unavailable.")
    return directory / "broker" / "broker.sock"


def prepare(uid):
    directory = Path(mkdtemp(prefix="keeper-agent-host-", dir="/var/tmp"))
    alter_acl(directory, "-m", f"u:{uid}:--x")
    prepare_socket(directory / "broker", uid)
    return directory


def require_pipes():
    for descriptor in (0, 1, 2):
        if not stat.S_ISFIFO(os.fstat(descriptor).st_mode):
            raise ValueError("Start the agent host from a trusted frontend using separate stdio pipes.")


def enter_scope(scope, command):
    try:
        verify_scope_limits(os.getpid(), scope, memory_limit=HOST_MEMORY, task_limit=HOST_TASKS)
        os.execv(command[0], command)
    except (OSError, ValueError) as error:
        raise SystemExit(f"Keeper did not start the isolated agent host. {error}") from None


def launch(directory, command, checkout, uid, gid):
    require_pipes()
    executable_digest(command)
    socket = host_directory(directory)
    scope = f"keeper-agent-host-{uuid4().hex}.scope"
    environment = {name: os.environ[name] for name in ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR")
                   if name in os.environ}
    with TemporaryDirectory(prefix="keeper-host-runtime-", dir="/var/tmp") as scratch:
        runtime = stage_runtime(checkout, Path(scratch)).parent
        # Retain namespace setup capabilities until Bubblewrap mounts the new root.
        # Bubblewrap drops all capabilities and disallows further user namespaces.
        with syscall_filter(unix_sockets=True, unix_socket_pairs=True) as seccomp:
            arguments = [
                "/usr/bin/systemd-run", "--user", "--scope", "--collect", "--quiet", "--expand-environment=no",
                f"--unit={scope}", "--property=RuntimeMaxSec=600s", "--property=TimeoutStopSec=1s",
                "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
                f"--property=MemoryMax={HOST_MEMORY}", "--property=MemorySwapMax=0",
                f"--property=TasksMax={HOST_TASKS}", "--property=CPUQuota=100%",
                "--", sys.executable, "-I", str(checkout / "src/keeper_bootstrap.py"),
                "keepassxc_agent_access.isolated_host", "--enter-scope", scope,
                "/usr/bin/prlimit", "--core=0:0", "--fsize=67108864:67108864", "--",
                *namespace(uid, gid, confined=False),
                "/usr/bin/setpriv", "--clear-groups", "--no-new-privs", "--", "/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--disable-userns",
                "--cap-drop", "ALL", "--hostname", "keeper-agent",
                "--new-session", "--die-with-parent", "--clearenv",
                "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
                "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
                "--proc", "/proc", "--dev", "/dev", "--size", "67108864", "--tmpfs", "/tmp",
                "--size", "67108864", "--tmpfs", "/work",
                "--size", "16777216", "--tmpfs", "/home/agent",
                "--ro-bind", str(runtime), "/keeper/runtime",
                "--ro-bind", str(socket), "/keeper/broker.sock",
                "--size", "1048576", "--perms", "0700", "--tmpfs", "/keeper/profile",
                "--remount-ro", "/",
                "--setenv", "HOME", "/home/agent", "--setenv", "PATH", "/keeper/runtime:/usr/bin:/bin",
                "--setenv", "KEEPASSXC_AGENT_SOCKET", "/keeper/broker.sock",
                "--setenv", "KEEPASSXC_AGENT_TOKEN_FILE", "/keeper/profile/token",
                "--chdir", "/work", "--seccomp", str(seccomp), "--", *command,
            ]
            process = subprocess.Popen(arguments, cwd="/", env=environment, pass_fds=(seccomp,),
                                       start_new_session=True)
            try:
                return process.wait(timeout=620)
            finally:
                if process.poll() is None:
                    stop_scope(scope, environment)
                    if process.poll() is None:
                        process.kill()
                    process.wait()


def main():
    if sys.argv[1:2] == ["--enter-scope"]:
        enter_scope(sys.argv[2], sys.argv[3:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true", help="Create a private host directory and broker endpoint")
    parser.add_argument("--directory", type=Path, help="Host directory from --prepare")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="The complete offline agent process to run")
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        uid, gid = subordinate_ids()
        if args.prepare and args.directory is None and not command:
            print(prepare(uid))
            return 0
        if args.prepare or args.directory is None or not command:
            raise ValueError("Use --prepare, or supply --directory and an installed command.")
        def interrupted(signum, _):
            raise SystemExit(128 + signum)

        for signum in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, interrupted)
        return launch(args.directory, command, Path(__file__).resolve().parents[2], uid, gid)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Keeper could not start the agent host. {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
