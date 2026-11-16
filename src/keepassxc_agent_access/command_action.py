"""Deliver a credential through stdin to an owner-approved local command."""

from contextlib import contextmanager, nullcontext
import ctypes
import errno
from hashlib import file_digest
import os
import socket
import struct
from pathlib import Path
from select import select
import stat
import subprocess
from time import monotonic
from uuid import uuid4

from .command_network import network_relay
from .protocol import ListingError, read_frame, remaining, validate_command


_READY_TIMEOUT = 3
_COMMAND_TIMEOUT = 5
_SCOPE_TIMEOUT = 12
_NETWORK_TIMEOUT = 15
_NETWORK_SCOPE_TIMEOUT = 22
_MEMORY_LIMIT = 192 * 1024**2
_TASK_LIMIT = 16
_SECRET_LIMIT = 65536
_PROMPT_SECRET_LIMIT = 4096
_CA = Path('/etc/ssl/certs/ca-certificates.crt')
_READY = b"keeper-ready\n"
_START = b"\x01"
_SANDBOX_BOOTSTRAP = """import os
import socket
import struct
import sys

null = os.open("/dev/null", os.O_WRONLY)
os.dup2(null, 2)
os.write(1, b"keeper-ready\\n")
os.dup2(null, 1)
os.close(null)
if os.read(0, 1) == b"\\x01":
    os.execv(sys.argv[1], sys.argv[1:])
sys.exit(1)
"""

# The isolated network namespace is mandatory. Block socket access as well so
# the command cannot use other socket families or any mounted Unix socket.
_BLOCKED_SYSCALLS = (
    "socket", "socketpair", "unshare", "setns", "mount", "mount_setattr",
    "umount2", "pivot_root", "move_mount", "open_tree", "fsopen", "fsmount",
    "fspick", "fsconfig", "ptrace", "process_vm_readv", "process_vm_writev",
    "pidfd_getfd", "open_by_handle_at", "name_to_handle_at", "keyctl",
    "add_key", "request_key", "bpf", "perf_event_open", "io_uring_setup",
    "io_uring_enter", "io_uring_register", "userfaultfd",
)


def executable_digest(command):
    command = validate_command(command)
    try:
        resolved = Path(command[0]).resolve(strict=True)
        if not resolved.is_relative_to("/usr"):
            raise ValueError
        for parent in (resolved.parent, *resolved.parent.parents):
            info = parent.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError
        info = resolved.stat()
        if (info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022
                or not info.st_mode & 0o111):
            raise ValueError
        with resolved.open("rb") as binary:
            return file_digest(binary, "sha256").hexdigest()
    except (OSError, RuntimeError, ValueError):
        raise ValueError("Choose a trusted system executable in /usr/bin.") from None


@contextmanager
def syscall_filter(unix_sockets=False):
    seccomp = ctypes.CDLL("libseccomp.so.2")
    seccomp.seccomp_init.argtypes = (ctypes.c_uint32,)
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_release.argtypes = (ctypes.c_void_p,)
    seccomp.seccomp_syscall_resolve_name.argtypes = (ctypes.c_char_p,)
    seccomp.seccomp_rule_add.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint)
    seccomp.seccomp_export_bpf.argtypes = (ctypes.c_void_p, ctypes.c_int)
    class Compare(ctypes.Structure):
        _fields_ = (("arg", ctypes.c_uint), ("op", ctypes.c_uint),
                    ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64))
    seccomp.seccomp_rule_add_array.argtypes = (
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(Compare),
    )
    context = seccomp.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        raise OSError("Could not initialize the command syscall filter.")
    try:
        denied = 0x00050000 | errno.EPERM  # SCMP_ACT_ERRNO(EPERM)
        for name in _BLOCKED_SYSCALLS:
            number = seccomp.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number < 0:
                raise OSError("Could not compile the command syscall filter.")
            if name == "socket" and unix_sockets:
                comparison = Compare(0, 1, socket.AF_UNIX, 0)  # SCMP_CMP_NE
                result = seccomp.seccomp_rule_add_array(context, denied, number, 1, ctypes.byref(comparison))
            else:
                result = seccomp.seccomp_rule_add(context, denied, number, 0)
            if result != 0:
                raise OSError("Could not compile the command syscall filter.")
        descriptor = os.memfd_create("keeper-command-seccomp", os.MFD_CLOEXEC)
        try:
            if seccomp.seccomp_export_bpf(context, descriptor) != 0:
                raise OSError("Could not export the command syscall filter.")
            os.lseek(descriptor, 0, os.SEEK_SET)
            yield descriptor
        finally:
            os.close(descriptor)
    finally:
        seccomp.seccomp_release(context)


def sandbox_arguments(command, seccomp, scope, *, relay_path=None, prompt_variable="", input_path=None, ca_file=_CA):
    lifetime = _NETWORK_SCOPE_TIMEOUT if relay_path is not None else _SCOPE_TIMEOUT
    arguments = [
        "/usr/bin/systemd-run", "--user", "--scope", "--collect", "--quiet", "--expand-environment=no",
        f"--unit={scope}", f"--property=RuntimeMaxSec={lifetime}s", "--property=TimeoutStopSec=1s",
        "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
        f"--property=MemoryMax={_MEMORY_LIMIT}", "--property=MemorySwapMax=0",
        f"--property=TasksMax={_TASK_LIMIT}", "--property=CPUQuota=100%",
        "--", "/usr/bin/prlimit", "--core=0:0", "--fsize=4194304:4194304", "--",
        "/usr/bin/setpriv", "--no-new-privs", "--",
        "/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--disable-userns",
        "--new-session", "--die-with-parent", "--clearenv", "--cap-drop", "ALL",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64", "--dev", "/dev",
        "--size", "16777216" if relay_path is not None else "4194304",
        "--tmpfs", "/tmp", "--setenv", "HOME", "/tmp", "--chdir", "/tmp",
        "--seccomp", str(seccomp),
    ]
    if relay_path is None:
        return [*arguments, "--", "/usr/bin/python3", "-I", "-c", _SANDBOX_BOOTSTRAP, *command]
    arguments += [
        "--dir", "/keeper", "--ro-bind", str(relay_path), "/keeper/relay",
        "--ro-bind", str(Path(__file__).with_name("command_prompt.py")), "/keeper/prompt",
        "--ro-bind", str(ca_file), "/keeper/trust.pem",
    ]
    if input_path is not None:
        arguments += ["--ro-bind", str(input_path), "/input"]
    return [*arguments, "--", "/keeper/prompt", "--launch", prompt_variable, *command]


def verify_scope_limits(pid, scope):
    lines = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    relative = next((line[4:] for line in lines if line.startswith("0::/")), "")
    location = Path(relative)
    if location.name != scope or ".." in location.parts:
        raise OSError("The command is not in its isolated process scope.")
    directory = Path("/sys/fs/cgroup") / location
    try:
        memory = int((directory / "memory.max").read_text())
        swap = int((directory / "memory.swap.max").read_text())
        tasks = int((directory / "pids.max").read_text())
        quota, period = map(int, (directory / "cpu.max").read_text().split())
        if not (0 < memory <= _MEMORY_LIMIT and swap == 0 and 0 < tasks <= _TASK_LIMIT and 0 < quota <= period):
            raise ValueError
    except (OSError, ValueError):
        raise OSError("The command scope's resource limits are unavailable.") from None


def stop_scope(scope, environment):
    try:
        subprocess.run(["/usr/bin/systemctl", "--user", "stop", scope], timeout=2, check=False,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, cwd="/", env=environment)
    except (OSError, subprocess.TimeoutExpired):
        # RuntimeMaxSec independently bounds the lifetime of the scope.
        pass


@contextmanager
def prepare_command(command, digest, *, destination=None, prompt_variable="", input_path=None, ca_file=None):
    if executable_digest(command) != digest:
        raise ValueError("The configured command executable changed.")
    scope = f"keeper-command-{uuid4().hex}.scope"
    relay_context = network_relay(destination) if destination is not None else nullcontext((None, None))
    with syscall_filter(unix_sockets=destination is not None) as seccomp, relay_context as (relay_path, relay):
        # The session address is needed only by systemd-run. Bubblewrap drops
        # that environment before the trusted startup code runs.
        environment = {name: os.environ[name] for name in ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR")
                       if name in os.environ}
        # A custom CA comes only from trusted owner startup, as for HTTPS actions.
        trust = Path(ca_file or os.environ.get("SSL_CERT_FILE") or _CA)
        arguments = sandbox_arguments(command, seccomp, scope, relay_path=relay_path,
                                      prompt_variable=prompt_variable, input_path=input_path, ca_file=trust)
        process = subprocess.Popen(arguments,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, cwd="/", env=environment,
                                   start_new_session=True, pass_fds=(seccomp,))
        readiness = process.stdout
        deadline = monotonic() + _READY_TIMEOUT

        def read(size):
            fd = readiness.fileno()
            if not select([fd], [], [], remaining(deadline))[0]:
                raise TimeoutError
            return os.read(fd, min(size, 1))

        try:
            try:
                ready = read_frame(read, len(_READY) + 1)
            except (EOFError, TimeoutError, ValueError, ListingError) as error:
                raise OSError("The isolated command sandbox did not start.") from error
            if ready != _READY:
                raise OSError("The isolated command sandbox did not start.")
            verify_scope_limits(process.pid, scope)
            readiness.close()
            process.stdout = None
            yield process if relay is None else (process, relay)
        finally:
            if process.poll() is None:
                stop_scope(scope, environment)
                if process.poll() is None:
                    process.kill()
            process.wait()
            process.stdin.close()
            readiness.close()


def deliver_credential(process, secret):
    if not isinstance(secret, str) or not 0 < len(secret) <= _SECRET_LIMIT:
        return False
    data = secret.encode("utf-8")
    if len(data) > _SECRET_LIMIT:
        return False
    try:
        process.communicate(input=_START + data, timeout=_COMMAND_TIMEOUT)
        return process.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def deliver_prompt(job, secret):
    process, relay = job
    if not isinstance(secret, str) or not 0 < len(secret) <= _PROMPT_SECRET_LIMIT:
        return "failed"
    data = secret.encode("utf-8")
    if len(data) > _PROMPT_SECRET_LIMIT or any(value in data for value in (b"\0", b"\r", b"\n")):
        return "failed"
    relay.active.set()
    try:
        process.communicate(input=_START + struct.pack("!H", len(data)) + data, timeout=_NETWORK_TIMEOUT)
        if process.returncode == 0:
            return "succeeded"
    except (OSError, subprocess.TimeoutExpired):
        pass
    finally:
        relay.stop()
    return "uncertain" if relay.transferred.is_set() else "failed"
