"""Deliver a credential through stdin to an owner-approved local command."""

from contextlib import contextmanager, nullcontext
import ctypes
import errno
import json
from hashlib import file_digest
import os
import socket
import struct
from pathlib import Path
from select import select
import stat
import subprocess
from tempfile import TemporaryDirectory, TemporaryFile
from time import monotonic
from uuid import uuid4

from .command_network import network_relay
from .protocol import ListingError, read_frame, remaining, sanitize_error_detail, validate_command


_READY_TIMEOUT = 3
_COMMAND_TIMEOUT = 5
_SCOPE_TIMEOUT = 12
_NETWORK_TIMEOUT = 15
_NETWORK_SCOPE_TIMEOUT = 22
_MEMORY_LIMIT = 192 * 1024**2
_TASK_LIMIT = 64
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
def syscall_filter(unix_sockets=False, *, unix_socket_pairs=False):
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
            if (name == "socket" and unix_sockets) or (name == "socketpair" and unix_socket_pairs):
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


def _prepare_synthetic_etc(directory):
    directory.chmod(0o755)
    uid, gid = os.getuid(), os.getgid()
    files = {
        "passwd": f"keeper:x:{uid}:{gid}:Keeper:/tmp:/usr/bin/sh\n",
        "group": f"keeper:x:{gid}:\n",
        "nsswitch.conf": "passwd: files\ngroup: files\n",
    }
    services_path = Path("/etc/services")
    try:
        data = services_path.read_bytes()
        files["services"] = data if len(data) <= 1048576 else b"ssh 22/tcp\nhttp 80/tcp\nhttps 443/tcp\n"
    except OSError:
        files["services"] = b"ssh 22/tcp\nhttp 80/tcp\nhttps 443/tcp\n"
    for name, content in files.items():
        target = directory / name
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="ascii")
        target.chmod(0o644)


def sandbox_arguments(command, seccomp, scope, *, relay_path=None, prompt_variable="", input_path=None, ca_file=_CA,
                      generic_prompt=False, environment=(), prompt_contains="", etc_dir=None):
    lifetime = _NETWORK_SCOPE_TIMEOUT if relay_path is not None else _SCOPE_TIMEOUT
    fsize = 16777216 if relay_path is not None else 4194304
    arguments = [
        "/usr/bin/systemd-run", "--user", "--scope", "--collect", "--quiet", "--expand-environment=no",
        f"--unit={scope}", f"--property=RuntimeMaxSec={lifetime}s", "--property=TimeoutStopSec=1s",
        "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
        f"--property=MemoryMax={_MEMORY_LIMIT}", "--property=MemorySwapMax=0",
        f"--property=TasksMax={_TASK_LIMIT}", "--property=CPUQuota=100%",
        "--", "/usr/bin/prlimit", "--core=0:0", f"--fsize={fsize}:{fsize}", "--",
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
    if etc_dir is not None:
        for name in ("passwd", "group", "nsswitch.conf", "services"):
            candidate = Path(etc_dir) / name
            if candidate.is_file():
                arguments += ["--ro-bind", str(candidate), f"/etc/{name}"]
    if relay_path is None:
        return [*arguments, "--", "/usr/bin/python3", "-I", "-c", _SANDBOX_BOOTSTRAP, *command]
    arguments += [
        "--dir", "/keeper", "--ro-bind", str(relay_path), "/keeper/relay",
        "--ro-bind", str(Path(__file__).with_name("command_prompt.py")), "/keeper/prompt",
        "--ro-bind", str(ca_file), "/keeper/trust.pem",
        "--ro-bind", str(ca_file), "/etc/ssl/certs/ca-certificates.crt",
    ]
    if input_path is not None:
        arguments += ["--ro-bind", str(input_path), "/input"]
    if generic_prompt:
        return [*arguments, "--", "/keeper/prompt", "--launch-generic", prompt_variable,
                prompt_contains or "password", json.dumps(dict(environment), separators=(",", ":")), *command]
    return [*arguments, "--", "/keeper/prompt", "--launch", prompt_variable, *command]


def verify_scope_limits(pid, scope, *, memory_limit=_MEMORY_LIMIT, task_limit=_TASK_LIMIT):
    lines = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    relative = next((line[4:] for line in lines if line.startswith("0::/")), "")
    location = Path(relative)
    if location.name != scope or ".." in location.parts:
        actual = sanitize_error_detail(relative) or "missing"
        raise OSError(f"The command is not in its isolated process scope ({actual} != {scope}).")
    directory = Path("/sys/fs/cgroup") / location
    try:
        memory = int((directory / "memory.max").read_text())
        swap = int((directory / "memory.swap.max").read_text())
        tasks = int((directory / "pids.max").read_text())
        quota, period = map(int, (directory / "cpu.max").read_text().split())
    except (OSError, ValueError) as error:
        detail = sanitize_error_detail(str(error))
        message = (f"The command scope's resource limits are unavailable: {detail}"
                   if detail else "The command scope's resource limits are unavailable.")
        raise OSError(message) from None
    problems = []
    if not 0 < memory <= memory_limit:
        problems.append(f"memory.max={memory}")
    if swap != 0:
        problems.append(f"memory.swap.max={swap}")
    if not 0 < tasks <= task_limit:
        problems.append(f"pids.max={tasks}")
    if not 0 < quota <= period:
        problems.append(f"cpu.max={quota}/{period}")
    if problems:
        raise OSError(f"The command scope's resource limits are unavailable: {', '.join(problems)}")


def stop_scope(scope, environment):
    try:
        subprocess.run(["/usr/bin/systemctl", "--user", "stop", scope], timeout=2, check=False,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, cwd="/", env=environment)
    except (OSError, subprocess.TimeoutExpired):
        # RuntimeMaxSec independently bounds the lifetime of the scope.
        pass


@contextmanager
def prepare_command(command, digest, *, destination=None, prompt_variable="", input_path=None, ca_file=None,
                    generic_prompt=False, environment=(), prompt_contains=""):
    if executable_digest(command) != digest:
        raise ValueError("The configured command executable changed.")
    resolved = str(Path(command[0]).resolve(strict=True))
    resolved_command = (resolved, *command[1:])
    scope = f"keeper-command-{uuid4().hex}.scope"
    relay_context = network_relay(destination) if destination is not None else nullcontext((None, None))
    with syscall_filter(unix_sockets=destination is not None, unix_socket_pairs=True) as seccomp, \
            relay_context as (relay_path, relay), \
            TemporaryDirectory(prefix="keeper-etc-") as etc_dir:
        _prepare_synthetic_etc(Path(etc_dir))
        # The session address is needed only by systemd-run. Bubblewrap drops
        # that environment before the trusted startup code runs.
        launcher_environment = {name: os.environ[name] for name in ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR")
                       if name in os.environ}
        # A custom CA comes only from trusted owner startup, as for HTTPS actions.
        trust = Path(ca_file or os.environ.get("SSL_CERT_FILE") or _CA)
        arguments = sandbox_arguments(resolved_command, seccomp, scope, relay_path=relay_path,
                                      prompt_variable=prompt_variable, input_path=input_path, ca_file=trust,
                                      generic_prompt=generic_prompt, environment=environment, prompt_contains=prompt_contains,
                                      etc_dir=etc_dir)
        with TemporaryFile("w+b") as startup_stderr:
            process = subprocess.Popen(arguments,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=startup_stderr, cwd="/", env=launcher_environment,
                                       start_new_session=True, pass_fds=(seccomp,))
            readiness = process.stdout
            deadline = monotonic() + _READY_TIMEOUT

            def read(size):
                fd = readiness.fileno()
                if not select([fd], [], [], remaining(deadline))[0]:
                    raise TimeoutError
                return os.read(fd, min(size, 1))

            def startup_detail():
                startup_stderr.seek(0)
                return sanitize_error_detail(startup_stderr.read(1024).decode("utf-8", "replace"))

            try:
                try:
                    try:
                        ready = read_frame(read, len(_READY) + 1)
                    except (EOFError, TimeoutError, ValueError, ListingError) as error:
                        detail = startup_detail()
                        message = (f"The isolated command sandbox did not start: {detail}"
                                   if detail else "The isolated command sandbox did not start.")
                        raise OSError(message) from error
                    if ready != _READY:
                        detail = startup_detail()
                        message = (f"The isolated command sandbox did not start: {detail}"
                                   if detail else "The isolated command sandbox did not start.")
                        raise OSError(message)
                finally:
                    # Close pre-dispatch stderr before scope verification or yielding to deliver credentials.
                    startup_stderr.close()
                verify_scope_limits(process.pid, scope)
                readiness.close()
                process.stdout = None
                yield process if relay is None else (process, relay)
            finally:
                # Stop the full cgroup even when its original process already
                # exited, so a forked descendant cannot outlive this use.
                stop_scope(scope, launcher_environment)
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
