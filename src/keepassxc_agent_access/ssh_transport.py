"""Strict OpenSSH transport, host key verification, and output scrubbing."""

from __future__ import annotations

import base64
import binascii
from contextlib import ExitStack, contextmanager
import hashlib
import os
from pathlib import Path
import re
import secrets
import selectors
import shlex
import signal
import socket
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Event, Thread
from time import monotonic
import urllib.parse

from .protocol import ListingError, sanitize_error_detail


MAX_UPLOAD_BYTES = 8 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 8 * 1024 * 1024

_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)
_PEM_TRUNCATED_RE = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*$", re.DOTALL)
_HEX_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_MODE_RE = re.compile(r"^[0-7]{3,4}$")

_KEY_PREFERENCE = {
    "ssh-ed25519": 0,
    "ecdsa-sha2-nistp256": 1,
    "ecdsa-sha2-nistp384": 2,
    "ecdsa-sha2-nistp521": 3,
    "rsa-sha2-512": 4,
    "rsa-sha2-256": 5,
    "ssh-rsa": 6,
}

_ASKPASS_SCRIPT = """#!/usr/bin/python3 -I
import os
import socket
import struct
import sys

sock_path = os.environ["KEEPER_SSH_ASKPASS_SOCK"]
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
    conn.settimeout(2)
    conn.connect(sock_path)
    header = b""
    while len(header) < 4:
        chunk = conn.recv(4 - len(header))
        if not chunk:
            sys.exit(1)
        header += chunk
    (length,) = struct.unpack("!I", header)
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            sys.exit(1)
        data.extend(chunk)
sys.stdout.buffer.write(bytes(data) + b"\\n")
sys.stdout.buffer.flush()
"""


class SshTransportError(Exception):
    """An SSH transport or host-key verification failure."""

    def __init__(self, code: str = "ssh_failed", detail: str | None = None):
        self.code = code
        self.detail = sanitize_error_detail(detail)
        super().__init__(self.detail or code)


def parse_ssh_fingerprint(value: str) -> str:
    """Parse a 64-char hex or OpenSSH SHA256:<base64> host-key fingerprint to lowercase hex."""
    if not isinstance(value, str):
        raise ValueError("Invalid SSH host key SHA-256 fingerprint.")
    if _HEX_FINGERPRINT_RE.fullmatch(value):
        return value
    if value.startswith("SHA256:"):
        b64_part = value[7:]
        if not b64_part or any(ch.isspace() for ch in b64_part):
            raise ValueError("Invalid SSH host key SHA-256 fingerprint.")
        padded = b64_part + "=" * (-len(b64_part) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("Invalid SSH host key SHA-256 fingerprint.") from None
        if len(raw) != 32:
            raise ValueError("Invalid SSH host key SHA-256 fingerprint.")
        return raw.hex()
    raise ValueError("Invalid SSH host key SHA-256 fingerprint.")


def format_ssh_fingerprint(hex_digest: str) -> str:
    """Format a 32-byte SHA-256 hex digest as an OpenSSH SHA256:<base64> fingerprint."""
    if not isinstance(hex_digest, str):
        raise ValueError("Invalid SSH host key SHA-256 fingerprint.")
    try:
        raw = bytes.fromhex(hex_digest)
    except ValueError:
        raise ValueError("Invalid SSH host key SHA-256 fingerprint.") from None
    if len(raw) != 32:
        raise ValueError("Invalid SSH host key SHA-256 fingerprint.")
    return "SHA256:" + base64.b64encode(raw).decode("ascii").rstrip("=")


def _validate_host(host: str) -> str:
    if (
        not isinstance(host, str)
        or not host
        or len(host) > 255
        or host.startswith("-")
        or any(ch.isspace() or ch in "\0\r\n[]/\\" for ch in host)
    ):
        raise ValueError("Invalid SSH host.")
    return host


def _validate_port(port: int) -> int:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid SSH port.")
    return port


def _validate_username(username: str) -> str:
    if (
        not isinstance(username, str)
        or not username
        or len(username.encode("utf-8")) > 1024
        or any(ch in username for ch in "\0\r\n")
    ):
        raise ValueError("Invalid SSH username.")
    return username


def _validate_known_hosts_line(known_hosts_line: str) -> str:
    if (
        not isinstance(known_hosts_line, str)
        or not known_hosts_line.strip()
        or any(ch in known_hosts_line for ch in "\0\r\n")
    ):
        raise ValueError("Invalid SSH known_hosts entry.")
    return known_hosts_line


def _validate_timeout(timeout: int | float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 120:
        raise ValueError("Invalid SSH timeout.")
    return float(timeout)


def _validate_command(command: str) -> str:
    if not isinstance(command, str) or not command or "\0" in command:
        raise ValueError("Invalid SSH command.")
    return command


def _validate_remote_path(remote_path: str) -> str:
    if (
        not isinstance(remote_path, str)
        or not remote_path
        or any(ch in remote_path for ch in "\0\r\n")
        or not all(ch.isprintable() for ch in remote_path)
    ):
        raise ValueError("Invalid remote path.")
    return remote_path


def probe_host_key(host: str, port: int = 22, *, timeout: int = 5) -> tuple[str, str, str]:
    """Probe an SSH server's host key via ssh-keyscan and return (known_hosts_line, hex, SHA256:...)."""
    _validate_host(host)
    _validate_port(port)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 60:
        raise ValueError("Invalid probe timeout.")

    try:
        proc = subprocess.run(
            ["/usr/bin/ssh-keyscan", "-T", str(timeout), "-p", str(port), host],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
            timeout=timeout + 5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SshTransportError("ssh_failed", detail=f"Timed out probing SSH host key for {host}:{port}.") from None
    except OSError as error:
        raise SshTransportError("ssh_failed", detail=f"Failed to probe SSH host key: {error}") from None

    stdout_text = proc.stdout.decode("utf-8", errors="replace")
    candidates: list[tuple[int, str, str, str]] = []
    for raw_line in stdout_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        key_type, key_b64 = parts[1], parts[2]
        try:
            blob = base64.b64decode(key_b64, validate=True)
        except (ValueError, binascii.Error):
            continue
        if not blob:
            continue
        rank = _KEY_PREFERENCE.get(key_type, 100)
        candidates.append((rank, key_type, key_b64, hashlib.sha256(blob).hexdigest()))

    if not candidates:
        stderr_detail = sanitize_error_detail(proc.stderr.decode("utf-8", errors="replace"))
        detail = stderr_detail or f"No SSH host key received from {host}:{port}."
        raise SshTransportError("ssh_failed", detail=detail)

    candidates.sort(key=lambda item: item[0])
    _, key_type, key_b64, sha256_hex = candidates[0]
    canonical_host = f"[{host}]:{port}" if port != 22 else host
    known_hosts_line = f"{canonical_host} {key_type} {key_b64}"
    return known_hosts_line, sha256_hex, format_ssh_fingerprint(sha256_hex)


def _secret_variants(forbidden: tuple[str, ...]) -> list[str]:
    variants: set[str] = set()
    for item in forbidden:
        if not isinstance(item, str) or len(item) < 4:
            continue
        variants.add(item)
        raw = item.encode("utf-8")
        b64 = base64.b64encode(raw).decode("ascii")
        variants.add(b64)
        stripped_b64 = b64.rstrip("=")
        if len(stripped_b64) >= 4:
            variants.add(stripped_b64)
        hex_lower = raw.hex()
        variants.add(hex_lower)
        variants.add(hex_lower.upper())
        variants.add(urllib.parse.quote(item, safe=""))
        variants.add(urllib.parse.quote_plus(item))
    return sorted(variants, key=len, reverse=True)


def scrub_output(text: str, forbidden: tuple[str, ...] = ()) -> str:
    """Strip terminal escapes, PEM private keys, forbidden secrets, and control chars."""
    if not isinstance(text, str):
        return ""
    cleaned = _CSI_RE.sub("", text)
    cleaned = _OSC_RE.sub("", cleaned)
    cleaned = _PEM_BLOCK_RE.sub("[REDACTED]", cleaned)
    cleaned = _PEM_TRUNCATED_RE.sub("[REDACTED]", cleaned)

    variants = _secret_variants(forbidden)
    if variants:
        pattern = re.compile("|".join(re.escape(variant) for variant in variants))
        cleaned = pattern.sub("[REDACTED]", cleaned)

    return "".join(ch for ch in cleaned if ch in "\n\r\t" or ch.isprintable())


def _contains_forbidden_bytes(raw: bytes, forbidden: tuple[str, ...]) -> bool:
    if not raw:
        return False
    decoded = raw.decode("utf-8", errors="ignore")
    for variant in _secret_variants(forbidden):
        if variant in decoded or variant.encode("utf-8") in raw:
            return True
    return False


@contextmanager
def _askpass_helper(tmpdir: Path, secret: str):
    """Serve an SSH password or passphrase over a private Unix socket up to two prompts."""
    askpass_path = tmpdir / "askpass.py"
    python_bin = "/usr/bin/python3" if os.access("/usr/bin/python3", os.X_OK) else sys.executable
    script = _ASKPASS_SCRIPT.replace("#!/usr/bin/python3 -I", f"#!{python_bin} -I", 1)
    askpass_path.write_text(script, encoding="utf-8")
    os.chmod(askpass_path, 0o700)

    sock_path = tmpdir / "askpass.sock"
    secret_bytes = secret.encode("utf-8")
    payload = struct.pack("!I", len(secret_bytes)) + secret_bytes
    stop = Event()

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(sock_path))
    os.chmod(sock_path, 0o600)
    listener.listen(2)
    listener.settimeout(0.2)

    def serve():
        served = 0
        try:
            while not stop.is_set() and served < 2:
                try:
                    client, _ = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                with client:
                    try:
                        client.settimeout(1.0)
                        client.sendall(payload)
                        served += 1
                    except OSError:
                        pass
        finally:
            try:
                listener.close()
            except OSError:
                pass

    thread = Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield askpass_path, sock_path
    finally:
        stop.set()
        try:
            listener.close()
        except OSError:
            pass
        thread.join(timeout=1.0)


def _kill_process(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=2.0)
    except (subprocess.TimeoutExpired, OSError):
        pass


def _close_stream(stream) -> None:
    if stream is not None:
        try:
            stream.close()
        except OSError:
            pass


def _run_ssh_raw(
    host: str,
    port: int,
    username: str,
    known_hosts_line: str,
    command: str,
    *,
    password: str = "",
    private_key: str | None = None,
    sudo_password: str | None = None,
    timeout: int | float = 30,
    guard=None,
    max_stdout: int = 32768,
    max_stderr: int = 16384,
    stdin_bytes: bytes | None = None,
) -> dict:
    _validate_host(host)
    _validate_port(port)
    _validate_username(username)
    _validate_known_hosts_line(known_hosts_line)
    _validate_command(command)
    timeout_sec = _validate_timeout(timeout)

    if private_key is None and not password:
        raise SshTransportError("ssh_failed", detail="SSH authentication requires a password or private key.")
    if sudo_password is not None and stdin_bytes is not None:
        raise ValueError("Cannot combine sudo password delivery with binary stdin upload.")
    if guard is not None and not guard():
        raise ListingError("revoked")

    if sudo_password is not None:
        nonce = secrets.token_hex(16)
        prompt_token = f"{nonce}:".encode("ascii")
        remote_cmd = f"/usr/bin/sudo -S -p {shlex.quote(nonce + ':')} -- /bin/sh -lc {shlex.quote(command)}"
    else:
        prompt_token = None
        remote_cmd = command

    use_askpass = bool(password)

    with TemporaryDirectory(prefix="keeper-ssh-", dir="/tmp") as tmpdir_str:
        tmpdir = Path(tmpdir_str)
        os.chmod(tmpdir, 0o700)

        kh_path = tmpdir / "known_hosts"
        kh_path.write_text(known_hosts_line.rstrip("\r\n") + "\n", encoding="utf-8")
        os.chmod(kh_path, 0o600)

        auth_args: list[str]
        if private_key is not None:
            key_path = tmpdir / "id_key"
            key_text = private_key if private_key.endswith("\n") else private_key + "\n"
            key_path.write_text(key_text, encoding="utf-8")
            os.chmod(key_path, 0o600)
            auth_args = [
                "-i",
                str(key_path),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PubkeyAuthentication=yes",
            ]
        else:
            auth_args = [
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "PreferredAuthentications=password,keyboard-interactive",
            ]

        ssh_cmd = [
            "/usr/bin/ssh",
            "-T",
            "-F",
            "/dev/null",
            "-o",
            f"BatchMode={'no' if use_askpass else 'yes'}",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={kh_path}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            *auth_args,
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-p",
            str(port),
            "-l",
            username,
            host,
            "--",
            remote_cmd,
        ]

        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": tmpdir_str,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

        with ExitStack() as stack:
            if use_askpass:
                askpass_path, sock_path = stack.enter_context(_askpass_helper(tmpdir, password))
                env["SSH_ASKPASS"] = str(askpass_path)
                env["SSH_ASKPASS_REQUIRE"] = "force"
                env["DISPLAY"] = "keeper"
                env["KEEPER_SSH_ASKPASS_SOCK"] = str(sock_path)

            proc = subprocess.Popen(
                ssh_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=tmpdir_str,
                start_new_session=True,
            )

            stdout_buf = bytearray()
            stderr_buf = bytearray()
            out_truncated = False
            err_truncated = False
            sudo_sent = False
            timed_out = False
            deadline = monotonic() + timeout_sec

            sel = selectors.DefaultSelector()
            stdin_view = memoryview(stdin_bytes) if stdin_bytes else None
            stdin_offset = 0
            stdin_open = False

            try:
                assert proc.stdout is not None and proc.stderr is not None and proc.stdin is not None
                os.set_blocking(proc.stdout.fileno(), False)
                os.set_blocking(proc.stderr.fileno(), False)
                sel.register(proc.stdout, selectors.EVENT_READ, data="stdout")
                sel.register(proc.stderr, selectors.EVENT_READ, data="stderr")

                if stdin_view is not None and len(stdin_view) > 0:
                    os.set_blocking(proc.stdin.fileno(), False)
                    sel.register(proc.stdin, selectors.EVENT_WRITE, data="stdin")
                    stdin_open = True
                elif sudo_password is None:
                    _close_stream(proc.stdin)
                else:
                    stdin_open = True

                while sel.get_map():
                    if guard is not None and not guard():
                        _kill_process(proc)
                        raise ListingError("revoked")
                    rem = deadline - monotonic()
                    if rem <= 0:
                        _kill_process(proc)
                        timed_out = True
                        break
                    events = sel.select(timeout=min(0.1, rem))
                    for key, _ in events:
                        tag = key.data
                        if tag == "stdin":
                            try:
                                written = os.write(key.fd, stdin_view[stdin_offset : stdin_offset + 65536])
                                stdin_offset += written
                                if stdin_offset >= len(stdin_view):
                                    sel.unregister(key.fileobj)
                                    _close_stream(proc.stdin)
                                    stdin_open = False
                            except BrokenPipeError:
                                sel.unregister(key.fileobj)
                                _close_stream(proc.stdin)
                                stdin_open = False
                            except BlockingIOError:
                                pass
                            continue

                        try:
                            chunk = os.read(key.fd, 65536)
                        except BlockingIOError:
                            continue
                        except OSError:
                            chunk = b""

                        if not chunk:
                            sel.unregister(key.fileobj)
                            _close_stream(key.fileobj)
                            continue

                        if tag == "stdout":
                            if len(stdout_buf) <= max_stdout:
                                take = max_stdout + 1 - len(stdout_buf)
                                stdout_buf.extend(chunk[:take])
                                if len(stdout_buf) > max_stdout:
                                    out_truncated = True
                                    del stdout_buf[max_stdout:]
                        else:
                            if prompt_token is not None and not sudo_sent:
                                stderr_buf.extend(chunk)
                                idx = stderr_buf.find(prompt_token)
                                if idx >= 0:
                                    del stderr_buf[idx : idx + len(prompt_token)]
                                    try:
                                        assert proc.stdin is not None
                                        proc.stdin.write(sudo_password.encode("utf-8") + b"\n")
                                        proc.stdin.flush()
                                    except OSError:
                                        pass
                                    _close_stream(proc.stdin)
                                    stdin_open = False
                                    sudo_sent = True
                                    if len(stderr_buf) > max_stderr:
                                        err_truncated = True
                                        del stderr_buf[max_stderr:]
                            elif len(stderr_buf) <= max_stderr:
                                take = max_stderr + 1 - len(stderr_buf)
                                stderr_buf.extend(chunk[:take])
                                if len(stderr_buf) > max_stderr:
                                    err_truncated = True
                                    del stderr_buf[max_stderr:]

                if stdin_open:
                    _close_stream(proc.stdin)

                if not timed_out:
                    rem = max(0.05, deadline - monotonic())
                    try:
                        proc.wait(timeout=rem)
                    except subprocess.TimeoutExpired:
                        _kill_process(proc)
                        timed_out = True
            finally:
                sel.close()
                if proc.poll() is None:
                    _kill_process(proc)
                _close_stream(proc.stdin)
                _close_stream(proc.stdout)
                _close_stream(proc.stderr)

            if guard is not None and not guard():
                raise ListingError("revoked")

            if len(stderr_buf) > max_stderr:
                err_truncated = True
                del stderr_buf[max_stderr:]

            return {
                "raw_stdout": bytes(stdout_buf[:max_stdout]),
                "raw_stderr": bytes(stderr_buf[:max_stderr]),
                "out_truncated": out_truncated,
                "err_truncated": err_truncated,
                "exit_code": None if timed_out else proc.returncode,
                "timed_out": timed_out,
            }


def _build_forbidden(password: str, sudo_password: str | None, private_key: str | None, forbidden: tuple[str, ...]) -> tuple[str, ...]:
    items: list[str] = []
    if password:
        items.append(password)
    if sudo_password:
        items.append(sudo_password)
    if private_key:
        items.extend(private_key.splitlines())
    items.extend(forbidden)
    return tuple(items)


def run_ssh_command(
    host: str,
    port: int,
    username: str,
    known_hosts_line: str,
    command: str,
    *,
    password: str = "",
    private_key: str | None = None,
    sudo_password: str | None = None,
    timeout: int = 30,
    guard=None,
    max_stdout: int = 32768,
    max_stderr: int = 16384,
    stdin_bytes: bytes | None = None,
    forbidden: tuple[str, ...] = (),
) -> dict:
    """Execute a command over OpenSSH with strict host-key verification and secret scrubbing."""
    raw = _run_ssh_raw(
        host,
        port,
        username,
        known_hosts_line,
        command,
        password=password,
        private_key=private_key,
        sudo_password=sudo_password,
        timeout=timeout,
        guard=guard,
        max_stdout=max_stdout,
        max_stderr=max_stderr,
        stdin_bytes=stdin_bytes,
    )
    all_forbidden = _build_forbidden(password, sudo_password, private_key, forbidden)
    clean_out = scrub_output(raw["raw_stdout"].decode("utf-8", errors="replace"), forbidden=all_forbidden)
    clean_err = scrub_output(raw["raw_stderr"].decode("utf-8", errors="replace"), forbidden=all_forbidden)
    truncated = raw["out_truncated"] or raw["err_truncated"]

    if raw["timed_out"]:
        return {
            "outcome": "failed",
            "exit_code": None,
            "stdout": clean_out,
            "stderr": clean_err,
            "truncated": truncated,
            "timed_out": True,
            "error_detail": f"SSH command timed out after {timeout}s.",
        }

    exit_code = raw["exit_code"]
    result = {
        "outcome": "succeeded" if exit_code == 0 else "failed",
        "exit_code": exit_code,
        "stdout": clean_out,
        "stderr": clean_err,
        "truncated": truncated,
        "timed_out": False,
    }
    if exit_code != 0 and not clean_out and clean_err:
        result["error_detail"] = sanitize_error_detail(clean_err)
    return result


def ssh_upload_bytes(
    host: str,
    port: int,
    username: str,
    known_hosts_line: str,
    remote_path: str,
    data: bytes,
    *,
    mode: str = "0600",
    password: str = "",
    private_key: str | None = None,
    timeout: int = 60,
    guard=None,
    forbidden: tuple[str, ...] = (),
) -> dict:
    """Upload bytes to a remote file via SSH stdin with strict permissions."""
    _validate_remote_path(remote_path)
    if not isinstance(mode, str) or not _MODE_RE.fullmatch(mode):
        raise ValueError("Invalid remote file mode.")
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("Invalid upload payload size.")
    payload = bytes(data)

    quoted_path = shlex.quote(remote_path)
    command = f"umask 077 && cat > {quoted_path} && chmod {mode} -- {quoted_path}"
    res = run_ssh_command(
        host,
        port,
        username,
        known_hosts_line,
        command,
        password=password,
        private_key=private_key,
        timeout=timeout,
        guard=guard,
        stdin_bytes=payload,
        forbidden=forbidden,
    )
    ok = res["outcome"] == "succeeded"
    error_detail = None
    if not ok:
        error_detail = res.get("error_detail") or sanitize_error_detail(res["stderr"]) or "SSH upload failed."
    return {
        "outcome": "succeeded" if ok else "failed",
        "bytes_written": len(payload) if ok else 0,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "exit_code": res["exit_code"],
        "error_detail": error_detail,
    }


def ssh_download_bytes(
    host: str,
    port: int,
    username: str,
    known_hosts_line: str,
    remote_path: str,
    *,
    max_bytes: int = 262144,
    encoding: str = "text",
    password: str = "",
    private_key: str | None = None,
    timeout: int = 60,
    guard=None,
    forbidden: tuple[str, ...] = (),
) -> dict:
    """Download up to max_bytes from a remote file via SSH, scrubbing or rejecting secret content."""
    _validate_remote_path(remote_path)
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_DOWNLOAD_BYTES:
        raise ValueError("Invalid download byte limit.")
    if encoding not in ("text", "base64"):
        raise ValueError("Invalid download encoding.")

    command = f"/usr/bin/head -c {max_bytes + 1} -- {shlex.quote(remote_path)}"
    raw = _run_ssh_raw(
        host,
        port,
        username,
        known_hosts_line,
        command,
        password=password,
        private_key=private_key,
        timeout=timeout,
        guard=guard,
        max_stdout=max_bytes,
    )
    all_forbidden = _build_forbidden(password, None, private_key, forbidden)

    if raw["timed_out"] or raw["exit_code"] != 0:
        clean_err = scrub_output(raw["raw_stderr"].decode("utf-8", errors="replace"), forbidden=all_forbidden)
        detail = f"SSH command timed out after {timeout}s." if raw["timed_out"] else (
            sanitize_error_detail(clean_err) or f"SSH download failed with exit code {raw['exit_code']}."
        )
        return {
            "outcome": "failed",
            "content": "",
            "bytes_read": 0,
            "truncated": False,
            "exit_code": raw["exit_code"],
            "error_detail": detail,
        }

    data = raw["raw_stdout"]
    if encoding == "base64":
        if _contains_forbidden_bytes(data, all_forbidden):
            raise SshTransportError(
                "ssh_failed",
                detail="Downloaded content contains a protected credential value.",
            )
        content = base64.b64encode(data).decode("ascii")
    else:
        content = scrub_output(data.decode("utf-8", errors="replace"), forbidden=all_forbidden)
        if len(content) > max_bytes:
            content = content[:max_bytes]

    return {
        "outcome": "succeeded",
        "content": content,
        "bytes_read": len(data),
        "truncated": raw["out_truncated"],
        "exit_code": raw["exit_code"],
        "error_detail": None,
    }
