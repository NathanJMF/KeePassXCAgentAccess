"""Real RFC 4253 / 4252 / 4254 SSH2 test server fixture using cryptography."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import os
from queue import Empty, Queue
import re
import shlex
import socket
import struct
from threading import Event, Lock, Thread
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


SSH_MSG_DISCONNECT = 1
SSH_MSG_IGNORE = 2
SSH_MSG_UNIMPLEMENTED = 3
SSH_MSG_DEBUG = 4
SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_SERVICE_ACCEPT = 6
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEX_ECDH_INIT = 30
SSH_MSG_KEX_ECDH_REPLY = 31
SSH_MSG_USERAUTH_REQUEST = 50
SSH_MSG_USERAUTH_FAILURE = 51
SSH_MSG_USERAUTH_SUCCESS = 52
SSH_MSG_USERAUTH_PK_OK = 60
SSH_MSG_GLOBAL_REQUEST = 80
SSH_MSG_REQUEST_SUCCESS = 81
SSH_MSG_REQUEST_FAILURE = 82
SSH_MSG_CHANNEL_OPEN = 90
SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
SSH_MSG_CHANNEL_OPEN_FAILURE = 92
SSH_MSG_CHANNEL_WINDOW_ADJUST = 93
SSH_MSG_CHANNEL_DATA = 94
SSH_MSG_CHANNEL_EXTENDED_DATA = 95
SSH_MSG_CHANNEL_EOF = 96
SSH_MSG_CHANNEL_CLOSE = 97
SSH_MSG_CHANNEL_REQUEST = 98
SSH_MSG_CHANNEL_SUCCESS = 99
SSH_MSG_CHANNEL_FAILURE = 100

SERVER_BANNER = b"SSH-2.0-KeeperTestSSH_1.0"


def ssh_string(data: bytes) -> bytes:
    return struct.pack("!I", len(data)) + data


def ssh_mpint(raw: bytes) -> bytes:
    stripped = raw.lstrip(b"\x00")
    if stripped and (stripped[0] & 0x80):
        stripped = b"\x00" + stripped
    return ssh_string(stripped)


def parse_string(buf: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(buf):
        raise ValueError("Truncated SSH string length")
    (length,) = struct.unpack_from("!I", buf, offset)
    offset += 4
    if offset + length > len(buf):
        raise ValueError("Truncated SSH string body")
    return buf[offset : offset + length], offset + length


def parse_uint32(buf: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(buf):
        raise ValueError("Truncated SSH uint32")
    (val,) = struct.unpack_from("!I", buf, offset)
    return val, offset + 4


def parse_bool(buf: bytes, offset: int) -> tuple[bool, int]:
    if offset + 1 > len(buf):
        raise ValueError("Truncated SSH boolean")
    return buf[offset] != 0, offset + 1


def parse_openssh_pubkey_line(line: str) -> bytes:
    parts = line.strip().split()
    if len(parts) < 2:
        raise ValueError("Invalid OpenSSH public key line")
    return base64.b64decode(parts[1], validate=True)


def _derive_key(k_mpint: bytes, h_digest: bytes, letter: bytes, session_id: bytes, size: int) -> bytes:
    out = hashlib.sha256(k_mpint + h_digest + letter + session_id).digest()
    while len(out) < size:
        out += hashlib.sha256(k_mpint + h_digest + out).digest()
    return out[:size]


class _PacketTransport:
    """RFC 4253 binary packet reader/writer with aes256-ctr + hmac-sha2-256."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.c2s_seq = 0
        self.s2c_seq = 0
        self.decryptor = None
        self.encryptor = None
        self.mac_c2s: bytes | None = None
        self.mac_s2c: bytes | None = None
        self.send_lock = Lock()

    def recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("SSH socket closed")
            buf.extend(chunk)
        return bytes(buf)

    def read_banner(self) -> bytes:
        buf = bytearray()
        while len(buf) < 255:
            ch = self.sock.recv(1)
            if not ch:
                raise EOFError("Client closed before sending SSH banner")
            if ch == b"\n":
                line = bytes(buf).rstrip(b"\r")
                if line.startswith(b"SSH-2.0-"):
                    return line
                buf.clear()
                continue
            buf.extend(ch)
        raise ValueError("SSH banner too long")

    def read_packet(self) -> bytes:
        if self.decryptor is None:
            first_4 = self.recv_exact(4)
            (pkt_len,) = struct.unpack("!I", first_4)
            if pkt_len < 2 or pkt_len > 65536:
                raise ValueError(f"Invalid unencrypted SSH packet length: {pkt_len}")
            rest = self.recv_exact(pkt_len)
            pad_len = rest[0]
            payload = rest[1 : pkt_len - pad_len]
            self.c2s_seq = (self.c2s_seq + 1) & 0xFFFFFFFF
            return payload

        first_block = self.decryptor.update(self.recv_exact(16))
        (pkt_len,) = struct.unpack("!I", first_block[:4])
        if pkt_len < 12 or pkt_len > 65536:
            raise ValueError(f"Invalid encrypted SSH packet length: {pkt_len}")
        remaining_len = (4 + pkt_len) - 16
        rest_plain = self.decryptor.update(self.recv_exact(remaining_len)) if remaining_len > 0 else b""
        packet_bytes = first_block + rest_plain
        mac_received = self.recv_exact(32)
        assert self.mac_c2s is not None
        expected_mac = hmac.new(
            self.mac_c2s,
            struct.pack("!I", self.c2s_seq) + packet_bytes,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(mac_received, expected_mac):
            raise ValueError("SSH MAC verification failed")
        self.c2s_seq = (self.c2s_seq + 1) & 0xFFFFFFFF
        pad_len = packet_bytes[4]
        return packet_bytes[5 : 4 + pkt_len - pad_len]

    def send_packet(self, payload: bytes) -> None:
        with self.send_lock:
            block_size = 16 if self.encryptor is not None else 8
            pad_len = block_size - ((5 + len(payload)) % block_size)
            if pad_len < 4:
                pad_len += block_size
            pkt_len = 1 + len(payload) + pad_len
            packet_bytes = struct.pack("!IB", pkt_len, pad_len) + payload + os.urandom(pad_len)
            if self.encryptor is not None:
                assert self.mac_s2c is not None
                mac = hmac.new(
                    self.mac_s2c,
                    struct.pack("!I", self.s2c_seq) + packet_bytes,
                    hashlib.sha256,
                ).digest()
                wire = self.encryptor.update(packet_bytes) + mac
            else:
                wire = packet_bytes
            self.s2c_seq = (self.s2c_seq + 1) & 0xFFFFFFFF
            self.sock.sendall(wire)

    def activate_keys(self, k_mpint: bytes, h_digest: bytes, session_id: bytes) -> None:
        iv_c2s = _derive_key(k_mpint, h_digest, b"A", session_id, 16)
        iv_s2c = _derive_key(k_mpint, h_digest, b"B", session_id, 16)
        key_c2s = _derive_key(k_mpint, h_digest, b"C", session_id, 32)
        key_s2c = _derive_key(k_mpint, h_digest, b"D", session_id, 32)
        self.mac_c2s = _derive_key(k_mpint, h_digest, b"E", session_id, 32)
        self.mac_s2c = _derive_key(k_mpint, h_digest, b"F", session_id, 32)
        self.decryptor = Cipher(algorithms.AES(key_c2s), modes.CTR(iv_c2s)).decryptor()
        self.encryptor = Cipher(algorithms.AES(key_s2c), modes.CTR(iv_s2c)).encryptor()


@dataclass
class SshTestServer:
    """In-process RFC 4253/4252/4254 SSH2 server supporting real OpenSSH clients."""

    username: str = "keeper"
    password: str | None = "ssh-pass-secret"
    sudo_password: str | None = "sudo-pass-secret"
    authorized_pubkeys: list[bytes] = field(default_factory=list)
    exec_handler: Callable[[str, Queue[bytes | None], Callable[[bytes], None], Callable[[bytes], None]], int] | None = None

    def __post_init__(self) -> None:
        self._host_priv = Ed25519PrivateKey.generate()
        pub_raw = self._host_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.host_key_blob = ssh_string(b"ssh-ed25519") + ssh_string(pub_raw)
        self.host_key_b64 = base64.b64encode(self.host_key_blob).decode("ascii")
        self.fingerprint_bytes = hashlib.sha256(self.host_key_blob).digest()
        self.fingerprint_hex = self.fingerprint_bytes.hex()
        self.fingerprint_sha256 = "SHA256:" + base64.b64encode(self.fingerprint_bytes).decode("ascii").rstrip("=")

        self.files: dict[str, tuple[bytes, str]] = {}
        self.executed_commands: list[str] = []
        self.auth_attempts: list[tuple[str, str, bool]] = []
        self._stop = Event()
        self._sock: socket.socket | None = None
        self._thread: Thread | None = None
        self.host = "127.0.0.1"
        self.port = 0

    @property
    def known_hosts_line(self) -> str:
        target = f"[{self.host}]:{self.port}" if self.port != 22 else self.host
        return f"{target} ssh-ed25519 {self.host_key_b64}"

    def add_authorized_pubkey_line(self, line: str) -> None:
        self.authorized_pubkeys.append(parse_openssh_pubkey_line(line))

    def start(self) -> "SshTestServer":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, 0))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self._thread = Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def __enter__(self) -> "SshTestServer":
        return self.start()

    def __exit__(self, *_) -> None:
        self.stop()

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            Thread(target=self._handle_connection, args=(conn,), daemon=True).start()

    def _build_kexinit(self) -> bytes:
        def namelist(val: bytes) -> bytes:
            return ssh_string(val)

        return (
            bytes([SSH_MSG_KEXINIT])
            + os.urandom(16)
            + namelist(b"curve25519-sha256")
            + namelist(b"ssh-ed25519")
            + namelist(b"aes256-ctr")
            + namelist(b"aes256-ctr")
            + namelist(b"hmac-sha2-256")
            + namelist(b"hmac-sha2-256")
            + namelist(b"none")
            + namelist(b"none")
            + namelist(b"")
            + namelist(b"")
            + bytes([0])
            + struct.pack("!I", 0)
        )

    def _handle_connection(self, sock: socket.socket) -> None:
        try:
            sock.settimeout(10.0)
            transport = _PacketTransport(sock)
            sock.sendall(SERVER_BANNER + b"\r\n")
            client_banner = transport.read_banner()

            server_kexinit = self._build_kexinit()
            transport.send_packet(server_kexinit)
            client_kexinit = transport.read_packet()
            if not client_kexinit or client_kexinit[0] != SSH_MSG_KEXINIT:
                return

            ecdh_init = transport.read_packet()
            if not ecdh_init or ecdh_init[0] != SSH_MSG_KEX_ECDH_INIT:
                return
            q_c, _ = parse_string(ecdh_init, 1)
            eph_priv = X25519PrivateKey.generate()
            q_s = eph_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            shared_secret = eph_priv.exchange(X25519PublicKey.from_public_bytes(q_c))
            k_mpint = ssh_mpint(shared_secret)

            h_input = (
                ssh_string(client_banner)
                + ssh_string(SERVER_BANNER)
                + ssh_string(client_kexinit)
                + ssh_string(server_kexinit)
                + ssh_string(self.host_key_blob)
                + ssh_string(q_c)
                + ssh_string(q_s)
                + k_mpint
            )
            h_digest = hashlib.sha256(h_input).digest()
            session_id = h_digest
            sig_raw = self._host_priv.sign(h_digest)
            sig_blob = ssh_string(b"ssh-ed25519") + ssh_string(sig_raw)

            transport.send_packet(
                bytes([SSH_MSG_KEX_ECDH_REPLY])
                + ssh_string(self.host_key_blob)
                + ssh_string(q_s)
                + ssh_string(sig_blob)
            )
            transport.send_packet(bytes([SSH_MSG_NEWKEYS]))

            newkeys = transport.read_packet()
            if not newkeys or newkeys[0] != SSH_MSG_NEWKEYS:
                return
            transport.activate_keys(k_mpint, h_digest, session_id)

            # Service request
            svc_req = transport.read_packet()
            if not svc_req or svc_req[0] != SSH_MSG_SERVICE_REQUEST:
                return
            svc_name, _ = parse_string(svc_req, 1)
            if svc_name != b"ssh-userauth":
                return
            transport.send_packet(bytes([SSH_MSG_SERVICE_ACCEPT]) + ssh_string(b"ssh-userauth"))

            # Userauth loop
            if not self._run_userauth(transport, session_id):
                return

            # Connection protocol
            self._run_connection(transport)
        except (EOFError, OSError, ValueError):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _run_userauth(self, transport: _PacketTransport, session_id: bytes) -> bool:
        methods = []
        if self.authorized_pubkeys:
            methods.append("publickey")
        if self.password is not None:
            methods.append("password")
        method_list = ",".join(methods or ["publickey", "password"]).encode("ascii")

        while True:
            pkt = transport.read_packet()
            if not pkt:
                return False
            if pkt[0] in (SSH_MSG_IGNORE, SSH_MSG_DEBUG):
                continue
            if pkt[0] == SSH_MSG_DISCONNECT:
                return False
            if pkt[0] != SSH_MSG_USERAUTH_REQUEST:
                return False

            username_b, off = parse_string(pkt, 1)
            service_b, off = parse_string(pkt, off)
            method_b, off = parse_string(pkt, off)
            username = username_b.decode("utf-8", errors="replace")
            method = method_b.decode("ascii", errors="replace")

            if service_b != b"ssh-connection":
                transport.send_packet(bytes([SSH_MSG_USERAUTH_FAILURE]) + ssh_string(method_list) + bytes([0]))
                continue

            if method == "none":
                self.auth_attempts.append((username, "none", False))
                transport.send_packet(bytes([SSH_MSG_USERAUTH_FAILURE]) + ssh_string(method_list) + bytes([0]))
                continue

            if method == "password":
                _change_pw, off = parse_bool(pkt, off)
                pw_b, _ = parse_string(pkt, off)
                pw = pw_b.decode("utf-8", errors="replace")
                ok = self.password is not None and username == self.username and pw == self.password
                self.auth_attempts.append((username, "password", ok))
                if ok:
                    transport.send_packet(bytes([SSH_MSG_USERAUTH_SUCCESS]))
                    return True
                transport.send_packet(bytes([SSH_MSG_USERAUTH_FAILURE]) + ssh_string(method_list) + bytes([0]))
                continue

            if method == "publickey":
                have_sig, off = parse_bool(pkt, off)
                alg_b, off = parse_string(pkt, off)
                pubkey_blob, off = parse_string(pkt, off)
                key_allowed = username == self.username and pubkey_blob in self.authorized_pubkeys
                if not have_sig:
                    if key_allowed:
                        transport.send_packet(
                            bytes([SSH_MSG_USERAUTH_PK_OK]) + ssh_string(alg_b) + ssh_string(pubkey_blob)
                        )
                    else:
                        self.auth_attempts.append((username, "publickey", False))
                        transport.send_packet(bytes([SSH_MSG_USERAUTH_FAILURE]) + ssh_string(method_list) + bytes([0]))
                    continue

                sig_field, _ = parse_string(pkt, off)
                ok = False
                if key_allowed and alg_b == b"ssh-ed25519":
                    ok = self._verify_ed25519_userauth(session_id, username_b, alg_b, pubkey_blob, sig_field)
                self.auth_attempts.append((username, "publickey", ok))
                if ok:
                    transport.send_packet(bytes([SSH_MSG_USERAUTH_SUCCESS]))
                    return True
                transport.send_packet(bytes([SSH_MSG_USERAUTH_FAILURE]) + ssh_string(method_list) + bytes([0]))
                continue

            transport.send_packet(bytes([SSH_MSG_USERAUTH_FAILURE]) + ssh_string(method_list) + bytes([0]))

    def _verify_ed25519_userauth(
        self,
        session_id: bytes,
        username_b: bytes,
        alg_b: bytes,
        pubkey_blob: bytes,
        sig_field: bytes,
    ) -> bool:
        try:
            pk_alg, off = parse_string(pubkey_blob, 0)
            pk_raw, _ = parse_string(pubkey_blob, off)
            sig_alg, off2 = parse_string(sig_field, 0)
            sig_raw, _ = parse_string(sig_field, off2)
            if pk_alg != b"ssh-ed25519" or sig_alg != b"ssh-ed25519":
                return False
            signed_data = (
                ssh_string(session_id)
                + bytes([SSH_MSG_USERAUTH_REQUEST])
                + ssh_string(username_b)
                + ssh_string(b"ssh-connection")
                + ssh_string(b"publickey")
                + bytes([1])
                + ssh_string(alg_b)
                + ssh_string(pubkey_blob)
            )
            Ed25519PublicKey.from_public_bytes(pk_raw).verify(sig_raw, signed_data)
            return True
        except (ValueError, InvalidSignature):
            return False

    def _run_connection(self, transport: _PacketTransport) -> None:
        channels: dict[int, tuple[int, int, Queue[bytes | None]]] = {}
        next_channel_id = 0
        exec_threads: list[Thread] = []

        while not self._stop.is_set():
            pkt = transport.read_packet()
            if not pkt:
                break
            msg = pkt[0]
            if msg in (SSH_MSG_IGNORE, SSH_MSG_DEBUG):
                continue
            if msg == SSH_MSG_DISCONNECT:
                break
            if msg == SSH_MSG_GLOBAL_REQUEST:
                _req_name, off = parse_string(pkt, 1)
                want_reply, _ = parse_bool(pkt, off)
                if want_reply:
                    transport.send_packet(bytes([SSH_MSG_REQUEST_FAILURE]))
                continue
            if msg == SSH_MSG_CHANNEL_OPEN:
                chan_type, off = parse_string(pkt, 1)
                sender_chan, off = parse_uint32(pkt, off)
                _init_win, off = parse_uint32(pkt, off)
                max_pkt, _ = parse_uint32(pkt, off)
                if chan_type != b"session":
                    transport.send_packet(
                        bytes([SSH_MSG_CHANNEL_OPEN_FAILURE])
                        + struct.pack("!II", sender_chan, 3)
                        + ssh_string(b"Unsupported channel type")
                        + ssh_string(b"")
                    )
                    continue
                local_id = next_channel_id
                next_channel_id += 1
                channels[local_id] = (sender_chan, min(max_pkt or 32768, 32768), Queue())
                transport.send_packet(
                    bytes([SSH_MSG_CHANNEL_OPEN_CONFIRMATION])
                    + struct.pack("!IIII", sender_chan, local_id, 2 * 1024 * 1024, 32768)
                )
                continue
            if msg == SSH_MSG_CHANNEL_WINDOW_ADJUST:
                continue
            if msg == SSH_MSG_CHANNEL_DATA:
                local_id, off = parse_uint32(pkt, 1)
                data, _ = parse_string(pkt, off)
                if local_id in channels:
                    sender_chan, _, stdin_q = channels[local_id]
                    stdin_q.put(data)
                    if data:
                        transport.send_packet(
                            bytes([SSH_MSG_CHANNEL_WINDOW_ADJUST]) + struct.pack("!II", sender_chan, len(data))
                        )
                continue
            if msg == SSH_MSG_CHANNEL_EOF:
                local_id, _ = parse_uint32(pkt, 1)
                if local_id in channels:
                    channels[local_id][2].put(None)
                continue
            if msg == SSH_MSG_CHANNEL_CLOSE:
                local_id, _ = parse_uint32(pkt, 1)
                if local_id in channels:
                    channels[local_id][2].put(None)
                    channels.pop(local_id, None)
                if not channels:
                    break
                continue
            if msg == SSH_MSG_CHANNEL_REQUEST:
                local_id, off = parse_uint32(pkt, 1)
                req_type, off = parse_string(pkt, off)
                want_reply, off = parse_bool(pkt, off)
                if local_id not in channels:
                    continue
                sender_chan, max_pkt, stdin_q = channels[local_id]
                if req_type == b"env":
                    if want_reply:
                        transport.send_packet(bytes([SSH_MSG_CHANNEL_FAILURE]) + struct.pack("!I", sender_chan))
                    continue
                if req_type != b"exec":
                    if want_reply:
                        transport.send_packet(bytes([SSH_MSG_CHANNEL_FAILURE]) + struct.pack("!I", sender_chan))
                    continue
                cmd_b, _ = parse_string(pkt, off)
                command = cmd_b.decode("utf-8", errors="replace")
                self.executed_commands.append(command)
                if want_reply:
                    transport.send_packet(bytes([SSH_MSG_CHANNEL_SUCCESS]) + struct.pack("!I", sender_chan))
                t = Thread(
                    target=self._run_exec,
                    args=(transport, sender_chan, max_pkt, stdin_q, command),
                    daemon=True,
                )
                exec_threads.append(t)
                t.start()

        for t in exec_threads:
            t.join(timeout=1.0)

    def _run_exec(
        self,
        transport: _PacketTransport,
        sender_chan: int,
        max_pkt: int,
        stdin_q: Queue[bytes | None],
        command: str,
    ) -> None:
        def write_stdout(data: bytes) -> None:
            for idx in range(0, len(data), max_pkt):
                chunk = data[idx : idx + max_pkt]
                transport.send_packet(bytes([SSH_MSG_CHANNEL_DATA]) + struct.pack("!I", sender_chan) + ssh_string(chunk))

        def write_stderr(data: bytes) -> None:
            for idx in range(0, len(data), max_pkt):
                chunk = data[idx : idx + max_pkt]
                transport.send_packet(
                    bytes([SSH_MSG_CHANNEL_EXTENDED_DATA]) + struct.pack("!II", sender_chan, 1) + ssh_string(chunk)
                )

        exit_code = 0
        try:
            if self.exec_handler is not None:
                exit_code = self.exec_handler(command, stdin_q, write_stdout, write_stderr)
            else:
                exit_code = self._default_exec(command, stdin_q, write_stdout, write_stderr)
        except Exception as error:
            try:
                write_stderr(f"Server exec error: {error}\n".encode("utf-8"))
            except OSError:
                pass
            exit_code = 1

        try:
            transport.send_packet(
                bytes([SSH_MSG_CHANNEL_REQUEST])
                + struct.pack("!I", sender_chan)
                + ssh_string(b"exit-status")
                + bytes([0])
                + struct.pack("!I", exit_code)
            )
            transport.send_packet(bytes([SSH_MSG_CHANNEL_EOF]) + struct.pack("!I", sender_chan))
            transport.send_packet(bytes([SSH_MSG_CHANNEL_CLOSE]) + struct.pack("!I", sender_chan))
        except OSError:
            pass

    def _read_all_stdin(self, stdin_q: Queue[bytes | None]) -> bytes:
        buf = bytearray()
        while not self._stop.is_set():
            try:
                chunk = stdin_q.get(timeout=0.1)
            except Empty:
                continue
            if chunk is None:
                break
            buf.extend(chunk)
        return bytes(buf)

    def _read_line_stdin(self, stdin_q: Queue[bytes | None], timeout: float = 5.0) -> str | None:
        buf = bytearray()
        deadline = 0.0
        step = 0.05
        while not self._stop.is_set() and deadline < timeout:
            try:
                chunk = stdin_q.get(timeout=step)
            except Empty:
                deadline += step
                continue
            if chunk is None:
                return buf.decode("utf-8", errors="replace").rstrip("\r\n") if buf else None
            buf.extend(chunk)
            if b"\n" in buf:
                line = bytes(buf).split(b"\n", 1)[0]
                return line.decode("utf-8", errors="replace").rstrip("\r")
        return None

    def _default_exec(
        self,
        command: str,
        stdin_q: Queue[bytes | None],
        write_stdout: Callable[[bytes], None],
        write_stderr: Callable[[bytes], None],
    ) -> int:
        # Sudo wrapper: /usr/bin/sudo -S -p <prompt> -- /bin/sh -lc <inner>
        sudo_match = re.fullmatch(
            r"/usr/bin/sudo -S -p (.+?) -- /bin/sh -lc (.+)",
            command,
            re.DOTALL,
        )
        if sudo_match:
            prompt_token = shlex.split(sudo_match.group(1))[0]
            inner_cmd = shlex.split(sudo_match.group(2))[0]
            write_stderr(prompt_token.encode("utf-8"))
            entered = self._read_line_stdin(stdin_q)
            if entered is None or self.sudo_password is None or entered != self.sudo_password:
                write_stderr(b"Sorry, try again.\n")
                return 1
            return self._default_exec(inner_cmd, stdin_q, write_stdout, write_stderr)

        # Upload: umask 077 && cat > '<path>' && chmod <mode> -- '<path>'
        upload_match = re.fullmatch(
            r"umask 077 && cat > (.+?) && chmod ([0-7]{3,4}) -- (.+)",
            command,
        )
        if upload_match:
            path = shlex.split(upload_match.group(1))[0]
            mode = upload_match.group(2)
            data = self._read_all_stdin(stdin_q)
            self.files[path] = (data, mode)
            return 0

        # Download: /usr/bin/head -c <n> -- '<path>'
        download_match = re.fullmatch(r"/usr/bin/head -c (\d+) -- (.+)", command)
        if download_match:
            limit = int(download_match.group(1))
            path = shlex.split(download_match.group(2))[0]
            entry = self.files.get(path)
            if entry is None:
                write_stderr(f"head: cannot open '{path}' for reading: No such file or directory\n".encode("utf-8"))
                return 1
            write_stdout(entry[0][:limit])
            return 0

        # Sleep command for timeout and live guard cancellation tests
        sleep_match = re.fullmatch(r"sleep (\d+(?:\.\d+)?)", command.strip())
        if sleep_match:
            total = float(sleep_match.group(1))
            elapsed = 0.0
            while elapsed < total and not self._stop.is_set():
                step = min(0.05, total - elapsed)
                self._stop.wait(step)
                elapsed += step
            return 0

        # Simple echo command
        if command.startswith("echo "):
            args = shlex.split(command[5:])
            write_stdout((" ".join(args) + "\n").encode("utf-8"))
            return 0

        if command.startswith("err "):
            write_stderr((command[4:] + "\n").encode("utf-8"))
            return 1

        if command == "fail":
            write_stderr(b"command failed\n")
            return 42

        write_stdout(f"ran:{command}\n".encode("utf-8"))
        return 0
