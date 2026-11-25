#!/usr/bin/python3 -I
"""Private sandbox prompt and generic command launcher. No Keeper imports."""

import ctypes
import ipaddress
import json
import os
from select import select
import socket
import struct
import subprocess
import sys
from threading import Thread


_PROMPT = "/tmp/keeper-prompt.sock"
_RELAY = "/keeper/relay/proxy.sock"
_LIMIT = 4096


def read_exact(stream, count):
    value = stream.read(count)
    if len(value) != count:
        raise ValueError("Incomplete credential frame")
    return value


def askpass(prompt):
    generic = os.environ.get("KEEPER_GENERIC_PROMPT") == "1"
    if (not isinstance(prompt, str) or not prompt or len(prompt) > _LIMIT
            or not all(ch.isprintable() or ch in "\r\n\t" for ch in prompt)
            or (os.environ.get("KEEPER_PROMPT_CONTAINS", "password").casefold() not in prompt.casefold()
                if generic else not prompt.startswith("Password"))):
        return 1
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(2)
        connection.connect(_PROMPT)
        with connection.makefile("rb") as stream:
            length, = struct.unpack("!H", read_exact(stream, 2))
            credential = read_exact(stream, length)
    if not credential:
        return 1
    sys.stdout.buffer.write(credential + b"\n")
    return 0


def proxy_stdio(host, port_text):
    """Bridge stdin/stdout to Keeper's SOCKS5 Unix-socket relay (e.g. ssh ProxyCommand)."""
    port = int(port_text)
    if not 0 < port <= 65535 or not host or len(host) > 255:
        return 1
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as relay:
        relay.settimeout(5)
        relay.connect(_RELAY)
        relay.sendall(b"\x05\x01\x00")
        if relay.recv(2) != b"\x05\x00":
            return 1
        try:
            addr = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            raw = host.encode("ascii")
            header = b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw
        else:
            header = (b"\x05\x01\x00" + (b"\x01" if addr.version == 4 else b"\x04") + addr.packed)
        relay.sendall(header + port.to_bytes(2, "big"))
        reply = b""
        while len(reply) < 10:
            chunk = relay.recv(10 - len(reply))
            if not chunk:
                return 1
            reply += chunk
        if reply[:2] != b"\x05\x00":
            return 1
        relay.settimeout(None)
        in_fd, out_fd = sys.stdin.fileno(), sys.stdout.fileno()
        while True:
            readers, _, _ = select((in_fd, relay), (), (), 1.0)
            if in_fd in readers:
                data = os.read(in_fd, 65536)
                if not data:
                    try:
                        relay.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    in_fd = -1
                else:
                    relay.sendall(data)
            if relay in readers:
                data = relay.recv(65536)
                if not data:
                    return 0
                os.write(out_fd, data)
            if in_fd == -1 and relay not in readers:
                # Drain any remaining bytes from remote cleanly via select loop.
                continue


def serve(listener, credential):
    # One reply can satisfy the approved job. Further prompts fail closed.
    try:
        client, _ = listener.accept()
        with client:
            client.settimeout(1)
            client.sendall(struct.pack("!H", len(credential)) + credential)
    except OSError:
        pass
    finally:
        listener.close()


def launch(prompt_variable, command, *, generic=False, declared=(), prompt_contains="password"):
    # Sandbox setup has finished. Mark this process nondumpable before
    # reading any credential, and establish the private prompt socket first.
    if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0):
        return 1
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(_PROMPT)
        listener.listen(1)
        sys.stdout.buffer.write(b"keeper-ready\n")
        sys.stdout.buffer.flush()
        if read_exact(sys.stdin.buffer, 1) != b"\x01":
            return 1
        length, = struct.unpack("!H", read_exact(sys.stdin.buffer, 2))
        if not 0 < length <= _LIMIT:
            return 1
        credential = read_exact(sys.stdin.buffer, length)
        if any(value in credential for value in (b"\0", b"\r", b"\n")):
            return 1
        worker = Thread(target=serve, args=(listener, credential), daemon=True)
        worker.start()
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/tmp",
            "https_proxy": "socks5h://localhost/keeper/relay/proxy.sock",
            "HTTPS_PROXY": "socks5h://localhost/keeper/relay/proxy.sock",
            "all_proxy": "socks5h://localhost/keeper/relay/proxy.sock",
            "ALL_PROXY": "socks5h://localhost/keeper/relay/proxy.sock",
            "SSL_CERT_FILE": "/keeper/trust.pem",
            prompt_variable: "/keeper/prompt",
        }
        if prompt_variable == "SSH_ASKPASS":
            environment["SSH_ASKPASS_REQUIRE"] = "force"
            environment["DISPLAY"] = "keeper"
        if generic:
            environment.update(dict(declared))
            environment["KEEPER_GENERIC_PROMPT"] = "1"
            environment["KEEPER_PROMPT_CONTAINS"] = prompt_contains
        return subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, env=environment, cwd="/tmp", close_fds=True,
                              check=False).returncode


if __name__ == "__main__":
    try:
        if len(sys.argv) == 2:
            raise SystemExit(askpass(sys.argv[1]))
        if len(sys.argv) == 4 and sys.argv[1] == "--proxy-stdio":
            raise SystemExit(proxy_stdio(sys.argv[2], sys.argv[3]))
        if len(sys.argv) >= 6 and sys.argv[1] == "--launch-generic":
            raise SystemExit(launch(sys.argv[2], sys.argv[5:], generic=True, prompt_contains=sys.argv[3],
                                   declared=json.loads(sys.argv[4])))
        if len(sys.argv) >= 4 and sys.argv[1] == "--launch":
            raise SystemExit(launch(sys.argv[2], sys.argv[3:]))
    except (OSError, ValueError):
        pass
    raise SystemExit(1)
