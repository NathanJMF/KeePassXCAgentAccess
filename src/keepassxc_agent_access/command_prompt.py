#!/usr/bin/python3 -I
"""Private sandbox prompt and generic command launcher. No Keeper imports."""

import ctypes
import json
import os
import socket
import struct
import subprocess
import sys
from threading import Thread


_PROMPT = "/tmp/keeper-prompt.sock"
_LIMIT = 4096


def read_exact(stream, count):
    value = stream.read(count)
    if len(value) != count:
        raise ValueError("Incomplete credential frame")
    return value


def askpass(prompt):
    generic = os.environ.get("KEEPER_GENERIC_PROMPT") == "1"
    if (not isinstance(prompt, str) or not prompt or not prompt.isprintable() or len(prompt) > _LIMIT
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
            "SSL_CERT_FILE": "/keeper/trust.pem",
            prompt_variable: "/keeper/prompt",
        }
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
        if len(sys.argv) >= 6 and sys.argv[1] == "--launch-generic":
            raise SystemExit(launch(sys.argv[2], sys.argv[5:], generic=True, prompt_contains=sys.argv[3],
                                   declared=json.loads(sys.argv[4])))
        if len(sys.argv) >= 4 and sys.argv[1] == "--launch":
            raise SystemExit(launch(sys.argv[2], sys.argv[3:]))
    except (OSError, ValueError):
        pass
    raise SystemExit(1)
