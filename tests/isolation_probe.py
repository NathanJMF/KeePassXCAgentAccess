"""Run this probe as the unprivileged agent, with only synthetic targets."""

import errno
import os
import socket
import subprocess
import sys


def must_deny(label, operation):
    try:
        operation()
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM):
            raise
        print(f"Denied: {label}", flush=True)
        return
    raise AssertionError(f"Agent gained access to {label}")


def read_one(path):
    with open(path, "rb") as stream:
        return stream.read(1)


def connect(path):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.connect(path)


def main(database, key_file, bus, wayland, pid, owner):
    with open("/proc/self/uid_map", encoding="ascii") as stream:
        maps = [tuple(map(int, line.split())) for line in stream]
    host_uid = next(host + os.geteuid() - guest for guest, host, count in maps
                    if guest <= os.geteuid() < guest + count)
    assert host_uid not in (0, int(owner)), "The probe needs a separate unprivileged host UID."
    must_deny("vault file", lambda: read_one(database))
    must_deny("key file", lambda: read_one(key_file))
    must_deny("owner process memory", lambda: read_one(f"/proc/{pid}/mem"))
    must_deny("desktop control socket", lambda: connect(wayland))

    for label, name, method, path in (
        ("owner session bus", "org.freedesktop.DBus",
         "org.freedesktop.DBus.ListNames", "/org/freedesktop/DBus"),
        ("owner keyring", "org.freedesktop.secrets",
         "org.freedesktop.DBus.Properties.GetAll", "/org/freedesktop/secrets"),
    ):
        command = ["/usr/bin/gdbus", "call", "--address", bus, "--dest", name,
                   "--object-path", path, "--method", method]
        if name == "org.freedesktop.secrets":
            command.append("org.freedesktop.Secret.Service")
        response = subprocess.run(command, capture_output=True, timeout=5, check=False)
        assert response.returncode != 0, f"Agent gained access to {label}"
        print(f"Denied: {label}", flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:])
