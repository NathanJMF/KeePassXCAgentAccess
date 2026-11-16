"""Per-job Unix-socket SOCKS relay to a single approved network origin."""

from contextlib import contextmanager
import ipaddress
from pathlib import Path
from select import select
import socket
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Lock, Thread
from time import monotonic


_TUNNELS = 8
_BYTES = 16 * 1024**2


def receive_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise OSError("Incomplete relay request")
        data.extend(chunk)
    return bytes(data)


def connection_target(sock):
    version, count = receive_exact(sock, 2)
    if version != 5 or not 0 < count <= 8 or 0 not in receive_exact(sock, count):
        raise ValueError("Unsupported relay greeting")
    sock.sendall(b"\x05\x00")
    version, command, reserved, family = receive_exact(sock, 4)
    if (version, command, reserved) != (5, 1, 0):
        raise ValueError("Unsupported relay operation")
    if family == 3:
        length = receive_exact(sock, 1)[0]
        host = receive_exact(sock, length).decode("ascii").lower()
    elif family in (1, 4):
        host = str(ipaddress.ip_address(receive_exact(sock, 4 if family == 1 else 16)))
    else:
        raise ValueError("Unsupported relay address")
    port = int.from_bytes(receive_exact(sock, 2), "big")
    return host, port


def approved_address(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            lookup = subprocess.run(["/usr/bin/getent", "ahosts", host], env={"PATH": "/usr/bin:/bin"},
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    cwd="/", timeout=2, check=True, text=True)
            addresses = lookup.stdout.split()
            address = ipaddress.ip_address(addresses[0]) if addresses else None
        except (OSError, ValueError, subprocess.SubprocessError):
            address = None
    if address is None:
        raise OSError("Could not resolve the approved network destination")
    return address


class Relay:
    def __init__(self, destination):
        self.destination = (destination.host, destination.port)
        self.address = approved_address(destination.host)
        self.active = Event()
        self.closed = Event()
        self.transferred = Event()
        self.lock = Lock()
        self.connections = set()
        self.threads = []
        self.bytes_left = _BYTES
        self.remaining = _TUNNELS

    def run(self, listener):
        while not self.closed.is_set():
            try:
                client, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with self.lock:
                if self.closed.is_set() or not self.active.is_set() or not self.remaining:
                    client.close()
                    continue
                self.remaining -= 1
                self.connections.add(client)
                worker = Thread(target=self.connect, args=(client,), daemon=True)
                self.threads.append(worker)
                worker.start()

    def connect(self, client):
        remote = None
        try:
            client.settimeout(1)
            if connection_target(client) != self.destination or self.closed.is_set():
                client.sendall(b"\x05\x02\x00\x01" + b"\0" * 6)
                return
            remote = socket.socket(socket.AF_INET6 if self.address.version == 6 else socket.AF_INET,
                                   socket.SOCK_STREAM)
            remote.settimeout(1)
            with self.lock:
                if self.closed.is_set():
                    return
                self.connections.add(remote)
            remote.connect((str(self.address), self.destination[1]))
            client.sendall(b"\x05\x00\x00\x01" + b"\0" * 6)
            self.forward(client, remote)
        except (OSError, ValueError):
            pass
        finally:
            with self.lock:
                self.connections.discard(client)
                self.connections.discard(remote)
            client.close()
            if remote is not None:
                remote.close()

    def forward(self, client, remote):
        deadline = monotonic() + 18
        while not self.closed.is_set() and monotonic() < deadline:
            readers, _, _ = select((client, remote), (), (), .25)
            for source in readers:
                data = source.recv(65536)
                if not data:
                    return
                with self.lock:
                    self.bytes_left -= len(data)
                    if self.bytes_left < 0:
                        return
                self.transferred.set()
                (remote if source is client else client).sendall(data)

    def stop(self):
        self.closed.set()
        with self.lock:
            for connection in self.connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


@contextmanager
def network_relay(destination):
    with TemporaryDirectory(prefix="keeper-relay-") as directory, socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(Path(directory) / "proxy.sock"))
        listener.listen(4)
        listener.settimeout(.1)
        relay = Relay(destination)
        thread = Thread(target=relay.run, args=(listener,), daemon=True)
        thread.start()
        try:
            yield Path(directory), relay
        finally:
            relay.stop()
            thread.join(.5)
            deadline = monotonic() + 1.25
            for worker in relay.threads:
                worker.join(max(0, deadline - monotonic()))
