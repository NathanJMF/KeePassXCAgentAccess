"""Serve metadata to one authorized OS account over a local pathname socket."""

from dataclasses import dataclass, field
import os
from pathlib import Path
from select import select
import socket
import stat
import struct
from threading import Lock, Thread
from time import monotonic

from .protocol import (
    CLIENT_TIMEOUT, ListingError, REQUEST_LIMIT, REQUEST_TIMEOUT,
    decode, encode, receive, remaining,
)


def peer_uid(connection):
    identity = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _, uid, _ = struct.unpack("iII", identity)
    return uid


@dataclass(frozen=True)
class BrokerConfig:
    path: Path
    agent_uid: int

    @classmethod
    def from_environment(cls):
        path = os.environ.get("KEEPASSXC_AGENT_SOCKET")
        uid = os.environ.get("KEEPASSXC_AGENT_UID", "")
        if not path or not (uid.isascii() and uid.isdecimal()) or len(uid) > 10:
            return None
        return cls(Path(path), int(uid))

    def validate(self):
        owner = os.geteuid()
        if not 0 < self.agent_uid < 2**32 - 1 or self.agent_uid == owner:
            raise ListingError()
        parent = self.path.parent
        if not self.path.is_absolute() or not self.path.name or parent.resolve(strict=True) != parent:
            raise ListingError()
        for directory in (parent, *parent.parents):
            info = directory.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner):
                raise ListingError()
            if info.st_mode & 0o022 and (directory == parent or not info.st_mode & stat.S_ISVTX):
                raise ListingError()
            if directory == parent and info.st_uid != owner:
                raise ListingError()


@dataclass
class _Listener:
    server: socket.socket
    session: object
    inode: tuple[int, int]
    path: Path
    uid: int
    clients: set[socket.socket] = field(default_factory=set)
    revision: int = 0


class ListingBroker:
    def __init__(self, config, current_session, handler):
        self.config = config
        self.current_session = current_session
        self.handler = handler
        self._mutex = Lock()
        self._listener = None

    @property
    def enabled(self):
        with self._mutex:
            listener = self._listener
            return listener is not None and self.current_session() is listener.session

    def start(self):
        with self._mutex:
            session = self.current_session()
            config = self.config
            if config is None or session is None:
                raise ListingError()
            if self._listener is not None:
                if self._listener.session is session:
                    return
                self._stop_locked()

            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            inode = None
            try:
                config.validate()
                server.bind(str(config.path))
                info = config.path.lstat()
                inode = (info.st_dev, info.st_ino)
                config.path.chmod(0o660)
                server.listen(8)
                server.settimeout(0.2)
            except (OSError, RuntimeError, ValueError, ListingError):
                server.close()
                if inode is not None:
                    self._unlink(config.path, inode)
                raise ListingError() from None

            listener = _Listener(server, session, inode, config.path, config.agent_uid)
            self._listener = listener
            Thread(target=self._serve, args=(listener,), daemon=True).start()

    def stop(self):
        with self._mutex:
            self._stop_locked()

    def update(self, save, config):
        """Publish settings and invalidate requests in one authorization transition."""
        with self._mutex:
            save()
            if config != self.config:
                self._stop_locked()
                self.config = config
            elif self._listener is not None:
                self._interrupt(self._listener)

    @staticmethod
    def _interrupt(listener):
        listener.revision += 1
        for client in listener.clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()
        listener.clients.clear()

    def _stop_locked(self):
        listener, self._listener = self._listener, None
        if listener is not None:
            self._interrupt(listener)
            listener.server.close()
            self._unlink(listener.path, listener.inode)

    @staticmethod
    def _unlink(path, inode):
        try:
            info = path.lstat()
            if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == inode:
                path.unlink()
        except OSError:
            pass

    def _serve(self, listener):
        while True:
            try:
                connection, _ = listener.server.accept()
            except TimeoutError:
                with self._mutex:
                    if self._listener is not listener:
                        return
                continue
            except OSError:
                return
            with self._mutex:
                try:
                    allowed = (
                        self._listener is listener and len(listener.clients) < 8
                        and peer_uid(connection) == listener.uid
                    )
                except OSError:
                    allowed = False
                if not allowed:
                    connection.close()
                    continue
                listener.clients.add(connection)
                revision = listener.revision
            Thread(target=self._client, args=(listener, connection, revision), daemon=True).start()

    def _client(self, listener, connection, revision):
        deadline = monotonic() + CLIENT_TIMEOUT

        def guarded(effect=lambda: None):
            with self._mutex:
                if (
                    self._listener is not listener or revision != listener.revision
                    or self.current_session() is not listener.session
                ):
                    return False
                # A waiting client sending more bytes or closing its connection revokes work.
                if select([connection], [], [], 0)[0]:
                    return False
                effect()
                return True

        def deliver(reply):
            try:
                connection.setblocking(False)
                payload = memoryview(reply)
                while payload:
                    _, writable, _ = select([], [connection], [], remaining(deadline))
                    if not writable:
                        return False
                    sent = None

                    def send():
                        nonlocal sent
                        try:
                            sent = connection.send(payload)
                        except BlockingIOError:
                            pass

                    if not guarded(send) or sent == 0:
                        return False
                    if sent:
                        payload = payload[sent:]
                return True
            except (OSError, ValueError):
                return False

        with connection:
            try:
                try:
                    request = decode(receive(connection, REQUEST_LIMIT, monotonic() + REQUEST_TIMEOUT))
                except (EOFError, ValueError, RecursionError, TimeoutError):
                    raise ListingError("invalid_request") from None
                if guarded():
                    response = self.handler(request, listener.uid, listener.session, guarded, guarded, deliver)
                    if response is not None:
                        deliver(response)
            except ListingError as error:
                try:
                    deliver(encode({"error": error.code}))
                except (OSError, ValueError):
                    pass
            except (OSError, ValueError):
                pass
            finally:
                with self._mutex:
                    listener.clients.discard(connection)
