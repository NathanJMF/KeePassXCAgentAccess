"""Serve metadata to one authorized OS account over a local pathname socket."""

from dataclasses import dataclass
import os
from pathlib import Path
from select import select
import socket
import stat
import struct
from threading import Lock, Thread
from time import monotonic

from .protocol import (
    LIST_REQUEST, ListingError, REQUEST_LIMIT, REQUEST_TIMEOUT,
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
    client: socket.socket | None = None


class ListingBroker:
    def __init__(self, config, current_session):
        self.config = config
        self.current_session = current_session
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
            if self.config is None or session is None:
                raise ListingError()
            if self._listener is not None:
                if self._listener.session is session:
                    return
                self._stop_locked()

            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            inode = None
            try:
                self.config.validate()
                server.bind(str(self.config.path))
                info = self.config.path.lstat()
                inode = (info.st_dev, info.st_ino)
                self.config.path.chmod(0o660)
                server.listen(4)
                server.settimeout(0.2)
            except (OSError, RuntimeError, ValueError, ListingError):
                server.close()
                if inode is not None:
                    self._unlink(inode)
                raise ListingError() from None

            listener = _Listener(server, session, inode)
            self._listener = listener
            Thread(target=self._serve, args=(listener,), daemon=True).start()

    def stop(self):
        with self._mutex:
            self._stop_locked()

    def _stop_locked(self):
        listener, self._listener = self._listener, None
        if listener is None:
            return
        if listener.client is not None:
            try:
                listener.client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            listener.client.close()
        listener.server.close()
        self._unlink(listener.inode)

    def _unlink(self, inode):
        try:
            info = self.config.path.lstat()
            if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == inode:
                self.config.path.unlink()
        except OSError:
            pass

    def _serve(self, listener):
        while True:
            with self._mutex:
                if self._listener is not listener:
                    return
            try:
                connection, _ = listener.server.accept()
            except TimeoutError:
                continue
            except OSError:
                return

            with connection:
                with self._mutex:
                    if self._listener is not listener:
                        return
                    listener.client = connection
                try:
                    if peer_uid(connection) == self.config.agent_uid:
                        self._handle(listener, connection)
                except (OSError, ValueError):
                    pass
                finally:
                    with self._mutex:
                        listener.client = None

    def _handle(self, listener, connection):
        deadline = monotonic() + REQUEST_TIMEOUT
        try:
            request = decode(receive(connection, REQUEST_LIMIT, deadline))
            if request != LIST_REQUEST or type(request["version"]) is not int:
                raise ListingError("invalid_request")
            if self.current_session() is not listener.session:
                return
            reply = listener.session.list_entries()
        except (EOFError, ValueError, RecursionError, TimeoutError):
            reply = encode({"error": "invalid_request"})
        except ListingError as error:
            reply = encode({"error": error.code})

        connection.setblocking(False)
        payload = memoryview(reply)
        while payload:
            _, writable, _ = select([], [connection], [], remaining(deadline))
            if not writable:
                return
            with self._mutex:
                if self._listener is not listener or self.current_session() is not listener.session:
                    return
                try:
                    sent = connection.send(payload)
                except BlockingIOError:
                    continue
            if sent == 0:
                return
            payload = payload[sent:]
