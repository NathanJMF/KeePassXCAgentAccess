"""Own the unlocked session and invalidate outstanding unlock attempts on lock."""

from enum import Enum
from threading import Event, Lock

from gi.repository import Gio

from .vault import UnlockCancelled, open_vault


class VaultState(Enum):
    SETUP = "Setup required"
    LOCKED = "Locked"
    UNLOCKED = "Unlocked"


class UnlockAttempt(Event):
    def __init__(self):
        super().__init__()
        self.keyring_request = Gio.Cancellable()

    def set(self):
        super().set()
        self.keyring_request.cancel()


class VaultController:
    def __init__(self, opener=open_vault):
        self._opener = opener
        self._mutex = Lock()
        self._attempt = UnlockAttempt()
        self._session = None
        self._source = None

    def state(self, configured):
        with self._mutex:
            if self._session is not None:
                return VaultState.UNLOCKED
            return VaultState.LOCKED if configured else VaultState.SETUP

    @property
    def source(self):
        with self._mutex:
            return self._source

    def begin(self):
        """Issue a cancellation token before dispatching work to a thread."""
        with self._mutex:
            self._attempt.set()
            self._attempt = UnlockAttempt()
            return self._attempt

    def verify(self, attempt, target, password):
        with self._opener(target, password, attempt):
            if attempt.is_set():
                raise UnlockCancelled

    def unlock(self, attempt, target, password, source):
        session = self._opener(target, password, attempt)
        with self._mutex:
            if not attempt.is_set():
                previous, self._session = self._session, session
                self._source = source
            else:
                previous = session
        if previous is not None:
            previous.close()
        if attempt.is_set():
            raise UnlockCancelled

    def lock(self):
        with self._mutex:
            self._attempt.set()
            session, self._session = self._session, None
            self._source = None
        if session is not None:
            session.close()
