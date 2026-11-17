"""Bounded one-shot authorization tickets shared with the owner UI."""

from dataclasses import dataclass, field
from threading import Event, Lock
from time import monotonic

from .activity import Attribution
from .protocol import APPROVAL_TIMEOUT, ListingError


@dataclass
class Approval:
    id: int
    uid: int
    context: Attribution
    action: str
    scope: tuple[str, ...]
    destination: str | None
    expires: float
    answer: str | None = None
    identity: str = ""
    project: str = ""
    requested: float = 0
    trusts_certificate: bool = False
    ready: Event = field(default_factory=Event)


class ApprovalQueue:
    def __init__(self, timeout=APPROVAL_TIMEOUT, capacity=4):
        self.timeout = timeout
        self.capacity = capacity
        self._lock = Lock()
        self._pending = {}

    def pending(self):
        with self._lock:
            return tuple(ticket for ticket in self._pending.values()
                         if ticket.answer is None and ticket.expires > monotonic())

    def resolve(self, identifier, approve):
        with self._lock:
            ticket = self._pending.get(identifier)
            if ticket is None or ticket.answer is not None or ticket.expires <= monotonic():
                return False
            ticket.answer = "approved" if approve else "declined"
            ticket.ready.set()
            return True

    def wait(self, ticket, live):
        with self._lock:
            if len(self._pending) >= self.capacity:
                raise ListingError("busy")
            self._pending[ticket.id] = ticket
        try:
            while live():
                remaining = ticket.expires - monotonic()
                if remaining <= 0:
                    return "expired"
                if ticket.ready.wait(min(remaining, .1)):
                    return ticket.answer if live() else "revoked"
            return "revoked"
        finally:
            with self._lock:
                self._pending.pop(ticket.id, None)
