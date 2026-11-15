"""Coordinate verified setup, persisted settings, and keyring cleanup."""

from dataclasses import replace
from uuid import uuid4

from .keyring import KeyringError
from .settings import Settings, SettingsError
from .vault import UnlockCancelled, VaultError


class VaultSetup:
    def __init__(self, settings, keyring, controller):
        self.store = settings
        self.keyring = keyring
        self.controller = controller

    def configure(self, attempt, target, password, remember):
        self.controller.verify(attempt, target, password)
        previous = self.store.read()
        if attempt.is_set():
            raise UnlockCancelled

        pending = previous.pending_items
        item = None
        if remember:
            item = uuid4().hex
            # Make an interrupted store discoverable before creating the keyring item.
            self.store.write(replace(previous, pending_items=(*pending, item)))
        try:
            if item is not None:
                self.keyring.remember(item, password, attempt.keyring_request)
            if attempt.is_set():
                raise UnlockCancelled
            if previous.active_item:
                pending = (*pending, previous.active_item)
            self.store.write(Settings(target, item, pending))
        except (KeyringError, SettingsError, UnlockCancelled):
            if item is not None:
                # The old settings are still active and the new item is pending.
                if attempt.is_set():
                    raise UnlockCancelled from None
                try:
                    self.keyring.remove(item)
                    self.store.write(previous)
                except (KeyringError, SettingsError):
                    pass
            raise
        self.controller.lock()
        return self.retry_cleanup()

    def unlock(self, attempt, password=None):
        if attempt.is_set():
            raise UnlockCancelled
        settings = self.store.read()
        if settings.target is None:
            raise VaultError("Configure a KeePass database first.")
        source = "manual"
        if password is None:
            if not settings.active_item:
                raise KeyringError("Enter the database password to unlock.")
            try:
                password = self.keyring.retrieve(settings.active_item, attempt.keyring_request)
            except KeyringError:
                if attempt.is_set():
                    raise UnlockCancelled from None
                raise
            source = "keyring"
        self.controller.unlock(attempt, settings.target, password, source)

    def forget(self):
        self.controller.lock()
        settings = self.store.read()
        if settings.active_item:
            self.store.write(replace(
                settings, active_item=None,
                pending_items=(*settings.pending_items, settings.active_item),
            ))
        return self.retry_cleanup()

    def retry_cleanup(self):
        settings = self.store.read()
        if not settings.pending_items:
            return True
        remaining = []
        for item in settings.pending_items:
            try:
                self.keyring.remove(item)
            except KeyringError:
                remaining.append(item)
        if tuple(remaining) != settings.pending_items:
            try:
                self.store.write(replace(settings, pending_items=tuple(remaining)))
            except SettingsError:
                return False
        return not remaining
