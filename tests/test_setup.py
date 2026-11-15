from dataclasses import replace
from pathlib import Path
import tempfile
from unittest import TestCase
from unittest.mock import patch

from pykeepass import create_database, PyKeePass

from keepassxc_agent_access.controller import VaultController, VaultState
from keepassxc_agent_access.keyring import KeyringError
from keepassxc_agent_access.settings import SettingsError, SettingsStore
from keepassxc_agent_access.setup import VaultSetup
from keepassxc_agent_access.vault import UnlockCancelled, VaultError, VaultTarget


class TestKeyring:
    def __init__(self):
        self.items = {}
        self.fail_remember = False
        self.fail_retrieve = False
        self.fail_remove = False

    def remember(self, item, password, cancellable=None):
        if self.fail_remember:
            raise KeyringError("Keyring unavailable.")
        self.items[item] = password

    def retrieve(self, item, cancellable=None):
        if self.fail_retrieve or item not in self.items:
            raise KeyringError("Saved item unavailable.")
        return self.items[item]

    def remove(self, item):
        if self.fail_remove:
            raise KeyringError("Keyring cleanup pending.")
        self.items.pop(item, None)


class SetupTests(TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.password = "Synthetic setup passphrase"
        self.target = VaultTarget(self.root / "fixture.kdbx")
        create_database(self.target.database, self.password)
        self.store = SettingsStore(self.root / "private" / "settings.json")
        self.keyring = TestKeyring()
        self.setup = self.restart()

    def restart(self):
        controller = VaultController()
        self.addCleanup(controller.lock)
        return VaultSetup(self.store, self.keyring, controller)

    def configure(self, remember, password=None, target=None):
        controller = self.setup.controller
        return self.setup.configure(
            controller.begin(), target or self.target, password or self.password, remember
        )

    def test_opt_in_and_unlock_after_restart(self):
        self.configure(True)
        initial = self.store.read()
        self.assertEqual(self.keyring.items, {initial.active_item: self.password})
        self.assertNotIn(self.password, self.store.path.read_text())
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.store.path.parent.stat().st_mode & 0o777, 0o700)
        reopened = self.restart()
        self.assertIs(reopened.controller.state(True), VaultState.LOCKED)
        reopened.unlock(reopened.controller.begin())
        self.assertEqual(reopened.controller.source, "keyring")

    def test_session_only_requires_manual_unlock(self):
        self.configure(False)
        self.assertFalse(self.keyring.items)
        with self.assertRaises(KeyringError):
            self.setup.unlock(self.setup.controller.begin())
        self.setup.unlock(self.setup.controller.begin(), self.password)
        self.assertEqual(self.setup.controller.source, "manual")

    def test_wrong_password_missing_database_and_cancellation_preserve_settings(self):
        self.configure(True)
        original = self.store.read()
        with self.assertRaises(VaultError):
            self.configure(False, password="wrong")
        with self.assertRaises(VaultError):
            self.configure(False, target=VaultTarget(self.root / "missing.kdbx"))
        attempt = self.setup.controller.begin()
        attempt.set()
        with self.assertRaises(UnlockCancelled):
            self.setup.configure(attempt, self.target, self.password, False)
        self.assertEqual(self.store.read(), original)
        self.assertEqual(len(self.keyring.items), 1)

    def test_unavailable_keyring_and_recovery(self):
        self.keyring.fail_remember = True
        with self.assertRaises(KeyringError):
            self.configure(True)
        self.assertIsNone(self.store.read().target)
        self.configure(False)
        self.keyring.fail_remember = False
        self.configure(True)
        self.keyring.fail_retrieve = True
        with self.assertRaises(KeyringError):
            self.setup.unlock(self.setup.controller.begin())
        self.assertIs(self.setup.controller.state(True), VaultState.LOCKED)
        self.setup.unlock(self.setup.controller.begin(), self.password)

    def test_replacement_and_session_only_remove_obsolete_items(self):
        self.configure(True)
        old = self.store.read().active_item
        rotated = "Rotated synthetic setup passphrase"
        vault = PyKeePass(self.target.database, password=self.password)
        vault.password = rotated
        vault.save()
        with self.assertRaises(VaultError):
            self.setup.unlock(self.setup.controller.begin())
        self.configure(True, rotated)
        current = self.store.read().active_item
        self.assertNotEqual(old, current)
        self.assertEqual(self.keyring.items, {current: rotated})
        self.configure(False, rotated)
        self.assertFalse(self.keyring.items)
        self.assertIsNone(self.store.read().active_item)

    def test_failed_commit_preserves_previous_configuration(self):
        self.configure(True)
        original = self.store.read()
        write = self.store.write

        def fail_replacement(settings):
            if settings.active_item != original.active_item:
                raise SettingsError("Commit failed.")
            write(settings)

        with patch.object(self.store, "write", side_effect=fail_replacement):
            with self.assertRaises(SettingsError):
                self.configure(True)
        self.assertEqual(self.store.read(), original)
        self.assertEqual(self.keyring.items, {original.active_item: self.password})

    def test_retry_and_forget_never_unlock_with_pending_items(self):
        self.configure(True)
        first = self.store.read().active_item
        self.keyring.fail_remove = True
        self.assertFalse(self.configure(True))
        current = self.store.read().active_item
        reopened = self.restart()
        self.assertEqual(self.store.read().pending_items, (first,))
        with patch.object(self.keyring, "retrieve", wraps=self.keyring.retrieve) as retrieve:
            attempt = reopened.controller.begin()
            reopened.unlock(attempt)
            retrieve.assert_called_once_with(current, attempt.keyring_request)
        self.assertFalse(reopened.forget())
        settings = self.store.read()
        self.assertEqual(settings.pending_items, (first, current))
        self.assertIsNone(settings.active_item)
        self.assertIs(reopened.controller.state(True), VaultState.LOCKED)
        after_restart = self.restart()
        with self.assertRaises(KeyringError):
            after_restart.unlock(after_restart.controller.begin())
        self.keyring.fail_remove = False
        self.assertTrue(after_restart.retry_cleanup())
        self.assertFalse(self.keyring.items)
        self.assertFalse(self.store.read().pending_items)

    def test_interrupted_keyring_write_recovers_from_pending_reference(self):
        self.configure(True)
        previous = self.store.read()
        self.keyring.items["interrupted"] = self.password
        self.store.write(replace(previous, pending_items=("interrupted",)))
        reopened = self.restart()
        self.assertTrue(reopened.retry_cleanup())
        self.assertEqual(self.store.read(), previous)
        self.assertNotIn("interrupted", self.keyring.items)
