import hashlib
import subprocess
from pathlib import Path
import tempfile
from threading import Event
import unittest
from unittest.mock import patch

from pykeepass import create_database

from keepassxc_agent_access.vault import UnlockCancelled, VaultError, VaultTarget, open_vault


class VaultTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.database = self.root / "fixture.kdbx"
        self.password = "Synthetic fixture password \u2603\n"

    def test_password_unlock_is_read_only(self):
        create_database(self.database, self.password)
        before = hashlib.sha256(self.database.read_bytes()).digest()
        with open_vault(VaultTarget(self.database), self.password, Event()) as session:
            self.assertIsNone(session._process.poll())
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).digest(), before)

    def test_password_and_key_file(self):
        key_file = self.root / "fixture.key"
        key_file.write_bytes(bytes(range(32)))
        create_database(self.database, self.password, str(key_file))
        before = self.database.read_bytes()
        with open_vault(VaultTarget(self.database, key_file), self.password, Event()):
            pass
        with self.assertRaisesRegex(VaultError, "rejected"):
            open_vault(VaultTarget(self.database), self.password, Event())
        with self.assertRaisesRegex(VaultError, "key file is missing"):
            open_vault(VaultTarget(self.database, self.root / "missing.key"), self.password, Event())
        self.assertEqual(self.database.read_bytes(), before)

    def test_wrong_password_and_invalid_database(self):
        create_database(self.database, self.password)
        with self.assertRaisesRegex(VaultError, "rejected"):
            open_vault(VaultTarget(self.database), "wrong", Event())
        self.database.write_bytes(b"Synthetic invalid database")
        with self.assertRaisesRegex(VaultError, "could not be opened"):
            open_vault(VaultTarget(self.database), self.password, Event())

    def test_worker_arguments_and_errors_exclude_passwords(self):
        create_database(self.database, self.password)
        target = VaultTarget(self.database)
        wrong = "Synthetic wrong password"
        with patch("keepassxc_agent_access.vault.subprocess.Popen", wraps=subprocess.Popen) as popen:
            with open_vault(target, self.password, Event()):
                pass
            with self.assertRaises(VaultError) as error:
                open_vault(target, wrong, Event())
        for call in popen.call_args_list:
            self.assertNotIn(self.password, repr(call))
            self.assertNotIn(wrong, repr(call))
            self.assertIs(call.kwargs["stderr"], subprocess.DEVNULL)
        self.assertNotIn(wrong, str(error.exception))

    def test_cancelled_unlock(self):
        cancelled = Event()
        cancelled.set()
        with self.assertRaises(UnlockCancelled):
            open_vault(VaultTarget(self.database), self.password, cancelled)
