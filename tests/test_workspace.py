from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

from pykeepass import create_database

from keepassxc_agent_access.access_settings import AccessMode, AccessSettings, Action, VaultPolicy
from keepassxc_agent_access.settings import Settings, SettingsStore
from keepassxc_agent_access.vault import VaultError, VaultTarget
from keepassxc_agent_access.workspace import Workspace


class Keyring:
    def __init__(self):
        self.items = {}

    def retrieve(self, item):
        return self.items[item]

    def remember(self, item, password):
        self.items[item] = password

    def remove(self, item):
        self.items.pop(item, None)


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.primary = self.root / "first.kdbx"
        self.copy = self.root / "second.kdbx"
        self.password = "Synthetic registration unlock"
        self.vault = create_database(self.primary, self.password)
        self.group = self.vault.add_group(self.vault.root_group, "Nested")
        self.entry = self.vault.add_entry(self.group, "Fixture", "synthetic", "Synthetic entry secret")
        self.vault.save()
        shutil.copyfile(self.primary, self.copy)
        self.keyring = Keyring()
        self.workspace = Workspace(self.root, self.keyring)
        self.addCleanup(self.workspace.lock_all)

    def test_copies_and_independent_sessions(self):
        first = self.workspace.add(VaultTarget(self.primary), self.password, True)
        second = self.workspace.add(VaultTarget(self.copy), self.password, False)
        first_session = self.workspace.session(first)
        second_session = self.workspace.session(second)
        self.assertNotEqual(first, second)
        self.assertEqual(first_session.worker.identity, second_session.worker.identity)
        self.assertEqual(first_session.entries, second_session.entries)
        self.assertEqual(first_session.entries[0]["group"], str(self.group.uuid))
        alias = self.root / "alias.kdbx"
        alias.hardlink_to(self.primary)
        with self.assertRaisesRegex(VaultError, "already registered"):
            self.workspace.add(VaultTarget(alias), self.password, False)
        self.workspace.lock(first)
        self.assertFalse(first_session.worker.available)
        self.assertIs(self.workspace.session(second), second_session)
        self.workspace.remove(first)
        self.assertEqual(self.keyring.items, {})
        self.assertTrue(self.primary.is_file())

    def test_migrate_legacy_keyring_and_bindings_and_relink(self):
        target = VaultTarget(self.primary)
        SettingsStore(self.root / "settings.json").write(Settings(target, "fixture-item", ("stale-item",)))
        self.keyring.items.update({"fixture-item": self.password, "stale-item": "stale fixture"})
        action = Action("check", "Check", str(self.entry.uuid), "https://example.test/")
        self.workspace.legacy_access.write(AccessSettings(
            AccessMode.ALLOW, vaults=((str(self.vault.root_group.uuid), VaultPolicy(actions=(action,))),),
        ))
        workspace = Workspace(self.root, self.keyring)
        self.addCleanup(workspace.lock_all)
        identifier, = workspace.registrations
        workspace.unlock(identifier)
        self.assertTrue(workspace.paused)
        record = workspace.registrations[identifier]
        self.assertEqual(record.item, "fixture-item")
        self.assertEqual(record.bindings[0].action, action)
        self.assertEqual(list(self.keyring.items), ["fixture-item"])
        moved = self.primary.rename(self.root / "moved.kdbx")
        wrong = self.root / "wrong.kdbx"
        create_database(wrong, self.password)
        with self.assertRaisesRegex(VaultError, "does not match"):
            workspace.relink(identifier, VaultTarget(wrong), self.password)
        workspace.relink(identifier, VaultTarget(moved), self.password)
        self.assertEqual(workspace.registrations[identifier].target.database, moved)
        workspace.remove(identifier)
        self.assertTrue(moved.exists())
        self.assertFalse(Workspace(self.root, self.keyring).registrations)
