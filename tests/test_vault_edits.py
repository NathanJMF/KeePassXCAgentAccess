import errno
from hashlib import sha256
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
import unittest
from unittest.mock import patch
from uuid import UUID

from pykeepass import PyKeePass, create_database

from keepassxc_agent_access import vault_edits
from keepassxc_agent_access.vault import VaultChanged, VaultError, VaultTarget, open_vault
from keepassxc_agent_access.workspace import Workspace


class VaultEditsTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / "test.kdbx"
        self.key = self.root / "fixture.key"
        self.key.write_bytes(bytes(range(32)))
        self.unlock = "Synthetic fixture unlock"
        self.target = VaultTarget(self.path, self.key)
        self.fixture = create_database(self.path, self.unlock, keyfile=str(self.key))
        self.entry = self.fixture.add_entry(
            self.fixture.root_group, "Fixture", "previous username", "Synthetic original password",
            notes="Preserve notes",
        )
        self.fixture.save()
        self.path.chmod(0o640)
        self.workspace = Workspace(self.root, None)
        self.addCleanup(self.workspace.lock_all)

    def _open(self):
        return self.workspace.add(self.target, self.unlock, False)

    def test_edit_move_and_recycle_preserve_kdbx_and_password(self):
        os.setxattr(self.path, "user.keeper-fixture", b"preserve")
        vault = self._open()
        original = self.workspace.session(vault)
        first = self.workspace.put_group(vault, original.worker.identity, name="First")
        second = self.workspace.put_group(vault, first, name="Second")
        self.assertEqual(self.workspace.put_group(vault, None, name="Relocated", group=second), second)
        new_entry = self.workspace.put_entry(vault, second, title="New entry", password="Synthetic new password")
        entry = str(self.entry.uuid)
        self.assertEqual(self.workspace.put_entry(
            vault, second, title="Edited", username="fixture-account", url="https://example.invalid",
            entry=entry,
        ), entry)
        session = self.workspace.session(vault)
        self.assertIsNot(session, original)
        rows = session.worker.scoped_entries([entry])["entries"]
        self.assertEqual(rows, [{"id": entry, "title": "Edited", "group_path": ["Relocated"]}])
        owner = {row["id"]: row for row in session.entries}
        self.assertEqual(owner[entry]["username"], "fixture-account")
        self.assertTrue(all("password" not in row for row in session.entries))

        self.workspace.remove_entry(vault, new_entry)
        self.workspace.remove_group(vault, second)
        self.assertEqual(self.workspace.session(vault).entries, ())
        current = PyKeePass(self.path, password=self.unlock, keyfile=str(self.key))
        edited = current.find_entries(uuid=self.entry.uuid, first=True)
        self.assertEqual(edited.password, "Synthetic original password")
        self.assertEqual(edited.notes, "Preserve notes")
        self.assertEqual(edited.history[0].title, "Fixture")
        self.assertEqual(edited.group.parentgroup.uuid, current.recyclebin_group.uuid)
        newly_created = current.find_entries(uuid=UUID(new_entry), first=True)
        self.assertEqual(newly_created.group.uuid, current.recyclebin_group.uuid)
        self.assertEqual(newly_created.password, "Synthetic new password")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o640)
        self.assertEqual(os.getxattr(self.path, "user.keeper-fixture"), b"preserve")
        self.assertEqual(self.workspace.registrations[vault].fingerprint, sha256(self.path.read_bytes()).hexdigest())

        before = self.fixture.kdbx.header.value.dynamic_header
        after = current.kdbx.header.value.dynamic_header
        self.assertNotEqual(before.master_seed.data, after.master_seed.data)
        self.assertNotEqual(before.encryption_iv.data, after.encryption_iv.data)
        inner_before = self.fixture.kdbx.body.payload.inner_header
        inner_after = current.kdbx.body.payload.inner_header
        self.assertNotEqual(inner_before.protected_stream_key.data, inner_after.protected_stream_key.data)

    def test_external_update_blocks_edit_and_invalidates_only_stale_session(self):
        vault = self._open()
        unrelated = self.root / "unrelated.kdbx"
        create_database(unrelated, self.unlock)
        other = self.workspace.add(VaultTarget(unrelated), self.unlock, False)
        stable = self.workspace.session(other)
        self.fixture.add_group(self.fixture.root_group, "Externally saved")
        self.fixture.save()
        external = self.path.read_bytes()

        with self.assertRaisesRegex(VaultChanged, "changed on disk"):
            self.workspace.put_group(vault, None, name="Uncommitted")
        self.assertEqual(self.path.read_bytes(), external)
        self.assertIsNone(self.workspace.session(vault))
        self.assertIs(self.workspace.session(other), stable)
        self.workspace.unlock(vault, self.unlock)
        self.assertIn("Externally saved", {group["name"] for group in self.workspace.session(vault).groups})

    def test_invalid_move_and_read_only_workers_do_not_modify_disk(self):
        vault = self._open()
        parent = self.workspace.put_group(vault, None, name="Parent")
        child = self.workspace.put_group(vault, parent, name="Child")
        before = self.path.read_bytes()
        old = self.workspace.session(vault)
        with self.assertRaisesRegex(VaultError, "outside the group"):
            self.workspace.put_group(vault, child, name="Parent", group=parent)
        with self.assertRaisesRegex(VaultError, "invalid"):
            self.workspace.remove_group(vault, old.worker.identity)
        self.assertIs(self.workspace.session(vault), old)

        with open_vault(self.target, self.unlock, Event()) as reader:
            with self.assertRaisesRegex(VaultError, "read-only"):
                reader.owner_edit({"change": "put_group", "parent": None, "name": "Denied", "group": None},
                                  lambda send: self.fail("Read-only worker reached commit"))
        self.assertEqual(self.path.read_bytes(), before)

    def test_external_save_after_staging_is_not_overwritten(self):
        vault = self._open()
        old = self.workspace.session(vault)
        edit = old.worker.owner_edit

        def commit_external_change(change, gate):
            def gate_after_save(send):
                self.assertIsNone(self.workspace.session(vault))
                self.fixture.add_group(self.fixture.root_group, "Concurrent save")
                self.fixture.save()
                return gate(send)

            return edit(change, gate_after_save)

        with patch.object(old.worker, "owner_edit", side_effect=commit_external_change):
            with self.assertRaisesRegex(VaultChanged, "changed on disk"):
                self.workspace.put_group(vault, None, name="Keeper edit")
        self.assertIsNone(self.workspace.session(vault))
        self.assertFalse(list(self.root.glob(".keeper-*")))
        reopened = PyKeePass(self.path, password=self.unlock, keyfile=str(self.key))
        self.assertIsNotNone(reopened.find_groups(name="Concurrent save", first=True))
        self.assertIsNone(reopened.find_groups(name="Keeper edit", first=True))

    def test_named_staging_preserves_xattrs_and_unrelated_paths(self):
        attr = "user.keeper-fixture"
        os.setxattr(self.path, attr, b"preserve")
        unrelated = self.root / attr
        unrelated.write_bytes(b"unrelated fixture")
        open_file = os.open

        def named_files_only(path, flags, *args, **kwargs):
            if flags & os.O_TMPFILE == os.O_TMPFILE:
                raise OSError(errno.EOPNOTSUPP, "fixture filesystem uses named staging")
            return open_file(path, flags, *args, **kwargs)

        stamp = vault_edits.file_stamp(self.path.stat())
        change = {"change": "put_group", "parent": None, "name": "Committed group", "group": None}
        opened = PyKeePass(self.path, password=self.unlock, keyfile=str(self.key))
        with patch.object(vault_edits.os, "open", side_effect=named_files_only):
            vault_edits.stage_edit(opened, self.path, stamp, change, lambda: None, lambda: True)

        reopened = PyKeePass(self.path, password=self.unlock, keyfile=str(self.key))
        self.assertIsNotNone(reopened.find_groups(name="Committed group", first=True))
        self.assertEqual(os.getxattr(self.path, attr), b"preserve")
        self.assertEqual(unrelated.read_bytes(), b"unrelated fixture")
        self.assertFalse(list(self.root.glob(".keeper-*")))

    def test_worker_stages_then_aborts_if_commit_is_not_authorized(self):
        vault = self._open()
        old = self.workspace.session(vault)
        before = self.path.read_bytes()
        with self.assertRaisesRegex(VaultError, "locked"):
            old.worker.owner_edit({"change": "put_group", "parent": None, "name": "Aborted", "group": None},
                                  lambda send: False)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(list(self.root.glob(".keeper-*")))
        self.assertTrue(old.worker.available)


if __name__ == "__main__":
    unittest.main()
