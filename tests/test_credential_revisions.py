"""Reusable use grants stay bound to the reviewed credential version."""

from dataclasses import asdict
import json
import os
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
from uuid import UUID, uuid4

from pykeepass import PyKeePass, create_database

from keepassxc_agent_access.activity import ActivityStore, Attribution
from keepassxc_agent_access.grants import Grants, Scope
from keepassxc_agent_access.vault import VaultTarget
from keepassxc_agent_access.workspace import Workspace


class CredentialRevisionTests(TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "synthetic.kdbx"
        self.unlock = "synthetic revision unlock"
        database = create_database(self.path, self.unlock)
        self.parent = str(database.root_group.uuid)
        self.first = str(database.add_entry(database.root_group, "First", "first-user", "first-secret").uuid)
        self.second = str(database.add_entry(database.root_group, "Second", "second-user", "second-secret").uuid)
        database.save()
        self.workspace = Workspace(self.root, None)
        self.addCleanup(self.workspace.lock_all)
        self.vault = self.workspace.add(VaultTarget(self.path), self.unlock, False)
        self.activity = ActivityStore(self.root / "activity.sqlite")
        self.activity.recover(30)
        self.grants = Grants(self.workspace, self.activity)
        self.credential = "ab" * 32

    def revision(self, entry=None):
        return self.workspace.credential_revision(self.vault, entry or self.first)

    def approve(self):
        status = self.grants.enroll(self.credential, 1500,
                                    {"identity": "Revision Trial", "project": "Synthetic",
                                     "items": [{"vault": self.vault, "entry": self.first, "uses": ["local_command"]}]},
                                    Attribution())
        self.assertEqual(status, "pending")
        grant = self.grants.authenticate(self.credential, 1500)
        choice, = self.grants.choices(grant.items[0])
        self.grants.decide(grant.id, [choice])
        return self.grants.records[grant.id]

    def update(self, entry=None, **fields):
        entry = entry or self.first
        row = next(row for row in self.workspace.session(self.vault).entries if row["id"] == entry)
        values = {"title": row["title"], "username": row["username"], "url": row["url"], **fields}
        return self.workspace.put_entry(self.vault, self.parent, entry=entry, **values)

    def test_legacy_registry_fallback_does_not_write_and_survives_lock_restart(self):
        self.workspace.lock(self.vault)
        saved = json.loads(self.workspace.path.read_text())
        for record in saved["vaults"]:
            record.pop("credential_epoch", None)
            record.pop("credential_nonces", None)
        self.workspace.path.write_text(json.dumps(saved))
        original = self.workspace.path.read_bytes()
        reopened = Workspace(self.root, None)
        self.addCleanup(reopened.lock_all)
        before = reopened.credential_revision(self.vault, self.first)
        self.assertRegex(before, r"^[0-9a-f]{64}$")
        self.assertEqual(reopened.path.read_bytes(), original)
        reopened.unlock(self.vault, self.unlock)
        self.assertEqual(reopened.credential_revision(self.vault, self.first), before)
        self.assertEqual(reopened.path.read_bytes(), original)
        reopened.lock(self.vault)
        again = Workspace(self.root, None)
        self.assertEqual(again.credential_revision(self.vault, self.first), before)
        legacy_scope = asdict(Scope(self.vault, self.first, True, None, None))
        legacy_scope.pop("use_revision")
        self.assertIsNone(Scope(**legacy_scope).use_revision)

    def test_metadata_edits_and_unrelated_credentials_preserve_target_revision(self):
        grant = self.approve()
        before = self.revision()
        other = self.revision(self.second)
        self.assertEqual(grant.scope[0].use_revision, before)
        from keepassxc_agent_access.scoped_broker import access_details
        wire = json.dumps(access_details(grant))
        self.assertNotIn("use_revision", wire)
        self.assertNotIn(before, wire)
        self.update(title="Updated title", url="https://changed.example.invalid/", notes="private synthetic note")
        self.assertEqual(self.revision(), before)
        self.assertEqual(self.revision(self.second), other)
        self.update(self.second, username="changed-second-user", password="changed-second-secret")
        self.assertEqual(self.revision(), before)
        self.assertNotEqual(self.revision(self.second), other)
        self.assertEqual(self.grants.records[grant.id].scope[0].use_revision, before)
        persisted = Workspace(self.root, None)
        self.assertEqual(persisted.credential_revision(self.vault, self.first), before)

    def test_password_username_and_generated_password_each_invalidate_without_bindings(self):
        grant = self.approve()
        self.assertFalse(self.workspace.registrations[self.vault].bindings)
        revision = self.revision()
        self.update(password="rotated-first-secret")
        self.assertNotEqual(self.revision(), revision)
        self.assertNotEqual(self.grants.records[grant.id].scope[0].use_revision, self.revision())
        revision = self.revision()
        self.update(username="rotated-first-user")
        self.assertNotEqual(self.revision(), revision)
        revision = self.revision()
        row = next(row for row in self.workspace.session(self.vault).entries if row["id"] == self.first)
        self.workspace._edit(self.vault, "put_entry", parent=self.parent, entry=self.first,
                             title=row["title"], username=row["username"], url=row["url"],
                             password=None, generate_password=True)
        self.assertNotEqual(self.revision(), revision)
        self.workspace.lock(self.vault)
        reopened = Workspace(self.root, None)
        self.addCleanup(reopened.lock_all)
        persisted = reopened.credential_revision(self.vault, self.first)
        reopened.unlock(self.vault, self.unlock)
        self.assertEqual(reopened.credential_revision(self.vault, self.first), persisted)
        self.assertNotEqual(persisted, grant.scope[0].use_revision)

    def test_precommit_revision_is_durable_even_when_the_credential_edit_is_aborted(self):
        grant = self.approve()
        before = self.revision()
        fingerprint = self.workspace.registrations[self.vault].fingerprint
        observed = []
        flushes = []
        real_fsync = os.fsync
        def sync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                flushes.append("directory")
            real_fsync(descriptor)
        def stop_before_publish():
            self.assertIn("directory", flushes)
            saved = Workspace(self.root, None)
            observed.append(saved.credential_revision(self.vault, self.first))
            self.assertNotEqual(observed[-1], before)
            raise RuntimeError("Synthetic precommit cancellation")
        with patch("keepassxc_agent_access.workspace.os.fsync", side_effect=sync), \
                self.assertRaisesRegex(RuntimeError, "precommit cancellation"):
            self.workspace._edit(self.vault, "put_entry", parent=self.parent, entry=self.first,
                                 title="First", username="first-user", url="", password="never-committed-secret",
                                 before_commit=stop_before_publish)
        self.assertEqual(self.revision(), observed[0])
        self.assertEqual(self.workspace.registrations[self.vault].fingerprint, fingerprint)
        self.assertNotEqual(self.grants.records[grant.id].scope[0].use_revision, observed[0])
        database = PyKeePass(self.path, password=self.unlock)
        self.assertEqual(database.find_entries(uuid=UUID(self.first), first=True).password, "first-secret")

    def test_external_replacement_rotates_epoch_for_every_entry_until_owner_regrant(self):
        grant = self.approve()
        self.update(password="internal rotation first")
        before = self.revision()
        other = self.revision(self.second)
        self.workspace.lock(self.vault)
        database = PyKeePass(self.path, password=self.unlock)
        database.find_entries(uuid=UUID(self.first), first=True).password = "external rotated credential"
        database.save()
        self.workspace.unlock(self.vault, self.unlock)
        record = self.workspace.registrations[self.vault]
        self.assertIsNotNone(record.credential_epoch)
        self.assertEqual(record.credential_nonces, ())
        self.assertNotEqual(self.revision(), before)
        self.assertNotEqual(self.revision(self.second), other)
        self.assertNotEqual(self.grants.records[grant.id].scope[0].use_revision, self.revision())
        # An explicit permission replacement pins the currently reviewed value.
        request = {"identity": grant.identity, "project": grant.project, "change_id": str(uuid4()),
                   "items": [{"vault": self.vault, "entry": self.first, "uses": ["local_command"]}]}
        self.assertEqual(self.grants.enroll(self.credential, 1500, request, Attribution()), "pending")
        pending = self.grants.records[grant.id].pending_change
        choice, = self.grants.choices(pending.items[0])
        self.grants.decide(grant.id, [choice], change_id=pending.id)
        self.assertEqual(self.grants.records[grant.id].scope[0].use_revision, self.revision())

    def test_agent_request_cannot_supply_credential_revision(self):
        from keepassxc_agent_access.grants import Item
        with self.assertRaises(ValueError):
            Item.parse({"vault": self.vault, "entry": self.first, "uses": ["local_command"],
                        "use_revision": self.revision()})
