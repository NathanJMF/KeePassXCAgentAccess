import json
from pathlib import Path
from threading import Event
from tempfile import TemporaryDirectory
from unittest import TestCase

from pykeepass import create_database

from keepassxc_agent_access.protocol import RESPONSE_LIMIT
from keepassxc_agent_access.vault import VaultTarget, open_vault


class EntryProjectionTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / "synthetic.kdbx"
        self.password = "Synthetic vault master password"
        self.vault = create_database(self.database, self.password)

    def listing(self):
        with open_vault(VaultTarget(self.database), self.password, Event()) as session:
            first = session.list_entries()
            self.assertEqual(first, session.list_entries())
        return first

    def test_titles_group_paths_stable_ids_and_recycle_bin(self):
        root = self.vault.root_group
        projects = self.vault.add_group(root, "Projects")
        sandbox = self.vault.add_group(projects, "Sandbox")
        visible_parent = self.vault.add_group(root, "Archive")
        root_entry = self.vault.add_entry(root, "Fixture root", "SYNTHETIC USER", "SYNTHETIC PASSWORD",
                                          url="https://synthetic.invalid/", notes="SYNTHETIC NOTES")
        binary = self.vault.add_binary(b"SYNTHETIC ATTACHMENT")
        root_entry.add_attachment(binary, "synthetic-attachment")
        nested = self.vault.add_entry(sandbox, "Duplicate", "", "")
        other = self.vault.add_entry(visible_parent, "Duplicate", "", "")
        trashed = self.vault.add_entry(root, "Discarded", "", "")
        self.vault.trash_entry(trashed)
        recycle_group = self.vault.recyclebin_group
        recycle_group.name = "Archive"
        recycle_child = self.vault.add_group(recycle_group, "Nested bin")
        self.vault.add_entry(recycle_child, "Discarded nested", "", "")
        self.vault.save()
        before = self.database.read_bytes()
        raw = self.listing()
        self.assertEqual(before, self.database.read_bytes())
        self.assertNotIn(b"SYNTHETIC", raw)
        self.assertNotIn(b"synthetic.invalid", raw)
        self.assertNotIn(b"synthetic-attachment", raw)
        expected = [
            {"id": str(root_entry.uuid), "title": "Fixture root", "group_path": []},
            {"id": str(other.uuid), "title": "Duplicate", "group_path": ["Archive"]},
            {"id": str(nested.uuid), "title": "Duplicate", "group_path": ["Projects", "Sandbox"]},
        ]
        self.assertCountEqual(json.loads(raw)["entries"], expected)

        self.vault.move_entry(nested, visible_parent)
        nested.title = "Renamed"
        self.vault.save()
        expected[2].update(title="Renamed", group_path=["Archive"])
        self.assertCountEqual(json.loads(self.listing())["entries"], expected)

    def test_empty_vault(self):
        self.assertEqual(json.loads(self.listing()), {"entries": []})

    def test_rejects_oversized_listing_without_partial_metadata(self):
        self.vault.add_entry(self.vault.root_group, "x" * RESPONSE_LIMIT, "", "")
        self.vault.save()
        self.assertEqual(json.loads(self.listing()), {"error": "too_large"})
