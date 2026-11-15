from dataclasses import replace
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from keepassxc_agent_access.access_settings import AccessMode, AccessStore, Action, Destination, VaultPolicy
from keepassxc_agent_access.activity import ActivityError, ActivityStore, Attribution
from keepassxc_agent_access.broker import BrokerConfig


class AccessStorageTests(TestCase):
    def setUp(self):
        folder = TemporaryDirectory(dir="/tmp")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)

    def test_defaults_and_vault_bindings_survive_restart(self):
        store = AccessStore(self.root / "access.json")
        default = store.read()
        self.assertEqual(default.mode, AccessMode.REVIEW)
        fallback = BrokerConfig(self.root / "existing.sock", os.geteuid() + 1)
        self.assertEqual(default.broker_config(fallback), fallback)
        vault, other, stable_id = (str(uuid4()) for _ in range(3))
        policy = VaultPolicy(frozenset({stable_id}), (
            Action("verify", "Verify service", stable_id, "https://example.invalid/check"),
        ))
        saved = replace(default, mode=AccessMode.SMART, endpoint=str(self.root / "broker.sock"),
                        uid=os.geteuid() + 1, vaults=((vault, policy),))
        store.write(saved)
        reopened = AccessStore(store.path).read()
        self.assertEqual(reopened, saved)
        self.assertEqual(reopened.for_vault(vault), policy)
        self.assertNotIn(stable_id, reopened.for_vault(other).automatic)
        self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)

    def test_refuses_ambiguous_destinations(self):
        for invalid in ("http://test.invalid/", "https://user@host.invalid/", "https://test.invalid/?x=y",
                        "https://test.invalid/#", "https://test.invalid:0/", "https://[::1]extra/",
                        "https://test.invalid//other", "https://test.invalid/\nfoo"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                Destination.parse(invalid)
        self.assertEqual(Destination.parse("https://[::1]:443/check").url, "https://[::1]:443/check")

    def test_activity_sessions_per_request_labels_and_recovery(self):
        store = ActivityStore(self.root / "activity.sqlite")
        store.recover(30)
        first_context = Attribution.parse({"model": "Fixture model 1", "chat": "Original", "chat_id": "fixture"})
        second_context = Attribution.parse({"model": "Fixture model 2", "chat": "Renamed", "chat_id": "fixture"})
        first = store.begin(123, first_context, "Verified service", "https://example.invalid:443/check")
        store.authorize(first, "Approved once")
        store.dispatched(first)
        second = store.begin(123, second_context, "List", None)
        store.finish(second, "Declined")
        store.recover(30)
        rows = store.rows()
        self.assertEqual([row["chat"] for row in rows], ["Renamed", "Original"])
        self.assertEqual(len({row["session"] for row in rows}), 1)
        self.assertEqual([row["model"] for row in rows], ["Fixture model 2", "Fixture model 1"])
        self.assertTrue(all(row["uid"] == 123 and row["completed"] >= row["requested"] for row in rows))
        self.assertEqual(rows[1]["outcome"], "Interrupted · outcome unknown")
        self.assertEqual(store.rows(model="model 2", outcome="declined")[0]["id"], second)
        self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)
        with patch("keepassxc_agent_access.activity.time", return_value=4102444800):
            store.prune(30)
        self.assertEqual(store.rows(), [])

    def test_activity_rejects_claimed_provenance_and_unprotected_database(self):
        with self.assertRaises(ValueError):
            Attribution.parse({"model": "Fixture model", "verified": True})
        path = self.root / "activity.sqlite"
        path.touch(mode=0o644)
        with self.assertRaises(ActivityError):
            ActivityStore(path).recover(30)
