from dataclasses import replace
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from keepassxc_agent_access.access_settings import (
    DEFAULT_TOKEN_LIFESPAN_DAYS, MAX_TOKEN_LIFESPAN_DAYS, MIN_TOKEN_LIFESPAN_DAYS,
    AccessMode, AccessStore, Action, ActionType, BrowserForm, Destination, VaultPolicy,
)
from keepassxc_agent_access.activity import ActivityError, ActivityStore, Attribution
from keepassxc_agent_access.broker import BrokerConfig
from keepassxc_agent_access.settings import SettingsError


class AccessStorageTests(TestCase):
    def setUp(self):
        folder = TemporaryDirectory(dir="/tmp")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)

    def test_defaults_and_vault_bindings_survive_restart(self):
        store = AccessStore(self.root / "access.json")
        default = store.read()
        self.assertEqual(default.mode, AccessMode.REVIEW)
        self.assertTrue(default.start_unlocked)
        self.assertTrue(default.agent_paused)
        self.assertFalse(default.auto_approve_token_credential_uses)
        self.assertFalse(default.auto_approve_token_rotations)
        self.assertFalse(default.auto_approve_token_extensions)
        self.assertEqual(default.token_lifespan_days, DEFAULT_TOKEN_LIFESPAN_DAYS)
        self.assertFalse(default.unlock_on_desktop_unlock)
        self.assertFalse(default.resume_on_desktop_unlock)
        self.assertFalse(default.review_usage)
        self.assertFalse(default.review_actions)
        fallback = BrokerConfig(self.root / "existing.sock", os.geteuid() + 1)
        self.assertEqual(default.broker_config(fallback), fallback)
        vault, other, stable_id = (str(uuid4()) for _ in range(3))
        policy = VaultPolicy(frozenset({stable_id}), (
            Action("verify", "Verify service", stable_id, "https://example.invalid/check"),
        ))
        saved = replace(default, mode=AccessMode.SMART, endpoint=str(self.root / "broker.sock"),
                        uid=os.geteuid() + 1, vaults=((vault, policy),), start_unlocked=False,
                        agent_paused=False, auto_approve_token_credential_uses=True,
                        auto_approve_token_rotations=True, auto_approve_token_extensions=True,
                        token_lifespan_days=14, unlock_on_desktop_unlock=True,
                        resume_on_desktop_unlock=True,
                        auto_approve_scoped_actions=frozenset({"tls_first_pin", "tls_cert_repin"}),
                        review_actions=frozenset({"list_entries", "update_entry"}))
        store.write(saved)
        reopened = AccessStore(store.path).read()
        self.assertEqual(reopened, saved)
        self.assertEqual(reopened.for_vault(vault), policy)
        self.assertNotIn(stable_id, reopened.for_vault(other).automatic)
        self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)

    def test_token_lifespan_and_extension_auto_approval_validation(self):
        store = AccessStore(self.root / "access.json")
        store.write(store.read())
        legacy = json.loads(store.path.read_text())
        del legacy["auto_approve_token_extensions"]
        del legacy["token_lifespan_days"]
        store.path.write_text(json.dumps(legacy))
        migrated = store.read()
        self.assertFalse(migrated.auto_approve_token_extensions)
        self.assertEqual(migrated.token_lifespan_days, DEFAULT_TOKEN_LIFESPAN_DAYS)

        for field, bad_values in (
            ("auto_approve_token_extensions", (1, 0, "true", None, [])),
            ("token_lifespan_days", (MIN_TOKEN_LIFESPAN_DAYS - 1, MAX_TOKEN_LIFESPAN_DAYS + 1,
                                     True, False, "3", 3.5, None)),
        ):
            for bad in bad_values:
                with self.subTest(field=field, bad=bad):
                    store.path.write_text(json.dumps({**legacy, field: bad}))
                    with self.assertRaises(SettingsError):
                        store.read()
                    with self.assertRaises(ValueError):
                        store.write(replace(migrated, **{field: bad}))

    def test_legacy_password_review_expands_to_all_transports(self):
        store = AccessStore(self.root / "access.json")
        default = replace(store.read(), review_usage=True, start_unlocked=False,
                          auto_approve_token_changes=True)
        store.write(default)
        persisted = json.loads(store.path.read_text())
        persisted["review_actions"] = ["use_password", "use_https", "list_entries"]
        store.path.write_text(json.dumps(persisted))

        migrated = store.read()
        self.assertEqual(migrated, replace(default, review_actions=frozenset({
            "use_https", "use_local_command", "use_networked_command", "use_browser", "list_entries",
        })))
        updated = replace(migrated, review_actions=frozenset({"use_local_command", "list_entries"}))
        store.write(updated)
        self.assertEqual(AccessStore(store.path).read(), updated)
        self.assertNotIn("use_password", json.loads(store.path.read_text())["review_actions"])

    def test_refuses_ambiguous_destinations(self):
        for invalid in ("http://test.invalid/", "https://user@host.invalid/", "https://test.invalid/?x=y",
                        "https://test.invalid/#", "https://test.invalid:0/", "https://[::1]extra/",
                        "https://test.invalid//other", "https://test.invalid/\nfoo"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                Destination.parse(invalid)
        self.assertEqual(Destination.parse("https://[::1]:443/check").url, "https://[::1]:443/check")

    def test_action_type_survives_saving_and_legacy_defaults_to_basic(self):
        store = AccessStore(self.root / "actions.json")
        vault, entry = str(uuid4()), str(uuid4())
        basic = Action("legacy", "Check legacy service", entry, "https://example.invalid/legacy")
        bearer = Action("api", "Check API", entry, "https://example.invalid/api", kind=ActionType.BEARER)
        policy = VaultPolicy(actions=(basic, bearer))
        store.write(replace(store.read(), vaults=((vault, policy),)))
        persisted = json.loads(store.path.read_text())
        actions = persisted["vaults"][vault]["actions"]
        self.assertEqual(actions[1]["kind"], "https_bearer_get")
        for field in ("kind", "method", "request_json"):
            del actions[0][field]
        store.path.write_text(json.dumps(persisted))
        self.assertEqual(store.read().for_vault(vault), policy)
        with self.assertRaisesRegex(ValueError, "supported credential action"):
            replace(bearer, kind="unknown")

    def test_https_profile_validates_and_canonicalizes_fixed_json(self):
        store = AccessStore(self.root / "actions.json")
        vault, entry = str(uuid4()), str(uuid4())
        action = Action("api", "Trigger API", entry, "https://example.invalid/api", kind=ActionType.BEARER,
                        method="POST", request_json='{ "priority": 2, "name": "café" }')
        self.assertEqual(action.request_json, '{"name":"café","priority":2}')
        self.assertEqual(action.scope, replace(action, request_json='{"priority":2,"name":"café"}').scope)
        self.assertNotEqual(action.scope, replace(action, method="PATCH").scope)
        self.assertNotEqual(action.scope, replace(action, request_json='{"priority":3}').scope)
        policy = VaultPolicy(actions=(action,))
        store.write(replace(store.read(), vaults=((vault, policy),)))
        self.assertEqual(AccessStore(store.path).read().for_vault(vault), policy)
        for body in ('["value"]', '{"a":1,"a":2}', '{"x":NaN}', '{"x":1e999}',
                     '{"x":"\\ud800"}', '{"x":"' + 'é' * 1024 + '"}',
                     '{"x":' + '[' * 1000 + '0' + ']' * 1000 + '}'):
            with self.subTest(body=body[:30]), self.assertRaises(ValueError):
                replace(action, request_json=body)
        for method in ("GET", "HEAD", "CONNECT", "POST\r\n"):
            with self.subTest(method=method), self.assertRaises(ValueError):
                replace(action, method=method)

    def test_browser_profile_is_saved_and_pins_all_form_settings(self):
        store = AccessStore(self.root / "actions.json")
        vault, entry = str(uuid4()), str(uuid4())
        browser = BrowserForm("https://example.invalid/session", "login", "user", "pass",
                              "account", "https://example.invalid/home")
        action = Action("login", "Sign in", entry, "https://example.invalid/login",
                        kind=ActionType.BROWSER, browser=browser)
        policy = VaultPolicy(actions=(action,))
        store.write(replace(store.read(), vaults=((vault, policy),)))
        self.assertEqual(AccessStore(store.path).read().for_vault(vault), policy)
        self.assertNotEqual(action.scope, replace(action, browser=replace(browser, success_id="new-id")).scope)
        self.assertNotEqual(action.scope, replace(action, browser=replace(browser, username_field="email")).scope)
        with self.assertRaisesRegex(ValueError, "same HTTPS origin"):
            replace(action, browser=replace(browser, success_url="https://other.invalid/"))
        with self.assertRaises(ValueError):
            replace(browser, username_field=browser.password_field)
        with self.assertRaises(ValueError):
            replace(action, kind=ActionType.BASIC)

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

    def test_activity_target_columns_migrate_and_preserve_historical_labels(self):
        store = ActivityStore(self.root / "activity.sqlite")
        store.recover(30)
        vault_id, entry = str(uuid4()), str(uuid4())
        legacy = store.begin(123, Attribution(), "Legacy use", None, entry, vault="Previous vault", vault_id=vault_id)
        store.finish(legacy, "Succeeded")
        with store.connection() as db:
            db.execute("ALTER TABLE activity DROP COLUMN folder")
            db.execute("ALTER TABLE activity DROP COLUMN entry_title")
            db.execute("ALTER TABLE activity DROP COLUMN group_id")
            db.execute("ALTER TABLE activity DROP COLUMN edit_request_id")

        reopened = ActivityStore(store.path)
        reopened.recover(30)
        legacy_row, = reopened.rows()
        self.assertEqual((legacy_row["vault"], legacy_row["vault_id"], legacy_row["entry"]),
                         ("Previous vault", vault_id, entry))
        self.assertIsNone(legacy_row["folder"])
        self.assertIsNone(legacy_row["entry_title"])
        self.assertIsNone(legacy_row["group_id"])
        self.assertIsNone(legacy_row["edit_request_id"])

        event = reopened.begin(123, Attribution(), "Create entry", "Root", vault="Example vault",
                               vault_id=vault_id, folder="Root", entry_title="At review")
        reopened.finish(event, "Succeeded", entry=entry)
        current, _ = ActivityStore(store.path).rows(limit=None)
        self.assertEqual([current], reopened.rows(limit=1))
        self.assertEqual((current["vault"], current["folder"], current["entry_title"], current["entry"]),
                         ("Example vault", "Root", "At review", entry))

    def test_activity_detail_column_migrates_sanitizes_and_counts_rows(self):
        store = ActivityStore(self.root / "activity.sqlite")
        store.recover(30)
        self.assertEqual(store.count(), 0)
        first = store.begin(123, Attribution(), "Use password", "https://example.invalid/")
        store.finish(first, "Failed", detail="  Line one\nline\t two\x07  ")
        self.assertEqual(store.count(), 1)
        row, = store.rows()
        self.assertEqual(row["detail"], "Line one line two")

        with store.connection() as db:
            db.execute("ALTER TABLE activity DROP COLUMN detail")
        reopened = ActivityStore(store.path)
        reopened.recover(30)
        migrated, = reopened.rows()
        self.assertIsNone(migrated["detail"])
        second = reopened.begin(123, Attribution(), "List vaults", None)
        reopened.finish(second, "Revoked", detail="x" * 300)
        self.assertEqual(reopened.count(), 2)
        newest = reopened.rows(limit=1)[0]
        self.assertEqual(newest["detail"], "x" * 240)

    def test_activity_rejects_claimed_provenance_and_unprotected_database(self):
        with self.assertRaises(ValueError):
            Attribution.parse({"model": "Fixture model", "verified": True})
        path = self.root / "activity.sqlite"
        path.touch(mode=0o644)
        with self.assertRaises(ActivityError):
            ActivityStore(path).recover(30)
