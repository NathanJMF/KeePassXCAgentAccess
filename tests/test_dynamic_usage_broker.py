"""Dynamic operations require reusable scope and the same guarded review path."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from time import monotonic, sleep
import unittest
from unittest.mock import patch

import test_scoped_broker as scoped


class DynamicUsageBrokerTests(unittest.TestCase):
    setUp = scoped.ScopedBrokerTests.setUp
    invoke = scoped.ScopedBrokerTests.invoke
    enroll = scoped.ScopedBrokerTests.enroll
    approve = scoped.ScopedBrokerTests.approve
    assert_code = scoped.ScopedBrokerTests.assert_code

    def reusable(self, uses=("https",), origins=("https://api.example.test/",), **extra):
        return {"vault": self.vaults[0], "entry": self.entry, "uses": list(uses), "origins": list(origins), **extra}

    def api(self, **extra):
        return {"type": "https", "url": "https://api.example.test/resource", "auth": "bearer", **extra}

    def use(self, usage, **extra):
        return self.invoke("use_password", entry=self.entry, vault=self.vaults[0], usage=usage, **extra)

    def test_reusable_https_has_no_binding_and_audits_only_fingerprint_and_origin(self):
        record = self.workspace.registrations[self.vaults[0]]
        self.workspace.registrations[self.vaults[0]] = replace(record, bindings=())
        self.approve([self.reusable()])
        result = self.use(self.api(method="POST", json={"operation": "private-request-body"}),
                          context={"note": "Create the requested synthetic resource"})
        self.assertEqual(result, {"outcome": "succeeded", "http_status": 200})
        event, = self.activity.rows(action="HTTPS Request")
        self.assertEqual(event["outcome"], "Succeeded")
        self.assertEqual(event["destination"], "POST https://api.example.test:443/")
        self.assertEqual(event["entry"], self.entry)
        self.assertEqual(event["note"], "Create the requested synthetic resource")
        self.assertIn("SHA-256", event["scope"])
        self.assertNotIn("private-request-body", repr(event))
        self.assertEqual(self.workspace.registrations[self.vaults[0]].bindings, ())

    def test_metadata_and_legacy_actions_do_not_grant_reusable_use(self):
        self.approve([{"vault": self.vaults[0], "entry": self.entry, "metadata": True, "action": "check"}])
        self.assert_code("ineligible", "use_password", entry=self.entry, vault=self.vaults[0], usage=self.api())
        self.assertEqual(self.invoke("use_password", entry=self.entry, action="check", vault=self.vaults[0]),
                         {"outcome": "succeeded", "http_status": 200})

    def test_scope_cannot_cross_entry_vault_transport_or_destination(self):
        self.approve([self.reusable()])
        for changes in ({"vault": self.vaults[1]}, {"entry": self.vaults[1]},
                        {"usage": self.api(url="https://other.example.test/resource")},
                        {"usage": {"type": "local_command", "command": ["/usr/bin/true"]}}):
            with self.subTest(changes=changes):
                self.assert_code("ineligible", "use_password", **{
                    "entry": self.entry, "vault": self.vaults[0], "usage": self.api(), **changes})
        self.assertEqual(len(self.activity.rows(action="Use password", outcome="Denied")), 4)

    def test_secret_body_placement_needs_separate_reviewed_permission(self):
        self.approve([self.reusable()])
        request = self.api(auth="template", method="POST", json={"credential": "{{password}}"})
        self.assert_code("ineligible", "use_password", entry=self.entry, vault=self.vaults[0], usage=request)
        self.approve([self.reusable(uses=("https", "https_body"))], index=1)
        self.assertEqual(self.invoke("use_password", index=1, entry=self.entry, vault=self.vaults[0], usage=request),
                         {"outcome": "succeeded", "http_status": 200})

    def test_reusable_cli_does_not_expose_child_outcome_or_private_audit_field(self):
        identifier = self.approve([self.reusable(uses=("local_command",), origins=())])
        worker = self.workspace.session(self.vaults[0]).worker
        for outcome in ("succeeded", "failed", "uncertain"):
            def use(action, gate, outcome=outcome):
                self.assertTrue(action.opaque)
                self.assertTrue(gate(lambda: None))
                return {"outcome": "dispatched", "_execution_outcome": outcome}
            with patch.object(worker, "use", side_effect=use):
                result = self.use({"type": "local_command", "command": ["/usr/bin/true"]})
            self.assertEqual(result, {"outcome": "dispatched"})
            self.assertIsNotNone(self.grants.records[identifier].last_used)
        self.assertEqual({e["outcome"] for e in self.activity.rows(action="Local Command")},
                         {"Succeeded", "Failed", "Interrupted · outcome unknown"})

    def test_unapproved_command_does_not_hash_a_system_binary(self):
        self.approve([self.reusable()])
        with patch("keepassxc_agent_access.usage.executable_digest", side_effect=AssertionError("unauthorized hashing")):
            self.assert_code("ineligible", "use_password", entry=self.entry, vault=self.vaults[0],
                             usage={"type": "local_command", "command": ["/usr/bin/true"]})

    def test_mixed_selectors_and_changed_authority_are_rejected(self):
        self.approve([self.reusable()])
        self.assert_code("invalid_request", "use_password", entry=self.entry, usage=self.api(), action="check")
        self.assert_code("invalid_request", "use_password", entry=self.entry, usage=self.api(), command=["/usr/bin/true"])
        self.assert_code("invalid_request", "use_password", entry=self.entry, vault=self.vaults[0],
                         usage=self.api(headers={"Host": "other.example.test"}))
        self.workspace.pause()
        self.assert_code("paused", "use_password", entry=self.entry, vault=self.vaults[0], usage=self.api())

    def test_concrete_usage_is_reviewed_and_revocation_prevents_dispatch(self):
        identifier = self.approve([self.reusable()])
        self.workspace.set_review_usage(True)
        worker = self.workspace.session(self.vaults[0]).worker
        with ThreadPoolExecutor(max_workers=1) as pool, patch.object(worker, "use", wraps=worker.use) as use:
            pending = pool.submit(self.use, self.api(method="POST", json={"operation": "review-this-request"}))
            deadline = monotonic() + 3
            while monotonic() < deadline and not self.engine.approvals.pending():
                sleep(.01)
            ticket, = self.engine.approvals.pending()
            self.assertIn("review-this-request", " ".join(ticket.scope))
            self.assertEqual(ticket.identity, "Fixture agent 0")
            self.grants.transition(identifier, "disabled")
            self.engine.approvals.resolve(ticket.id, True)
            from keepassxc_agent_access.protocol import ListingError
            with self.assertRaises(ListingError) as error:
                pending.result(3)
            self.assertEqual(error.exception.code, "revoked")
            use.assert_not_called()

    def test_replaced_credentials_require_fresh_review_but_metadata_remains_available(self):
        item = self.reusable(metadata=True)
        identifier = self.approve([item])
        session = self.workspace.session(self.vaults[0])
        self.workspace._invalidate_changed_credentials(self.vaults[0], session,
            {"entry": self.entry, "username": "replacement-account", "password": None})
        self.assert_code("credential_changed", "use_password", entry=self.entry, vault=self.vaults[0], usage=self.api())
        self.assertEqual(len(self.invoke("list_entries", vault=self.vaults[0])["entries"]), 1)
        event, = self.activity.rows(action="HTTPS Request", outcome="Stale")
        self.assertEqual(event["entry"], self.entry)
        from uuid import uuid4
        self.invoke("request_access", request={"identity": "Fixture agent 0", "project": "Fixture",
                                              "change_id": str(uuid4()), "items": [item]})
        pending = self.grants.records[identifier].pending_change
        self.grants.decide(identifier, [self.grants.choices(pending.items[0])[0]], change_id=pending.id)
        self.assertEqual(self.use(self.api()), {"outcome": "succeeded", "http_status": 200})
        status = self.invoke("access_status", details=True)
        self.assertNotIn("use_revision", status["scope"][0])

    def test_credential_rotation_cancels_a_waiting_usage_approval(self):
        self.approve([self.reusable()])
        self.workspace.set_review_usage(True)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.use, self.api())
            deadline = monotonic() + 3
            while monotonic() < deadline and not self.engine.approvals.pending():
                sleep(.01)
            ticket, = self.engine.approvals.pending()
            self.workspace._invalidate_changed_credentials(self.vaults[0], self.workspace.session(self.vaults[0]),
                {"entry": self.entry, "username": "fixture-user-0", "password": "synthetic replacement"})
            self.engine.approvals.resolve(ticket.id, True)
            from keepassxc_agent_access.protocol import ListingError
            with self.assertRaises(ListingError) as error:
                pending.result(3)
            self.assertEqual(error.exception.code, "revoked")

    def test_legacy_status_shape_stays_compatible_and_missing_use_revision_fails_closed(self):
        self.approve([{"vault": self.vaults[0], "entry": self.entry, "metadata": True}])
        status = self.invoke("access_status", details=True)
        self.assertEqual(set(status["scope"][0]),
                         {"vault", "entry", "group", "metadata", "username", "url", "action", "edits",
                          "vault_locked", "stale"})
        self.assertFalse(status["scope"][0]["vault_locked"])
        self.assertFalse(status["scope"][0]["stale"])
        identifier = self.approve([self.reusable()], index=1)
        grant = self.grants.records[identifier]
        self.grants.records[identifier] = replace(grant, scope=tuple(replace(s, use_revision=None) for s in grant.scope))
        self.assert_code("credential_changed", "use_password", index=1, entry=self.entry, vault=self.vaults[0], usage=self.api())
