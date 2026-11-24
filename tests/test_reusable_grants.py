"""Owner-reviewed reusable credential permissions preserve exact recipient scope."""

from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

import gi

gi.require_version("Gtk", "3.0")
from keepassxc_agent_access.activity import ActivityStore, Attribution
from keepassxc_agent_access.grants import CREDENTIAL_USES, Grants, Item, Scope
from keepassxc_agent_access.vault import VaultTarget
from keepassxc_agent_access.workspace import Registration, Unlocked, Workspace
from keepassxc_agent_access.workspace_views import credential_use_labels, token_permissions


class ReusableGrantTests(TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.workspace = Workspace(temporary.name, None)
        self.activity = ActivityStore(self.workspace.directory / "activity.sqlite")
        self.activity.recover(30)
        self.grants = Grants(self.workspace, self.activity)
        self.vault = str(uuid4())
        self.entry = str(uuid4())
        self.group = str(uuid4())
        self.credential = "a1" * 32
        self.workspace.registrations[self.vault] = Registration(
            self.vault, "Synthetic", VaultTarget(Path("synthetic.kdbx")), None, None)
        self.row = {"id": self.entry, "title": "Synthetic Account", "group_path": ["Services"],
                    "group": self.group, "url": "https://unrelated.example.test/"}
        self.workspace.sessions[self.vault] = Unlocked(SimpleNamespace(available=True), (), (self.row,))

    def request(self, uses=("https",), origins=("https://service.example.test",), **extra):
        return {"vault": self.vault, "entry": self.entry, "uses": list(uses), "origins": list(origins), **extra}

    def enroll(self, request, *, change_id=None, credential=None, identity="Deployment Assistant"):
        payload = {"identity": identity, "project": "Synthetic Trial", "items": [request]}
        if change_id is not None:
            payload["change_id"] = change_id
        return self.grants.enroll(credential or self.credential, 1500, payload, Attribution())

    def approve(self):
        record = self.grants.authenticate(self.credential, 1500)
        self.grants.decide(record.id, [self.grants.choices(item)[0] for item in record.items])
        return self.grants.authenticate(self.credential, 1500)

    def test_use_only_permission_needs_no_configured_action_or_metadata(self):
        self.assertEqual(self.enroll(self.request()), "pending")
        grant = self.approve()
        scope, = grant.scope
        self.assertEqual(scope.uses, ("https",))
        self.assertEqual(scope.origins, ("https://service.example.test:443/",))
        self.assertFalse(scope.metadata or scope.username or scope.url)
        self.assertIsNone(scope.action)
        self.assertIsNone(scope.revision)
        self.assertEqual(self.workspace.registrations[self.vault].bindings, ())
        self.row["url"] = "https://attacker.example.test/"
        self.assertEqual(scope.origins, ("https://service.example.test:443/",))
        reloaded = Grants(self.workspace, self.activity).authenticate(self.credential, 1500)
        self.assertEqual(reloaded.scope, grant.scope)
        self.assertEqual(reloaded.items, grant.items)

    def test_types_destinations_and_group_permissions_fail_closed(self):
        invalid = [
            self.request(uses=("unknown",)), self.request(uses=("https", "https")),
            self.request(uses="https"), self.request(uses=([],)),
            self.request(origins=()), self.request(origins="https://service.example.test/"),
            self.request(origins=("http://service.example.test/",)),
            self.request(origins=("https://service.example.test/path",)),
            self.request(origins=("https://service.example.test/?query=yes",)),
            self.request(origins=("https://user@service.example.test/",)),
            self.request(origins=("https://service.example.test/", "https://service.example.test:443/")),
            self.request(origins=tuple(f"https://host-{index}.example.test/" for index in range(9))),
            self.request(uses=(), origins=("https://service.example.test/",)),
            self.request(uses=("https_body",)),
            self.request(uses=("local_command",)),
            {"vault": self.vault, "group": self.group, "uses": ["local_command"]},
            {"vault": self.vault, "group": self.group, "uses": ["https"],
             "origins": ["https://service.example.test/"]},
        ]
        for request in invalid:
            with self.subTest(request=request), self.assertRaises((TypeError, ValueError)):
                Item.parse(request)
        self.assertEqual(self.grants.records, {})

    def test_local_commands_have_no_network_destinations_and_freeze_inputs(self):
        uses = ["local_command"]
        item = Item.parse({"vault": self.vault, "entry": self.entry, "uses": uses})
        uses.append("https")
        self.assertEqual(item.uses, ("local_command",))
        self.assertEqual(item.origins, ())
        self.assertIsInstance(hash(item), int)
        scope = Scope(self.vault, self.entry, False, None, None, uses=["https", "browser"],
                      origins=["https://service.example.test/"])
        self.assertEqual(scope.uses, ("browser", "https"))
        self.assertEqual(scope.origins, ("https://service.example.test:443/",))
        self.assertIn("Use Password in HTTPS Requests", scope.audit_summary())
        self.assertIn("https://service.example.test:443/", scope.audit_summary())
        with self.assertRaises(ValueError):
            replace(scope, group=self.group)

    def test_old_saved_grants_do_not_gain_reusable_permissions(self):
        self.assertEqual(self.enroll({"vault": self.vault, "entry": self.entry, "metadata": True}), "pending")
        self.approve()
        saved = json.loads(self.grants.path.read_text())
        for record in saved["grants"]:
            for item in (*record["items"], *record["scope"]):
                item.pop("uses")
                item.pop("origins")
        self.grants.path.write_text(json.dumps(saved))
        grant = Grants(self.workspace, self.activity).authenticate(self.credential, 1500)
        self.assertTrue(grant.scope[0].metadata)
        self.assertEqual(grant.scope[0].uses, ())
        self.assertEqual(grant.scope[0].origins, ())
        self.assertEqual(grant.items[0].uses, ())

    def test_legacy_token_auto_approval_cannot_approve_new_uses_or_destinations(self):
        def legacy_only(setting):
            return setting in ("auto_approve_tokens", "auto_approve_token_changes")

        with patch.object(self.workspace, "token_auto_approval_enabled", side_effect=legacy_only):
            self.assertEqual(self.enroll(self.request()), "pending")
            reusable = self.grants.authenticate(self.credential, 1500)
            self.assertEqual(reusable.scope, ())
            self.assertEqual(self.enroll({"vault": self.vault, "entry": self.entry, "metadata": True},
                                         credential="a2" * 32, identity="Metadata Assistant"), "active")

    def test_permission_change_keeps_old_scope_until_new_origin_is_reviewed(self):
        self.enroll(self.request())
        original = self.approve()
        change = str(uuid4())

        def legacy_only(setting):
            return setting in ("auto_approve_tokens", "auto_approve_token_changes")

        with patch.object(self.workspace, "token_auto_approval_enabled", side_effect=legacy_only):
            self.assertEqual(self.enroll(self.request(uses=("https", "browser"),
                                                     origins=("https://second.example.test/",)), change_id=change), "pending")
        grant = self.grants.authenticate(self.credential, 1500)
        self.assertEqual(grant.scope, original.scope)
        self.assertEqual(grant.pending_change.items[0].origins, ("https://second.example.test:443/",))
        pending = grant.pending_change
        self.grants.decide(grant.id, [self.grants.choices(item)[0] for item in pending.items], change_id=change)
        approved = self.grants.authenticate(self.credential, 1500)
        self.assertEqual(approved.scope[0].uses, ("browser", "https"))
        self.assertEqual(approved.scope[0].origins, ("https://second.example.test:443/",))
        self.assertEqual(approved.generation, original.generation + 1)
        self.assertIsNone(approved.pending_change)

    def test_permission_change_allows_omitting_identity_and_project_and_rejects_mismatch(self):
        from keepassxc_agent_access.protocol import ListingError

        self.enroll(self.request())
        self.approve()
        change = str(uuid4())
        self.assertEqual(self.grants.enroll(
            self.credential, 1500,
            {"change_id": change, "items": [self.request(uses=("https", "browser"))]},
            Attribution(),
        ), "pending")
        with self.assertRaises(ListingError):
            self.grants.enroll(
                self.credential, 1500,
                {"identity": "Different Identity", "change_id": str(uuid4()),
                 "items": [self.request(uses=("https",))]},
                Attribution(),
            )

    def test_permission_text_exposes_transports_and_pinned_recipients(self):
        item = Item.parse(self.request(uses=tuple(CREDENTIAL_USES)))
        labels = dict(credential_use_labels(item))
        self.assertEqual(set(labels), set(CREDENTIAL_USES.values()))
        self.assertIn("Command output and exit status stay private", labels[CREDENTIAL_USES["local_command"]])
        self.assertIn("https://service.example.test:443/", labels[CREDENTIAL_USES["https"]])
        self.assertIn("Can send the credential", labels[CREDENTIAL_USES["networked_command"]])
        self.assertIn("may be stored or published", labels[CREDENTIAL_USES["https_body"]])
        scope = Scope(self.vault, self.entry, False, None, None, uses=item.uses, origins=item.origins)
        text = token_permissions(self.workspace.registrations[self.vault], [scope])
        for caption in CREDENTIAL_USES.values():
            self.assertIn(caption, text)
        self.assertIn("Approved Destinations: https://service.example.test:443/", text)
        self.assertNotIn("Entry Metadata", text)

    def test_denied_and_removed_profiles_can_re_enroll_and_preserve_unrelated_pins(self):
        from keepassxc_agent_access.protocol import ListingError

        self.assertEqual(self.enroll(self.request()), "pending")
        denied_record = self.grants.authenticate(self.credential, 1500)
        self.grants.decide(denied_record.id, None)
        self.assertEqual(self.grants.authenticate(self.credential, 1500).status, "denied")
        with self.assertRaises(ListingError):
            self.enroll(self.request(), change_id=str(uuid4()))
        self.assertEqual(self.enroll({"vault": self.vault, "entry": self.entry, "metadata": True},
                                     identity="New Assistant"), "pending")
        active = self.approve()
        self.assertNotEqual(active.id, denied_record.id)
        self.assertNotIn(denied_record.id, self.grants.records)

        self.grants.transition(active.id, "removed")
        self.assertEqual(self.enroll(self.request(uses=("https_results",)), identity="Re-enrolled Assistant"), "pending")
        fresh = self.approve()
        rev = self.workspace.registrations[self.vault].credential_revision(self.entry)
        pin = "c" * 64
        self.grants.trust_result_certificate(
            fresh.id, fresh.generation, self.vault, self.entry, rev, "https://service.example.test:443/", pin, (None,))
        second_entry = str(uuid4())
        self.workspace.sessions[self.vault] = Unlocked(
            SimpleNamespace(available=True), (), (self.row, {**self.row, "id": second_entry, "title": "Second"}),
        )
        change = str(uuid4())
        self.grants.enroll(self.credential, 1500, {
            "change_id": change,
            "items": [self.request(uses=("https_results",)),
                      {"vault": self.vault, "entry": second_entry, "metadata": True}],
        }, Attribution())
        pending = self.grants.authenticate(self.credential, 1500).pending_change
        self.grants.decide(fresh.id, [self.grants.choices(item)[0] for item in pending.items], change_id=change)
        updated = self.grants.authenticate(self.credential, 1500)
        self.assertEqual(updated.scope[0].result_certificates, (("https://service.example.test:443/", pin),))
