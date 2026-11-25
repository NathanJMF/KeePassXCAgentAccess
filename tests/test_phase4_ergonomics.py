"""Tests for Phase 4 Workstream 4A ergonomics, additive grants, discovery query, notes & capability metadata."""

from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from time import monotonic
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

import gi

gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
from pykeepass import PyKeePass, create_database

from keepassxc_agent_access.access_settings import Action, ActionType
from keepassxc_agent_access.activity import ActivityStore, Attribution
from keepassxc_agent_access.agent_cli import _validate, edit_request
from keepassxc_agent_access.agent_runner import ENROLLMENT, EDIT_REQUEST, OPERATIONS, invocation
from keepassxc_agent_access.console_access import ConsoleGrant
from keepassxc_agent_access.edit_requests import EditRequests
from keepassxc_agent_access.grants import CREDENTIAL_USES, Grants, Item, MAX_ITEMS, MAX_ORIGINS, Scope
from keepassxc_agent_access.guest_access import GuestGrant
from keepassxc_agent_access.protocol import ENTRY_FIELDS, ListingError, decode, encode
from keepassxc_agent_access.scoped_broker import ScopedBroker, access_details
from keepassxc_agent_access.ssh_access import SshPermit
from keepassxc_agent_access.vault import VaultTarget, open_vault
from keepassxc_agent_access.workspace import Registration, Unlocked, Workspace
from keepassxc_agent_access.workspace_views import metadata_labels


class Phase4ErgonomicsTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.workspace = Workspace(self.root, None)
        self.addCleanup(self.workspace.lock_all)
        self.activity = ActivityStore(self.root / "activity.sqlite")
        self.activity.recover(30)
        self.grants = Grants(self.workspace, self.activity)
        self.edits = EditRequests(self.workspace, self.grants, self.activity)
        self.broker = ScopedBroker(self.workspace, self.grants, self.activity, edits=self.edits)
        self.workspace.pause(False)

        self.cred = "11" * 32
        self.cred2 = "22" * 32
        self.vault_id = str(uuid4())
        self.vault2_id = str(uuid4())
        self.entry_id = str(uuid4())
        self.entry2_id = str(uuid4())
        self.group_root = str(uuid4())
        self.group_infra = str(uuid4())
        self.group_prod = str(uuid4())

        self.groups = (
            {"id": self.group_root, "name": "Root", "parent": None},
            {"id": self.group_infra, "name": "Infra", "parent": self.group_root},
            {"id": self.group_prod, "name": "Production", "parent": self.group_infra},
        )
        self.entry1_row = {
            "id": self.entry_id, "title": "Proxmox Primary", "group_path": ["Infra", "Production"],
            "group": self.group_prod, "username": "root@pam", "url": "https://pve.internal:8006/",
            "notes": "Cluster management notes", "has_totp": True,
            "custom_attribute_keys": ["region", "tier"], "attachments": ["id_ed25519", "ca.crt"],
        }
        self.entry2_row = {
            "id": self.entry2_id, "title": "Git Forge", "group_path": ["Infra"],
            "group": self.group_infra, "username": "git-bot", "url": "https://git.internal/",
            "notes": "Deploy key notes", "has_totp": False,
            "custom_attribute_keys": [], "attachments": [],
        }

        class FakeWorker:
            available = True

            def __init__(self, rows):
                self.rows = rows

            def scoped_entries(self, identifiers):
                return {"entries": [
                    {"id": r["id"], "title": r["title"], "group_path": r["group_path"]}
                    for r in self.rows if r["id"] in identifiers
                ]}

            def entry(self, identifier):
                return next((r for r in self.rows if r["id"] == identifier), None)

            def close(self):
                pass

        self.workspace.registrations[self.vault_id] = Registration(
            self.vault_id, "Operations Vault", VaultTarget(Path("ops.kdbx")), None, None,
        )
        self.workspace.sessions[self.vault_id] = Unlocked(
            FakeWorker([self.entry1_row, self.entry2_row]), self.groups, (self.entry1_row, self.entry2_row),
        )
        self.workspace.discovery.remember(self.vault_id, self.groups, (self.entry1_row, self.entry2_row))

        self.vault2_group = str(uuid4())
        self.vault2_entry = str(uuid4())
        v2_groups = ({"id": self.vault2_group, "name": "Personal", "parent": None},)
        v2_entries = ({
            "id": self.vault2_entry, "title": "Home Router", "group_path": [],
            "group": self.vault2_group, "username": "admin-secret", "url": "https://router.home/",
            "notes": "Router PIN 9999", "has_totp": False,
            "custom_attribute_keys": ["model"], "attachments": [],
        },)
        self.workspace.registrations[self.vault2_id] = Registration(
            self.vault2_id, "Personal Vault", VaultTarget(Path("personal.kdbx")), None, None,
        )
        self.workspace.sessions[self.vault2_id] = Unlocked(
            FakeWorker(list(v2_entries)), v2_groups, v2_entries,
        )
        self.workspace.discovery.remember(self.vault2_id, v2_groups, v2_entries)

    def _wire(self, operation, credential=None, uid=1500, **fields):
        payload = {"version": 1, "operation": operation, **fields}
        if operation != "discover":
            payload["credential"] = credential or self.cred
        out = []

        def live(effect=lambda: None):
            effect()
            return True

        def deliver(frame, guard):
            return guard(lambda: out.append(decode(frame)) or True)

        direct = self.broker(payload, uid, None, live, live, deliver)
        return decode(direct) if direct else out[0]

    def _enroll_and_approve(self, items, *, credential=None, identity="Phase4 Agent"):
        cred = credential or self.cred
        res = self._wire("request_access", credential=cred, request={
            "identity": identity, "project": "Phase4", "items": items,
        })
        self.assertEqual(res, {"status": "pending"})
        rec = self.grants.authenticate(cred, 1500)
        self.grants.decide(rec.id, [self.grants.choices(item)[0] for item in rec.items])
        return self.grants.authenticate(cred, 1500)

    def test_additive_mode_validation_and_merging(self):
        # Reject mode="add" without change_id and unknown modes
        for bad_req in (
            {"identity": "A", "project": "P", "mode": "add",
             "items": [{"vault": self.vault_id, "entry": self.entry_id, "metadata": True}]},
            {"identity": "A", "project": "P", "mode": "merge",
             "items": [{"vault": self.vault_id, "entry": self.entry_id, "metadata": True}]},
        ):
            with self.assertRaises(ListingError) as err:
                self._wire("request_access", request=bad_req)
            self.assertEqual(err.exception.code, "invalid_request")
            with self.assertRaises(ValueError):
                invocation("request_access", {"request": bad_req})

        # Initial grant with metadata + https on entry1
        self._enroll_and_approve([{
            "vault": self.vault_id, "entry": self.entry_id, "metadata": True,
            "uses": ["https"], "origins": ["https://pve.internal:8006/"],
        }])
        cid = str(uuid4())
        add_items = [
            {
                "vault": self.vault_id, "entry": self.entry_id, "metadata": True, "username": True, "notes": True,
                "uses": ["ssh_exec", "ssh_sftp"], "origins": ["ssh://pve.internal:22"],
            },
            {
                "vault": self.vault_id, "entry": self.entry2_id, "metadata": True, "url": True,
            },
        ]
        self.assertEqual(
            self._wire("request_access", request={"change_id": cid, "mode": "add", "items": add_items}),
            {"status": "pending"},
        )
        # Idempotent retry before approval returns pending
        self.assertEqual(
            self._wire("request_access", request={"change_id": cid, "mode": "add", "items": add_items}),
            {"status": "pending"},
        )
        # Changing mode on same change_id is rejected
        with self.assertRaises(ListingError) as conflict:
            self._wire("request_access", request={"change_id": cid, "mode": "replace", "items": add_items})
        self.assertEqual(conflict.exception.code, "invalid_request")

        details = self._wire("access_status", details=True)
        pending_items = details["pending_change"]["items"]
        self.assertEqual(len(pending_items), 2)
        first = pending_items[0]
        self.assertEqual(first["entry"], self.entry_id)
        self.assertTrue(first["metadata"] and first["username"] and first["notes"])
        self.assertFalse(first["url"])
        self.assertEqual(sorted(first["uses"]), ["https", "ssh_exec", "ssh_sftp"])
        self.assertEqual(sorted(first["origins"]), ["https://pve.internal:8006/", "ssh://pve.internal:22"])

        rec = self.grants.authenticate(self.cred, 1500)
        self.grants.decide(rec.id, [self.grants.choices(item)[0] for item in rec.pending_change.items], change_id=cid)
        # Idempotent retry after approval returns active
        self.assertEqual(
            self._wire("request_access", request={"change_id": cid, "mode": "add", "items": add_items}),
            {"status": "active"},
        )
        updated = self.grants.authenticate(self.cred, 1500)
        self.assertEqual(len(updated.scope), 2)
        self.assertEqual(updated.scope[0].uses, ("https", "ssh_exec", "ssh_sftp"))
        self.assertTrue(updated.scope[0].notes)
        self.assertEqual(updated.scope[1].entry, self.entry2_id)
        self.assertTrue(updated.scope[1].url)

        # Adding a distinct action on the same entry keeps both scopes distinct
        self.workspace.save_binding(self.vault_id, Action("check", "Check", self.entry_id, "https://pve.internal/"))
        cid_action = str(uuid4())
        self._wire("request_access", request={
            "change_id": cid_action, "mode": "add",
            "items": [{"vault": self.vault_id, "entry": self.entry_id, "action": "check"}],
        })
        rec = self.grants.authenticate(self.cred, 1500)
        self.grants.decide(rec.id, [self.grants.choices(item)[0] for item in rec.pending_change.items],
                           change_id=cid_action)
        self.assertEqual(len(self.grants.authenticate(self.cred, 1500).scope), 3)

        # Enforces MAX_ORIGINS on merged item
        cid_overflow = str(uuid4())
        too_many_origins = [f"https://host-{i}.example.test/" for i in range(MAX_ORIGINS)]
        with self.assertRaises(ListingError) as overflow:
            self._wire("request_access", request={
                "change_id": cid_overflow, "mode": "add",
                "items": [{"vault": self.vault_id, "entry": self.entry_id,
                           "uses": ["https"], "origins": too_many_origins}],
            })
        self.assertEqual(overflow.exception.code, "invalid_request")

        # Enforces MAX_ITEMS when combined items exceed limit
        too_many_items = [{"vault": self.vault_id, "label": f"Extra-{i}", "metadata": True}
                          for i in range(MAX_ITEMS)]
        with self.assertRaises(ListingError) as too_many:
            self._wire("request_access", request={
                "change_id": str(uuid4()), "mode": "add", "items": too_many_items,
            })
        self.assertEqual(too_many.exception.code, "invalid_request")

        # Schema exposes mode and notes
        self.assertEqual(ENROLLMENT["properties"]["mode"]["enum"], ["replace", "add"])
        self.assertEqual(ENROLLMENT["properties"]["items"]["items"]["properties"]["notes"], {"type": "boolean"})
        self.assertIn("notes", EDIT_REQUEST["properties"]["fields"]["properties"])
        self.assertIn("query", OPERATIONS["discover"]["inputSchema"]["properties"]
                      if isinstance(OPERATIONS["discover"], dict)
                      else OPERATIONS["discover"][1]["inputSchema"]["properties"])

    def test_revocation_generation_and_permit_continuity(self):
        grant = self._enroll_and_approve([{
            "vault": self.vault_id, "entry": self.entry_id,
            "uses": ["https", "https_results", "https_body", "ssh_exec"],
            "origins": ["https://pve.internal:8006/", "ssh://pve.internal:22"],
        }])
        self.assertEqual(grant.generation, 0)
        self.assertEqual(grant.revocation_generation, 0)

        # Legacy tokens.json migration defaults revocation_generation to generation
        saved = json.loads(self.grants.path.read_text())
        saved["grants"][0]["generation"] = 3
        saved["grants"][0].pop("revocation_generation", None)
        self.grants.path.write_text(json.dumps(saved))
        reloaded_grants = Grants(self.workspace, self.activity)
        self.grants = self.broker.grants = reloaded_grants
        grant = reloaded_grants.authenticate(self.cred, 1500)
        self.assertEqual((grant.generation, grant.revocation_generation), (3, 3))

        # Build active GuestGrant, ConsoleGrant, and SshPermit for this grant
        rev = self.workspace.registrations[self.vault_id].credential_revision(self.entry_id)
        session = self.workspace.session(self.vault_id)
        guest_permit = GuestGrant(grant.id, grant.revocation_generation, self.workspace.generation,
                                  self.vault_id, self.entry_id, rev, session, monotonic() + 600)
        console_permit = ConsoleGrant(grant.id, grant.revocation_generation, self.workspace.generation,
                                      self.vault_id, self.entry_id, rev, "https://pve.internal:8006/",
                                      "/ws", session, monotonic() + 600)
        ssh_permit = SshPermit(grant.id, grant.revocation_generation, self.workspace.generation,
                               self.vault_id, self.entry_id, rev, None, None, session,
                               "a" * 64, monotonic() + 600)
        self.assertTrue(self.broker.guest_access.current(guest_permit))
        self.assertTrue(self.broker.console_access.current(console_permit))
        self.assertTrue(self.broker.ssh_access._permit_current(ssh_permit))

        # Additive change_id increments generation but NOT revocation_generation
        cid_add = str(uuid4())
        self._wire("request_access", request={
            "change_id": cid_add, "mode": "add",
            "items": [{"vault": self.vault_id, "entry": self.entry2_id, "metadata": True}],
        })
        rec = reloaded_grants.authenticate(self.cred, 1500)
        reloaded_grants.decide(rec.id, [reloaded_grants.choices(item)[0] for item in rec.pending_change.items],
                               change_id=cid_add)
        after_add = reloaded_grants.authenticate(self.cred, 1500)
        self.assertEqual(after_add.generation, 4)
        self.assertEqual(after_add.revocation_generation, 3)
        self.assertTrue(self.broker.guest_access.current(guest_permit))
        self.assertTrue(self.broker.console_access.current(console_permit))
        self.assertTrue(self.broker.ssh_access._permit_current(ssh_permit))

        # Non-additive scope shrink increments revocation_generation and invalidates permits
        cid_shrink = str(uuid4())
        self._wire("request_access", request={
            "change_id": cid_shrink, "mode": "replace",
            "items": [{"vault": self.vault_id, "entry": self.entry2_id, "metadata": True}],
        })
        rec = reloaded_grants.authenticate(self.cred, 1500)
        reloaded_grants.decide(rec.id, [reloaded_grants.choices(item)[0] for item in rec.pending_change.items],
                               change_id=cid_shrink)
        after_shrink = reloaded_grants.authenticate(self.cred, 1500)
        self.assertEqual(after_shrink.generation, 5)
        self.assertEqual(after_shrink.revocation_generation, 4)
        self.assertFalse(self.broker.guest_access.current(guest_permit))
        self.assertFalse(self.broker.console_access.current(console_permit))
        self.assertFalse(self.broker.ssh_access._permit_current(ssh_permit))

        # release_entry also increments revocation_generation and invalidates permits
        grant2 = self._enroll_and_approve([
            {"vault": self.vault_id, "entry": self.entry_id, "metadata": True,
             "uses": ["ssh_exec"], "origins": ["ssh://pve.internal:22"]},
        ], credential=self.cred2, identity="Release Agent")
        ssh_permit2 = SshPermit(grant2.id, grant2.revocation_generation, self.workspace.generation,
                                self.vault_id, self.entry_id, rev, None, None, session,
                                "a" * 64, monotonic() + 600)
        self.assertTrue(self.broker.ssh_access._permit_current(ssh_permit2))
        reloaded_grants.release_entry(grant2, self.vault_id, self.entry_id, Attribution())
        after_release = reloaded_grants.authenticate(self.cred2, 1500)
        self.assertEqual(after_release.revocation_generation, grant2.revocation_generation + 1)
        self.assertFalse(self.broker.ssh_access._permit_current(ssh_permit2))

        # Credential rotation invalidates active permits via revision mismatch
        grant3 = self._enroll_and_approve([
            {"vault": self.vault_id, "entry": self.entry_id,
             "uses": ["https", "https_results"], "origins": ["https://pve.internal:8006/"]},
        ], credential="44" * 32, identity="Rotation Agent")
        guest_permit3 = GuestGrant(grant3.id, grant3.revocation_generation, self.workspace.generation,
                                   self.vault_id, self.entry_id, rev, session, monotonic() + 600)
        self.assertTrue(self.broker.guest_access.current(guest_permit3))
        self.workspace._invalidate_changed_credentials(self.vault_id, session, {
            "entry": self.entry_id, "username": "rotated-user",
        })
        self.assertFalse(self.broker.guest_access.current(guest_permit3))

    def test_discover_query_filtering_and_validation(self):
        # Match by entry title (case-insensitive) includes only matching entry & its ancestor groups
        res = self._wire("discover", query="proxmox")
        self.assertEqual(len(res["vaults"]), 1)
        v = res["vaults"][0]
        self.assertEqual(v["id"], self.vault_id)
        self.assertEqual([e["id"] for e in v["entries"]], [self.entry_id])
        self.assertEqual([g["id"] for g in v["groups"]], [self.group_root, self.group_infra, self.group_prod])
        self.assertEqual(_validate(res, {"operation": "discover", "query": "proxmox"}), res)

        # Match by group slash path includes matching group, ancestor chain, and entries in matching groups
        by_path = self._wire("discover", query="Infra/Production")
        self.assertEqual([v["id"] for v in by_path["vaults"]], [self.vault_id])
        self.assertEqual([e["id"] for e in by_path["vaults"][0]["entries"]], [self.entry_id])

        # Match by vault name returns whole vault
        by_vault = self._wire("discover", query="personal")
        self.assertEqual([v["id"] for v in by_vault["vaults"]], [self.vault2_id])
        self.assertEqual([e["id"] for e in by_vault["vaults"][0]["entries"]], [self.vault2_entry])

        # summary=True with query filters vaults without returning groups/entries
        summary = self._wire("discover", summary=True, query="proxmox")
        self.assertEqual(len(summary["vaults"]), 1)
        self.assertEqual(summary["vaults"][0]["id"], self.vault_id)
        self.assertEqual((summary["vaults"][0]["groups"], summary["vaults"][0]["entries"]), ([], []))

        # Never matches username, url, or notes
        for secret_text in ("admin-secret", "router.home", "9999", "root@pam"):
            self.assertEqual(self._wire("discover", query=secret_text), {"vaults": []})

        # Invalid queries are rejected with invalid_request
        for bad_query in ("", "   ", "a" * 129, "line\nbreak", 123):
            with self.assertRaises(ListingError) as err:
                self._wire("discover", query=bad_query)
            self.assertEqual(err.exception.code, "invalid_request")
            with self.assertRaises(ValueError):
                invocation("discover", {"query": bad_query})
        args, _ = invocation("discover", {"query": "Proxmox", "summary": True})
        self.assertIn("--query=Proxmox", args)

    def test_notes_and_capability_metadata_projection_and_scoping(self):
        # Verify real PyKeePass owner_snapshot vs entry_listing isolation
        db_path = self.root / "real.kdbx"
        kp = create_database(db_path, "master-pw")
        grp = kp.add_group(kp.root_group, "Infra")
        long_notes = "A" * 5000
        e = kp.add_entry(grp, "Real Entry", "real-user", "real-pw", url="https://real.example/", notes=long_notes)
        e.otp = "otpauth://totp/real?secret=JBSWY3DPEHPK3PXP"
        e.set_custom_property("TOTP Seed", "JBSWY3DPEHPK3PXP")
        e.set_custom_property("TOTP Settings", "30;6")
        e.set_custom_property("z_key", "secret_val_z")
        e.set_custom_property("a_key", "secret_val_a")
        att_bin = kp.add_binary(b"PRIVATE KEY BYTES")
        e.add_attachment(att_bin, "ssh_key.pem")
        kp.save()

        with open_vault(VaultTarget(db_path), "master-pw", Event()) as session:
            snap = session.owner_snapshot()
            row = snap["entries"][0]
            self.assertNotIn("notes", row)
            self.assertEqual(len(session.owner_entry_notes(str(e.uuid))), 5000)
            self.assertTrue(row["has_totp"])
            self.assertEqual(row["custom_attribute_keys"], ["a_key", "z_key"])
            self.assertEqual(row["attachments"], ["ssh_key.pem"])
            self.assertNotIn("secret_val", json.dumps(snap))
            self.assertNotIn("PRIVATE KEY BYTES", json.dumps(snap))
            worker_listing = json.loads(session.list_entries())["entries"][0]
            self.assertEqual(set(worker_listing), {"id", "title", "group_path"})

        # Grant with metadata=True ONLY (notes=False)
        grant_meta = self._enroll_and_approve([{"vault": self.vault_id, "entry": self.entry_id, "metadata": True}])
        self.assertFalse(grant_meta.scope[0].notes)
        self.assertNotIn("Entry Notes", grant_meta.scope[0].audit_summary())

        # Default list_entries omits capability fields
        base = self._wire("list_entries", vault=self.vault_id)["entries"][0]
        self.assertEqual(set(base), {"id", "title", "group_path"})

        # Capability fields require explicit request and metadata=True
        caps = self._wire("list_entries", vault=self.vault_id,
                          fields=["has_totp", "custom_attribute_keys", "attachments"])
        self.assertEqual(caps["entries"][0]["has_totp"], True)
        self.assertEqual(caps["entries"][0]["custom_attribute_keys"], ["region", "tier"])
        self.assertEqual(caps["entries"][0]["attachments"], ["id_ed25519", "ca.crt"])
        self.assertEqual(_validate(caps, {"operation": "list_entries",
                                          "fields": ["has_totp", "custom_attribute_keys", "attachments"]}), caps)

        # Notes fails closed when scope.notes is False
        with self.assertRaises(ListingError) as no_notes:
            self._wire("list_entries", vault=self.vault_id, fields=["notes"])
        self.assertEqual(no_notes.exception.code, "ineligible")
        self.assertEqual(no_notes.exception.detail, "Grant does not permit reading entry notes.")

        # notes=True cannot be requested without metadata=True
        with self.assertRaises(ValueError):
            Item.parse({"vault": self.vault_id, "entry": self.entry_id, "metadata": False, "notes": True})

        # Grant with notes=True succeeds and displays Entry Notes in audit/labels
        grant_notes = self._enroll_and_approve(
            [{"vault": self.vault_id, "entry": self.entry_id, "metadata": True, "notes": True}],
            credential=self.cred2, identity="Notes Agent",
        )
        self.assertIn("Entry Notes", grant_notes.scope[0].audit_summary())
        self.assertIn("Entry Notes", metadata_labels(grant_notes.scope[0]))
        notes_res = self._wire("list_entries", credential=self.cred2, vault=self.vault_id, fields=["notes"])
        self.assertEqual(notes_res["entries"][0]["notes"], "Cluster management notes")
        self.assertEqual(_validate(notes_res, {"operation": "list_entries", "fields": ["notes"]}), notes_res)
        self.assertEqual(set(ENTRY_FIELDS), {"username", "url", "notes", "has_totp", "custom_attribute_keys", "attachments"})

        # CLI validation checks types for new ENTRY_FIELDS
        with self.assertRaises(ListingError):
            _validate({"entries": [{**base, "has_totp": "yes"}]},
                      {"operation": "list_entries", "fields": ["has_totp"]})
        with self.assertRaises(ListingError):
            _validate({"entries": [{**base, "attachments": [123]}]},
                      {"operation": "list_entries", "fields": ["attachments"]})

        # Edit requests support notes while preserving untouched >4096-char notes on other updates
        real_vid = self.workspace.add(VaultTarget(db_path), "master-pw", False)
        real_entry_id = str(e.uuid)
        real_group_id = str(grp.uuid)
        cred3 = "33" * 32
        self._enroll_and_approve([
            {"vault": real_vid, "entry": real_entry_id, "edits": ["update_entry"]},
            {"vault": real_vid, "group": real_group_id, "edits": ["create_entry"]},
        ], credential=cred3, identity="Notes Editor")
        edit1 = {"id": str(uuid4()), "operation": "update_entry", "vault": real_vid, "entry": real_entry_id,
                 "fields": {"title": "Updated Title"}}
        self.assertEqual(edit_request(edit1)["fields"], {"title": "Updated Title"})
        self.assertEqual(self._wire("request_edit", credential=cred3, request=edit1)["status"], "applied")
        self.assertEqual(len(PyKeePass(db_path, password="master-pw").find_entries(uuid=UUID(real_entry_id), first=True).notes), 5000)

        edit2 = {"id": str(uuid4()), "operation": "update_entry", "vault": real_vid, "entry": real_entry_id,
                 "fields": {"notes": "Replaced notes"}}
        self.assertEqual(self._wire("request_edit", credential=cred3, request=edit2)["status"], "applied")
        self.assertEqual(PyKeePass(db_path, password="master-pw").find_entries(uuid=UUID(real_entry_id), first=True).notes,
                         "Replaced notes")

        edit3 = {"id": str(uuid4()), "operation": "create_entry", "vault": real_vid, "parent": real_group_id,
                 "fields": {"title": "Created With Notes", "notes": "Initial notes"}}
        res3 = self._wire("request_edit", credential=cred3, request=edit3)
        self.assertEqual(res3["status"], "applied")
        self.assertEqual(PyKeePass(db_path, password="master-pw").find_entries(uuid=UUID(res3["result"]), first=True).notes,
                         "Initial notes")

    def test_descriptive_ineligible_details(self):
        self._enroll_and_approve([{
            "vault": self.vault_id, "entry": self.entry_id, "metadata": True,
            "uses": ["https"], "origins": ["https://pve.internal:8006/"],
        }])
        # Locked vault
        saved_session = self.workspace.sessions.pop(self.vault_id)
        with self.assertRaises(ListingError) as locked_err:
            self._wire("list_entries", vault=self.vault_id)
        self.assertEqual(locked_err.exception.code, "ineligible")
        self.assertIn("locked", locked_err.exception.detail.lower())
        self.workspace.sessions[self.vault_id] = saved_session

        # Vault not in scope
        with self.assertRaises(ListingError) as out_vault:
            self._wire("list_entries", vault=self.vault2_id)
        self.assertEqual(out_vault.exception.code, "ineligible")
        self.assertIn("scope", out_vault.exception.detail.lower())

        # Unapproved origin
        with self.assertRaises(ListingError) as bad_origin:
            self._wire("use_password", vault=self.vault_id, entry=self.entry_id, usage={
                "type": "https", "url": "https://other.example.test/", "auth": "bearer",
            })
        self.assertEqual(bad_origin.exception.code, "ineligible")
        self.assertIn("origin", bad_origin.exception.detail.lower())

        # Missing SSH permission
        with self.assertRaises(ListingError) as no_ssh:
            self._wire("ssh_exec", vault=self.vault_id, entry=self.entry_id,
                       origin="ssh://pve.internal:22", command="hostname")
        self.assertEqual(no_ssh.exception.code, "ineligible")
        self.assertIn("ssh_exec", no_ssh.exception.detail)

        # Missing entry in scope
        with self.assertRaises(ListingError) as no_entry:
            self._wire("use_password", vault=self.vault_id, entry=self.entry2_id, usage={
                "type": "https", "url": "https://pve.internal:8006/", "auth": "bearer",
            })
        self.assertEqual(no_entry.exception.code, "ineligible")
        self.assertIn("entry", no_entry.exception.detail.lower())


if __name__ == "__main__":
    unittest.main()
