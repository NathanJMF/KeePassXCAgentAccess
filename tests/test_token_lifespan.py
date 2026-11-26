"""Unit tests for token life spans, automatic expiry/pruning, and life span extensions."""

from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic, time
import unittest
from unittest.mock import patch
from uuid import uuid4

from keepassxc_agent_access.access_settings import DEFAULT_TOKEN_LIFESPAN_DAYS, MAX_TOKEN_LIFESPAN_DAYS
from keepassxc_agent_access.activity import ActivityStore, Attribution
from keepassxc_agent_access.console_access import ConsoleGrant
from keepassxc_agent_access.edit_requests import EditRequests
from keepassxc_agent_access.grants import ExtensionRequest, Grants, LIVE_GRANT_STATES, MAX_PENDING
from keepassxc_agent_access.guest_access import GuestGrant
from keepassxc_agent_access.protocol import ListingError, decode
from keepassxc_agent_access.scoped_broker import ScopedBroker, access_details
from keepassxc_agent_access.vault import VaultTarget
from keepassxc_agent_access.workflow import Workflow
from keepassxc_agent_access.workspace import Registration, Unlocked, Workspace


class FakeWorker:
    available = True

    def __init__(self, entry, group):
        self.row = {"id": entry, "title": "Service Account", "group_path": ["Services"], "group": group}
        self.rows = [self.row]

    def scoped_entries(self, identifiers):
        return {"entries": [row for row in self.rows if row["id"] in identifiers]}

    def entry(self, _):
        return self.row

    def use(self, _action, gate, **_options):
        if not gate(lambda: None):
            raise ListingError("revoked")
        return {"outcome": "succeeded", "http_status": 200}

    def console(self, _request, gate):
        if not gate(lambda: None):
            raise ListingError("revoked")
        return {"width": 100, "height": 100, "changed": False}


class TokenLifespanTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory(dir="/tmp")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.workspace = Workspace(self.root, None)
        self.activity = ActivityStore(self.root / "activity.sqlite")
        self.activity.recover(30)
        self.grants = Grants(self.workspace, self.activity)
        self.edits = EditRequests(self.workspace, self.grants, self.activity)
        self.broker = ScopedBroker(self.workspace, self.grants, self.activity, edits=self.edits)
        self.vault = str(uuid4())
        self.group = str(uuid4())
        self.entry = str(uuid4())
        self.secrets = [f"{i:02x}" * 32 for i in range(1, 70)]
        self.worker = FakeWorker(self.entry, self.group)
        self.workspace.registrations[self.vault] = Registration(
            self.vault, "Primary", VaultTarget(self.root / "primary.kdbx"), None, None,
        )
        owner_row = {
            **self.worker.row,
            "username": "fixture-user",
            "url": "https://service.example.test/",
            "password": "fixture-password",
            "notes": "",
        }
        self.workspace.sessions[self.vault] = Unlocked(
            self.worker, ({"id": self.group, "parent": None, "name": "Services"},), (owner_row,),
        )
        self.workspace.pause(False)

    def invoke(self, operation, index=0, uid=1500, **fields):
        data = {"version": 1, "operation": operation, "credential": self.secrets[index], **fields}
        output = []

        def deliver(frame, guard):
            return guard(lambda: output.append(decode(frame)) or True)

        def live(effect=lambda: None):
            effect()
            return True

        immediate = self.broker(data, uid, None, live, live, deliver)
        return decode(immediate) if immediate else (output[0] if output else None)

    def enroll_and_approve(self, index=0, identity="Lifespan Agent", items=None):
        items = items or [{"vault": self.vault, "entry": self.entry, "metadata": True}]
        status = self.invoke("request_access", index=index, request={
            "identity": identity, "project": "Lifespan Project", "items": items,
        })
        self.assertEqual(status, {"status": "pending"})
        record = self.grants.authenticate(self.secrets[index], 1500)
        choices = [self.grants.choices(item)[0] for item in record.items]
        self.grants.decide(record.id, choices)
        return self.grants.records[record.id]

    def test_workspace_lifespan_setting_persists_without_pausing_or_bumping_generation(self):
        self.assertEqual(self.workspace.token_lifespan_days, DEFAULT_TOKEN_LIFESPAN_DAYS)
        generation = self.workspace.generation
        paused = self.workspace.paused

        self.workspace.set_token_lifespan_days(10)
        self.assertEqual(self.workspace.token_lifespan_days, 10)
        self.assertEqual(self.workspace.generation, generation)
        self.assertEqual(self.workspace.paused, paused)
        self.assertEqual(Workspace(self.root, None).token_lifespan_days, 10)

        for bad in (0, -5, MAX_TOKEN_LIFESPAN_DAYS + 1, True, False, "10", 10.0):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.workspace.set_token_lifespan_days(bad)

    def test_extension_request_validation_and_legacy_migration(self):
        with self.assertRaises(ValueError):
            ExtensionRequest(str(uuid4()), time(), Attribution(), 3, status="unknown")
        for bad_days in (0, MAX_TOKEN_LIFESPAN_DAYS + 1, True, "3"):
            with self.subTest(bad_days=bad_days), self.assertRaises(ValueError):
                ExtensionRequest(str(uuid4()), time(), Attribution(), bad_days)

        # Enroll and approve, then strip expires_at and extension from tokens.json to simulate legacy storage.
        active = self.enroll_and_approve(index=0, identity="Legacy Active")
        self.invoke("request_access", index=1, request={
            "identity": "Legacy Pending", "project": "Lifespan Project",
            "items": [{"vault": self.vault, "entry": self.entry, "metadata": True}],
        })
        pending = self.grants.authenticate(self.secrets[1], 1500)
        self.grants.decide(pending.id, None)  # denied terminal record
        self.invoke("request_access", index=2, request={
            "identity": "Legacy Pending Live", "project": "Lifespan Project",
            "items": [{"vault": self.vault, "entry": self.entry, "metadata": True}],
        })
        pending_live = self.grants.authenticate(self.secrets[2], 1500)

        raw = json.loads(self.grants.path.read_text())
        for row in raw["grants"]:
            row.pop("expires_at", None)
            row.pop("extension", None)
        self.grants.path.write_text(json.dumps(raw))

        self.workspace.set_token_lifespan_days(7)
        now = 1_800_000_000.0
        with patch("keepassxc_agent_access.grants.time", return_value=now):
            reloaded = Grants(self.workspace, self.activity)

        self.assertAlmostEqual(reloaded.records[active.id].expires_at, now + 7 * 86400)
        self.assertAlmostEqual(reloaded.records[pending_live.id].expires_at, now + 7 * 86400)
        self.assertIsNone(reloaded.records[pending.id].expires_at)

        # Verify persisted backfilled expires_at survived to disk.
        persisted = json.loads(self.grants.path.read_text())
        by_id = {row["id"]: row for row in persisted["grants"]}
        self.assertAlmostEqual(by_id[active.id]["expires_at"], now + 7 * 86400)
        self.assertIsNone(by_id[pending.id]["expires_at"])

    def test_expiry_lifecycle_re_enrollment_identity_reuse_and_retention_pruning(self):
        t0 = 1_800_000_000.0
        with patch("keepassxc_agent_access.grants.time", return_value=t0):
            self.workspace.set_token_lifespan_days(2)
            active = self.enroll_and_approve(index=0, identity="Expiring Agent")
            self.invoke("request_access", index=1, request={
                "identity": "Pending Expiring", "project": "Lifespan Project",
                "items": [{"vault": self.vault, "entry": self.entry, "metadata": True}],
            })
            pending = self.grants.authenticate(self.secrets[1], 1500)

        self.assertAlmostEqual(active.expires_at, t0 + 2 * 86400)
        self.assertAlmostEqual(pending.expires_at, t0 + 2 * 86400)
        self.assertTrue(self.grants.is_active(active, now=t0 + 2 * 86400 - 1))
        self.assertTrue(self.grants.is_expired(active, now=t0 + 2 * 86400))
        self.assertFalse(self.grants.is_active(active, now=t0 + 2 * 86400))

        # Advance past expiry; rows() and authenticate() auto-prune and log Activity.
        t1 = t0 + 2 * 86400 + 5
        with patch("keepassxc_agent_access.grants.time", return_value=t1):
            self.assertEqual(self.grants.rows(), [])
            expired_active = self.grants.records[active.id]
            expired_pending = self.grants.records[pending.id]
            self.assertEqual(expired_active.status, "expired")
            self.assertEqual(expired_active.generation, active.generation + 1)
            self.assertEqual(expired_active.scope, ())
            self.assertEqual(expired_active.items, ())
            self.assertIsNone(expired_active.change)
            self.assertIsNone(expired_active.extension)
            self.assertEqual(expired_pending.status, "expired")

            # access_status returns {"status": "expired"} cleanly; details omit expires_at/expires_in.
            self.assertEqual(self.invoke("access_status", index=0), {"status": "expired"})
            details = self.invoke("access_status", index=0, details=True)
            self.assertEqual(details["status"], "expired")
            self.assertNotIn("expires_at", details)
            self.assertNotIn("expires_in", details)

            # Scoped operations reject expired tokens.
            for op, extra in (
                ("list_vaults", {}),
                ("list_entries", {"vault": self.vault}),
                ("extend_access", {}),
                ("release_entry", {"vault": self.vault, "entry": self.entry}),
            ):
                with self.subTest(op=op), self.assertRaises(ListingError) as err:
                    self.invoke(op, index=0, **extra)
                self.assertEqual(err.exception.code, "ineligible")

            # Identity is freed for another token, and same credential can re-enroll.
            self.assertEqual(self.invoke("request_access", index=2, request={
                "identity": "Expiring Agent", "project": "Other",
                "items": [{"vault": self.vault, "entry": self.entry, "metadata": True}],
            }), "pending" if False else {"status": "pending"})

            self.assertEqual(self.invoke("request_access", index=0, request={
                "identity": "Fresh Identity", "project": "Lifespan Project",
                "items": [{"vault": self.vault, "entry": self.entry, "metadata": True}],
            }), {"status": "pending"})
            re_enrolled = self.grants.authenticate(self.secrets[0], 1500)
            self.assertEqual(re_enrolled.status, "pending")
            self.assertNotEqual(re_enrolled.id, active.id)

        expire_events = self.activity.rows(action="Expire token")
        self.assertEqual(len(expire_events), 2)
        self.assertEqual({row["outcome"] for row in expire_events}, {"Expired"})

        # Test retention pruning respects expires_at/requested and last_used.
        with patch("keepassxc_agent_access.grants.time", return_value=t1 + 100):
            self.grants._put(replace(self.grants.records[pending.id], last_used=t1 + 50))
        # At t1 + 10 days with retention=15, the two re-enrolled tokens expire (count=2), while old pending is kept.
        self.assertEqual(self.grants.prune_expired(now=t1 + 10 * 86400, retention_days=15), 2)
        self.assertIn(pending.id, self.grants.records)
        # At t1 + 16 days with retention=15, pending (expired at t0+2d, last_used=t1+50) is pruned.
        self.assertEqual(self.grants.prune_expired(now=t1 + 16 * 86400, retention_days=15), 1)
        self.assertNotIn(pending.id, self.grants.records)
        self.assertNotIn(pending.verifier, self.grants.credentials)

    def test_owner_extend_preserves_generation_and_resets_lifespan(self):
        t0 = 1_800_000_000.0
        with patch("keepassxc_agent_access.grants.time", return_value=t0):
            grant = self.enroll_and_approve(index=0)
            # Pending agent extension is marked active when owner extends directly.
            status, grant = self.grants.request_extension(grant.id, 5, Attribution(note="Need more time"))
            self.assertEqual(status, "pending")
            gen_before = grant.generation
            extended = self.grants.extend(grant.id, 10, decision="Extended in Access")
            self.assertEqual(extended.generation, gen_before)
            self.assertAlmostEqual(extended.expires_at, t0 + 10 * 86400)
            self.assertEqual(extended.extension.status, "active")
            self.assertIsNone(extended.pending_extension)

            # Clicking Extend with days=None resets timer to token_lifespan_days (does not stack +3d).
            reset_once = self.grants.extend(grant.id)
            self.assertAlmostEqual(reset_once.expires_at, t0 + DEFAULT_TOKEN_LIFESPAN_DAYS * 86400)
            reset_twice = self.grants.extend(grant.id)
            self.assertAlmostEqual(reset_twice.expires_at, t0 + DEFAULT_TOKEN_LIFESPAN_DAYS * 86400)

            # Cap at now + MAX_TOKEN_LIFESPAN_DAYS * 86400.
            capped = self.grants.extend(grant.id, MAX_TOKEN_LIFESPAN_DAYS)
            self.assertAlmostEqual(capped.expires_at, t0 + MAX_TOKEN_LIFESPAN_DAYS * 86400)

            # Disabled non-expired tokens can also be extended directly.
            self.grants.transition(grant.id, "disabled")
            disabled_ext = self.grants.extend(grant.id, 2)
            self.assertEqual(disabled_ext.status, "disabled")
            self.assertAlmostEqual(disabled_ext.expires_at, t0 + 2 * 86400)

        # Expired tokens cannot be extended.
        with patch("keepassxc_agent_access.grants.time", return_value=t0 + 400 * 86400):
            with self.assertRaises(ListingError) as err:
                self.grants.extend(grant.id, 5)
            self.assertEqual(err.exception.code, "revoked")
            self.assertEqual(self.grants.records[grant.id].status, "expired")

    def test_extend_button_renderer_draws_visible_text(self):
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gdk, Gtk
        import cairo
        from keepassxc_agent_access.workspace_style import install_style
        from keepassxc_agent_access.workspace_views import ExtendButtonRenderer

        win = Gtk.Window()
        win.set_name("keeper-workspace")
        install_style(win)
        tv = Gtk.TreeView()
        tv.get_style_context().add_class("keeper-table")
        win.add(tv)
        win.realize()

        renderer = ExtendButtonRenderer()
        renderer.set_property("visible-button", True)
        renderer.set_property("sensitive-button", True)
        area = Gdk.Rectangle()
        area.x, area.y, area.width, area.height = 0, 0, 96, 36
        for flags in (0, Gtk.CellRendererState.PRELIT):
            surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, 96, 36)
            cr = cairo.Context(surface)
            cr.set_source_rgb(0.15, 0.15, 0.15)
            cr.paint()
            renderer.do_render(cr, tv, area, area, flags)
            data = bytes(surface.get_data())
            # Center horizontal strip should contain bright label text pixels.
            text_pixels = sum(
                1 for y in range(10, 26) for x in range(20, 76)
                for offset in ((y * 96 + x) * 4,)
                if max(data[offset], data[offset + 1], data[offset + 2]) > 180
            )
            self.assertGreater(text_pixels, 80)
        win.destroy()

    def test_agent_extension_manual_review_idempotency_denial_and_auto_approval(self):
        t0 = 1_800_000_000.0
        ext_id = str(uuid4())
        with patch("keepassxc_agent_access.grants.time", return_value=t0):
            grant = self.enroll_and_approve(index=0)
            reply = self.invoke("extend_access", index=0, days=5, extension_id=ext_id)
            self.assertEqual(reply["status"], "pending")
            self.assertEqual(reply["expires_at"], int(grant.expires_at))

            details = self.invoke("access_status", index=0, details=True)
            self.assertEqual(details["pending_extension"], {"id": ext_id, "days": 5})
            self.assertEqual(details["expires_at"], int(grant.expires_at))
            self.assertGreater(details["expires_in"], 0)

            # Idempotent retry with same extension_id and days returns pending without creating a second event.
            self.assertEqual(self.invoke("extend_access", index=0, days=5, extension_id=ext_id), reply)
            self.assertEqual(len(self.activity.rows(action="Request token extension")), 1)

            # Idempotent retry without extension_id when pending matches days.
            self.assertEqual(self.invoke("extend_access", index=0, days=5), reply)

            # Conflicting days with same extension_id -> invalid_request; different extension_id/days -> token_extension_pending.
            with self.assertRaises(ListingError) as err:
                self.invoke("extend_access", index=0, days=6, extension_id=ext_id)
            self.assertEqual(err.exception.code, "invalid_request")

            with self.assertRaises(ListingError) as err:
                self.invoke("extend_access", index=0, days=5, extension_id=str(uuid4()))
            self.assertEqual(err.exception.code, "token_extension_pending")

            with self.assertRaises(ListingError) as err:
                self.invoke("extend_access", index=0, days=6)
            self.assertEqual(err.exception.code, "token_extension_pending")

            # Deny the extension; details show last_extension and retry with same id returns denied.
            self.grants.decide_extension(grant.id, ext_id, False)
            denied_details = self.invoke("access_status", index=0, details=True)
            self.assertIsNone(denied_details["pending_extension"])
            self.assertEqual(denied_details["last_extension"], {"id": ext_id, "status": "denied"})
            self.assertEqual(self.invoke("extend_access", index=0, days=5, extension_id=ext_id)["status"], "denied")

            # Submit a second extension and approve it; generation must not bump.
            ext_id2 = str(uuid4())
            gen_before = self.grants.records[grant.id].generation
            self.assertEqual(self.invoke("extend_access", index=0, days=7, extension_id=ext_id2)["status"], "pending")
            approved = self.grants.decide_extension(grant.id, ext_id2, True)
            self.assertEqual(approved.generation, gen_before)
            self.assertAlmostEqual(approved.expires_at, t0 + 7 * 86400)
            self.assertEqual(self.invoke("extend_access", index=0, days=7, extension_id=ext_id2)["status"], "active")

        # Auto-approval uses a sliding window (does not stack across repeated calls).
        self.workspace.acknowledge_token_auto_approval(True)
        self.workspace.set_token_auto_approval("auto_approve_token_extensions", True)
        self.workspace.set_token_lifespan_days(5)
        t1 = t0 + 86400
        with patch("keepassxc_agent_access.grants.time", return_value=t1):
            # Requesting > token_lifespan_days still awaits owner review even when auto-approve is on.
            over = self.invoke("extend_access", index=0, days=10, extension_id=str(uuid4()))
            self.assertEqual(over["status"], "pending")
            self.grants.decide_extension(grant.id, self.grants.records[grant.id].pending_extension.id, False)

            # Requesting <= token_lifespan_days (or default days=None) auto-approves with sliding window.
            auto1 = self.invoke("extend_access", index=0, extension_id=str(uuid4()))
            self.assertEqual(auto1["status"], "active")
            # Existing expires_at was t0 + 7d = t1 + 6d; t1 + 5d < t1 + 6d so max keeps t0 + 7d.
            self.assertEqual(auto1["expires_at"], int(t0 + 7 * 86400))

            # Advance to t0 + 4d (3d remaining), auto-extend by 5d -> advances to t0 + 9d, and calling twice does not stack to +14d.
            t2 = t0 + 4 * 86400
        with patch("keepassxc_agent_access.grants.time", return_value=t2):
            auto2 = self.invoke("extend_access", index=0, days=5, extension_id=str(uuid4()))
            self.assertEqual(auto2["status"], "active")
            self.assertEqual(auto2["expires_at"], int(t2 + 5 * 86400))
            auto3 = self.invoke("extend_access", index=0, days=5, extension_id=str(uuid4()))
            self.assertEqual(auto3["expires_at"], int(t2 + 5 * 86400))

            # Enabling auto_approve_extended_lifespans auto-approves requests beyond default life span.
            self.workspace.set_token_auto_approval("auto_approve_extended_lifespans", True)
            over_auto = self.invoke("extend_access", index=0, days=10, extension_id=str(uuid4()))
            self.assertEqual(over_auto["status"], "active")
            self.assertEqual(over_auto["expires_at"], int(t2 + 10 * 86400))
            self.workspace.set_token_auto_approval("auto_approve_extended_lifespans", False)

    def test_pending_extension_respects_capacity_disabled_transition_and_workflow_ineligibility(self):
        grant = self.enroll_and_approve(index=0, identity="Capacity Holder")
        # Fill MAX_PENDING slots with pending tokens, so a pending extension hits MAX_PENDING.
        for i in range(1, MAX_PENDING + 1):
            self.invoke("request_access", index=i, request={
                "identity": f"Queued {i}", "project": "Lifespan Project",
                "items": [{"vault": self.vault, "entry": self.entry, "metadata": True}],
            })
        with self.assertRaises(ListingError) as err:
            self.grants.request_extension(grant.id, 3, Attribution())
        self.assertEqual(err.exception.code, "busy")

        # Remove one pending item so extension can queue, then disabling denies pending_extension.
        first_pending = next(r for r in self.grants.rows() if r.status == "pending")
        self.grants.decide(first_pending.id, None)
        status, grant = self.grants.request_extension(grant.id, 3, Attribution())
        self.assertEqual(status, "pending")
        self.grants.transition(grant.id, "disabled")
        disabled = self.grants.records[grant.id]
        self.assertEqual(disabled.extension.status, "denied")
        self.assertIsNone(disabled.pending_extension)
        self.grants.transition(grant.id, "removed")
        removed = self.grants.records[grant.id]
        self.assertIsNone(removed.extension)
        self.assertIsNone(removed.expires_at)

        # Workflow-only tokens have expires_at set and cannot request extensions.
        draft = self.grants.workflow_candidate(
            self.secrets[65], 1500, {"identity": "Workflow Agent", "project": "WF"},
            Attribution(), {"vault": self.vault, "entry": self.entry, "uses": ["https_results"],
                            "origins": ["https://service.example.test/"]},
            (str(uuid4()), "a" * 64),
        )
        self.assertIsNotNone(draft.expires_at)
        self.grants.issue_workflow(draft)
        with self.assertRaises(ListingError) as err:
            self.grants.request_extension(draft.id, 3, Attribution())
        self.assertEqual(err.exception.code, "ineligible")

    def test_runtime_expiry_enforced_across_broker_edits_guest_console_and_workflows(self):
        t0 = 1_800_000_000.0
        with patch("keepassxc_agent_access.grants.time", return_value=t0):
            grant = self.enroll_and_approve(index=0, items=[{
                "vault": self.vault, "entry": self.entry, "metadata": True,
                "edits": ["update_entry"],
            }])

        # Submit an edit while active (held for owner review).
        self.workspace.set_review_action("update_entry", True)
        edit_id = str(uuid4())
        edit_reply = self.invoke("request_edit", index=0, request={
            "id": edit_id, "operation": "update_entry", "vault": self.vault,
            "entry": self.entry, "fields": {"title": "New Title"},
        })
        self.assertEqual(edit_reply, {"id": edit_id, "status": "pending"})

        # Build live GuestGrant, ConsoleGrant, and Workflow handles referencing this token.
        revision = self.workspace.registrations[self.vault].credential_revision(self.entry)
        session = self.workspace.session(self.vault)
        guest_grant = GuestGrant(grant.id, grant.generation, self.workspace.generation,
                                 self.vault, self.entry, revision, session, monotonic() + 600)
        console_grant = ConsoleGrant(grant.id, grant.generation, self.workspace.generation,
                                     self.vault, self.entry, revision, "https://service.example.test:443/",
                                     "/sock", session, monotonic() + 600)
        workflow = Workflow(str(uuid4()), grant.id, grant.generation, self.workspace.generation,
                            self.vault, self.entry, revision, session, monotonic() + 600,
                            {}, {}, {}, set())

        self.assertTrue(self.broker.guest_access.current(guest_grant))
        self.assertTrue(self.broker.console_access.current(console_grant))
        self.assertTrue(self.broker.workflows.current(workflow))
        self.assertTrue(self.edits._active(grant))

        # Expire the token without calling prune_expired() yet: runtime guards must reject immediately.
        expired_now = grant.expires_at + 10
        with patch("keepassxc_agent_access.grants.time", return_value=expired_now):
            self.assertFalse(self.broker.guest_access.current(guest_grant))
            self.assertFalse(self.broker.console_access.current(console_grant))
            self.assertFalse(self.broker.workflows.current(workflow))
            self.assertFalse(self.edits._active(grant))

            # EditRequests._discard_stale_proposals marks pending edit stale.
            self.assertEqual(self.edits.rows(), [])
            with self.activity.connection() as db:
                row = db.execute("SELECT status FROM edit_requests WHERE id=?", (edit_id,)).fetchone()
                self.assertEqual(row["status"], "stale")

            # Broker operations reject expired token.
            with self.assertRaises(ListingError) as err:
                self.invoke("request_edit", index=0, request={
                    "id": str(uuid4()), "operation": "update_entry", "vault": self.vault,
                    "entry": self.entry, "fields": {"title": "Blocked"},
                })
            self.assertEqual(err.exception.code, "ineligible")


if __name__ == "__main__":
    unittest.main()
