from pathlib import Path
import stat
import tempfile
from threading import RLock
from time import monotonic
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from gi.repository import Gdk

from keepassxc_agent_access.activity import Attribution
from keepassxc_agent_access.approvals import Approval
from keepassxc_agent_access.grants import Choice, Grant, Item, PermissionChange, Scope
from keepassxc_agent_access.review_popups import ReviewPopups
from keepassxc_agent_access.settings import SettingsError
from keepassxc_agent_access.workspace_app import Gtk, WorkspaceApplication
from keepassxc_agent_access.workspace_views import (
    ACCESS_STATES, ACTIVITY_ACTION_ICONS, ACTIVITY_STATES, AccessView, ActivityView, activity_execution,
    activity_matches, edit_binding, entry_details, locked_review_vaults, usage_approval_caption,
)


class ReviewPopupTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="keeper-popups-test-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "desktop-notifications.json"
        self.popups = ReviewPopups(self.path)

    def test_pending_requests_are_shown_once_and_in_order(self):
        grant = ("grant", "grant-id")
        edit = ("edit", "token/edit-id")
        self.assertEqual(self.popups.next_request((grant, edit)), grant)
        self.popups.mark_reviewed(*grant)
        self.assertEqual(self.popups.next_request((grant, edit)), edit)
        self.popups.mark_reviewed(*edit)
        self.assertIsNone(self.popups.next_request((grant, edit)))
        self.assertIsNone(self.popups.next_request(()))

    def test_toggle_keeps_the_existing_private_notification_preference(self):
        grant = ("grant", "grant-id")
        self.popups.load()
        self.assertTrue(self.popups.enabled)
        self.assertFalse(self.path.exists())
        self.popups.set_enabled(False)
        self.assertIsNone(self.popups.next_request((grant,)))

        reopened = ReviewPopups(self.path)
        reopened.load()
        self.assertFalse(reopened.enabled)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        reopened.set_enabled(True)
        self.assertEqual(reopened.next_request((grant,)), grant)

    def test_bad_settings_disable_popups_and_failed_save_keeps_choice(self):
        self.path.write_text('{"desktop_notifications": "false"}', encoding="utf-8")
        with self.assertRaisesRegex(SettingsError, "request pop-up setting"):
            self.popups.load()
        self.assertFalse(self.popups.enabled)
        with patch("keepassxc_agent_access.review_popups.write_private_json",
                   side_effect=SettingsError("save failed")):
            with self.assertRaises(SettingsError):
                self.popups.set_enabled(True)
        self.assertFalse(self.popups.enabled)

    def test_manual_review_opens_the_expiring_request_even_if_popups_are_off(self):
        late = SimpleNamespace(id=7, expires=50)
        early = SimpleNamespace(id=8, expires=20)
        grant = SimpleNamespace(id="grant", status="pending", pending_change=None)
        app = SimpleNamespace(grants=SimpleNamespace(rows=lambda: (grant,)), pending_edits=lambda: (),
                              usage_approvals=SimpleNamespace(pending=lambda: (late, early)), dialog=None, busy=False)
        app._review_requests = lambda: WorkspaceApplication._review_requests(app)
        self.assertEqual(app._review_requests(), (("usage", "8"), ("usage", "7"), ("grant", "grant")))
        self.popups.enabled = False
        self.assertIsNone(self.popups.next_request(app._review_requests()))
        view = SimpleNamespace(app=app, open_record=Mock())
        AccessView._open_next(view)
        view.open_record.assert_called_once_with("8", "usage")

    def test_unlock_from_review_only_reopens_the_visible_owner_request(self):
        dialog = Mock()
        app = SimpleNamespace(dialog=dialog, unlock_record=Mock())
        record = SimpleNamespace(name="Synthetic Vault")
        control = Mock()
        box = Mock()
        feedback = Mock()
        with patch.object(Gtk, "Button", return_value=control), patch.object(Gtk, "Box", return_value=box), \
                patch("keepassxc_agent_access.workspace_app._label", return_value=feedback), \
                patch("keepassxc_agent_access.workspace_app.styled", return_value=feedback):
            self.assertIs(WorkspaceApplication.unlock_review_button(app, record, dialog), box)
        _, clicked = control.connect.call_args.args
        clicked()
        self.assertEqual(app.unlock_record.call_args.args, (record,))
        self.assertIs(app.unlock_record.call_args.kwargs["parent"], dialog)
        finished = app.unlock_record.call_args.kwargs["finished"]
        finished(False, "")
        dialog.response.assert_not_called()
        feedback.show.assert_not_called()
        finished(False, "Incorrect password")
        feedback.set_text.assert_called_once_with("Incorrect password")
        feedback.show.assert_called_once()
        finished(True, "")
        dialog.response.assert_called_once_with(Gtk.ResponseType.APPLY)
        app.dialog = Mock()
        finished(True, "")
        dialog.response.assert_called_once()

    def test_unqualified_requests_offer_a_choice_of_locked_vaults(self):
        workspace = SimpleNamespace(registrations={"a": "First Vault", "b": "Second Vault", "c": "Open Vault"},
                                    session=lambda identifier: object() if identifier == "c" else None)
        self.assertEqual(list(locked_review_vaults(workspace, [SimpleNamespace(vault=None)])),
                         ["First Vault", "Second Vault"])
        self.assertEqual(list(locked_review_vaults(workspace, [SimpleNamespace(vault="a")])), ["First Vault"])

    def test_caption_matches_the_authority_even_when_access_can_resume(self):
        default = {"id": 1, "uid": 123, "context": Attribution(), "action": "Fixture", "scope": (),
                   "destination": None, "expires": 1}
        for settings, text in (
            ({}, "this operation only"),
            ({"opens_console": True, "reuse_minutes": 5}, "can be reopened"),
            ({"guest_command": True, "reuse_minutes": 5}, "status checks"),
            ({"workflow_review": True}, "listed operations"),
            ({"workflow_review": True, "workflow_enrollment": True, "resume_access": True}, "listed operations"),
        ):
            with self.subTest(settings=settings):
                self.assertIn(text, usage_approval_caption(Approval(**default, **settings)))

    @staticmethod
    def _descendants(root):
        items = [root]
        if hasattr(root, "get_children"):
            for child in root.get_children():
                items.extend(ReviewPopupTests._descendants(child))
        return items

    @staticmethod
    def _make_fake_app():
        return SimpleNamespace(
            window=None,
            busy=False,
            exiting=False,
            desktop=SimpleNamespace(locked=False),
            broker=SimpleNamespace(enabled=True),
            workspace=SimpleNamespace(
                paused=False,
                mutex=RLock(),
                registrations={},
                session=lambda _vid: None,
                owner_session=lambda _vid: None,
            ),
            grants=None,
            pending_edits=lambda: (),
            usage_approvals=SimpleNamespace(pending=lambda: ()),
            review_popups=SimpleNamespace(mark_reviewed=Mock()),
            _review_requests=lambda: (),
            _refresh=Mock(),
            confirm=Mock(return_value=True),
            owner_operation=lambda fn: fn(),
            set_agent_paused=Mock(),
            unlock_review_button=lambda *_a, **_kw: Gtk.Box(),
        )

    def test_review_displays_note_context_permission_diff_and_keyboard(self):
        v1 = str(uuid4())
        e_old, e_shared, e_new = str(uuid4()), str(uuid4()), str(uuid4())
        entry_rows = [
            {"id": e_old, "title": "Old Entry", "group": "root", "group_path": []},
            {"id": e_shared, "title": "Shared Entry", "group": "root", "group_path": []},
            {"id": e_new, "title": "New Entry", "group": "root", "group_path": []},
        ]
        session = SimpleNamespace(entries=entry_rows, groups=[{"id": "root", "name": "Root", "parent": None}])
        reg = SimpleNamespace(name="Work", target=SimpleNamespace(database=Path("/tmp/work.kdbx")), binding=lambda *_: None)
        app = self._make_fake_app()
        app.workspace = SimpleNamespace(
            paused=False, mutex=RLock(), registrations={v1: reg},
            session=lambda _vid: session, owner_session=lambda _vid: session,
        )

        grant_scope = (
            Scope(v1, e_old, True, None, None),
            Scope(v1, e_shared, True, None, None, username=True),
        )
        grant = Grant(
            id="tok-1234", verifier="v" * 64, uid=1000, requested=10.0,
            identity="Agent Alpha", project="Proj X",
            context=Attribution(model="model-a", chat="chat-a"),
            items=(Item(v1, e_old, None, True, None),),
            status="active", scope=grant_scope,
        )
        change_items = (
            Item(v1, e_shared, None, True, None, url=True),
            Item(None, None, "Pick Target", True, None),
        )
        change = PermissionChange(
            id="chg-1", requested=20.0,
            context=Attribution(model="gpt-5", chat="Main Chat", note="Need new entry URL"),
            items=change_items,
        )
        shared_choice = Choice(Scope(v1, e_shared, True, None, None, url=True), "Work", ("Shared Entry",), None)
        alt_old = Choice(Scope(v1, e_old, True, None, None), "Work", ("Old Entry",), None)
        alt_new = Choice(Scope(v1, e_new, True, None, None), "Work", ("New Entry",), None)
        app.grants = SimpleNamespace(
            records={grant.id: grant},
            choices=lambda item: [shared_choice] if item.entry == e_shared else [alt_old, alt_new],
            decide=Mock(),
        )
        view = AccessView(app)

        captured = {}

        def fake_run(dialog, standalone=False):
            labels = [w for w in self._descendants(dialog) if isinstance(w, Gtk.Label)]
            expanders = [w for w in self._descendants(dialog) if isinstance(w, Gtk.Expander)]
            self.assertEqual(len(expanders), 1)
            expander = expanders[0]
            self.assertFalse(expander.get_expanded())
            summary = [lbl.get_text() for lbl in labels if not lbl.is_ancestor(expander)]
            self.assertTrue(any("Need new entry URL" in text for text in summary))
            self.assertTrue(any("gpt-5" in text and "Main Chat" in text for text in summary))
            self.assertTrue(all("tok-1234" not in text and "verified" not in text for text in summary))
            self.assertIn("Permission Changes", summary)
            self.assertIn("Removed", summary)
            self.assertIn("Changed", summary)
            self.assertTrue(any("Pending selection" in text for text in summary))

            combo = next(w for w in self._descendants(dialog) if isinstance(w, Gtk.ComboBoxText))
            combo.set_active(1)  # Choose alt_new -> Added + Removed + Changed
            updated_summary = [
                lbl.get_text() for lbl in self._descendants(dialog)
                if isinstance(lbl, Gtk.Label) and not lbl.is_ancestor(expander)
            ]
            self.assertIn("Added", updated_summary)
            self.assertTrue(any("New Entry" in text for text in updated_summary))

            combo.set_active(0)  # Choose alt_old -> Unchanged!
            unchanged_summary = [
                lbl.get_text() for lbl in self._descendants(dialog)
                if isinstance(lbl, Gtk.Label) and not lbl.is_ancestor(expander)
            ]
            self.assertIn("Unchanged", unchanged_summary)

            # Keyboard: Ctrl+C allowed (False), Return/Space swallowed (True), Escape emits DELETE_EVENT.
            copy_evt = Gdk.Event.new(Gdk.EventType.KEY_PRESS)
            copy_evt.key.keyval = Gdk.KEY_c
            copy_evt.key.state = Gdk.ModifierType.CONTROL_MASK
            self.assertFalse(dialog.emit("key-press-event", copy_evt))
            ret_evt = Gdk.Event.new(Gdk.EventType.KEY_PRESS)
            ret_evt.key.keyval = Gdk.KEY_Return
            self.assertTrue(dialog.emit("key-press-event", ret_evt))

            responses = []
            dialog.connect("response", lambda _d, resp: responses.append(resp))
            esc_evt = Gdk.Event.new(Gdk.EventType.KEY_PRESS)
            esc_evt.key.keyval = Gdk.KEY_Escape
            self.assertTrue(dialog.emit("key-press-event", esc_evt))
            captured["responses"] = responses
            dialog.destroy()
            return responses[-1]

        app.run_dialog = fake_run
        view._review(grant, change=change)
        self.assertEqual(captured["responses"], [Gtk.ResponseType.DELETE_EVENT])
        app.grants.decide.assert_not_called()

    def test_review_usage_shows_note_context_live_pause_blocker_and_keyboard(self):
        app = self._make_fake_app()
        app.workspace.paused = True
        ticket = Approval(
            id=9, uid=1000,
            context=Attribution(model="claude-sonnet", chat="Ops Chat", note="Routine read note"),
            action="Use password", scope=("Vault / Entry",), destination="https://api.example.com",
            expires=monotonic() + 60, identity="Agent Beta", project="Ops",
            write_once=False, resume_access=True,
        )
        app.usage_approvals = SimpleNamespace(pending=lambda: (ticket,), resolve=Mock())
        view = AccessView(app)

        def fake_run(dialog, standalone=False):
            labels = [w.get_text() for w in self._descendants(dialog) if isinstance(w, Gtk.Label)]
            self.assertIn("Routine read note", labels)
            self.assertTrue(any("claude-sonnet" in t and "Ops Chat" in t for t in labels))
            blocker = next(
                w for w in self._descendants(dialog)
                if w.get_style_context().has_class("keeper-review-blocker")
            )
            self.assertTrue(blocker.get_visible())
            resume_btn = next(
                w for w in self._descendants(blocker)
                if isinstance(w, Gtk.Button) and w.get_label() == "Resume Agent Access"
            )
            self.assertFalse(resume_btn.get_can_focus())
            approve_btn = dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT)
            self.assertEqual(approve_btn.get_label(), "Resume Access and Approve")

            copy_evt = Gdk.Event.new(Gdk.EventType.KEY_PRESS)
            copy_evt.key.keyval = Gdk.KEY_C
            copy_evt.key.state = Gdk.ModifierType.CONTROL_MASK
            self.assertFalse(dialog.emit("key-press-event", copy_evt))
            space_evt = Gdk.Event.new(Gdk.EventType.KEY_PRESS)
            space_evt.key.keyval = Gdk.KEY_space
            self.assertTrue(dialog.emit("key-press-event", space_evt))
            responses = []
            dialog.connect("response", lambda _d, r: responses.append(r))
            esc_evt = Gdk.Event.new(Gdk.EventType.KEY_PRESS)
            esc_evt.key.keyval = Gdk.KEY_Escape
            self.assertTrue(dialog.emit("key-press-event", esc_evt))
            dialog.destroy()
            return responses[-1]

        app.run_dialog = fake_run
        view._review_usage(ticket)
        app.usage_approvals.resolve.assert_not_called()

    def test_access_view_stale_credentials_search_and_bulk_remove(self):
        v1 = str(uuid4())
        e1 = str(uuid4())
        stale_grant = Grant(
            id="g-stale", verifier="a" * 64, uid=1000, requested=20.0,
            identity="Stale Bot", project="Alpha Proj",
            context=Attribution(model="m1", chat="c1"), items=(), status="active",
            scope=(Scope(v1, e1, True, None, None),),
        )
        fresh_grant = Grant(
            id="g-fresh", verifier="b" * 64, uid=1000, requested=10.0,
            identity="Fresh Bot", project="Beta Proj",
            context=Attribution(model="m2", chat="c2"), items=(), status="disabled",
            scope=(),
        )
        stale_state = {"g-stale": True}
        app = self._make_fake_app()

        def reapprove(gid):
            stale_state[gid] = False

        app.grants = SimpleNamespace(
            rows=lambda: (stale_grant, fresh_grant),
            records={stale_grant.id: stale_grant, fresh_grant.id: fresh_grant},
            is_stale=lambda g: stale_state.get(g.id, False),
            reapprove_credentials=Mock(side_effect=reapprove),
            transition=Mock(),
        )
        view = AccessView(app)
        view.refresh()

        self.assertEqual(ACCESS_STATES["Active · Credential Changed"], ("dialog-warning-symbolic", "keeper_warning"))
        model = view.table.get_model()
        statuses = {row[view.RECORD_ID]: row[view.STATUS] for row in model}
        self.assertEqual(statuses["g-stale"], "Active · Credential Changed")
        self.assertEqual(statuses["g-fresh"], "Disabled")
        self.assertTrue(view.remove_multiple.get_sensitive())

        # Context menu offers Re-approve only for stale grant.
        stale_row = next(row for row in model if row[view.RECORD_ID] == "g-stale")
        fresh_row = next(row for row in model if row[view.RECORD_ID] == "g-fresh")
        stale_labels = [lbl for section in view._context(stale_row) for lbl, _ in section]
        fresh_labels = [lbl for section in view._context(fresh_row) for lbl, _ in section]
        self.assertIn("Re-approve Current Credential", stale_labels)
        self.assertIn("Disable Token", stale_labels)
        self.assertNotIn("Re-approve Current Credential", fresh_labels)

        # Search filters rows by identity/status/project/model/chat.
        view.search.set_text("credential changed")
        self.assertEqual([row[view.RECORD_ID] for row in view.table.get_model()], ["g-stale"])
        view.search.set_text("Beta Proj")
        self.assertEqual([row[view.RECORD_ID] for row in view.table.get_model()], ["g-fresh"])
        view.search.set_text("")
        self.assertEqual(len(view.table.get_model()), 2)

        # _manage shows custom response 1 when stale and refreshes in-place.
        manage_calls = []

        def fake_manage_run(dialog):
            manage_calls.append(dialog.get_widget_for_response(AccessView.REAPPROVE_RESPONSE) is not None)
            has_apply = dialog.get_widget_for_response(Gtk.ResponseType.APPLY) is not None
            self.assertTrue(has_apply)
            dialog.destroy()
            return AccessView.REAPPROVE_RESPONSE if len(manage_calls) == 1 else Gtk.ResponseType.CLOSE

        app.run_dialog = fake_manage_run
        view._manage(stale_grant)
        self.assertEqual(manage_calls, [True, False])
        app.grants.reapprove_credentials.assert_called_once_with("g-stale")

        # Re-approve error opens an error dialog.
        app.grants.reapprove_credentials.side_effect = ValueError("Unlock vault first")
        error_dialogs = []
        app.run_dialog = lambda d: (error_dialogs.append(d.get_property("text")), d.destroy(), Gtk.ResponseType.CLOSE)[-1]
        view._reapprove_credentials("g-stale")
        self.assertEqual(error_dialogs, ["Could not re-approve credentials"])

        # Remove Multiple bulk-deletes selected tokens after one confirmation.
        def fake_bulk_run(dialog):
            checks = [w for w in self._descendants(dialog) if isinstance(w, Gtk.CheckButton)]
            self.assertEqual(len(checks), 2)
            checks[0].set_active(True)
            checks[1].set_active(True)
            dialog.destroy()
            return Gtk.ResponseType.OK

        app.run_dialog = fake_bulk_run
        view._remove_multiple()
        app.confirm.assert_called_once()
        self.assertEqual([c.args for c in app.grants.transition.call_args_list],
                         [("g-stale", "removed"), ("g-fresh", "removed")])

    def test_activity_view_truncation_reason_matches_and_workflow_icon(self):
        for state in ("Interrupted · outcome unknown", "Submitted", "Timed out", "Too large",
                      "Active", "Pending", "Authorized", "Dispatching", "Declined"):
            self.assertIn(state, ACTIVITY_STATES)
        for action in ("Provision Account", "Review Workflow", "Run Guest Command", "Check Guest Command",
                       "Release Guest Command", "Open Guest Console", "View Guest Console",
                       "Send Guest Console Input", "Close Guest Console", "Check Guest Console",
                       "Discover resources", "Broker request rate limit"):
            self.assertIn(action, ACTIVITY_ACTION_ICONS)

        row = {"id": 1, "action": "Use password", "outcome": "Denied", "destination": "https://api.example.com",
               "note": "Deploy build", "detail": "Certificate mismatch", "requested": 10.0}
        self.assertIn(("Reason", "Certificate mismatch"), activity_execution(row))
        self.assertTrue(activity_matches(row, ("V", "G", "K"), {"action": "deploy"}))
        self.assertTrue(activity_matches(row, ("V", "G", "K"), {"action": "api.example.com"}))
        self.assertTrue(activity_matches(row, ("V", "G", "K"), {"outcome": "certificate"}))

        wf_row = {"id": 1, "action": "Use password", "outcome": "Succeeded", "requested": 10.0, "identity": "Bot"}
        vals = ActivityView._values(wf_row, ("V", "G", "K"), ("workflow", "tok", "wf-1"),
                                    action="Workflow (2)", children=((), ()))
        self.assertEqual(vals[ActivityView.ACTION_ICON], "system-run-symbolic")

        app = self._make_fake_app()
        sample_rows = [{"id": 1, "action": "List vaults", "outcome": "Succeeded", "requested": 10.0}]
        app.activity = SimpleNamespace(rows=Mock(return_value=sample_rows), count=Mock(return_value=1500))
        view = ActivityView(app)
        view.refresh()
        app.activity.rows.assert_called_with(limit=1000)
        self.assertTrue(view.truncation_banner.get_visible())
        self.assertEqual(view.truncation_label.get_text(), "Showing newest 1,000 of 1,500 events")

        # Filters pass limit=None and hide the truncation banner.
        view.filters["action"].set_text("List")
        view.refresh()
        app.activity.rows.assert_called_with(limit=None)
        self.assertFalse(view.truncation_banner.get_visible())

        # Clearing filters restores banner until Show All is clicked.
        view.filters["action"].set_text("")
        view.refresh()
        self.assertTrue(view.truncation_banner.get_visible())
        view.show_all_button.clicked()
        app.activity.rows.assert_called_with(limit=None)
        self.assertFalse(view.truncation_banner.get_visible())

        # <= 1000 events hides banner by default.
        view.show_all = False
        app.activity.count.return_value = 500
        view.refresh()
        self.assertFalse(view.truncation_banner.get_visible())

    def test_entry_details_has_copy_password_and_edit_binding_uses_placeholders(self):
        app = self._make_fake_app()
        record = SimpleNamespace(name="Vault", bindings=())
        app.selection = ("v1", "")
        app.workspace.registrations = {"v1": record}
        app.workspace.owner_session = lambda _v: object()
        app._copy_password = Mock()
        app.copy_reference = Mock()
        entry = {"id": "e1", "title": "My Entry", "username": "alice", "url": "https://example.com",
                 "group": "g1", "group_path": ["Web"]}

        def fake_entry_run(dialog):
            copy_pw = next(
                w for w in self._descendants(dialog)
                if isinstance(w, Gtk.Button) and w.get_label() == "Copy Password"
            )
            copy_pw.clicked()
            dialog.hide()
            return Gtk.ResponseType.CLOSE

        app.run_dialog = fake_entry_run
        entry_details(app, "v1", entry)
        app._copy_password.assert_called_once_with("v1", "e1")

        def fake_binding_run(dialog):
            widgets = {w.get_name(): w for w in self._descendants(dialog)}
            self.assertEqual(widgets["action-id"].get_text(), "")
            self.assertEqual(widgets["action-id"].get_placeholder_text(), "health-check")
            self.assertEqual(widgets["action-name"].get_text(), "")
            self.assertEqual(widgets["action-name"].get_placeholder_text(), "Health check")
            dialog.destroy()
            return Gtk.ResponseType.CANCEL

        app.run_dialog = fake_binding_run
        edit_binding(app, "v1", "e1", None)
