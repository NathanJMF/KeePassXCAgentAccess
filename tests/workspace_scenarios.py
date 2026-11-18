"""Verify a legacy upgrade and token separation on a private GNOME desktop."""

import atexit
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import traceback
from unittest.mock import patch
from uuid import UUID, uuid4

from pykeepass import PyKeePass, create_database

from broker_scenarios import NAMESPACE, PASSWORD as UNLOCK, REPO, isolated_uid, prepare, verify_isolation
from desktop_scenarios import set_screen_active, wait_for
from password_scenarios import button, descendants
from keepassxc_agent_access.access_settings import REVIEW_ACTIONS, AccessMode, AccessStore, Action, ActionType, VaultPolicy
from keepassxc_agent_access.activity import ActivityStore
from keepassxc_agent_access.controller import VaultController
from keepassxc_agent_access.launcher import install as install_launcher
from keepassxc_agent_access.settings import SettingsStore
from keepassxc_agent_access.setup import VaultSetup
from keepassxc_agent_access.tray import Gio, GLib, Gtk
from keepassxc_agent_access.edit_request_view import OPERATION_LABELS
from keepassxc_agent_access.workspace_app import (
    ENTRY_FOLDER_COLUMN, ENTRY_ID_COLUMN, Gdk, WorkspaceApplication,
)
from keepassxc_agent_access.workspace_editor import edit_entry
from keepassxc_agent_access.workspace_views import edit_binding
from keepassxc_agent_access.keyring import SystemKeyring
from tls_fixture import AUTHORIZATION, PASSWORD, USERNAME, tls_service


OTHER_PASSWORD = "synthetic-second-password-sentinel"
STORED_URL = "https://fixture.example.test/owner-preview"
BEARER_AUTHORIZATION = f"Bearer {PASSWORD}"
EDIT_PASSWORD = "synthetic-owner-edit-password"
REQUESTED_PASSWORD = "synthetic-approval-only-password"
COPY_PASSWORD = " synthetic clipboard password \u2603 "


def monitor_notifications():
    messages = []
    connection = Gio.DBusConnection.new_for_address_sync(
        os.environ["DBUS_SESSION_BUS_ADDRESS"],
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None, None,
    )

    def capture(_connection, message, incoming):
        if incoming and message.get_interface() == "org.gtk.Notifications":
            messages.append((message.get_member(), message.get_body().unpack()))
            return None
        return message

    connection.add_filter(capture)
    connection.call_sync(
        "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.Monitoring", "BecomeMonitor",
        GLib.Variant("(asu)", (["type='method_call',interface='org.gtk.Notifications'"], 0)),
        None, Gio.DBusCallFlags.NONE, 1500, None,
    )
    return connection, messages


def main(root):
    target, endpoint, private, fixture = prepare(root)
    install_launcher(REPO / "run-tray", os.environ["XDG_DATA_HOME"])
    notification_monitor, notification_messages = monitor_notifications()
    atexit.register(notification_monitor.close_sync, None)
    runtime = root / "cli"
    shutil.copy2(REPO / "keeper-agent-runner", runtime / "keeper-agent-runner")
    shutil.copyfile(REPO / "src/keepassxc_agent_access/agent_runner.py",
                    runtime / "src/keepassxc_agent_access/agent_runner.py")
    first_entry, direct_entry, nested_entry = [row["id"] for row in fixture]
    duplicate_title = fixture[1]["title"]
    primary = PyKeePass(target.database, password=UNLOCK, keyfile=str(target.key_file))
    credential = primary.find_entries(uuid=UUID(first_entry), first=True)
    credential.username, credential.password = USERNAME, PASSWORD
    credential.url = STORED_URL
    primary.find_entries(uuid=UUID(nested_entry), first=True).password = COPY_PASSWORD
    primary.save()
    second_path = private / "second.kdbx"
    shutil.copyfile(target.database, second_path)
    copied = PyKeePass(second_path, password=UNLOCK, keyfile=str(target.key_file))
    copied.find_entries(uuid=UUID(first_entry), first=True).password = OTHER_PASSWORD
    copied.save()

    uid = isolated_uid()
    profiles = root / "profiles"
    profiles.mkdir()
    profiles.chmod(0o1777)
    names = ("alpha", "beta", "review", "review-live", "review-paused", "expanded", "bearer", "scoped-editor",
             "auto-token")
    directories = [str(profiles / name) for name in names]
    atexit.register(subprocess.run, [*NAMESPACE, "rm", "-rf", "--", *directories], check=True)
    subprocess.run([*NAMESPACE, "mkdir", "-m", "700", *directories], check=True)

    settings = SettingsStore(private / "settings.json")
    keyring = SystemKeyring()
    setup = VaultSetup(settings, keyring, VaultController())
    setup.configure(setup.controller.begin(), target, UNLOCK, True)
    original_item = settings.read().active_item
    assert original_item
    old_activity = ActivityStore(private / "activity.sqlite")
    # Use the pre-upgrade activity columns, so this exercises actual schema migration.
    with old_activity.connection() as db:
        db.executescript("""
            CREATE TABLE sessions (id INTEGER PRIMARY KEY, uid INTEGER, chat_id TEXT, UNIQUE(uid,chat_id));
            CREATE TABLE activity (id INTEGER PRIMARY KEY, session INTEGER, requested REAL, decided REAL,
                completed REAL, model TEXT, chat TEXT, action TEXT, entry TEXT, destination TEXT,
                decision TEXT, outcome TEXT, status INTEGER);
            INSERT INTO sessions VALUES(1, 500, 'previous-chat');
            INSERT INTO activity(id,session,requested,completed,action,outcome)
            VALUES(1,1,strftime('%s','now'),strftime('%s','now'),'Legacy fixture','Succeeded');
        """)

    with tls_service(private, extra_authorization=(BEARER_AUTHORIZATION,)) as (certificate, url, calls):
        os.environ["SSL_CERT_FILE"] = str(certificate)
        old_access = AccessStore(private / "access.json")
        imported = Action("check", "Imported fixture action", first_entry, url + "/first")
        old_access.write(replace(old_access.read(), mode=AccessMode.ALLOW, endpoint=str(endpoint), uid=uid,
                                 vaults=((str(primary.root_group.uuid), VaultPolicy({first_entry}, (imported,))),)))
        app = WorkspaceApplication(private, keyring, show_window=True)
        result = 1
        captured = []
        token_ids = {}
        enrollment_model, enrollment_chat = "Synthetic enrollment model", "Synthetic enrollment chat"
        action_model, action_chat = "Synthetic test model", "Synthetic test chat"

        def settings_switch(page, name, enabled=None, *, label=None):
            active = []

            def change(dialog):
                assert dialog.get_title() == "Keeper Settings"
                assert dialog.get_style_context().has_class("keeper-dialog")
                divider = next(widget for widget in descendants(dialog)
                               if widget.get_style_context().has_class("keeper-settings-divider"))
                wait_for_paint(divider)
                area = dialog.get_content_area()
                window = app.window.get_window()
                workarea = window.get_display().get_monitor_at_window(window).get_workarea()
                assert tuple(dialog.get_default_size()) == (min(1080, workarea.width - 48),
                                                            min(826, workarea.height - 80))
                assert divider.translate_coordinates(area, 0, 0)[1] == 0
                assert divider.get_allocated_height() == area.get_allocated_height()
                pages = next(widget for widget in descendants(dialog) if widget.get_name() == "keeper-settings-pages")
                assert [pages.child_get_property(child, "title") for child in pages.get_children()] == [
                    "Auto Approve", "Vaults", "Updates", "Broker Settings",
                ]
                assert pages.get_visible_child_name() == "auto-approve"
                assert dialog.get_widget_for_response(Gtk.ResponseType.CLOSE) is None
                pages.set_visible_child_name(page)
                toggles = [widget for widget in descendants(pages.get_visible_child()) if isinstance(widget, Gtk.Switch)]
                if page == "auto-approve":
                    assert [widget.get_name() for widget in toggles] == [
                        "request-popups", "auto-approve-usage", *REVIEW_ACTIONS, "token-auto-approval-acknowledged",
                        "auto_approve_tokens", "auto_approve_token_changes",
                    ]
                    acknowledgement = toggles[-3]
                    reveal = next(widget for widget in descendants(pages.get_visible_child())
                                  if widget.get_name() == "token-auto-approval-options")
                    assert reveal.get_reveal_child() == acknowledgement.get_active()
                    danger = [widget.get_text() for widget in descendants(pages.get_visible_child())
                              if isinstance(widget, Gtk.Label)
                              and widget.get_style_context().has_class("keeper-settings-danger")]
                    assert danger == ["I Understand", "Danger", "Access Tokens - Create",
                                      "Access Tokens - Update Permissions"]
                toggle = next(widget for widget in toggles if widget.get_name() == name)
                if label is not None:
                    assert toggle.get_accessible().get_name() == label
                if enabled is not None:
                    toggle.set_active(enabled)
                if page == "auto-approve":
                    assert reveal.get_reveal_child() == acknowledgement.get_active()
                active.append(toggle.get_active())
                dialog.close()

            drive_dialog(app.settings_button.clicked, change)
            return active[0]

        def click_decision(widget):
            event = Gdk.Event.new(Gdk.EventType.BUTTON_RELEASE)
            event.button.button = Gdk.BUTTON_PRIMARY
            mouse = widget.get_display().get_default_seat().get_pointer()
            event.set_device(mouse)
            event.set_source_device(mouse)
            with patch("keepassxc_agent_access.owner_views.Gtk.get_current_event", return_value=event):
                widget.clicked()

        def assert_keypress_ignored(dialog, profile, *, permission_change=False):
            responses = []
            listener = dialog.connect("response", lambda _, response: responses.append(response))
            try:
                for kind in (Gdk.EventType.KEY_PRESS, Gdk.EventType.KEY_RELEASE):
                    for key in (Gdk.KEY_Return, Gdk.KEY_space, Gdk.KEY_Escape):
                        event = Gdk.Event.new(kind)
                        event.key.keyval = key
                        assert dialog.emit("key-press-event" if kind == Gdk.EventType.KEY_PRESS
                                           else "key-release-event", event)
                for response in (Gtk.ResponseType.ACCEPT, Gtk.ResponseType.REJECT):
                    widget = dialog.get_widget_for_response(response)
                    assert not widget.get_can_focus()
                    widget.clicked()
                assert not responses
                grant = app.grants.records[token_ids[profile]]
                assert (grant.pending_change.status if permission_change else grant.status) == "pending"
            finally:
                dialog.disconnect(listener)

        def invoke(profile, *command, request=None, expected=0, model=action_model, chat=action_chat, note=None):
            env = [f"KEEPASSXC_AGENT_SOCKET={endpoint}", f"KEEPASSXC_AGENT_MODEL={model}",
                   f"KEEPASSXC_AGENT_CHAT={chat}", "KEEPASSXC_AGENT_CHAT_ID=test-chat"]
            if note:
                env.append(f"KEEPASSXC_AGENT_NOTE={note}")
            if profile:
                env.append(f"KEEPASSXC_AGENT_TOKEN_FILE={profiles / profile / 'token'}")
            args = [*NAMESPACE, "/usr/bin/env", "-i", f"PATH={root / 'cli'}:/usr/bin:/bin",
                    *env, "keepassxc-agent", *command, "--json"]
            process = subprocess.run(args, cwd="/tmp", capture_output=True,
                                     input=json.dumps(request).encode() if request else None, timeout=12)
            assert process.returncode == expected, process.stderr.decode()
            captured.append((repr(args).encode(), process.stdout, process.stderr))
            if expected and not process.stdout:
                return process.stderr.decode()
            return json.loads(process.stdout)

        def enroll(profile, items, expected=0, *, identity=None):
            existing = set(app.grants.records)
            request = {"identity": identity or f"Agent {profile}", "project": "Disposable project", "items": items}
            result = invoke(profile, "access", "request", expected=expected, model=enrollment_model,
                            chat=enrollment_chat, request=request, note="Check approved services")
            created = app.grants.records.keys() - existing
            if created:
                token_ids[profile], = created
            return result

        def expected_identity(profile):
            name = app.grants.records[token_ids[profile]].identity
            return f"{name} (reported)"

        def drive_dialog(action, callback, *, opens_async=False):
            failures = []

            def fill():
                if app.dialog is None:
                    return GLib.SOURCE_CONTINUE
                try:
                    callback(app.dialog)
                except Exception as error:
                    failures.append(error)
                    app.dialog.response(Gtk.ResponseType.CANCEL)
                return GLib.SOURCE_REMOVE

            source = GLib.timeout_add(20, fill)
            action()
            if opens_async:
                wait_for(lambda: not GLib.MainContext.default().find_source_by_id(source),
                         "Waiting for a GTK dialog timed out")
            if GLib.MainContext.default().find_source_by_id(source):
                GLib.source_remove(source)
                raise AssertionError("Expected a GTK dialog")
            if failures:
                raise failures[0]

        def drive_request_popup(callback):
            visible = app.window.get_visible()

            def check(dialog):
                assert dialog.get_mapped()
                assert dialog.get_transient_for() is None
                assert app.window.get_visible() == visible
                callback(dialog)

            with patch.object(app.window, "present", side_effect=AssertionError("Request raised the Keeper window")):
                drive_dialog(app._refresh, check, opens_async=True)
            assert app.window.get_visible() == visible

        def access_root(profile):
            view = app.access_view
            return next(row for row in view.table.get_model() if row[view.RECORD_ID] == token_ids[profile])

        def access_row(profile):
            app.access_button.clicked()
            table = app.access_view.table
            path = access_root(profile).path
            table.get_selection().select_path(path)
            return lambda: table.row_activated(path, table.get_column(0))

        def approve(profile, vault=None, *, popup=False, resume=False):
            def confirm(dialog):
                assert dialog.get_title() == "Review Access Request"
                if not popup:
                    assert dialog.get_transient_for() == app.window
                labels = [child for child in descendants(dialog) if isinstance(child, Gtk.Label)]
                expander, = [child for child in descendants(dialog) if isinstance(child, Gtk.Expander)]
                assert not expander.get_expanded()
                summary = [label.get_text() for label in labels
                           if label.get_mapped() and not label.is_ancestor(expander)]
                assert app.grants.records[token_ids[profile]].identity in summary, summary
                assert "Requested by · agent-reported" in summary
                assert "Disposable project" in summary, summary
                assert "Permissions if Approved" in summary
                assert all(token_ids[profile] not in text and "verified" not in text for text in summary)
                details = [child.get_text() for child in descendants(expander) if isinstance(child, Gtk.Label)]
                assert token_ids[profile] in details, details
                assert any("verified" in text for text in details)
                assert "Disposable project (reported)" in details, details
                if profile == "alpha":
                    assert fixture[0]["title"] in summary, summary
                    assert "Read Entry Details" in summary and "Entry ID, title and group path" in summary
                    assert "Read Username" in summary and USERNAME in summary
                    assert "Run Imported fixture action" in summary, summary
                    assert first_entry in details and all(first_entry not in text for text in summary)
                    assert not any(isinstance(child, Gtk.ComboBoxText) for child in descendants(dialog))
                elif profile == "expanded":
                    assert "Requested Entries (3)" in summary
                    assert "Read Stored URL" in summary and STORED_URL in summary
                elif profile == "bearer":
                    assert any("HTTPS Bearer token GET" in label and url + "/first" in label for label in summary)
                elif profile == "scoped-editor":
                    assert {"Requested Resources (2)", "Update Entry Details", "Create Entries in Group"} <= set(summary)
                if vault:
                    combo, = [child for child in descendants(dialog) if isinstance(child, Gtk.ComboBoxText)]
                    assert len(combo.get_model()) == 4
                    assert "Choose the exact entry before approving." in summary
                    assert not dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT).get_sensitive()
                    choices = app.grants.choices(next(row for row in app.grants.rows() if row.status == "pending").items[0])
                    index = next(i for i, choice in enumerate(choices)
                                 if choice.scope.vault == vault and choice.scope.entry == nested_entry)
                    combo.set_active(index)
                    updated = [child.get_text() for child in descendants(dialog) if isinstance(child, Gtk.Label)]
                    assert duplicate_title in updated
                    assert " › ".join((choices[index].vault_name, *choices[index].path[:-1])) in updated
                approve_button = dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT)
                assert approve_button.get_label() == ("Resume Access and Approve" if resume else "Approve")
                assert dialog.get_widget_for_response(Gtk.ResponseType.REJECT).get_label() == "Deny"
                assert dialog.get_widget_for_response(Gtk.ResponseType.CLOSE) is None
                assert any("for all approved agents" in label for label in summary) == resume
                assert approve_button.get_sensitive()
                assert_keypress_ignored(dialog, profile)
                click_decision(approve_button)
            if popup:
                drive_request_popup(confirm)
            else:
                drive_dialog(access_row(profile), confirm)

        def deny(profile, *, popup=False):
            def reject(dialog):
                paused = app.workspace.paused
                approval = dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT)
                assert approval.get_label() == ("Resume Access and Approve" if paused else "Approve")
                assert_keypress_ignored(dialog, profile)
                click_decision(dialog.get_widget_for_response(Gtk.ResponseType.REJECT))

            paused = app.workspace.paused
            if popup:
                drive_request_popup(reject)
            else:
                drive_dialog(access_row(profile), reject)
            assert app.workspace.paused == paused
            assert invoke(profile, "access", "status") == {"status": "denied"}

        def expanded_scope(tree, rows, name_column, permissions_column):
            leaves = {}

            def collect(row, parent_path):
                path = (*parent_path, row[name_column])
                if row.model.iter_has_child(row.iter):
                    assert tree.row_expanded(row.path), path
                    for child in row.iterchildren():
                        collect(child, path)
                else:
                    assert path not in leaves
                    leaves[path] = row[permissions_column]

            for row in rows:
                collect(row, ())
            return leaves

        def check_token_scope(first, second, *, first_locked=False):
            first_name = app.workspace.registrations[first].name
            second_name = app.workspace.registrations[second].name
            root_entry = fixture[0]["title"]
            nested_path = (second_name, *fixture[2]["group_path"], fixture[2]["title"])
            first_entry_path = (f"{first_name} · Locked", "Entry 1") if first_locked else (first_name, root_entry)
            app.access_button.clicked()
            table = app.access_view.table
            identity = app.access_view.TITLES.index("Identity")
            project = app.access_view.TITLES.index("Project")
            token = access_root("expanded")
            if not first_locked:
                assert not table.row_expanded(token.path)
            table.expand_row(token.path, False)
            check_child_indentation(table, token, next(token.iterchildren()))

            def scope_label(path):
                vault, *groups, entry = path
                return f"{vault} > {' / '.join(groups) or '—'} > {entry}"

            def read_inline():
                token = access_root("expanded")
                assert table.row_expanded(token.path)
                entries = {}
                for row in token.iterchildren():
                    assert not row.model.iter_has_child(row.iter)
                    assert row[identity] not in entries
                    label = row[identity].encode("utf-8")
                    offsets = row[app.access_view.SEPARATOR_OFFSETS]
                    assert len(offsets) == 2 and all(label[index:index + 1] == b">" for index in offsets)
                    entries[row[identity]] = row[project]
                return entries

            inline = read_inline()
            assert set(inline) == {scope_label(path) for path in (first_entry_path, (second_name, root_entry), nested_path)}
            assert all(secret not in value for pair in inline.items() for value in pair
                       for secret in (STORED_URL, USERNAME, PASSWORD, OTHER_PASSWORD))
            if not first_locked:
                invoke("expanded", "vaults", "list")
                app.access_view.refresh()
                assert read_inline() == inline
                for _ in range(3):
                    table.get_column(identity).clicked()
                    assert read_inline() == inline
                app.activity_button.clicked()
                app.access_button.clicked()
                token = access_root("expanded")
                assert not table.row_expanded(token.path)
                table.expand_row(token.path, False)
                assert read_inline() == inline

            def inspect(dialog):
                assert dialog.get_title() == "Access Token"
                labels = {child.get_text() for child in descendants(dialog)
                          if isinstance(child, Gtk.Label) and child.is_visible()}
                assert "Approved Entries" in labels
                assert ("Unlock a database to see its group and entry names." in labels) == first_locked
                assert all(first not in value and second not in value for value in labels)
                tree, = [child for child in descendants(dialog) if isinstance(child, Gtk.TreeView)]
                assert [column.get_title() for column in tree.get_columns()] == ["Database / Group / Entry", "Permissions"]
                entries = expanded_scope(tree, tree.get_model(), 0, 1)
                assert {scope_label(path): permissions for path, permissions in entries.items()} == inline
                assert entries[first_entry_path] and "Entry Metadata" not in entries[first_entry_path]
                assert "Entry Metadata" in entries[second_name, root_entry]
                assert "Stored URL" in entries[second_name, root_entry]
                assert "Entry Metadata" in entries[nested_path]
                assert "Stored URL" not in entries[nested_path]
                assert all(STORED_URL not in description for description in entries.values())
                dialog.response(Gtk.ResponseType.CLOSE)

            drive_dialog(access_row("expanded"), inspect)

        def select_tree(vault, group=""):
            model = app.tree.get_model()
            matches = []

            def find(_model, path, row, *_):
                if tuple(model[row][1:3]) == (vault, group):
                    matches.append(path.copy())

            model.foreach(find)
            path, = matches
            if group:
                app.tree.expand_to_path(path)
            app.tree.get_selection().select_path(path)
            app.tree.row_activated(path, app.tree.get_column(0))
            return path

        def wait_for_paint(widget):
            clock = widget.get_frame_clock()
            frame = clock.get_frame_counter()
            widget.queue_draw()
            wait_for(lambda: clock.get_frame_counter() > frame, "Keeper view did not repaint")

        def check_toolbar_button(button):
            wait_for_paint(button)
            content = button.get_child()
            if isinstance(content, Gtk.Stack):
                content = content.get_visible_child()
            x, y = content.translate_coordinates(button, 0, 0)
            size = button.get_allocated_width(), button.get_allocated_height()
            assert abs(2 * x + content.get_allocated_width() - size[0]) <= 1
            assert abs(2 * y + content.get_allocated_height() - size[1]) <= 1
            return size

        def check_date_widths(table, row, *titles):
            wait_for_paint(table)
            for column in table.get_columns():
                if column.get_title() not in titles:
                    continue
                column.cell_set_cell_data(row.model, row.iter, False, False)
                required = sum(cell.get_preferred_width(table)[1] for cell in column.get_cells()
                               if cell.get_visible())
                assert column.get_width() >= required, (column.get_title(), column.get_width(), required)

        def check_child_indentation(table, parent, child):
            expander = table.get_expander_column()
            parent_area = table.get_cell_area(parent.path, expander)
            child_area = table.get_cell_area(child.path, expander)
            expected = parent_area.width - child_area.width
            assert expected > 0
            for column in table.get_columns():
                if column == expander:
                    continue
                spacer = column.get_cells()[0]
                column.cell_set_cell_data(parent.model, parent.iter, False, False)
                assert not spacer.get_visible(), column.get_title()
                column.cell_set_cell_data(child.model, child.iter, False, False)
                assert spacer.get_visible() and spacer.get_fixed_size()[0] == expected, column.get_title()

        def browse_positions(vault, group=""):
            select_tree(vault, group)
            wait_for_paint(app.browser)
            widgets = {
                "icon": app.browse_icon, "title": app.browse_title, "lock": app.vault_buttons["lock"],
                "filter": app.entry_search, "table": app.entry_scroll, "columns": app.entries.get_column(0).get_button(),
            }
            return {name: widget.translate_coordinates(app.window, 0, 0)[1] for name, widget in widgets.items()}

        def workspace_positions():
            wait_for(lambda: not app.stack.get_transition_running(), "Workspace view did not finish switching")
            view = app.stack.get_visible_child()
            wait_for_paint(view)
            widgets = {
                style: next(widget for widget in descendants(view)
                            if widget.get_mapped() and widget.get_style_context().has_class(style))
                for style in ("keeper-section-icon", "keeper-title", "keeper-card")
            }
            widgets["sidebar"] = app.tree
            return {name: tuple(widget.translate_coordinates(app.window, 0, 0)) for name, widget in widgets.items()}

        def use(profile, vault, entry=first_entry, expected=0):
            return invoke(profile, "use", "--vault", vault, "--entry", entry, "--action", "check", expected=expected)

        def context_menu(tree, path=None, *, activate=None):
            previous = set(Gtk.Menu.get_for_attach_widget(tree) or ())
            if path is None:
                assert tree.emit("popup-menu")
            else:
                column = next(item for item in tree.get_columns() if item.get_visible())
                def row_position():
                    rect = tree.get_cell_area(path, column)
                    x = rect.x + max(1, rect.width // 2)
                    y = rect.y + max(1, rect.height // 2)
                    hit = tree.get_path_at_pos(x, y)
                    return (x, y) if hit and hit[0] == path else None

                wait_for(row_position, "Entry row was not laid out")
                x, y = row_position()
                event = Gdk.Event.new(Gdk.EventType.BUTTON_PRESS)
                event.button.window = tree.get_bin_window()
                event.button.button = Gdk.BUTTON_SECONDARY
                event.button.x = x
                event.button.y = y
                event.set_device(tree.get_display().get_default_seat().get_pointer())
                assert tree.emit("button-press-event", event)
            menu, = set(Gtk.Menu.get_for_attach_widget(tree) or ()) - previous
            options = [item for item in menu.get_children() if not isinstance(item, Gtk.SeparatorMenuItem)]
            for item in options:
                if item.get_label() in ("Delete…", "Remove Token…"):
                    style = item.get_style_context()
                    assert style.has_class("keeper-delete")
                    found, color = style.lookup_color("keeper_failure")
                    assert found and style.get_color(Gtk.StateFlags.NORMAL).equal(color)
            labels = [item.get_label() for item in options]
            menu.popdown()
            if activate is not None:
                options[labels.index(activate)].activate()
            menu.destroy()
            return labels

        def token_context_menu(profile, *, activate=None):
            access_row(profile)
            tree = app.access_view.table
            model, node = tree.get_selection().get_selected()
            return context_menu(tree, model.get_path(node), activate=activate)

        def open_entry(identifier):
            table = app.entries
            path = next(row.path for row in table.get_model() if row[ENTRY_ID_COLUMN] == identifier)
            table.row_activated(path, next(column for column in table.get_columns() if column.get_title() == "Title"))

        def entry_locations(dialog):
            choosers = {child.get_name(): child for child in descendants(dialog) if isinstance(child, Gtk.ComboBoxText)}
            return choosers["entry-vault"], choosers["group-location"]

        def sidebar_group_options(vault):
            model = app.tree.get_model()
            options = []

            def collect(_model, _path, item, *_):
                name, current_vault, group = model[item][:3]
                if current_vault != vault or not group:
                    return
                names = [name]
                parent = model.iter_parent(item)
                while parent is not None and model[parent][2]:
                    names.append(model[parent][0])
                    parent = model.iter_parent(parent)
                options.append((group, " / ".join(reversed(names))))

            model.foreach(collect)
            return options

        def check_group_order(vault, chooser):
            expected = sidebar_group_options(vault)
            actual = [(row[chooser.get_id_column()], row[0]) for row in chooser.get_model()]
            assert actual == expected
            return expected

        def check_editors(vault, other_vault):
            original_notes = "Synthetic notes on line one\nSynthetic notes on line two"
            updated_notes = original_notes + "\nUpdated in Keeper"

            def fill_group(dialog, name):
                field = next(child for child in descendants(dialog) if child.get_name() == "group-name")
                assert not any(child.get_name() == "group-location" for child in descendants(dialog))
                field.set_text(name)
                dialog.response(Gtk.ResponseType.OK)

            def fields(dialog, title, create=False):
                grid, = [child for child in descendants(dialog) if isinstance(child, Gtk.Grid)]
                captions = sorted((grid.child_get_property(child, "top-attach"), child.get_text())
                                  for child in grid.get_children() if isinstance(child, Gtk.Label))
                assert [label for _, label in captions] == ["Vault", "Group", "Title", "URL", "Username",
                                                           "Password", "Notes"]
                vault_choice, group_choice = entry_locations(dialog)
                assert vault_choice.get_active_id() == vault
                assert vault_choice.get_sensitive() == create
                assert group_choice.get_sensitive() and group_choice.get_active_id() == group
                check_group_order(vault, group_choice)
                if create:
                    assert {row[vault_choice.get_id_column()] for row in vault_choice.get_model()} == {
                        vault, other_vault,
                    }
                else:
                    assert len(vault_choice.get_model()) == 1
                controls = {child.get_name(): child for child in descendants(dialog) if isinstance(child, Gtk.Entry)}
                notes = next(child for child in descendants(dialog) if child.get_name() == "entry-notes")
                assert isinstance(notes, Gtk.TextView)
                buffer = notes.get_buffer()
                assert buffer.get_text(*buffer.get_bounds(), True) == ("" if create else original_notes)
                buffer.set_text(original_notes if create else updated_notes)
                controls["entry-title"].set_text(title)
                controls["entry-username"].set_text("fixture-editor")
                controls["entry-url"].set_text("https://fixture.example.test/new")
                field = controls["entry-password"]
                assert not field.get_visibility()
                if create:
                    field.set_text(EDIT_PASSWORD)
                else:
                    assert not field.get_sensitive() and not field.get_text()
                dialog.response(Gtk.ResponseType.OK)

            session = app.workspace.owner_session(vault)
            root, = (group["id"] for group in session.groups if group["parent"] is None)
            folder = next(group["id"] for group in session.groups if group["parent"] == root)
            select_tree(vault, folder)
            drive_dialog(app.new_group_item.activate, lambda dialog: fill_group(dialog, "Accounting fixture group"))
            wait_for(lambda: not app.busy, "Creating a group timed out")
            group = app.selection[1]
            assert group and app.browse_title.get_text() == "Accounting fixture group"
            created_group = next(row for row in app.workspace.owner_session(vault).groups if row["id"] == group)
            assert created_group["parent"] == root
            def check_first_sidebar_group(dialog):
                vault_choice, group_choice = entry_locations(dialog)
                assert vault_choice.get_active_id() == vault
                options = check_group_order(vault, group_choice)
                assert [label for _, label in options] == [
                    "Harbor Lab", "Harbor Lab / Field Notes", "Accounting fixture group",
                ]
                assert group_choice.get_active_id() == options[0][0]
                dialog.response(Gtk.ResponseType.CANCEL)

            select_tree(vault)
            drive_dialog(app.new_entry_item.activate, check_first_sidebar_group)
            select_tree(vault, group)

            other_session = app.workspace.owner_session(other_vault)
            other_group, = (row["id"] for row in other_session.groups if row["name"] == "Harbor Lab")
            cross_title = "Cross-vault entry fixture"

            def cross_vault_entry(dialog):
                vault_choice, group_choice = entry_locations(dialog)
                assert vault_choice.get_active_id() == vault
                assert group_choice.get_active_id() == group
                check_group_order(vault, group_choice)
                assert not group_choice.set_active_id(root)
                assert vault_choice.set_active_id(other_vault)
                options = check_group_order(other_vault, group_choice)
                assert group_choice.get_active_id() == options[0][0]
                assert group_choice.set_active_id(other_group)
                title = next(child for child in descendants(dialog) if child.get_name() == "entry-title")
                title.set_text(cross_title)
                dialog.response(Gtk.ResponseType.OK)

            drive_dialog(app.new_entry_item.activate, cross_vault_entry)
            wait_for(lambda: not app.busy, "Creating an entry in the other vault timed out")
            assert app.selection == (other_vault, other_group)
            destination = app.workspace.registrations[other_vault].target
            saved_other = PyKeePass(destination.database, password=UNLOCK, keyfile=str(destination.key_file))
            cross_entry = saved_other.find_entries(title=cross_title, first=True)
            assert cross_entry is not None and cross_entry.group.uuid == UUID(other_group)
            assert all(row["title"] != cross_title for row in app.workspace.owner_session(vault).entries)
            app.workspace.delete_entry(other_vault, str(cross_entry.uuid))
            select_tree(vault, group)

            drive_dialog(app.new_entry_item.activate, lambda dialog: fields(dialog, "Created entry", create=True))
            wait_for(lambda: not app.busy, "Creating an entry timed out")
            entry, = app.entry_rows.values()
            assert entry["title"] == "Created entry"
            assert "password" not in entry and "notes" not in entry
            drive_dialog(lambda: edit_entry(app, vault, group, entry), lambda dialog: fields(dialog, "Edited entry"),
                         opens_async=True)
            wait_for(lambda: not app.busy, "Editing an entry timed out")
            edited, = app.entry_rows.values()
            assert edited["id"] == entry["id"] and edited["title"] == "Edited entry"
            drive_dialog(app._edit_group, lambda dialog: fill_group(dialog, "Edited fixture group"))
            wait_for(lambda: not app.busy, "Editing a group timed out")
            assert app.selection == (vault, group)
            assert app.browse_title.get_text() == "Edited fixture group"

            owner = PyKeePass(target.database, password=UNLOCK, keyfile=str(target.key_file))
            actual = owner.find_entries(uuid=UUID(entry["id"]), first=True)
            assert actual and actual.title == "Edited entry" and actual.password == EDIT_PASSWORD
            assert actual.notes == updated_notes
            assert original_notes.encode() not in old_activity.path.read_bytes()

            def decide(response):
                def check(dialog):
                    assert "permanently deleted" in dialog.get_property("secondary-text")
                    button = dialog.get_widget_for_response(Gtk.ResponseType.OK)
                    assert button.get_label() == "Delete"
                    assert button.get_style_context().has_class("destructive-action")
                    assert dialog.get_default_widget() == dialog.get_widget_for_response(Gtk.ResponseType.CANCEL)
                    dialog.response(response)
                return check

            def confirm_entry_deletion(dialog):
                button(dialog, "Delete…").clicked()
                GLib.timeout_add(25, finish_entry_deletion)

            def finish_entry_deletion():
                if app.dialog and isinstance(app.dialog, Gtk.MessageDialog):
                    decide(Gtk.ResponseType.OK)(app.dialog)
                    return GLib.SOURCE_REMOVE
                return GLib.SOURCE_CONTINUE

            drive_dialog(app._delete_group, decide(Gtk.ResponseType.CANCEL))
            assert app.selection == (vault, group)
            assert entry["id"] in app.entry_rows
            drive_dialog(lambda: open_entry(entry["id"]), confirm_entry_deletion)
            wait_for(lambda: not app.busy, "Deleting an entry timed out")
            assert not app.entry_rows
            drive_dialog(app._delete_group, decide(Gtk.ResponseType.OK))
            wait_for(lambda: not app.busy, "Deleting a group timed out")
            assert app.selection == (vault, "")
            saved = PyKeePass(target.database, password=UNLOCK, keyfile=str(target.key_file))
            assert saved.find_entries(uuid=UUID(entry["id"]), first=True) is None
            assert saved.find_groups(uuid=UUID(group), first=True) is None

        def check_entries_without_groups(vault):
            empty_path = private / "empty.kdbx"
            create_database(empty_path, password=UNLOCK, keyfile=str(target.key_file))
            empty_vault = app.workspace.add(replace(target, database=empty_path), UNLOCK, False)
            try:
                original_title = "Entry in a vault without groups"
                edited_title = "Edited ungrouped entry"

                def create_without_group(dialog):
                    vault_choice, group_choice = entry_locations(dialog)
                    assert vault_choice.set_active_id(empty_vault)
                    assert not group_choice.get_sensitive() and group_choice.get_active_id() is None
                    assert group_choice.get_active_text() == "No groups"
                    title = next(child for child in descendants(dialog) if child.get_name() == "entry-title")
                    title.set_text(original_title)
                    assert dialog.get_widget_for_response(Gtk.ResponseType.OK).get_sensitive()
                    dialog.response(Gtk.ResponseType.OK)

                select_tree(vault)
                drive_dialog(app.new_entry_item.activate, create_without_group)
                wait_for(lambda: not app.busy, "Creating an entry without groups timed out")
                assert app.selection == (empty_vault, "")
                session = app.workspace.owner_session(empty_vault)
                root, = (row["id"] for row in session.groups if row["parent"] is None)
                entry, = session.entries
                assert entry["title"] == original_title and entry["group"] == root
                group = app.workspace.put_group(empty_vault, root, name="A group fixture")
                app._refresh()

                def edit_without_group(dialog):
                    _, group_choice = entry_locations(dialog)
                    assert check_group_order(empty_vault, group_choice) == [(group, "A group fixture")]
                    assert group_choice.get_active_id() is None
                    title = next(child for child in descendants(dialog) if child.get_name() == "entry-title")
                    title.set_text(edited_title)
                    assert dialog.get_widget_for_response(Gtk.ResponseType.OK).get_sensitive()
                    dialog.response(Gtk.ResponseType.OK)

                drive_dialog(lambda: edit_entry(app, empty_vault, "", entry), edit_without_group, opens_async=True)
                wait_for(lambda: not app.busy, "Editing an ungrouped entry timed out")
                reopened = PyKeePass(empty_path, password=UNLOCK, keyfile=str(target.key_file))
                saved = reopened.find_entries(uuid=UUID(entry["id"]), first=True)
                assert saved is not None and saved.title == edited_title and saved.group.uuid == UUID(root)
            finally:
                app.workspace.remove(empty_vault)

        def activity_leaf(event_id):
            view = app.activity_view
            for root in view.table.get_model():
                rows = root.iterchildren() if root.model.iter_has_child(root.iter) else (root,)
                for row in rows:
                    if row[view.RECORD_ID] == str(event_id):
                        return row
            raise AssertionError(f"Expected Activity event {event_id}")

        def activity_group(events, outcome):
            view = app.activity_view
            summary = activity_leaf(events[0]["id"]).parent
            assert summary is not None
            outcome_column = view.TITLES.index("Outcome")
            assert summary[outcome_column] == outcome
            assert [row[view.RECORD_ID] for row in summary.iterchildren()] == [str(event["id"]) for event in events]
            return summary

        def check_agent_edits(first, second):
            def runner(profile, tool, arguments, *, error=False):
                message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": tool, "arguments": arguments}}
                args = [*NAMESPACE, "/usr/bin/env", "-i", "PATH=/usr/bin:/bin",
                        "KEEPASSXC_AGENT_MODEL=Synthetic test model",
                        "KEEPASSXC_AGENT_CHAT=Edit acceptance", str(runtime / "keeper-agent-runner"),
                        "--socket", str(endpoint), "--profile-dir", str(profiles / profile)]
                process = subprocess.run(args, input=(json.dumps(message) + "\n").encode(), cwd="/tmp",
                                         capture_output=True, check=True, timeout=12)
                captured.append((repr(args).encode(), process.stdout, process.stderr))
                result = json.loads(process.stdout)["result"]
                assert result["isError"] == error
                text = result["content"][0]["text"]
                return text if error else json.loads(text)

            def status(proposal, profile="beta"):
                return runner(profile, "edit_status", {"id": proposal["id"]})

            def propose(operation, vault=first, **fields):
                proposal = {"id": str(uuid4()), "operation": operation, "vault": vault, **fields}
                assert runner("beta", "request_edit", {"request": proposal}) == {
                    "id": proposal["id"], "status": "pending",
                }
                return proposal

            def decide(proposal, response, *, strings=(), password=None, before=None, allow=True,
                       resume=False, popup=False):
                app.access_button.clicked()
                view = app.access_view
                table = view.table
                row = next(row for row in table.get_model() if row[view.RECORD_ID].endswith("/" + proposal["id"]))
                assert row[view.TITLES.index("Identity")] == expected_identity("beta")
                assert row[view.TITLES.index("Model")] == f"{action_model} (reported)"
                assert row[view.TITLES.index("Chat")] == "Edit acceptance (reported)"
                path = row.path
                table.get_selection().select_path(path)

                def check(dialog):
                    title = OPERATION_LABELS[proposal["operation"]]
                    if proposal["operation"] == "replace_password" and proposal.get("password_source") == "owner":
                        title = "Save Password in Keeper"
                    assert dialog.get_title() == title
                    labels = [child.get_text() for child in descendants(dialog) if isinstance(child, Gtk.Label)]
                    assert all(any(expected.casefold() in label.casefold() for label in labels) for expected in strings)
                    if password:
                        entry = next(child for child in descendants(dialog) if child.get_name() == "edit-owner-password")
                        assert not entry.get_visibility() and not entry.get_text()
                        entry.set_text(password)
                    approve = dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT)
                    if resume:
                        assert not approve.get_sensitive()
                        assert "Agent access is paused" in labels
                        resume_control = button(dialog, "Resume Agent Access")
                        assert resume_control.get_visible() and resume_control.get_sensitive()
                        click_decision(resume_control)
                        assert not app.workspace.paused and status(proposal)["status"] == "pending"
                        assert not resume_control.get_parent().get_visible()
                    assert approve.get_sensitive() == allow
                    if before:
                        before()
                    if response in (Gtk.ResponseType.ACCEPT, Gtk.ResponseType.REJECT):
                        click_decision(dialog.get_widget_for_response(response))
                    else:
                        dialog.response(response)

                if popup:
                    drive_request_popup(check)
                else:
                    drive_dialog(lambda: table.row_activated(path, table.get_column(0)), check)
                wait_for(lambda: not app.busy, "Approved agent edit did not finish")

            def apply(proposal, **kwargs):
                decide(proposal, Gtk.ResponseType.ACCEPT, **kwargs)
                result = status(proposal)
                assert result["status"] == "applied", (result, app.message)
                return result.get("result")

            session = app.workspace.owner_session(first)
            root_group, = [item["id"] for item in session.groups if item["parent"] is None]
            app.set_agent_paused(True)
            first_group = propose("create_group", parent=root_group, fields={"name": "Reviewed group"})
            duplicate = runner("beta", "request_edit", {"request": first_group})
            assert duplicate["status"] == "pending"
            assert runner("expanded", "edit_status", {"id": first_group["id"]}, error=True)
            group = apply(first_group, strings=("Reviewed group", "Proposed"), resume=True, popup=True)
            assert runner("beta", "request_edit", {"request": first_group}) == {
                "id": first_group["id"], "status": "applied", "result": group,
            }
            assert sum(item["id"] == group for item in app.workspace.owner_session(first).groups) == 1

            rename = propose("rename_group", group=group, fields={"name": "Approved group"})
            apply(rename, strings=("Reviewed group", "Approved group"))
            new = propose("create_entry", parent=group, fields={"title": "Agent fixture", "username": "fixture"},
                          password_source="owner")
            entry = apply(new, strings=("Agent fixture", "Approved group"), password=REQUESTED_PASSWORD)
            assert invoke("beta", "entries", "list")["entries"] == fixture[2:]
            assert invoke("beta", "entries", "list", "--vault", first, expected=1)
            proposal = propose("update_entry", entry=entry, fields={"title": "Approved edit"})
            decide(proposal, Gtk.ResponseType.REJECT, strings=("Agent fixture", "Approved edit"))
            assert status(proposal) == {"id": proposal["id"], "status": "denied"}

            def external_change():
                app.workspace.put_entry(first, group, title="Saved by owner", entry=entry)

            stale = propose("update_entry", entry=entry, fields={"title": "Stale proposal"})
            decide(stale, Gtk.ResponseType.ACCEPT, strings=("Agent fixture", "Stale proposal"), before=external_change)
            assert status(stale)["status"] == "stale"
            apply(propose("update_entry", entry=entry, fields={"url": "https://fixture.example.test/approved"}),
                  strings=("https://fixture.example.test/approved", "Saved by owner"))

            second_group = apply(propose("create_group", parent=root_group, fields={"name": "Move destination"}))
            apply(propose("move_entry", entry=entry, parent=second_group), strings=("Move destination",))
            apply(propose("move_group", group=second_group, parent=group), strings=("Affected contents", "1 entry"))
            apply(propose("recycle_entry", entry=entry), strings=("Recycle bin", "Saved by owner"))
            apply(propose("recycle_group", group=group), strings=("Affected contents", "Recycle bin"))

            generated = propose("replace_password", vault=second, entry=first_entry, password_source="generate")
            apply(generated, strings=("Keeper will generate",))
            owner = PyKeePass(second_path, password=UNLOCK, keyfile=str(target.key_file))
            password = owner.find_entries(uuid=UUID(first_entry), first=True).password
            assert password and password != OTHER_PASSWORD
            assert use("expanded", second, expected=1)
            replaced = propose("replace_password", vault=second, entry=first_entry, password_source="owner")
            apply(replaced, password=REQUESTED_PASSWORD)
            owner.reload()
            assert owner.find_entries(uuid=UUID(first_entry), first=True).password == REQUESTED_PASSWORD

            private_state = [path.read_bytes() for path in private.glob("*.json")] + [old_activity.path.read_bytes()]
            assert all(password.encode() not in content and REQUESTED_PASSWORD.encode() not in content
                       for content in private_state)
            assert all(password.encode() not in data for call in captured for data in call)
            rows = old_activity.rows(chat="Edit acceptance")
            assert rows and all(row.get("token") for row in rows)
            outcomes = {row["outcome"].lower() for row in rows}
            assert "denied" in outcomes and "stale" in outcomes and {"applied", "succeeded"} & outcomes
            assert any(row["outcome"] == "Denied" and row["folder"] == "Approved group"
                       and row["entry_title"] == "Agent fixture" for row in rows)
            assert any(row["outcome"] == "Succeeded" and row["entry"] == entry
                       and row["folder"] == "Approved group" and row["entry_title"] == "Agent fixture"
                       for row in rows)
            app.activity_button.clicked()
            app.activity_view.filters["chat"].set_text("Edit acceptance")
            app.activity_view.refresh()
            view = app.activity_view
            assert len(view.table.get_model()) >= 3
            denied = [row for row in rows if f"Edit request {proposal['id']}" in (row["scope"] or "")]
            assert [row["outcome"] for row in denied] == ["Denied", "Pending review"]
            summary = activity_group(denied, "Denied")
            assert summary[view.TITLES.index("Vault")] == app.workspace.registrations[first].name
            assert summary[view.TITLES.index("Group")] == "Approved group"
            assert summary[view.TITLES.index("Key")] == "Agent fixture"
            create_events = [row for row in rows if f"Edit request {first_group['id']}" in (row["scope"] or "")]
            create_summary = activity_group(create_events, "Succeeded")
            assert create_summary[view.TITLES.index("Group")] == "Reviewed group"
            assert create_summary[view.TITLES.index("Key")] == "—"

            view.table.expand_row(summary.path, False)
            request = activity_leaf(denied[1]["id"])
            view.table.get_selection().select_path(request.path)

            def read_request(dialog):
                labels = {child.get_text() for child in descendants(dialog) if isinstance(child, Gtk.Label)}
                assert {denied[1]["action"], "Pending review"} <= labels
                assert "Denied" not in labels
                dialog.response(Gtk.ResponseType.CLOSE)

            drive_dialog(lambda: view.table.row_activated(request.path, view.table.get_column(0)), read_request)
            view.filters["outcome"].set_text("Pending review")
            view.refresh()
            summary = activity_group(denied, "Denied")
            assert view.table.row_expanded(summary.path)
            selected_model, selected = view.table.get_selection().get_selected()
            assert selected_model[selected][view.RECORD_ID] == str(denied[1]["id"])
            group_header = view.table.get_column(view.TITLES.index("Group"))
            for _ in range(3):
                group_header.clicked()
                summary = activity_group(denied, "Denied")
                assert view.table.row_expanded(summary.path)
            view.filters["outcome"].set_text("")
            view.filters["chat"].set_text("")

        def exercise():
            nonlocal result
            try:
                wait_for(lambda: app.tray_connected, "AppIndicator did not connect")
                assert app.window.get_visible()
                assert app.window.get_title() == "Keeper"
                app.minimize_button.clicked()
                assert not app.window.get_visible()
                assert app.broker.enabled and endpoint.exists()
                bus = app.get_dbus_connection()
                bus.call(
                    bus.get_unique_name(), "/org/ayatana/NotificationItem/keepassxc_agent_access",
                    "org.kde.StatusNotifierItem", "XAyatanaSecondaryActivate", GLib.Variant("(u)", (0,)),
                    None, Gio.DBusCallFlags.NONE, 1500, None, None, None,
                )
                wait_for(app.window.get_visible, "Tray middle-click did not restore Keeper")
                assert app.workspace.paused and app.grants.rows() == []
                assert app.indicator.get_icon() == "keeper-agent-access-paused"
                assert old_activity.rows(action="Legacy fixture")[0]["token"] is None
                first, = app.workspace.registrations
                assert app.workspace.registrations[first].item == original_item
                assert app.broker.enabled and endpoint.exists()
                subprocess.run(["setfacl", "-m", f"u:{uid}:rw", endpoint], check=True)
                assert "token is required" in invoke(None, "entries", "list", expected=1)
                wait_for(lambda: not app.busy and app.workspace.session(first), "Saved vault did not unlock at startup")
                assert app.vault_lock_button.get_accessible().get_name() == "Lock All Vaults"
                check_toolbar_button(app.add_vault_button)
                vault_lock_size = check_toolbar_button(app.vault_lock_button)
                def check_updates(dialog):
                    pages = next(widget for widget in descendants(dialog) if widget.get_name() == "keeper-settings-pages")
                    pages.set_visible_child_name("updates")
                    page = pages.get_visible_child()
                    check = button(page, "Check for Updates")
                    apply = button(page, "Apply Update")

                    def status(value):
                        return any(isinstance(label, Gtk.Label) and label.get_text() == value
                                   for label in descendants(page))

                    assert not apply.get_sensitive()
                    check.clicked()
                    wait_for(lambda: status("Keeper is up to date."), "Update status was unavailable.")
                    assert not apply.get_sensitive()
                    check.clicked()
                    wait_for(apply.get_sensitive, "Apply Update was unavailable.")
                    assert status("Update available · 222222222222")
                    apply.clicked()
                    wait_for(lambda: start.called, "The updater did not start.")
                    assert start.call_args.args[0] == newer
                    dialog.close()

                from keepassxc_agent_access.updates import Candidate
                current = Candidate(Path("/fixture"), "origin", "refs/heads/main", "1" * 40, "1" * 40)
                newer = replace(current, target="2" * 40)
                with patch("keepassxc_agent_access.workspace_app.check_for_update", side_effect=(current, newer)), \
                     patch("keepassxc_agent_access.workspace_app.start_update") as start:
                    drive_dialog(app.settings_button.clicked, check_updates)

                assert settings_switch("vaults", "start-unlocked")
                assert not settings_switch("vaults", "start-unlocked", False)
                assert not old_access.read().start_unlocked
                assert settings_switch("vaults", "start-unlocked", True)
                app.vault_lock_button.clicked()
                assert not app.workspace.session(first)
                assert app.vault_lock_button.get_accessible().get_name() == "Unlock All Vaults"
                assert check_toolbar_button(app.vault_lock_button) == vault_lock_size
                root_path = select_tree(first)
                assert not app.tree.row_expanded(root_path)
                locked_actions = context_menu(app.tree)
                assert locked_actions.count("Unlock") == 1 and "Relink Vault…" in locked_actions
                assert "Lock Vault" not in locked_actions and "New Entry…" not in locked_actions
                assert "Enter password…" not in locked_actions
                assert [button.get_label() for button in app.vault_buttons.values() if button.get_visible()] == ["Unlock"]
                app.vault_lock_button.clicked()
                wait_for(lambda: not app.busy and app.workspace.session(first), "Unlock all did not use the saved password")

                app.vault_buttons["lock"].clicked()
                keyring.remember(original_item, "synthetic-stale-vault-password")

                def replace_password(dialog):
                    assert dialog.get_title() == f"Unlock {app.workspace.registrations[first].name}"
                    labels = [widget.get_text() for widget in descendants(dialog) if isinstance(widget, Gtk.Label)]
                    assert any("password" in label.lower() for label in labels)
                    remember, = (widget for widget in descendants(dialog) if isinstance(widget, Gtk.CheckButton))
                    assert remember.get_label() == "Remember in the OS Keyring"
                    remember.set_active(True)
                    field, = (widget for widget in descendants(dialog) if isinstance(widget, Gtk.Entry))
                    assert not field.get_text() and not field.get_visibility()
                    field.set_text(UNLOCK)
                    dialog.response(Gtk.ResponseType.OK)

                drive_dialog(app.vault_buttons["unlock"].clicked, replace_password, opens_async=True)
                wait_for(lambda: not app.busy and app.workspace.session(first), "Replacement password did not unlock")
                replacement_item = app.workspace.registrations[first].item
                assert replacement_item and replacement_item != original_item
                assert keyring.retrieve(replacement_item) == UNLOCK
                app.vault_buttons["lock"].clicked()
                app.vault_buttons["unlock"].clicked()
                wait_for(lambda: not app.busy and app.workspace.session(first), "Replacement keyring item did not unlock")
                assert app.tree.row_expanded(root_path)
                wait_for(lambda: app.new_item.get_allocated_height() > 1, "New button was not laid out")
                assert app.new_item.get_allocated_height() == app.vault_buttons["lock"].get_allocated_height()
                new_menu = app.new_item.get_popup()
                assert [item.get_label() for item in new_menu.get_children() if item.get_visible()] == ["Group…", "Entry…"]
                assert app.workspace.registrations[first].bindings[0].action == imported
                assert {row[ENTRY_ID_COLUMN]: row[ENTRY_FOLDER_COLUMN] for row in app.entries.get_model()} == {
                    first_entry: "Root", direct_entry: "Harbor Lab", nested_entry: "Harbor Lab / Field Notes",
                }
                assert [column.get_title() for column in app.entries.get_columns() if column.get_visible()] == [
                    "Created", "Modified", "Folder", "Title", "Username", "URL",
                ]
                timestamp = re.compile(r"\d{2}:\d{2} · \d{2}-\d{2}-\d{2}")
                assert all(timestamp.fullmatch(row[index]) for row in app.entries.get_model() for index in (3, 4))
                check_date_widths(app.entries, app.entries.get_model()[0], "Created", "Modified")
                app.entry_search.set_text("harbor lab / FIELD")
                assert [row[ENTRY_ID_COLUMN] for row in app.entries.get_model()] == [nested_entry]
                app.entry_search.set_text("")
                assert "Copy Root Group Reference" in context_menu(app.tree)
                assert not any(widget.get_tooltip_text() == "Vault options" for widget in descendants(app.window))
                entry_table = app.entries
                first_path = next(row.path for row in entry_table.get_model() if row[ENTRY_ID_COLUMN] == first_entry)
                nested_path = next(row.path for row in entry_table.get_model() if row[ENTRY_ID_COLUMN] == nested_entry)
                entry_table.get_selection().select_path(first_path)
                clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
                with patch("keepassxc_agent_access.workspace_clipboard.PASSWORD_CLIPBOARD_TIMEOUT_MS", 1000):
                    assert context_menu(entry_table, nested_path, activate="Copy Password") == [
                        "View Entry Details…", "Edit Entry…", "Copy Password", "Copy Entry Reference", "Delete…",
                    ]
                    wait_for(lambda: not app.busy, "Password copy did not finish")
                assert isinstance(clipboard.get_owner(), Gtk.TextBuffer)
                assert clipboard.wait_for_text() == COPY_PASSWORD
                wait_for(lambda: clipboard.wait_for_text() is None, "Copied password did not expire")
                entry_model, selected = entry_table.get_selection().get_selected()
                assert entry_model[selected][ENTRY_ID_COLUMN] == nested_entry

                select_tree(first, app.entry_rows[nested_entry]["group"])
                copy_path, = (row.path for row in entry_table.get_model() if row[ENTRY_ID_COLUMN] == nested_entry)
                context_menu(entry_table, copy_path, activate="Copy Password")
                wait_for(lambda: not app.busy, "Copy Password in the group did not finish")
                assert clipboard.wait_for_text() == COPY_PASSWORD
                clipboard.set_text("newer clipboard content", -1)
                app.password_clipboard.clear()
                assert clipboard.wait_for_text() == "newer clipboard content"
                context_menu(entry_table, copy_path, activate="Copy Password")
                wait_for(lambda: not app.busy, "Second Copy Password did not finish")
                app.vault_buttons["lock"].clicked()
                assert clipboard.wait_for_text() is None
                select_tree(first)
                app.vault_buttons["unlock"].clicked()
                wait_for(lambda: not app.busy and app.workspace.session(first), "Vault did not reopen")

                title_column = next(column for column in entry_table.get_columns() if column.get_title() == "Title")
                original = [tuple(row) for row in entry_table.get_model()]
                for direction in (Gtk.SortType.ASCENDING, Gtk.SortType.DESCENDING):
                    title_column.clicked()
                    assert title_column.get_sort_indicator() and title_column.get_sort_order() == direction
                    expected = sorted(original, key=lambda row: row[0].casefold(), reverse=direction == Gtk.SortType.DESCENDING)
                    assert [tuple(row) for row in entry_table.get_model()] == expected
                title_column.clicked()
                assert not title_column.get_sort_indicator()
                assert [tuple(row) for row in entry_table.get_model()] == original

                def setup_secondary(dialog):
                    assert dialog.database.set_filename(str(second_path))
                    dialog.key_file_enabled.set_active(True)
                    assert dialog.key_file.set_filename(str(target.key_file))
                    dialog.password.set_text(UNLOCK)
                    dialog.remember.set_active(True)
                    dialog.response(Gtk.ResponseType.OK)

                drive_dialog(app.add_vault_button.clicked, setup_secondary)
                wait_for(lambda: not app.busy, "Second vault setup timed out")
                second, = set(app.workspace.registrations) - {first}
                assert app.workspace.session(second)
                assert app.workspace.session(second).worker.identity == app.workspace.session(first).worker.identity
                assert not app.workspace.registrations[second].bindings

                def edit_action(dialog):
                    assert dialog.get_title() == "Credential Action"
                    fields = [child for child in dialog.get_content_area().get_children() if isinstance(child, Gtk.Entry)]
                    for field, value in zip(fields, ("check", "Second vault action", url + "/second")):
                        field.set_text(value)
                    dialog.response(Gtk.ResponseType.OK)

                def configure_action(dialog):
                    dialog.response(Gtk.ResponseType.APPLY)
                    GLib.timeout_add(25, lambda: follow_up())

                def follow_up():
                    if app.dialog and app.dialog.get_title() == "Credential Action":
                        edit_action(app.dialog)
                        GLib.timeout_add(25, close_details)
                        return GLib.SOURCE_REMOVE
                    return GLib.SOURCE_CONTINUE

                def close_details():
                    if app.dialog and app.dialog.get_title() == fixture[0]["title"]:
                        app.dialog.response(Gtk.ResponseType.CLOSE)
                        return GLib.SOURCE_REMOVE
                    return GLib.SOURCE_CONTINUE

                select_tree(second)
                drive_dialog(lambda: open_entry(first_entry), configure_action)
                assert app.workspace.registrations[second].binding(first_entry, "check").action.url.endswith("/second")
                first_groups = app.workspace.session(first).groups
                outer = next(row["id"] for row in first_groups if row["name"] == "Harbor Lab")
                inner = next(row["id"] for row in first_groups if row["name"] == "Field Notes")
                vault_positions = browse_positions(first)
                group_positions = browse_positions(first, outer)
                assert vault_positions == group_positions, (vault_positions, group_positions)
                assert browse_positions(first, inner) == vault_positions
                group_layout = workspace_positions()
                for view_button in (app.activity_button, app.access_button):
                    view_button.clicked()
                    layout = workspace_positions()
                    assert layout == group_layout, (group_layout, layout)
                select_tree(first, outer)
                assert context_menu(app.tree) == [
                    "New Entry…", "Edit Group…", "Copy Group Reference", "Delete…",
                ]
                assert [item.get_label() for item in new_menu.get_children() if item.get_visible()] == ["Group…", "Entry…"]
                assert [row[ENTRY_ID_COLUMN] for row in app.entries.get_model()] == [direct_entry]
                assert [column.get_title() for column in app.entries.get_columns() if column.get_visible()] == [
                    "Created", "Modified", "Title", "Username", "URL",
                ]
                selected_path = select_tree(first, inner)
                assert [row[ENTRY_ID_COLUMN] for row in app.entries.get_model()] == [nested_entry]
                assert app.browse_title.get_text() == "Field Notes"
                app.entry_search.set_text("NO MATCH")
                assert not list(app.entries.get_model())
                assert app.empty_entries.get_text() == "No entries match this filter."
                app.entry_search.set_text(duplicate_title.upper())
                assert [row[ENTRY_ID_COLUMN] for row in app.entries.get_model()] == [nested_entry]
                assert app.entry_count.get_text() == "1 entry"
                app.activity_button.clicked()
                assert app.stack.get_visible_child_name() == "activity"
                assert app.tree.get_selection().path_is_selected(selected_path)
                parent_path = selected_path.copy()
                assert parent_path.up() and app.tree.row_expanded(parent_path)
                select_tree(first, inner)
                assert app.stack.get_visible_child_name() == "browse"
                assert app.entry_search.get_text() == duplicate_title.upper()
                select_tree(first, outer)
                assert not app.entry_search.get_text()

                alpha = [{"vault": first, "entry": first_entry, "metadata": True, "username": True, "action": "check"}]
                beta = [{"label": duplicate_title, "metadata": True}]
                expanded = [{"vault": first, "entry": first_entry, "action": "check"},
                            {"vault": second, "entry": first_entry, "action": "check", "metadata": True, "url": True},
                            {"vault": second, "entry": nested_entry, "metadata": True}]
                assert app.workspace.paused
                app.set_agent_paused(False)
                assert settings_switch("auto-approve", "request-popups", label="Request Pop-Ups")
                app.minimize_button.clicked()
                assert not app.window.get_visible()
                assert enroll("alpha", alpha) == enroll("alpha", alpha) == {"status": "pending"}
                verify_isolation(target, old_access.path, app.workspace.path, app.grants.path)
                approve("alpha", popup=True)
                app.set_agent_paused(True)
                assert enroll("review-paused", alpha) == {"status": "pending"}
                deny("review-paused", popup=True)
                assert app.workspace.paused
                app._present()
                assert not settings_switch("auto-approve", "request-popups", False)
                config = private / "desktop-notifications.json"
                assert json.loads(config.read_text()) == {"desktop_notifications": False}
                assert enroll("beta", beta) == {"status": "pending"}
                duplicate_identity = enroll("review", beta, expected=1, identity="  aGENT beta  ")
                assert "identity" in duplicate_identity.casefold()
                assert enroll("review", beta) == {"status": "pending"}
                assert len(app.grants.rows()) == 3
                assert "unavailable for this token" in invoke("beta", "vaults", "list", expected=1)
                settled = []
                GLib.timeout_add(1100, lambda: settled.append(app.dialog is None))
                wait_for(lambda: settled, "Keeper did not poll for pending requests")
                assert settled == [True]
                app.access_button.clicked()
                access_view = app.access_view
                access_table = access_view.table
                assert [column.get_title() for column in access_table.get_columns()] == [
                    "Requested", "Last Used", "Identity", "Model", "Project", "Chat", "Status",
                ]
                assert [row[access_view.STATUS] for row in access_table.get_model()] == ["Pending", "Pending", "Active"]
                identity_column = access_view.TITLES.index("Identity")
                model_column, chat_column = (access_view.TITLES.index(name) for name in ("Model", "Chat"))
                assert token_ids["beta"] != token_ids["review"]
                for profile in ("alpha", "beta", "review"):
                    token_row = access_root(profile)
                    assert token_row[identity_column] == expected_identity(profile)
                    assert token_row[model_column] == f"{enrollment_model} (reported)"
                    assert token_row[chat_column] == f"{enrollment_chat} (reported)"
                assert access_root("beta")[identity_column] != access_root("review")[identity_column]
                assert isinstance(access_table.get_model(), Gtk.TreeStore)
                assert access_table.get_expander_column() == access_table.get_column(0)
                access_model = access_table.get_model()
                assert not access_model.iter_has_child(access_root("beta").iter)
                assert access_model.iter_has_child(access_root("alpha").iter)
                assert all(timestamp.fullmatch(row[0]) and row[1] == "—" for row in access_table.get_model())
                assert token_context_menu("beta") == ["Review Request…"]
                assert token_context_menu("alpha") == ["View Permissions…", "Disable Token", "Remove Token…"]
                assert not app.review_popups.enabled
                deny("review")
                assert app.workspace.paused
                assert "unavailable for this token" in invoke("review", "vaults", "list", expected=1)
                assert settings_switch("auto-approve", "request-popups", True)
                assert json.loads(config.read_text()) == {"desktop_notifications": True}
                assert "paused" in invoke("alpha", "vaults", "list", expected=1)
                approve("beta", second, popup=True, resume=True)
                assert not app.workspace.paused
                assert app.workspace.session(first) and app.workspace.session(second)
                assert enroll("review-live", alpha) == {"status": "pending"}
                deny("review-live", popup=True)
                assert not app.workspace.paused

                assert invoke("alpha", "access", "status") == {"status": "active"}
                assert [row["id"] for row in invoke("alpha", "vaults", "list")["vaults"]] == [first]
                assert [row["id"] for row in invoke("beta", "vaults", "list")["vaults"]] == [second]
                assert invoke("alpha", "entries", "list")["entries"] == fixture[:1]
                assert invoke("beta", "entries", "list", "--vault", second)["entries"] == fixture[2:]
                assert invoke("alpha", "entries", "list", "--field", "username", "--field", "url")["entries"] == [
                    {**fixture[0], "username": USERNAME},
                ]
                assert invoke("beta", "entries", "list", "--field", "url")["entries"] == fixture[2:]
                denied = invoke("alpha", "entries", "list", "--vault", second, expected=1)
                assert denied == invoke("alpha", "entries", "list", "--vault", str(UUID(int=30)), expected=1)
                assert invoke("beta", "entries", "list", "--vault", first, expected=1) == denied
                assert use("alpha", second, expected=1) == denied
                assert use("beta", second, expected=1) == denied
                assert use("alpha", first, direct_entry, expected=1) == denied
                assert not calls
                assert use("alpha", first) == {"outcome": "succeeded", "http_status": 200}
                assert calls == [("/first", AUTHORIZATION)]
                assert enroll("expanded", expanded) == {"status": "pending"}
                approve("expanded")
                assert len(invoke("expanded", "vaults", "list")["vaults"]) == 2
                assert "Choose a vault" in invoke("expanded", "entries", "list", expected=1)
                assert invoke("expanded", "entries", "list", "--vault", first) == {"entries": []}
                listed = invoke("expanded", "entries", "list", "--vault", second)["entries"]
                assert {row["id"]: row for row in listed} == {first_entry: fixture[0], nested_entry: fixture[2]}
                with_fields = invoke("expanded", "entries", "list", "--vault", second,
                                     "--field", "username", "--field", "url")["entries"]
                assert {row["id"]: row for row in with_fields} == {
                    first_entry: {**fixture[0], "url": STORED_URL}, nested_entry: fixture[2],
                }
                app.access_view.refresh()
                expanded_row = access_root("expanded")
                assert expanded_row[model_column] == f"{enrollment_model} (reported)"
                assert expanded_row[chat_column] == f"{enrollment_chat} (reported)"
                assert timestamp.fullmatch(expanded_row[1])
                check_date_widths(access_table, expanded_row, "Requested", "Last Used")
                check_token_scope(first, second)
                assert STORED_URL.encode() not in old_activity.path.read_bytes()
                assert USERNAME.encode() not in old_activity.path.read_bytes()
                assert use("expanded", second, expected=1) == {"outcome": "failed", "http_status": 401}
                other_header = "Basic " + b64encode(f"{USERNAME}:{OTHER_PASSWORD}".encode()).decode("ascii")
                assert calls[-1] == ("/second", other_header)
                select_tree(first)

                def edit_type(dialog):
                    table = next(child for child in descendants(dialog) if isinstance(child, Gtk.TreeView))
                    table.get_selection().select_path(Gtk.TreePath.new_from_string("0"))
                    dialog.response(Gtk.ResponseType.ACCEPT)
                    GLib.timeout_add(25, choose_bearer)

                def choose_bearer():
                    if not app.dialog or app.dialog.get_title() != "Credential Action":
                        return GLib.SOURCE_CONTINUE
                    chooser = next(child for child in descendants(app.dialog) if child.get_name() == "action-kind")
                    chooser.set_active_id(ActionType.BEARER.value)
                    app.dialog.response(Gtk.ResponseType.OK)
                    GLib.timeout_add(25, close_details)
                    return GLib.SOURCE_REMOVE

                drive_dialog(lambda: open_entry(first_entry), edit_type)
                rebound = app.workspace.registrations[first].binding(first_entry, "check")
                assert rebound.action.kind is ActionType.BEARER and rebound.action.url == imported.url
                assert use("alpha", first, expected=1) == denied
                bearer = [{"vault": first, "entry": first_entry, "action": "check"}]
                assert enroll("bearer", bearer) == {"status": "pending"}
                approve("bearer")
                assert use("bearer", first) == {"outcome": "succeeded", "http_status": 200}
                assert calls[-1] == ("/first", BEARER_AUTHORIZATION)

                def configure_browser(dialog):
                    widgets = {child.get_name(): child for child in descendants(dialog)}
                    widgets["action-kind"].set_active_id(ActionType.BROWSER.value)
                    fields = {
                        "action-destination": url + "/sign-in",
                        "browser-submit_url": url + "/session",
                        "browser-form_id": "sign-in",
                        "browser-username_field": "user",
                        "browser-password_field": "password",
                        "browser-success_id": "account-home",
                        "browser-success_url": url + "/account",
                    }
                    for name, value in fields.items():
                        field = widgets[name]
                        assert field.get_visible()
                        field.set_text(value)
                    assert not widgets["action-method"].is_visible()
                    dialog.response(Gtk.ResponseType.OK)

                drive_dialog(lambda: edit_binding(app, first, first_entry, None), configure_browser)
                browser = app.workspace.registrations[first].binding(first_entry, "health-check")
                assert browser.action.kind is ActionType.BROWSER
                assert browser.action.browser.success_id == "account-home"
                assert browser.action.browser.submit_url == url + "/session"
                app.workspace.remove_binding(first, first_entry, "health-check")

                app.workspace.save_binding(first, replace(imported, url=url + "/changed"), "check")
                assert use("alpha", first, expected=1) == denied
                assert use("bearer", first, expected=1) == denied
                assert all(path != "/changed" for path, _ in calls)
                assert "unavailable for this token" in enroll("alpha", beta, expected=1)

                select_tree(first)
                app.vault_buttons["lock"].clicked()
                assert not app.workspace.session(first) and app.workspace.session(second)
                assert not app.entry_scroll.get_visible() and len(app.entries.get_model()) == 0
                assert invoke("alpha", "entries", "list", expected=1) == denied
                assert invoke("beta", "entries", "list")["entries"] == fixture[2:]
                check_token_scope(first, second, first_locked=True)
                select_tree(second)

                def check_locked_destination(dialog):
                    vault_choice, group_choice = entry_locations(dialog)
                    unlock = next(child for child in descendants(dialog) if child.get_name() == "entry-unlock-vault")
                    assert len(vault_choice.get_model()) == 2 and vault_choice.get_active_id() == second
                    second_options = check_group_order(second, group_choice)
                    assert group_choice.get_active_id() == second_options[0][0] and not unlock.get_visible()
                    assert vault_choice.set_active_id(first)
                    assert vault_choice.get_active_text().endswith(" · Locked")
                    assert not group_choice.get_sensitive()
                    assert group_choice.get_active_id() is None
                    assert group_choice.get_active_text() == "Vault is locked"
                    assert unlock.get_visible() and unlock.get_label() == "Unlock Vault"
                    title = next(child for child in descendants(dialog) if child.get_name() == "entry-title")
                    title.set_text("Unsaved entry fixture")
                    password = next(child for child in descendants(dialog) if child.get_name() == "entry-password")
                    password.set_text(EDIT_PASSWORD)
                    save = dialog.get_widget_for_response(Gtk.ResponseType.OK)
                    assert not save.get_sensitive()
                    assert vault_choice.set_active_id(second)
                    assert group_choice.get_sensitive() and group_choice.get_active_id() == second_options[0][0]
                    assert save.get_sensitive() and not unlock.get_visible()
                    assert vault_choice.set_active_id(first)
                    assert not save.get_sensitive() and unlock.get_visible()

                    unlock.clicked()
                    wait_for(lambda: not app.busy and app.workspace.session(first),
                             "Vault did not unlock from the entry form")
                    assert app.dialog is dialog and dialog.get_visible()
                    assert vault_choice.get_active_id() == first
                    assert vault_choice.get_active_text() == app.workspace.registrations[first].name
                    first_options = check_group_order(first, group_choice)
                    assert group_choice.get_sensitive() and group_choice.get_active_id() == first_options[0][0]
                    assert save.get_sensitive() and not unlock.get_visible()
                    assert title.get_text() == "Unsaved entry fixture" and password.get_text() == EDIT_PASSWORD
                    assert app.workspace.session(second)
                    dialog.response(Gtk.ResponseType.CANCEL)

                drive_dialog(app.new_entry_item.activate, check_locked_destination)

                manual_path = private / "manual.kdbx"
                shutil.copyfile(second_path, manual_path)
                manual = app.workspace.add(replace(target, database=manual_path), UNLOCK, False)
                app.workspace.lock(manual)
                app._refresh()
                select_tree(manual)
                assert context_menu(app.tree).count("Unlock") == 1
                assert [button.get_label() for button in app.vault_buttons.values() if button.get_visible()] == ["Unlock"]

                def check_unsaved_prompt(dialog):
                    assert dialog.get_title() == "Unlock manual"
                    remember, = (widget for widget in descendants(dialog) if isinstance(widget, Gtk.CheckButton))
                    assert remember.get_label() == "Remember in the OS Keyring" and not remember.get_active()
                    dialog.response(Gtk.ResponseType.CANCEL)

                drive_dialog(app.vault_buttons["unlock"].clicked, check_unsaved_prompt)
                assert not app.workspace.session(manual)
                select_tree(second)

                def check_manual_unlock(dialog):
                    vault_choice, group_choice = entry_locations(dialog)
                    assert vault_choice.set_active_id(manual)
                    unlock = next(child for child in descendants(dialog) if child.get_name() == "entry-unlock-vault")
                    title = next(child for child in descendants(dialog) if child.get_name() == "entry-title")
                    title.set_text("Manual unlock draft")
                    save = dialog.get_widget_for_response(Gtk.ResponseType.OK)

                    error = next(child for child in descendants(dialog) if child.get_name() == "entry-unlock-error")

                    def answer_prompt(prompt, response, password=UNLOCK):
                        assert prompt is not dialog and prompt.get_title() == "Unlock manual"
                        assert prompt.get_transient_for() is dialog
                        if response == Gtk.ResponseType.OK:
                            field, = (child for child in descendants(prompt) if isinstance(child, Gtk.Entry))
                            field.set_text(password)
                        prompt.response(response)

                    drive_dialog(unlock.clicked, lambda prompt: answer_prompt(prompt, Gtk.ResponseType.CANCEL))
                    assert app.dialog is dialog and not app.workspace.session(manual)
                    assert unlock.get_visible() and not save.get_sensitive() and not error.get_visible()
                    assert title.get_text() == "Manual unlock draft"
                    drive_dialog(unlock.clicked, lambda prompt: answer_prompt(
                        prompt, Gtk.ResponseType.OK, "synthetic-wrong-vault-password",
                    ))
                    wait_for(lambda: not app.busy and error.get_visible(), "Unlock failure was not shown")
                    assert app.dialog is dialog and not app.workspace.session(manual)
                    assert unlock.get_sensitive() and not save.get_sensitive()
                    assert title.get_text() == "Manual unlock draft"
                    drive_dialog(unlock.clicked, lambda prompt: answer_prompt(prompt, Gtk.ResponseType.OK))
                    wait_for(lambda: not app.busy and app.workspace.session(manual), "Manual unlock timed out")
                    assert app.dialog is dialog and vault_choice.get_active_id() == manual
                    options = check_group_order(manual, group_choice)
                    assert group_choice.get_active_id() == options[0][0] and save.get_sensitive()
                    assert not error.get_visible() and not unlock.get_visible()
                    assert title.get_text() == "Manual unlock draft"
                    assert not app.workspace.registrations[manual].item
                    dialog.response(Gtk.ResponseType.CANCEL)

                try:
                    drive_dialog(app.new_entry_item.activate, check_manual_unlock)
                finally:
                    app.workspace.remove(manual)
                select_tree(first)
                token_context_menu("alpha", activate="Disable Token")
                assert invoke("alpha", "access", "status") == {"status": "disabled"}
                assert invoke("alpha", "entries", "list", expected=1) == denied
                assert invoke("beta", "entries", "list")["entries"] == fixture[2:]
                assert token_context_menu("alpha") == ["View Permissions…", "Re-enable Token", "Remove Token…"]
                disabled = access_root("alpha")
                assert disabled[app.access_view.STATUS] == "Disabled"
                access_table.expand_row(disabled.path, False)
                assert access_table.row_expanded(disabled.path)
                scope, = disabled.iterchildren()
                assert not scope.model.iter_has_child(scope.iter)
                assert scope[identity_column] == f"{app.workspace.registrations[first].name} > — > {fixture[0]['title']}"
                permissions = scope[access_view.TITLES.index("Project")]
                assert "Entry Metadata" in permissions and "Username" in permissions
                drive_dialog(access_row("alpha"), lambda dialog: dialog.response(Gtk.ResponseType.APPLY))
                assert invoke("alpha", "entries", "list")["entries"] == fixture[:1]
                alpha_record = next(row for row in app.grants.rows() if row.identity == "Agent alpha")
                assert alpha_record.last_used and alpha_record.last_used >= alpha_record.requested
                drive_dialog(lambda: token_context_menu("alpha", activate="Remove Token…"),
                             lambda dialog: dialog.response(Gtk.ResponseType.OK))
                assert enroll("alpha", alpha, expected=1) == denied
                assert invoke("alpha", "entries", "list", expected=1) == denied
                assert invoke("beta", "entries", "list")["entries"] == fixture[2:]

                check_editors(first, second)
                check_entries_without_groups(first)
                assert invoke("beta", "entries", "list")["entries"] == fixture[2:]
                app.activity_button.clicked()
                view = app.activity_view
                table = view.table
                assert [column.get_title() for column in table.get_columns()] == [
                    "Time", "Action", "Identity", "Vault", "Group", "Key", "Outcome",
                ]
                activity_identity = view.TITLES.index("Identity")
                assert isinstance(table.get_model(), Gtk.TreeStore)
                assert table.get_expander_column() == table.get_column(0)
                app.activity_view.filters["identity"].set_text("Agent beta")
                app.activity_view.refresh()
                assert len(table.get_model()) > 0
                check_date_widths(table, table.get_model()[0], "Time")
                allowed = {str(row["id"]) for row in old_activity.rows(agent="Agent beta")
                           if row["token"] == token_ids["beta"]}
                for root in table.get_model():
                    assert timestamp.fullmatch(root[0])
                    assert root[view.RECORD_ID] in allowed and root[activity_identity] == expected_identity("beta")
                    assert all(timestamp.fullmatch(row[0]) and row[view.RECORD_ID] in allowed
                               and row[activity_identity] == expected_identity("beta") for row in root.iterchildren())
                access = next(row for row in old_activity.rows(vault="second", action="Use password")
                              if row["entry"] == first_entry and row["entry_title"])
                assert access["folder"] == "Root" and access["entry_title"] == fixture[0]["title"]
                token_event = old_activity.rows(action="Remove token")[0]
                assert token_event["token"] == alpha_record.id and token_event["entry_title"] == fixture[0]["title"]
                legacy, = old_activity.rows(action="Legacy fixture")
                assert legacy["vault"] is None and legacy["folder"] is None and legacy["entry_title"] is None

                app.activity_view.filters["identity"].set_text("")
                app.activity_view.refresh()
                assert activity_leaf(legacy["id"])[activity_identity] == "—"
                token_events = [row for row in old_activity.rows(agent="Agent alpha")
                                if row["action"] in ("Request token", "Approve token", "Disable token",
                                                     "Re-enable token", "Remove token")]
                assert [row["action"] for row in token_events] == [
                    "Remove token", "Re-enable token", "Disable token", "Approve token", "Request token",
                ]
                token_summary = activity_group(token_events, "Removed")
                assert token_summary[activity_identity] == expected_identity("alpha")
                assert all(row[activity_identity] == expected_identity("alpha") for row in token_summary.iterchildren())
                assert not table.row_expanded(token_summary.path)
                def read_parent(dialog):
                    labels = {label.get_text() for label in descendants(dialog) if isinstance(label, Gtk.Label)}
                    assert {"Remove token", "Audit Note", "Check approved services"} <= labels
                    assert "No note provided." not in labels
                    dialog.response(Gtk.ResponseType.CLOSE)

                drive_dialog(lambda: table.row_activated(token_summary.path, table.get_column(0)), read_parent)
                assert not table.row_expanded(token_summary.path)
                assert table.expand_row(token_summary.path, False)
                pending = activity_leaf(token_events[-1]["id"])
                for child in token_summary.iterchildren():
                    assert not child.model.iter_has_child(child.iter)
                    check_child_indentation(table, token_summary, child)
                action_column = table.get_column(view.ACTION)
                _, action_icon, action_text = action_column.get_cells()
                action_column.cell_set_cell_data(pending.model, pending.iter, False, False)
                assert action_icon.get_property("icon-name") == "dialog-question-symbolic"
                assert action_text.get_property("text") == "Request token"
                wait_for_paint(table)
                outcome_column = table.get_column(view.OUTCOME)
                outcome_indent, outcome_icon, outcome_text = outcome_column.get_cells()
                disabled_event = activity_leaf(token_events[2]["id"])
                for event, label, icon in (
                    (token_summary, "Removed", "user-trash-symbolic"),
                    (disabled_event, "Disabled", "action-unavailable-symbolic"),
                ):
                    outcome_column.cell_set_cell_data(event.model, event.iter, False, False)
                    assert outcome_icon.get_property("icon-name") == icon
                    assert outcome_text.get_property("text") == label
                outcome_column.cell_set_cell_data(pending.model, pending.iter, False, False)
                assert outcome_icon.get_property("icon-name") == "appointment-soon-symbolic"
                assert outcome_text.get_property("text") == "Pending approval"
                required = sum(cell.get_preferred_width(table)[1]
                               for cell in (outcome_indent, outcome_icon, outcome_text))
                assert outcome_column.get_width() >= required, (outcome_column.get_width(), required)
                assert table.collapse_row(token_summary.path)
                assert not table.row_expanded(token_summary.path)

                row = activity_leaf(access["id"])
                action_column.cell_set_cell_data(row.model, row.iter, False, False)
                assert action_icon.get_property("icon-name") == "dialog-password-symbolic"
                assert row[activity_identity] == expected_identity("expanded")
                assert row[view.TITLES.index("Vault")] == "second"
                assert row[view.TITLES.index("Group")] == "Root"
                assert row[view.TITLES.index("Key")] == fixture[0]["title"]
                path = row.path
                table.expand_to_path(path)
                table.get_selection().select_path(path)
                assert context_menu(table) == ["View Details…"]

                def read_activity(dialog):
                    wait_for_paint(dialog)
                    window = app.window.get_window()
                    workarea = window.get_display().get_monitor_at_window(window).get_workarea()
                    assert tuple(dialog.get_size()) == (min(860, workarea.width - 48),
                                                       min(740, workarea.height - 80))
                    labels = [child.get_text() for child in descendants(dialog) if isinstance(child, Gtk.Label)]
                    assert {"Resource", "Vault", "Group", "Key", "second", "Root", fixture[0]["title"]} <= set(labels)
                    assert {f"{action_model} (reported)", f"{action_chat} (reported)"} <= set(labels)
                    assert "No note provided." in labels
                    assert labels.index("Execution") < labels.index("Audit Note")
                    expander = next(child for child in descendants(dialog) if isinstance(child, Gtk.Expander))
                    assert expander.get_label() == "Technical Details" and not expander.get_expanded()
                    dialog.response(Gtk.ResponseType.CLOSE)

                drive_dialog(lambda: table.row_activated(path, table.get_column(0)), read_activity)
                check_agent_edits(first, second)
                assert app.usage_button.get_accessible().get_name() == "Auto Approve: On"
                usage_size = check_toolbar_button(app.usage_button)
                assert app.usage_button.get_style_context().has_class("keeper-usage-allow")
                assert app.usage_button.get_active()
                assert not settings_switch("auto-approve", "auto-approve-usage", False)
                assert not app.usage_button.get_active()
                assert app.usage_button.get_accessible().get_name() == "Auto Approve: Off"
                assert check_toolbar_button(app.usage_button) == usage_size
                assert app.usage_button.get_style_context().has_class("keeper-usage-review")
                assert old_access.read().review_usage

                named_group = next(row["group"] for row in app.workspace.session(second).entries
                                   if row["id"] == nested_entry)
                edits = [{"vault": second, "entry": nested_entry, "edits": ["update_entry"]},
                         {"vault": second, "group": named_group, "edits": ["create_entry"]}]
                assert enroll("scoped-editor", edits) == {"status": "pending"}
                approve("scoped-editor")

                def review_usage(dialog):
                    assert dialog.get_title() == "Review Agent Usage"
                    labels = {child.get_text() for child in descendants(dialog) if isinstance(child, Gtk.Label)}
                    assert {"Agent beta", "List entries", "Approval applies to this operation only."} <= labels
                    click_decision(dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT))

                assert settings_switch("auto-approve", "list_entries")
                assert not settings_switch("auto-approve", "list_entries", False, label="Groups and Entries - Read")
                app.usage_button.set_active(True)
                assert not old_access.read().review_usage
                assert old_access.read().review_actions == {"list_entries"}
                with ThreadPoolExecutor() as pool:
                    reviewed = pool.submit(invoke, "beta", "entries", "list")
                    drive_request_popup(review_usage)
                    assert reviewed.result(timeout=4)["entries"] == fixture[2:]
                assert settings_switch("auto-approve", "list_entries", True)
                assert invoke("beta", "entries", "list")["entries"] == fixture[2:]
                assert app.pause_button.get_accessible().get_name() == "Pause Agent Access"
                pause_size = check_toolbar_button(app.pause_button)
                app.pause_button.clicked()
                assert app.pause_button.get_accessible().get_name() == "Resume Agent Access"
                assert check_toolbar_button(app.pause_button) == pause_size
                assert app.workspace.paused and app.workspace.session(second)
                assert app.indicator.get_icon() == "keeper-agent-access-paused"
                assert "paused" in invoke("beta", "entries", "list", expected=1)
                listings = [row for row in old_activity.rows(agent="Agent beta", action="List entries")
                            if row["vault_id"] == second and row["chat_id"] == "test-chat"]
                assert len(listings) > 1 and listings[0]["outcome"] == "Paused"
                same_scope = [row for row in listings if row["scope"] == listings[0]["scope"]]
                assert len(same_scope) < len(listings)
                assert any(row["outcome"] == "Succeeded" for row in same_scope[1:])
                app.activity_view.refresh()
                activity_group(same_scope, "Paused")
                app.pause_button.clicked()
                assert app.indicator.get_icon() == "keeper-agent-access-active"
                assert not settings_switch("auto-approve", "token-auto-approval-acknowledged")
                assert settings_switch("auto-approve", "token-auto-approval-acknowledged", True, label="I Understand")
                assert not settings_switch("auto-approve", "auto_approve_token_changes",
                                           label="Access Tokens - Update Permissions")
                assert settings_switch("auto-approve", "auto_approve_tokens", True,
                                       label="Access Tokens - Create")
                assert old_access.read().auto_approve_tokens
                assert not settings_switch("auto-approve", "auto-approve-usage", False)
                assert settings_switch("auto-approve", "auto_approve_tokens")
                assert not settings_switch("auto-approve", "auto_approve_tokens", False)
                assert settings_switch("auto-approve", "auto_approve_tokens", True)
                assert settings_switch("auto-approve", "auto-approve-usage", True)
                initial_item = {"vault": first, "entry": first_entry, "metadata": True}
                assert enroll("auto-token", [initial_item]) == {"status": "active"}
                token = token_ids["auto-token"]
                assert ("grant", token) not in app._review_requests()
                approved = old_activity.rows(action="Approve token", agent="Agent auto-token")
                assert len(approved) == 1 and approved[0]["decision"] == "Auto approved"
                assert invoke("auto-token", "entries", "list", "--vault", first)["entries"][0]["id"] == first_entry

                change = {"identity": "Agent auto-token", "project": "Disposable project",
                          "items": [{**initial_item, "vault": second, "entry": nested_entry}],
                          "change_id": str(uuid4())}
                assert invoke("auto-token", "access", "request", request=change) == {"status": "pending"}
                request_id = f"{token}/{change['change_id']}"
                assert ("grant-change", request_id) in app._review_requests()
                app.access_button.clicked()
                view = app.access_view
                row, = [row for row in view.table.get_model() if row[view.RECORD_ID] == request_id]
                assert row[view.STATUS] == "Permission Change Pending"
                assert row.iterchildren() is not None
                assert invoke("auto-token", "entries", "list", "--vault", first)["entries"][0]["id"] == first_entry

                def approve_permission_change(dialog):
                    assert dialog.get_title() == "Review Token Permission Change"
                    assert_keypress_ignored(dialog, "auto-token", permission_change=True)
                    click_decision(dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT))

                drive_request_popup(approve_permission_change)
                assert invoke("auto-token", "access", "request", request=change) == {"status": "active"}
                assert invoke("auto-token", "entries", "list", "--vault", second)["entries"][0]["id"] == nested_entry
                assert settings_switch("auto-approve", "auto_approve_token_changes", True)
                assert not settings_switch("auto-approve", "auto_approve_tokens", False)
                assert old_access.read().auto_approve_token_changes
                change = {**change, "items": [initial_item], "change_id": str(uuid4())}
                assert invoke("auto-token", "access", "request", request=change) == {"status": "active"}
                assert ("grant-change", f"{token}/{change['change_id']}") not in app._review_requests()
                decisions = old_activity.rows(action="Approve token permissions", agent="Agent auto-token")
                assert [row["decision"] for row in decisions] == ["Auto approved", "Approved in Access"]
                assert invoke("auto-token", "entries", "list", "--vault", first)["entries"][0]["id"] == first_entry
                assert not settings_switch("auto-approve", "token-auto-approval-acknowledged", False)
                assert not old_access.read().auto_approve_token_changes
                assert invoke("auto-token", "entries", "list", "--vault", first)["entries"][0]["id"] == first_entry

                set_screen_active(True)
                wait_for(lambda: app.desktop.locked and not app.workspace.sessions, "Desktop lock did not close both workers")
                assert app.workspace.paused and "paused" in invoke("beta", "vaults", "list", expected=1)
                set_screen_active(False)
                wait_for(lambda: not app.desktop.locked, "Test desktop did not resume")
                assert app.workspace.paused and not app.workspace.sessions

                persisted = [old_activity.path.read_bytes(), app.grants.path.read_bytes(), app.workspace.path.read_bytes()]
                for name in names:
                    raw = subprocess.check_output([*NAMESPACE, "cat", str(profiles / name / "token")]).strip()
                    assert all(raw not in data for data in persisted)
                    assert all(raw not in data for call in captured for data in call)
                for sentinel in (UNLOCK, PASSWORD, OTHER_PASSWORD, EDIT_PASSWORD, REQUESTED_PASSWORD, AUTHORIZATION, BEARER_AUTHORIZATION, other_header):
                    assert all(sentinel.encode() not in data for data in persisted)
                    assert all(sentinel.encode() not in data for call in captured for data in call)
                assert not any(application == app.get_application_id()
                               for _, (application, *_) in notification_messages)
                app.window.close()
                wait_for(lambda: app.exiting, "Closing the window did not quit Keeper")
                print("Workspace scenario passed: two vaults, scoped CLI, GNOME mouse-only request pop-ups, four access decisions, credential types, migration, locks and Activity", flush=True)
                result = 0
            except Exception:
                traceback.print_exc()
            finally:
                if not app.exiting:
                    app._quit()
            return GLib.SOURCE_REMOVE

        app.connect("activate", lambda *_: GLib.idle_add(exercise))
        app.run(None)
        assert not endpoint.exists()
        return result


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1])))
