"""Verify a legacy upgrade and token separation on a private GNOME desktop."""

import atexit
from base64 import b64encode
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import traceback
from uuid import UUID, uuid4

from pykeepass import PyKeePass

from broker_scenarios import NAMESPACE, PASSWORD as UNLOCK, REPO, isolated_uid, prepare, verify_isolation
from desktop_scenarios import set_screen_active, wait_for
from password_scenarios import button, descendants
from keepassxc_agent_access.access_settings import AccessMode, AccessStore, Action, ActionType, VaultPolicy
from keepassxc_agent_access.activity import ActivityStore
from keepassxc_agent_access.controller import VaultController
from keepassxc_agent_access.settings import SettingsStore
from keepassxc_agent_access.setup import VaultSetup
from keepassxc_agent_access.tray import GLib, Gtk
from keepassxc_agent_access.edit_request_view import OPERATION_LABELS
from keepassxc_agent_access.workspace_app import ENTRY_ID_COLUMN, WorkspaceApplication
from keepassxc_agent_access.workspace_editor import edit_entry, recycle_entry
from keepassxc_agent_access.keyring import SystemKeyring
from tls_fixture import AUTHORIZATION, PASSWORD, USERNAME, tls_service


OTHER_PASSWORD = "synthetic-second-password-sentinel"
STORED_URL = "https://fixture.example.test/owner-preview"
BEARER_AUTHORIZATION = f"Bearer {PASSWORD}"
EDIT_PASSWORD = "synthetic-owner-edit-password"
REQUESTED_PASSWORD = "synthetic-approval-only-password"


def main(root):
    target, endpoint, private, fixture = prepare(root)
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
    names = ("alpha", "beta", "review", "expanded", "bearer")
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

        def invoke(profile, *command, request=None, expected=0):
            env = [f"KEEPASSXC_AGENT_SOCKET={endpoint}", "KEEPASSXC_AGENT_MODEL=Synthetic test model",
                   "KEEPASSXC_AGENT_CHAT=Synthetic test chat", "KEEPASSXC_AGENT_CHAT_ID=test-chat"]
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

        def enroll(profile, items, expected=0):
            return invoke(profile, "access", "request", expected=expected, request={
                "identity": f"Agent {profile}", "project": "Disposable project", "items": items,
            })

        def drive_dialog(action, callback):
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
            if GLib.MainContext.default().find_source_by_id(source):
                GLib.source_remove(source)
                raise AssertionError("Expected a GTK dialog")
            if failures:
                raise failures[0]

        def access_row(profile):
            app.access_button.clicked()
            table = app.access_view.table
            path = next(row.path for row in table.get_model() if row[1].startswith(f"Agent {profile} "))
            table.get_selection().select_path(path)
            return lambda: table.row_activated(path, table.get_column(0))

        def approve(profile, vault=None):
            def confirm(dialog):
                assert dialog.get_title() == "Review access request"
                labels = [child.get_text() for child in descendants(dialog) if isinstance(child, Gtk.Label)]
                assert any("verified" in label for label in labels)
                assert any("Disposable project (reported)" in label for label in labels)
                if profile == "alpha":
                    assert any(f"Username  {USERNAME}" in label for label in labels)
                elif profile == "expanded":
                    assert any(f"Stored URL  {STORED_URL}" in label for label in labels)
                elif profile == "bearer":
                    assert any("HTTPS Bearer token GET" in label and url + "/first" in label for label in labels)
                if vault:
                    combo, = [child for child in descendants(dialog) if isinstance(child, Gtk.ComboBoxText)]
                    assert len(combo.get_model()) == 4
                    assert not dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT).get_sensitive()
                    choices = app.grants.choices(next(row for row in app.grants.rows() if row.status == "pending").items[0])
                    index = next(i for i, choice in enumerate(choices)
                                 if choice.scope.vault == vault and choice.scope.entry == nested_entry)
                    combo.set_active(index)
                assert dialog.get_widget_for_response(Gtk.ResponseType.ACCEPT).get_sensitive()
                dialog.response(Gtk.ResponseType.ACCEPT)
            drive_dialog(access_row(profile), confirm)

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

        def use(profile, vault, entry=first_entry, expected=0):
            return invoke(profile, "use", "--vault", vault, "--entry", entry, "--action", "check", expected=expected)

        def open_entry(identifier):
            table = app.entries
            path = next(row.path for row in table.get_model() if row[ENTRY_ID_COLUMN] == identifier)
            table.row_activated(path, next(column for column in table.get_columns() if column.get_title() == "Title"))

        def check_editors(vault):
            def fill_group(dialog, name):
                field = next(child for child in descendants(dialog) if child.get_name() == "group-name")
                field.set_text(name)
                dialog.response(Gtk.ResponseType.OK)

            def fields(dialog, title, create=False):
                controls = {child.get_name(): child for child in descendants(dialog) if isinstance(child, Gtk.Entry)}
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

            select_tree(vault)
            drive_dialog(app.new_group_item.activate, lambda dialog: fill_group(dialog, "New fixture group"))
            wait_for(lambda: not app.busy, "Creating a group timed out")
            group = app.selection[1]
            assert group and app.browse_title.get_text() == "New fixture group"
            drive_dialog(app.new_entry_item.activate, lambda dialog: fields(dialog, "Created entry", create=True))
            wait_for(lambda: not app.busy, "Creating an entry timed out")
            entry, = app.entry_rows.values()
            assert entry["title"] == "Created entry"
            assert "password" not in entry
            drive_dialog(lambda: edit_entry(app, vault, group, entry), lambda dialog: fields(dialog, "Edited entry"))
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

            def accept(dialog):
                dialog.response(Gtk.ResponseType.OK)

            drive_dialog(lambda: recycle_entry(app, vault, group, edited), accept)
            wait_for(lambda: not app.busy, "Recycling an entry timed out")
            assert not app.entry_rows
            drive_dialog(app._recycle_group, accept)
            wait_for(lambda: not app.busy, "Recycling a group timed out")
            assert app.selection == (vault, "")
            assert all(row["id"] != group for row in app.workspace.owner_session(vault).groups)

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

            def decide(proposal, response, *, strings=(), password=None, before=None, allow=True, resume=False):
                app.access_button.clicked()
                table = app.access_view.table
                path = next(row.path for row in table.get_model() if row[5].endswith("/" + proposal["id"]))
                table.get_selection().select_path(path)

                def check(dialog):
                    assert dialog.get_title() == OPERATION_LABELS[proposal["operation"]]
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
                        resume_control = button(dialog, "Resume agent access")
                        assert resume_control.get_visible() and resume_control.get_sensitive()
                        resume_control.clicked()
                        assert not app.workspace.paused and status(proposal)["status"] == "pending"
                        assert not resume_control.get_parent().get_visible()
                    assert approve.get_sensitive() == allow
                    if before:
                        before()
                    dialog.response(response)

                drive_dialog(lambda: table.row_activated(path, table.get_column(0)), check)
                wait_for(lambda: not app.busy, "Approved agent edit did not finish")

            def apply(proposal, **kwargs):
                decide(proposal, Gtk.ResponseType.ACCEPT, **kwargs)
                result = status(proposal)
                assert result["status"] == "applied", (result, app.message)
                return result.get("result")

            session = app.workspace.owner_session(first)
            root_group, = [item["id"] for item in session.groups if item["parent"] is None]
            first_group = propose("create_group", parent=root_group, fields={"name": "Reviewed group"})
            duplicate = runner("beta", "request_edit", {"request": first_group})
            assert duplicate["status"] == "pending"
            assert runner("expanded", "edit_status", {"id": first_group["id"]}, error=True)
            app.set_agent_paused(True)
            group = apply(first_group, strings=("Reviewed group", "Proposed"), resume=True)
            assert runner("beta", "request_edit", {"request": first_group}) == {
                "id": first_group["id"], "status": "applied", "result": group,
            }
            assert sum(item["id"] == group for item in app.workspace.owner_session(first).groups) == 1

            rename = propose("rename_group", group=group, fields={"name": "Approved group"})
            apply(rename, strings=("Reviewed group", "Approved group"))
            new = propose("create_entry", parent=group, fields={"title": "Agent fixture", "username": "fixture"})
            entry = apply(new, strings=("Agent fixture", "Approved group"))
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
            assert len(app.activity_view.table.get_model()) >= 3
            app.activity_view.filters["chat"].set_text("")

        def exercise():
            nonlocal result
            try:
                wait_for(lambda: app.tray_connected, "AppIndicator did not connect")
                assert app.window.get_visible()
                assert app.window.get_title() == "Keeper"
                assert app.workspace.paused and app.grants.rows() == []
                assert old_activity.rows(action="Legacy fixture")[0]["token"] is None
                first, = app.workspace.registrations
                assert app.workspace.registrations[first].item == original_item
                assert app.broker.enabled and endpoint.exists()
                subprocess.run(["setfacl", "-m", f"u:{uid}:rw", endpoint], check=True)
                verify_isolation(target)
                assert "token is required" in invoke(None, "entries", "list", expected=1)
                app.vault_buttons["unlock"].clicked()
                wait_for(lambda: not app.busy and app.workspace.session(first), "Migrated keyring did not unlock")
                assert app.workspace.registrations[first].bindings[0].action == imported
                assert {row[ENTRY_ID_COLUMN]: row[3] for row in app.entries.get_model()} == {
                    first_entry: "Root", direct_entry: "Harbor Lab", nested_entry: "Harbor Lab / Field Notes",
                }
                assert [column.get_title() for column in app.entries.get_columns() if column.get_visible()] == [
                    "Folder", "Title", "Username", "URL",
                ]
                app.entry_search.set_text("harbor lab / FIELD")
                assert [row[ENTRY_ID_COLUMN] for row in app.entries.get_model()] == [nested_entry]
                app.entry_search.set_text("")

                def setup_secondary(dialog):
                    assert dialog.database.set_filename(str(second_path))
                    dialog.key_file_enabled.set_active(True)
                    assert dialog.key_file.set_filename(str(target.key_file))
                    dialog.password.set_text(UNLOCK)
                    dialog.remember.set_active(True)
                    dialog.response(Gtk.ResponseType.OK)

                drive_dialog(button(app.window, "Add vault…").clicked, setup_secondary)
                wait_for(lambda: not app.busy, "Second vault setup timed out")
                second, = set(app.workspace.registrations) - {first}
                assert app.workspace.session(second)
                assert app.workspace.session(second).worker.identity == app.workspace.session(first).worker.identity
                assert not app.workspace.registrations[second].bindings

                def edit_action(dialog):
                    assert dialog.get_title() == "Credential action"
                    fields = [child for child in dialog.get_content_area().get_children() if isinstance(child, Gtk.Entry)]
                    for field, value in zip(fields, ("check", "Second vault action", url + "/second")):
                        field.set_text(value)
                    dialog.response(Gtk.ResponseType.OK)

                def configure_action(dialog):
                    dialog.response(Gtk.ResponseType.APPLY)
                    GLib.timeout_add(25, lambda: follow_up())

                def follow_up():
                    if app.dialog and app.dialog.get_title() == "Credential action":
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
                select_tree(first, outer)
                assert [row[ENTRY_ID_COLUMN] for row in app.entries.get_model()] == [direct_entry]
                assert [column.get_title() for column in app.entries.get_columns() if column.get_visible()] == [
                    "Title", "Username", "URL",
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
                            {"vault": second, "entry": first_entry, "action": "check", "metadata": True, "url": True}]
                assert enroll("alpha", alpha) == enroll("alpha", alpha) == {"status": "pending"}
                assert enroll("beta", beta) == {"status": "pending"}
                assert enroll("review", beta) == {"status": "pending"}
                assert len(app.grants.rows()) == 3
                assert "unavailable for this token" in invoke("beta", "vaults", "list", expected=1)
                approve("alpha")
                assert [c.get_title() for c in app.access_view.table.get_columns()] == list(app.access_view.TITLES)
                assert [row[3] for row in app.access_view.table.get_model()] == ["Pending", "Pending", "Active"]
                assert app.access_view.table.get_model()[-1][4] == "—"
                approve("beta", second)
                drive_dialog(access_row("review"), lambda dialog: dialog.response(Gtk.ResponseType.REJECT))
                assert invoke("review", "access", "status") == {"status": "denied"}
                assert "unavailable for this token" in invoke("review", "vaults", "list", expected=1)
                assert "paused" in invoke("alpha", "vaults", "list", expected=1)
                assert app.workspace.session(first) and app.workspace.session(second)

                app.pause_button.clicked()
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
                assert invoke("expanded", "entries", "list", "--vault", second)["entries"] == fixture[:1]
                assert invoke("expanded", "entries", "list", "--vault", second,
                              "--field", "username", "--field", "url")["entries"] == [{**fixture[0], "url": STORED_URL}]
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
                    if not app.dialog or app.dialog.get_title() != "Credential action":
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
                app.vault_buttons["unlock"].clicked()
                wait_for(lambda: not app.busy and app.workspace.session(first), "First vault did not unlock again")
                drive_dialog(access_row("alpha"), lambda dialog: dialog.response(Gtk.ResponseType.APPLY))
                assert invoke("alpha", "access", "status") == {"status": "disabled"}
                assert invoke("alpha", "entries", "list", expected=1) == denied
                assert invoke("beta", "entries", "list")["entries"] == fixture[2:]
                drive_dialog(access_row("alpha"), lambda dialog: dialog.response(Gtk.ResponseType.APPLY))
                assert invoke("alpha", "entries", "list")["entries"] == fixture[:1]
                alpha_record = next(row for row in app.grants.rows() if row.identity == "Agent alpha")
                assert alpha_record.last_used and alpha_record.last_used >= alpha_record.requested
                app.grants.transition(alpha_record.id, "removed")
                assert enroll("alpha", alpha, expected=1) == denied
                assert invoke("alpha", "entries", "list", expected=1) == denied
                assert invoke("beta", "entries", "list")["entries"] == fixture[2:]

                check_editors(first)
                assert invoke("beta", "entries", "list")["entries"] == fixture[2:]
                app.activity_button.clicked()
                assert [column.get_title() for column in app.activity_view.table.get_columns()] == list(app.activity_view.TITLES)
                app.activity_view.filters["agent"].set_text("Agent beta")
                app.activity_view.refresh()
                assert len(app.activity_view.table.get_model()) > 0
                assert all(row["agent"] == "Agent beta" for row in app.activity_view.rows.values())
                access = next(row for row in old_activity.rows(vault="second", action="Use password")
                              if row["entry"] == first_entry and row["entry_title"])
                assert access["folder"] == "Root" and access["entry_title"] == fixture[0]["title"]
                token_event = old_activity.rows(action="Remove token")[0]
                assert token_event["token"] == alpha_record.id and token_event["entry_title"] == fixture[0]["title"]
                legacy, = old_activity.rows(action="Legacy fixture")
                assert legacy["vault"] is None and legacy["folder"] is None and legacy["entry_title"] is None

                app.activity_view.filters["agent"].set_text("")
                app.activity_view.refresh()
                activity_table = app.activity_view.table
                model = activity_table.get_model()
                path = next(row.path for row in model if row[app.activity_view.RECORD_ID] == str(access["id"]))
                row = model[path]
                assert row[app.activity_view.TITLES.index("Vault")] == "second"
                assert row[app.activity_view.TITLES.index("Target")] == "Root / " + fixture[0]["title"]
                activity_table.get_selection().select_path(path)

                def read_activity(dialog):
                    labels = {child.get_text() for child in descendants(dialog) if isinstance(child, Gtk.Label)}
                    assert {"Target", "Vault", "Folder", "Entry", "second", "Root", fixture[0]["title"]} <= labels
                    expander = next(child for child in descendants(dialog) if isinstance(child, Gtk.Expander))
                    assert expander.get_label() == "Technical details" and not expander.get_expanded()
                    dialog.response(Gtk.ResponseType.CLOSE)

                drive_dialog(lambda: activity_table.row_activated(path, activity_table.get_column(0)), read_activity)
                check_agent_edits(first, second)
                app.tray_items["pause"].activate()
                assert app.workspace.paused and app.workspace.session(second)
                assert "paused" in invoke("beta", "entries", "list", expected=1)
                app.tray_items["pause"].activate()
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
                print("Workspace scenario passed: two vaults, scoped CLI, GNOME owner and agent edits, credential types, migration, locks and Activity", flush=True)
                result = 0
            except Exception:
                traceback.print_exc()
            finally:
                app._quit()
            return GLib.SOURCE_REMOVE

        app.connect("activate", lambda *_: GLib.idle_add(exercise))
        app.run(None)
        assert not endpoint.exists()
        return result


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1])))
