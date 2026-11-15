"""Exercise the password broker through a native GNOME desktop and isolated CLI."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

from uuid import UUID
from pykeepass import PyKeePass

from broker_scenarios import NAMESPACE, PASSWORD as UNLOCK, isolated_uid, prepare, verify_isolation
from desktop_scenarios import set_screen_active, wait_for
from keepassxc_agent_access.access_settings import AccessMode
from keepassxc_agent_access.controller import VaultController
from keepassxc_agent_access.keyring import SystemKeyring
from keepassxc_agent_access.setup import VaultSetup
from keepassxc_agent_access.settings import SettingsStore
from keepassxc_agent_access.tray import GLib, Gtk, VaultApplication
from tls_fixture import AUTHORIZATION, PASSWORD, USERNAME, tls_service


def descendants(widget):
    yield widget
    if isinstance(widget, Gtk.Container):
        for child in widget.get_children():
            yield from descendants(child)


def named(widget, name):
    return next(child for child in descendants(widget) if child.get_name() == name)


def button(widget, text):
    return next(item for item in descendants(widget)
                if isinstance(item, Gtk.Button) and item.get_label() == text)


def main(root):
    target, endpoint, private, fixture = prepare(root)
    identifiers = [row["id"] for row in fixture]
    vault = PyKeePass(target.database, password=UNLOCK, keyfile=str(target.key_file))
    for row in fixture:
        entry = vault.find_entries(uuid=UUID(row["id"]), first=True)
        entry.username, entry.password = USERNAME, PASSWORD
    vault.save()

    uid = isolated_uid()
    with tls_service(private) as (certificate, url, calls), ThreadPoolExecutor(max_workers=4) as workers:
        os.environ["SSL_CERT_FILE"] = str(certificate)
        for option in ("KEEPASSXC_AGENT_SOCKET", "KEEPASSXC_AGENT_UID"):
            os.environ.pop(option, None)
        controller = VaultController()
        setup = VaultSetup(SettingsStore(private / "settings.json"), SystemKeyring(), controller)
        setup.configure(controller.begin(), target, UNLOCK, True)
        app = VaultApplication(setup=setup, show_window=True)
        app.access_store.write(replace(app.access_store.read(), endpoint=str(endpoint), uid=uid))
        # Initialize through the normal app-start path with persisted broker settings.
        app = VaultApplication(setup=setup, show_window=True)
        result = 1

        def invoke(*command, model="Synthetic model"):
            return workers.submit(subprocess.run, [
                *NAMESPACE, "/usr/bin/env", "-i", f"PATH={root / 'cli'}:/usr/bin:/bin",
                f"KEEPASSXC_AGENT_SOCKET={endpoint}", f"KEEPASSXC_AGENT_MODEL={model}",
                "KEEPASSXC_AGENT_CHAT=Synthetic chat", "KEEPASSXC_AGENT_CHAT_ID=fixture-session",
                "keepassxc-agent", *command,
            ], cwd="/tmp", capture_output=True, check=False, timeout=20)

        def done(job, code=0):
            wait_for(job.done, "CLI did not finish")
            process = job.result()
            assert process.returncode == code, process.stderr.decode()
            for forbidden in (PASSWORD, AUTHORIZATION, USERNAME):
                assert forbidden.encode() not in process.stdout + process.stderr
            return json.loads(process.stdout) if process.stdout else None

        def unlock():
            app.menu_items["unlock"].activate()
            wait_for(lambda: not app.busy, "vault unlock failed")
            assert app.status.get_text() == "Unlocked", app.notice.get_text()

        def enable():
            app.menu_items["enable_listing"].activate()
            assert app.broker.enabled
            subprocess.run(["setfacl", "-m", f"u:{uid}:rw", endpoint], check=True)

        def change_mode(mode, auto=False):
            app.buttons["access"].clicked()
            dialog = app.owner_views.dialog
            table = named(dialog, "entry-review")
            wait_for(lambda: len(table.get_model()) == 3, "Access entry flags did not load")
            named(dialog, "access-mode").set_active_id(mode.value)
            if auto:
                model = table.get_model()
                index = next(i for i, row in enumerate(model) if row[2] == identifiers[0])
                table.get_columns()[0].get_cells()[0].emit("toggled", str(index))
            dialog.response(Gtk.ResponseType.APPLY)
            assert app.owner_views.dialog is None
            assert app.access_store.read().mode is mode

        def save_action(action, index, path, update=False):
            app.buttons["actions"].clicked()
            dialog = app.owner_views.dialog
            if update:
                assert named(dialog, "configured-actions").set_active_id(action)
            else:
                named(dialog, "action-id").set_text(action)
            named(dialog, "action-name").set_text("Synthetic " + action)
            named(dialog, "action-url").set_text(url + path)
            field = named(dialog, "action-entry")

            def entry_available():
                return field.set_active_id(identifiers[index])

            wait_for(entry_available, "Actions entry list did not load")
            button(dialog, "Save action").clicked()
            app.owner_views.close()
            policy = app.access_store.read().for_vault(app.setup.controller.current_session().identity)
            assert next(item for item in policy.actions if item.id == action).url.endswith(path)

        def pending(job):
            wait_for(lambda: app.approval_ui.dialog is not None, "Approval popup did not appear")
            assert not job.done()
            return app.approval_ui.dialog

        def use(index, action, model="Synthetic model"):
            return invoke("use", "--entry", identifiers[index], "--action", action, "--json", model=model)

        def exercise():
            nonlocal result
            try:
                wait_for(lambda: app.tray_connected, "AppIndicator did not connect")
                assert app.status.get_text() == "Locked"
                assert app.window.get_visible()
                assert app.access_store.read().mode is AccessMode.REVIEW
                unlock()
                enable()
                verify_isolation(target)
                save_action("one", 0, "/one")
                save_action("two", 1, "/two")

                reviewed = use(1, "two")
                popup = pending(reviewed)
                app.menu_items["pending"].activate()
                assert app.approval_ui.dialog is popup
                assert any(isinstance(item, Gtk.Label) and url in item.get_text()
                           for item in descendants(popup))
                assert not calls
                button(popup, "Approve once").clicked()
                assert done(reviewed)["http_status"] == 200

                refused = use(1, "two")
                button(pending(refused), "Decline").clicked()
                assert done(refused, 1) is None
                dismissed = use(1, "two")
                pending(dismissed).close()
                assert done(dismissed, 1) is None

                listed = invoke("entries", "list", "--json")
                button(pending(listed), "Approve once").clicked()
                assert len(done(listed)["entries"]) == 3
                assert len(calls) == 1

                change_mode(AccessMode.ALLOW)
                assert done(use(0, "one", model="Another synthetic model"))["outcome"] == "succeeded"
                assert len(done(invoke("entries", "list", "--json"))["entries"]) == 3
                assert app.approval_ui.dialog is None

                change_mode(AccessMode.SMART, auto=True)
                assert [row["id"] for row in done(invoke("entries", "list", "--json"))["entries"]] == identifiers[:1]
                protected = use(1, "two")
                popup = pending(protected)
                assert done(use(0, "one"))["http_status"] == 200
                button(popup, "Approve once").clicked()
                assert done(protected)["http_status"] == 200
                extended = invoke("entries", "list", "--include-reviewed", "--json")
                button(pending(extended), "Approve once").clicked()
                assert len(done(extended)["entries"]) == 3

                stale = use(1, "two")
                pending(stale)
                save_action("two", 1, "/updated", update=True)
                assert done(stale, 1) is None
                wait_for(lambda: app.approval_ui.dialog is None, "Stale prompt did not close")
                revoked = use(1, "two")
                pending(revoked)
                app.menu_items["stop_listing"].activate()
                assert done(revoked, 1) is None
                assert not endpoint.exists()
                enable()
                locked = use(1, "two")
                pending(locked)
                set_screen_active(True)
                wait_for(lambda: app.status.get_text() == "Locked", "Desktop did not lock")
                assert done(locked, 1) is None
                assert not endpoint.exists()
                set_screen_active(False)
                wait_for(lambda: not app.desktop.locked, "Desktop did not resume")

                wait_for(lambda: sum(row["outcome"] == "Revoked" for row in app.activity_store.rows()) >= 3,
                         "Revocations were not recorded")
                rows = app.activity_store.rows()
                assert {row["decision"] for row in rows} >= {"Allowed by policy", "Approved once"}
                assert {row["outcome"] for row in rows} >= {"Succeeded", "Declined", "Revoked"}
                assert any(row["chat"] == "Synthetic chat" for row in rows)
                assert any(row["model"] == "Another synthetic model" for row in rows)
                assert [path for path, _ in calls] == ["/two", "/one", "/one", "/two"]
                assert all(header == AUTHORIZATION for _, header in calls)
                assert PASSWORD.encode() not in app.activity_store.path.read_bytes()
                assert AUTHORIZATION.encode() not in app.activity_store.path.read_bytes()
                app.menu_items["activity"].activate()
                tree = next(child for child in descendants(app.owner_views.dialog) if isinstance(child, Gtk.TreeView))
                assert [col.get_title() for col in tree.get_columns()] == ["Time", "Model", "Chat", "Action", "Outcome"]
                assert len(tree.get_model()) == len(rows)
                model_filter = next(child for child in descendants(app.owner_views.dialog)
                                    if isinstance(child, Gtk.Entry) and child.get_placeholder_text() == "Model")
                model_filter.set_text("Another")
                assert len(tree.get_model()) == 1
                tree.get_selection().select_path(Gtk.TreePath.new_from_string("0"))
                assert any(isinstance(widget, Gtk.Label) and "agent-reported" in widget.get_text().lower()
                           for widget in descendants(app.owner_views.dialog))
                print("Password scenario passed: all modes, native decisions, isolated CLI and Activity", flush=True)
                result = 0
            except Exception:
                traceback.print_exc()
            finally:
                app._quit()
            return GLib.SOURCE_REMOVE

        app.connect("activate", lambda *_: GLib.idle_add(exercise))
        app.run(None)
        return result


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1])))
