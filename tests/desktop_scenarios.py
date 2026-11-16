"""Exercise the GTK tray across fresh processes in the private test desktop."""

import os
from pathlib import Path
import subprocess
import sys
from threading import Event
from time import monotonic, sleep
import traceback

from pykeepass import create_database, PyKeePass

from keepassxc_agent_access.tray import Gio, GLib, Gtk, VaultApplication
from keepassxc_agent_access.vault import UnlockCancelled, open_vault


ORIGINAL = "Synthetic legacy passphrase for desktop testing"
ROTATED = "Synthetic rotated passphrase for desktop testing"
RECOVERY = "Synthetic recovery passphrase for desktop testing"


def wait_for(predicate, description, timeout=10):
    deadline = monotonic() + timeout
    context = GLib.MainContext.default()
    while monotonic() < deadline:
        context.iteration(False)
        if predicate():
            return
        sleep(0.01)
    raise AssertionError(description)


def fill_setup(app, database, key_file, password, response=Gtk.ResponseType.OK):
    def submit():
        dialog = app.dialog
        if dialog is None:
            return GLib.SOURCE_CONTINUE
        assert dialog.database.set_filename(str(database))
        dialog.key_file_enabled.set_active(True)
        assert dialog.key_file.set_filename(str(key_file))
        assert not dialog.password.get_visibility()
        dialog.password.set_text(password)
        dialog.remember.set_active(True)
        dialog.response(response)
        return GLib.SOURCE_REMOVE

    GLib.timeout_add(50, submit)
    app._configure_dialog()
    wait_for(lambda: not app.busy, "wizard verification did not finish")


def enter_password(app, password):
    def submit():
        if app.dialog is None:
            return GLib.SOURCE_CONTINUE
        entry = next(w for w in app.dialog.get_content_area().get_children() if isinstance(w, Gtk.Entry))
        assert not entry.get_visibility()
        entry.set_text(password)
        app.dialog.response(Gtk.ResponseType.OK)
        return GLib.SOURCE_REMOVE

    GLib.timeout_add(50, submit)
    app.buttons["manual"].clicked()
    wait_for(lambda: not app.busy, "manual unlock did not finish")


def set_screen_active(enabled):
    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    name = "org.gnome.ScreenSaver"
    bus.call_sync(name, "/org/gnome/ScreenSaver", name, "SetActive",
                  GLib.Variant("(b)", (enabled,)), None, Gio.DBusCallFlags.NONE, 3000, None)


def configure(app, root, database, key_file):
    assert app.status.get_text() == "Setup required"
    assert app.buttons["setup"].get_visible()
    status, opening = app.menu.get_children()
    assert status.get_label() == "Setup required" and not status.get_sensitive()
    assert opening.get_label() == "Open Keeper"
    key_file.write_bytes(bytes(range(32)))
    create_database(database, ORIGINAL, str(key_file))
    legacy = root / "legacy-input.txt"
    legacy.write_text(ORIGINAL)
    vault = PyKeePass(database, password=ORIGINAL, keyfile=str(key_file))
    vault.password = ROTATED
    vault.save()
    before = database.read_bytes()

    fill_setup(app, database, key_file, "Incorrect synthetic input")
    assert "rejected" in app.notice.get_text()
    assert app.setup.store.read().target is None
    fill_setup(app, database, key_file, ROTATED)
    assert app.status.get_text() == "Locked"
    assert app.setup.store.read().active_item
    assert database.read_bytes() == before
    initial = app.setup.store.read()
    fill_setup(app, database, key_file, "Cancelled synthetic input", Gtk.ResponseType.CANCEL)
    assert app.setup.store.read() == initial
    assert all(secret not in app.setup.store.path.read_text() for secret in (ORIGINAL, ROTATED))
    legacy.unlink()


def verify(app, root, database, key_file):
    assert not (root / "legacy-input.txt").exists()
    assert app.status.get_text() == "Locked"
    assert app.buttons["unlock"].get_visible()
    app.buttons["unlock"].clicked()
    wait_for(lambda: not app.busy, "saved password unlock did not finish")
    assert app.status.get_text() == "Unlocked", app.notice.get_text()
    assert app.menu_items["status"].get_label() == "Unlocked · OS keyring"
    assert "using the saved password" in app.notice.get_text()
    if os.environ.get("TRAY_TEST_ISOLATION") == "1":
        check_isolation(database, key_file)

    app.buttons["lock"].clicked()
    assert app.status.get_text() == "Locked"
    app.menu_items["open"].activate()
    assert app.window.get_visible()
    app.window.close()
    wait_for(lambda: not app.window.get_visible(), "the window did not close to the tray")
    app.menu_items["open"].activate()
    assert app.window.get_visible()

    app.buttons["unlock"].clicked()
    wait_for(lambda: not app.busy, "second unlock did not finish")
    set_screen_active(True)
    wait_for(lambda: app.status.get_text() == "Locked", "GNOME session lock did not lock the vault")
    set_screen_active(False)
    wait_for(lambda: not app.desktop.locked, "test desktop did not resume")

    started, cancelled = Event(), Event()

    def delayed(target, password, attempt):
        started.set()
        if attempt.wait(5):
            cancelled.set()
            raise UnlockCancelled
        return open_vault(target, password, attempt)

    app.setup.controller._opener = delayed
    app.buttons["unlock"].clicked()
    wait_for(started.is_set, "test unlock did not start")
    set_screen_active(True)
    wait_for(lambda: not app.busy, "in-flight unlock did not stop when the desktop locked")
    assert cancelled.is_set()
    assert app.status.get_text() == "Locked"
    set_screen_active(False)

    vault = PyKeePass(database, password=ROTATED, keyfile=str(key_file))
    vault.password = RECOVERY
    vault.save()


def check_isolation(database, key_file):
    paths = [
        str(database), str(key_file), os.environ["DBUS_SESSION_BUS_ADDRESS"],
        str(Path(os.environ["XDG_RUNTIME_DIR"]) / os.environ["WAYLAND_DISPLAY"]),
        str(os.getpid()), str(os.geteuid()),
    ]
    with (Path(__file__).parent / "isolation_probe.py").open() as probe:
        subprocess.run(
            ["unshare", "--user", "--map-auto", "--setuid", "0", "--setgid", "0",
             "/usr/bin/python3", "-", *paths],
            stdin=probe, cwd="/tmp", check=True, timeout=15,
        )


def recover(app, root, _database, _key_file):
    assert app.status.get_text() == "Locked"
    app.buttons["unlock"].clicked()
    wait_for(lambda: not app.busy, "invalid saved unlock did not finish")
    assert app.status.get_text() == "Locked"
    assert "rejected" in app.notice.get_text()
    assert "recover" in app.notice.get_text()
    assert not (root / "legacy-input.txt").exists()
    enter_password(app, RECOVERY)
    assert app.status.get_text() == "Unlocked"
    assert app.setup.controller.source == "manual"
    app.buttons["forget"].clicked()
    wait_for(lambda: not app.busy, "forget did not finish")
    assert app.status.get_text() == "Locked"
    assert not app.setup.store.read().active_item
    assert not app.setup.store.read().pending_items


def fallback(app, _root, _database, _key_file):
    wait_for(lambda: app.window.get_visible(), "main window did not open without a tray")
    assert not app.tray_connected
    assert app.buttons["unlock"].get_visible()


def main(phase, root):
    app = VaultApplication()
    result = 1
    scenario = {"configure": configure, "verify": verify, "recover": recover, "fallback": fallback}[phase]

    def run_scenario():
        nonlocal result
        try:
            if phase != "fallback":
                wait_for(lambda: app.tray_connected, "AppIndicator did not connect to GNOME")
            scenario(app, root, root / "fixture.kdbx", root / "fixture.key")
            print(f"Desktop scenario passed: {phase}", flush=True)
            result = 0
        except Exception:
            traceback.print_exc()
        finally:
            app._quit()
        return GLib.SOURCE_REMOVE

    app.connect("activate", lambda *_: GLib.idle_add(run_scenario))
    app.run(None)
    return result


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], Path(sys.argv[2])))
