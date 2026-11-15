"""Exercise GNOME desktop entry discovery, launch, and single-instance reuse."""

from dataclasses import replace
import os
from pathlib import Path
import signal
import subprocess
import sys
from time import monotonic, sleep

from gi.repository import Gio, GLib

from broker_scenarios import PASSWORD, invoke, isolated_uid, prepare
from keepassxc_agent_access.access_settings import AccessMode, AccessStore
from keepassxc_agent_access.controller import VaultController
from keepassxc_agent_access.keyring import SystemKeyring
from keepassxc_agent_access.launcher import DESKTOP_ID
from keepassxc_agent_access.settings import SettingsStore
from keepassxc_agent_access.setup import VaultSetup


APP = DESKTOP_ID.removesuffix(".desktop")
bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)


def call(name, path, interface, method, params=None):
    return bus.call_sync(name, path, interface, method, params, None,
                         Gio.DBusCallFlags.NONE, 1500, None).unpack()


def app_pid():
    return call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                "GetConnectionUnixProcessID", GLib.Variant("(s)", (APP,)))[0]


def wait_for(check):
    deadline = monotonic() + 8
    while monotonic() < deadline:
        try:
            if result := check():
                return result
        except (GLib.Error, OSError, StopIteration):
            pass
        sleep(.1)
    raise AssertionError("Expected GNOME application state was unavailable.")


def menu():
    entries, = call("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher",
                    "org.freedesktop.DBus.Properties", "Get",
                    GLib.Variant("(ss)", ("org.kde.StatusNotifierWatcher", "RegisteredStatusNotifierItems")))
    selected = next(row for row in entries if "keepassxc_agent_access" in row)
    name, _, item_path = selected.partition("@")
    title, = call(name, item_path, "org.freedesktop.DBus.Properties", "Get",
                  GLib.Variant("(ss)", ("org.kde.StatusNotifierItem", "Title")))
    assert title == "Keeper"
    path, = call(name, item_path, "org.freedesktop.DBus.Properties", "Get",
                 GLib.Variant("(ss)", ("org.kde.StatusNotifierItem", "Menu")))
    _, layout = call(name, path, "com.canonical.dbusmenu", "GetLayout",
                     GLib.Variant("(iias)", (0, -1, ["label", "enabled", "visible"])))
    return name, path, {props["label"]: (item, props) for item, props, _ in layout[2] if "label" in props}


def row(label):
    name, path, rows = menu()
    if label in rows and rows[label][1].get("visible", True):
        return name, path, rows[label]
    return None


def click(label):
    name, path, (item, props) = wait_for(lambda: row(label))
    assert props.get("enabled", True)
    call(name, path, "com.canonical.dbusmenu", "Event",
         GLib.Variant("(isvu)", (item, "clicked", GLib.Variant("s", ""), 0)))


def stop(pid):
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass

    def stopped():
        try:
            return app_pid() != pid
        except GLib.Error:
            return True

    wait_for(stopped)


def main(root):
    config = root / "desktop-config"
    os.environ["XDG_CONFIG_HOME"] = str(config)
    os.environ.pop("KEEPASSXC_AGENT_SOCKET", None)
    os.environ.pop("KEEPASSXC_AGENT_UID", None)
    config.mkdir()
    documents = root / "Custom Documents"
    (config / "user-dirs.dirs").write_text(f'XDG_DOCUMENTS_DIR="{documents}"\n', encoding="utf-8")
    subprocess.run(["./install-launcher"], check=True, capture_output=True)
    relative_skill = Path("keepassxc-agent-access") / "SKILL.md"
    installed = documents / "Skills" / relative_skill
    assert installed.read_bytes() == (Path("skills") / relative_skill).read_bytes()
    edited = b"Locally edited Keeper skill\n"
    installed.write_bytes(edited)
    subprocess.run(["./install-launcher"], check=True, capture_output=True)
    assert installed.read_bytes() == edited
    launcher = Gio.DesktopAppInfo.new(DESKTOP_ID)
    assert launcher is not None and "--show-window" in launcher.get_commandline()
    assert launcher.get_name() == "Keeper"

    assert launcher.launch([], None)
    first = wait_for(app_pid)
    try:
        wait_for(lambda: row("Open Keeper"))
        assert launcher.launch([], None)
        sleep(.6)
        assert app_pid() == first
    finally:
        stop(first)

    target, endpoint, _private, _expected = prepare(root)
    store = SettingsStore()
    setup = VaultSetup(store, SystemKeyring(), VaultController())
    setup.configure(setup.controller.begin(), target, PASSWORD, True)
    access = AccessStore(store.path.with_name("access.json"))
    uid = isolated_uid()
    access.write(replace(access.read(), mode=AccessMode.ALLOW, endpoint=str(endpoint), uid=uid))

    assert launcher.launch([], None)
    second = wait_for(app_pid)
    try:
        wait_for(lambda: row("Resume agent access"))
        wait_for(endpoint.exists)
        subprocess.run(["setfacl", "-m", f"u:{uid}:rw", endpoint], check=True)
        result = invoke(root, endpoint)
        assert result.returncode != 0 and not result.stdout
        assert b"approved access token" in result.stderr
        click("Resume agent access")
        wait_for(lambda: row("Pause agent access"))
        click("Pause agent access")
        wait_for(lambda: row("Resume agent access"))
    finally:
        stop(second)
    assert not endpoint.exists()
    print("Launcher scenario passed: skill installation, GNOME registration, single instance and persisted settings", flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
