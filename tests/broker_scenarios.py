"""Synthetic GNOME broker scenarios and the fresh-agent test fixture."""

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import traceback

from pykeepass import create_database

from desktop_scenarios import fill_setup, set_screen_active, wait_for
from keepassxc_agent_access.access_settings import AccessMode
from keepassxc_agent_access.controller import VaultController
from keepassxc_agent_access.keyring import SystemKeyring
from keepassxc_agent_access.settings import SettingsStore
from keepassxc_agent_access.setup import VaultSetup
from keepassxc_agent_access.tray import GLib, VaultApplication
from keepassxc_agent_access.vault import VaultTarget


NAMESPACE = ["unshare", "--user", "--map-auto", "--setuid", "0", "--setgid", "0"]
PASSWORD = "Synthetic broker trial master password"
CLI_ARGS = ["keepassxc-agent", "entries", "list", "--json"]
REPO = Path(__file__).resolve().parents[1]


def isolated_uid():
    mapping = subprocess.check_output([*NAMESPACE, "cat", "/proc/self/uid_map"]).split()
    assert int(mapping[0]) == 0
    return int(mapping[1])


def prepare(root):
    root.chmod(0o711)
    private = root / "private"
    private.mkdir(mode=0o700)
    endpoint = root / "shared" / "entries.sock"
    endpoint.parent.mkdir(mode=0o755)
    database = private / "fixture.kdbx"
    key_file = private / "fixture.key"
    key_file.write_bytes(secrets.token_bytes(32))
    vault = create_database(database, PASSWORD, str(key_file))
    tag = secrets.token_hex(2)
    title = f"Quartz Relay {tag}"
    group = vault.add_group(vault.root_group, "Harbor Lab")
    nested = vault.add_group(group, "Field Notes")
    expected = []
    for parent, name, path in [
        (vault.root_group, f"Juniper Index {tag}", []),
        (group, title, ["Harbor Lab"]),
        (nested, title, ["Harbor Lab", "Field Notes"]),
    ]:
        entry = vault.add_entry(parent, name, "synthetic user", "synthetic credential")
        expected.append({"id": str(entry.uuid), "title": name, "group_path": path})
    discarded = vault.add_entry(group, "Discarded fixture", "", "")
    vault.trash_entry(discarded)
    vault.save()
    (private / "expected.json").write_text(json.dumps({"entries": expected}))

    runtime = root / "cli"
    modules = runtime / "src" / "keepassxc_agent_access"
    modules.mkdir(parents=True)
    for file in ("__init__.py", "agent_cli.py", "protocol.py", "runner_token.py"):
        shutil.copyfile(REPO / "src/keepassxc_agent_access" / file, modules / file)
    shutil.copy2(REPO / "keepassxc-agent", runtime / CLI_ARGS[0])
    return VaultTarget(database, key_file), endpoint, private, expected


def invoke(root, endpoint):
    return subprocess.run(
        [*NAMESPACE, "/usr/bin/env", "-i", f"PATH={root / 'cli'}:/usr/bin:/bin",
         f"KEEPASSXC_AGENT_SOCKET={endpoint}", *CLI_ARGS],
        cwd="/tmp", capture_output=True, check=False, timeout=10,
    )


def verify_isolation(target):
    socket_path = Path(os.environ["XDG_RUNTIME_DIR"]) / os.environ["WAYLAND_DISPLAY"]
    with (REPO / "tests/isolation_probe.py").open() as probe:
        subprocess.run(
            [*NAMESPACE, "/usr/bin/python3", "-", str(target.database), str(target.key_file),
             os.environ["DBUS_SESSION_BUS_ADDRESS"], str(socket_path), str(os.getpid()),
             str(os.geteuid())],
            stdin=probe, cwd="/tmp", check=True, timeout=15,
        )


def main(root, hold):
    target, endpoint, private, expected = prepare(root)
    uid = isolated_uid()
    os.environ["KEEPASSXC_AGENT_SOCKET"] = str(endpoint)
    os.environ["KEEPASSXC_AGENT_UID"] = str(uid)
    controller = VaultController()
    setup = VaultSetup(SettingsStore(private / "settings.json"), SystemKeyring(), controller)
    setup.configure(controller.begin(), target, PASSWORD, True)
    app = VaultApplication(setup=setup)
    app.access_store.write(replace(app.access_store.read(), mode=AccessMode.ALLOW))
    result = 1

    def unavailable():
        response = invoke(root, endpoint)
        assert response.returncode != 0 and not response.stdout

    def listing():
        response = invoke(root, endpoint)
        assert response.returncode == 0, response.stderr.decode()
        actual = json.loads(response.stdout)["entries"]
        assert {row["id"]: row for row in actual} == {row["id"]: row for row in expected}

    def enable():
        app.menu_items["enable_listing"].activate()
        assert app.broker.enabled
        assert "Agent access enabled" in app.menu_items["status"].get_label()
        subprocess.run(["setfacl", "-m", f"u:{uid}:rw", endpoint], check=True)

    def unlock():
        app.menu_items["unlock"].activate()
        wait_for(lambda: not app.busy, "test vault did not unlock")
        assert app.status.get_text() == "Unlocked"
        assert not app.broker.enabled

    def revoke_trial():
        nonlocal result
        if not (private / "revoke").exists():
            return GLib.SOURCE_CONTINUE
        try:
            app.menu_items["stop_listing"].activate()
            unavailable()
            (private / "revoked").touch()
            print("Broker scenario passed: skill trial revocation", flush=True)
            result = 0
        finally:
            app._quit()
        return GLib.SOURCE_REMOVE

    def check():
        nonlocal result
        keep_running = False
        try:
            wait_for(lambda: app.tray_connected, "AppIndicator did not connect to GNOME")
            assert app.status.get_text() == "Locked"
            unavailable()
            unlock()
            unavailable()
            enable()
            listing()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as owner:
                owner.settimeout(5)
                owner.connect(str(endpoint))
                assert not owner.recv(1)
            verify_isolation(target)
            if hold:
                (private / "ready").touch()
                GLib.timeout_add(150, revoke_trial)
                keep_running = True
                return GLib.SOURCE_REMOVE

            app.menu_items["stop_listing"].activate()
            unavailable()
            enable()
            set_screen_active(True)
            wait_for(lambda: app.status.get_text() == "Locked", "GNOME lock did not revoke listing")
            unavailable()
            set_screen_active(False)
            wait_for(lambda: not app.desktop.locked, "test desktop did not resume")
            unlock()
            unavailable()
            enable()
            replacement = private / "replacement.kdbx"
            shutil.copyfile(target.database, replacement)
            fill_setup(app, replacement, target.key_file, PASSWORD)
            assert setup.store.read().target.database == replacement
            unavailable()
            unlock()
            enable()
            listing()
            print("Broker scenario passed: tray lifecycle and isolated CLI", flush=True)
            result = 0
        except Exception:
            traceback.print_exc()
        finally:
            if not keep_running:
                app._quit()
        return GLib.SOURCE_REMOVE

    app.connect("activate", lambda *_: GLib.idle_add(check))
    app.run(None)
    assert not endpoint.exists(), "App exit left the broker socket in place"
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--hold", action="store_true")
    options = parser.parse_args()
    raise SystemExit(main(options.root, options.hold))
