import json
import os
import stat
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from keepassxc_agent_access.installation import DESKTOP_SERVICE, Installation, SERVICE, desktop_service_contents, main as install_main, service_contents
from keepassxc_agent_access.agent_setup import PAYLOAD_LIMIT, RUNTIME, setup as admin_setup, unit_contents
from keepassxc_agent_access.launcher import (
    antigravity_mcp_entry, antigravity_mcp_snippet, desktop_contents, desktop_icon, normalize_desktop_icon,
    skill_launcher_contents, _install_skill,
)


class InstallationTests(unittest.TestCase):
    def test_agent_service_waits_for_graphical_session_and_paces_restarts(self):
        unit = service_contents(Path("/tmp/keeper"), 100000)
        for line in (
            b"PartOf=graphical-session.target",
            b"After=graphical-session.target",
            b"Restart=on-failure",
            b"RestartSec=1",
            b"WantedBy=graphical-session.target",
        ):
            self.assertIn(line, unit)
        self.assertNotIn(b"After=graphical-session-pre.target", unit)

    def test_agent_connection_uses_desktop_socket_and_protected_dedicated_service(self):
        listener, runner = unit_contents(1000, "keeper-agent-1000", Path('/run/keeper-broker-1000/broker.sock'),
                                         Path('/usr/local/lib/keeper-connect-1000'))
        self.assertIn(b"ListenStream=/run/keeper-connect-1000.sock\nSocketUser=1000\nSocketMode=0600\nAccept=yes", listener)
        self.assertIn(b"User=keeper-agent-1000", runner)
        self.assertIn(b"--project-profiles /var/lib/keeper-connect-1000 --connection-profiles", runner)
        for setting in (b"NoNewPrivileges=yes", b"ProtectHome=yes", b"RestrictAddressFamilies=AF_UNIX"):
            self.assertIn(setting, runner)

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.skill = self.root / "Documents/Skills/Keeper/SKILL.md"
        self.legacy_skill = self.root / "Documents/Skills/keepassxc-agent-access/SKILL.md"
        with patch("keepassxc_agent_access.installation.GLib.get_user_data_dir", return_value=str(self.root / "data")), \
             patch("keepassxc_agent_access.installation.GLib.get_user_config_dir", return_value=str(self.root / "config")):
            self.installation = Installation()
        for target, options in (
            ("skill_destination", {"return_value": self.skill}),
            ("antigravity_skill_destination", {"return_value": None}),
            ("antigravity_mcp_config_destination", {"return_value": None}),
            ("stop_application", {}),
        ):
            patcher = patch(f"keepassxc_agent_access.installation.{target}", **options)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_managed_install_update_and_uninstall(self):
        installation = self.installation
        launcher, runner = installation.install(False)
        self.assertIsNone(runner)
        self.assertEqual(launcher.read_text(), desktop_contents(installation.app / "run-tray"))
        self.assertTrue((installation.app / "run-tray").is_file())
        self.assertTrue(self.skill.exists())
        helper = self.skill.with_name("keeper-agent")
        self.assertTrue(helper.is_file() and os.access(helper, os.X_OK))
        self.assertEqual(helper.read_bytes(), skill_launcher_contents(installation.app / "keeper-agent"))
        invocation = subprocess.run([helper, "--help"], capture_output=True, text=True)
        self.assertEqual(invocation.returncode, 0, invocation.stderr)
        self.assertIn("keeper-agent", invocation.stdout)
        installation.install(False)
        self.assertTrue(installation.uninstall())
        self.assertFalse(launcher.exists() or self.skill.exists() or helper.exists() or installation.app.exists())
        self.assertFalse(installation.uninstall())

    def test_upgrade_cleans_up_bundled_legacy_copy_and_preserves_edited_copy(self):
        installation = self.installation
        installation.install(False)
        bundled = self.skill.read_bytes()
        self.legacy_skill.parent.mkdir()
        self.legacy_skill.write_bytes(bundled)
        self.skill.unlink()
        installation.install(False)
        self.assertEqual(self.skill.read_bytes(), bundled)
        self.assertFalse(self.legacy_skill.exists())

        edited = b"Locally edited legacy skill"
        self.legacy_skill.write_bytes(edited)
        installation.install(False)
        installation.uninstall()
        self.assertFalse(self.skill.exists())
        self.assertEqual(self.legacy_skill.read_bytes(), edited)

    def test_preserves_custom_skill_and_refuses_to_overwrite_custom_launcher(self):
        installation = self.installation
        installation.install(False)
        edited = b"Locally edited skill"
        self.skill.write_bytes(edited)
        installation.install(False)
        self.assertEqual(self.skill.read_bytes(), edited)
        installation.launcher.write_bytes(b"Locally edited launcher")
        with self.assertRaisesRegex(ValueError, "customized launcher"):
            installation.install(False)
        self.assertTrue(installation.uninstall())
        self.assertEqual(self.skill.read_bytes(), edited)
        self.assertEqual(installation.launcher.read_bytes(), b"Locally edited launcher")

    def test_skill_helper_collision_refuses_install_before_publication(self):
        helper = self.skill.with_name("keeper-agent")
        helper.parent.mkdir(parents=True)
        helper.write_bytes(b"#!/bin/sh\necho unrelated program\n")
        helper.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "customized skill helper"):
            self.installation.install(False)
        self.assertFalse(self.skill.exists())
        self.assertFalse(self.installation.app.exists())
        self.assertEqual(helper.read_bytes(), b"#!/bin/sh\necho unrelated program\n")
        helper.unlink()
        target = self.root / "elsewhere"
        target.write_bytes(skill_launcher_contents(self.installation.app / "keeper-agent"))
        helper.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "customized skill helper"):
            self.installation.install(False)
        self.assertTrue(helper.is_symlink())
        self.assertFalse(self.skill.exists())

    def test_customized_skill_helper_is_kept_on_uninstall(self):
        self.installation.install(False)
        helper = self.skill.with_name("keeper-agent")
        helper.write_bytes(b"Custom helper")
        with self.assertRaisesRegex(ValueError, "customized skill helper"):
            self.installation.install(False)
        self.assertTrue(self.installation.uninstall())
        self.assertEqual(helper.read_bytes(), b"Custom helper")

    def test_generated_skill_helper_quotes_the_installed_path(self):
        executable = self.root / "trusted path $(touch injected) ' quoted" / "program"
        executable.parent.mkdir()
        executable.write_text("#!/bin/sh\nprintf '%s' \"$1\"\n")
        executable.chmod(0o755)
        helper = self.root / "helper"
        helper.write_bytes(skill_launcher_contents(executable))
        helper.chmod(0o755)
        response = subprocess.run([helper, "literal ; $HOME"], capture_output=True, text=True)
        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertEqual(response.stdout, "literal ; $HOME")
        self.assertFalse((self.root / "injected").exists())

    def test_standalone_skill_install_requires_a_safe_executable_helper(self):
        helper = self.skill.with_name("keeper-agent")
        with patch("keepassxc_agent_access.launcher.skill_destination", return_value=self.skill):
            _install_skill()
            self.assertTrue(self.skill.is_file() and os.access(helper, os.X_OK))
            original_skill = self.skill.read_bytes()
            self.skill.unlink()
            helper.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "customized skill helper"):
                _install_skill()
            self.assertFalse(self.skill.exists())
            helper.chmod(0o755)
            _install_skill()
            self.assertEqual(self.skill.read_bytes(), original_skill)
            self.skill.unlink()
            helper.unlink()
            target = self.root / "unrelated"
            target.write_bytes(b"Unrelated")
            helper.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "customized skill helper"):
                _install_skill()
            self.assertFalse(self.skill.exists())
            self.assertTrue(helper.is_symlink())
            self.assertEqual(target.read_bytes(), b"Unrelated")

    def test_desktop_upgrade_and_uninstall_leave_external_broker_running(self):
        installation = self.installation
        installation.install(False)
        with patch("keepassxc_agent_access.installation.external_broker_active", return_value=True), \
             patch("keepassxc_agent_access.installation.stop_application") as stop:
            installation.install(False)
            self.assertTrue(installation.uninstall())
            stop.assert_not_called()

    def test_agent_install_failure_restores_desktop_install(self):
        installation = self.installation
        installation.install(False)
        self.legacy_skill.parent.mkdir()
        self.skill.rename(self.legacy_skill)
        state = json.loads(installation.manifest.read_bytes())
        state["skill_path"] = str(self.legacy_skill)
        old_state = json.dumps(state).encode()
        installation.manifest.write_bytes(old_state)
        previous_launcher = installation.launcher.read_bytes()
        previous_program = (installation.app / "run-tray").read_bytes()
        helper = self.skill.with_name("keeper-agent")
        previous_helper = helper.read_bytes()
        helper.chmod(0o711)
        failed = subprocess.CalledProcessError(1, ["systemctl"])

        def fail_enable(command, *args, **kwargs):
            if command == "enable":
                raise failed

        with patch.object(installation, "agent_unit", return_value=b"Unit for trial"), \
             patch("keepassxc_agent_access.installation.systemctl", side_effect=fail_enable) as manager, \
             patch("keepassxc_agent_access.installation.skill_launcher_contents", return_value=b"Updated helper contents"):
            with self.assertRaises(subprocess.CalledProcessError):
                installation.install(True)
            manager.assert_any_call("disable", "--now", SERVICE, check=False)
        self.assertFalse(installation.unit.exists())
        self.assertTrue(self.legacy_skill.is_file())
        self.assertFalse(self.skill.exists())
        self.assertEqual(installation.manifest.read_bytes(), old_state)
        self.assertEqual(installation.launcher.read_bytes(), previous_launcher)
        self.assertEqual((installation.app / "run-tray").read_bytes(), previous_program)
        self.assertEqual(helper.read_bytes(), previous_helper)
        self.assertEqual(stat.S_IMODE(helper.stat().st_mode), 0o711)

    def test_agent_upgrade_retains_service_and_uninstall_disables_it(self):
        installation = self.installation
        with patch.object(installation, "agent_unit", return_value=b"Unit for trial"), \
             patch("keepassxc_agent_access.installation.systemctl") as manager:
            launcher, runner = installation.install(True)
            self.assertIn("keeper-open", launcher.read_text())
            self.assertEqual(runner, installation.app / "keeper-run-agent")
            installation.install(False)
            manager.assert_any_call("enable", "--now", SERVICE)
            self.assertTrue(installation.uninstall())
            manager.assert_any_call("disable", "--now", SERVICE)
        self.assertFalse(installation.unit.exists())

    def test_antigravity_skill_install_preserves_custom_edits_and_uninstalls(self):
        ag_skill = self.root / ".gemini/config/skills/keeper/SKILL.md"
        with patch("keepassxc_agent_access.installation.antigravity_skill_destination", return_value=ag_skill):
            self.installation.install(False)
            self.assertTrue(ag_skill.is_file())
            self.assertEqual(ag_skill.read_bytes(), self.skill.read_bytes())
            self.installation.install(False)
            self.assertTrue(self.installation.uninstall())
            self.assertFalse(ag_skill.exists())

            self.installation.install(False)
            custom = b"Locally customized Antigravity Keeper skill"
            ag_skill.write_bytes(custom)
            self.installation.install(False)
            self.assertEqual(ag_skill.read_bytes(), custom)
            self.assertTrue(self.installation.uninstall())
            self.assertEqual(ag_skill.read_bytes(), custom)

    def test_preserves_custom_desktop_icon_while_still_rejecting_custom_exec(self):
        installation = self.installation
        launcher, _ = installation.install(False)
        nightfall = launcher.read_text().replace("Icon=dialog-password", "Icon=nightfall-keeper")
        self.assertEqual(desktop_icon(nightfall), "nightfall-keeper")
        self.assertEqual(normalize_desktop_icon(nightfall), launcher.read_text())
        launcher.write_text(nightfall)

        installation.install(False)
        self.assertIn("Icon=nightfall-keeper", launcher.read_text())

        launcher.write_text(nightfall.replace("Exec=", "Exec=env FOO=1 "))
        with self.assertRaisesRegex(ValueError, "customized launcher"):
            installation.install(False)
        launcher.write_text(nightfall)
        self.assertTrue(installation.uninstall())
        self.assertFalse(launcher.exists())

    def test_connect_agent_install_skips_legacy_wrapper_registers_mcp_and_autostart(self):
        installation = self.installation
        installation.install(False)
        helper = self.skill.with_name("keeper-agent")
        self.assertTrue(helper.exists())

        mcp_config = self.root / ".gemini/config/mcp_config.json"
        mcp_config.parent.mkdir(parents=True)
        mcp_config.write_text(json.dumps({"mcpServers": {"other": {"command": "/bin/true", "args": []}}}))
        with patch("keepassxc_agent_access.installation.antigravity_mcp_config_destination", return_value=mcp_config), \
             patch("keepassxc_agent_access.installation.external_broker_managed", return_value=False), \
             patch("keepassxc_agent_access.installation.systemd_user_available", return_value=True), \
             patch("keepassxc_agent_access.installation.systemctl") as manager:
            installation.install(False, stop_existing=True, connect_agent=True)
            self.assertFalse(helper.exists())
            saved_mcp = json.loads(mcp_config.read_text())
            self.assertEqual(saved_mcp["mcpServers"]["other"], {"command": "/bin/true", "args": []})
            self.assertEqual(saved_mcp["mcpServers"]["keeper"], antigravity_mcp_entry(installation.app / "keeper-connect"))
            self.assertIn(str(installation.app / "keeper-connect"), antigravity_mcp_snippet(installation.app / "keeper-connect"))
            self.assertEqual(installation.desktop_unit.read_bytes(), desktop_service_contents(installation.app))
            manager.assert_any_call("enable", "--now", DESKTOP_SERVICE)

            self.assertTrue(installation.uninstall())
            manager.assert_any_call("disable", "--now", DESKTOP_SERVICE, check=False)
            self.assertFalse(installation.desktop_unit.exists())
            saved_after = json.loads(mcp_config.read_text())
            self.assertEqual(saved_after["mcpServers"], {"other": {"command": "/bin/true", "args": []}})

    def test_connect_agent_preserves_custom_antigravity_mcp_entry(self):
        installation = self.installation
        mcp_config = self.root / ".gemini/config/mcp_config.json"
        mcp_config.parent.mkdir(parents=True)
        custom = {"command": "/custom/keeper", "args": ["--profile", "work"]}
        mcp_config.write_text(json.dumps({"mcpServers": {"keeper": custom}}))
        with patch("keepassxc_agent_access.installation.antigravity_mcp_config_destination", return_value=mcp_config), \
             patch("keepassxc_agent_access.installation.external_broker_managed", return_value=True):
            installation.install(False, stop_existing=True, connect_agent=True)
            self.assertEqual(json.loads(mcp_config.read_text())["mcpServers"]["keeper"], custom)
            self.assertTrue(installation.uninstall())
            self.assertEqual(json.loads(mcp_config.read_text())["mcpServers"]["keeper"], custom)

    def test_agent_setup_upgrade_removes_obsolete_runtime_files(self):
        owner = 1000
        runtime = self.root / f"usr/local/lib/keeper-connect-{owner}"
        old_extra = runtime / "src/keepassxc_agent_access/obsolete.py"
        old_extra.parent.mkdir(parents=True)
        old_extra.write_bytes(b"# removed module")
        old_hashes = {str(old_extra): "a" * 64}
        listener = self.root / f"etc/systemd/system/keeper-connect-{owner}.socket"
        runner = self.root / f"etc/systemd/system/keeper-connect-{owner}@.service"
        tmpfiles = self.root / f"etc/tmpfiles.d/keeper-connect-{owner}.conf"
        record = self.root / f"etc/keeper/connection-{owner}.json"
        listener_bytes, runner_bytes = unit_contents(owner, f"keeper-agent-{owner}",
                                                     Path(f"/run/keeper-broker-{owner}/broker.sock"), runtime)
        record.parent.mkdir(parents=True)
        listener.parent.mkdir(parents=True)
        tmpfiles.parent.mkdir(parents=True)
        import hashlib
        payload = {name: b"data" for name in RUNTIME}
        for name, data in payload.items():
            p = runtime / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            old_hashes[str(p)] = hashlib.sha256(data).hexdigest()
        listener.write_bytes(listener_bytes)
        runner.write_bytes(runner_bytes)
        old_hashes[str(listener)] = hashlib.sha256(listener_bytes).hexdigest()
        old_hashes[str(runner)] = hashlib.sha256(runner_bytes).hexdigest()
        old_hashes[str(old_extra)] = hashlib.sha256(b"# removed module").hexdigest()
        record.write_text(json.dumps({"version": 1, "owner": owner,
                                      "endpoint": f"/run/keeper-broker-{owner}/broker.sock",
                                      "uid": 999, "files": old_hashes}))

        from pwd import struct_passwd
        pw = struct_passwd((f"keeper-agent-{owner}", "x", 999, 999, "", "/nonexistent", "/usr/sbin/nologin"))

        def fake_publish(path, content, mode):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

        with patch("keepassxc_agent_access.agent_setup.connection_record", return_value=record), \
             patch("keepassxc_agent_access.agent_setup.Path", side_effect=lambda *a: self.root / Path(*a).relative_to("/") if str(a[0]).startswith(("/usr/local/lib", "/etc/systemd", "/etc/tmpfiles")) else Path(*a)), \
             patch("keepassxc_agent_access.agent_setup.trusted_file", side_effect=lambda p: p.read_bytes() if p.exists() else None), \
             patch("keepassxc_agent_access.agent_setup.publish", side_effect=fake_publish), \
             patch("keepassxc_agent_access.agent_setup.call"), \
             patch("keepassxc_agent_access.agent_setup.owner_broker", return_value=(Path(f"/run/keeper-broker-{owner}/broker.sock"), pw)):
            admin_setup(owner, None, None, {name: b"new" for name in RUNTIME})
        self.assertFalse(old_extra.exists())

    def test_uninstall_removes_orphaned_connection_when_user_dir_missing(self):
        with patch("sys.argv", ["installation", "uninstall"]), \
             patch("keepassxc_agent_access.installation.os.geteuid", return_value=1000), \
             patch.object(self.installation, "manages_system_connection", return_value=True), \
             patch("keepassxc_agent_access.installation.Installation", return_value=self.installation), \
             patch("keepassxc_agent_access.installation.installed_connection", return_value=object()), \
             patch("keepassxc_agent_access.installation.administer_connection") as admin:
            install_main()
        admin.assert_called_once_with("remove")

    def test_isolated_xdg_uninstall_skips_system_connection_removal(self):
        self.assertFalse(self.installation.manages_system_connection())
        self.installation.install(False)
        with patch("sys.argv", ["installation", "uninstall"]), \
             patch("keepassxc_agent_access.installation.os.geteuid", return_value=1000), \
             patch("keepassxc_agent_access.installation.Installation", return_value=self.installation), \
             patch("keepassxc_agent_access.installation.installed_connection", return_value=object()), \
             patch("keepassxc_agent_access.installation.administer_connection") as admin:
            install_main()
        admin.assert_not_called()
        self.assertFalse(self.installation.app.exists())

    def test_connection_update_needed_compares_runtime_against_source(self):
        runtime = self.root / "usr/local/lib/keeper-connect-1000"
        source = self.root / "src-checkout"
        for name in RUNTIME:
            app_path = "src/keepassxc_agent_access/agent_setup.py" if name == "agent-setup" else name
            (runtime / name).parent.mkdir(parents=True, exist_ok=True)
            (source / app_path).parent.mkdir(parents=True, exist_ok=True)
            (runtime / name).write_bytes(b"same")
            (source / app_path).write_bytes(b"same")

        real_path = Path
        with patch("keepassxc_agent_access.installation.installed_connection", return_value=object()), \
             patch("keepassxc_agent_access.installation.os.getuid", return_value=1000), \
             patch("keepassxc_agent_access.installation.Path",
                   side_effect=lambda p: runtime if str(p) == "/usr/local/lib/keeper-connect-1000" else real_path(p)):
            self.assertFalse(self.installation.connection_update_needed(source))
            (source / "keepassxc-agent").write_bytes(b"changed")
            self.assertTrue(self.installation.connection_update_needed(source))


if __name__ == "__main__":
    unittest.main()
