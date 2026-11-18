import json
import os
import stat
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from keepassxc_agent_access.installation import Installation, SERVICE
from keepassxc_agent_access.agent_setup import unit_contents
from keepassxc_agent_access.launcher import desktop_contents, skill_launcher_contents, _install_skill


class InstallationTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
