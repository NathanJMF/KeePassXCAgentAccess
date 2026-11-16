from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from keepassxc_agent_access.installation import Installation, SERVICE
from keepassxc_agent_access.launcher import desktop_contents


class InstallationTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.skill = self.root / "Documents/Skills/keepassxc-agent-access/SKILL.md"
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
        installation.install(False)
        self.assertTrue(installation.uninstall())
        self.assertFalse(launcher.exists() or self.skill.exists() or installation.app.exists())
        self.assertFalse(installation.uninstall())

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
        old_state = installation.manifest.read_bytes()
        previous_launcher = installation.launcher.read_bytes()
        previous_program = (installation.app / "run-tray").read_bytes()
        failed = subprocess.CalledProcessError(1, ["systemctl"])

        def fail_enable(command, *args, **kwargs):
            if command == "enable":
                raise failed

        with patch.object(installation, "agent_unit", return_value=b"Unit for trial"), \
             patch("keepassxc_agent_access.installation.systemctl", side_effect=fail_enable) as manager:
            with self.assertRaises(subprocess.CalledProcessError):
                installation.install(True)
            manager.assert_any_call("disable", "--now", SERVICE, check=False)
        self.assertFalse(installation.unit.exists())
        self.assertEqual(installation.manifest.read_bytes(), old_state)
        self.assertEqual(installation.launcher.read_bytes(), previous_launcher)
        self.assertEqual((installation.app / "run-tray").read_bytes(), previous_program)

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
