from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from keepassxc_agent_access.updates import UpdateError, apply_update, check_for_update


class UpdateTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.base = self.root / "managed"
        self.base.mkdir(mode=0o700)
        self.publisher = self.base / "upstream"
        self.publisher.mkdir()
        self.git(self.publisher, "init", "--initial-branch=main")
        installer = self.publisher / "install"
        installer.write_text('#!/bin/sh\nprintf installed > install-result\nprintf "%s\\n" "$@" > install-args\n')
        installer.chmod(0o755)
        self.first = self.commit("Initial revision")
        self.checkout = self.base / "update-source"
        self.git(self.root, "clone", str(self.publisher), str(self.checkout))
        self.checkout.chmod(0o700)
        self.state = {"update_url": str(self.publisher), "update_ref": "refs/heads/main", "revision": self.first}
        self.installation = SimpleNamespace(installed=lambda: self.state, app=self.checkout,
                                            base=self.base, update_source=self.checkout)

    @staticmethod
    def git(directory, *args):
        return subprocess.run(["git", "-C", str(directory), *args], text=True, check=True,
                              capture_output=True).stdout.strip()

    def commit(self, name):
        (self.publisher / "version").write_text(name)
        self.git(self.publisher, "add", ".")
        self.git(self.publisher, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-m", name)
        return self.git(self.publisher, "rev-parse", "HEAD")

    def test_checks_latest_without_mutating_checkout_and_applies_exact_commit(self):
        self.assertEqual(check_for_update(self.installation).target, self.first)
        target = self.commit("New release")
        checked = check_for_update(self.installation)
        self.assertEqual(checked.target, target)
        self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD"), self.first)
        self.assertFalse((self.checkout / "install-result").exists())
        with patch("keepassxc_agent_access.updates.external_broker_active", return_value=False), \
             patch.dict(self.state, unit="fixture"), patch("keepassxc_agent_access.updates.present_application") as reopen:
            self.assertEqual(apply_update(self.installation, checked), "Keeper was updated.")
            reopen.assert_called_once_with()
        self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD"), target)
        self.assertEqual((self.checkout / "version").read_text(), "New release")
        self.assertEqual((self.checkout / "install-result").read_text(), "installed")
        self.assertEqual((self.checkout / "install-args").read_text().splitlines(), ["--no-launch", "--agent"])

    def test_dirty_installation_is_not_reported_up_to_date(self):
        self.state["source_dirty"] = True
        with self.assertRaisesRegex(UpdateError, "local changes"):
            check_for_update(self.installation)

    def test_legacy_workspace_update_source_requires_new_install(self):
        self.state = {"checkout": str(self.checkout), "revision": self.first}
        with self.assertRaisesRegex(UpdateError, "trusted Keeper checkout"):
            check_for_update(self.installation)

    def test_refuses_dirty_checkout_and_preserves_local_changes(self):
        self.commit("Remote update")
        file = self.checkout / "version"
        file.write_text("Local work")
        with self.assertRaisesRegex(UpdateError, "local changes"):
            apply_update(self.installation, check_for_update(self.installation))
        self.assertEqual(file.read_text(), "Local work")
        self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD"), self.first)

    def test_refuses_update_when_remote_advances_after_check(self):
        self.commit("First update")
        checked = check_for_update(self.installation)
        self.commit("Second update")
        with self.assertRaisesRegex(UpdateError, "changed"):
            apply_update(self.installation, checked)
        self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD"), self.first)

    def test_refuses_diverged_checkout(self):
        self.commit("Remote work")
        file = self.checkout / "local"
        file.write_text("Local work")
        self.git(self.checkout, "add", "local")
        self.git(self.checkout, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-m", "Local commit")
        head = self.git(self.checkout, "rev-parse", "HEAD")
        with self.assertRaisesRegex(UpdateError, "fast-forwarded"):
            apply_update(self.installation, check_for_update(self.installation))
        self.assertEqual(self.git(self.checkout, "rev-parse", "HEAD"), head)


if __name__ == "__main__":
    unittest.main()
