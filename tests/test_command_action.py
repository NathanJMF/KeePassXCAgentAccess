import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from unittest import TestCase, skipUnless
from unittest.mock import patch

from pykeepass import create_database

from keepassxc_agent_access.access_settings import Action, ActionType
from keepassxc_agent_access.command_action import deliver_credential, executable_digest, prepare_command, verify_scope_limits
from keepassxc_agent_access.protocol import ListingError, validate_command
from keepassxc_agent_access.vault import VaultTarget, open_vault


class LocalCommandTests(TestCase):
    def test_command_uses_literal_arguments_and_requires_a_trusted_executable(self):
        command = ("/usr/bin/cat", "one literal argument")
        self.assertEqual(validate_command(list(command)), command)
        for invalid in (("cat",), ("/tmp/tool",), ("/usr/bin/../tool",), ("/usr/bin/cat", "x\ny")):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_command(invalid)

    def test_changed_executable_fails_before_starting_sandbox(self):
        with patch("keepassxc_agent_access.command_action.executable_digest", return_value="a" * 64), \
             patch("keepassxc_agent_access.command_action.subprocess.Popen") as launch:
            with self.assertRaisesRegex(ValueError, "executable changed"):
                with prepare_command(("/usr/bin/cat",), "0" * 64):
                    self.fail("The command should be rejected before startup")
            launch.assert_not_called()

    def test_scope_rejects_unbounded_swap(self):
        files = {"cgroup": "0::/user.slice/fixture.scope\n", "memory.max": str(192 * 1024**2),
                 "memory.swap.max": "max", "pids.max": "16", "cpu.max": "100000 100000"}
        with patch.object(Path, "read_text", autospec=True, side_effect=lambda path: files[path.name]):
            with self.assertRaisesRegex(OSError, "resource limits are unavailable"):
                verify_scope_limits(123, "fixture.scope")
            files["memory.swap.max"] = "0"
            verify_scope_limits(123, "fixture.scope")

    @skipUnless(os.environ.get("KEEPER_TEST_LOCAL_SANDBOX") == "1", "Needs the desktop's systemd user manager")
    def test_timed_out_command_is_reaped(self):
        command = ("/usr/bin/sleep", "10")
        with patch("keepassxc_agent_access.command_action._COMMAND_TIMEOUT", .2):
            with prepare_command(command, executable_digest(command)) as process:
                self.assertFalse(deliver_credential(process, "disposable command timeout fixture"))
        self.assertIsNotNone(process.poll())

    @skipUnless(os.environ.get("KEEPER_TEST_LOCAL_SANDBOX") == "1", "Needs the desktop's systemd user manager")
    def test_vault_worker_delivers_only_inside_the_local_sandbox(self):
        with TemporaryDirectory() as directory:
            target = Path(directory) / "synthetic.kdbx"
            marker = Path(directory) / "synthetic-host-marker"
            marker.touch()
            secret = "synthetic stdin credential"
            unlock = "synthetic vault unlock"
            database = create_database(target, unlock)
            entry = database.add_entry(database.root_group, "Synthetic command", "", secret)
            database.save()
            digest = hashlib.sha256(secret.encode()).hexdigest()
            check = "import hashlib,sys;d=sys.stdin.buffer.read();print(d);sys.exit(hashlib.sha256(d).hexdigest()!=sys.argv[1])"
            checks = [
                ("/usr/bin/python3", "-I", "-c", check, digest),
                ("/usr/bin/test", "!", "-e", str(marker)),
                ("/usr/bin/python3", "-I", "-c", "import sys;sys.exit(sys.argv[1]!=chr(36)+'{INVOCATION_ID}')",
                 "${INVOCATION_ID}"),
                ("/usr/bin/python3", "-I", "-c", "import socket;socket.socket()"),
            ]

            def approve(send):
                send()
                return True

            with open_vault(VaultTarget(target), unlock, Event()) as worker:
                for number, command in enumerate(checks):
                    action = Action("local", "Synthetic command", str(entry.uuid), "", kind=ActionType.STDIN,
                                    command=command, executable_sha256=executable_digest(command))
                    if number == 0:
                        with self.assertRaises(ListingError) as error:
                            worker.use(action, lambda _: False)
                        self.assertEqual(error.exception.code, "revoked")
                    expected = "failed" if number == len(checks) - 1 else "succeeded"
                    self.assertEqual(worker.use(action, approve), {"outcome": expected})
