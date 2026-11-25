from contextlib import contextmanager
import hashlib
import ipaddress
import os
from pathlib import Path
import socket
import subprocess
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
from unittest import TestCase, skipUnless
from unittest.mock import Mock, patch

from pykeepass import create_database

from keepassxc_agent_access.access_settings import Action, ActionType, Destination
from keepassxc_agent_access.command_action import (
    _TASK_LIMIT, deliver_credential, executable_digest, prepare_command, sandbox_arguments, verify_scope_limits,
)
from keepassxc_agent_access.command_network import Relay, approved_address, approved_addresses, connection_target
from keepassxc_agent_access.command_prompt import askpass, launch, proxy_stdio
from keepassxc_agent_access.protocol import ListingError, UPLOAD_LIMIT, encode, validate_command, validate_upload
from keepassxc_agent_access.vault import VaultSession, VaultTarget, open_vault
from keepassxc_agent_access import vault_worker


class LocalCommandTests(TestCase):
    def test_command_uses_literal_arguments_and_requires_a_trusted_executable(self):
        command = ("/usr/bin/cat", "one literal argument")
        self.assertEqual(validate_command(list(command)), command)
        for invalid in (("cat",), ("/tmp/tool",), ("/usr/bin/../tool",), ("/usr/bin/cat", "x\ny")):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_command(invalid)

    def test_network_scope_accepts_an_origin_and_pins_the_prompt_and_input_policy(self):
        entry = "229b7a79-bcb0-450c-a320-bfccdd672f75"
        details = {"kind": ActionType.NETWORK_PROMPT, "command": ("/usr/bin/true",),
                   "executable_sha256": "0" * 64, "prompt_variable": "TOOL_ASKPASS"}
        action = Action("network", "Network check", entry, "https://example.invalid", **details)
        attached = Action("network", "Network check", entry, "https://example.invalid", accepts_input=True, **details)
        self.assertNotEqual(action.scope, attached.scope)
        with self.assertRaisesRegex(ValueError, "HTTPS origin"):
            Action("network", "Network check", entry, "https://example.invalid/repository", **details)

    def test_prompt_cannot_supply_a_password_for_a_username_role(self):
        with patch("keepassxc_agent_access.command_prompt.socket.socket") as connect:
            self.assertEqual(askpass("Username for the fixture:"), 1)
            connect.assert_not_called()

    def test_upload_descriptor_bounds_input_and_rejects_paths(self):
        description = {"size": UPLOAD_LIMIT, "sha256": "a" * 64}
        self.assertEqual(validate_upload(description), description)
        for invalid in ({**description, "size": UPLOAD_LIMIT + 1}, {**description, "path": "/tmp/fixture"},
                        {**description, "sha256": "unknown"}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_upload(invalid)

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

    def test_sandbox_binds_system_ca_and_raises_task_limit(self):
        self.assertEqual(_TASK_LIMIT, 64)
        arguments = sandbox_arguments(("/usr/bin/true",), 7, "fixture.scope",
                                      relay_path=Path("/tmp/relay"), prompt_variable="GIT_ASKPASS",
                                      ca_file=Path("/tmp/custom-ca.pem"))
        pairs = list(zip(arguments, arguments[1:], arguments[2:]))
        self.assertIn(("--ro-bind", "/tmp/custom-ca.pem", "/keeper/trust.pem"), pairs)
        self.assertIn(("--ro-bind", "/tmp/custom-ca.pem", "/etc/ssl/certs/ca-certificates.crt"), pairs)

    def test_verify_scope_limits_includes_task_limit_detail(self):
        files = {"cgroup": "0::/user.slice/fixture.scope\n", "memory.max": str(192 * 1024**2),
                 "memory.swap.max": "0", "pids.max": "65", "cpu.max": "100000 100000"}
        with patch.object(Path, "read_text", autospec=True, side_effect=lambda path: files[path.name]):
            with self.assertRaisesRegex(OSError, "pids.max=65"):
                verify_scope_limits(123, "fixture.scope")

    def test_prepare_command_captures_pre_ready_stderr_and_allows_unix_socketpair(self):
        class FakeProcess:
            pid = 4242

            def __init__(self, _args, *, stderr, **_kwargs):
                self.stdin = Mock()
                self.stdout = Mock()
                self.stdout.fileno.return_value = 99
                stderr.write(b"bwrap: setting up uid map failed\n")
                stderr.flush()

            def poll(self):
                return 1

            def wait(self):
                return 1

        with patch("keepassxc_agent_access.command_action.executable_digest", return_value="0" * 64), \
             patch("keepassxc_agent_access.command_action.syscall_filter") as sc_filter, \
             patch("keepassxc_agent_access.command_action.subprocess.Popen", side_effect=FakeProcess), \
             patch("keepassxc_agent_access.command_action.select", return_value=([99], [], [])), \
             patch("keepassxc_agent_access.command_action.os.read", return_value=b""), \
             patch("keepassxc_agent_access.command_action.stop_scope"):
            sc_filter.return_value.__enter__.return_value = 5
            with self.assertRaisesRegex(OSError, "bwrap: setting up uid map failed"):
                with prepare_command(("/usr/bin/true",), "0" * 64):
                    self.fail("Should not yield after startup failure")
            sc_filter.assert_called_once_with(unix_sockets=False, unix_socket_pairs=True)

    def test_approved_addresses_and_relay_fall_back_across_resolved_ips(self):
        getent_out = (
            "2001:db8::1     STREAM api.example.test\n"
            "2001:db8::1     DGRAM  \n"
            "198.51.100.10   STREAM api.example.test\n"
        )
        completed = subprocess.CompletedProcess(["getent"], 0, stdout=getent_out)
        with patch("keepassxc_agent_access.command_network.subprocess.run", return_value=completed):
            resolved = approved_addresses("api.example.test")
            self.assertEqual(resolved, (ipaddress.ip_address("2001:db8::1"), ipaddress.ip_address("198.51.100.10")))
            self.assertEqual(approved_address("api.example.test"), resolved[0])

        with patch("keepassxc_agent_access.command_network.approved_addresses", return_value=resolved):
            relay = Relay(Destination.parse("https://api.example.test/"))
        self.assertEqual(relay.addresses, resolved)
        self.assertEqual(relay.address, resolved[0])

        attempted = []
        created = []

        class FakeSocket:
            def __init__(self, family, _kind):
                self.family = family
                self.closed = False
                created.append(self)

            def settimeout(self, _value):
                pass

            def connect(self, addr):
                attempted.append(addr)
                if addr[0] == "2001:db8::1":
                    raise OSError("Network unreachable")

            def close(self):
                self.closed = True

        client = Mock()
        with patch("keepassxc_agent_access.command_network.connection_target", return_value=("api.example.test", 443)), \
             patch("keepassxc_agent_access.command_network.socket.socket", side_effect=FakeSocket), \
             patch.object(relay, "forward") as forward:
            relay.connect(client)
        self.assertEqual(attempted, [("2001:db8::1", 443), ("198.51.100.10", 443)])
        self.assertTrue(created[0].closed)
        forward.assert_called_once_with(client, created[1])

    def test_opaque_command_pre_dispatch_failure_returns_unavailable_with_detail(self):
        entry = SimpleNamespace(password="secret")
        frames = []
        with patch.object(vault_worker, "reply", side_effect=frames.append), \
             patch.object(vault_worker, "prepare_command", side_effect=OSError("bwrap: missing userns\n\x00")), \
             patch("keepassxc_agent_access.vault_worker.sys.stdin") as fake_stdin:
            vault_worker.use_command(entry, ("/usr/bin/true",), "0" * 64, opaque=True)
            fake_stdin.buffer.readline.assert_not_called()
        self.assertEqual(frames, [encode({"error": "unavailable", "detail": "bwrap: missing userns"})])

        session = VaultSession(Mock())
        action = Action("agent-request", "Local Command", "229b7a79-bcb0-450c-a320-bfccdd672f75", "",
                        kind=ActionType.STDIN, command=("/usr/bin/true",), executable_sha256="0" * 64, opaque=True)

        @contextmanager
        def exchange(_request, _timeout):
            yield lambda: frames[0]

        with patch.object(session, "_exchange", side_effect=exchange):
            with self.assertRaises(ListingError) as error:
                session.use(action, lambda _: True)
        self.assertEqual(error.exception.code, "unavailable")
        self.assertEqual(error.exception.detail, "bwrap: missing userns")

        # Post-dispatch failures still hide details and return dispatched for opaque commands.
        frames.clear()

        @contextmanager
        def post_dispatch_prepare(*_args, **_kwargs):
            yield Mock()

        with patch.object(vault_worker, "reply", side_effect=frames.append), \
             patch.object(vault_worker, "prepare_command", side_effect=post_dispatch_prepare), \
             patch.object(vault_worker, "deliver_credential", side_effect=OSError("secret stderr")), \
             patch("keepassxc_agent_access.vault_worker.sys.stdin") as fake_stdin:
            fake_stdin.buffer.readline.return_value = b"dispatch\n"
            vault_worker.use_command(entry, ("/usr/bin/true",), "0" * 64, opaque=True)
        self.assertEqual(frames, [encode({"ready": True}), encode({"outcome": "failed"})])

    def test_sandbox_synthetic_etc_and_fsize_and_ipv6_relay_and_askpass(self):
        with TemporaryDirectory() as directory:
            etc_dir = Path(directory) / "etc"
            etc_dir.mkdir()
            (etc_dir / "passwd").write_text("keeper:x:1000:1000:Keeper:/tmp:/usr/bin/sh\n")
            arguments = sandbox_arguments(("/usr/bin/ssh",), 7, "fixture.scope",
                                          relay_path=Path("/tmp/relay"), prompt_variable="SSH_ASKPASS",
                                          etc_dir=etc_dir)
            self.assertIn("--fsize=16777216:16777216", arguments)
            triples = list(zip(arguments, arguments[1:], arguments[2:]))
            self.assertIn(("--ro-bind", str(etc_dir / "passwd"), "/etc/passwd"), triples)

        # ATYP=3 IPv6 literals are normalized so Relay accepts ::1 and [::1].
        pair_a, pair_b = socket.socketpair()
        with pair_a, pair_b:
            pair_b.sendall(b"\x05\x01\x00" + b"\x05\x01\x00\x03\x08[0:0::1]\x00\x16")
            self.assertEqual(connection_target(pair_a), ("::1", 22))
            self.assertEqual(pair_b.recv(2), b"\x05\x00")

        # Multi-line generic password prompts are allowed, while username prompts remain blocked.
        with patch.dict(os.environ, {"KEEPER_GENERIC_PROMPT": "1", "KEEPER_PROMPT_CONTAINS": "password"}, clear=False):
            with patch("keepassxc_agent_access.command_prompt.socket.socket") as connect:
                self.assertEqual(askpass("Host notice\nEnter username: "), 1)
                connect.assert_not_called()
                connect.return_value.__enter__.return_value.makefile.return_value.__enter__.return_value.read.side_effect = [
                    b"\x00\x03", b"xyz",
                ]
                self.assertEqual(askpass("Host notice\nEnter password: "), 0)
                connect.assert_called_once()
