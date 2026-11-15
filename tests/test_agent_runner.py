import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import stat
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
from unittest import TestCase

from keepassxc_agent_access.agent_runner import inherited_directory_fds, invocation
from keepassxc_agent_access.protocol import decode, encode
from keepassxc_agent_access.runner_token import credential


RUNNER = Path(__file__).resolve().parents[1] / "keeper-agent-runner"
MISSING = {"status": "uninitialized"}


def frame(method, params=None, *, identifier=1):
    return {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params or {}}


def call_tool(name, arguments=None, *, identifier=1):
    return frame("tools/call", {"name": name, "arguments": arguments or {}}, identifier=identifier)


def payload(reply):
    result = reply["result"]
    assert not result["isError"], result
    return json.loads(result["content"][0]["text"])


class RunnerTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory(dir="/tmp")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.endpoint = self.root / "keeper.sock"
        self.profile = self.root / "agent-profile"

    def run_server(self, *messages, profile=None, environment=None):
        result = subprocess.run(
            [RUNNER, "--socket", self.endpoint, "--profile-dir", profile or self.profile],
            env=environment, input=b"".join(encode(message) for message in messages),
            capture_output=True, check=False, timeout=12,
        )
        return result, [decode(line) for line in result.stdout.splitlines()]

    def test_tools_and_uninitialized_status_keep_profile_private_and_empty(self):
        result, replies = self.run_server(
            frame("initialize", {"protocolVersion": "2025-06-18"}, identifier=1),
            frame("tools/list", identifier=2),
            call_tool("access_status", identifier=3),
            environment={**os.environ, "KEEPASSXC_AGENT_TOKEN_FILE": str(self.root / "wrong")},
        )
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        self.assertEqual(replies[0]["result"]["serverInfo"]["name"], "Keeper")
        self.assertEqual(replies[0]["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual({tool["name"] for tool in replies[1]["result"]["tools"]},
                         {"access_status", "request_access", "request_edit", "edit_status",
                          "list_vaults", "list_entries", "use_password"})
        self.assertEqual(payload(replies[2]), MISSING)
        self.assertEqual(stat.S_IMODE(self.profile.stat().st_mode), 0o700)
        self.assertEqual(list(self.profile.iterdir()), [])

    def test_unsafe_profiles_fail_distinctly(self):
        self.profile.mkdir()
        self.profile.chmod(0o755)
        link = self.root / "profile-link"
        link.symlink_to(self.profile, target_is_directory=True)
        for profile in (self.profile, link):
            with self.subTest(profile=profile):
                result, replies = self.run_server(call_tool("access_status"), profile=profile)
                self.assertEqual((result.returncode, replies), (1, []))
                self.assertIn(b"private runner-owned directory", result.stderr)
        self.profile.chmod(0o700)
        (self.profile / "token").write_bytes(b"invalid synthetic token")
        result, replies = self.run_server(call_tool("access_status"))
        self.assertEqual(result.returncode, 0)
        self.assertTrue(replies[0]["result"]["isError"])
        self.assertIn("unavailable or unsafe", replies[0]["result"]["content"][0]["text"])

    def test_runner_rejects_non_keeper_operations_and_credential_access(self):
        requests = [
            call_tool("run_shell", {"command": "cat token"}, identifier=1),
            call_tool("access_status", {"token_file": "arbitrary-path"}, identifier=2),
            call_tool("list_entries", {"fields": ["password"]}, identifier=3),
            call_tool("request_access", {"request": "payload"}, identifier=4),
            call_tool("use_password", {"entry": "invalid", "action": "alternate"}, identifier=5),
        ]
        result, replies = self.run_server(*requests)
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        self.assertEqual(len(replies), len(requests))
        for reply in replies:
            self.assertEqual(reply["result"],
                             {"content": [{"type": "text", "text": "Invalid Keeper tool or arguments."}],
                              "isError": True})
        self.assertEqual(list(self.profile.iterdir()), [])

    def test_edit_tools_pass_only_typed_arguments_to_the_cli(self):
        request_id = "229b7a79-bcb0-450c-a320-bfccdd672f75"
        example = {"id": request_id, "operation": "replace_password", "vault": request_id,
                   "entry": request_id, "password_source": "generate"}
        args, data = invocation("request_edit", {"request": example})
        self.assertEqual(args[1:], ["edits", "request", "--json"])
        self.assertEqual(decode(data), example)
        args, data = invocation("edit_status", {"id": request_id})
        self.assertEqual(args[1:], ["edits", "status", "--json", f"--request={request_id}"])
        self.assertEqual(data, b"")
        result, replies = self.run_server(
            call_tool("request_edit", {"request": {**example, "password": "synthetic-secret"}}, identifier=1),
            call_tool("edit_status", {"id": "--help"}, identifier=2),
        )
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        self.assertNotIn(b"synthetic-secret", result.stdout)
        self.assertTrue(all(row["result"]["isError"] for row in replies))
        self.assertEqual(list(self.profile.iterdir()), [])

    def test_permission_change_requires_an_initialized_profile(self):
        request = {"identity": "Fixture", "project": "Fixture",
                   "items": [{"label": "Fixture", "metadata": True}],
                   "change_id": "229b7a79-bcb0-450c-a320-bfccdd672f75"}
        result, replies = self.run_server(call_tool("request_access", {"request": request}))
        self.assertEqual(result.returncode, 0)
        self.assertTrue(replies[0]["result"]["isError"])
        self.assertEqual(list(self.profile.iterdir()), [])

    def test_enrollment_retains_the_same_credential_across_runner_restarts(self):
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(self.endpoint))
            listener.listen()
            listener.settimeout(8)
            observed = []

            def serve():
                for response in ({"status": "pending"}, {"status": "active"}):
                    connection, _ = listener.accept()
                    with connection, connection.makefile("rb") as stream:
                        observed.append(decode(stream.readline()))
                        connection.sendall(encode(response))

            thread = Thread(target=serve, daemon=True)
            thread.start()
            scope = {"identity": "Fixture", "project": "Fixture", "items": [{"label": "Fixture", "metadata": True}]}
            enrolled, replies = self.run_server(call_tool("request_access", {"request": scope}))
            self.assertEqual(payload(replies[0]), {"status": "pending"})
            checked, replies = self.run_server(call_tool("access_status"))
            self.assertEqual(payload(replies[0]), {"status": "active"})
            thread.join(8)
            self.assertEqual([request["operation"] for request in observed], ["request_access", "access_status"])
            self.assertEqual(observed[0]["request"], scope)
            token = observed[0]["credential"]
            self.assertEqual(observed[1]["credential"], token)
            self.assertEqual(stat.S_IMODE((self.profile / "token").stat().st_mode), 0o600)
            self.assertNotIn(token.encode(), enrolled.stdout + checked.stdout + enrolled.stderr + checked.stderr)

    def test_tool_child_inherits_only_configured_directory_descriptors(self):
        directories = [self.root / name for name in ("broker-path", "profile-path")]
        for path in directories:
            path.mkdir(mode=0o700)
        socket_anchor, profile_anchor = fds = tuple(os.open(path, os.O_PATH | os.O_DIRECTORY) for path in directories)
        for fd in fds:
            self.addCleanup(os.close, fd)
        endpoint = Path(f"/proc/self/fd/{socket_anchor}/keeper.sock")
        profile = Path(f"/proc/self/fd/{profile_anchor}/agent-profile")
        self.assertEqual(inherited_directory_fds(endpoint, profile, fds), tuple(sorted(fds)))
        invalid = ((), (socket_anchor,), (*fds, profile_anchor))
        for supplied in invalid:
            with self.subTest(supplied=supplied), self.assertRaises(ValueError):
                inherited_directory_fds(endpoint, profile, supplied)
        with open(self.root / "regular-file", "w") as file:
            with self.assertRaises(ValueError):
                inherited_directory_fds(Path(f"/proc/self/fd/{file.fileno()}/keeper.sock"), profile,
                                        (file.fileno(), profile_anchor))

        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(directories[0] / "keeper.sock"))
            listener.listen()
            listener.settimeout(8)
            calls = []

            def serve():
                connection, _ = listener.accept()
                with connection, connection.makefile("rb") as stream:
                    calls.append(decode(stream.readline())["operation"])
                    connection.sendall(encode({"status": "pending"}))

            thread = Thread(target=serve, daemon=True)
            thread.start()
            request = call_tool("request_access", {"request": {"identity": "Fixture", "project": "Fixture",
                                                               "items": [{"label": "Fixture", "metadata": True}]}})
            result = subprocess.run(
                [RUNNER, "--socket", endpoint, "--profile-dir", profile,
                 "--inherit-directory-fd", str(socket_anchor), "--inherit-directory-fd", str(profile_anchor)],
                input=encode(request), pass_fds=fds, capture_output=True, check=False, timeout=12,
            )
            self.assertEqual((result.returncode, result.stderr), (0, b""))
            self.assertEqual(payload(decode(result.stdout)), {"status": "pending"})
            thread.join(8)
            self.assertEqual(calls, ["request_access"])
            self.assertEqual(stat.S_IMODE((directories[1] / "agent-profile" / "token").stat().st_mode), 0o600)

    def test_concurrent_initialization_yields_one_private_token(self):
        self.profile.mkdir(mode=0o700)
        path = self.profile / "token"
        with ThreadPoolExecutor(max_workers=8) as workers:
            results = list(workers.map(lambda _: credential(path, create=True), range(32)))
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(list(self.profile.iterdir()), [path])
        self.assertEqual(path.stat().st_nlink, 1)
