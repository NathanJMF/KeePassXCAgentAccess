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

from keepassxc_agent_access.agent_runner import AgentRunner, inherited_directory_fds, invocation
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
    def test_project_profiles_follow_thread_metadata_and_reject_missing_ids(self):
        from hashlib import sha256

        def request(thread):
            message = call_tool("access_status")
            if thread is not None:
                message["params"]["_meta"] = {"threadId": thread}
            return message

        def run(*messages):
            result = subprocess.run(
                [RUNNER, "--socket", self.endpoint, "--project-profiles", self.profile],
                input=b"".join(encode(message) for message in messages), capture_output=True, check=True, timeout=12,
            )
            return [decode(line) for line in result.stdout.splitlines()]

        first, second = "thread-project-one", "thread-project-two"
        first_profile = self.profile / sha256(first.encode("ascii")).hexdigest()
        replies = run(request(None), request("../profile"), request(first), request(second), request(first))
        self.assertTrue(replies[0]["result"]["isError"])
        self.assertTrue(replies[1]["result"]["isError"])
        self.assertEqual([payload(reply) for reply in replies[2:]], [MISSING] * 3)
        self.assertEqual(len(list(self.profile.iterdir())), 2)
        self.assertEqual(stat.S_IMODE(first_profile.stat().st_mode), 0o700)
        self.assertFalse((first_profile / "token").exists())

    def test_generic_mcp_profile_names_are_optional_and_persist_across_connections(self):
        from hashlib import sha256

        def run(*messages):
            result = subprocess.run(
                [RUNNER, "--socket", self.endpoint, "--project-profiles", self.profile, "--connection-profiles"],
                input=b"".join(encode(message) for message in messages), capture_output=True, check=True, timeout=12,
            )
            return [decode(line) for line in result.stdout.splitlines()]

        self.assertEqual(payload(run(call_tool("access_status"))[0]), MISSING)
        self.assertEqual(list(self.profile.iterdir()), [])
        select = {"jsonrpc": "2.0", "method": "keeper/profile", "params": {"name": "Workspace-One"}}
        for _ in range(2):
            self.assertEqual(payload(run(select, frame("initialize"), call_tool("access_status"))[-1]), MISSING)
        named = self.profile / sha256(b"connection:Workspace-One").hexdigest()
        self.assertEqual(list(self.profile.iterdir()), [named])
        self.assertEqual(stat.S_IMODE(named.stat().st_mode), 0o700)

    def test_connection_profiles_support_per_task_profile_argument_and_persist_across_reconnects(self):
        from hashlib import sha256

        def run(*messages):
            result = subprocess.run(
                [RUNNER, "--socket", self.endpoint, "--project-profiles", self.profile, "--connection-profiles"],
                input=b"".join(encode(message) for message in messages), capture_output=True, check=True, timeout=12,
            )
            return [decode(line) for line in result.stdout.splitlines()]

        first = run(call_tool("access_status", {"profile": "conv-alpha"}))
        second = run(call_tool("access_status", {"profile": "conv-beta"}))
        again = run(call_tool("access_status", {"profile": "conv-alpha"}))
        self.assertEqual([payload(r[0]) for r in (first, second, again)], [MISSING] * 3)
        alpha_dir = self.profile / sha256(b"task:conv-alpha").hexdigest()
        beta_dir = self.profile / sha256(b"task:conv-beta").hexdigest()
        self.assertEqual(set(self.profile.iterdir()), {alpha_dir, beta_dir})
        self.assertEqual(stat.S_IMODE(alpha_dir.stat().st_mode), 0o700)

        invalid = run(call_tool("access_status", {"profile": "../escape"}))[0]
        self.assertTrue(invalid["result"]["isError"])

        with_meta = call_tool("access_status", {"profile": "ignored-when-meta-present"})
        with_meta["params"]["_meta"] = {"conversationId": "host-conv-123"}
        self.assertEqual(payload(run(with_meta)[0]), MISSING)
        self.assertTrue((self.profile / sha256(b"host-conv-123").hexdigest()).is_dir())

    def test_request_access_allows_omitting_identity_and_project_only_with_change_id(self):
        from uuid import uuid4

        change_id = str(uuid4())
        args, data = invocation("request_access", {
            "request": {"change_id": change_id, "items": [{"label": "Fixture", "metadata": True}]},
        })
        self.assertEqual(args[1:], ["access", "request", "--json"])
        self.assertEqual(decode(data)["change_id"], change_id)
        with self.assertRaises(ValueError):
            invocation("request_access", {"request": {"items": [{"label": "Fixture", "metadata": True}]}})

    def test_workflow_registration_cannot_replace_host_identity_or_fill_empty_host_values(self):
        from unittest.mock import patch
        from uuid import uuid4

        for identity, project in (("Host assigned identity", "Fixture"), ("", "")):
            with self.subTest(identity=identity), patch.dict(os.environ, KEEPASSXC_AGENT_IDENTITY=identity,
                                                             KEEPASSXC_AGENT_PROJECT=project):
                runner = AgentRunner(self.endpoint, self.profile)
                reply = runner.call_tool({"name": "workflow_request", "arguments": {
                    "request": {"id": str(uuid4())}, "registration": {"identity": "Other identity", "project": "Fixture"},
                }})
                self.assertTrue(reply["isError"])
                self.assertIn("rejected", reply["content"][0]["text"])
                self.assertFalse((self.profile / "token").exists())

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
        self.assertTrue(replies[0]["result"]["instructions"])
        self.assertEqual({tool["name"] for tool in replies[1]["result"]["tools"]},
                         {"discover", "access_status", "request_access", "release_entry", "request_edit", "edit_status",
                          "list_vaults", "list_entries", "use_password", "write_status", "guest_run", "guest_status",
                          "guest_release", "guest_wait", "console_open", "console_view", "console_wait", "console_input",
                          "console_close", "workflow_request", "workflow_status", "workflow_run", "provision_account"})
        self.assertEqual(payload(replies[2]), MISSING)
        self.assertEqual(stat.S_IMODE(self.profile.stat().st_mode), 0o700)
        self.assertEqual(list(self.profile.iterdir()), [])

    def test_launchers_start_with_isolated_python_from_an_unrelated_directory(self):
        environment = {**os.environ, "PYTHONHOME": str(self.root / "missing"), "PYTHONPATH": str(self.root)}
        for executable in ("keeper-run-agent", "keeper-agent-runner", "keepassxc-agent"):
            with self.subTest(executable=executable):
                result = subprocess.run([RUNNER.with_name(executable), "--help"], cwd=self.root,
                                        env=environment, capture_output=True, check=True, timeout=5)
                self.assertIn(b"usage:", result.stdout)

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

    def test_access_status_details_are_typed_and_do_not_create_a_token(self):
        args, data = invocation("access_status", {"details": True})
        self.assertEqual(args[1:], ["access", "status", "--json", "--details"])
        self.assertEqual(data, b"")
        with self.assertRaises(ValueError):
            invocation("access_status", {"details": "true"})
        result, replies = self.run_server(call_tool("access_status", {"details": True}))
        self.assertEqual(result.returncode, 0)
        detail = payload(replies[0])
        self.assertEqual(detail["status"], "uninitialized")
        self.assertEqual(detail["scope"], [])
        self.assertEqual(detail["requested_items"], [])
        self.assertIsNone(detail["identity"])
        self.assertEqual(list(self.profile.iterdir()), [])

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
            self.assertTrue(reply["result"]["isError"])
            self.assertTrue(reply["result"]["content"][0]["text"].startswith("Invalid Keeper tool or arguments."))
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

    def test_command_tool_uses_literal_argument_vector(self):
        entry = "229b7a79-bcb0-450c-a320-fbccdd672f75"
        args, data = invocation("use_password", {
            "entry": entry, "action": "local-check", "command": ["/usr/bin/cat", "literal argument"],
        })
        self.assertEqual(args[1:], ["run", "--json", f"--entry={entry}", "--action=local-check",
                                     "--", "/usr/bin/cat", "literal argument"])
        self.assertEqual(data, b"")

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

    def test_connection_profiles_reject_ephemeral_mutations_until_persistent_profile_selected(self):
        from uuid import uuid4

        def run(*messages):
            result = subprocess.run(
                [RUNNER, "--socket", self.endpoint, "--project-profiles", self.profile, "--connection-profiles"],
                input=b"".join(encode(message) for message in messages), capture_output=True, check=True, timeout=12,
            )
            return [decode(line) for line in result.stdout.splitlines()]

        req = {"identity": "Fixture", "project": "Fixture", "items": [{"label": "Sample", "metadata": True}]}
        wf = {"id": str(uuid4()), "vault": str(uuid4()), "entry": str(uuid4()),
              "origin": "https://example.test/", "steps": [{"name": "step", "request": {}}]}
        replies = run(
            call_tool("request_access", {"request": req}, identifier=1),
            call_tool("workflow_request", {"request": wf, "registration": {"identity": "A", "project": "B"}}, identifier=2),
        )
        for reply in replies:
            self.assertTrue(reply["result"]["isError"])
            self.assertIn("Pass a persistent profile parameter", reply["result"]["content"][0]["text"])
        self.assertEqual(list(self.profile.iterdir()), [])

    def test_serve_drains_oversized_frame_and_continues(self):
        from io import BytesIO
        from keepassxc_agent_access.agent_runner import MAX_MESSAGE

        oversized = b'{"jsonrpc":"2.0","id":1,"method":"ping","pad":"' + (b"a" * MAX_MESSAGE) + b'"}\n'
        follow_up = encode(frame("ping", identifier=2))
        sink = BytesIO()
        AgentRunner(self.endpoint, self.profile).serve(BytesIO(oversized + follow_up), sink)
        replies = [decode(line) for line in sink.getvalue().splitlines()]
        self.assertEqual(replies[0]["error"]["code"], -32600)
        self.assertIsNone(replies[0]["id"])
        self.assertEqual(replies[1], {"jsonrpc": "2.0", "id": 2, "result": {}})

    def test_usage_schema_has_oneof_branches_and_direct_runner_rejects_input_path(self):
        from keepassxc_agent_access.agent_runner import USAGE

        self.assertIn("https_results", USAGE["properties"]["type"]["enum"])
        branches = {branch["properties"]["type"]["enum"][0]: branch for branch in USAGE["oneOf"]}
        self.assertEqual(set(branches), {"local_command", "networked_command", "https", "https_results", "browser"})
        for branch in branches.values():
            self.assertIs(branch["additionalProperties"], False)

        entry = "229b7a79-bcb0-450c-a320-fbccdd672f75"
        network = {"type": "networked_command", "command": ["/usr/bin/cat", "/input"],
                   "origin": "https://example.test/", "prompt_variable": "GIT_ASKPASS"}
        with self.assertRaisesRegex(ValueError, "keeper-connect"):
            invocation("use_password", {"entry": entry, "usage": network, "input_path": "/tmp/artifact"})

    def test_call_tool_allows_sanitized_error_detail_and_truncates_to_400(self):
        from unittest.mock import patch
        from keepassxc_agent_access.protocol import ERRORS

        runner = AgentRunner(self.endpoint, self.profile)
        long_detail = "d" * 500
        completed = subprocess.CompletedProcess([], 1, b"", (ERRORS["invalid_request"] + " " + long_detail).encode())
        with patch("keepassxc_agent_access.agent_runner.subprocess.run", return_value=completed):
            reply = runner.call_tool({"name": "access_status", "arguments": {}})
        self.assertTrue(reply["isError"])
        text = reply["content"][0]["text"]
        self.assertTrue(text.startswith(ERRORS["invalid_request"] + " "))
        self.assertLessEqual(len(text), 400)

        unexpected = subprocess.CompletedProcess([], 1, b"", b"Traceback (most recent call last): secret")
        with patch("keepassxc_agent_access.agent_runner.subprocess.run", return_value=unexpected):
            reply = runner.call_tool({"name": "access_status", "arguments": {}})
        self.assertEqual(reply["content"][0]["text"], "Keeper could not complete the request.")

    def test_keeper_connect_rewrites_input_path_and_injects_schema(self):
        from base64 import b64decode
        from importlib.machinery import SourceFileLoader
        from importlib.util import module_from_spec, spec_from_loader

        connect_path = RUNNER.with_name("keeper-connect")
        loader = SourceFileLoader("keeper_connect", str(connect_path))
        spec = spec_from_loader("keeper_connect", loader)
        mod = module_from_spec(spec)
        loader.exec_module(mod)

        tools_reply = encode({
            "jsonrpc": "2.0", "id": 1,
            "result": {"tools": [{"name": "use_password", "inputSchema": {"type": "object", "properties": {"entry": {"type": "string"}}}}]},
        })
        injected = decode(mod.process_incoming_line(tools_reply))
        self.assertIn("input_path", injected["result"]["tools"][0]["inputSchema"]["properties"])
        self.assertEqual(decode(mod.process_incoming_line(encode(injected))), injected)

        artifact = self.root / "artifact.bin"
        artifact.write_bytes(b"hello\x00world")
        entry = "229b7a79-bcb0-450c-a320-fbccdd672f75"
        network = {"type": "networked_command", "command": ["/usr/bin/cat", "/input"],
                   "origin": "https://example.test/", "prompt_variable": "GIT_ASKPASS"}
        req = call_tool("use_password", {"entry": entry, "usage": network, "input_path": str(artifact)}, identifier=7)
        fwd, local = mod.process_outgoing_line(encode(req))
        self.assertIsNone(local)
        rewritten = decode(fwd)
        args = rewritten["params"]["arguments"]
        self.assertNotIn("input_path", args)
        self.assertEqual(b64decode(args["input_base64"]), b"hello\x00world")

        both = call_tool("use_password", {"entry": entry, "usage": network, "input_path": str(artifact), "input_base64": "YQ=="}, identifier=8)
        fwd, local = mod.process_outgoing_line(encode(both))
        self.assertIsNone(fwd)
        self.assertTrue(decode(local)["result"]["isError"])
        self.assertIn("not both", decode(local)["result"]["content"][0]["text"])

        empty = self.root / "empty.bin"
        empty.write_bytes(b"")
        for bad_path in ("", str(self.root), str(self.root / "missing.bin"), str(empty)):
            bad = call_tool("use_password", {"entry": entry, "usage": network, "input_path": bad_path}, identifier=9)
            fwd, local = mod.process_outgoing_line(encode(bad))
            self.assertIsNone(fwd)
            self.assertTrue(decode(local)["result"]["isError"])

        oversized = self.root / "big.bin"
        with open(oversized, "wb") as stream:
            stream.truncate(8 * 1024 * 1024 + 1)
        bad_big = call_tool("use_password", {"entry": entry, "usage": network, "input_path": str(oversized)}, identifier=10)
        fwd, local = mod.process_outgoing_line(encode(bad_big))
        self.assertIsNone(fwd)
        self.assertTrue(decode(local)["result"]["isError"])

        bad_cli = subprocess.run([connect_path, "--profile", "../bad"], capture_output=True, check=False, timeout=5)
        self.assertEqual(bad_cli.returncode, 2)

        with socket.socket(socket.AF_UNIX) as listener:
            sock_path = self.root / "connect.sock"
            listener.bind(str(sock_path))
            listener.listen()
            listener.settimeout(5)
            received = []

            def serve_sock():
                conn, _ = listener.accept()
                with conn, conn.makefile("rb") as stream:
                    received.append(decode(stream.readline()))
                    received.append(decode(stream.readline()))
                    conn.sendall(tools_reply)

            t = Thread(target=serve_sock, daemon=True)
            t.start()
            from io import BytesIO
            out = BytesIO()
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(str(sock_path))
                mod.proxy(BytesIO(encode(req)), out, client, profile="Work-1")
            t.join(5)
            self.assertEqual(received[0], {"jsonrpc": "2.0", "method": "keeper/profile", "params": {"name": "Work-1"}})
            self.assertEqual(b64decode(received[1]["params"]["arguments"]["input_base64"]), b"hello\x00world")
            self.assertIn("input_path", decode(out.getvalue())["result"]["tools"][0]["inputSchema"]["properties"])
