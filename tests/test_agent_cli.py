import os
from pathlib import Path
import socket
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
from unittest import TestCase

from keepassxc_agent_access.protocol import LIST_REQUEST, decode


CLI = Path(__file__).resolve().parents[1] / "keepassxc-agent"


class AgentCliTests(TestCase):
    def invoke(self, endpoint):
        return subprocess.run(
            [CLI, "entries", "list", "--json"],
            env={**os.environ, "KEEPASSXC_AGENT_SOCKET": str(endpoint)},
            capture_output=True, check=False, timeout=7,
        )

    def reply(self, contents):
        with TemporaryDirectory(dir="/tmp") as directory, socket.socket(socket.AF_UNIX) as listener:
            endpoint = Path(directory) / "list.sock"
            listener.bind(str(endpoint))
            listener.listen()
            listener.settimeout(7)
            requests = []

            def serve():
                connection, _ = listener.accept()
                with connection, connection.makefile("rb") as stream:
                    requests.append(decode(stream.readline()))
                    connection.sendall(contents)

            server = Thread(target=serve, daemon=True)
            server.start()
            result = self.invoke(endpoint)
            server.join(7)
            self.assertEqual(requests, [LIST_REQUEST])
            return result

    def test_success_has_exact_json_and_no_diagnostics(self):
        payload = b'{"entries":[{"id":"00000000-0000-0000-0000-000000000001","title":"Sample","group_path":[]}]}\n'
        result = self.reply(payload)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, payload)
        self.assertEqual(result.stderr, b"")

    def test_malformed_truncated_and_unavailable_never_print_data(self):
        for reply in (b'{"entries":[{"password":"secret sentinel"}]}\n',
                      b'{"entries":[]}', b'not-json\n'):
            with self.subTest(reply=reply):
                result = self.reply(reply)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertNotIn(b"secret sentinel", result.stderr)
        with TemporaryDirectory(dir="/tmp") as directory:
            result = self.invoke(Path(directory) / "missing.sock")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"Ask the vault owner", result.stderr)

    def test_size_limit_reports_a_safe_diagnostic(self):
        result = self.reply(b'{"error":"too_large"}\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"size limit", result.stderr)
