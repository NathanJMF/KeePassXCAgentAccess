import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from pykeepass import create_database

from keepassxc_agent_access.access_settings import Action, ActionType
from keepassxc_agent_access.https_action import authenticate, prepare_https
from keepassxc_agent_access.protocol import ListingError
from keepassxc_agent_access.vault import VaultTarget, open_vault
from tls_fixture import AUTHORIZATION, PASSWORD, USERNAME, tls_service


class HTTPSActionTests(TestCase):
    def test_bearer_uses_only_the_password_and_returns_only_status(self):
        secret = "fixture_token.+~/-=="
        authorization = f"Bearer {secret}"
        entry = SimpleNamespace(password=secret)
        with TemporaryDirectory() as directory, tls_service(directory, authorization=authorization) as (cert, url, calls):
            with patch.dict(os.environ, {"SSL_CERT_FILE": str(cert)}):
                for path, expected in (("/check", {"outcome": "succeeded", "http_status": 200}),
                                       ("/redirect", {"outcome": "failed", "http_status": 302})):
                    with self.subTest(path=path), prepare_https(url + path) as (connection, resource):
                        self.assertEqual(authenticate(connection, resource, entry, ActionType.BEARER.value), expected)
            self.assertEqual(calls, [("/check", authorization), ("/redirect", authorization)])

    def test_bearer_rejects_invalid_tokens_before_sending_a_request(self):
        connection = Mock()
        for invalid in (None, "", " leading", "contains space", "token\r\nX-Injected: yes",
                        "part=middle", "á", "token,append", "\t", "=padding-only"):
            with self.subTest(invalid=invalid):
                self.assertEqual(authenticate(connection, "/check", SimpleNamespace(password=invalid), ActionType.BEARER),
                                 {"outcome": "failed"})
        connection.request.assert_not_called()
        self.assertEqual(authenticate(connection, "/check", SimpleNamespace(password="fixture"), "unknown"),
                         {"outcome": "failed"})
        connection.request.assert_not_called()

    def test_worker_sends_only_authorized_request_and_returns_status(self):
        with TemporaryDirectory() as directory, tls_service(directory) as (cert, url, calls):
            database = Path(directory) / "synthetic.kdbx"
            vault = create_database(database, "Fixture unlock")
            entry = vault.add_entry(vault.root_group, "Synthetic service", USERNAME, PASSWORD)
            vault.save()

            def action(path="/check", host=url):
                return Action("fixture", "Check fixture", str(entry.uuid), host + path)

            def allow(send):
                send()
                return True

            with open_vault(VaultTarget(database), "Fixture unlock", Event()) as untrusted:
                self.assertEqual(untrusted.use(action(), allow), {"outcome": "failed"})
                self.assertEqual(calls, [])

            with patch.dict(os.environ, {"SSL_CERT_FILE": str(cert), "HTTPS_PROXY": "http://127.0.0.1:1"}):
                with open_vault(VaultTarget(database), "Fixture unlock", Event()) as worker:
                    self.assertEqual(worker.entry(str(entry.uuid))["title"], "Synthetic service")
                    self.assertEqual(worker.identity, str(vault.root_group.uuid))
                    with self.assertRaises(ListingError):
                        worker.use(action(), lambda _: False)
                    self.assertEqual(calls, [])
                    self.assertEqual(worker.use(action(), allow), {"outcome": "succeeded", "http_status": 200})
                    result = worker.use(action("/redirect"), allow)
                    self.assertEqual(result, {"outcome": "failed", "http_status": 302})
                    self.assertNotIn(PASSWORD, repr(result))
                    self.assertNotIn(AUTHORIZATION, repr(result))
                    self.assertEqual(worker.use(action("/wrong", url.replace("127.0.0.1", "localhost")), allow),
                                     {"outcome": "failed"})
                    self.assertEqual(worker.use(action("/slow"), allow), {"outcome": "failed"})
            self.assertEqual(calls, [("/check", AUTHORIZATION), ("/redirect", AUTHORIZATION),
                                    ("/slow", AUTHORIZATION)])
