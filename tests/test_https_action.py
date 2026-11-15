import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from unittest import TestCase
from unittest.mock import patch

from pykeepass import create_database

from keepassxc_agent_access.access_settings import Action
from keepassxc_agent_access.protocol import ListingError
from keepassxc_agent_access.vault import VaultTarget, open_vault
from tls_fixture import AUTHORIZATION, PASSWORD, USERNAME, tls_service


class HTTPSActionTests(TestCase):
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
