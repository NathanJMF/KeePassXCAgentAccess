from io import BytesIO
import gzip
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, Mock, patch

from pykeepass import create_database

from keepassxc_agent_access.access_settings import Action, ActionType
from keepassxc_agent_access.browser_action import _HTML_LIMIT, _html
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
                        actual = authenticate(connection, resource, entry, ActionType.BEARER.value)
                        self.assertEqual(actual["outcome"], expected["outcome"])
                        self.assertEqual(actual["http_status"], expected["http_status"])
                        self.assertNotIn(secret, repr(actual))
            self.assertEqual(calls, [("/check", authorization), ("/redirect", authorization)])

    def test_fixed_json_worker_with_bearer_token_and_uncertain_write(self):
        secret = "synthetic_api_token"
        authorization = f"Bearer {secret}"
        with TemporaryDirectory() as directory, tls_service(directory, authorization=authorization) as (cert, url, calls):
            database = Path(directory) / "synthetic.kdbx"
            vault = create_database(database, "Fixture unlock")
            entry = vault.add_entry(vault.root_group, "Synthetic API", "fixture", secret)
            vault.save()

            def action(path, host=url):
                return Action("trigger", "Trigger API", str(entry.uuid), host + path, kind=ActionType.BEARER,
                              method="POST", request_json='{"event": "verify"}')

            def allow(send):
                send()
                return True

            with patch.dict(os.environ, {"SSL_CERT_FILE": str(cert)}):
                with open_vault(VaultTarget(database), "Fixture unlock", Event()) as worker:
                    with self.assertRaises(ListingError):
                        worker.use(action("/check"), lambda _: False)
                    wrong = worker.use(action("/wrong", url.replace("127.0.0.1", "localhost")), allow)
                    self.assertEqual(wrong["outcome"], "failed")
                    self.assertNotIn(secret, repr(wrong))
                    self.assertEqual(calls, [])
                    for path, expected in (
                        ("/check", {"outcome": "succeeded", "http_status": 200}),
                        ("/redirect", {"outcome": "failed", "http_status": 302}),
                        ("/disconnect", {"outcome": "uncertain"}),
                    ):
                        with self.subTest(path=path):
                            actual = worker.use(action(path), allow)
                            self.assertEqual(actual["outcome"], expected["outcome"])
                            if "http_status" in expected:
                                self.assertEqual(actual.get("http_status"), expected["http_status"])
                            self.assertNotIn(secret, repr(actual))
            self.assertEqual(calls, [
                ("POST", path, authorization, "application/json", b'{"event":"verify"}')
                for path in ("/check", "/redirect", "/disconnect")
            ])

    def test_invalid_or_interim_status_leaves_write_outcome_unknown(self):
        connection = MagicMock()
        response = connection.getresponse.return_value.__enter__.return_value
        for status in (103, 600):
            with self.subTest(status=status):
                response.status = status
                self.assertEqual(authenticate(connection, "/check", SimpleNamespace(password="fixture"),
                                              ActionType.BEARER, method="PUT"), {"outcome": "uncertain"})

    def test_bearer_rejects_invalid_tokens_before_sending_a_request(self):
        connection = Mock()
        for invalid in (None, "", " leading", "contains space", "token\r\nX-Injected: yes",
                        "á", "\t", "foo\x00bar", "x" * 8193):
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
                untrusted_res = untrusted.use(action(), allow)
                self.assertEqual(untrusted_res["outcome"], "failed")
                self.assertNotIn(PASSWORD, repr(untrusted_res))
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
                    self.assertEqual(result["outcome"], "failed")
                    self.assertEqual(result["http_status"], 302)
                    self.assertNotIn(PASSWORD, repr(result))
                    self.assertNotIn(AUTHORIZATION, repr(result))
                    wrong_host = worker.use(action("/wrong", url.replace("127.0.0.1", "localhost")), allow)
                    self.assertEqual(wrong_host["outcome"], "failed")
                    self.assertNotIn(PASSWORD, repr(wrong_host))
                    slow = worker.use(action("/slow"), allow)
                    self.assertEqual(slow["outcome"], "failed")
                    self.assertNotIn(PASSWORD, repr(slow))
            self.assertEqual(calls, [("/check", AUTHORIZATION), ("/redirect", AUTHORIZATION),
                                    ("/slow", AUTHORIZATION)])

    def test_basic_and_bearer_support_custom_headers_without_overriding_authorization(self):
        entry = "229b7a79-bcb0-450c-a320-bfccdd672f75"
        action = Action("custom", "Custom Headers", entry, "https://example.invalid/check",
                        kind=ActionType.BEARER, headers=(("Accept", "application/json"), ("X-Trace", "1")))
        self.assertEqual(action.headers, (("Accept", "application/json"), ("X-Trace", "1")))
        for bad_headers in ((("Authorization", "Bearer override"),), (("X-Secret", "{{password}}"),)):
            with self.subTest(bad_headers=bad_headers), self.assertRaises(ValueError):
                Action("bad", "Bad", entry, "https://example.invalid/check",
                       kind=ActionType.BEARER, headers=bad_headers)

        connection = MagicMock()
        connection.getresponse.return_value.__enter__.return_value.status = 200
        self.assertEqual(authenticate(connection, "/check", SimpleNamespace(password="tok", username="user"),
                                      ActionType.BEARER, headers=(("Accept", "application/json"),)),
                         {"outcome": "succeeded", "http_status": 200})
        sent_headers = connection.request.call_args.kwargs["headers"]
        self.assertEqual(sent_headers, {"Accept": "application/json", "Authorization": "Bearer tok"})
        self.assertEqual(authenticate(connection, "/check", SimpleNamespace(password="tok", username="user"),
                                      ActionType.BASIC, headers=(("authorization", "Basic fake"),)),
                         {"outcome": "failed"})

    def test_browser_html_supports_gzip_and_blocks_decompression_bombs(self):
        from email.message import EmailMessage

        def make_response(payload, *, encoding=None):
            headers = EmailMessage()
            headers["Content-Type"] = "text/html; charset=utf-8"
            if encoding is not None:
                headers["Content-Encoding"] = encoding
            stream = BytesIO(payload)
            return SimpleNamespace(headers=headers, read=stream.read)

        html = "<form id='f'>ok</form>"
        self.assertEqual(_html(make_response(gzip.compress(html.encode("utf-8")), encoding="GZip")), html)
        bomb = gzip.compress(b"a" * (_HTML_LIMIT + 100))
        self.assertLess(len(bomb), _HTML_LIMIT)
        self.assertIsNone(_html(make_response(bomb, encoding="gzip")))
        self.assertIsNone(_html(make_response(b"not-gzip", encoding="gzip")))
        self.assertIsNone(_html(make_response(html.encode("utf-8"), encoding="br")))

    def test_browser_form_script_allows_checkbox_and_hidden_rails_pattern(self):
        from keepassxc_agent_access.browser_document import display, inspect

        cfg = {"form_id": "f", "username_field": "u", "password_field": "p"}
        url = "https://example.test/login"
        rails_checked = (
            '<form id="f" method="post" action="/submit">'
            '<input name="u" type="text"><input name="p" type="password">'
            '<input name="rem" type="hidden" value="0">'
            '<input name="rem" type="checkbox" value="1" checked>'
            '<input name="opt" type="checkbox" value="yes">'
            '<input name="agree" type="checkbox" value="on" checked>'
            '</form>'
        )
        rails_unchecked = rails_checked.replace('value="1" checked', 'value="1"')
        dup_pass = (
            '<form id="f" method="post" action="/submit">'
            '<input name="u" type="text"><input name="p" type="password">'
            '<input name="p" type="checkbox" value="1">'
            '</form>'
        )
        dup_hidden = (
            '<form id="f" method="post" action="/submit">'
            '<input name="u" type="text"><input name="p" type="password">'
            '<input name="p" type="hidden" value="override">'
            '</form>'
        )
        with patch.dict(os.environ, {}, clear=False), display():
            self.assertEqual(inspect(rails_checked, url, cfg),
                             {"action": "https://example.test/submit", "hidden": [["rem", "1"], ["agree", "on"]]})
            self.assertEqual(inspect(rails_unchecked, url, cfg),
                             {"action": "https://example.test/submit", "hidden": [["rem", "0"], ["agree", "on"]]})
            self.assertIsNone(inspect(dup_pass, url, cfg))
            self.assertIsNone(inspect(dup_hidden, url, cfg))
