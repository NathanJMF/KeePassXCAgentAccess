import json
import os
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from threading import Event, Thread
from unittest import TestCase
from unittest.mock import Mock, patch

from keepassxc_agent_access.broker import BrokerConfig, ListingBroker
from keepassxc_agent_access.protocol import (
    LIST_REQUEST, ListingError, REQUEST_LIMIT, encode,
)


class BrokerTests(TestCase):
    def setUp(self):
        scratch = TemporaryDirectory(dir="/tmp")
        self.addCleanup(scratch.cleanup)
        self.path = Path(scratch.name) / "list.sock"
        self.agent_uid = os.geteuid() + 1
        self.session = Mock()
        self.session.list_entries.return_value = b'{"entries":[]}\n'
        self.current = self.session
        self.broker = ListingBroker(
            BrokerConfig(self.path, self.agent_uid), lambda: self.current, self.handle
        )
        self.addCleanup(self.broker.stop)

    @staticmethod
    def handle(request, _uid, session, _live, _dispatch, _deliver):
        if isinstance(request, dict) and request.get("operation") == "detail_error":
            raise ListingError("invalid_request", detail="Specify a vault UUID.")
        if request != LIST_REQUEST or type(request["version"]) is not int:
            raise ListingError("invalid_request")
        return session.list_entries()

    def connection(self):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.settimeout(6)
            client.connect(str(self.path))
        except BaseException:
            client.close()
            raise
        return client

    def invoke(self, request):
        with self.connection() as client:
            client.sendall(request)
            with client.makefile("rb") as stream:
                return json.loads(stream.readline())

    def test_socket_creation_and_peer_check(self):
        self.assertFalse(self.broker.enabled)
        self.broker.start()
        self.assertTrue(self.broker.enabled)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o660)
        # The real connector is the owner UID, which differs from the configured agent.
        with self.connection() as client:
            self.assertEqual(client.recv(100), b"")
        self.session.list_entries.assert_not_called()

    def test_valid_invalid_and_oversized_requests(self):
        with patch("keepassxc_agent_access.broker.peer_uid", return_value=self.agent_uid):
            self.broker.start()
            for invalid in [b'{"version":true,"operation":"list_entries"}\n',
                            b'{"version":1,"operation":"show_password"}\n',
                            b'{"version":1,"version":1,"operation":"list_entries"}\n',
                            b'{"version":1,"operation":"list_entries","password":0}\n']:
                self.assertEqual(self.invoke(invalid), {"error": "invalid_request"})
            self.assertEqual(self.invoke(b"x" * REQUEST_LIMIT), {"error": "too_large"})
            self.assertEqual(self.invoke(encode({"version": 1, "operation": "detail_error"})),
                             {"error": "invalid_request", "detail": "Specify a vault UUID."})
            self.assertEqual(self.invoke(encode(LIST_REQUEST)), {"entries": []})
        self.session.list_entries.assert_called_once()

    def test_revocation_aborts_pending_response_and_can_start_again(self):
        entered, finish = Event(), Event()

        def wait_for_release():
            entered.set()
            finish.wait(3)
            return b'{"entries":[]}\n'

        self.session.list_entries.side_effect = wait_for_release
        with patch("keepassxc_agent_access.broker.peer_uid", return_value=self.agent_uid):
            self.broker.start()
            result = []

            def request():
                with self.connection() as client:
                    client.sendall(encode(LIST_REQUEST))
                    result.append(client.recv(32))

            thread = Thread(target=request)
            thread.start()
            self.assertTrue(entered.wait(2))
            self.broker.stop()
            finish.set()
            thread.join(2)
            self.assertEqual(result, [b""])
            self.assertFalse(self.path.exists())
            self.session.list_entries.side_effect = None
            self.broker.start()
            self.assertEqual(self.invoke(encode(LIST_REQUEST)), {"entries": []})

    def test_socket_path_refuses_unsafe_parent_and_preserves_existing_files(self):
        self.path.write_text("existing owner file")
        with self.assertRaises(ListingError):
            self.broker.start()
        self.assertEqual(self.path.read_text(), "existing owner file")
        self.path.unlink()
        self.path.parent.chmod(0o770)
        with self.assertRaises(ListingError):
            self.broker.start()

    def test_start_requires_a_current_session_and_separate_uid(self):
        self.current = None
        with self.assertRaises(ListingError):
            self.broker.start()
        owner_config = BrokerConfig(self.path, os.geteuid())
        with self.assertRaises(ListingError):
            ListingBroker(owner_config, lambda: self.session, self.handle).start()

    def test_start_unlinks_stale_dead_socket(self):
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(str(self.path))
        stale.close()
        self.assertTrue(self.path.is_socket())
        with patch("keepassxc_agent_access.broker.peer_uid", return_value=self.agent_uid):
            self.broker.start()
            self.assertTrue(self.broker.enabled)
            self.assertEqual(self.invoke(encode(LIST_REQUEST)), {"entries": []})

    def test_start_refuses_active_listening_socket(self):
        active = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(active.close)
        active.bind(str(self.path))
        active.listen(1)
        with self.assertRaises(ListingError):
            self.broker.start()
        self.assertFalse(self.broker.enabled)
        with self.connection() as client:
            accepted, _ = active.accept()
            accepted.close()
