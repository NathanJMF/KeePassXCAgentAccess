"""Useful private-session results from a synthetic HTTPS service."""

from base64 import b64encode
from contextlib import contextmanager
from hashlib import sha256
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import secrets
import ssl
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, quote

from keepassxc_agent_access.result_delivery import (
    BODY_LIMIT, GuestLoginCache, ResultRequest, _private_strings, _project, deliver_results, parse_result_usage,
)
from tls_fixture import tls_service


@contextmanager
def inventory_service():
    password = 'private-' + secrets.token_hex(12) + '-"-{{username}}'
    username = 'fixture-admin'
    ticket = 'ticket-' + secrets.token_hex(16)
    csrf = 'csrf-' + secrets.token_hex(16)
    node = 'node-' + secrets.token_hex(3)
    vmid = secrets.randbelow(800) + 100
    seen = []
    fixture = SimpleNamespace(password=password, username=username, ticket=ticket, csrf=csrf, node=node, vmid=vmid, seen=seen)

    class Service(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def handle(self):
            try:
                super().handle()
            except (OSError, ssl.SSLError):
                pass
        def respond(self, data, *, status=200):
            raw = data if isinstance(data, bytes) else json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Set-Cookie', 'private=' + ticket)
            self.end_headers()
            self.wfile.write(raw)
        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            if self.headers.get('Content-Type') == 'application/json':
                body = json.loads(raw)
            else:
                body = {key: values[0] for key, values in parse_qs(raw.decode()).items()}
            seen.append(('POST', self.path, body))
            if self.path == '/login' and body == {'username': username + '@realm', 'password': password}:
                self.respond({'data': {'ticket': ticket, 'csrf': csrf, 'password': password, 'username': username}})
            elif self.path == '/write' and self.headers.get('Cookie') == 'Auth=' + ticket:
                self.respond({'data': [{'vmid': body['vmid'], 'status': 'created'}]})
            elif self.path == '/write-echo' and self.headers.get('Cookie') == 'Auth=' + ticket:
                self.respond({'data': ticket})
            else:
                self.respond({'error': password}, status=401)
        def do_GET(self):
            seen.append(('GET', self.path, self.headers.get('Cookie'), self.headers.get('Authorization')))
            if self.path == '/slow':
                self.send_response(200)
                self.send_header('Content-Length', '100000')
                self.end_headers()
                for _ in range(200):
                    self.wfile.write(b' ')
                    self.wfile.flush()
                    sleep(.05)
                return
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', '/inventory')
                self.end_headers()
                return
            if self.path == '/whoami':
                self.respond({'data': [{'name': username}]})
                return
            if self.path.startswith('/echo/'):
                kind = self.path.rsplit('/', 1)[1]
                echo = {'raw': password, 'base64': b64encode(password.encode()).decode(), 'ticket': ticket,
                        'quoted': quote(password, safe=''), 'hex': password.encode().hex(),
                        'basic': b64encode((username + ':' + password).encode()).decode(),
                        'cookie': b64encode(('Auth=' + ticket).encode()).decode()}[kind]
                self.respond({'data': [{'name': echo}]})
                return
            if self.path == '/duplicate':
                self.respond(b'{"data":[{"name":"first","name":"second"}]}')
                return
            if self.path == '/nan':
                self.respond(b'{"data":[{"name":NaN}]}')
                return
            if self.path == '/large':
                self.respond(b' ' * (BODY_LIMIT + 1))
                return
            valid = self.headers.get('Cookie') == 'Auth=' + ticket or self.headers.get('Authorization') == 'Basic ' + b64encode((username + ':' + password).encode()).decode()
            if not valid:
                self.respond({'error': password}, status=401)
                return
            self.respond({'data': [{'type': 'node', 'node': node, 'vmid': None, 'name': node, 'status': 'online', 'private': password},
                                   {'type': 'qemu', 'node': node, 'vmid': vmid, 'name': 'available-guest', 'status': 'running', 'private': ticket}]})

    with TemporaryDirectory() as temporary, tls_service(temporary, handler=Service) as (cert, url, _):
        fixture.origin = url
        fixture.certificate = cert
        fixture.pin = sha256(ssl.PEM_cert_to_DER_cert(Path(cert).read_text())).hexdigest()
        fixture.entry = SimpleNamespace(password=password, username=username)
        yield fixture


def workflow(fixture, path='/inventory', columns=None):
    return {'type': 'https_results', 'origin': fixture.origin, 'certificate_sha256': fixture.pin,
            'login': {'path': '/login', 'form': {'username': '{{username}}@realm', 'password': '{{password}}'},
                      'capture': {'ticket': '/data/ticket', 'csrf': '/data/csrf'}},
            'request': {'path': path, 'auth': 'session', 'headers': {'Cookie': 'Auth={{session.ticket}}'}},
            'result': {'path': '/data', 'columns': columns or ['type', 'node', 'vmid', 'name', 'status']}}


class ResultDeliveryTests(TestCase):
    def test_cached_guest_login_expires_before_a_delayed_dispatch(self):
        connection = Mock()
        cache = Mock()
        cache.get.return_value = (11, {"session.ticket": "private_ticket", "session.csrf": "private_csrf"}, ())
        clock = 10

        @contextmanager
        def connected(_origin, _pin, deadline):
            self.assertEqual(deadline, 11)
            yield connection

        def delayed_gate():
            nonlocal clock
            clock = 11
            return True

        site = SimpleNamespace(origin="https://synthetic.test", pin="a" * 64)
        item = SimpleNamespace(username="sample", password="fixture-only")
        with patch("keepassxc_agent_access.result_delivery._connection", side_effect=connected), \
                patch("keepassxc_agent_access.result_delivery.monotonic", side_effect=lambda: clock):
            answer = deliver_results(workflow(site), item, delayed_gate, private_result=97,
                                     login_context={"key": "synthetic", "expires": 100, "reuse": True},
                                     login_cache=cache)
        self.assertEqual(answer, {"outcome": "failed"})
        connection.request.assert_not_called()

    def test_private_form_login_returns_fresh_inventory_and_not_credentials(self):
        with inventory_service() as site:
            calls = []
            config = parse_result_usage(workflow(site))
            reply = deliver_results(config, site.entry, lambda: calls.append(True) or True)
            self.assertEqual(reply['outcome'], 'succeeded')
            self.assertEqual(reply['http_status'], 200)
            self.assertEqual(reply['data'][0]['node'], site.node)
            selected = next(row for row in reply['data'] if row['type'] == 'qemu' and row['status'] == 'running')
            self.assertEqual(selected['vmid'], site.vmid)
            self.assertEqual(len(calls), 2)
            self.assertEqual([row[:2] for row in site.seen], [('POST', '/login'), ('GET', '/inventory')])
            for secret in (site.password, site.ticket, site.csrf):
                self.assertNotIn(secret, json.dumps(reply))
                self.assertNotIn(secret, config.canonical_json)
                self.assertNotIn(secret, repr(config.description))
            self.assertEqual(parse_result_usage(config.data), config)

    def test_json_login_and_nonsecret_resource_write_return_useful_results(self):
        with inventory_service() as site:
            data = workflow(site)
            data['login']['json'] = data['login'].pop('form')
            data['request'].update(method='POST', path='/write', json={'vmid': site.vmid})
            data['result']['columns'] = ['vmid', 'status']
            reply = deliver_results(data, site.entry, lambda: True)
            self.assertEqual(reply, {'outcome': 'succeeded', 'http_status': 200,
                                     'data': [{'vmid': site.vmid, 'status': 'created'}]})

    def test_gate_revocation_before_private_ticket_use_stops_resource_request(self):
        with inventory_service() as site:
            decisions = iter((True, False))
            result = deliver_results(workflow(site), site.entry, lambda: next(decisions))
            self.assertEqual(result, {'outcome': 'failed'})
            self.assertEqual([row[:2] for row in site.seen], [('POST', '/login')])

    def test_named_scalar_write_result_still_filters_captured_credentials(self):
        with inventory_service() as site:
            data = workflow(site, '/write-echo')
            data['approve_write_once'] = True
            data['request']['method'] = 'POST'
            data['result'] = {'path': '/data', 'scalar': 'task_id'}
            self.assertEqual(deliver_results(data, site.entry, lambda: True), {'outcome': 'acknowledged', 'http_status': 200})
            self.assertEqual([row[:2] for row in site.seen], [('POST', '/login'), ('POST', '/write-echo')])

    def test_wrong_certificate_pin_sends_no_credential_or_request(self):
        with inventory_service() as site:
            data = workflow(site)
            data['certificate_sha256'] = '0' * 64
            calls = []
            self.assertEqual(deliver_results(data, site.entry, lambda: calls.append(True) or True), {'outcome': 'failed'})
            self.assertEqual(site.seen, [])
            self.assertEqual(calls, [])

    def test_echoes_and_common_encoded_credentials_are_not_released(self):
        with inventory_service() as site:
            for kind in ('raw', 'ticket', 'quoted', 'base64', 'hex', 'basic', 'cookie'):
                with self.subTest(kind=kind):
                    result = deliver_results(workflow(site, '/echo/' + kind, ['name']), site.entry, lambda: True)
                    self.assertEqual(result, {'outcome': 'failed'})

    def test_redirect_duplicate_nonfinite_and_oversize_responses_fail_closed(self):
        with inventory_service() as site:
            for path in ('/redirect', '/duplicate', '/nan', '/large'):
                with self.subTest(path=path):
                    result = deliver_results(workflow(site, path, ['name']), site.entry, lambda: True)
                    self.assertNotIn('data', result)
                    self.assertEqual(result['outcome'], 'failed')
            self.assertEqual(sum(row[0] == 'GET' and row[1] == '/inventory' for row in site.seen), 0)

    def test_no_login_basic_auth_and_projection_bounds(self):
        with inventory_service() as site:
            data = workflow(site)
            del data['login']
            data['request'] = {'path': '/inventory', 'auth': 'basic'}
            count = []
            result = deliver_results(data, site.entry, lambda: count.append(True) or True)
            self.assertEqual(result['data'][1]['vmid'], site.vmid)
            self.assertEqual(len(count), 1)

    def test_strict_descriptors_do_not_turn_private_login_into_result_release(self):
        with inventory_service() as site:
            base = workflow(site)
            cases = [
                {**base, 'origin': site.origin + '/path'},
                {**base, 'result': {'path': '/data', 'columns': ['ticket']}},
                {**base, 'approve_write_once': True},
                {**base, 'request': {**base['request'], 'method': 'POST'},
                 'result': {'path': '/data/ticket', 'scalar': 'task_id'}},
                {**base, 'request': {**base['request'], 'path': '//other.invalid/'}},
                {**base, 'request': {**base['request'], 'headers': {'Host': 'other.invalid'}}},
                {**base, 'request': {**base['request'], 'method': 'POST', 'json': {'content': '{{session.ticket}}'}}},
                {**base, 'request': {**base['request'], 'query': {'value': '{{password}}'}}},
                {**base, 'login': {**base['login'], 'capture': {'ticket': '/bad~pointer'}}},
                {**base, 'request': {**base['request'], 'headers': {'Cookie': '{{session.unknown}}'}}},
            ]
            for data in cases:
                with self.subTest(data=data), self.assertRaises(ValueError):
                    parse_result_usage(data)
            self.assertEqual(site.seen, [])

    def test_whole_workflow_deadline_stops_a_slow_response(self):
        with inventory_service() as site, patch('keepassxc_agent_access.result_delivery.WORKFLOW_SECONDS', .3):
            started = monotonic()
            result = deliver_results(workflow(site, '/slow', ['name']), site.entry, lambda: True)
            elapsed = monotonic() - started
            self.assertEqual(result, {'outcome': 'failed'})
            self.assertLess(elapsed, 1.5)

    def test_username_result_needs_independent_metadata_permission(self):
        with inventory_service() as site:
            request = workflow(site, '/whoami', ['name'])
            self.assertEqual(deliver_results(request, site.entry, lambda: True), {'outcome': 'failed'})
            result = deliver_results(request, site.entry, lambda: True, allow_username=True)
            self.assertEqual(result, {'outcome': 'succeeded', 'http_status': 200, 'data': [{'name': site.username}]})

    def test_no_pin_uses_owner_ca_trust_and_never_sends_to_untrusted_certificate(self):
        with inventory_service() as site:
            request = workflow(site)
            del request['certificate_sha256']
            calls = []
            with patch.dict(os.environ, SSL_CERT_FILE='/nonexistent/keeper-test-ca.pem'):
                self.assertEqual(deliver_results(request, site.entry, lambda: calls.append(True) or True), {'outcome': 'failed'})
            self.assertEqual(site.seen, [])
            self.assertEqual(calls, [])
            with patch.dict(os.environ, SSL_CERT_FILE=str(site.certificate)):
                reply = deliver_results(request, site.entry, lambda: True)
            self.assertEqual(reply['outcome'], 'succeeded')
            self.assertEqual(reply['data'][1]['vmid'], site.vmid)

    def test_get_scalar_basic_bearer_headers_private_strings_and_guest_output(self):
        with inventory_service() as site:
            # GET with result.scalar is allowed on non-private paths and custom basic/bearer headers work.
            get_scalar = {
                'type': 'https_results', 'origin': site.origin, 'certificate_sha256': site.pin,
                'request': {'path': '/inventory', 'auth': 'basic', 'headers': {'Accept': 'application/json', 'X-Echo': 'running'}},
                'result': {'path': '/data/1/status', 'scalar': 'state'},
            }
            reply = deliver_results(get_scalar, site.entry, lambda: True)
            self.assertEqual(reply, {'outcome': 'succeeded', 'http_status': 200, 'data': [{'state': 'running'}]})
            with self.assertRaises(ValueError):
                parse_result_usage({**get_scalar, 'request': {'path': '/inventory', 'auth': 'bearer', 'headers': {'Authorization': 'x'}}})
            with self.assertRaises(ValueError):
                parse_result_usage({**get_scalar, 'result': {'path': '/data/ticket', 'scalar': 'state'}})

            # GuestLoginCache works even without certificate_sha256 (pin=None).
            cache = GuestLoginCache()
            ca_req = workflow(site)
            del ca_req['certificate_sha256']
            with patch.dict(os.environ, SSL_CERT_FILE=str(site.certificate)):
                ctx = {'key': 'guest-job-1', 'expires': monotonic() + 30, 'reuse': True}
                first = deliver_results(ca_req, site.entry, lambda: True, login_context=ctx, login_cache=cache)
                second = deliver_results(ca_req, site.entry, lambda: True, login_context=ctx, login_cache=cache)
                self.assertEqual(first['outcome'], 'succeeded')
                self.assertEqual(second['outcome'], 'succeeded')
                self.assertEqual(sum(row[:2] == ('POST', '/login') for row in site.seen), 1)

        # Non-guest https_results allow \n, \r, \t up to 512 chars.
        projected = _project({'data': [{'msg': 'line1\n\tline2\r'}]}, {'path': '/data', 'columns': ['msg']}, ())
        self.assertEqual(projected, [{'msg': 'line1\n\tline2\r'}])

        # Guest output strips ANSI CSI/OSC and control chars and truncates instead of failing.
        ansi_text = '\x1b]0;title\x07\x1b[31mhello\x1b[0m\x00\n' + ('x' * 2100)
        guest_projected = _project({'data': [{'out': ansi_text}]}, {'path': '/data', 'columns': ['out']}, (), guest_output=True)
        self.assertTrue(guest_projected[0]['out'].startswith('hello\n'))
        self.assertTrue(guest_projected[0]['out'].endswith('\n...[truncated]'))
        self.assertEqual(len(guest_projected[0]['out']), 2048)

        # _private_strings ignores short/trivial non-secret strings while keeping private keys and long secrets.
        doc = {'ok': 'ok', 'path': '/', 'flag': 'true', 'num': '12345678', 'token': 'abc',
               'nested': {'secret_id': 's1', 'note': 'long-session-value-xyz'}}
        self.assertEqual(_private_strings(doc), ['abc', 's1', 'long-session-value-xyz'])

    def test_connection_falls_back_across_approved_addresses(self):
        import ipaddress
        from keepassxc_agent_access.result_delivery import _connection

        attempted = []
        with patch('keepassxc_agent_access.result_delivery.approved_addresses',
                   return_value=(ipaddress.ip_address('2001:db8::1'), ipaddress.ip_address('127.0.0.1'))), \
             patch('keepassxc_agent_access.result_delivery.socket.create_connection',
                   side_effect=[OSError('unreachable'), Mock()]) as create_conn, \
             patch('keepassxc_agent_access.result_delivery.HTTPSConnection') as https_conn:
            conn_inst = https_conn.return_value
            conn_inst.sock = Mock()
            def run_connect():
                attempted.append(conn_inst._create_connection(('example.test', 443), 2))
            conn_inst.connect.side_effect = run_connect
            with _connection('https://example.test/', None, monotonic() + 5):
                pass
        self.assertEqual([call.args[0] for call in create_conn.call_args_list],
                         [('2001:db8::1', 443), ('127.0.0.1', 443)])
