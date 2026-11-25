"""Useful private-session results from a synthetic HTTPS service."""

from base64 import b64encode
from contextlib import contextmanager
import gzip
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
import zlib

from keepassxc_agent_access.result_delivery import (
    BODY_LIMIT, MAX_COLUMNS, MAX_ROWS, RESULT_LIMIT, SOCKET_SECONDS, WORKFLOW_SECONDS,
    GuestLoginCache, ResultRequest, _private_strings, _project, deliver_results, parse_result_usage,
    scrub_error_text,
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
        self.assertEqual(answer["outcome"], "failed")
        self.assertNotIn("data", answer)
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
            self.assertEqual(result['outcome'], 'failed')
            self.assertNotIn('data', result)
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
            result = deliver_results(data, site.entry, lambda: calls.append(True) or True)
            self.assertEqual(result['outcome'], 'failed')
            self.assertNotIn('data', result)
            self.assertEqual(site.seen, [])
            self.assertEqual(calls, [])

    def test_echoes_and_common_encoded_credentials_are_not_released(self):
        with inventory_service() as site:
            for kind in ('raw', 'ticket', 'quoted', 'base64', 'hex', 'basic', 'cookie'):
                with self.subTest(kind=kind):
                    result = deliver_results(workflow(site, '/echo/' + kind, ['name']), site.entry, lambda: True)
                    self.assertEqual(result['outcome'], 'failed')
                    self.assertNotIn('data', result)
                    for secret in (site.password, site.ticket, site.csrf):
                        self.assertNotIn(secret, json.dumps(result))

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
            self.assertEqual(result['outcome'], 'failed')
            self.assertNotIn('data', result)
            self.assertLess(elapsed, 1.5)

    def test_username_result_needs_independent_metadata_permission(self):
        with inventory_service() as site:
            request = workflow(site, '/whoami', ['name'])
            denied = deliver_results(request, site.entry, lambda: True)
            self.assertEqual(denied['outcome'], 'failed')
            self.assertNotIn('data', denied)
            self.assertNotIn(site.username, json.dumps(denied))
            result = deliver_results(request, site.entry, lambda: True, allow_username=True)
            self.assertEqual(result, {'outcome': 'succeeded', 'http_status': 200, 'data': [{'name': site.username}]})

    def test_no_pin_uses_owner_ca_trust_and_never_sends_to_untrusted_certificate(self):
        with inventory_service() as site:
            request = workflow(site)
            del request['certificate_sha256']
            calls = []
            with patch.dict(os.environ, SSL_CERT_FILE='/nonexistent/keeper-test-ca.pem'):
                denied = deliver_results(request, site.entry, lambda: calls.append(True) or True)
                self.assertEqual(denied['outcome'], 'failed')
                self.assertNotIn('data', denied)
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

    def test_raised_caps_and_projection_limits(self):
        self.assertEqual(BODY_LIMIT, 2 * 1024 * 1024)
        self.assertEqual(RESULT_LIMIT, 256 * 1024)
        self.assertEqual(MAX_ROWS, 512)
        self.assertEqual(MAX_COLUMNS, 32)
        self.assertEqual(WORKFLOW_SECONDS, 45)
        self.assertEqual(SOCKET_SECONDS, 15)

        base = {
            'type': 'https_results',
            'origin': 'https://synthetic.test',
            'request': {'path': '/submit', 'method': 'POST', 'auth': 'bearer', 'json': {'payload': 'a' * 12000}},
            'result': {'path': '/data', 'columns': [f'col_{i}' for i in range(32)]},
        }
        parsed = parse_result_usage(base)
        self.assertEqual(len(parsed.data['result']['columns']), 32)
        with self.assertRaises(ValueError):
            parse_result_usage({**base, 'result': {'path': '/data', 'columns': [f'col_{i}' for i in range(33)]}})
        with self.assertRaises(ValueError):
            parse_result_usage({**base, 'request': {**base['request'], 'json': {'payload': 'a' * 65537}}})
        with self.assertRaises(ValueError):
            parse_result_usage({**base, 'request': {**base['request'], 'json': {'payload': 'a' * 60000}},
                                'login': {'path': '/login', 'form': {'password': '{{password}}', 'pad': 'b' * 14000},
                                          'capture': {'tok': '/tok'}}})

        rows_ok = [{'col_0': i} for i in range(512)]
        self.assertEqual(len(_project({'data': rows_ok}, {'path': '/data', 'columns': ['col_0']}, ())), 512)
        with self.assertRaises(ValueError):
            _project({'data': [{'col_0': i} for i in range(513)]}, {'path': '/data', 'columns': ['col_0']}, ())

    def test_project_dot_paths_scalar_arrays_truncation_and_key_safety(self):
        # JSON key names matching forbidden words ("id", "session", "Path") do not poison safe scalar values.
        doc = {
            'data': [
                {
                    'id': 42,
                    'session': 'normal-label',
                    'Path': 'safe-path',
                    'metadata': {'name': 'web-1', 'labels': ['prod', 'blue', None, 7, True, 1.5]},
                    'a.b': 'exact-dotted-key',
                    'a': {'b': 'nested-value', 'secret_child': 'ok'},
                    'missing_nested': 'not-a-dict',
                }
            ]
        }
        projection = {
            'path': '/data',
            'columns': ['id', 'session', 'Path', 'metadata.name', 'metadata.labels', 'a.b',
                        'missing_nested.deep', 'absent.field'],
        }
        projected = _project(doc, projection, ('id', 'session', 'Path', 'pw'))
        self.assertEqual(projected, [{
            'id': 42,
            'session': 'normal-label',
            'Path': 'safe-path',
            'metadata.name': 'web-1',
            'metadata.labels': ['prod', 'blue', None, 7, True, 1.5],
            'a.b': 'exact-dotted-key',
            'missing_nested.deep': None,
            'absent.field': None,
        }])

        # Short raw password (e.g. 2 chars) is still caught in scalar values and array elements.
        with self.assertRaises(ValueError):
            _project({'data': [{'id': 'my-pw-here'}]}, {'path': '/data', 'columns': ['id']}, ('pw',))
        with self.assertRaises(ValueError):
            _project({'data': [{'tags': ['ok', 'pw']}]}, {'path': '/data', 'columns': ['tags']}, ('pw',))

        # Array bounds and nested structure rejection.
        self.assertEqual(
            _project({'data': [{'tags': list(range(64))}]}, {'path': '/data', 'columns': ['tags']}, ()),
            [{'tags': list(range(64))}],
        )
        for bad_row in (
            {'tags': list(range(65))},
            {'tags': [{'nested': 'dict'}]},
            {'tags': [['nested', 'list']]},
            {'tags': [99]},
        ):
            with self.subTest(bad_row=bad_row), self.assertRaises(ValueError):
                _project({'data': [bad_row]}, {'path': '/data', 'columns': ['tags']}, (), private_number=99)

        # Non-guest text cells > 512 chars succeed up to 4096 and truncate at 4096 with control chars stripped.
        medium = 'm' * 1000
        self.assertEqual(_project({'data': [{'msg': medium}]}, {'path': '/data', 'columns': ['msg']}, ()), [{'msg': medium}])
        long_text = '\x1b[31mhi\x1b[0m\x00\n' + ('z' * 4500)
        truncated = _project({'data': [{'msg': long_text}]}, {'path': '/data', 'columns': ['msg']}, ())
        self.assertTrue(truncated[0]['msg'].startswith('hi\n'))
        self.assertTrue(truncated[0]['msg'].endswith('\n...[truncated]'))
        self.assertEqual(len(truncated[0]['msg']), 4096)
        with self.assertRaises(ValueError):
            _project({'data': [{'msg': ('a' * 4200) + 'secret-at-end'}]}, {'path': '/data', 'columns': ['msg']}, ('secret-at-end',))

        # Dot-path descriptor validation rejects leading/trailing/empty segments and private segments.
        valid_dot = parse_result_usage({
            'type': 'https_results', 'origin': 'https://synthetic.test',
            'request': {'path': '/items', 'auth': 'bearer'},
            'result': {'path': '/data', 'columns': ['metadata.name', 'status.phase']},
        })
        self.assertEqual(valid_dot.data['result']['columns'], ['metadata.name', 'status.phase'])
        for bad_col in ('.name', 'name.', 'a..b', 'user.ticket', 'meta.csrf_token', 'auth.password'):
            with self.subTest(bad_col=bad_col), self.assertRaises(ValueError):
                parse_result_usage({
                    'type': 'https_results', 'origin': 'https://synthetic.test',
                    'request': {'path': '/items', 'auth': 'bearer'},
                    'result': {'path': '/data', 'columns': [bad_col]},
                })

    def test_scrub_error_text(self):
        raw = '\x1b]0;title\x07\x1b[31mError:\x1b[0m\x00 bad\n\tuser=alice:pw12345 b64=' + b64encode(b'pw12345').decode() + ' short=pw'
        cleaned = scrub_error_text(raw, ['pw', 'alice:pw12345', 'pw12345'], max_len=120)
        self.assertNotIn('\x1b', cleaned)
        self.assertNotIn('\x00', cleaned)
        self.assertNotIn('pw12345', cleaned)
        self.assertNotIn('alice:pw12345', cleaned)
        self.assertNotIn(b64encode(b'pw12345').decode(), cleaned)
        self.assertNotIn('=pw', cleaned)
        self.assertIn('[REDACTED]', cleaned)
        self.assertLessEqual(len(cleaned), 120)

        truncated = scrub_error_text('word ' * 200, (), max_len=64)
        self.assertEqual(len(truncated), 64)
        self.assertTrue(truncated.endswith('...'))

    def test_http_features_204_gzip_deflate_cookies_headers_login_and_error_bodies(self):
        password = 'tok:with/special@chars=1!'
        session_cookie = 'sess-' + secrets.token_hex(12)
        csrf_hdr = 'csrf-hdr-' + secrets.token_hex(10)
        seen_accept_encoding = []

        class FeatureService(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def handle(self):
                try:
                    super().handle()
                except (OSError, ssl.SSLError):
                    pass
            def do_POST(self):
                if self.path == '/header-login':
                    if self.headers.get('Authorization') != 'Bearer ' + password:
                        self.send_response(401)
                        self.end_headers()
                        self.wfile.write(b'bad auth ' + password.encode())
                        return
                    self.send_response(204)
                    self.send_header('Set-Cookie', f'SESSIONID={session_cookie}; Path=/; HttpOnly; SameSite=Lax')
                    self.send_header('Set-Cookie', 'tiny=1; Path=/')
                    self.send_header('X-CSRF-Token', csrf_hdr)
                    self.end_headers()
                    return
                self.send_response(404)
                self.end_headers()
            def do_GET(self):
                seen_accept_encoding.append(self.headers.get('Accept-Encoding'))
                if self.path == '/items-gzip':
                    if self.headers.get('Cookie') != f'SESSIONID={session_cookie}' or self.headers.get('X-CSRF') != csrf_hdr:
                        self.send_response(403)
                        self.end_headers()
                        return
                    payload = gzip.compress(json.dumps({
                        'data': [{'id': 1, 'session_label': 'Path', 'session': 'ignored-key',
                                  'meta': {'name': 'tiny=1 ok', 'tags': ['a', 'b']}}]
                    }).encode('utf-8'))
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Encoding', 'gzip')
                    self.send_header('Content-Length', str(len(payload)))
                    self.send_header('Set-Cookie', 'flag=1; Path=/; HttpOnly; SameSite=Lax')
                    self.send_header('Authorization', 'short7')
                    self.send_header('ETag', '"v1-etag"')
                    self.send_header('X-Secret-Echo', f'leak {password} and {session_cookie}')
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if self.path == '/deflate-zlib':
                    payload = zlib.compress(json.dumps({'data': [{'ok': True}]}).encode('utf-8'))
                    self.send_response(200)
                    self.send_header('Content-Encoding', 'deflate')
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if self.path == '/deflate-raw':
                    comp = zlib.compressobj(wbits=-zlib.MAX_WBITS)
                    payload = comp.compress(json.dumps({'data': [{'ok': 'raw'}]}).encode('utf-8')) + comp.flush()
                    self.send_response(200)
                    self.send_header('Content-Encoding', 'deflate')
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if self.path == '/zip-bomb':
                    payload = gzip.compress(b'A' * (BODY_LIMIT + 1024))
                    self.send_response(200)
                    self.send_header('Content-Encoding', 'gzip')
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if self.path == '/empty-204':
                    self.send_response(204)
                    self.send_header('X-Request-Id', 'req-204')
                    self.end_headers()
                    return
                if self.path == '/empty-200':
                    self.send_response(200)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                if self.path == '/empty-json-object':
                    payload = b'{}'
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if self.path == '/error-gzip':
                    msg = ('\x1b[31mDenied\x1b[0m: bad secret ' + password + ' ' + ('x' * 5000)).encode('utf-8')
                    payload = gzip.compress(msg)
                    self.send_response(422)
                    self.send_header('Content-Encoding', 'gzip')
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return

        with TemporaryDirectory() as temporary, tls_service(temporary, handler=FeatureService) as (cert, origin, _):
            pin = sha256(ssl.PEM_cert_to_DER_cert(Path(cert).read_text())).hexdigest()
            entry = SimpleNamespace(username='svc-user', password=password)

            # 1. Header-based login (no body), cookie:<Name> + header:<Name> capture, gzip response,
            # Set-Cookie short-value non-poisoning, JSON key safety, and safe response header export.
            cfg = {
                'type': 'https_results',
                'origin': origin,
                'certificate_sha256': pin,
                'login': {
                    'path': '/header-login',
                    'headers': {'Authorization': 'Bearer {{password}}'},
                    'capture': {'sid': 'cookie:SESSIONID', 'csrf': 'header:X-CSRF-Token'},
                },
                'request': {
                    'path': '/items-gzip',
                    'auth': 'session',
                    'headers': {'Cookie': 'SESSIONID={{session.sid}}', 'X-CSRF': '{{session.csrf}}'},
                },
                'result': {
                    'path': '/data',
                    'columns': ['id', 'session_label', 'meta.name', 'meta.tags'],
                    'headers': ['ETag', 'X-Secret-Echo', 'X-Missing'],
                },
            }
            reply = deliver_results(cfg, entry, lambda: True)
            self.assertEqual(reply['outcome'], 'succeeded', reply)
            self.assertEqual(reply['http_status'], 200)
            self.assertEqual(reply['data'], [{'id': 1, 'session_label': 'Path', 'meta.name': 'tiny=1 ok', 'meta.tags': ['a', 'b']}])
            self.assertEqual(reply['headers']['ETag'], '"v1-etag"')
            self.assertNotIn('X-Missing', reply['headers'])
            self.assertNotIn(password, reply['headers']['X-Secret-Echo'])
            self.assertNotIn(session_cookie, reply['headers']['X-Secret-Echo'])
            self.assertIn('[REDACTED]', reply['headers']['X-Secret-Echo'])
            self.assertIn('gzip', seen_accept_encoding[-1])

            # 2. Relaxed Bearer token validation & deflate (zlib + raw) responses.
            for path, expected_val in (('/deflate-zlib', True), ('/deflate-raw', 'raw')):
                bearer_cfg = {
                    'type': 'https_results', 'origin': origin, 'certificate_sha256': pin,
                    'request': {'path': path, 'auth': 'bearer'},
                    'result': {'path': '/data', 'columns': ['ok']},
                }
                res = deliver_results(bearer_cfg, entry, lambda: True)
                self.assertEqual(res, {'outcome': 'succeeded', 'http_status': 200, 'data': [{'ok': expected_val}]})

            # Reject whitespace in Bearer token.
            bad_bearer = deliver_results(
                {'type': 'https_results', 'origin': origin, 'certificate_sha256': pin,
                 'request': {'path': '/deflate-zlib', 'auth': 'bearer'},
                 'result': {'path': '/data', 'columns': ['ok']}},
                SimpleNamespace(username='', password='bad token'),
                lambda: True,
            )
            self.assertEqual(bad_bearer['outcome'], 'failed')

            # 3. Zip bomb fails closed without exceeding BODY_LIMIT.
            bomb_cfg = {
                'type': 'https_results', 'origin': origin, 'certificate_sha256': pin,
                'request': {'path': '/zip-bomb', 'auth': 'bearer'},
                'result': {'path': '/data', 'columns': ['ok']},
            }
            bomb_res = deliver_results(bomb_cfg, entry, lambda: True)
            self.assertEqual(bomb_res['outcome'], 'failed')
            self.assertIn('limit', bomb_res.get('error_detail', ''))

            # 4. 204 No Content and empty 200 succeed with data=[]; non-empty {} still fails missing path.
            for path, code in (('/empty-204', 204), ('/empty-200', 200)):
                empty_cfg = {
                    'type': 'https_results', 'origin': origin, 'certificate_sha256': pin,
                    'request': {'path': path, 'auth': 'bearer'},
                    'result': {'path': '/data', 'columns': ['id'], 'headers': ['X-Request-Id']},
                }
                empty_res = deliver_results(empty_cfg, entry, lambda: True)
                self.assertEqual(empty_res['outcome'], 'succeeded')
                self.assertEqual(empty_res['http_status'], code)
                self.assertEqual(empty_res['data'], [])
                if code == 204:
                    self.assertEqual(empty_res['headers'], {'X-Request-Id': 'req-204'})

            nonempty_missing = deliver_results(
                {'type': 'https_results', 'origin': origin, 'certificate_sha256': pin,
                 'request': {'path': '/empty-json-object', 'auth': 'bearer'},
                 'result': {'path': '/data', 'columns': ['id']}},
                entry,
                lambda: True,
            )
            self.assertEqual(nonempty_missing['outcome'], 'failed')
            self.assertNotIn('data', nonempty_missing)

            # 5. Scrubbed gzip 422 error body.
            err_res = deliver_results(
                {'type': 'https_results', 'origin': origin, 'certificate_sha256': pin,
                 'request': {'path': '/error-gzip', 'auth': 'bearer'},
                 'result': {'path': '/data', 'columns': ['id']}},
                entry,
                lambda: True,
            )
            self.assertEqual(err_res['outcome'], 'failed')
            self.assertEqual(err_res['http_status'], 422)
            self.assertIn('[REDACTED]', err_res['error_detail'])
            self.assertNotIn(password, err_res['error_detail'])
            self.assertNotIn('\x1b', err_res['error_detail'])
            self.assertLessEqual(len(err_res['error_detail']), 512)

            # 6. Validation rejects invalid login captures/headers and private result.headers.
            for invalid in (
                {'type': 'https_results', 'origin': origin,
                 'login': {'path': '/login', 'headers': {'X-App': '1'}, 'capture': {'tok': '/tok'}},
                 'request': {'path': '/items', 'auth': 'session', 'headers': {'Cookie': '{{session.tok}}'}},
                 'result': {'path': '/data', 'columns': ['id']}},
                {'type': 'https_results', 'origin': origin,
                 'login': {'path': '/login', 'headers': {'Authorization': '{{password}}'}, 'capture': {'tok': 'cookie:'}},
                 'request': {'path': '/items', 'auth': 'session', 'headers': {'Cookie': '{{session.tok}}'}},
                 'result': {'path': '/data', 'columns': ['id']}},
                {'type': 'https_results', 'origin': origin,
                 'login': {'path': '/login', 'headers': {'Authorization': '{{password}}'}, 'capture': {'tok': 'header:bad name'}},
                 'request': {'path': '/items', 'auth': 'session', 'headers': {'Cookie': '{{session.tok}}'}},
                 'result': {'path': '/data', 'columns': ['id']}},
                {'type': 'https_results', 'origin': origin,
                 'request': {'path': '/items', 'auth': 'bearer'},
                 'result': {'path': '/data', 'columns': ['id'], 'headers': ['Set-Cookie']}},
                {'type': 'https_results', 'origin': origin,
                 'request': {'path': '/items', 'auth': 'bearer'},
                 'result': {'path': '/data', 'columns': ['id'], 'headers': ['Authorization']}},
                {'type': 'https_results', 'origin': origin,
                 'request': {'path': '/items', 'auth': 'bearer'},
                 'result': {'path': '/data', 'columns': ['id'], 'headers': ['ETag', 'etag']}},
                {'type': 'https_results', 'origin': origin,
                 'request': {'path': '/items', 'auth': 'bearer'},
                 'result': {'path': '/data', 'columns': ['id'], 'headers': [f'X-H-{i}' for i in range(9)]}},
            ):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    parse_result_usage(invalid)
