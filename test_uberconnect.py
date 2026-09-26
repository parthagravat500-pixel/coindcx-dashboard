import base64
import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlencode, urlsplit

import app
import uberconnect as uber

ENV = {'UBER_PROFILE_API_APPROVED': 'true', 'UBER_CLIENT_ID': 'fixture-client',
       'UBER_CLIENT_SECRET': 'fixture-secret-only-never-live',
       'UBER_REDIRECT_URI': 'https://dashboard.example.com/api/uber/callback'}
ACCESS = 'fixture-access-token-never-live'
TOKEN = {'access_token': ACCESS, 'token_type': 'Bearer', 'expires_in': 3600, 'scope': 'profile'}
PROFILE = {'sub': 'fixture-user', 'email': 'private-fixture@example.invalid', 'phone_number': 'private-fixture'}


class UberTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, ENV, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.now = 1000
        self.transport = MagicMock(side_effect=lambda kind, values, **kw: dict(TOKEN) if kind == 'exchange' else dict(PROFILE) if kind == 'profile' else {})
        self.manager = uber.UberConnection(self.transport, lambda: self.now)

    def begin(self):
        url, binding = self.manager.begin(True)
        state = parse_qs(urlsplit(url).query)['state'][0]
        return urlencode({'code': 'fixture-code', 'state': state}), uber.COOKIE + '=' + binding

    def connect(self):
        self.manager.complete(*self.begin())

    def test_missing_approval_config_and_consent_never_send_requests(self):
        for consent in (None, False, 'true', 1):
            with self.assertRaises(ValueError):
                self.manager.begin(consent)
        for key in ENV:
            with self.subTest(key=key), patch.dict(os.environ, {key: ''}):
                self.assertFalse(self.manager.status()['can_connect'])
                with self.assertRaises(ValueError):
                    self.manager.begin(True)
        self.transport.assert_not_called()

    def test_redirect_must_be_fixed_https_callback_without_credentials(self):
        for uri in ('http://dashboard.example.com/api/uber/callback',
                    'https://dashboard.example.com/other',
                    'https://name:secret@dashboard.example.com/api/uber/callback',
                    ENV['UBER_REDIRECT_URI'] + '?next=https://example.invalid',
                    ENV['UBER_REDIRECT_URI'] + '#secret',
                    'https://dashboard.example.com:8080/api/uber/callback'):
            with self.subTest(uri=uri), patch.dict(os.environ, {'UBER_REDIRECT_URI': uri}):
                with self.assertRaises(ValueError):
                    self.manager.begin(True)
        self.transport.assert_not_called()

    def test_start_is_profile_only_and_status_does_not_leak_secrets(self):
        query, cookie = self.begin()
        self.assertEqual(self.manager.status()['status'], 'awaiting_uber')
        self.assertFalse(self.manager.status()['connected'])
        self.assertFalse(self.manager.status()['can_connect'])
        public = json.dumps(self.manager.status())
        for secret in (ENV['UBER_CLIENT_SECRET'], query, cookie):
            self.assertNotIn(secret, public)
        self.transport.assert_not_called()

    def test_state_cookie_expiry_and_duplicates_block_exchange(self):
        query, cookie = self.begin()
        for q, c in ((query, ''), (query, cookie + 'wrong'), ('state=wrong&code=fixture', cookie),
                     (query + '&state=other', cookie), (query + '&code=other', cookie),
                     ('state=x&code=' + 'x' * 8200, cookie)):
            with self.assertRaises(ValueError):
                self.manager.complete(q, c)
        self.transport.assert_not_called()
        self.now += 600
        with self.assertRaises(ValueError):
            self.manager.complete(query, cookie)
        self.assertEqual(self.manager.status()['status'], 'expired')
        self.transport.assert_not_called()

    def test_denial_is_consumed_and_does_not_retry(self):
        query, cookie = self.begin()
        with self.assertRaises(ValueError):
            self.manager.complete(query + '&error=access_denied&error_description=PRIVATE', cookie)
        with self.assertRaises(ValueError):
            self.manager.complete(query, cookie)
        self.transport.assert_not_called()
        self.assertNotIn('PRIVATE', json.dumps(self.manager.status()))

    def test_verified_connection_discards_profile_and_prevents_replay(self):
        query, cookie = self.begin()
        self.manager.complete(query, cookie)
        self.assertTrue(self.manager.status()['connected'])
        self.assertEqual(self.manager.status()['expires_at'], 4600)
        self.assertFalse(self.manager.status()['authorizes_testing'])
        self.assertFalse(self.manager.status()['tests_enabled'])
        for secret in (ACCESS, ENV['UBER_CLIENT_SECRET'], *PROFILE.values()):
            self.assertNotIn(secret, json.dumps(self.manager.status()))
        with self.assertRaises(ValueError):
            self.manager.complete(query, cookie)
        self.assertEqual([c.args[0] for c in self.transport.call_args_list], ['exchange', 'profile'])
        self.assertFalse(uber.UberConnection(self.transport).status()['connected'])

    def test_expiry_and_configuration_changes_remove_connected_status(self):
        self.connect()
        with patch.dict(os.environ, {'UBER_CLIENT_SECRET': 'changed-fixture-secret-only'}):
            self.assertFalse(self.manager.status()['connected'])
            self.assertTrue(self.manager.status()['can_disconnect'])
        with patch.dict(os.environ, {'UBER_PROFILE_API_APPROVED': 'false'}):
            self.assertFalse(self.manager.status()['connected'])
        self.now += 3600
        self.assertEqual(self.manager.status()['status'], 'expired')
        self.assertFalse(self.manager.status()['connected'])
        self.assertEqual(self.transport.call_count, 2)

    def test_scope_and_token_validation_fail_before_profile(self):
        for change in ({'scope': 'profile history'}, {'scope': ''}, {'scope': None},
                       {'expires_in': True}, {'expires_in': 0}, {'token_type': 'Basic'},
                       {'access_token': 'bad\r\nheader'}):
            with self.subTest(change=change):
                self.setUpFixtureTransport({**TOKEN, **change})
                with self.assertRaises(ValueError):
                    self.connect()
                self.assertFalse(self.manager.status()['connected'])
                self.assertNotIn('profile', [c.args[0] for c in self.transport.call_args_list])

    def setUpFixtureTransport(self, response):
        self.transport = MagicMock(side_effect=lambda kind, values, **kw: response if kind == 'exchange' else {})
        self.manager = uber.UberConnection(self.transport, lambda: self.now)

    def test_failed_profile_revokes_token_without_exposing_response(self):
        def transport(kind, values, **kw):
            if kind == 'exchange':
                return dict(TOKEN)
            if kind == 'profile':
                raise RuntimeError('PRIVATE ' + ACCESS)
            return {}
        self.transport.side_effect = transport
        with self.assertRaises(ValueError) as error:
            self.connect()
        self.assertNotIn(ACCESS, str(error.exception))
        self.assertFalse(self.manager.status()['connected'])
        self.assertEqual([c.args[0] for c in self.transport.call_args_list], ['exchange', 'profile', 'revoke'])

    def test_disconnect_during_exchange_never_restores_connection(self):
        def transport(kind, values, **kw):
            if kind == 'exchange':
                self.manager.disconnect()
                return dict(TOKEN)
            return {}
        self.transport.side_effect = transport
        with self.assertRaises(ValueError):
            self.connect()
        self.assertEqual([c.args[0] for c in self.transport.call_args_list], ['exchange', 'revoke'])
        self.assertFalse(self.manager.status()['connected'])

    def test_disconnect_forgets_token_even_when_revocation_fails(self):
        self.connect()
        self.transport.side_effect = RuntimeError('PRIVATE ' + ACCESS)
        self.manager.disconnect()
        state = self.manager.status()
        self.assertFalse(state['connected'])
        self.assertIsNone(self.manager.token)
        self.assertTrue(state['revocation_unconfirmed'])
        self.assertNotIn(ACCESS, json.dumps(state))

    def test_profile_check_cannot_extend_expired_token(self):
        def transport(kind, values, **kw):
            if kind == 'exchange':
                return dict(TOKEN)
            if kind == 'profile':
                self.now += 3600
                return dict(PROFILE)
            return {}
        self.transport.side_effect = transport
        with self.assertRaises(ValueError):
            self.connect()
        self.assertFalse(self.manager.status()['connected'])
        self.assertEqual([c.args[0] for c in self.transport.call_args_list], ['exchange', 'profile', 'revoke'])

    def test_cancel_pending_attempt_blocks_late_callback(self):
        query, cookie = self.begin()
        self.manager.disconnect()
        with self.assertRaises(ValueError):
            self.manager.complete(query, cookie)
        self.transport.assert_not_called()

    def test_http_transport_has_fixed_destinations_and_no_redirect_or_retry(self):
        values, _ = uber.config()
        for kind, (host, path, method) in uber.ENDPOINTS.items():
            response = MagicMock(status=200)
            response.read.return_value = b'{}'
            response.getheader.return_value = 'application/json; charset=utf-8'
            conn = MagicMock()
            conn.getresponse.return_value = response
            with patch('uberconnect.http.client.HTTPSConnection', return_value=conn) as client:
                uber.request(kind, values, code='fixture-code', token=ACCESS)
            client.assert_called_once_with(host, 443, timeout=12)
            self.assertEqual(conn.request.call_args.args, (method, path))
            self.assertEqual(conn.request.call_count, 1)
            conn.close.assert_called_once()
        for status, body, mime in ((302, b'PRIVATE', 'text/html'), (429, b'PRIVATE', 'application/json'),
                                   (200, b'x' * (uber.MAX_BODY + 1), 'application/json'),
                                   (200, b'PRIVATE', 'text/html')):
            response = MagicMock(status=status)
            response.read.return_value = body
            response.getheader.return_value = mime
            conn = MagicMock()
            conn.getresponse.return_value = response
            with patch('uberconnect.http.client.HTTPSConnection', return_value=conn):
                with self.assertRaises(ValueError) as error:
                    uber.request('exchange', values, code='fixture-code')
            self.assertNotIn('PRIVATE', str(error.exception))
            self.assertEqual(conn.request.call_count, 1)
            conn.close.assert_called_once()


class UberHTTPTests(unittest.TestCase):
    def test_auth_csrf_callback_cookie_and_no_target_activation(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, ENV, clear=True), \
                patch.object(app, 'DATA', Path(tmp)), patch.object(app, 'TOKEN', 'fixture-dashboard-password-not-live'):
            calls = []
            def transport(kind, values, **kw):
                calls.append(kind)
                return dict(TOKEN) if kind == 'exchange' else dict(PROFILE) if kind == 'profile' else {}
            with patch.object(uber, 'manager', uber.UberConnection(transport)):
                app.init()
                server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                client = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                auth = {'Authorization': 'Basic ' + base64.b64encode(('admin:' + app.TOKEN).encode()).decode()}
                headers = {**auth, 'X-CSRF-Token': app.CSRF}
                def send(method, path, request_headers=None, body=None):
                    client.request(method, path, headers=request_headers or {}, body=body)
                    response = client.getresponse()
                    return response.status, dict(response.getheaders()), response.read()
                try:
                    self.assertEqual(send('POST', '/api/uber/start', body='{"consent":true}')[0], 401)
                    self.assertEqual(send('POST', '/api/uber/start', auth, '{"consent":true}')[0], 403)
                    self.assertEqual(send('GET', '/api/uber/callback?state=x&code=x')[0], 401)
                    self.assertEqual(send('GET', '/api/uber/callback?state=x&code=x', auth)[0], 400)
                    self.assertEqual(send('POST', '/api/uber/start', headers, '{"consent":true,"password":"PRIVATE"}')[0], 400)
                    self.assertEqual(calls, [])
                    status, result_headers, body = send('POST', '/api/uber/start', headers, '{"consent":true}')
                    self.assertEqual(status, 200)
                    cookie = result_headers['Set-Cookie']
                    for flag in ('__Host-', 'Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=600'):
                        self.assertIn(flag, cookie)
                    params = parse_qs(urlsplit(json.loads(body)['authorization_url']).query)
                    self.assertEqual(params['scope'], ['profile'])
                    self.assertNotIn(ENV['UBER_CLIENT_SECRET'], body.decode())
                    callback = '/api/uber/callback?' + urlencode({'state': params['state'][0], 'code': 'fixture-code'})
                    status, result_headers, body = send('GET', callback, {**auth, 'Cookie': cookie.split(';')[0]})
                    self.assertEqual(status, 303)
                    self.assertEqual(result_headers['Location'], '/#uberConnectionCard')
                    self.assertIn('Max-Age=0', result_headers['Set-Cookie'])
                    self.assertEqual(result_headers['Referrer-Policy'], 'no-referrer')
                    self.assertEqual(calls, ['exchange', 'profile'])
                    snapshot = app.snapshot()
                    self.assertTrue(snapshot['uber_connection']['connected'])
                    self.assertTrue(snapshot['paused'])
                    self.assertEqual(snapshot['targets'], [])
                    self.assertEqual(snapshot['findings'], [])
                    for value in (ACCESS, ENV['UBER_CLIENT_SECRET'], *PROFILE.values()):
                        self.assertNotIn(value, json.dumps(snapshot))
                    self.assertEqual(send('POST', '/api/uber/disconnect', auth, '{}')[0], 403)
                    self.assertTrue(uber.manager.status()['connected'])
                    self.assertEqual(send('POST', '/api/uber/disconnect', headers, '{}')[0], 200)
                    self.assertFalse(uber.manager.status()['connected'])
                    self.assertEqual(calls, ['exchange', 'profile', 'revoke'])
                finally:
                    client.close()
                    server.shutdown()
                    server.server_close()
                    thread.join()


if __name__ == '__main__':
    unittest.main()
