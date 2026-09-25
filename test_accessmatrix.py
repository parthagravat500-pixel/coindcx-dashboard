import http.client
import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

import accesscheck
import accessmatrix
import app

MARKER_A = 'scopeguard_account_a_synthetic_marker_9876'
MARKER_B = 'scopeguard_account_b_synthetic_marker_1234'
AUTH_A = 'Bearer fixture-owned-account-a'
AUTH_B = 'Bearer fixture-owned-account-b'
CONFIG = {'mode': 'two_account', 'url': 'https://example.com/account-a-record',
          'authorization': AUTH_A, 'marker': MARKER_A,
          'peer_url': 'https://example.com/account-b-record',
          'peer_authorization': AUTH_B, 'peer_marker': MARKER_B}


def response(status=200, marker=True, json_body=True):
    return {'status': status, 'json': json_body, 'marker_present': marker,
            'bytes': 60, 'sha256': 'synthetic-response-digest'}


class MatrixTests(unittest.TestCase):
    def run_matrix(self, responses, allowed=lambda: True):
        transport = MagicMock(side_effect=responses)
        pace = MagicMock()
        result = accessmatrix.compare(CONFIG, transport, allowed, pace)
        return result, transport, pace

    def test_reproduction_requires_both_controls_and_repeated_peer_exposure(self):
        result, transport, pace = self.run_matrix([response()] * 6)
        self.assertTrue(result['reproduced'])
        self.assertFalse(result['submission_ready'])
        self.assertEqual(transport.call_count, 6)
        self.assertEqual(pace.call_count, 5)
        self.assertEqual([c.args[1] for c in transport.call_args_list], [AUTH_A, AUTH_B, AUTH_B, AUTH_B, AUTH_A, AUTH_B])
        for private in (AUTH_A, AUTH_B, MARKER_A, MARKER_B):
            self.assertNotIn(private, json.dumps(result))

    def test_denied_peer_access_repeats_controls_before_concluding(self):
        for denied in (response(401, False), response(403, False), response(404, False), response(200, False)):
            result, transport, _ = self.run_matrix([response(), response(), denied, response(), response()])
            self.assertIn('held', result['status'])
            self.assertFalse(result['reproduced'])
            self.assertEqual(transport.call_count, 5)

    def test_expired_peer_control_cannot_be_reported_as_secure(self):
        result, transport, _ = self.run_matrix([response(), response(401, False)])
        self.assertIn('Setup needs attention', result['status'])
        self.assertEqual(transport.call_count, 2)
        result, _, _ = self.run_matrix([response(), response(), response(403, False), response(), response(401, False)])
        self.assertIn('inconclusive', result['status'])

    def test_inconsistent_or_non_json_exposure_never_confirms(self):
        result, _, _ = self.run_matrix([response(), response(), response(), response(403, False), response(), response()])
        self.assertIn('Inconclusive', result['status'])
        self.assertFalse(result['reproduced'])
        for probe in (response(302), response(200, True, False)):
            result, _, _ = self.run_matrix([response(), response(), probe, response(), response()])
            self.assertIn('Inconclusive', result['status'])

    def test_rate_limit_and_server_error_stop_immediately(self):
        for status in (429, 500, 503):
            transport = MagicMock(side_effect=[response(), response(status, False)])
            with self.assertRaises(RuntimeError):
                accessmatrix.compare(CONFIG, transport, pace=lambda _: None)
            self.assertEqual(transport.call_count, 2)

    def test_revocation_during_pacing_stops_before_next_request(self):
        allowed = [True]
        transport = MagicMock(return_value=response())
        with self.assertRaises(InterruptedError):
            accessmatrix.compare(CONFIG, transport, lambda: allowed[0], lambda _: allowed.__setitem__(0, False))
        self.assertEqual(transport.call_count, 1)

    def test_real_loopback_fixture_secure_and_vulnerable_variants(self):
        # Network traffic is confined to a deliberately created local fixture.
        # Production transports remain HTTPS-only and reject loopback addresses.
        class Fixture(BaseHTTPRequestHandler):
            vulnerable = False

            def log_message(self, *args):
                pass

            def do_GET(self):
                auth = self.headers.get('Authorization')
                owner = AUTH_A if self.path == '/account-a-record' else AUTH_B
                permitted = auth == owner or (self.vulnerable and self.path == '/account-a-record' and auth == AUTH_B)
                body = json.dumps({'record': (MARKER_A if owner == AUTH_A else MARKER_B)} if permitted else {'error': 'Forbidden'}).encode()
                self.send_response(200 if permitted else 403)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def transport(url, auth, marker):
            conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
            try:
                conn.request('GET', '/' + url.rsplit('/', 1)[1], headers={'Authorization': auth})
                reply = conn.getresponse()
                value = json.loads(reply.read())
                return response(reply.status, value.get('record') == marker)
            finally:
                conn.close()

        try:
            secure = accessmatrix.compare(CONFIG, transport, pace=lambda _: None)
            self.assertFalse(secure['reproduced'])
            self.assertIn('held', secure['status'])
            Fixture.vulnerable = True
            vulnerable = accessmatrix.compare(CONFIG, transport, pace=lambda _: None)
            self.assertTrue(vulnerable['reproduced'])
            self.assertEqual(len(vulnerable['evidence']), 6)
            self.assertFalse(vulnerable['submission_ready'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)


class MatrixConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        data = patch.object(app, 'DATA', Path(self.temp.name))
        data.start()
        self.addCleanup(data.stop)
        app.init()
        self.expires = int(time.time()) + 3600
        with app.db() as c:
            for name, url in [('A', CONFIG['url']), ('B', CONFIG['peer_url'])]:
                c.execute('INSERT INTO targets(name,url,policy,rules,expires,interval,cors) VALUES(?,?,?,?,?,900,0)',
                          (name, url, 'https://example.com/policy', 'Owned fixtures only; no external tests', self.expires))
        self.form = dict(target=1, peer_target=2, marker=MARKER_A, peer_marker=MARKER_B,
                         authorization=AUTH_A, peer_authorization=AUTH_B, mode='two_account',
                         rules='Owned isolated fixture permits six read-only comparisons every fifteen minutes.',
                         permission=True, own_data=True, read_only=True, private_expected=True,
                         two_accounts_owned=True, six_requests_permitted=True)

    def test_config_requires_explicit_new_permission_and_distinct_accounts(self):
        for override in ({'two_accounts_owned': False}, {'six_requests_permitted': False},
                         {'peer_authorization': AUTH_A}, {'peer_marker': MARKER_A},
                         {'peer_target': 1}, {'mode': 'scan_everything'}):
            with self.subTest(override=override), self.assertRaises(ValueError):
                app.mutate('/api/access-check', {**self.form, **override})
        self.assertFalse(accesscheck.config_path(app.DATA, 1).exists())

    def test_config_rejects_cross_origin_policy_and_disabled_control(self):
        for field, value in [('url', 'https://other.example/account-b'), ('policy', 'https://other.example/policy'), ('enabled', 0), ('expires', 0)]:
            with app.db() as c:
                c.execute('UPDATE targets SET url=?,policy=?,enabled=1,expires=? WHERE id=2', (CONFIG['peer_url'], 'https://example.com/policy', self.expires))
                c.execute('UPDATE targets SET ' + field + '=? WHERE id=2', (value,))
            with self.assertRaises(ValueError):
                app.mutate('/api/access-check', self.form)

    def test_credentials_stay_private_and_expiry_uses_earliest_scope(self):
        with app.db() as c:
            c.execute('UPDATE targets SET expires=? WHERE id=2', (self.expires - 100,))
        app.mutate('/api/access-check', self.form)
        private = accesscheck.config_path(app.DATA, 1)
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        self.assertEqual(app.snapshot()['access_checks'][0]['expires'], self.expires - 100)
        for secret in (AUTH_A, AUTH_B, MARKER_A, MARKER_B):
            self.assertNotIn(secret, json.dumps(app.snapshot()))

    def test_revoked_second_target_stops_dispatch(self):
        app.mutate('/api/access-check', self.form)
        app.mutate('/api/all-pause', {'paused': False})
        with app.db() as c:
            c.execute('UPDATE targets SET enabled=0 WHERE id=2')
        with patch('accesscheck.fetch') as transport, patch('accessmatrix.time.sleep'):
            accesscheck.tick(app.db, app.DATA, app.log)
            transport.assert_not_called()
        profile = app.snapshot()['access_checks'][0]
        self.assertFalse(profile['enabled'])
        self.assertFalse(profile['result']['reproduced'])

    def test_inconclusive_result_disables_further_reads(self):
        app.mutate('/api/access-check', self.form)
        app.mutate('/api/all-pause', {'paused': False})
        result = {'mode': 'two_account', 'status': 'Inconclusive: fixture', 'reproduced': False, 'submission_ready': False, 'evidence': []}
        with patch('accesscheck.compare', return_value=result) as compare:
            accesscheck.tick(app.db, app.DATA, app.log)
            accesscheck.tick(app.db, app.DATA, app.log)
            compare.assert_called_once()
        self.assertFalse(app.snapshot()['access_checks'][0]['enabled'])

    def test_due_profiles_rotate_between_programs_one_at_a_time(self):
        legacy = {k: v for k, v in self.form.items() if k not in ('mode', 'peer_target', 'peer_marker', 'peer_authorization', 'two_accounts_owned', 'six_requests_permitted')}
        app.mutate('/api/access-check', legacy)
        with app.db() as c:
            c.execute('UPDATE targets SET policy=? WHERE id=2', ('https://second.example/policy',))
            c.execute('INSERT INTO program_rotation VALUES(?,?)', ('https://example.com/policy', int(time.time())))
        app.mutate('/api/access-check', {**legacy, 'target': 2})
        app.mutate('/api/all-pause', {'paused': False})
        result = {'status': 'Access boundary held for this test', 'reproduced': False, 'submission_ready': False, 'evidence': []}
        with patch('accesscheck.compare', return_value=result) as compare:
            accesscheck.tick(app.db, app.DATA, app.log)
            self.assertEqual(compare.call_count, 1)
            self.assertEqual(compare.call_args.args[0]['url'], CONFIG['peer_url'])
            accesscheck.tick(app.db, app.DATA, app.log)
            self.assertEqual(compare.call_count, 2)
            self.assertEqual(compare.call_args.args[0]['url'], CONFIG['url'])
