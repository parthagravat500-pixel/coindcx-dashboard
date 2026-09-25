import copy
import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

import gitlabcheck
import gitlabpair


class PairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.c = sqlite3.connect(':memory:')
        self.addCleanup(self.c.close)
        self.c.row_factory = sqlite3.Row
        self.c.execute('CREATE TABLE settings(paused INTEGER)')
        self.c.execute('INSERT INTO settings VALUES(0)')
        gitlabcheck.init(self.c)
        self.owner = dict(project='owner-a/private-a', token='glpat-' + 'a' * 24, marker='scopeguard_' + 'a' * 32)
        self.peer = dict(project='owner-b/private-b', token='glpat-' + 'b' * 24, marker='scopeguard_' + 'b' * 32)
        self.consent = dict(own_project=True, policy_permission=True, read_only=True,
                            two_accounts_owned=True, rules='Owned unshared fixture accounts; eight read-only comparisons per fifteen minutes permitted.')
        gitlabcheck.configure(self.c, self.root, {**self.owner, **self.consent})
        self.c.execute("UPDATE gitlab_check SET result=?,due=? WHERE id=1", (json.dumps({'verified_connection': True}), int(time.time()) + 900))
        self.form = dict(self.peer, **self.consent, mode='two_account')

    @contextmanager
    def db(self):
        yield self.c
        self.c.commit()

    @staticmethod
    def response(data=None, status=200):
        return dict(status=status, data=data, bytes=32, sha256='synthetic-fingerprint')

    def token_info(self, user):
        return self.response(dict(user_id=user, active=True, revoked=False, scopes=['read_api']))

    def project(self, account='A', role=50, private=True):
        config = self.owner if account == 'A' else self.peer
        return self.response(dict(id=10 if account == 'A' else 20, path_with_namespace=config['project'],
                                 visibility='private' if private else 'public', description=config['marker'],
                                 permissions={'group_access': {'access_level': role}}))

    def denied(self):
        return [self.token_info(1), self.token_info(2), self.project(), self.project('B'),
                self.response({}, 404), self.project(), self.project('B')]

    def run_compare(self, replies, allowed=lambda: True, pace=None):
        transport = Mock(side_effect=replies)
        pace = pace or Mock()
        result = gitlabpair.compare(self.owner, self.peer, allowed, transport, pace)
        return result, transport, pace

    def test_denial_checks_distinct_identities_and_both_controls_twice(self):
        result, transport, pace = self.run_compare(self.denied())
        self.assertIn('boundary held', result['status'])
        self.assertTrue(result['verified_connection'])
        self.assertTrue(result['account_identities_distinct'])
        self.assertFalse(result['reproduced'])
        self.assertFalse(result['submission_ready'])
        self.assertEqual(transport.call_count, 7)
        self.assertEqual(pace.call_count, 7)
        self.assertEqual(len(result['evidence']), 7)
        for secret in (self.owner['token'], self.peer['token'], self.owner['marker'], self.peer['marker']):
            self.assertNotIn(secret, json.dumps(result))

    def test_same_identity_and_excess_scope_stop_before_project_requests(self):
        for responses in ([self.token_info(1), self.token_info(1)],
                          [self.response(dict(user_id=1, active=True, revoked=False, scopes=['api']))]):
            result, transport, _ = self.run_compare(responses)
            self.assertTrue(result['status'].startswith('Setup needed:'))
            self.assertFalse(result['reproduced'])
            self.assertLessEqual(transport.call_count, 2)

    def test_repeated_exposure_is_candidate_only_with_eight_request_cap(self):
        responses = [self.token_info(1), self.token_info(2), self.project(), self.project('B'),
                     self.project(role=0), self.project(role=0), self.project(), self.project('B')]
        result, transport, _ = self.run_compare(responses)
        self.assertTrue(result['reproduced'])
        self.assertFalse(result['submission_ready'])
        self.assertEqual(result['severity'], 'Not assessed')
        self.assertEqual(transport.call_count, 8)

    def test_intended_project_membership_never_becomes_a_finding(self):
        replies = [self.token_info(1), self.token_info(2), self.project(), self.project('B'),
                   self.project(role=20), self.project(role=20), self.project(), self.project('B')]
        result, _, _ = self.run_compare(replies)
        self.assertFalse(result['reproduced'])
        self.assertIn('assigned role', result['status'])

    def test_wrong_project_public_control_or_insufficient_role_stop(self):
        wrong = self.project()
        wrong['data']['path_with_namespace'] = 'some-other/private-project'
        for control in (wrong, self.project(role=20), self.project(private=False)):
            result, transport, _ = self.run_compare([self.token_info(1), self.token_info(2), control])
            self.assertIn('Setup needs attention', result['status'])
            self.assertFalse(result['verified_connection'])
            self.assertEqual(transport.call_count, 3)

    def test_failed_repeated_control_is_not_reported_as_a_pass(self):
        replies = self.denied()
        replies[-1] = self.response({}, 401)
        result, _, _ = self.run_compare(replies)
        self.assertIn('inconclusive', result['status'])
        self.assertFalse(result['verified_connection'])

    def test_server_limit_stops_without_retry(self):
        for status in (429, 500, 503):
            result, transport, _ = self.run_compare([dict(self.response({}, status), retry_at=12345)])
            self.assertTrue(result['provider_stop'])
            self.assertEqual(result['retry_at'], 12345)
            self.assertEqual(transport.call_count, 1)

    def test_pause_during_pacing_prevents_request(self):
        permitted = [True]
        result, transport, _ = self.run_compare([], lambda: permitted[0], lambda _: permitted.__setitem__(0, False))
        self.assertIn('paused', result['status'])
        transport.assert_not_called()

    def test_configuration_reuses_primary_server_file_and_keeps_secrets_private(self):
        before = gitlabcheck.secret_path(self.root).read_bytes()
        gitlabcheck.configure(self.c, self.root, self.form)
        path = gitlabpair.secret_path(self.root)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.owner['token'], path.read_text())
        self.assertEqual(before, gitlabcheck.secret_path(self.root).read_bytes())
        state = gitlabcheck.snapshot(self.c)
        self.assertEqual(state['expires'], state['peer']['expires'])
        for private in (self.owner['token'], self.peer['token'], self.owner['marker'], self.peer['marker']):
            self.assertNotIn(private, json.dumps(state))

    def test_missing_consent_duplicate_project_token_or_marker_is_rejected(self):
        for change in ({'two_accounts_owned': False}, {'policy_permission': False},
                       {'project': self.owner['project']}, {'token': self.owner['token']},
                       {'marker': self.owner['marker']}, {'token': 'invalid\nheader'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                gitlabcheck.configure(self.c, self.root, {**self.form, **change})
        self.assertFalse(gitlabpair.secret_path(self.root).exists())

    def test_revoked_primary_dispatches_nothing_and_peer_disconnect_preserves_primary(self):
        gitlabcheck.configure(self.c, self.root, self.form)
        self.c.execute('UPDATE gitlab_check SET enabled=0 WHERE id=1')
        with patch('gitlabpair.compare') as compare:
            gitlabpair.tick(self.db, self.root, lambda *args: None)
            compare.assert_not_called()
        self.assertFalse(gitlabpair.snapshot(self.c)['enabled'])
        gitlabcheck.configure(self.c, self.root, {'mode': 'remove_peer'})
        self.assertFalse(gitlabpair.secret_path(self.root).exists())
        self.assertTrue(gitlabcheck.secret_path(self.root).exists())

    def test_disconnect_primary_removes_both_credentials(self):
        gitlabcheck.configure(self.c, self.root, self.form)
        gitlabcheck.disconnect(self.c, self.root)
        self.assertFalse(gitlabcheck.secret_path(self.root).exists())
        self.assertFalse(gitlabpair.secret_path(self.root).exists())
        self.assertFalse(gitlabpair.snapshot(self.c)['configured'])

    def test_peer_rate_limit_pauses_both_checks(self):
        gitlabcheck.configure(self.c, self.root, self.form)
        stopped = dict(status='Stopped: HTTP 429; no conclusion', evidence=[], provider_stop=True)
        with patch('gitlabpair.compare', return_value=stopped):
            gitlabpair.tick(self.db, self.root, lambda *args: None)
        self.assertFalse(gitlabcheck.snapshot(self.c)['enabled'])
        self.assertFalse(gitlabpair.snapshot(self.c)['enabled'])

    def test_configuration_cannot_reset_the_peer_request_cooldown(self):
        gitlabcheck.configure(self.c, self.root, self.form)
        checked = int(time.time())
        self.c.execute('UPDATE gitlab_peer SET checked=? WHERE id=1', (checked,))
        gitlabcheck.configure(self.c, self.root, self.form)
        self.assertGreaterEqual(gitlabpair.snapshot(self.c)['due'], checked + 900)
