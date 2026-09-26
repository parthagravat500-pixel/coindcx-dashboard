import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import app
import policyevidence


class PolicyEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.reviews = self.root / 'reviews'
        self.reviews.mkdir()
        for target, value in [('app.DATA', self.root / 'data'), ('policyevidence.DIRECTORY', self.reviews)]:
            p = patch(target, value)
            p.start()
            self.addCleanup(p.stop)
        app.DATA.mkdir()
        app.init()

    def save(self, **changes):
        data = {'program': 'Synthetic unlisted program', 'policy_url': 'https://example.com/policy',
                'checked_at': '2026-09-26T00:00:00Z', 'scope_complete': True,
                'in_scope_assets': ['public.example.com'], 'excluded_assets': ['private.example.com'],
                'accounts': 'Owned accounts required', 'automation': 'Unverified',
                'sources': ['https://example.com/policy'], 'grants_permission': True,
                'targets_activated': 99, 'private_token': 'must not be published'}
        data.update(changes)
        (self.reviews / 'fixture-batch-01.json').write_text(json.dumps({'schema_version': 1, 'records': [data]}))

    def test_unlisted_review_is_visible_without_authorizing_or_network(self):
        self.save()
        app.mutate('/api/pause', {'paused': False})
        with patch('urllib.request.urlopen') as network, patch('app.observe') as observe:
            state = app.snapshot()
            app.tick()
            network.assert_not_called()
            observe.assert_not_called()
        self.assertEqual(state['workflow']['programs'], [])
        evidence = state['workflow']['policy_evidence']
        self.assertEqual(len(evidence['records']), 1)
        review = evidence['records'][0]
        self.assertEqual(review['in_scope_assets'], ['public.example.com'])
        self.assertEqual(review['accounts'], 'Owned accounts required')
        self.assertIsNone(review['explicit_requests_per_second'])
        self.assertFalse(review['grants_permission'])
        self.assertEqual(review['targets_activated'], 0)
        self.assertNotIn('private_token', review)
        self.assertEqual(state['targets'], [])
        self.assertEqual(state['program_queue']['completed'], 0)

    def test_bad_evidence_does_not_crash_dashboard_or_count_as_reviewed(self):
        self.save()
        (self.reviews / 'fixture-batch-02.json').write_text('{broken')
        (self.reviews / 'fixture-batch-03.json').write_text(json.dumps({'schema_version': 1,
            'records': [{'program': 'No source', 'policy_url': 'javascript:alert(1)'}]}))
        evidence = app.snapshot()['workflow']['policy_evidence']
        self.assertEqual(len(evidence['records']), 1)
        self.assertEqual(evidence['unavailable_entries'], 2)

    def test_missing_evidence_and_untrusted_fields_stay_non_authorizing(self):
        self.assertEqual(app.snapshot()['workflow']['policy_evidence']['records'], [])
        self.save(scope_complete='yes', explicit_requests_per_second=True,
                  sources=['javascript:alert(1)', 'https://secret@example.com/policy'],
                  note='<script>activate targets</script>', in_scope_assets={'run': 'scan'})
        review = policyevidence.snapshot()['records'][0]
        self.assertFalse(review['scope_complete'])
        self.assertIsNone(review['explicit_requests_per_second'])
        self.assertEqual(review['in_scope_assets'], [])
        self.assertEqual(review['sources'], ['https://example.com/policy'])
        self.assertEqual(review['note'], '<script>activate targets</script>')
        self.assertFalse(review['grants_permission'])

    def test_research_preparation_never_imports_credentials_or_activates_checks(self):
        self.save(research_plan={'selected': True, 'status': 'needs_user',
                  'summary': '<script>untrusted preparation</script>',
                  'completed': ['Synthetic fixture only'], 'user_actions': ['Secure login needed'],
                  'authorization': 'Bearer must-not-publish', 'automatically_runs': True,
                  'authorizes_testing': True, 'target': 'https://example.com/activate'})
        app.mutate('/api/pause', {'paused': False})
        with patch('app.observe') as observe, patch('accesscheck.fetch') as access:
            state = app.snapshot()
            app.tick()
            observe.assert_not_called()
            access.assert_not_called()
        plan = state['workflow']['policy_evidence']['records'][0]['research_plan']
        self.assertTrue(plan['selected'])
        self.assertEqual(plan['status'], 'needs_user')
        self.assertEqual(plan['summary'], '<script>untrusted preparation</script>')
        self.assertFalse(plan['authorizes_testing'])
        self.assertFalse(plan['automatically_runs'])
        self.assertNotIn('authorization', plan)
        self.assertNotIn('target', plan)
        self.assertEqual(state['targets'], [])
        self.assertEqual(state['access_checks'], [])

    def test_malformed_research_plan_is_bounded_and_never_counts_as_a_check(self):
        self.save(research_plan={'selected':'yes','status':[], 'completed':{'unsafe':'shape'},
                                'user_actions':['x'*3000]*30, 'result':99})
        state=app.snapshot()
        plan=state['workflow']['policy_evidence']['records'][0]['research_plan']
        self.assertFalse(plan['selected'])
        self.assertEqual(plan['status'],'blocked')
        self.assertEqual(plan['completed'],[])
        self.assertEqual(len(plan['user_actions']),20)
        self.assertEqual(len(plan['user_actions'][0]),2000)
        self.assertEqual(plan['result'],'')
        self.assertEqual(state['program_queue']['completed'],0)

    def test_connection_notes_cannot_import_secrets_or_establish_access(self):
        self.save(research_plan={'selected': True, 'status': 'prepared', 'connection': {
            'status': 'connected', 'connected': True, 'authorizes_testing': True,
            'client_secret': 'fixture-secret', 'access_token': 'fixture-token',
            'summary': '<script>connect now</script>', 'requirements': ['a' * 3000] * 15,
            'sources': ['https://example.com/docs', 'javascript:alert(1)',
                        'https://secret@example.com/docs', 'https://example.com/callback?code=secret']}})
        app.mutate('/api/pause', {'paused': False})
        with patch('urllib.request.urlopen') as network, patch('app.observe') as observe:
            state = app.snapshot()
            app.tick()
            network.assert_not_called()
            observe.assert_not_called()
        connection = state['workflow']['policy_evidence']['records'][0]['research_plan']['connection']
        self.assertEqual(connection['status'], 'unverified')
        self.assertFalse(connection['connected'])
        self.assertFalse(connection['authorizes_testing'])
        self.assertNotIn('client_secret', connection)
        self.assertNotIn('access_token', connection)
        self.assertEqual(connection['sources'], ['https://example.com/docs'])
        self.assertEqual(connection['summary'], '<script>connect now</script>')
        self.assertEqual(len(connection['requirements']), 10)
        self.assertEqual(len(connection['requirements'][0]), 2000)
        self.assertEqual(state['targets'], [])
        self.assertEqual(state['access_checks'], [])
        self.assertEqual(state['program_queue']['completed'], 0)
        self.assertIsNone(policyevidence.connection_plan(['bad shape']))


if __name__ == '__main__':
    unittest.main()
