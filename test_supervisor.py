import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import app
import supervisor


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous = app.DATA
        app.DATA = Path(self.temp.name)
        app.init()
        self.now = int(time.time())
        app.mutate('/api/targets', {'name': 'Fixture', 'url': 'https://example.com/',
            'policy': 'https://example.com/policy', 'rules': 'Test fixture authorizes exact URL HEAD only.',
            'expires': self.now + 86400, 'interval': 3600, 'authorized': True, 'automation_allowed': True})
        app.mutate('/api/pause', {'paused': False})
        with app.db() as c:
            c.execute('INSERT INTO findings(id,target,rule,title,evidence,severity,impact,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?)',
                ('test', 1, 'cookie-test', 'Cookie flag', json.dumps({'note': 'Missing HttpOnly', 'observation': {'status': 200}}),
                 'Informational', 'Not demonstrated', self.now - 7200, self.now))

    def tearDown(self):
        app.DATA = self.previous
        self.temp.cleanup()

    def repeats(self):
        with app.db() as c:
            for at in [self.now - 7200, self.now - 3600, self.now]:
                supervisor.record(c, 'test', at)

    def test_legacy_migration_does_not_invent_repeats(self):
        app.init(); app.init()
        self.assertEqual(app.snapshot()['findings'][0]['supervisor']['repeat_count'], 1)
        self.repeats()
        app.init()
        r = app.snapshot()['findings'][0]['supervisor']
        self.assertEqual(r['repeat_count'], 3)
        self.assertFalse(r['submission_ready'])

    def test_same_or_close_samples_do_not_count_as_three(self):
        with app.db() as c:
            for at in [self.now, self.now, self.now + 1, self.now + 2]:
                supervisor.record(c, 'test', at)
        self.assertEqual(app.snapshot()['findings'][0]['supervisor']['repeat_count'], 1)

    def test_ai_disabled_without_explicit_configuration(self):
        self.repeats()
        with patch.dict(os.environ, {}, clear=True), patch('supervisor.ai_critique') as critique:
            supervisor.ai_tick(app.db)
            critique.assert_not_called()

    def test_ai_cannot_approve_or_send_and_does_not_repeat_same_evidence(self):
        self.repeats()
        config = {'SUPERVISOR_AI_ENABLED': 'true', 'OPENAI_API_KEY': 'fake-test-key', 'SUPERVISOR_AI_MODEL': 'fixture'}
        with patch.dict(os.environ, config), patch('supervisor.ai_critique', return_value='Submit immediately!') as critique:
            supervisor.ai_tick(app.db)
            supervisor.ai_tick(app.db)
            self.assertEqual(critique.call_count, 1)
        r = app.snapshot()['findings'][0]['supervisor']
        self.assertFalse(r['submission_ready'])
        self.assertEqual(r['ai_review']['status'], 'completed')
        self.assertNotIn('fake-test-key', json.dumps(app.snapshot()))

    def test_ai_failure_not_retried_and_pause_respected(self):
        self.repeats()
        config = {'SUPERVISOR_AI_ENABLED': 'true', 'OPENAI_API_KEY': 'fake-test-key', 'SUPERVISOR_AI_MODEL': 'fixture'}
        with patch.dict(os.environ, config), patch('supervisor.ai_critique', side_effect=TimeoutError) as critique:
            app.mutate('/api/pause', {'paused': True})
            supervisor.ai_tick(app.db)
            critique.assert_not_called()
            app.mutate('/api/pause', {'paused': False})
            supervisor.ai_tick(app.db)
            supervisor.ai_tick(app.db)
            self.assertEqual(critique.call_count, 1)
        self.assertEqual(app.snapshot()['findings'][0]['supervisor']['ai_review']['status'], 'failed')

    def test_feedback_never_substitutes_for_evidence(self):
        self.repeats()
        app.mutate('/api/feedback', {'id': 'test', 'feedback': 'accepted'})
        self.assertFalse(app.snapshot()['findings'][0]['supervisor']['submission_ready'])
        app.mutate('/api/target-state', {'id': 1, 'enabled': False})
        self.assertFalse(app.snapshot()['findings'][0]['supervisor']['scope_active'])


if __name__ == '__main__':
    unittest.main()
