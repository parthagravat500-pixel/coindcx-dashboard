import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import app
import connections
import supervisor
import workflow
from test_workflow import program


class LocalModeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data = patch.object(app, 'DATA', Path(self.tmp.name))
        self.data.start(); self.addCleanup(self.data.stop)
        self.env = patch.dict(os.environ, {'OPENAI_API_KEY': 'sk-old-paid-key',
            'SUPERVISOR_AI_MODEL': 'gpt-4.1-mini', 'SUPERVISOR_AI_ENABLED': 'true',
            'DISCOVERY_AI_ENABLED': 'true'})
        self.env.start(); self.addCleanup(self.env.stop)
        app.init()

    def test_no_paid_requests_even_with_old_environment(self):
        with patch('urllib.request.urlopen') as network:
            supervisor.ai_tick(app.db)
            workflow.ai_tick(app.db)
            with self.assertRaises(ValueError):
                app.mutate('/api/ai/connect', {'key': 'sk-new-paid-key-for-test', 'approve_charges': True})
            network.assert_not_called()
        self.assertFalse(connections.status()['enabled'])

    def test_startup_removes_old_saved_key_and_persists_disabled(self):
        connections.save(app.DATA, {'enabled': True, 'key': 'sk-old-paid-key-for-test'})
        connections.load(app.DATA)
        self.assertEqual(json.loads(connections.path(app.DATA).read_text()), {'enabled': False})
        self.assertNotIn('OPENAI_API_KEY', os.environ)
        self.assertEqual(os.environ['DISCOVERY_AI_ENABLED'], 'false')
        connections.load(app.DATA)
        self.assertFalse(supervisor.ai_enabled())

    def test_all_programs_reviewed_without_network_or_scan_authorization(self):
        workflow.sync(app.db, 'intigriti', [program('Company'+str(i)) for i in range(25)], int(time.time()))
        with patch('urllib.request.urlopen') as network:
            s = app.snapshot()
            network.assert_not_called()
        self.assertEqual(len(s['workflow']['programs']), 25)
        self.assertTrue(all(p['local_review']['method'] == 'Local rules' for p in s['workflow']['programs']))
        self.assertTrue(all(not p['local_review']['scan_authorized'] for p in s['workflow']['programs']))
        self.assertEqual(s['targets'], [])
        self.assertEqual(s['connection']['mode'], 'local')

    def test_stale_and_unknown_rewards_remain_uncertain(self):
        r = workflow.local_review({'available': True, 'stale': True, 'maximum': None})
        self.assertIn('out of date', r['note'])
        self.assertIn('unknown', r['note'])
        self.assertFalse(r['scan_authorized'])
