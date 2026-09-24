import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import app
import connections

KEY='sk-fixture-for-private-connection-tests'

class ConnectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.old=app.DATA;app.DATA=Path(self.tmp.name)
        self.env=patch.dict(os.environ,{},clear=True);self.env.start();app.init()
    def tearDown(self):
        app.DATA=self.old;self.env.stop();self.tmp.cleanup()
    def test_consent_and_valid_key_required_before_network(self):
        with patch('connections.verify_key') as verify:
            with self.assertRaises(ValueError):connections.connect(app.DATA,{'key':KEY})
            with self.assertRaises(ValueError):connections.connect(app.DATA,{'key':'bad','approve_charges':True})
            verify.assert_not_called()
        self.assertFalse(connections.path(app.DATA).exists())
    def test_private_persistence_and_no_secret_in_state(self):
        with patch('connections.verify_key') as verify:
            app.mutate('/api/ai/connect',{'key':KEY,'approve_charges':True});verify.assert_called_once_with(KEY)
        self.assertEqual(stat.S_IMODE(connections.path(app.DATA).stat().st_mode),0o600)
        self.assertNotIn(KEY,json.dumps(app.snapshot()))
        self.assertTrue(app.snapshot()['connection']['enabled'])
        os.environ.clear();connections.load(app.DATA)
        self.assertTrue(connections.status()['enabled'])
        self.assertEqual(os.environ['OPENAI_API_KEY'],KEY)
    def test_failed_verification_does_not_replace_working_key(self):
        with patch('connections.verify_key'):connections.connect(app.DATA,{'key':KEY,'approve_charges':True})
        with patch('connections.verify_key',side_effect=ValueError('Not accepted')):
            with self.assertRaises(ValueError):connections.connect(app.DATA,{'key':KEY+'-new','approve_charges':True})
        self.assertEqual(os.environ['OPENAI_API_KEY'],KEY)
        self.assertEqual(json.loads(connections.path(app.DATA).read_text())['key'],KEY)
    def test_disconnect_removes_saved_key_and_persists(self):
        with patch('connections.verify_key'):connections.connect(app.DATA,{'key':KEY,'approve_charges':True})
        app.mutate('/api/ai/disconnect',{})
        self.assertNotIn(KEY,connections.path(app.DATA).read_text())
        self.assertFalse(connections.status()['enabled']);connections.load(app.DATA)
        self.assertEqual(os.environ['DISCOVERY_AI_ENABLED'],'false')
    def test_atomic_pause_preserves_target_permissions(self):
        app.mutate('/api/all-pause',{'paused':True});s=app.snapshot()
        self.assertTrue(s['paused']);self.assertFalse(s['workflow']['enabled'])
        app.mutate('/api/all-pause',{'paused':False});s=app.snapshot()
        self.assertFalse(s['paused']);self.assertTrue(s['workflow']['enabled'])
        self.assertEqual(s['targets'],[])

if __name__=='__main__':unittest.main()
