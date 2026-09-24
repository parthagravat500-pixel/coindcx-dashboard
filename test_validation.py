import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
import app
import validation

class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        p=patch.object(app,'DATA',Path(self.tmp.name));p.start();self.addCleanup(p.stop)
        self.token='isolated-validation-password-123456'
        p=patch.object(app,'TOKEN',self.token);p.start();self.addCleanup(p.stop)
        app.init()
        self.server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.port=self.server.server_address[1]
    def test_real_http_checks_are_read_only_and_redacted(self):
        before=app.snapshot()['paused'];result=validation.run(self.port,self.token)
        self.assertEqual(result['status'],'All covered checks passed');self.assertEqual(len(result['checks']),7)
        self.assertTrue(all(x['passed'] for x in result['checks']));self.assertEqual(app.snapshot()['paused'],before)
        self.assertNotIn(self.token,json.dumps(result));self.assertNotIn(app.CSRF,json.dumps(result));self.assertFalse(result['submission_ready'])
    def test_broken_auth_is_reproduced_and_not_bounty_eligible(self):
        with patch.object(app.Handler,'authenticate',return_value=True):result=validation.run(self.port,self.token)
        self.assertTrue(result['confirmed_issue']);self.assertEqual(len(result['confirmed_checks']),2)
        self.assertFalse(result['submission_ready']);self.assertEqual(len(result['checks']),9)
    def test_wrong_control_cannot_pass(self):
        result=validation.run(self.port,'wrong-control-password-123456789')
        self.assertIn('Inconclusive',result['status']);self.assertFalse(result['confirmed_issue']);self.assertEqual(len(result['checks']),1)
    def test_pause_schedule_history_and_manual_cooldown(self):
        with patch.object(validation,'run') as run:
            validation.tick(app.db,app.log,self.port,self.token);run.assert_not_called()
        with self.assertRaises(ValueError):app.mutate('/api/validation/run',{})
        app.mutate('/api/all-pause',{'paused':False});validation.tick(app.db,app.log,self.port,self.token)
        v=app.snapshot()['validation'];self.assertEqual(v['completed'],1);self.assertEqual(len(v['runs']),1)
        with self.assertRaises(ValueError):app.mutate('/api/validation/run',{})
        with patch.object(validation,'run') as run:
            validation.tick(app.db,app.log,self.port,self.token);run.assert_not_called()
    def test_network_failure_and_pause_are_not_passes(self):
        app.mutate('/api/all-pause',{'paused':False})
        with patch.object(validation,'request',side_effect=TimeoutError):validation.tick(app.db,app.log,self.port,self.token)
        v=app.snapshot()['validation'];self.assertEqual(v['completed'],0);self.assertIn('could not finish',v['status'])
        with self.assertRaises(InterruptedError):validation.run(self.port,self.token,lambda:False)
