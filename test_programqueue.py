import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import app
import programqueue
import workflow


class ProgramQueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        p=patch.object(app,'DATA',Path(self.tmp.name));p.start();self.addCleanup(p.stop)
        app.init();self.now=int(time.time())
        app.mutate('/api/pause',{'paused':False})

    def add(self,name,policy):
        app.mutate('/api/targets',{'name':name,'url':'https://example.com/'+name,'policy':policy,
            'rules':'Synthetic fixture: permission for exact URL HEAD checks only.',
            'expires':self.now+3600,'interval':3600,'authorized':True,'automation_allowed':True,'cors':False})

    def sync_h1(self):
        workflow.sync(app.db,'hackerone',[{'name':'Fixture','url':'https://hackerone.com/fixture',
            'offers_bounties':True,'submission_state':'open'}],self.now)

    def test_directory_never_creates_targets_or_calls_websites(self):
        self.sync_h1()
        with patch('app.observe') as request:app.tick();request.assert_not_called()
        q=app.snapshot()['program_queue']
        self.assertEqual(q['listed_h1'],1);self.assertEqual(q['permission_needed'],1)
        self.assertEqual(app.snapshot()['targets'],[]);self.assertEqual(q['completed'],0)

    def test_rotates_programs_and_persists_position(self):
        self.add('a1','https://example.com/program-a');self.add('a2','https://example.com/program-a')
        self.add('b1','https://example.com/program-b')
        with app.db() as c:
            first=programqueue.next_target(c,self.now);self.assertEqual(first['name'],'a1')
            programqueue.begin(c,first,self.now)
            c.execute('UPDATE targets SET due=? WHERE id=?',(self.now+3600,first['id']))
        app.init()
        with app.db() as c:self.assertEqual(programqueue.next_target(c,self.now)['name'],'b1')

    def test_saved_scope_directory_status_pause_and_expiry_gate_dispatch(self):
        self.add('one','https://hackerone.com/fixture')
        with patch('app.observe') as request:
            app.tick();request.assert_not_called()
            self.sync_h1()
            with app.db() as c:c.execute('UPDATE programs SET available=0')
            app.tick();request.assert_not_called()
            with app.db() as c:c.execute('UPDATE programs SET available=1');c.execute('UPDATE discovery_sources SET failures=1')
            app.tick();request.assert_not_called()
            self.sync_h1();app.mutate('/api/pause',{'paused':True})
            app.tick();request.assert_not_called()
            app.mutate('/api/pause',{'paused':False})
            with app.db() as c:c.execute('UPDATE targets SET expires=0')
            app.tick();request.assert_not_called()

    def test_no_observation_advances_without_claiming_confirmation(self):
        self.add('one','https://example.com/program-a');self.add('two','https://example.com/program-b')
        with patch('app.observe',return_value={'status':200}),patch('app.findings',return_value=[]):
            app.tick();app.tick()
        q=app.snapshot()['program_queue']
        self.assertEqual(q['completed'],2);self.assertEqual(len(q['attempts']),2)
        self.assertTrue(all(r['outcome']=='no_observation' for r in q['attempts']))
        self.assertEqual(q['confirmed_payable'],0);self.assertFalse(q['automatic_submission'])
        self.assertEqual(app.snapshot()['workflow']['submissions'],[])
        with patch('app.observe') as request:app.tick();request.assert_not_called()

    def test_h1_exact_policy_match_is_required_and_expired_directory_blocks(self):
        self.sync_h1();self.add('one','https://hackerone.com/fixture-other')
        with patch('app.observe') as request:app.tick();request.assert_not_called()
        with app.db() as c:c.execute("UPDATE targets SET policy='https://hackerone.com/fixture/'")
        with patch('app.observe',return_value={'status':200}) as request,patch('app.findings',return_value=[]):
            app.tick();request.assert_called_once_with('https://example.com/one')
        with app.db() as c:
            c.execute('UPDATE targets SET due=0')
            c.execute('UPDATE discovery_sources SET last_success=?',(self.now-86401,))
        with patch('app.observe') as request:app.tick();request.assert_not_called()

    def test_failure_moves_to_next_program_without_bypassing_backoff(self):
        self.add('one','https://example.com/program-a');self.add('two','https://example.com/program-b')
        with patch('app.observe',side_effect=[TimeoutError(),{'status':200}]) as request,patch('app.findings',return_value=[]):
            app.tick();app.tick();app.tick();self.assertEqual(request.call_count,2)
        q=app.snapshot()['program_queue']
        self.assertEqual([r['outcome'] for r in q['attempts']],['no_observation','error'])
        self.assertEqual(q['completed'],1)

    def test_throttled_or_incomplete_check_is_not_clean(self):
        self.add('one','https://example.com/program-a')
        for response,outcome in [(429,'stopped'),(302,'inconclusive')]:
            with app.db() as c:c.execute('UPDATE targets SET enabled=1,due=0')
            with patch('app.observe',return_value={'status':response}),patch('app.findings',return_value=[]):app.tick()
            self.assertEqual(app.snapshot()['program_queue']['attempts'][0]['outcome'],outcome)
        self.assertEqual(app.snapshot()['program_queue']['completed'],0)

    def test_restart_marks_stale_attempt_inconclusive_and_finish_is_idempotent(self):
        self.add('one','https://example.com/program-a')
        with app.db() as c:
            t=programqueue.next_target(c,self.now)
            run=programqueue.begin(c,t,self.now-200)
            programqueue.heartbeat(c,self.now)
            programqueue.finish(c,run,'no_observation')
            run=programqueue.begin(c,t,self.now)
            programqueue.finish(c,run,'no_observation');programqueue.finish(c,run,'no_observation')
        q=app.snapshot()['program_queue']
        self.assertEqual(q['completed'],1);self.assertEqual(q['attempts'][1]['outcome'],'interrupted')
