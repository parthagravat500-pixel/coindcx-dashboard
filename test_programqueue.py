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

    def test_waiting_schedule_is_not_reported_as_queued_work(self):
        self.sync_h1();self.add('one','https://hackerone.com/fixture')
        with app.db() as c:
            programqueue.heartbeat(c,self.now)
            c.execute('UPDATE targets SET due=?',(self.now+7200,))
        q=app.snapshot()['program_queue']
        self.assertEqual(q['queue_state'],'waiting_schedule')
        self.assertEqual(q['waiting_targets'],1)
        self.assertEqual(q['due_targets'],0)
        self.assertEqual(q['next_due'],self.now+7200)
        self.assertEqual(q['rows'][0]['status'],'Waiting for scheduled check')
        self.assertEqual(q['rows'][0]['due_urls'],0)
        self.assertIsNone(q['next_target'])
        with patch('app.observe') as request:app.tick();request.assert_not_called()

    def test_blocker_counts_partition_saved_targets_without_granting_access(self):
        for name in ('disabled','expired','directory','waiting','due'):
            self.add(name,'https://hackerone.com/missing' if name=='directory' else 'https://example.com/policy')
        with app.db() as c:
            programqueue.heartbeat(c,self.now)
            c.execute("UPDATE targets SET enabled=0,expires=0 WHERE name='disabled'")
            c.execute("UPDATE targets SET expires=0 WHERE name='expired'")
            c.execute("UPDATE targets SET due=? WHERE name='waiting'",(self.now+3600,))
        q=app.snapshot()['program_queue']
        self.assertEqual(q['saved_targets'],5)
        for key in ('disabled_targets','expired_targets','directory_blocked_targets','waiting_targets','due_targets'):
            self.assertEqual(q[key],1,key)
        self.assertEqual(q['queue_state'],'ready')
        self.assertEqual(q['next_target'],'due')
        self.assertEqual(q['completed'],0)

    def test_directory_source_diagnostic_explains_global_gate(self):
        self.sync_h1();self.add('one','https://hackerone.com/fixture')
        with app.db() as c:
            programqueue.heartbeat(c,self.now)
            c.execute("UPDATE discovery_sources SET failures=2,status='Synthetic refresh failure'")
        q=app.snapshot()['program_queue']
        self.assertEqual(q['queue_state'],'no_eligible_targets')
        self.assertEqual(q['directory_blocked_targets'],1)
        self.assertTrue(q['directory_source']['blocked'])
        self.assertEqual(q['directory_source']['failures'],2)
        self.assertIn('refresh failed',q['directory_source']['blocker'])
        self.assertEqual(q['directory_source']['status'],'Synthetic refresh failure')

        self.sync_h1()
        q=app.snapshot()['program_queue']
        self.assertFalse(q['directory_source']['blocked'])
        self.assertIsNone(q['directory_source']['blocker'])

    def test_worker_health_and_pause_are_separate_from_ready_work(self):
        self.add('one','https://example.com/policy')
        self.assertEqual(app.snapshot()['program_queue']['queue_state'],'worker_unavailable')
        with app.db() as c:programqueue.heartbeat(c,self.now+3600)
        self.assertFalse(app.snapshot()['program_queue']['healthy'])
        app.mutate('/api/pause',{'paused':True})
        self.assertEqual(app.snapshot()['program_queue']['queue_state'],'paused')

    def test_local_sorting_does_not_claim_official_policy_review(self):
        self.sync_h1()
        with patch('workflow.ai_enabled',return_value=False):
            flow=app.snapshot()['workflow']
        self.assertNotIn('all listed programs reviewed',flow['ai_status'])
        self.assertIsNone(flow['programs'][0]['policy_review'])
        self.assertFalse(flow['programs'][0]['scan_authorized'])

    def test_advisory_policy_record_never_activates_a_target(self):
        self.sync_h1()
        note={'note':'Synthetic policy evidence only','grants_permission':False,'review_status':'reviewed_restricted'}
        with patch.dict(workflow.POLICY_REVIEWS,{'https://hackerone.com/fixture':note}):
            state=app.snapshot()
            self.assertEqual(state['workflow']['programs'][0]['policy_review'],note)
            self.assertFalse(state['workflow']['programs'][0]['scan_authorized'])
            self.assertEqual(state['targets'],[])
            with patch('app.observe') as request:app.tick();request.assert_not_called()

    def test_policy_review_counts_do_not_imply_queue_permission(self):
        workflow.sync(app.db,'hackerone',[{'name':'PayPal','url':'https://hackerone.com/paypal',
            'offers_bounties':True,'submission_state':'open'},
            {'name':'Unknown','url':'https://hackerone.com/unknown',
             'offers_bounties':True,'submission_state':'open'}],self.now)
        state=app.snapshot();summary=state['workflow']['policy_review_summary']
        self.assertEqual(summary['listed_programs'],2)
        self.assertEqual(summary['matched_listings'],1)
        self.assertEqual(summary['unreviewed_listings'],1)
        self.assertEqual(summary['authorizing'],0)
        self.assertEqual(summary['non_authorizing'],1)
        self.assertGreaterEqual(summary['records_total'],1)
        self.assertEqual(state['targets'],[])
        with patch('app.observe') as request:app.tick();request.assert_not_called()

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
