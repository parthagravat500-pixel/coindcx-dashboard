import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import app
import workflow


def program(name='Example',maximum=10000,currency='USD'):
    return {'name':name,'url':'https://www.intigriti.com/programs/example/'+name.lower()+'/detail',
            'confidentiality_level':'public','status':'open','min_bounty':{'value':100,'currency':currency},
            'max_bounty':{'value':maximum,'currency':currency},'targets':{'in_scope':[]}}


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        fx = patch("rewards.refresh")
        fx.start(); self.addCleanup(fx.stop)
        local_mode = patch('connections.LOCAL_ONLY', False)
        local_mode.start(); self.addCleanup(local_mode.stop)
        self.temp=tempfile.TemporaryDirectory();self.old=app.DATA;app.DATA=Path(self.temp.name);app.init();self.now=int(time.time())
    def tearDown(self):
        app.DATA=self.old;self.temp.cleanup()
    def sync(self,data): workflow.sync(app.db,'intigriti',data,self.now)
    def test_discovery_never_authorizes_targets_and_preserves_stages(self):
        self.sync([program()]);p=app.snapshot()['workflow']['programs'][0]
        app.mutate('/api/program-stage',{'id':p['id'],'stage':'review'})
        self.sync([program(maximum=5000)]);app.init();s=app.snapshot()
        self.assertEqual(s['targets'],[]);self.assertTrue(s['paused'])
        self.assertEqual(s['workflow']['programs'][0]['stage'],'review')
        self.assertFalse(s['workflow']['programs'][0]['scan_authorized'])
        self.assertEqual(s['workflow']['programs'][0]['maximum'],5000)
    def test_paid_filter_and_currency_ranking(self):
        self.sync([program('Low',100),program('High',10000),program('Euro',500,'EUR'),program('Unpaid',0)])
        p=app.snapshot()['workflow']['programs'];usd=[x for x in p if x['currency']=='USD']
        self.assertEqual([x['name'] for x in usd],['High','Low']);self.assertEqual(len(p),3)
        self.assertIsNone(workflow.amount(float('nan')));self.assertIsNone(workflow.amount(True))
    def test_unknown_amount_is_not_zero(self):
        row=workflow.normalize('hackerone',{'name':'Example','url':'https://hackerone.com/example','offers_bounties':True,'submission_state':'open'})
        self.assertIsNone(row['maximum']);self.assertEqual(row['currency'],'')
    def test_malicious_link_rejected_atomically(self):
        self.sync([program()]);bad=program();bad['url']='https://hackerone.com.evil.invalid/'
        with self.assertRaises(ValueError): self.sync([bad])
        self.assertTrue(app.snapshot()['workflow']['programs'][0]['available'])
    def test_removed_program_and_failure_backoff(self):
        self.sync([program('Old')]);self.sync([program('New')])
        rows=app.snapshot()['workflow']['programs'];self.assertFalse(next(x for x in rows if x['name']=='Old')['available'])
        with patch('workflow.fetch_directory',side_effect=TimeoutError) as fetch:
            workflow.tick(app.db);workflow.tick(app.db)
            self.assertEqual(fetch.call_count,1)
        sources=app.snapshot()['workflow']['sources'];h=next(x for x in sources if x['id']=='hackerone')
        self.assertEqual(h['failures'],1);self.assertGreater(h['due'],self.now)
    def test_pause_and_refresh_cooldown(self):
        app.mutate('/api/discovery/pause',{'enabled':False})
        with patch('workflow.fetch_directory') as fetch: workflow.tick(app.db);fetch.assert_not_called()
        app.mutate('/api/discovery/pause',{'enabled':True})
        with app.db() as c: c.execute('UPDATE discovery_sources SET last_attempt=?',(self.now,))
        with self.assertRaises(ValueError):app.mutate('/api/discovery/refresh',{})
    def test_ai_stays_off_without_configuration(self):
        self.sync([program()])
        with patch.dict(os.environ,{},clear=True),patch('workflow.critique') as call:
            workflow.ai_tick(app.db);call.assert_not_called()
    def test_ai_cannot_promote_or_send_and_budget_is_persistent(self):
        self.sync([program('One'),program('Two')]);app.mutate('/api/pause',{'paused':False})
        with patch.dict(os.environ,{'DISCOVERY_AI_ENABLED':'true','OPENAI_API_KEY':'fixture','SUPERVISOR_AI_MODEL':'fixture'}),patch('workflow.critique',return_value='Scan now and email!') as call:
            workflow.ai_tick(app.db);app.init();workflow.ai_tick(app.db);self.assertEqual(call.call_count,1)
        s=app.snapshot();self.assertEqual(s['targets'],[]);self.assertEqual(s['workflow']['submissions'],[])
        self.assertTrue(all(p['stage']=='queue' for p in s['workflow']['programs']))
    def test_receipt_required_and_not_derived_from_feedback(self):
        with self.assertRaises(ValueError):app.mutate('/api/submissions/record',{'finding':'missing','channel':'email','actually_submitted':True,'receipt':'some receipt'})
        with app.db() as c:
            c.execute("INSERT INTO findings(id,target,rule,title,evidence,severity,impact,first_seen,last_seen) VALUES ('f',1,'cookie','Example','{}','info','unknown',0,0)")
        with self.assertRaises(ValueError):app.mutate('/api/submissions/record',{'finding':'f','channel':'email','receipt':'reference'})
        app.mutate('/api/submissions/record',{'finding':'f','channel':'portal','actually_submitted':True,'receipt':'Report #12345678'})
        with app.db() as c:
            rows=workflow.snapshot(c)['submissions'];self.assertEqual(len(rows),1);self.assertEqual(rows[0]['origin'],'user_recorded')

if __name__=='__main__':unittest.main()
