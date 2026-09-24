import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import app
import reporting

class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.old=app.DATA;app.DATA=Path(self.tmp.name);app.init()
        self.now=int(time.time())
        with app.db() as c:
            c.execute("INSERT INTO targets(name,url,policy,rules,expires,interval,cors) VALUES (?,?,?,?,?,?,?)",('GitHub','https://github.com/','https://bounty.github.com/rules','Fixture only',self.now+3600,3600,0))
            c.execute('INSERT INTO findings(id,target,rule,title,evidence,severity,impact,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?)',('f',1,'cookie-test','Fixture report',json.dumps({'note':'Missing flag'}),'Informational','Unproven',self.now,self.now))
        app.mutate('/api/pause',{'paused':False})
        reporting.save(app.DATA,{'enabled':True,'username':'fixture','token':'fixture-private-token'})
    def tearDown(self):app.DATA=self.old;self.tmp.cleanup()
    def ready(self):
        return {'submission_ready':True,'channel':{'url':'https://hackerone.com/github'},'validated_report':{'reproduction':'Independent fixture reproduction steps with enough detail for the receiving reviewer.','impact':'Independently established fixture impact with sufficient explanation.'}}
    def test_current_lead_never_sends_even_if_feedback_accepted(self):
        app.mutate('/api/feedback',{'id':'f','feedback':'accepted'})
        with patch('reporting.request') as req:reporting.tick(app.db,app.DATA);req.assert_not_called()
        self.assertEqual(app.snapshot()['workflow']['submissions'],[])
    def test_confirmed_receipt_and_duplicate_protection(self):
        with patch('reporting.supervisor.review',return_value=self.ready()),patch('reporting.request',return_value={'data':{'type':'report','id':'12345'}}) as req:
            reporting.tick(app.db,app.DATA);app.init();reporting.tick(app.db,app.DATA);self.assertEqual(req.call_count,1)
        records=app.snapshot()['workflow']['submissions'];self.assertEqual(records[0]['origin'],'hackerone_receipt');self.assertEqual(records[0]['receipt'],'https://hackerone.com/reports/12345')
    def test_uncertain_delivery_is_not_retried_or_counted_sent(self):
        with patch('reporting.supervisor.review',return_value=self.ready()),patch('reporting.request',side_effect=TimeoutError) as req:
            reporting.tick(app.db,app.DATA);reporting.tick(app.db,app.DATA);self.assertEqual(req.call_count,1)
        s=app.snapshot();self.assertEqual(s['workflow']['submissions'],[]);self.assertEqual(s['reporting']['attempts'][0]['status'],'uncertain')
    def test_scope_pause_and_route_are_enforced(self):
        with patch('reporting.supervisor.review',return_value=self.ready()),patch('reporting.request') as req:
            app.mutate('/api/pause',{'paused':True});reporting.tick(app.db,app.DATA)
            app.mutate('/api/pause',{'paused':False});app.mutate('/api/target-state',{'id':1,'enabled':False});reporting.tick(app.db,app.DATA);req.assert_not_called()
        r=self.ready();r['channel']['url']='https://hackerone.com.evil.invalid/github'
        with self.assertRaises(ValueError):reporting.make_payload({'title':'x'},{'enabled':True,'expires':self.now+3600},r)
    def test_no_evidence_means_no_submission(self):
        r=self.ready();r.pop('validated_report')
        with self.assertRaises(ValueError):reporting.make_payload({'title':'x'},{'enabled':True,'expires':self.now+3600},r)
    def test_connect_requires_consent_and_keeps_secrets_private(self):
        with patch('reporting.request',return_value={'data':[]}) as req:
            with self.assertRaises(ValueError):reporting.connect(app.DATA,{'username':'fixture','token':'fixture-private-token'})
            req.assert_not_called()
            reporting.connect(app.DATA,{'username':'fixture','token':'fixture-private-token','authorize_delivery':True})
        self.assertNotIn('fixture-private-token',json.dumps(app.snapshot()))
        self.assertEqual((app.DATA/'reporting-connection.json').stat().st_mode&0o777,0o600)
        app.mutate('/api/reporting/disconnect',{});self.assertFalse(app.snapshot()['reporting']['connected'])

if __name__=='__main__':unittest.main()
