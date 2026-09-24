import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch,MagicMock
import app
import accesscheck as ac

MARKER='scopeguard_synthetic_test_marker_123456'
AUTH='Bearer synthetic-test-credential-12345'
CONFIG={'url':'https://example.com/own-record','marker':MARKER,'authorization':AUTH}

def response(status=200,marker=True,json_body=True):
    return {'status':status,'marker_present':marker,'json':json_body,'bytes':60,'sha256':'digest'}

class AccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        p=patch.object(app,'DATA',Path(self.tmp.name));p.start();self.addCleanup(p.stop);app.init()
        with app.db() as c:
            c.execute("INSERT INTO targets(name,url,policy,rules,expires,interval,cors) VALUES(?,?,?,?,?,900,0)",('Owned test',CONFIG['url'],'https://example.com/policy','Synthetic permission for isolated unit tests',int(time.time())+3600))
    def configure(self):
        app.mutate('/api/access-check',{'target':1,'marker':MARKER,'authorization':AUTH,'rules':'Policy permits four read-only comparisons per fifteen minutes of my own private JSON record.','permission':True,'own_data':True,'read_only':True,'private_expected':True})
    def test_repeated_private_marker_exposure_has_controls_and_no_secret(self):
        calls=[]
        def fetch(url,auth,marker):calls.append(auth);return response()
        r=ac.compare(CONFIG,transport=fetch)
        self.assertTrue(r['reproduced']);self.assertFalse(r['submission_ready']);self.assertEqual(r['severity'],'Not assessed')
        self.assertEqual(calls,[AUTH,None,None,AUTH]);self.assertNotIn(MARKER,json.dumps(r));self.assertNotIn(AUTH,json.dumps(r))
    def test_denied_anonymous_and_public_nonmarker_responses(self):
        for anon in (response(401,False),response(403,False),response(200,False)):
            f=MagicMock(side_effect=[response(),anon]);r=ac.compare(CONFIG,transport=f)
            self.assertFalse(r['reproduced']);self.assertEqual(f.call_count,2);self.assertIn('held',r['status'])
    def test_failed_control_and_inconsistent_repeat_do_not_confirm(self):
        f=MagicMock(return_value=response(200,False));r=ac.compare(CONFIG,transport=f)
        self.assertEqual(f.call_count,1);self.assertIn('Setup',r['status'])
        r=ac.compare(CONFIG,transport=MagicMock(side_effect=[response(),response(),response(),response(401,False)]))
        self.assertFalse(r['reproduced']);self.assertIn('Inconclusive',r['status'])
    def test_stop_rate_limit_pause_redirect_and_html(self):
        for status in (429,500,503):
            with self.assertRaises(RuntimeError):ac.compare(CONFIG,transport=lambda *a:response(status))
        with self.assertRaises(InterruptedError):ac.compare(CONFIG,allowed=lambda:False,transport=MagicMock())
        for resp in (response(302),response(200,True,False)):
            r=ac.compare(CONFIG,transport=MagicMock(return_value=resp));self.assertFalse(r['reproduced']);self.assertIn('Setup',r['status'])
    def test_credentials_private_pause_expiry_and_removal(self):
        self.configure();p=ac.config_path(app.DATA,1)
        self.assertEqual(os.stat(p).st_mode & 0o777,0o600);self.assertNotIn(AUTH,json.dumps(app.snapshot()))
        with patch.object(ac,'compare') as compare:
            ac.tick(app.db,app.DATA,app.log);compare.assert_not_called()
            app.mutate('/api/all-pause',{'paused':False})
            with app.db() as c:c.execute('UPDATE targets SET expires=0')
            ac.tick(app.db,app.DATA,app.log);compare.assert_not_called()
        app.mutate('/api/access-check/remove',{'target':1});self.assertFalse(p.exists());self.assertEqual(app.snapshot()['access_checks'],[])
    def test_reproduced_profile_stops_and_no_bounty_submission(self):
        self.configure();app.mutate('/api/all-pause',{'paused':False})
        result=ac.compare(CONFIG,transport=MagicMock(return_value=response()))
        with patch.object(ac,'compare',return_value=result) as compare:
            ac.tick(app.db,app.DATA,app.log);ac.tick(app.db,app.DATA,app.log);compare.assert_called_once()
        p=app.snapshot()['access_checks'][0];self.assertFalse(p['enabled']);self.assertTrue(p['result']['reproduced'])
        self.assertEqual(app.snapshot()['workflow']['submissions'],[])
    def test_reject_missing_permissions(self):
        with self.assertRaises(ValueError):app.mutate('/api/access-check',{'target':1})
    def test_transport_pins_public_ip_and_never_forwards_credentials(self):
        conn=MagicMock();reply=conn.getresponse.return_value;reply.status=302;reply.read.return_value=b'{}'
        reply.getheader.side_effect=lambda k,default='':{'Content-Type':'application/json','Location':'https://other.example/'}.get(k,default)
        context=MagicMock()
        with patch('accesscheck.public_addresses',return_value=['93.184.216.34']),patch('accesscheck.socket.create_connection') as connect,patch('accesscheck.ssl.create_default_context',return_value=context),patch('accesscheck.http.client.HTTPSConnection',return_value=conn):
            r=ac.fetch(CONFIG['url'],AUTH,MARKER)
        self.assertEqual(r['status'],302);conn.request.assert_called_once();self.assertEqual(conn.request.call_args.args,('GET','/own-record'))
        self.assertEqual(conn.request.call_args.kwargs['headers']['Authorization'],AUTH)
        self.assertEqual(connect.call_args.args[0],('93.184.216.34',443));self.assertEqual(context.wrap_socket.call_args.kwargs['server_hostname'],'example.com')
    def test_json_marker_in_values_only_and_body_limit(self):
        conn=MagicMock();reply=conn.getresponse.return_value;reply.status=200
        reply.getheader.side_effect=lambda k,default='':{'Content-Type':'application/json'}.get(k,default)
        with patch('accesscheck.public_addresses',return_value=['93.184.216.34']),patch('accesscheck.socket.create_connection'),patch('accesscheck.ssl.create_default_context'),patch('accesscheck.http.client.HTTPSConnection',return_value=conn):
            reply.read.return_value=json.dumps({'record':MARKER}).encode();self.assertTrue(ac.fetch(CONFIG['url'],None,MARKER)['marker_present'])
            reply.read.return_value=json.dumps({MARKER:'public'}).encode();self.assertFalse(ac.fetch(CONFIG['url'],None,MARKER)['marker_present'])
            reply.read.return_value=b'x'*65537
            with self.assertRaises(ValueError):ac.fetch(CONFIG['url'],AUTH,MARKER)
