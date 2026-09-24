import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock,patch
import app
import capitaldemo as cd

MARKER='SG_0123456789abcdef'
CONFIG={'identifier':'demo@example.com','api_key':'synthetic_api_key','password':'synthetic_api_password','marker':MARKER}
TOKENS={'CST':'synthetic_cst_token','X-SECURITY-TOKEN':'synthetic_security_token'}
def response(status=200,data=None):return {'status':status,'data':data,'tokens':TOKENS,'bytes':60,'sha256':'fingerprint'}
def listing(present=True):return response(data={'watchlists':[{'name':MARKER,'defaultSystemWatchlist':False}] if present else []})

def run(responses,**kwargs):
    transport=MagicMock(side_effect=responses)
    return cd.run(CONFIG,transport=transport,pace=lambda:None,**kwargs),transport

class CapitalDemoTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        p=patch.object(app,'DATA',Path(self.tmp.name));p.start();self.addCleanup(p.stop);app.init()
    def connect(self):
        app.mutate('/api/capital-demo/connect',{**CONFIG,'permission':True,'demo_only':True,'own_account':True,'create_watchlist':True})
    def test_normal_boundary_and_fresh_session_each_run(self):
        for _ in range(2):
            r,t=run([response(),listing(),response(401)])
            self.assertFalse(r['reproduced']);self.assertIn('held',r['status'])
            self.assertEqual(t.call_args_list[0].args[:2],('POST','/api/v1/session'))
            self.assertEqual(t.call_args_list[-1].args,('GET','/api/v1/watchlists',None,None))
            self.assertEqual(t.call_count,3)
    def test_setup_creates_only_empty_synthetic_watchlist(self):
        claim=MagicMock()
        r,t=run([response(),listing(False),response(data={'status':'SUCCESS'}),listing(),response(403)],claim_setup=claim)
        claim.assert_called_once();self.assertIn('held',r['status'])
        self.assertEqual(t.call_args_list[2].args,('POST','/api/v1/watchlists',TOKENS,{'name':MARKER,'epics':[]}))
    def test_controls_and_redacted_reproduced_observation(self):
        r,t=run([response(),listing(),listing(),listing(),listing()])
        self.assertTrue(r['reproduced']);self.assertFalse(r['submission_ready']);self.assertEqual(t.call_count,5)
        for secret in [MARKER,*TOKENS.values(),*CONFIG.values()]:self.assertNotIn(secret,json.dumps(r))
    def test_bad_control_and_failed_creation_stop(self):
        for responses in ([response(401)], [response(),response(403)], [response(),listing(False),response(400)], [response(),listing(False),response(data={'status':'SUCCESS'}),listing(False)]):
            r,t=run(responses);self.assertIn('Setup needs attention',r['status']);self.assertFalse(r['reproduced'])
    def test_redirect_nonjson_and_inconsistent_exposure_are_inconclusive(self):
        for responses in ([response(),listing(),response(302)], [response(),listing(),response(200)], [response(),listing(),listing(),listing(False),listing()]):
            r,t=run(responses);self.assertIn('Inconclusive',r['status']);self.assertFalse(r['reproduced'])
    def test_pause_before_every_request_and_rate_limits(self):
        allowed=MagicMock(side_effect=[True,False]);t=MagicMock(return_value=response())
        with self.assertRaises(InterruptedError):cd.run(CONFIG,allowed,t,lambda:None)
        self.assertEqual(t.call_count,1)
        for status in (429,500):
            with self.assertRaises(RuntimeError):run([response(status)])
    def test_private_storage_permissions_expiry_disconnect(self):
        self.connect();p=cd.path(app.DATA)
        self.assertEqual(os.stat(p).st_mode&0o777,0o600)
        for secret in CONFIG.values():self.assertNotIn(secret,json.dumps(app.snapshot()))
        with patch.object(cd,'run') as r:
            cd.tick(app.db,app.DATA,app.log);r.assert_not_called()
            app.mutate('/api/all-pause',{'paused':False})
            with app.db() as c:c.execute('UPDATE capital_demo SET expires=0')
            cd.tick(app.db,app.DATA,app.log);r.assert_not_called()
        app.mutate('/api/capital-demo/disconnect',{});self.assertFalse(p.exists());self.assertFalse(app.snapshot()['capital_demo']['enabled'])
    def test_schedule_stop_on_exposure_and_no_report(self):
        self.connect();app.mutate('/api/all-pause',{'paused':False})
        result,_=run([response(),listing(),listing(),listing(),listing()])
        with patch.object(cd,'run',return_value=result) as r:
            cd.tick(app.db,app.DATA,app.log);cd.tick(app.db,app.DATA,app.log);r.assert_called_once()
        self.assertFalse(app.snapshot()['capital_demo']['enabled']);self.assertEqual(app.snapshot()['capital_demo']['runs'],1)
        self.assertEqual(app.snapshot()['workflow']['submissions'],[])
        with self.assertRaises(ValueError):self.connect()
    def test_setup_not_repeated_after_ambiguous_write(self):
        self.connect();app.mutate('/api/all-pause',{'paused':False})
        def fail(config,allowed,claim_setup):claim_setup();raise TimeoutError('token secret must not be logged')
        with patch.object(cd,'run',side_effect=fail):cd.tick(app.db,app.DATA,app.log)
        with app.db() as c:self.assertEqual(c.execute('SELECT setup_attempted FROM capital_demo').fetchone()[0],1)
        state=app.snapshot();self.assertFalse(state['capital_demo']['enabled']);self.assertNotIn('token secret',json.dumps(state))
    def test_missing_confirmation_and_header_injection(self):
        with self.assertRaises(ValueError):app.mutate('/api/capital-demo/connect',CONFIG)
        with self.assertRaises(ValueError):cd.request('GET','/api/v1/watchlists',{'CST':'bad\r\nHost: evil'})
        with self.assertRaises(ValueError):cd.request('GET','/api/v1/watchlists',{'Host':'evil.example'})
    def test_transport_fixed_demo_ip_tls_no_redirect_and_trading_blocked(self):
        for method,url in [('POST','/api/v1/positions'),('POST','/api/v1/accounts/topUp'),('GET','https://evil.example/'),('DELETE','/api/v1/watchlists')]:
            with self.assertRaises(ValueError):cd.request(method,url)
        with self.assertRaises(ValueError):cd.request('POST','/api/v1/watchlists',TOKENS,{'name':MARKER,'epics':['SILVER']})
        conn=MagicMock();reply=conn.getresponse.return_value;reply.status=302;reply.read.return_value=b'{}'
        reply.getheader.side_effect=lambda k,d='':{'Content-Type':'application/json','Location':'https://evil.example/'}.get(k,d)
        ctx=MagicMock()
        with patch('capitaldemo.public_addresses',return_value=['93.184.216.34']),patch('capitaldemo.socket.create_connection') as connect,patch('capitaldemo.ssl.create_default_context',return_value=ctx),patch('capitaldemo.http.client.HTTPSConnection',return_value=conn):
            r=cd.request('GET','/api/v1/watchlists',TOKENS)
        self.assertEqual(r['status'],302);conn.request.assert_called_once();self.assertEqual(connect.call_args.args[0],('93.184.216.34',443));self.assertEqual(ctx.wrap_socket.call_args.kwargs['server_hostname'],cd.HOST)
