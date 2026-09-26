import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import app
import accesscheck
import autopilot
import gitlabcheck
import gitlabpair
import validation

MARKER = 'scopeguard_synthetic_fixture_marker_123456789'
AUTH = 'Bearer owned_fixture_test_credential_12345'


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_HEAD(self):
        self.server.seen.append((self.path,'HEAD'))
        self.send_response(200); self.end_headers()
    def do_GET(self):
        self.server.seen.append((self.path,bool(self.headers.get('Authorization'))))
        if self.path == '/badcontrol': status = 401
        elif self.path == '/rate': status = 429
        elif self.path == '/protected' and self.headers.get('Authorization') != AUTH: status = 401
        else: status = 200
        body = json.dumps({'synthetic':MARKER} if status == 200 else {'error':'denied'}).encode()
        self.send_response(status); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)


class AutopilotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        patcher = patch.object(app,'DATA',Path(self.tmp.name)); patcher.start(); self.addCleanup(patcher.stop)
        patcher = patch.object(app,'TOKEN','owned-dashboard-test-password-123456'); patcher.start(); self.addCleanup(patcher.stop)
        app.init()
        self.fixture = ThreadingHTTPServer(('127.0.0.1',0),FixtureHandler)
        self.fixture.seen = []
        self.web = ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
        for server in (self.fixture,self.web):
            threading.Thread(target=server.serve_forever,daemon=True).start()
            self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        self.port = self.web.server_address[1]
        self.runners = {'headers':lambda target: app.tick(target),
                        'access':lambda target: accesscheck.tick(app.db,app.DATA,app.log,target),
                        'owned_validation':lambda _:validation.tick(app.db,app.log,self.port,app.TOKEN)}

    def api(self,path,data=None,authenticated=True):
        conn = http.client.HTTPConnection('127.0.0.1',self.port)
        headers = {'Content-Type':'application/json'}
        if authenticated:
            headers['Authorization'] = 'Basic '+base64.b64encode(('admin:'+app.TOKEN).encode()).decode()
            headers['X-CSRF-Token'] = app.CSRF
        conn.request('GET' if data is None else 'POST',path,body=None if data is None else json.dumps(data),headers=headers)
        response = conn.getresponse(); body=response.read(); status=response.status; conn.close()
        return status,json.loads(body) if body else None

    def add(self,path,policy=None,access=True):
        target = {'name':'Owned fixture '+path,'url':'https://fixture.example'+path,
                  'policy':policy or 'https://policy.example/'+path.strip('/'),
                  'rules':'Owned local fixtures only; read-only comparisons on synthetic data are authorized.',
                  'interval':3600,'expires':int(time.time())+3600,'authorized':True,'automation_allowed':True,'cors':False}
        status,_=self.api('/api/targets',target); self.assertEqual(status,200)
        with app.db() as c: key=c.execute('SELECT id FROM targets WHERE url=?',(target['url'],)).fetchone()[0]
        if access:
            status,_=self.api('/api/access-check',{'target':key,'marker':MARKER,'authorization':AUTH,
                        'rules':target['rules'],'permission':True,'own_data':True,'read_only':True,'private_expected':True})
            self.assertEqual(status,200)
        return key

    def transport(self,url,auth,marker):
        conn=http.client.HTTPConnection('127.0.0.1',self.fixture.server_address[1])
        conn.request('GET',urlsplit(url).path,headers={'Authorization':auth} if auth else {})
        response=conn.getresponse(); body=response.read(); status=response.status; conn.close()
        return {'status':status,'json':True,'marker_present':marker in body.decode(),
                'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}

    def resume(self): self.assertEqual(self.api('/api/all-pause',{'paused':False})[0],200)
    def tick(self): autopilot.tick(app.db,app.LOCK,app.log,self.runners)

    def test_complete_runtime_flow_selects_runs_saves_and_moves_on(self):
        self.add('/leaky'); self.add('/protected'); self.add('/badcontrol')
        expired=self.add('/expired')
        with app.db() as c: c.execute('UPDATE targets SET expires=0 WHERE id=?',(expired,))
        self.resume()
        with patch.object(accesscheck,'fetch',side_effect=self.transport):
            for _ in range(4): self.tick()
        status,state=self.api('/api/state'); self.assertEqual(status,200)
        q=state['autopilot']
        self.assertEqual([r['outcome'] for r in reversed(q['recent_runs'])],
                         ['reproduced_boundary','boundary_held','inconclusive','boundary_held'])
        self.assertEqual(len(q['cases']),1)
        self.assertEqual(len(self.fixture.seen),7)
        self.assertFalse(any(path=='/expired' for path,_ in self.fixture.seen))
        self.assertIn('eligibility unverified',q['cases'][0]['draft'])
        self.assertEqual(q['confirmed_bounty_bugs'],0)
        self.assertFalse(q['automatic_submission'])
        self.assertEqual(state['workflow']['submissions'],[])
        self.assertEqual(q['progress']['completed'],3)
        self.assertEqual(q['progress']['self_checks'],1)
        self.assertEqual(q['progress']['unfinished'],1)
        self.assertNotIn(MARKER,json.dumps(q)); self.assertNotIn(AUTH,json.dumps(q))
        app.init()
        self.assertEqual(len(app.snapshot()['autopilot']['cases']),1)
        self.assertEqual(app.snapshot()['autopilot']['progress'],q['progress'])
        self.assertEqual(self.api('/api/state',authenticated=False)[0],401)

    def test_pause_makes_no_request(self):
        self.add('/leaky')
        with patch.object(accesscheck,'fetch') as request:
            self.tick(); request.assert_not_called()
        self.assertEqual(app.snapshot()['autopilot']['state'],'paused')
        self.assertEqual(app.snapshot()['autopilot']['recent_runs'],[])

    def test_mozilla_and_unverified_directory_never_dispatch(self):
        mozilla=self.add('/mozilla')
        with app.db() as c:c.execute("UPDATE targets SET policy='https://hackerone.com/mozilla' WHERE id=?",(mozilla,))
        unknown=self.add('/unknown',policy='https://hackerone.com/not-reviewed',access=False)
        self.resume()
        with app.db() as c:
            rows=autopilot.jobs(c)
            self.assertTrue(all(j['blocker'] for j in rows if j['target'] in (mozilla,unknown) and j['kind']!='owned_validation'))
        with patch.object(accesscheck,'fetch') as request,patch.object(app,'observe') as headers:
            self.tick(); request.assert_not_called(); headers.assert_not_called()
            app.tick(mozilla); accesscheck.tick(app.db,app.DATA,app.log,mozilla)
            request.assert_not_called(); headers.assert_not_called()
        self.assertEqual(app.snapshot()['program_queue']['eligible_targets'],0)
        self.assertEqual(app.snapshot()['autopilot']['recent_runs'][0]['kind'],'owned_validation')

    def test_program_cooldown_and_schedules_survive_restart(self):
        self.add('/leaky',policy='https://policy.example/shared')
        self.add('/protected',policy='https://policy.example/shared')
        self.resume()
        with patch.object(accesscheck,'fetch',side_effect=self.transport): self.tick()
        app.init()
        with app.db() as c:
            j=autopilot.next_job(c)
            self.assertEqual(j['kind'],'owned_validation')
            c.execute('UPDATE validation_schedule SET due=?',(int(time.time())+3600,))
            self.assertIsNone(autopilot.next_job(c))
            c.execute('UPDATE autonomous_programs SET next_allowed=0')
            self.assertEqual(autopilot.next_job(c)['key'],'access:2')

    def test_abandoned_lease_is_not_completed_or_immediately_retried(self):
        self.add('/protected'); self.resume()
        with app.db() as c:
            j=autopilot.next_job(c); now=int(time.time())
            c.execute("INSERT INTO autonomous_runs(job,kind,stamp,started,finished,lease_until,outcome,evidence) VALUES(?,?,?,?,0,?,'running','[]')",(j['key'],j['kind'],j['stamp'],now,now+300))
            c.execute('INSERT INTO autonomous_rotation VALUES(?,?,?,0,0)',(j['key'],j['stamp'],now))
        with patch.object(accesscheck,'fetch') as request:
            self.tick(); request.assert_not_called()
            with app.db() as c:c.execute('UPDATE autonomous_runs SET lease_until=0')
            self.tick(); request.assert_not_called()
        q=app.snapshot()['autopilot']
        self.assertEqual(q['recent_runs'][1]['outcome'],'interrupted')
        self.assertEqual(q['cases'],[])
        self.assertEqual(q['progress']['unfinished'],1)
        self.runners={}
        self.tick(); app.init()
        self.assertEqual(app.snapshot()['autopilot']['progress']['unfinished'],1)

    def test_completed_totals_survive_history_pruning_and_restart(self):
        key=self.add('/headers',access=False); self.resume()
        now=int(time.time())
        with app.db() as c:
            c.execute('DELETE FROM autonomous_totals_origin')
            c.execute('DELETE FROM autonomous_totals')
            for i in range(202):
                c.execute('''INSERT INTO autonomous_runs(job,kind,stamp,started,finished,lease_until,outcome,evidence)
                  VALUES(?,?,?,?,?,0,?,'[]')''',('headers:'+str(key),'headers','old-fixture',now-500+i,now-500+i,
                                                            'no_observation' if i<200 else 'failed'))
        app.init() # Migrate a retained journal from the earlier application version.
        self.assertEqual(app.snapshot()['autopilot']['progress']['completed'],200)
        self.runners={'headers':lambda _: {'outcome':'no_observation'}}
        self.tick()
        with app.db() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM autonomous_runs').fetchone()[0],200)
        app.init(); app.init()
        progress=app.snapshot()['autopilot']['progress']
        self.assertEqual(progress['completed'],201)
        self.assertEqual(progress['unfinished'],2)
        self.assertEqual(progress['self_checks'],0)
        self.assertGreaterEqual(progress['last_completed'],now)

    def test_disabled_task_details_explain_stop_without_revealing_server_text(self):
        key=self.add('/stopped',access=False)
        with app.db() as c:
            c.execute('UPDATE targets SET enabled=0,state=? WHERE id=?',('Stopped: HTTP 403 '+AUTH,key))
        q=app.snapshot()['autopilot']
        job=next(j for j in q['jobs'] if j['key']=='headers:'+str(key))
        self.assertIn('website refused access',job['blocker_detail'])
        self.assertNotIn(AUTH,json.dumps(q))
        with app.db() as c:
            receipt=autopilot.diagnostic(c,'a'*40)
        self.assertEqual(receipt['blocker_detail_counts'][job['blocker_detail']],1)
        self.assertNotIn(AUTH,json.dumps(receipt))
        with app.db() as c:c.execute('UPDATE targets SET expires=0 WHERE id=?',(key,))
        job=next(j for j in app.snapshot()['autopilot']['jobs'] if j['key']=='headers:'+str(key))
        self.assertIn('Permission has expired',job['blocker_detail'])
        second=self.add('/expired-parent')
        with app.db() as c:
            c.execute('UPDATE targets SET expires=0 WHERE id=?',(second,))
            c.execute('UPDATE access_checks SET enabled=0 WHERE target=?',(second,))
        job=next(j for j in app.snapshot()['autopilot']['jobs'] if j['key']=='access:'+str(second))
        self.assertIn('Permission has expired',job['blocker_detail'])

    def test_connection_failure_details_use_only_fixed_labels(self):
        row={'expires':int(time.time())+3600,'status':AUTH,'result':json.dumps({'authentication_failed':True,'error':AUTH})}
        self.assertIn('account connection was rejected',autopilot.stop_detail(row,int(time.time())))
        row['result']=json.dumps({'reproduced':True,'error':AUTH})
        self.assertIn('possible issue was saved',autopilot.stop_detail(row,int(time.time())))
        row['result']='not valid JSON '+AUTH
        self.assertNotIn(AUTH,autopilot.stop_detail(row,int(time.time())))

    def test_revocation_during_control_stops_the_next_request(self):
        key=self.add('/leaky'); self.resume()
        def revoke(*args):
            result=self.transport(*args)
            with app.db() as c:c.execute('UPDATE targets SET expires=0 WHERE id=?',(key,))
            return result
        with patch.object(accesscheck,'fetch',side_effect=revoke): self.tick()
        self.assertEqual(len(self.fixture.seen),1)
        q=app.snapshot()['autopilot']; self.assertEqual(q['cases'],[])
        self.assertEqual(q['recent_runs'][0]['outcome'],'inconclusive')

    def test_exception_does_not_starve_other_work_or_expose_error(self):
        self.add('/leaky'); self.resume()
        self.runners['access']=lambda _: (_ for _ in ()).throw(ValueError('PRIVATE_EXCEPTION'))
        self.tick(); self.tick()
        q=app.snapshot()['autopilot']
        self.assertEqual(q['recent_runs'][1]['outcome'],'failed')
        self.assertEqual(q['recent_runs'][0]['kind'],'owned_validation')
        self.assertNotIn('PRIVATE_EXCEPTION',json.dumps(q))

    def test_reproduction_flag_without_complete_controls_is_not_evidence(self):
        fabricated={'reproduced':True,'status':'exposed','evidence':[{'status':200}]*6}
        self.assertEqual(autopilot.classify('access',fabricated),'inconclusive')
        self.assertEqual(autopilot.classify('access',{'evidence':None}),'inconclusive')
        self.assertEqual(autopilot.classify('owned_validation',{'confirmed_issue':True,'checks':[{}]*9}),'inconclusive')
        self.assertEqual(autopilot.classify('access',{'status':'Access boundary held for this test','evidence':[{},{}]}),'inconclusive')

    def test_disabled_profile_is_not_reenabled_by_finishing_result(self):
        key=self.add('/protected');self.resume()
        def disable(config,allowed):
            with app.db() as c:c.execute('UPDATE access_checks SET enabled=0 WHERE target=?',(key,))
            return {'status':'Access boundary held for this test','reproduced':False,'evidence':[]}
        with patch.object(accesscheck,'compare',side_effect=disable):self.tick()
        with app.db() as c:self.assertEqual(c.execute('SELECT enabled FROM access_checks WHERE target=?',(key,)).fetchone()[0],0)
        self.assertEqual(app.snapshot()['autopilot']['cases'],[])

    def test_rate_limit_stops_without_case_or_immediate_retry(self):
        self.add('/rate'); self.resume()
        with patch.object(accesscheck,'fetch',side_effect=self.transport): self.tick(); self.tick()
        self.assertEqual(len(self.fixture.seen),1)
        self.assertEqual(app.snapshot()['autopilot']['cases'],[])

    def test_gitlab_results_require_actual_control_and_repeat_evidence(self):
        owner=dict(project='fixture-a/private',token='fixture-owner-token',marker=MARKER)
        peer=dict(project='fixture-b/private',token='fixture-peer-token',marker=MARKER+'B')
        def response(data,status=200):
            return dict(data=data,status=status,bytes=10,sha256='a'*64)
        def token(uid):return response(dict(active=True,revoked=False,scopes=['read_api'],user_id=uid))
        def project(config,uid,role=50):
            return response(dict(id=uid,path_with_namespace=config['project'],visibility='private',description=config['marker'],permissions={'project_access':{'access_level':role}}))
        a=project(owner,1);b=project(peer,2);cross=project(owner,1,0);denied=response({},404)
        for replies,expected in (([token(1),a,denied],'boundary_held'),([token(1),a,cross,cross,a],'reproduced_boundary')):
            responses=iter(replies)
            result=gitlabcheck.compare(owner,transport=lambda *_:next(responses),pace=lambda _:None)
            self.assertEqual(autopilot.classify('gitlab',result),expected)
            if expected=='reproduced_boundary':
                result['evidence'][-1]['private']=False
                self.assertEqual(autopilot.classify('gitlab',result),'inconclusive')
        for replies,expected in (([token(1),token(2),a,b,denied,a,b],'boundary_held'),
                                 ([token(1),token(2),a,b,cross,cross,a,b],'reproduced_boundary')):
            responses=iter(replies)
            result=gitlabpair.compare(owner,peer,transport=lambda *_:next(responses),pace=lambda _:None)
            self.assertEqual(autopilot.classify('gitlab_pair',result),expected)
            result['evidence'][-1]['marker_present']=False
            self.assertEqual(autopilot.classify('gitlab_pair',result),'inconclusive')

    def test_header_observation_completes_without_runtime_investigation(self):
        self.add('/headers',access=False);self.resume()
        with app.db() as c:c.execute('UPDATE validation_schedule SET due=?',(int(time.time())+3600,))
        def head(url):
            conn=http.client.HTTPConnection('127.0.0.1',self.fixture.server_address[1])
            conn.request('HEAD',urlsplit(url).path);r=conn.getresponse();r.read();conn.close()
            return dict(status=r.status,headers={},cookies=[])
        with patch.object(app,'observe',side_effect=head):self.tick()
        state=app.snapshot()
        self.assertEqual(self.fixture.seen,[('/headers','HEAD')])
        self.assertEqual(state['program_queue']['completed'],1)
        self.assertEqual(state['autopilot']['recent_runs'][0]['outcome'],'observations')
        self.assertEqual(state['autopilot']['cases'],[])

    def test_diagnostics_contain_no_account_or_target_details(self):
        key=self.add('/private-sensitive-resource')
        with app.db() as c:c.execute('UPDATE targets SET expires=0 WHERE id=?',(key,))
        with app.db() as c:
            receipt=autopilot.diagnostic(c,'a'*40)
        raw=json.dumps(receipt)
        for forbidden in (AUTH,MARKER,'fixture.example','private-sensitive-resource',app.TOKEN,app.CSRF): self.assertNotIn(forbidden,raw)
        self.assertEqual(receipt['revision'],'a'*40)
        self.assertEqual(receipt['blocker_counts'],{'Testing permission expired':2})
        self.assertEqual(receipt['eligible_kinds'],{'owned_validation':1})
        self.assertEqual(receipt['next_due'],0)

    def test_duplicate_workers_do_not_dispatch_twice(self):
        self.add('/protected'); self.resume()
        started=threading.Event(); release=threading.Event(); calls=[]
        def runner(_):
            calls.append(1); started.set(); release.wait(3); return None
        self.runners['access']=runner
        thread=threading.Thread(target=self.tick);thread.start()
        try:
            self.assertTrue(started.wait(2)); self.tick(); self.assertEqual(calls,[1])
        finally:
            release.set();thread.join(3)
        self.assertFalse(thread.is_alive())


if __name__=='__main__': unittest.main()
