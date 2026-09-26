import copy
import base64
import hashlib
import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch, MagicMock

import app
import autopilot
import boundarysuite
import browserruntime
import checkpointengine
import huntops
import workflow
import workflowmap


class FocusedResearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.old=app.DATA
        app.DATA=Path(self.tmp.name);app.init();self.now=int(time.time())
        with app.db() as c:
            c.execute('UPDATE settings SET paused=0')
            self.ids=[]
            for name in ('one','two','page'):
                self.ids.append(c.execute('''INSERT INTO targets(name,url,policy,rules,expires,interval,cors)
                  VALUES(?,?,?,?,?,?,0)''',(name,'https://fixture.example.test/'+name,
                  'https://fixture.example.test/policy','Owned synthetic GET comparison fixture permission.',self.now+3600,900)).lastrowid)
        self.data={'name':'Owned fixture workflow','rules':'Owned test accounts and synthetic resources; twelve GET requests per 15 minutes permitted.',
            'permission':True,'own_accounts':True,'synthetic_data':True,'read_only_get':True,'expected_access_reviewed':True,
            'interval':900,'request_budget':12,'request_gap':1,
            'accounts':[{'id':'a','role':'owner','authorization':'Bearer synthetic-account-a-secret'},
                        {'id':'b','role':'member','authorization':'Bearer synthetic-account-b-secret'}],
            'resources':[{'id':'one','target':self.ids[0],'owner':'a','allow':['a'],
                          'marker':'owned_synthetic_marker_one_12345','feature':'private_object'},
                         {'id':'two','target':self.ids[1],'owner':'b','allow':['b'],
                          'marker':'owned_synthetic_marker_two_12345','feature':'nested_resource'}]}

    def tearDown(self):app.DATA=self.old;self.tmp.cleanup()

    def configure(self,data=None):
        with app.db() as c:return huntops.configure(c,app.DATA,data or self.data)

    def transport(self,vulnerable=False):
        self.calls=[]
        def fetch(url,auth,marker):
            self.calls.append((url,auth))
            owner='a' if url.endswith('/one') else 'b'
            exposed=vulnerable or auth.endswith('-'+owner+'-secret')
            return {'status':200 if exposed else 403,'json':True,'marker_present':exposed,
                    'bytes':30,'sha256':hashlib.sha256(str(exposed).encode()).hexdigest(),
                    'body':'MUST NOT BE PERSISTED','authorization':auth,'cookie':'SECRET'}
        return fetch

    def tick(self,fetch=None):huntops.tick(app.db,app.DATA,app.log,fetch or self.transport(),pace=lambda _:None)

    def due(self,key):
        with app.db() as c:
            c.execute('UPDATE hunt_profiles SET due=0 WHERE id=?',(key,))
            c.execute('UPDATE autonomous_programs SET next_allowed=0')

    def test_private_configuration_and_snapshot(self):
        key=self.configure();p=huntops.path(app.DATA,key)
        self.assertEqual(p.stat().st_mode & 0o777,0o600)
        with app.db() as c:
            visible=json.dumps(huntops.snapshot(c))
            self.assertNotIn('Bearer synthetic',visible);self.assertNotIn('owned_synthetic_marker',visible)
            self.assertEqual(huntops.snapshot(c)['metrics']['programs_testing'],1)
        self.assertIn('Bearer synthetic',p.read_text())

    def test_permissions_and_origin_and_budget_required(self):
        for change in ({'permission':False},{'read_only_get':False},{'request_budget':25},
                       {'interval':10},{'request_gap':0},{'expires':self.now+10*86400}):
            with self.subTest(change=change),app.db() as c,self.assertRaises(ValueError):
                huntops.configure(c,app.DATA,{**self.data,**change})
        invalid=copy.deepcopy(self.data);invalid['accounts'][1]['authorization']=invalid['accounts'][0]['authorization']
        with app.db() as c,self.assertRaises(ValueError):huntops.configure(c,app.DATA,invalid)
        with app.db() as c:c.execute("UPDATE targets SET url='https://other.example.test/two' WHERE id=?",(self.ids[1],))
        with app.db() as c,self.assertRaises(ValueError):huntops.configure(c,app.DATA,self.data)

    def test_complete_evidence_and_real_read_controls(self):
        key=self.configure();self.tick(self.transport(True))
        with app.db() as c:
            s=huntops.snapshot(c);self.assertEqual(s['metrics']['reproduced'],1)
            self.assertEqual(s['metrics']['reports_ready'],0)
            self.assertFalse(s['profiles'][0]['enabled'])
            proof=s['cases'][0]['evidence'];self.assertTrue(boundarysuite.verify_test(proof,proof['test']))
            raw=json.dumps(s);self.assertNotIn('MUST NOT BE PERSISTED',raw);self.assertNotIn('synthetic-account-a-secret',raw)
            saved=c.execute('SELECT * FROM hunt_cases').fetchone()
            report=huntops.report(c,saved['id']);self.assertIn('Investigation draft',report)
            self.assertIn('comparison_two',report);self.assertNotIn('Bearer',report)
            support=huntops.checkpoint_support(c,'target:'+str(self.ids[0]))
            self.assertEqual(support['SG-0161']['state'],'runtime_failed')
        self.assertEqual(len(self.calls),4)
        self.tick(self.transport(True));self.assertEqual(len(self.calls),0)

    def test_false_signal_and_review_gate(self):
        key=self.configure();self.tick(self.transport(True))
        with app.db() as c:
            item=huntops.snapshot(c)['cases'][0]
            with self.assertRaises(ValueError):huntops.review(c,{'id':item['id'],'disposition':'validated','impact':'X'*50})
            huntops.review(c,{'id':item['id'],'disposition':'false_positive','impact':'The resource was intentionally shared.'})
            self.assertLess(huntops.learning(c)[0]['priority'],0.5)
            s=huntops.snapshot(c);self.assertEqual(s['metrics']['reproduced'],0)
            huntops.review(c,{'id':item['id'],'disposition':'validated','impact':'Synthetic private record was exposed to the unrelated owned account.',
                'identities_verified':True,'expected_access_verified':True,'scope_verified':True,'duplicates_checked':True})
            self.assertTrue(huntops.snapshot(c)['cases'][0]['report_ready'])
            c.execute('UPDATE targets SET enabled=0 WHERE id=?',(self.ids[0],))
            self.assertFalse(huntops.snapshot(c)['cases'][0]['report_ready'])

    def test_pause_and_midrun_permission_change(self):
        key=self.configure()
        with app.db() as c:c.execute('UPDATE settings SET paused=1')
        self.tick(self.transport());self.assertEqual(self.calls,[])
        with app.db() as c:c.execute('UPDATE settings SET paused=0')
        fetch=self.transport(True)
        def revoke(url,auth,marker):
            result=fetch(url,auth,marker)
            with app.db() as c:c.execute('UPDATE targets SET enabled=0 WHERE id=?',(self.ids[0],))
            return result
        self.tick(revoke)
        self.assertEqual(len(self.calls),1)
        with app.db() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM hunt_cases').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT state FROM hunt_runs').fetchone()[0],'invalidated')

    def test_global_lease_prevents_overlap(self):
        key=self.configure()
        with app.db() as c:
            c.execute("INSERT INTO autonomous_runs(job,kind,stamp,started,finished,lease_until,outcome,evidence) VALUES('x','gitlab','x',?,0,?,'running','[]')",(self.now,self.now+300))
        self.tick(self.transport());self.assertEqual(self.calls,[])
        with app.db() as c:
            c.execute("UPDATE autonomous_runs SET outcome='boundary_held'")
            c.execute("INSERT INTO hunt_runs(profile,revision,stamp,kind,started,finished,lease_until,state,result) VALUES(?,'r','s','matrix',?,0,?,'running','{}')",(key,self.now,self.now+300))
            self.assertIsNone(autopilot.next_job(c,self.now))
        self.tick(self.transport());self.assertEqual(self.calls,[])

    def test_resume_after_restart_and_bounded_batches(self):
        self.data['request_budget']=6;key=self.configure();self.tick()
        with app.db() as c:
            self.assertEqual(c.execute('SELECT cursor FROM hunt_profiles').fetchone()[0],1)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM hunt_cases').fetchone()[0],0)
        app.init();self.due(key);self.tick()
        with app.db() as c:self.assertEqual(c.execute('SELECT cursor FROM hunt_profiles').fetchone()[0],2)
        self.assertEqual(len(self.calls),6)

    def test_stale_policy_or_target_changes_block_requests(self):
        key=self.configure()
        with app.db() as c:c.execute("UPDATE targets SET rules='Updated permission requires a fresh method review.' WHERE id=?",(self.ids[0],))
        self.tick(self.transport());self.assertEqual(self.calls,[])
        with app.db() as c:self.assertIn('changed',huntops.snapshot(c)['profiles'][0]['blocker'])

    def test_html_map_does_not_follow_links_or_store_values(self):
        config={'accounts':[{'id':'a','authorization':'private-auth'}],'browser_account':'a',
                'map_urls':['https://fixture.example.test/page'],'request_gap':1,'request_budget':4,'browser':False}
        calls=[]
        def fetch(url,auth):
            calls.append(url)
            return {'status':200,'content_type':'text/html','body':b'<a href="https://outside.test/secret">Private name</a><form action="/delete" method="post"><input type="password" value="NEVER_SAVE"></form>'}
        result=workflowmap.map_pages(config,transport=fetch,pace=lambda _:None)
        self.assertEqual(len(calls),1);self.assertEqual(len(result['pages'][0]['links']),1)
        self.assertEqual(result['pages'][0]['forms'][0]['method'],'POST')
        raw=json.dumps(result)
        for value in ('NEVER_SAVE','Private name','outside.test','private-auth'):self.assertNotIn(value,raw)
        stopped=workflowmap.map_pages(config,allowed=lambda:False,transport=fetch)
        self.assertEqual(stopped['requests'],0)

    def test_mapping_permission_and_scheduling(self):
        self.data['map_targets']=[self.ids[2]]
        with app.db() as c,self.assertRaises(ValueError):huntops.configure(c,app.DATA,self.data)
        self.data['mapping_permission']=True;key=self.configure();calls=[]
        def mapper(config,permit,pace):
            calls.append(config['map_urls']);self.assertTrue(permit())
            return {'engine':'fixture','pages':[{'route':'synthetic','forms':[]}],'requests':1,'state':'complete','browser_executed':False}
        huntops.tick(app.db,app.DATA,app.log,mapper=mapper,pace=lambda _:None)
        with app.db() as c:
            s=huntops.snapshot(c);self.assertEqual(s['metrics']['features_mapped'],1)
            self.assertEqual(s['recent_runs'][0]['kind'],'map')
        self.due(key);self.tick()
        with app.db() as c:self.assertEqual(huntops.snapshot(c)['recent_runs'][0]['kind'],'matrix')

    def test_focus_ranks_actual_configuration_and_never_enables(self):
        for i in range(7):
            workflow.sync(app.db,'hackerone',[{'name':'Example '+str(i),'url':'https://hackerone.com/example'+str(i),
                'offers_bounties':True,'submission_state':'open','max_bounty':100}],self.now+i)
        with app.db() as c:
            before=list(c.execute('SELECT id,enabled FROM targets'))
            packs=huntops.focus(c)
            self.assertLessEqual(len(packs),5)
            self.assertTrue(all(p['status']=='Preparing' for p in packs))
            self.assertEqual([tuple(r) for r in before],[tuple(r) for r in c.execute('SELECT id,enabled FROM targets')])

    def test_benchmark_and_real_http_known_bug_detection(self):
        b=boundarysuite.benchmark();self.assertEqual(b['passed'],b['total']);self.assertEqual(b['false_positives'],0)
        self.configure()
        marker=self.data['resources'][0]['marker']
        other_marker=self.data['resources'][1]['marker']
        class Fixture(BaseHTTPRequestHandler):
            vulnerable=True
            def log_message(self,*args):pass
            def do_GET(self):
                first=self.path=='/one'
                owner=self.headers.get('Authorization','').endswith('-a-secret' if first else '-b-secret')
                status=200 if owner or self.vulnerable else 403
                body=json.dumps({'marker':marker if first else other_marker} if status==200 else {'error':'denied'}).encode()
                self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        server=ThreadingHTTPServer(('127.0.0.1',0),Fixture);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def transport(url,auth,wanted):
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
            try:
                conn.request('GET',urlsplit(url).path,headers={'Authorization':auth} if auth else {})
                response=conn.getresponse();body=response.read()
                return {'status':response.status,'json':True,'marker_present':wanted in body.decode(),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
            finally:conn.close()
        try:
            config=huntops.load(app.DATA,next(app.DATA.glob('workflow-*.json')).stem.removeprefix('workflow-'))
            result=boundarysuite.run(config,transport,pace=lambda _:None)
            self.assertTrue(boundarysuite.verify_test(result,result['tests'][0]))
            Fixture.vulnerable=False
            result=boundarysuite.run(config,transport,pace=lambda _:None)
            self.assertEqual(result['reproduced'],0)
            self.assertTrue(all(t['state']=='boundary_held' for t in result['tests']))
        finally:server.shutdown();server.server_close();thread.join()

    def test_runtime_setup_not_triggered_by_imports_or_snapshot(self):
        with patch.object(browserruntime.subprocess,'run',side_effect=AssertionError('No install during tests')):
            app.init();app.snapshot()

    def test_broken_comparison_account_is_inconclusive(self):
        key=self.configure();config=huntops.load(app.DATA,key);fetch=self.transport()
        def broken(url,auth,marker):
            result=fetch(url,auth,marker)
            if auth.endswith('-b-secret'):result.update(status=401,marker_present=False)
            return result
        result=boundarysuite.run(config,broken,pace=lambda _:None)
        peer=[t for t in result['tests'] if t['actor']=='b'][0]
        self.assertEqual(peer['state'],'inconclusive')
        self.assertEqual(result['stop_reason'],'Comparison account control failed')
        self.assertEqual(result['reproduced'],0)

    def test_browser_interception_blocks_unapproved_requests(self):
        module=MagicMock();browser=module.sync_playwright.return_value.__enter__.return_value.chromium.launch.return_value
        context=browser.new_context.return_value;page=context.new_page.return_value;handlers=[]
        context.route.side_effect=lambda pattern,handler:handlers.append(handler)
        page.evaluate.return_value={'forms':1,'links':0,'buttons':0}
        calls=[];routes=[]
        def navigate(url,**kwargs):
            for method,route_url in [('GET',url),('GET','https://outside.invalid/private'),('POST',url),('GET',url)]:
                route=MagicMock();route.request.method=method;route.request.url=route_url
                handlers[0](route);routes.append(route)
        page.goto.side_effect=navigate
        def fetch(url,auth):
            calls.append((url,auth));return {'status':200,'content_type':'text/html','body':b'<form></form>'}
        config={'accounts':[{'id':'a','authorization':'synthetic-private-auth'}],'browser_account':'a',
                'map_urls':['https://owned.example.test/page'],'request_budget':4,'request_gap':1}
        with patch.dict('sys.modules',{'playwright':MagicMock(),'playwright.sync_api':module}):
            result=workflowmap.chromium_map(config,lambda:True,fetch,lambda _:None)
        self.assertEqual(len(calls),1);self.assertEqual(result['blocked_requests'],2)
        self.assertTrue(result['browser_executed']);self.assertEqual(result['pages'][0]['rendered']['forms'],1)
        self.assertNotIn('synthetic-private-auth',json.dumps(result))
        routes[1].abort.assert_called_once();routes[2].abort.assert_called_once()
        args=module.sync_playwright.return_value.__enter__.return_value.chromium.launch.call_args.kwargs['args']
        self.assertIn('--proxy-server=http://127.0.0.1:9',args)
        context.route_web_socket.assert_called_once()

    def test_report_api_authentication_and_csrf(self):
        self.configure();self.tick(self.transport(True))
        with app.db() as c:key=c.execute('SELECT id FROM hunt_cases').fetchone()[0]
        old_token=app.TOKEN;app.TOKEN='synthetic-workflow-private-dashboard-password'
        server=ThreadingHTTPServer(('127.0.0.1',0),app.Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        auth={'Authorization':'Basic '+base64.b64encode(('admin:'+app.TOKEN).encode()).decode()}
        def request(method,path,headers=None,body=None):
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
            try:
                conn.request(method,path,headers=headers or {},body=body)
                response=conn.getresponse();return response.status,response.read().decode()
            finally:conn.close()
        try:
            self.assertEqual(request('GET','/workflow-report/'+key)[0],401)
            status,body=request('GET','/workflow-report/'+key,auth)
            self.assertEqual(status,200);self.assertIn('Investigation draft',body);self.assertNotIn('Bearer synthetic',body)
            self.assertEqual(request('POST','/api/workflows/disable',auth,json.dumps({'id':'unknown'}))[0],403)
        finally:server.shutdown();server.server_close();thread.join();app.TOKEN=old_token


if __name__=='__main__':unittest.main()
