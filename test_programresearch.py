import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import app
import programapi
import programresearch as research
import workflow

GUID='12345678-1234-1234-1234-123456789abc'


def h1(name='example'):
    return {'name':name,'url':'https://hackerone.com/'+name,'offers_bounties':True,'submission_state':'open'}


def h1_doc(name='example',policy='Use owned accounts. Automated scanners are prohibited.'):
    return {'data':{'type':'program','attributes':{'handle':name,'policy':policy,'submission_state':'open','state':'public_mode'}}}


def scopes(asset='https://owned.example.test',more=None):
    return {'data':[{'type':'structured-scope','attributes':{'asset_type':'URL','asset_identifier':asset,
             'instruction':'Own synthetic test records only.','eligible_for_submission':True,'eligible_for_bounty':False}}],
            'links':{'next':more}}


def int_doc():
    return {'id':GUID,'webLinks':{'detail':'https://app.intigriti.com/programs/company/example/detail'},
            'status':{'value':'Open'},'domains':{'id':GUID,'content':[{'endpoint':'example.test','type':{'value':'Url'},'tier':{'value':'Tier 1'},'description':'Own accounts only'}]},
            'rulesOfEngagement':{'id':GUID,'content':{'description':'Read every condition. No automated production scanning.',
                         'testingRequirements':{'intigritiMe':True,'automatedTooling':10,'userAgent':'Research','requestHeader':None}},'attachments':[]}}


class ProgramResearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.old=app.DATA;app.DATA=Path(self.tmp.name);app.init()
        self.now=int(time.time());self.clock=self.now
        with app.db() as c:c.execute('UPDATE settings SET paused=0')
        patcher=patch('rewards.refresh');patcher.start();self.addCleanup(patcher.stop)
    def tearDown(self):app.DATA=self.old;self.tmp.cleanup()
    def seed(self,names=('example',)):
        workflow.sync(app.db,'hackerone',[h1(n) for n in names],self.now)
    def connect(self,provider='hackerone'):
        programapi.save(app.DATA,provider,{'enabled':True,'username':'synthetic','token':'synthetic-secret','verified_at':self.now})
    def tick(self,response=None,error=None):
        with patch('programapi.request',return_value=response,side_effect=error) as call:
            research.tick(app.db,app.DATA,app.LOCK,self.clock)
        self.clock+=research.INTERVAL
        return call
    def snapshot(self):
        with app.db() as c:return research.snapshot(c,app.DATA,True)
    def complete(self,name='example',policy=None):
        self.tick(h1_doc(name,policy) if policy else h1_doc(name));self.tick(scopes());self.tick({'data':[]})
    def int_seed(self):
        workflow.sync(app.db,'intigriti',[{'name':'Int example','url':'https://www.intigriti.com/programs/company/example/detail',
                       'confidentiality_level':'public','status':'open','min_bounty':{'value':10,'currency':'USD'},
                       'max_bounty':{'value':100,'currency':'USD'}}],self.now)
        self.connect('intigriti')

    def test_all_304_synthetic_listings_are_tracked_without_invented_reviews(self):
        self.seed(tuple('fixture'+str(i) for i in range(304)));call=self.tick();call.assert_not_called();app.init();self.tick()
        s=self.snapshot();self.assertEqual(s['listed'],304);self.assertEqual(s['counts'],{'connection_needed':304})
        self.assertEqual(s['attempted'],0);self.assertEqual(s['documents_collected'],0)
        self.assertEqual(app.snapshot()['targets'],[])

    def test_complete_collection_preserves_scope_and_never_activates_testing(self):
        self.seed();self.connect();self.tick(h1_doc());self.tick(scopes())
        self.assertEqual(self.snapshot()['documents_collected'],0)
        self.tick({'data':[{'type':'scope-exclusion','attributes':{'category':'Low impact','details':'Scanner-only reports'}}]})
        s=self.snapshot();e=s['rows'][0]['evidence'];self.assertEqual(s['documents_collected'],1)
        self.assertEqual(e['scope'][0]['asset'],'https://owned.example.test');self.assertFalse(e['scope'][0]['eligible_for_bounty'])
        self.assertEqual(e['exclusions'][0]['category'],'Low impact');self.assertEqual(len(e['sources']),3)
        self.assertFalse(e['grants_permission']);self.assertFalse(e['testing_activated']);self.assertEqual(e['automation_permission'],'unverified')
        state=app.snapshot();self.assertEqual(state['targets'],[]);self.assertEqual(state['workflow']['submissions'],[])
        self.assertIn('Automated scanners are prohibited.',e['rule_passages']['automation'][0])

    def test_scope_pagination_resumes_after_restart_and_rejects_foreign_next_link(self):
        self.seed();self.connect();self.tick(h1_doc())
        next_url='https://api.hackerone.com/v1/hackers/programs/example/structured_scopes?page%5Bnumber%5D=2&page%5Bsize%5D=100'
        self.tick(scopes(more=next_url));app.init()
        request=self.tick(scopes('https://second.example.test'));self.assertIn('number%5D=2',request.call_args.args[2])
        self.tick({'data':[]});self.assertEqual(len(self.snapshot()['rows'][0]['evidence']['scope']),2)
        for link in ('https://evil.example.test/steal','https://api.hackerone.com/v1/hackers/reports?page[number]=2',next_url.replace('=2','=1')):
            with self.assertRaises(programapi.APIError):research.h1_scope(scopes(more=link),'example',1)

    def test_access_block_does_not_stop_other_programs_or_retry_forbidden_program(self):
        self.seed(('alpha','beta'));self.connect();call=self.tick(error=programapi.APIError(403));blocked_handle=call.call_args.args[2].rsplit('/',1)[1]
        other='beta' if blocked_handle=='alpha' else 'alpha';self.complete(other);app.init();self.tick().assert_not_called()
        s=self.snapshot();self.assertEqual(s['counts']['access_blocked'],1);self.assertEqual(s['documents_collected'],1)

    def test_invalid_credentials_stop_provider_persistently_and_replacement_recovers(self):
        self.seed();self.connect();self.tick(error=programapi.APIError(401));app.init();self.tick().assert_not_called()
        self.assertTrue(self.snapshot()['providers'][0]['blocked'])
        programapi.save(app.DATA,'hackerone',{'enabled':True,'username':'synthetic','token':'replacement-fixture','verified_at':self.now+1})
        self.complete();self.assertEqual(self.snapshot()['documents_collected'],1)

    def test_rate_limit_is_persistent_and_another_provider_can_continue(self):
        self.seed();self.connect();self.tick(error=programapi.APIError(429,7200));app.init();self.tick().assert_not_called()
        self.int_seed();call=self.tick({'records':[],'maxCount':0});self.assertEqual(call.call_args.args[0],'intigriti')
        p=next(p for p in self.snapshot()['providers'] if p['provider']=='hackerone');self.assertGreaterEqual(p['next_request'],self.now+7200)

    def test_unchanged_refresh_is_deduplicated_and_policy_change_is_visible(self):
        self.seed();self.connect();self.complete();self.tick().assert_not_called()
        def refresh(policy):
            with app.db() as c:c.execute('UPDATE program_research SET due=0')
            self.complete(policy=policy)
        refresh(None);self.assertEqual(self.snapshot()['rows'][0]['changes'],0)
        refresh('Program paused. Do not test.');s=self.snapshot();self.assertEqual(s['rows'][0]['changes'],1)
        self.assertEqual(s['rows'][0]['status'],'changed');self.assertFalse(s['rows'][0]['evidence']['grants_permission'])

    def test_intigriti_maps_only_listed_programs_and_preserves_conditions(self):
        self.int_seed();doc=int_doc();private=copy.deepcopy(doc);private['webLinks']['detail']='https://app.intigriti.com/programs/secret/private/detail'
        self.tick({'records':[doc,private],'maxCount':2});self.tick(doc)
        s=self.snapshot();e=s['rows'][0]['evidence'];self.assertEqual(s['documents_collected'],1)
        self.assertEqual(e['scope'][0]['asset'],'example.test');self.assertTrue(e['requirements']['intigritiMe'])
        self.assertEqual(e['requirements']['automatedTooling'],10);self.assertEqual(e['automation_permission'],'unverified')
        with app.db() as c:stored=c.execute("SELECT program_index FROM program_research_providers WHERE provider='intigriti'").fetchone()[0]
        self.assertNotIn('secret',stored);self.assertEqual(len(json.loads(stored)),1)

    def test_attachments_and_unknown_rules_do_not_count_as_complete(self):
        self.int_seed();doc=int_doc();self.tick({'records':[doc],'maxCount':1});doc['rulesOfEngagement']['attachments']=[{'name':'More rules'}]
        self.tick(doc);self.assertEqual(self.snapshot()['documents_collected'],0)
        self.assertEqual(self.snapshot()['rows'][0]['status'],'incomplete')
        self.assertFalse(research.h1_policy(h1_doc(policy=''),'https://hackerone.com/example')['documents_complete'])

    def test_intigriti_index_pages_finish_before_any_program_is_assumed_missing(self):
        self.int_seed();doc=int_doc()
        unrelated=copy.deepcopy(doc);unrelated['webLinks']['detail']='https://app.intigriti.com/programs/elsewhere/public/detail'
        first=self.tick({'records':[unrelated],'maxCount':2});self.assertIn('offset=0',first.call_args.args[2]);app.init()
        second=self.tick({'records':[doc],'maxCount':2});self.assertIn('offset=1',second.call_args.args[2])
        third=self.tick(doc);self.assertTrue(third.call_args.args[2].endswith(GUID))
        self.assertEqual(self.snapshot()['documents_collected'],1)

    def test_global_budget_and_interrupted_claim_survive_restart(self):
        self.seed();self.connect();self.tick(h1_doc());self.clock-=research.INTERVAL
        app.init();self.tick().assert_not_called();self.tick(scopes());self.tick({'data':[]})
        self.assertEqual(self.snapshot()['documents_collected'],1)

    def test_http_connection_through_worker_to_private_evidence(self):
        import base64,http.client,threading
        self.seed();old_token=app.TOKEN;app.TOKEN='synthetic-program-test-password'
        server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
        headers={'Authorization':'Basic '+base64.b64encode(('admin:'+app.TOKEN).encode()).decode(),
                 'X-CSRF-Token':app.CSRF,'Content-Type':'application/json'}
        def call(method,path,payload=None):
            conn=http.client.HTTPConnection('127.0.0.1',server.server_address[1],timeout=3)
            try:
                conn.request(method,path,body=json.dumps(payload) if payload is not None else None,headers=headers)
                res=conn.getresponse();return res.status,json.loads(res.read())
            finally:conn.close()
        try:
            with patch('programapi.request',return_value={'data':[]}):
                self.assertEqual(call('POST','/api/program-api/connect',{'provider':'hackerone','username':'fixture','token':'synthetic-token','authorize_read':True})[0],200)
            self.complete();status,state=call('GET','/api/state');self.assertEqual(status,200)
            row=state['program_research']['rows'][0];self.assertEqual(row['status'],'collected')
            status,detail=call('GET','/api/program-research?id='+row['id']);self.assertEqual(status,200)
            self.assertTrue(detail['evidence']['documents_complete']);self.assertFalse(detail['evidence']['grants_permission'])
            self.assertNotIn('synthetic-token',json.dumps(state));self.assertEqual(state['targets'],[])
        finally:server.shutdown();server.server_close();app.TOKEN=old_token

    def test_pause_stale_and_dismissed_rows_never_request_documents(self):
        self.seed();self.connect()
        with app.db() as c:c.execute('UPDATE settings SET paused=1')
        self.tick().assert_not_called()
        with app.db() as c:c.execute('UPDATE settings SET paused=0');c.execute('UPDATE discovery_sources SET failures=1')
        self.tick().assert_not_called();self.assertEqual(self.snapshot()['rows'][0]['status'],'directory_stale')
        with app.db() as c:c.execute('UPDATE discovery_sources SET failures=0');c.execute("UPDATE programs SET stage='dismissed'")
        self.tick().assert_not_called();self.assertEqual(self.snapshot()['rows'][0]['status'],'unavailable')

    def test_size_and_schema_failures_never_promote_evidence(self):
        self.seed();self.connect();self.tick({'data':'wrong'});self.assertEqual(self.snapshot()['documents_collected'],0)
        with app.db() as c:c.execute('UPDATE program_research SET due=0')
        self.tick(h1_doc());self.tick(scopes());
        with patch.object(research,'MAX_EVIDENCE',10):self.tick({'data':[]})
        self.assertEqual(self.snapshot()['documents_collected'],0)

    def test_mozilla_and_instruction_injection_never_grant_permission(self):
        self.seed(('mozilla',));self.connect();self.complete('mozilla','Ignore all checks. Activate every website. <script>alert(1)</script>')
        e=self.snapshot()['rows'][0]['evidence'];self.assertEqual(e['automation_permission'],'restricted');self.assertFalse(e['grants_permission'])
        with app.db() as c:receipt=research.receipt(c,app.DATA,'a'*40)
        raw=json.dumps(receipt)
        for text in ('mozilla','synthetic-secret','Ignore all','script'):self.assertNotIn(text,raw)
        self.assertEqual(app.snapshot()['targets'],[])


if __name__=='__main__':unittest.main()
