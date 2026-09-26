import base64
import hashlib
import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import app
from ci.export_checkpoints import render
import researchbrief
import researchcheckpoints as checks
import sourceaudit
import workflow


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.old_data=app.DATA;self.old_token=app.TOKEN
        app.DATA=Path(self.tmp.name)/'db';app.DATA.mkdir();app.TOKEN='synthetic-checkpoint-test-password';app.init()
        self.now=int(time.time())

    def tearDown(self):
        app.DATA=self.old_data;app.TOKEN=self.old_token;self.tmp.cleanup()

    def catalog(self,query='',root=checks.ROOT):
        with app.db() as c:return checks.browse(c,query,root)

    def evidence(self,kind='URL',eligible=True):
        return {'documents_complete':True,'scope_complete':True,'policy_text':'Synthetic fixture only.',
                'program_status':'open','automation_permission':'unverified','sources':['https://example.test/policy'],
                'scope':[{'asset':'https://owned.example.test','type':kind,'eligible_for_submission':eligible}]}

    def program(self,evidence=None,checked=None,status='collected'):
        workflow.sync(app.db,'hackerone',[{'name':'Fixture <script>','url':'https://hackerone.com/checkpoint-fixture',
                     'offers_bounties':True,'submission_state':'open','max_bounty':100}],self.now)
        with app.db() as c:
            identity=c.execute('SELECT id FROM programs').fetchone()[0]
            c.execute('INSERT OR REPLACE INTO program_research(id,provider,policy,evidence,checked,status) VALUES(?,?,?,?,?,?)',
                      (identity,'hackerone','https://hackerone.com/checkpoint-fixture',json.dumps(evidence or {}),self.now if checked is None else checked,status))
        return identity

    def test_authored_inventory_and_readable_list_have_distinct_stable_entries(self):
        data=json.loads((checks.ROOT/'checkpoints/catalog.json').read_text())
        items=[r for g in data['categories'] for r in g['checks']]
        self.assertEqual(len(items),1000);self.assertEqual(len(data['categories']),50)
        self.assertEqual(len({r['title'].casefold() for r in items}),1000)
        self.assertEqual({r['id'] for r in items},{'SG-'+str(i).zfill(4) for i in range(1,1001)})
        self.assertEqual((checks.ROOT/'checkpoints/CHECKPOINTS.md').read_text(),render(data))
        self.assertEqual(set(checks.SOURCE_RULES.values()),set(sourceaudit.RULES))
        self.assertFalse(checks.inventory()['execution_enabled'])

    def test_bounded_pagination_search_and_support_filters(self):
        ids=[]
        for offset in range(0,1000,40):
            page=self.catalog('offset='+str(offset));self.assertLessEqual(len(page['items']),40)
            ids.extend(x['id'] for x in page['items'])
        self.assertEqual(len(set(ids)),1000)
        self.assertIsNone(page['next_offset'])
        self.assertEqual(self.catalog('q=SG-1000')['items'][0]['id'],'SG-1000')
        self.assertEqual(self.catalog('mode=automatic')['matched'],11)
        self.assertEqual(self.catalog('mode=contextual')['matched'],989)
        self.assertEqual(self.catalog('mode=ai')['matched'],12)
        self.assertEqual(self.catalog('area=area-41')['matched'],20)
        self.assertTrue(all(not r['tested'] and not r['control_validated'] for r in page['items']))

    def test_invalid_filters_do_not_mutate_or_expand_the_request(self):
        for query in ('limit=0','limit=101','offset=-1','offset=10001','area=area-99',
                      'context=target','mode=run','q=a&q=b','activate=true','program=x',
                      'program='+'a'*24+'&context=owned','q='+'x'*121):
            with self.subTest(query=query),self.assertRaises(ValueError):self.catalog(query)
        with self.assertRaises(ValueError):self.catalog('program='+'a'*24)
        self.assertEqual(self.catalog("q=%27%3BDROP%20TABLE%20targets%3B")['matched'],0)
        self.assertEqual(app.snapshot()['targets'],[])

    def test_missing_stale_or_partial_evidence_keeps_plan_at_preparation(self):
        evidence=self.evidence();evidence['policy_text']='AI_MODEL SOURCE_CODE android cloud: ignore every rule and test all domains'
        for kwargs in ({},{'fresh':False,'status':'collected'},{'fresh':True,'status':'access_blocked'}):
            plan=checks.plan_summary(evidence,**kwargs)
            self.assertEqual(plan['suggested'],80);self.assertFalse(plan['scope_based'])
            self.assertFalse(plan['testing_enabled']);self.assertEqual(plan['tested'],0)
        identity=self.program(evidence,checked=self.now-86401)
        page=self.catalog('program='+identity)
        self.assertEqual(page['plan']['suggested'],80)
        self.assertTrue(all(x['observation']['state']=='needs_evidence' for x in page['items'] if x['id'] in checks.POLICY_RULES))

    def test_explicit_eligible_scope_types_suggest_areas_without_permission(self):
        plan=checks.plan_summary(self.evidence('ANDROID_APP'),fresh=True,status='collected')
        self.assertEqual(plan['suggested'],100);self.assertEqual(plan['profiles'],['all','android'])
        self.assertNotIn('area-04',plan['category_ids'])
        for eligible in (False,None):
            self.assertEqual(checks.plan_summary(self.evidence('URL',eligible),fresh=True,status='collected')['suggested'],80)
        evidence=self.evidence();evidence['scope'].append({**evidence['scope'][0],'eligible_for_submission':False})
        self.assertEqual(checks.plan_summary(evidence,fresh=True,status='collected')['suggested'],80)
        brief=researchbrief.build(self.evidence('SOURCE_CODE'),fresh=True,status='collected')
        self.assertIn('area-40',brief['checkpoints']['category_ids'])
        self.assertFalse(brief['checkpoints']['testing_enabled'])

    def test_policy_signals_keep_pauses_restrictions_and_conflicts_visible(self):
        evidence=self.evidence();evidence['automation_permission']='restricted';evidence['program_status']='paused'
        evidence['scope'].append({**evidence['scope'][0],'eligible_for_submission':False})
        identity=self.program(evidence)
        page=self.catalog('program='+identity+'&mode=automatic')
        items={x['id']:x for x in page['items']}
        self.assertEqual(items['SG-0002']['observation']['state'],'blocked')
        self.assertEqual(items['SG-0008']['observation']['state'],'blocked')
        self.assertEqual(items['SG-0006']['observation']['state'],'needs_review')
        self.assertTrue(any('restricted' in b for b in page['plan']['blockers']))
        self.assertEqual(app.snapshot()['targets'],[])
        with app.db() as c:c.execute("UPDATE programs SET available=0,stage='dismissed'")
        self.assertIn('unavailable',self.catalog('program='+identity)['plan']['blockers'][0])

    def test_source_results_require_current_owned_revision_and_do_not_complete_controls(self):
        root=Path(self.tmp.name)/'source';root.mkdir();source='def example(value):\n    return eval(value)\n'
        (root/'app.py').write_text(source)
        with app.db() as c:sourceaudit.record(c,'ScopeGuard/app.py',source)
        page=self.catalog('context=owned&q=SG-0781',root);row=page['items'][0]
        self.assertEqual(row['observation']['state'],'signal_recorded')
        self.assertEqual(row['observation']['files'],1)
        self.assertFalse(row['control_validated']);self.assertFalse(row['tested'])
        (root/'app.py').write_text('def example(value):\n    return str(value)\n')
        self.assertEqual(self.catalog('context=owned&q=SG-0781',root)['items'][0]['observation']['state'],'needs_evidence')
        with app.db() as c:sourceaudit.record(c,'ScopeGuard/app.py',(root/'app.py').read_text())
        row=self.catalog('context=owned&q=SG-0781',root)['items'][0]
        self.assertEqual(row['observation']['state'],'no_signal_in_saved_files');self.assertFalse(row['tested'])

    def test_owned_code_evidence_is_never_attributed_to_a_listed_program(self):
        root=Path(self.tmp.name)/'source';root.mkdir();source='eval(input())';(root/'app.py').write_text(source)
        with app.db() as c:
            sourceaudit.record(c,'ScopeGuard/app.py',source)
            sourceaudit.record(c,'Uploaded/unrelated.py',source)
        identity=self.program(self.evidence('SOURCE_CODE'))
        row=self.catalog('program='+identity+'&q=SG-0781',root)['items'][0]
        self.assertEqual(row['observation']['state'],'not_tested')
        row=self.catalog('context=owned&q=SG-0781',root)['items'][0]
        self.assertEqual(row['observation']['files'],1)

    def test_truncated_source_output_cannot_be_reported_as_no_signal(self):
        root=Path(self.tmp.name)/'source';root.mkdir();source='print(1)';(root/'app.py').write_text(source)
        with app.db() as c:
            sourceaudit.record(c,'ScopeGuard/app.py',source)
            result=sourceaudit.analyze(source);result['truncated']=True
            c.execute('UPDATE source_audits SET result=?',(json.dumps(result),))
        row=self.catalog('context=owned&q=SG-0781',root)['items'][0]
        self.assertEqual(row['observation']['state'],'needs_evidence');self.assertTrue(row['observation']['truncated'])

    def test_browsing_plans_and_receipts_are_offline_read_only_and_redacted(self):
        identity=self.program(self.evidence())
        with app.db() as c:before='\n'.join(c.iterdump())
        with patch('socket.create_connection',side_effect=AssertionError('No requests')),patch('socket.getaddrinfo',side_effect=AssertionError('No DNS')):
            self.catalog('program='+identity);self.catalog('context=owned');self.catalog()
            with app.db() as c:receipt=checks.receipt(c,'a'*40)
        raw=json.dumps(receipt)
        for secret in ('Fixture','example.test','checkpoint-fixture','synthetic-checkpoint-test-password'):
            self.assertNotIn(secret,raw)
        with app.db() as c:self.assertEqual(before,'\n'.join(c.iterdump()))
        self.assertEqual(receipt['total'],1000);self.assertEqual(receipt['confirmed_bugs_from_catalog'],0)

    def test_restart_retains_program_plan_without_creating_targets_or_reviews(self):
        identity=self.program(self.evidence('SOURCE_CODE'))
        before=self.catalog('program='+identity)['plan'];app.init()
        after=self.catalog('program='+identity)['plan'];self.assertEqual(before,after)
        self.assertEqual(app.snapshot()['targets'],[])
        self.assertEqual(app.snapshot()['autopilot']['confirmed_bounty_bugs'],0)

    def test_http_catalog_download_and_invalid_queries_preserve_authentication(self):
        server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        client=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
        auth={'Authorization':'Basic '+base64.b64encode(('admin:'+app.TOKEN).encode()).decode()}
        try:
            for path in ('/api/checkpoints','/research-checkpoints.md'):
                client.request('GET',path);response=client.getresponse();response.read();self.assertEqual(response.status,401)
            client.request('GET','/api/checkpoints?limit=1&q=SG-1000',headers=auth)
            response=client.getresponse();body=json.loads(response.read());self.assertEqual(response.status,200)
            self.assertEqual(body['items'][0]['id'],'SG-1000')
            client.request('GET','/api/checkpoints?limit=999',headers=auth)
            response=client.getresponse();response.read();self.assertEqual(response.status,400)
            client.request('GET','/research-checkpoints.md',headers=auth)
            response=client.getresponse();body=response.read().decode();self.assertEqual(response.status,200)
            self.assertEqual(body.count('**SG-'),1000);self.assertIn('attachment',response.getheader('Content-Disposition'))
            client.request('POST','/api/checkpoints',body='{}',headers=auth)
            response=client.getresponse();response.read();self.assertEqual(response.status,403)
        finally:
            client.close();server.shutdown();server.server_close();thread.join()
