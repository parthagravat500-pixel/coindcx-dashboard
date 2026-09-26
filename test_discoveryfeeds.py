import io
import json
import tempfile
import threading
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import app
import discoveryfeeds as feeds
import programapi
import programresearch
import workflow


def company(name='Fixture company',url='https://company.example.com/security',bounty='yes',alive='alive'):
    return {'program_name':name,'policy_url':url,'offers_bounty':bounty,'policy_url_status':alive}


def crowd(name='Crowd fixture',payout=1000):
    return {'name':name,'url':'https://bugcrowd.com/engagements/fixture','max_payout':payout,
            'targets':{'in_scope':[{'target':'not-an-approved-target.example.com'}]}}


def ywh():
    return {'id':'fixture','name':'YWH fixture','public':True,'disabled':False,
            'min_bounty':50,'max_bounty':1000,'targets':{'in_scope':[]}}


class DiscoveryFeedTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.old=app.DATA;app.DATA=Path(self.temp.name)
        app.init();self.now=int(time.time())
        p=patch('rewards.refresh');p.start();self.addCleanup(p.stop)

    def tearDown(self):
        app.DATA=self.old;self.temp.cleanup()

    def sync(self,source,rows):
        return workflow.sync(app.db,source,rows,self.now)

    def test_paid_adapters_preserve_unknown_currency_and_permission(self):
        for source,row in [('bugcrowd',crowd()),('yeswehack',ywh()),('independent',company())]:
            self.sync(source,[row])
        s=app.snapshot()
        self.assertEqual(len(s['workflow']['programs']),3)
        for p in s['workflow']['programs']:
            self.assertFalse(p['scan_authorized']);self.assertEqual(p['readiness']['category'],'unknown')
            self.assertIsNone(p['maximum']);self.assertIsNone(p['reward_usd']);self.assertEqual(p['currency'],'')
            self.assertFalse(p['details']['grants_permission']);self.assertEqual(p['details']['policy_status'],'unverified')
        self.assertEqual(s['targets'],[]);self.assertEqual(s['findings'],[])
        with app.db() as c:
            receipt=workflow.receipt(c,'a'*40)
        self.assertEqual(receipt['listed'],3);self.assertEqual(receipt['targets_activated_by_discovery'],0)
        self.assertNotIn('company.example.com',json.dumps(receipt))

    def test_independent_filters_platforms_unpaid_and_preserves_conditionals(self):
        self.sync('independent',[company(bounty='no'),company(url='https://hackerone.com/fixture'),
                  company(url='https://app.intigriti.com/programs/company/fixture/detail'),
                  company('Conditional',bounty='partial'),company('Dead','https://dead.example.com/security',alive='dead')])
        rows=app.snapshot()['workflow']['programs'];self.assertEqual(len(rows),2)
        conditional=next(p for p in rows if p['name']=='Conditional')
        self.assertIn('Conditional',conditional['details']['reward_status'])
        self.assertFalse(next(p for p in rows if p['name']=='Dead')['available'])
        self.assertIsNone(feeds.normalize('yeswehack',{**ywh(),'public':False}))
        self.assertIsNone(feeds.normalize('bugcrowd',crowd(payout=0)))
        self.assertFalse(feeds.normalize('yeswehack',{**ywh(),'disabled':True})['open'])

    def test_unsafe_links_rejected_without_network_and_bad_rows_counted(self):
        urls=['javascript:alert(1)','http://example.com/policy','https://user:password@example.com/security',
              'https://127.0.0.1/security','https://[::1]/security','https://localhost/security',
              'https://a.internal/security','https://company.example.com:444/security',
              'https://company.example.com\\@evil.example.com/security','https://company.example.com/\nsecurity']
        with patch('urllib.request.OpenerDirector.open') as request,patch('socket.getaddrinfo') as dns:
            for url in urls:
                with self.subTest(url=url),self.assertRaises(ValueError):feeds.normalize('independent',company(url=url))
            self.sync('independent',[company(),company(url='javascript:alert(1)')])
            request.assert_not_called();dns.assert_not_called()
        with app.db() as c:
            source=c.execute("SELECT * FROM discovery_sources WHERE id='independent'").fetchone()
            self.assertEqual(source['invalid_rows'],1);self.assertEqual(source['accepted_rows'],1)
        with self.assertRaises(ValueError):self.sync('independent',[company(url='javascript:alert(1)')])
        self.assertTrue(app.snapshot()['workflow']['programs'][0]['available'])
        with self.assertRaises(ValueError):feeds.normalize('bugcrowd',{**crowd(),'url':'https://bugcrowd.com.attacker.com/engagements/fixture'})
        with self.assertRaises(ValueError):feeds.normalize('yeswehack',{**ywh(),'id':'../private'})

    def test_canonical_dedup_removal_and_restart_preserve_review_state(self):
        self.sync('independent',[company(url='https://company.example.com/security/'),
                  company(url='https://company.example.com/security#rules'),company('Other','https://other.example.com/policy')])
        rows=app.snapshot()['workflow']['programs'];self.assertEqual(len(rows),2)
        key=next(p for p in rows if p['name']=='Fixture company')['id']
        app.mutate('/api/program-stage',{'id':key,'stage':'review'})
        self.sync('independent',[company()]);app.init()
        rows=app.snapshot()['workflow']['programs']
        self.assertEqual(next(p for p in rows if p['id']==key)['stage'],'review')
        self.assertFalse(next(p for p in rows if p['name']=='Other')['available'])
        self.sync('independent',[company(),company(alive='dead')])
        self.assertFalse(next(p for p in app.snapshot()['workflow']['programs'] if p['id']==key)['available'])

    def test_new_sources_get_review_status_without_platform_requests(self):
        for source,row in [('bugcrowd',crowd()),('yeswehack',ywh()),('independent',company())]:self.sync(source,[row])
        app.mutate('/api/all-pause',{'paused':False})
        with patch('programapi.credentials',return_value=None),patch('programapi.request') as request:
            programresearch.tick(app.db,app.DATA,threading.RLock(),now=self.now)
            request.assert_not_called()
        s=app.snapshot()['program_research']
        self.assertEqual(s['counts'],{'policy_review_needed':3})
        self.assertEqual(s['documents_collected'],0);self.assertEqual(s['attempted'],0)
        self.assertEqual(s['briefs_prepared'],0)
        self.assertEqual({p['provider'] for p in s['providers']},{'hackerone','intigriti'})
        for row in s['rows']:
            self.assertIn('not connected for this source',row['preparation']['next_step'])
            with app.db() as c:data=programresearch.detail(c,row['id'])
            self.assertFalse(data['evidence'].get('grants_permission',False))

    def test_discovery_only_fetches_fixed_feed_and_bounds_responses(self):
        class Response(io.BytesIO):
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
        with patch('workflow.urllib.request.OpenerDirector.open',return_value=Response(json.dumps([company()]).encode())) as call:
            data=workflow.fetch_directory('independent')
            self.assertEqual(call.call_args.args[0].full_url,feeds.SOURCES['independent'][0])
            self.assertEqual(len(data),1)
        with patch('workflow.MAX_BYTES',10),patch('workflow.urllib.request.OpenerDirector.open',return_value=Response(b'x'*11)):
            with self.assertRaises(ValueError):workflow.fetch_directory('independent')
        with self.assertRaises(ValueError):self.sync('independent',[company()]*10001)
        with self.assertRaises(ValueError):workflow.NoRedirect().redirect_request(None,None,302,'',{},'https://company.example.com')

    def test_scheduler_budget_pause_and_late_response(self):
        with app.db() as c:c.execute("UPDATE discovery_sources SET due=? WHERE id!='independent'",(self.now+10000,))
        def pause_during_fetch(source):
            self.assertEqual(source,'independent')
            app.mutate('/api/discovery/pause',{'enabled':False})
            app.mutate('/api/discovery/pause',{'enabled':True})
            return [company()]
        with patch('workflow.fetch_directory',side_effect=pause_during_fetch) as fetch:
            workflow.tick(app.db);workflow.tick(app.db)
            self.assertEqual(fetch.call_count,1)
        self.assertEqual(app.snapshot()['workflow']['programs'],[])
        with app.db() as c:
            c.execute('UPDATE discovery_sources SET due=0,last_attempt=0')
            c.execute('UPDATE discovery_health SET next_request=0')
        with patch('workflow.fetch_directory',return_value=[]) as fetch:
            workflow.tick(app.db);workflow.tick(app.db);self.assertEqual(fetch.call_count,1)
        with app.db() as c:c.execute('UPDATE discovery_sources SET last_attempt=0')
        workflow.RUN_LOCK.acquire()
        try:
            with patch('workflow.fetch_directory') as fetch:workflow.tick(app.db);fetch.assert_not_called()
        finally:workflow.RUN_LOCK.release()

    def test_rate_limit_and_access_refusal_retained_across_restart(self):
        with app.db() as c:c.execute("UPDATE discovery_sources SET due=? WHERE id!='bugcrowd'",(self.now+100000,))
        error=urllib.error.HTTPError(feeds.SOURCES['bugcrowd'][0],429,'Limited',{'Retry-After':'7200'},None)
        with patch('workflow.fetch_directory',side_effect=error):workflow.tick(app.db)
        with app.db() as c:
            row=c.execute("SELECT * FROM discovery_sources WHERE id='bugcrowd'").fetchone()
            self.assertGreaterEqual(row['due'],self.now+7200)
            c.execute('UPDATE discovery_sources SET last_attempt=0,due=0')
        app.init()
        with patch('workflow.fetch_directory') as fetch:workflow.tick(app.db);fetch.assert_not_called()
        with app.db() as c:
            c.execute('UPDATE discovery_health SET next_request=0')
            c.execute("UPDATE discovery_sources SET due=? WHERE id!='bugcrowd'",(self.now+100000,))
        error=urllib.error.HTTPError(feeds.SOURCES['bugcrowd'][0],403,'Private',{},None)
        with patch('workflow.fetch_directory',side_effect=error):workflow.tick(app.db)
        app.init()
        with app.db() as c:
            c.execute('UPDATE discovery_sources SET last_attempt=0')
            c.execute('UPDATE discovery_health SET next_request=0')
        app.mutate('/api/discovery/refresh',{})
        with patch('workflow.fetch_directory',return_value=[]) as fetch:
            # Other sources can continue; the refused source stays blocked.
            workflow.tick(app.db);self.assertNotEqual(fetch.call_args.args[0],'bugcrowd')
        with app.db() as c:self.assertEqual(c.execute("SELECT blocked FROM discovery_sources WHERE id='bugcrowd'").fetchone()[0],1)

    def test_original_schema_migration_preserves_old_listing(self):
        with app.db() as c:
            c.execute('DROP TABLE discovery_sources');c.execute('DROP TABLE discovery_settings')
            c.execute('CREATE TABLE discovery_settings(id INTEGER PRIMARY KEY,enabled INTEGER)')
            c.execute('INSERT INTO discovery_settings VALUES(1,0)')
            c.execute('CREATE TABLE discovery_sources(id TEXT PRIMARY KEY,due INTEGER DEFAULT 0,last_attempt INTEGER DEFAULT 0,last_success INTEGER DEFAULT 0,status TEXT DEFAULT "Waiting",failures INTEGER DEFAULT 0)')
            c.execute("INSERT INTO discovery_sources(id,last_success,due) VALUES('hackerone',?,?)",(self.now,self.now+200))
        app.init()
        with app.db() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM discovery_sources').fetchone()[0],5)
            self.assertEqual(c.execute("SELECT last_success FROM discovery_sources WHERE id='hackerone'").fetchone()[0],self.now)
            self.assertEqual(c.execute('SELECT enabled FROM discovery_settings').fetchone()[0],0)


if __name__=='__main__':unittest.main()
