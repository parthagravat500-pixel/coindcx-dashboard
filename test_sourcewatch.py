import io
import json
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import app
import projectaudit
import sourcewatch as s

SHA='a'*40
NEXT='b'*40


class SourceWatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        p=patch.object(app,'DATA',Path(self.tmp.name));p.start();self.addCleanup(p.stop)
        app.init()
        self.data={'repository':'owner/project','branch':'main','subdirectory':'',
            'rules':'I own this synthetic test repository and permit read-only source review.',
            'authorized':True,'expires':int(time.time())+86400}
    def configure(self):
        app.mutate('/api/source-watch',self.data)
        return self.watch()['id']
    def watch(self):return app.snapshot()['source_watch']['watches'][0]
    def enable(self):app.mutate('/api/all-pause',{'paused':False})
    def due(self):
        with app.db() as c:
            c.execute('UPDATE source_watches SET due=0')
            c.execute('UPDATE source_watch_health SET next_request=0')
    def archive(self,sha=SHA,files=None,root=None):
        buf=io.BytesIO()
        files=files or {'app.py':'raise RuntimeError("MUST_NOT_EXECUTE")\ndef route():\n return eval(input())'}
        with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as z:
            for path,text in files.items():z.writestr((root or 'project-'+sha)+'/'+path,text)
        return buf.getvalue()
    def ref(self,sha=SHA):return json.dumps({'ref':'refs/heads/main','object':{'type':'commit','sha':sha}}).encode()
    def tick(self):s.tick(app.db,app.LOCK,app.log)
    def test_consent_paths_expiry_and_limits(self):
        for key,value in [('authorized',False),('repository','https://github.com/owner/project'),('repository','owner/../project'),('branch','../main'),('branch','main//x'),('branch','main?token=x'),('subdirectory','../src'),('subdirectory','src/'),('rules','short'),('expires',0)]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                with app.db() as c:s.configure(c,{**self.data,key:value})
        for i in range(3):
            with app.db() as c:s.configure(c,{**self.data,'repository':'owner/project'+str(i)})
        with self.assertRaises(ValueError):
            with app.db() as c:s.configure(c,self.data)
    def test_initial_pause_no_network_then_commit_review_and_unchanged_skip(self):
        self.configure()
        with patch.object(s,'fetch',side_effect=[self.ref(),self.archive(),self.ref()]) as fetch:
            self.tick();fetch.assert_not_called()
            self.enable();self.tick();self.assertEqual(fetch.call_count,2)
            w=self.watch();self.assertEqual(w['last_commit'],SHA);self.assertEqual(w['reviews'],1)
            self.assertGreater(w['due'],w['checked']+850)
            self.tick();self.assertEqual(fetch.call_count,2)
            self.due();self.tick();self.assertEqual(fetch.call_count,3)
        a=app.snapshot()['project_audits'][0]
        self.assertEqual(a['result']['source_revision']['commit'],SHA)
        self.assertEqual(a['result']['files_analyzed'],1)
        self.assertEqual(a['result']['total_findings'],1)
        self.assertEqual(a['result']['automatic_validation']['modeled_flows'],1)
        self.assertIn('not submission-ready',a['result']['findings'][0]['investigation_draft'])
        self.assertEqual(app.snapshot()['targets'],[])
        self.assertEqual(app.snapshot()['workflow']['submissions'],[])
        self.assertEqual(a['result']['confirmed_bugs'],0)
        self.assertNotIn('MUST_NOT_EXECUTE',json.dumps(a))
        self.assertEqual(a['result']['findings'][0]['file'],'app.py')
        self.assertEqual(self.watch()['reviews'],1)
        app.init();self.assertEqual(self.watch()['last_commit'],SHA)
    def test_new_revision_uses_stable_paths(self):
        self.configure();self.enable()
        with patch.object(s,'fetch',side_effect=[self.ref(),self.archive(),self.ref(NEXT),self.archive(NEXT,{'app.py':'\n\ndef route():\n return eval(input())'})]):
            self.tick();self.due();self.tick()
        r=app.snapshot()['project_audits'][0]['result']
        self.assertEqual(r['changes']['changed_files'],['app.py'])
        self.assertEqual(r['changes']['new_leads'],0)
        self.assertEqual(r['source_revision']['commit'],NEXT)
        self.assertEqual(self.watch()['reviews'],2)
    def test_pause_or_revoke_between_requests(self):
        for action in ('pause','disable','expire','renew'):
            with self.subTest(action=action):
                self.configure();self.enable();self.due()
                def fetch(*args):
                    with app.db() as c:
                        if action=='pause':c.execute('UPDATE settings SET paused=1')
                        elif action=='expire':c.execute('UPDATE source_watches SET expires=0')
                        elif action=='renew':c.execute('UPDATE source_watches SET generation=generation+1')
                        else:c.execute('UPDATE source_watches SET enabled=0')
                    return self.ref()
                with patch.object(s,'fetch',side_effect=fetch) as f:self.tick();self.assertEqual(f.call_count,1)
                self.assertEqual(app.snapshot()['project_audits'],[])
    def test_bad_or_redirected_source_does_not_replace_previous_evidence(self):
        self.configure();self.enable()
        with patch.object(s,'fetch',side_effect=[self.ref(),self.archive()]):self.tick()
        self.due()
        with patch.object(s,'fetch',side_effect=s.FetchError('Source request stopped: HTTP 302.')):self.tick()
        self.assertEqual(self.watch()['enabled'],0)
        self.assertEqual(app.snapshot()['project_audits'][0]['result']['source_revision']['commit'],SHA)
    def test_rate_backoff_survives_renewal(self):
        self.configure();self.enable()
        with patch.object(s,'fetch',side_effect=s.FetchError('Rate limited',7200)):self.tick()
        due=self.watch()['due'];self.assertGreater(due,time.time()+7100)
        self.configure();self.assertEqual(self.watch()['due'],due)
        with patch.object(s,'fetch') as f:self.tick();f.assert_not_called()
    def test_three_transient_failures_disable(self):
        self.configure();self.enable()
        with patch.object(s,'fetch',side_effect=TimeoutError):
            for _ in range(3):self.due();self.tick()
        self.assertEqual(self.watch()['enabled'],0);self.assertEqual(self.watch()['failures'],3)
    def test_expiry_stops_without_network(self):
        self.configure();self.enable()
        with app.db() as c:c.execute('UPDATE source_watches SET expires=0')
        with patch.object(s,'fetch') as f:self.tick();f.assert_not_called()
        self.assertIn('expired',self.watch()['status'])
    def test_archive_root_and_language_errors_stop(self):
        for archive in [self.archive(root='unexpected'),self.archive(files={'only.rb':'puts 1'})]:
            self.configure();self.enable();self.due()
            with patch.object(s,'fetch',side_effect=[self.ref(),archive]):self.tick()
            self.assertEqual(self.watch()['enabled'],0)
            self.assertEqual(app.snapshot()['project_audits'],[])
    def test_bad_ref_identity_stops(self):
        self.configure();self.enable()
        wrong=json.dumps({'ref':'refs/heads/another','object':{'type':'commit','sha':SHA}}).encode()
        with patch.object(s,'fetch',return_value=wrong) as f:self.tick();self.assertEqual(f.call_count,1)
        self.assertEqual(self.watch()['enabled'],0)
    def test_prefix_filter_and_duplicate_archives(self):
        self.data['subdirectory']='src';self.configure();self.enable()
        archive=self.archive(files={'src/app.py':'def safe():\n return 1','other/a.py':'def route():\n return eval(input())'},root='Project-'+SHA)
        with patch.object(s,'fetch',side_effect=[self.ref(),archive]):self.tick()
        r=app.snapshot()['project_audits'][0]['result'];self.assertEqual(r['files_analyzed'],1);self.assertEqual(r['total_findings'],0)
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z:
            z.writestr('root/a.py','x=1')
            z.writestr('root/a.py','x=2')
        import base64
        with self.assertRaises(ValueError):projectaudit.archive(base64.b64encode(buf.getvalue()).decode(),prefix='root/')
    def test_engine_change_rechecks_same_revision(self):
        self.configure();self.enable()
        with patch.object(s,'fetch',side_effect=[self.ref(),self.archive(),self.ref(),self.archive()]) as f:
            self.tick();self.due()
            with app.db() as c:c.execute("UPDATE source_watches SET engine='previous'")
            self.tick();self.assertEqual(f.call_count,4)
        self.assertEqual(self.watch()['reviews'],2)
    def test_identical_python_in_new_commit_reuses_analysis_without_new_leads(self):
        self.configure();self.enable()
        with patch.object(s,'fetch',side_effect=[self.ref(),self.archive(),self.ref(NEXT),self.archive(NEXT)]):
            self.tick();self.due();self.tick()
        r=app.snapshot()['project_audits'][0]['result']
        self.assertTrue(r['source_revision']['analysis_reused'])
        self.assertEqual(r['changes']['new_leads'],0)
        self.assertEqual(r['findings'][0]['change_status'],'Existing lead')
    def test_commit_response_with_invalid_object(self):
        self.configure();self.enable()
        with patch.object(s,'fetch',return_value=b'{"ref":"refs/heads/main","object":null}'):
            self.tick()
        self.assertEqual(self.watch()['enabled'],0)
    def test_fetch_blocks_host_redirect_and_honors_retry(self):
        with self.assertRaises(ValueError):s.fetch('localhost','/',100)
        response=MagicMock();response.status=302
        conn=MagicMock();conn.getresponse.return_value=response
        with patch.object(s,'public_addresses',return_value=['140.82.112.6']),patch.object(s.socket,'create_connection'),patch.object(s.ssl,'create_default_context'),patch.object(s.http.client,'HTTPSConnection',return_value=conn):
            with self.assertRaises(s.FetchError):s.fetch('api.github.com','/path',100)
            self.assertEqual(conn.request.call_count,1)
            headers=conn.request.call_args.kwargs['headers'];self.assertNotIn('Authorization',headers)
            response.status=429;response.getheader.side_effect=lambda k,d='':{'Retry-After':'7200'}.get(k,d)
            with self.assertRaises(s.FetchError) as e:s.fetch('api.github.com','/path',100)
            self.assertGreaterEqual(e.exception.retry,7200)


if __name__=='__main__':unittest.main()
