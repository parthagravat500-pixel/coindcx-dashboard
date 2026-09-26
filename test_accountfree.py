import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import accountfree
import app
import programqueue


class PublicResearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        p = patch.object(app, 'DATA', Path(self.temp.name)); p.start(); self.addCleanup(p.stop)
        self.plan = {'reviewed': int(time.time())-1, 'expires': int(time.time())+600,
                     'programs': [{'id':'test', 'name':'Test', 'policy':'https://example.com/security',
                                   'pages':['https://example.com/'], 'script_hosts':['example.com'], 'budget':5}]}
        p = patch.object(accountfree, 'load_plan', return_value=self.plan); p.start(); self.addCleanup(p.stop)
        app.init()
        with app.db() as c: c.execute('UPDATE settings SET paused=0')

    @staticmethod
    def response(text='', status=200, mime='text/html', limited=False):
        return {'body':text.encode(), 'status':status, 'type':mime, 'limited':limited}

    def test_only_referenced_allowlisted_static_scripts_and_no_raw_contents(self):
        urls = []
        def transport(url, headers):
            urls.append(url)
            if url.endswith('.js'):
                return self.response('element.innerHTML=location.hash; const value="PRIVATE_TEST_VALUE";', mime='application/javascript')
            return self.response('<a href="/private">Ignore</a><script src="https://other.com/x.js"></script><script src="/x.js"></script><script src="/delete"></script>')
        accountfree.tick(app.db, app.log, transport, lambda _:None)
        self.assertEqual(urls, ['https://example.com/', 'https://example.com/x.js'])
        with app.db() as c: s=accountfree.snapshot(c)
        self.assertEqual(s['candidates'], 1)
        self.assertEqual(s['confirmed_bugs'], 0)
        self.assertNotIn('PRIVATE_TEST_VALUE', json.dumps(s))
        self.assertEqual(s['requests'], 2)

    def test_forbidden_and_rate_limit_stop_without_retries(self):
        for status in (301,401,403,429,500):
            calls=[]
            p={**self.plan['programs'][0], 'pages':['https://example.com/','https://example.com/other']}
            result=accountfree.run_program(p,lambda:True,lambda u,h:(calls.append(u) or self.response(status=status)),lambda _:None)
            self.assertEqual(len(calls),1)
            self.assertEqual(result['state'],'http_'+str(status))
            self.assertEqual(result['reviewed'],0)

    def test_pause_between_requests_and_no_restart(self):
        def transport(url, headers):
            with app.db() as c:c.execute('UPDATE settings SET paused=1')
            return self.response('<script src="/next.js"></script>')
        accountfree.tick(app.db,app.log,transport,lambda _:None)
        with app.db() as c:
            self.assertEqual(accountfree.snapshot(c)['requests'],1)
            c.execute('UPDATE settings SET paused=0')
            c.execute('UPDATE public_research_health SET next_request=0')
        with patch.object(accountfree,'fetch') as request:
            accountfree.tick(app.db,app.log,request,lambda _:None)
            request.assert_not_called()

    def test_expiration_and_crash_do_not_restart_requests(self):
        self.plan['expires']=int(time.time())-1
        with patch.object(accountfree,'fetch') as request:
            accountfree.tick(app.db,app.log,request,lambda _:None);request.assert_not_called()
        with app.db() as c:self.assertEqual(c.execute('SELECT state FROM public_batches').fetchone()[0],'expired')
        self.plan['expires']=int(time.time())+100
        with app.db() as c:c.execute("UPDATE public_batches SET state='running',started=?",(int(time.time())-700,))
        with patch.object(accountfree,'fetch') as request:
            accountfree.tick(app.db,app.log,request,lambda _:None);request.assert_not_called()
        with app.db() as c:self.assertEqual(c.execute('SELECT state FROM public_batches').fetchone()[0],'interrupted')

    def test_sensitive_material_and_challenge_stop_and_discard(self):
        for body,state in [('-----BEGIN PRIVATE KEY-----\nTOP_SECRET','sensitive_material_stop'),('Verify you are human','access_challenge')]:
            result,scripts=accountfree.analyze(body.encode(),'text/html')
            self.assertEqual(result['state'],state)
            self.assertNotIn('sha256',result)
            self.assertNotIn('TOP_SECRET',json.dumps(result))
            self.assertEqual(scripts,[])

    def test_document_clues_never_grant_automation(self):
        raw=self.response('<p>Bug bounty program. Automated tools are forbidden. '+('Public program rules. '*30)+'</p>')
        result=accountfree.policy_result(raw)
        self.assertEqual(result['state'],'document_collected')
        self.assertFalse(result['authorization'])

    def test_finite_script_budget(self):
        calls=[]
        body=''.join('<script src="/script'+str(i)+'.js"></script>' for i in range(30))
        result=accountfree.run_program(self.plan['programs'][0],lambda:True,
            lambda u,h:(calls.append(u) or self.response(body)),lambda _:None)
        self.assertEqual(len(calls),5)
        self.assertEqual(result['requests'],5)

    def test_scope_validation_blocks_redirect_hosts_and_private_names(self):
        for url in ['http://example.com/','https://name:secret@example.com/','https://example.com:8443/','https://example.com/#x']:
            with self.assertRaises(ValueError):accountfree.checked_url(url)
        self.assertTrue(programqueue.automation_blocker('https://hackerone.com/flipkart'))
        self.assertTrue(programqueue.automation_blocker('https://example.com/policy','https://www.flipkart.com/'))

    def test_sanitized_and_comment_code_not_claimed(self):
        result,_=accountfree.analyze(b'<script>// x.innerHTML=location.hash;\nx.innerHTML=DOMPurify.sanitize(location.hash);</script>','text/html')
        self.assertEqual(result['patterns'],[])


if __name__ == '__main__':unittest.main()
