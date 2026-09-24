import base64
import json
import sqlite3
import subprocess
import tempfile
import time
import unittest
import http.client
import threading
from pathlib import Path
from unittest.mock import patch

import ci_identity as identity
import research
import app


class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=test-only',
                        '-keyout',str(cls.root/'key'),'-out',str(cls.root/'cert'),'-days','1'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        der = subprocess.check_output(['openssl','x509','-in',str(cls.root/'cert'),'-outform','DER'])
        cls.keys = {'keys':[{'kid':'test','kty':'RSA','use':'sig','alg':'RS256','x5c':[base64.b64encode(der).decode()]}]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def claims(self):
        return dict(iss=identity.ISSUER,aud=identity.AUDIENCE,repository=identity.REPOSITORY,
                    repository_id='1350819047',repository_owner_id='319591622',ref=identity.BRANCH,
                    sub=identity.SUBJECT,workflow_ref=identity.WORKFLOW,
                    event_name='push',runner_environment='github-hosted',iat=1000,nbf=1000,exp=1300,
                    sha='a'*40,workflow_sha='a'*40,run_id='123',run_attempt='1')

    def token(self, claims=None, header=None):
        encode = lambda b:base64.urlsafe_b64encode(b).decode().rstrip('=')
        header = header or dict(alg='RS256',typ='JWT',kid='test')
        message = encode(json.dumps(header).encode())+'.'+encode(json.dumps(claims or self.claims()).encode())
        sig = subprocess.run(['openssl','dgst','-sha256','-sign',str(self.root/'key')],input=message.encode(),capture_output=True,check=True).stdout
        return message+'.'+encode(sig)

    def test_valid_real_signature(self):
        self.assertEqual(identity.verify_token(self.token(),self.keys,1100)['run_id'],'123')

    def test_wrong_claims_fail(self):
        for key,value in [('repository','other/repo'),('aud','other'),('ref','refs/heads/main'),('sub','other'),
                          ('sub','repo:'+identity.REPOSITORY+':ref:'+identity.BRANCH),
                          ('workflow_ref','other'),('repository_id','1'),('repository_owner_id','1'),
                          ('runner_environment','self-hosted'),('event_name','pull_request'),('exp',1001),
                          ('iat',True),('workflow_sha','b'*40),('run_id','../../x')]:
            with self.subTest(claim=key), self.assertRaises(ValueError):
                identity.verify_token(self.token({**self.claims(),key:value}),self.keys,1100)

    def test_tampering_and_header_injection_fail(self):
        token=self.token();head,body,sig=token.split('.')
        sig=('B' if sig[0]!='B' else 'C')+sig[1:]
        with self.assertRaises(ValueError):identity.verify_token(head+'.'+body+'.'+sig,self.keys,1100)
        for change in [{'alg':'none'},{'jku':'https://example.com/keys'},{'kid':'absent'},{'crit':[]}]:
            with self.subTest(change=change),self.assertRaises(ValueError):
                identity.verify_token(self.token(header={**dict(alg='RS256',typ='JWT',kid='test'),**change}),self.keys,1100)
        with self.assertRaises(ValueError):identity.strict_object([('aud','one'),('aud','two')])


class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.c=sqlite3.connect(':memory:');self.c.row_factory=sqlite3.Row;self.addCleanup(self.c.close)
        self.c.execute('CREATE TABLE settings(paused INTEGER)');self.c.execute('INSERT INTO settings VALUES(0)')
        research.init(self.c)
        self.claims={'sha':'a'*40,'run_id':'123','run_attempt':'1'}

    def enable(self):research.configure(self.c,{'enabled':True})
    def send(self,stage,**extra):return research.receive(self.c,self.claims,{'revision':'a'*40,'stage':stage,**extra})
    def result(self):return dict(model='Qwen2.5-Coder-7B-Instruct-Q4_K_M',status='reviewed',calibration_passed=True,
                                 reviews=[dict(file='app.py',line=1,analysis='A test hypothesis, not evidence.')])

    def test_disabled_and_paused_deny_start(self):
        self.assertFalse(self.send('start')['accepted']);self.enable()
        self.c.execute('UPDATE settings SET paused=1');self.assertFalse(self.send('start')['accepted'])

    def test_lease_private_result_and_replay(self):
        self.enable();self.assertTrue(self.send('start')['accepted'])
        self.assertTrue(self.send('result',result=self.result())['accepted'])
        snap=research.snapshot(self.c);review=snap['ai_reviews'][0]['result']
        self.assertFalse(review['submission_ready']);self.assertEqual(review['confirmed_bugs'],0)
        self.assertFalse(snap['autonomous_bounty_hunting']);self.assertFalse(self.send('start')['accepted'])
        self.send('result',result={**self.result(),'reviews':[]})
        self.assertEqual(research.snapshot(self.c)['ai_reviews'][0]['result'],review)

    def test_no_lease_wrong_revision_and_expiry(self):
        self.enable()
        with self.assertRaises(ValueError):self.send('result',result=self.result())
        with self.assertRaises(ValueError):research.receive(self.c,self.claims,{'stage':'start','revision':'b'*40})
        self.send('start');self.c.execute('UPDATE private_ai_reviews SET started=1')
        with self.assertRaises(ValueError):self.send('result',result=self.result())

    def test_only_one_lease_and_pause_receipt(self):
        self.enable();self.send('start')
        self.assertFalse(research.receive(self.c,{**self.claims,'run_id':'124'},{'stage':'start','revision':'a'*40})['accepted'])
        self.c.execute('UPDATE settings SET paused=1');self.assertFalse(self.send('result',result=self.result())['accepted'])

    def test_disable_cancels_lease_and_late_result_cannot_replace_it(self):
        self.enable();self.send('start');research.configure(self.c,{'enabled':False})
        self.assertEqual(research.snapshot(self.c)['ai_reviews'][0]['state'],'cancelled')
        self.enable();self.send('result',result=self.result())
        self.assertEqual(research.snapshot(self.c)['ai_reviews'][0]['state'],'cancelled')

    def test_model_cannot_promote_its_own_claim(self):
        r=research.clean_result({**self.result(),'confirmed_bugs':100,'submission_ready':True})
        self.assertEqual(r['confirmed_bugs'],0);self.assertFalse(r['submission_ready'])
        for change in [{'calibration_passed':False},{'reviews':[]},{'model':'unknown'},
                       {'reviews':[dict(file='secrets.env',line=1,analysis='private')]}]:
            with self.subTest(change=change),self.assertRaises(ValueError):research.clean_result({**self.result(),**change})

    def test_run_filter_and_link_are_fixed(self):
        run=dict(id=123,path='.github/workflows/scopeguard-isolated.yml',head_branch='scopeguard-app',repository={'full_name':research.REPO},
                 head_sha='a'*40,status='completed',conclusion='success',html_url='https://attacker.invalid',updated_at=None)
        result=research.normalize_runs({'workflow_runs':[None,{},run,{**run,'id':124},{**run,'head_branch':'main'}]})
        self.assertEqual(len(result),1);self.assertIn('github.com/'+research.REPO,result[0]['url'])

    def test_key_cache_and_receipt_rate_are_bounded(self):
        with patch.dict(research.KEY_CACHE,{'at':0,'keys':[]}):
            with self.assertRaises(ValueError):research.claims_for('not-a-token')
        with patch.object(research,'REQUEST_TIMES',[]):
            self.assertTrue(all(research.admit_request() for _ in range(12)))
            self.assertFalse(research.admit_request())


class ReceiptHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        p=patch.object(app,'DATA',Path(self.tmp.name));p.start();self.addCleanup(p.stop)
        p=patch.object(app,'TOKEN','unit-test-password-with-24-characters');p.start();self.addCleanup(p.stop)
        p=patch.object(research,'REQUEST_TIMES',[]);p.start();self.addCleanup(p.stop)
        app.init()
        self.server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)

    def request(self,path,headers,body='{}'):
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_address[1],timeout=3)
        try:
            connection.request('POST',path,body,headers)
            response=connection.getresponse()
            return response.status,response.read().decode()
        finally:connection.close()

    def test_no_identity_bad_identity_and_size(self):
        self.assertEqual(self.request('/api/ci-review',{})[0],401)
        with patch.object(research,'claims_for',side_effect=ValueError('private diagnostic must not leak')):
            status,body=self.request('/api/ci-review',{'Authorization':'Bearer invalid'})
        self.assertEqual(status,403);self.assertNotIn('diagnostic',body)
        self.assertEqual(self.request('/api/ci-review',{},'x'*32001)[0],400)

    def test_ai_configuration_still_requires_auth(self):
        self.assertEqual(self.request('/api/research-ai',{},'{"enabled":true}')[0],401)

    def test_valid_identity_cannot_bypass_owner_pause(self):
        claims={'sha':'a'*40,'run_id':'123','run_attempt':'1'}
        with patch.object(research,'claims_for',return_value=claims):
            status,body=self.request('/api/ci-review',{'Authorization':'Bearer synthetic'},json.dumps({'stage':'start','revision':'a'*40}))
        self.assertEqual(status,200);self.assertFalse(json.loads(body)['accepted'])
