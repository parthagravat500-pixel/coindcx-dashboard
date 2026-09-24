import base64
import http.client
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import app
import engine


class ScopeTests(unittest.TestCase):
    def test_url_restrictions(self):
        for url in ['http://example.com', 'https://user:pass@example.com', 'https://example.com:444/',
                    'https://example.com/#x', 'https://example.com/?token=x', 'https://*.example.com',
                    'https://example.com/\r\nx:1', 'https://example.com\\@evil.com', 'https://%65xample.com']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                engine.validate_url(url)
        self.assertEqual(engine.validate_url('https://example.com/scope').path, '/scope')

    def test_dns_private_and_mixed_blocked(self):
        for addresses in [('127.0.0.1',), ('169.254.169.254',), ('::1',), ('10.1.1.1',), ('93.184.216.34', '192.168.0.1')]:
            result = [(2, 1, 6, '', (a, 443)) for a in addresses]
            with patch('engine.socket.getaddrinfo', return_value=result), self.assertRaises(ValueError):
                engine.public_addresses('example.com')

    def test_head_pinned_ip_and_redaction(self):
        conn = MagicMock()
        conn.getresponse.return_value.status = 302
        conn.getresponse.return_value.getheaders.return_value = [('Location','https://other.example/secret'),('Set-Cookie','session=SECRET; Secure; HttpOnly')]
        tls = MagicMock()
        tls.getpeercert.return_value = {'notAfter':'2030'}
        context = MagicMock()
        context.wrap_socket.return_value = tls
        with patch('engine.public_addresses',return_value=['93.184.216.34']), patch('engine.socket.create_connection') as connect, patch('engine.ssl.create_default_context',return_value=context), patch('engine.http.client.HTTPSConnection',return_value=conn):
            result=engine.observe('https://example.com/approved')
            connect.assert_called_once_with(('93.184.216.34',443),timeout=12)
            self.assertEqual(conn.request.call_args.args,('HEAD','/approved'))
            self.assertEqual(conn.request.call_count,1)
            self.assertNotIn('SECRET',json.dumps(result))
            self.assertNotIn('other.example',json.dumps(result))
            self.assertEqual(engine.findings(result),[])

    def test_cors_is_only_a_lead(self):
        basic={'status':200,'headers':{},'cookies':[]}
        cors={'status':200,'headers':{'access-control-allow-origin':'https://scopeguard.invalid','access-control-allow-credentials':'true'}}
        result=engine.findings(basic,cors)
        self.assertTrue(any(f['rule']=='cors-reflection' for f in result))
        self.assertTrue(all(f['severity']=='Informational' for f in result))


class AppTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.old=app.DATA
        app.DATA=Path(self.temp.name)
        app.init()
        app.TOKEN='test-password-not-for-production-12345'
        self.target={'name':'Fixture','url':'https://example.com/approved','policy':'https://example.com/policy',
                     'rules':'Synthetic test authorization; only these exact HEAD requests.', 'expires':int(time.time())+86400,
                     'interval':3600,'authorized':True,'automation_allowed':True,'cors':False}

    def tearDown(self):
        app.DATA=self.old
        self.temp.cleanup()

    def add(self):
        app.mutate('/api/targets',self.target)

    def resume(self):
        app.mutate('/api/pause',{'paused':False})

    def test_schedule_changes_require_active_permission_and_preserve_scope(self):
        self.add()
        data={'id':1,'interval':300,'reviewed':True,'rules':'Reviewed fixture permission for low-volume exact URL HEAD only.','start_delay':60}
        for change in [{'reviewed':False},{'interval':1},{'interval':True},{'start_delay':301}]:
            with self.assertRaises(ValueError):app.mutate('/api/target-schedule',{**data,**change})
        app.mutate('/api/target-schedule',data)
        t=app.snapshot()['targets'][0]
        self.assertEqual(t['interval'],300);self.assertEqual(t['url'],self.target['url'])
        self.assertEqual(t['expires'],self.target['expires']);self.assertFalse(t['cors'])
        app.mutate('/api/target-state',{'id':1,'enabled':False})
        with self.assertRaises(ValueError):app.mutate('/api/target-schedule',data)
        with app.db() as c:c.execute('UPDATE targets SET enabled=1,expires=0 WHERE id=1')
        with self.assertRaises(ValueError):app.mutate('/api/target-schedule',data)

    def test_authorization_required(self):
        for key in ['authorized','automation_allowed']:
            with self.assertRaises(ValueError):
                app.mutate('/api/targets',{**self.target,key:False})
        with self.assertRaises(ValueError):
            app.mutate('/api/targets',{**self.target,'expires':int(time.time())+8*86400})

    def test_paused_expired_and_disabled_never_fetch(self):
        self.add()
        with patch('app.observe') as observe:
            app.tick()
            self.resume()
            app.mutate('/api/target-state',{'id':1,'enabled':False})
            app.tick()
            app.mutate('/api/target-state',{'id':1,'enabled':True})
            with app.db() as c:
                c.execute('UPDATE targets SET expires=0')
            app.tick()
            observe.assert_not_called()

    def test_stops_on_throttle_without_cors(self):
        self.target['cors']=True
        self.add();self.resume()
        with patch('app.observe',return_value={'status':429}) as observe:
            app.tick()
            self.assertEqual(observe.call_count,1)
        self.assertFalse(app.snapshot()['targets'][0]['enabled'])

    def test_dedup_feedback_and_persistence(self):
        self.add();self.resume()
        observation={'status':200,'headers':{},'cookies':[],'checked_at':int(time.time())}
        with patch('app.observe',return_value=observation) as observe:
            app.tick()
            first=app.snapshot()['findings']
            app.tick()
            self.assertEqual(observe.call_count,1)
            with app.db() as c:
                c.execute('UPDATE targets SET due=0')
            app.tick()
            self.assertEqual(len(app.snapshot()['findings']),len(first))
        key=first[0]['id']
        app.mutate('/api/feedback',{'id':key,'feedback':'accepted'})
        app.init()
        state=app.snapshot()
        self.assertFalse(state['paused'])
        self.assertGreater(state['findings'][0]['review_priority'],.5)

    def test_failure_backoff_and_disable(self):
        self.add();self.resume()
        with patch('app.observe',side_effect=TimeoutError):
            for _ in range(3):
                with app.db() as c:
                    c.execute('UPDATE targets SET due=0')
                app.tick()
        target=app.snapshot()['targets'][0]
        self.assertFalse(target['enabled'])
        self.assertEqual(target['failures'],3)
        self.assertGreater(target['due'],time.time())

    def test_http_auth_csrf_and_report(self):
        self.add();self.resume()
        with patch('app.observe',return_value={'status':200,'headers':{},'cookies':[]}):
            app.tick()
        server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        client=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
        auth={'Authorization':'Basic '+base64.b64encode(('admin:'+app.TOKEN).encode()).decode()}
        try:
            client.request('GET','/api/state');response=client.getresponse();response.read();self.assertEqual(response.status,401)
            client.request('GET','/api/state',headers=auth);response=client.getresponse();state=json.loads(response.read());self.assertEqual(response.status,200)
            client.request('POST','/api/pause',body='{"paused":true}',headers=auth);response=client.getresponse();response.read();self.assertEqual(response.status,403)
            client.request('POST','/api/pause',body='{"paused":true}',headers={**auth,'X-CSRF-Token':state['csrf']});response=client.getresponse();response.read();self.assertEqual(response.status,200)
            client.request('GET','/report/'+state['findings'][0]['id'],headers=auth);response=client.getresponse();report=response.read().decode();self.assertIn('DRAFT',report);self.assertIn('Not demonstrated',report)
            client.request('GET','/',headers=auth);response=client.getresponse();self.assertIn('ScopeGuard',response.read().decode())
        finally:
            client.close();server.shutdown();server.server_close();thread.join()


if __name__=='__main__':
    unittest.main()
