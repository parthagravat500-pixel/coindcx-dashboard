import base64
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock,patch

import app
import programapi
import reporting


class ProgramAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.old=app.DATA;self.old_token=app.TOKEN
        app.DATA=Path(self.tmp.name);app.TOKEN='synthetic-dashboard-password-1234';app.init()
    def tearDown(self):app.DATA=self.old;app.TOKEN=self.old_token;self.tmp.cleanup()

    def test_routes_are_read_only_and_cannot_exfiltrate_credentials(self):
        for route in ('https://evil.example/path','//evil.example/path','/v1/hackers/reports',
                      '/v1/hackers/programs/example/../reports','/v1/hackers/programs/example?token=secret',
                      '/v1/hackers/programs/example?page[number]=2&page[number]=3',
                      '/v1/hackers/programs/example#fragment'):
            self.assertFalse(programapi.valid_route('hackerone',route))
        self.assertTrue(programapi.valid_route('hackerone','/v1/hackers/programs/example/structured_scopes?page%5Bnumber%5D=2&page%5Bsize%5D=100'))
        self.assertFalse(programapi.canonical('https://hackerone.com.evil.example/example'))
        self.assertFalse(programapi.canonical('https://user@hackerone.com/example'))

    def test_transport_pins_host_uses_only_get_and_stops_at_redirect(self):
        conn=MagicMock();conn.getresponse.return_value.status=302;conn.getresponse.return_value.getheader.return_value=''
        with patch('programapi.public_addresses',return_value=['93.184.216.34']),patch('programapi.socket.create_connection') as dial,patch('programapi.ssl.create_default_context'),patch('programapi.http.client.HTTPSConnection',return_value=conn):
            with self.assertRaises(programapi.APIError) as error:programapi.request('hackerone',{'username':'fixture','token':'secret'},'/v1/hackers/programs/example')
        self.assertEqual(error.exception.code,302);self.assertEqual(conn.request.call_count,1)
        self.assertEqual(conn.request.call_args.args,('GET','/v1/hackers/programs/example'))
        dial.assert_called_once_with(('93.184.216.34',443),timeout=20)
        self.assertNotIn('secret',str(error.exception))
        self.assertEqual(programapi.retry_after('Sat, 26 Sep 2026 12:00:00 GMT',1790420400),3601)

    def test_connection_is_read_only_private_and_never_enables_report_delivery(self):
        with patch('programapi.request',return_value={'data':[]}) as request:
            with self.assertRaises(ValueError):programapi.connect(app.DATA,{'provider':'hackerone','username':'fixture','token':'synthetic-token'})
            request.assert_not_called()
            programapi.connect(app.DATA,{'provider':'hackerone','username':'fixture','token':'synthetic-token','authorize_read':True})
        self.assertEqual((app.DATA/'program-api-connections.json').stat().st_mode&0o777,0o600)
        self.assertIsNone(reporting.load(app.DATA))
        self.assertNotIn('synthetic-token',json.dumps(app.snapshot()))
        self.assertFalse(app.snapshot()['reporting']['connected'])

    def test_existing_connection_reused_but_explicit_disconnect_stays_disconnected(self):
        reporting.save(app.DATA,{'enabled':True,'username':'fixture','token':'synthetic-token'})
        self.assertTrue(programapi.status(app.DATA)['hackerone']['uses_existing_connection'])
        app.mutate('/api/program-api/disconnect',{'provider':'hackerone'});app.init()
        self.assertIsNone(programapi.credentials(app.DATA,'hackerone'));self.assertIsNotNone(reporting.load(app.DATA))

    def test_failed_connection_does_not_replace_saved_credentials_or_leak_error(self):
        saved={'enabled':True,'username':'fixture','token':'old-synthetic-token'};programapi.save(app.DATA,'hackerone',saved)
        with patch('programapi.request',side_effect=ValueError('SENSITIVE-FIXTURE')):
            with self.assertRaises(ValueError) as e:programapi.connect(app.DATA,{'provider':'hackerone','username':'fixture','token':'replacement-fixture','authorize_read':True})
        self.assertNotIn('SENSITIVE',str(e.exception));self.assertEqual(programapi.credentials(app.DATA,'hackerone'),saved)

    def test_real_http_auth_and_csrf_protect_connection_and_evidence(self):
        server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            auth='Basic '+base64.b64encode(('admin:'+app.TOKEN).encode()).decode()
            def call(method,path,headers):
                c=http.client.HTTPConnection('127.0.0.1',server.server_address[1],timeout=3)
                try:
                    c.request(method,path,body='{}' if method=='POST' else None,headers=headers);r=c.getresponse();r.read();return r.status
                finally:c.close()
            self.assertEqual(call('GET','/api/program-research?id='+'a'*24,{}),401)
            self.assertEqual(call('POST','/api/program-api/connect',{}),401)
            self.assertEqual(call('POST','/api/program-api/connect',{'Authorization':auth,'Content-Type':'application/json'}),403)
            self.assertEqual(call('GET','/api/program-research?id='+'a'*24,{'Authorization':auth}),404)
        finally:server.shutdown();server.server_close()


if __name__=='__main__':unittest.main()
