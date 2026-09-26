import base64
import http.client
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

import app
import leadwork
import projectaudit
from test_querycheck import QUOTED,NUMERIC


class LeadWorkflowTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        p=patch.object(app,'DATA',Path(tmp.name));p.start();self.addCleanup(p.stop)
        self.token='synthetic-lead-workflow-password-12345'
        p=patch.object(app,'TOKEN',self.token);p.start();self.addCleanup(p.stop)
        app.init()

    def state(self):
        with app.db() as c:return leadwork.snapshot(c)

    def sync(self):
        with app.db() as c:return leadwork.sync(c)

    def record(self,source=QUOTED):
        with app.db() as c:projectaudit.record(c,'Owned fixture',{'web.py':source})

    def test_source_followup_deduplicates_and_survives_restart(self):
        self.record();self.assertEqual(self.sync(),1)
        first=self.state();self.assertEqual(first['active_leads'],1)
        lead=first['leads'][0]
        self.assertEqual(lead['state'],'local_reproduction')
        self.assertFalse(lead['details']['confirmed_bounty'])
        self.assertIn('Local component test:',lead['details']['draft'])
        self.assertEqual(self.sync(),0);app.init();self.assertEqual(self.sync(),0)
        self.assertEqual(self.state()['changes'],first['changes'])
        self.assertEqual(len(self.state()['leads']),1)
        self.assertEqual(app.snapshot()['targets'],[])

    def test_guarded_suspicion_is_not_promoted_and_missing_lead_is_not_a_fix(self):
        self.record(NUMERIC.replace(' return db.execute',' if not value.isdigit():\n  return None\n return db.execute'))
        self.sync();self.assertEqual(self.state()['active_leads'],0)
        self.assertEqual(self.state()['leads'][0]['state'],'not_reproduced')
        self.record('def route():\n return 1');self.sync()
        lead=self.state()['leads'][0]
        self.assertEqual(lead['state'],'not_observed')
        self.assertIn('not a proven fix',lead['label'])
        self.assertFalse(lead['active'])

    def test_current_review_is_honored_but_code_change_reopens_evidence(self):
        self.record();self.sync()
        with app.db() as c:
            audit=projectaudit.snapshot(c)[0]
            projectaudit.save_note(c,{'project':'Owned fixture','finding':audit['result']['findings'][0]['id'],
                'digest':audit['digest'],'disposition':'out_of_scope','notes':'Owned synthetic fixture is not a bounty target.'})
        self.sync();self.assertEqual(self.state()['active_leads'],0)
        self.assertEqual(self.state()['leads'][0]['state'],'set_aside')
        self.record('\n'+QUOTED);self.sync()
        self.assertEqual(self.state()['active_leads'],1)
        self.assertEqual(len(self.state()['leads']),1)

    def test_fixed_receipt_has_no_source_private_values_or_drafts(self):
        self.record(QUOTED.replace('SELECT *','SELECT private_secret_canary, owner'));self.sync()
        with app.db() as c:receipt=leadwork.receipt(c,'a'*40)
        raw=json.dumps(receipt)
        for forbidden in ('Owned fixture','web.py','private_secret_canary',self.token,'query_sha256'):self.assertNotIn(forbidden,raw)
        self.assertEqual(receipt['counts'],{'local_reproduction':1})
        self.assertEqual(receipt['confirmed_bounty_bugs'],0)

    def test_authenticated_upload_to_worker_to_dashboard_uses_real_component(self):
        server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        headers={'Content-Type':'application/json','Authorization':'Basic '+base64.b64encode(('admin:'+self.token).encode()).decode(),'X-CSRF-Token':app.CSRF}
        def request(method,path,data=None,auth=True):
            conn=http.client.HTTPConnection('127.0.0.1',server.server_address[1]);conn.request(method,path,body=json.dumps(data) if data is not None else None,headers=headers if auth else {})
            r=conn.getresponse();body=r.read();status=r.status;conn.close();return status,json.loads(body) if body else None
        zipped=io.BytesIO()
        with zipfile.ZipFile(zipped,'w') as z:z.writestr('web.py',QUOTED)
        payload={'name':'Synthetic fixture','owned':True,'archive':base64.b64encode(zipped.getvalue()).decode()}
        self.assertEqual(request('POST','/api/project-audit',payload,False)[0],401)
        self.assertEqual(request('POST','/api/project-audit',payload)[0],200)
        # One actual worker iteration. External work and waiting are replaced;
        # the local source pipeline and lead index run their production functions.
        with patch.object(app.workqueue,'tick'),patch.object(app.WAKE,'wait',side_effect=StopIteration),patch('builtins.print'):
            with self.assertRaises(StopIteration):app.queue_worker()
        status,state=request('GET','/api/state');self.assertEqual(status,200)
        lead=next(l for l in state['lead_inbox']['leads'] if l['source']=='Uploaded/Synthetic fixture')
        self.assertEqual(lead['state'],'local_reproduction')
        self.assertEqual(state['lead_inbox']['active_leads'],1)
        self.assertFalse(state['lead_inbox']['automatic_submission'])
        self.assertEqual(state['workflow']['submissions'],[])
        self.assertEqual(state['targets'],[])
        self.assertTrue(state['paused'])
        self.assertNotIn('SELECT * FROM records',json.dumps(state['lead_inbox']))


if __name__=='__main__':unittest.main()
