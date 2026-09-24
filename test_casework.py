import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import app
import casework


class CaseworkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        p = patch.object(app, 'DATA', Path(self.tmp.name)); p.start(); self.addCleanup(p.stop)
        app.init()
        app.mutate('/api/targets', {'name':'Fixture','url':'https://example.com/',
            'policy':'https://example.com/policy','rules':'Fixture permission for exact URL HEAD only.',
            'expires':int(time.time())+3600,'interval':3600,'authorized':True,'automation_allowed':True})
        with app.db() as c:
            for key,rule in [('cookie','cookie-test'),('cors','cors-reflection')]:
                c.execute('INSERT INTO findings(id,target,rule,title,evidence,severity,impact,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?)',
                    (key,1,rule,'Fixture',json.dumps({'note':'Fixture observation'}),'Informational','Unproven',int(time.time()),int(time.time())))

    def test_context_priority_and_user_feedback(self):
        s=app.snapshot();self.assertEqual(s['findings'][0]['id'],'cors')
        app.mutate('/api/feedback',{'id':'cors','feedback':'duplicate'})
        s=app.snapshot();self.assertEqual(s['findings'][0]['id'],'cookie')

    def test_notes_persist_but_never_validate_or_authorize(self):
        notes={key:'User assertion, not independently verified.' for key in casework.FIELDS}
        app.mutate('/api/evidence',{'finding':'cors','notes':notes})
        app.init()
        f=next(f for f in app.snapshot()['findings'] if f['id']=='cors')
        self.assertEqual(f['casework']['completed_sections'],8)
        self.assertEqual(f['casework']['notes'],notes)
        self.assertFalse(f['casework']['submission_ready'])
        self.assertFalse(f['supervisor']['submission_ready'])
        report=casework.report_section(f['casework'])
        self.assertIn('user-provided and unverified',report)
        self.assertIn(notes['impact'],report)

    def test_invalid_evidence_does_not_save(self):
        for data in [{'finding':'missing','notes':{}},{'finding':'cookie','notes':{'impact':55}},
                     {'finding':'cookie','notes':{'impact':'x'*1501}},
                     {'finding':'cookie','notes':{'submission_ready':True}}]:
            with self.assertRaises(ValueError):app.mutate('/api/evidence',data)
        with app.db() as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM case_notes').fetchone()[0],0)

    def test_no_requests_from_notes_and_expired_permission_block(self):
        app.mutate('/api/evidence',{'finding':'cookie','notes':{'actual':'https://127.0.0.1/private <script>alert(1)</script>'}})
        with app.db() as c:c.execute('UPDATE targets SET expires=0')
        with patch('urllib.request.urlopen') as request:
            f=next(f for f in app.snapshot()['findings'] if f['id']=='cookie');request.assert_not_called()
        self.assertTrue(any('expired' in b for b in f['casework']['blockers']))
        self.assertFalse(f['supervisor']['submission_ready'])
