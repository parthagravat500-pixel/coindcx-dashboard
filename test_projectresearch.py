import json
import sqlite3
import unittest
import projectaudit as p

class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.c=sqlite3.connect(':memory:');self.c.row_factory=sqlite3.Row;p.init(self.c)
        self.files={'web.py':'def route():\n value=input()\n return eval(value)'}
    def tearDown(self):self.c.close()
    def current(self):return p.snapshot(self.c)[0]
    def note(self,disposition='false_positive',notes='This entry point is not reachable in this version.'):
        a=self.current();return {'project':a['name'],'finding':a['result']['findings'][0]['id'],'digest':a['digest'],'disposition':disposition,'notes':notes}
    def test_line_movement_preserves_lead_identity_and_reopens_stale_decision(self):
        p.record(self.c,'Test',self.files);a=self.current();fid=a['result']['findings'][0]['id']
        p.save_note(self.c,self.note());self.assertEqual(self.current()['result']['active_leads'],0)
        p.record(self.c,'Test',{'web.py':'\n\n'+self.files['web.py']})
        a=self.current();f=a['result']['findings'][0]
        self.assertEqual(f['id'],fid);self.assertEqual(f['change_status'],'Existing lead')
        self.assertEqual(a['result']['changes']['new_leads'],0)
        self.assertTrue(f['review_note']['stale']);self.assertFalse(f['set_aside'])
        self.assertEqual(a['result']['changes']['changed_files'],['web.py'])
    def test_real_new_path_and_no_longer_observed_never_confirm(self):
        p.record(self.c,'Test',{'safe.py':'def safe():\n return 1'})
        p.record(self.c,'Test',self.files);a=self.current()
        self.assertEqual(a['result']['changes']['new_leads'],1)
        self.assertEqual(a['result']['changes']['removed_files'],['safe.py'])
        self.assertEqual(a['result']['findings'][0]['change_status'],'New lead')
        p.record(self.c,'Test',{'web.py':'def route():\n return 1'})
        a=self.current();self.assertEqual(len(a['result']['changes']['no_longer_observed']),1)
        self.assertEqual(a['result']['confirmed_bugs'],0);self.assertFalse(a['result']['submission_ready'])
    def test_stale_or_forged_decisions_rejected(self):
        p.record(self.c,'Test',self.files);data=self.note()
        p.record(self.c,'Test',{'web.py':self.files['web.py']+'\n'})
        with self.assertRaises(ValueError):p.save_note(self.c,data)
        with self.assertRaises(ValueError):p.save_note(self.c,self.note(disposition='confirmed'))
        with self.assertRaises(ValueError):p.save_note(self.c,self.note(notes=''))
    def test_upgrade_makes_baseline_not_fake_new_leads(self):
        old=p.analyze(self.files);old['engine']='project-flow-1'
        self.c.execute('INSERT INTO project_audits VALUES(?,?,?,?)',('Test','old',1,json.dumps(old)))
        p.record(self.c,'Test',self.files);a=self.current()
        self.assertFalse(a['result']['changes']['has_baseline'])
        self.assertEqual(a['result']['findings'][0]['change_status'],'Baseline lead')
    def test_parameter_binding_negative_control_still_safe(self):
        r=p.analyze({'app.py':'def route():\n q=input()\n return db.execute("SELECT * FROM x WHERE id=?", (q,))'})
        self.assertEqual(r['total_findings'],0)
    def test_same_operation_grouping_is_not_verification(self):
        p.record(self.c,'Test',{'a.py':'def a():\n return eval(input())\ndef b():\n return eval(input())'})
        a=self.current();self.assertEqual(len(a['result']['findings']),2)
        for f in a['result']['findings']:
            self.assertEqual(f['related_leads'],1);self.assertFalse(f['confirmed'])
            self.assertIn('question',f['research'])
        raw=self.c.execute('SELECT result FROM project_audits').fetchone()[0]
        self.assertNotIn('return eval(input())',raw)

if __name__=='__main__':unittest.main()
