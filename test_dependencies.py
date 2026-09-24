import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import app
import dependencies as d
import sourceaudit

class DeeperTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        p=patch.object(app,'DATA',Path(self.tmp.name));p.start();self.addCleanup(p.stop);app.init()
    def upload(self):
        app.mutate('/api/dependencies',{'project':'Test','filename':'requirements.txt','source':'Django==2.2.0\nrequests>=2','owned':True,'share_packages':True})
    def test_inventory_and_no_unpinned_guess(self):
        p,skipped=d.inventory('requirements.txt','Django==2.2.0\nfoo>=1\n-r other.txt\nhttps://private.invalid/token\n')
        self.assertEqual(p,[{'ecosystem':'PyPI','name':'django','version':'2.2.0'}]);self.assertEqual(skipped,3)
        p,skipped=d.inventory('package-lock.json',json.dumps({'lockfileVersion':3,'packages':{'':{},'node_modules/lodash':{'version':'4.17.20'},'node_modules/a/node_modules/lodash':{'version':'4.17.20'},'node_modules/private':{'version':'file:../private'}}}))
        self.assertEqual(len(p),1);self.assertEqual(skipped,1)
    def test_consent_and_input_bounds(self):
        with self.assertRaises(ValueError):app.mutate('/api/dependencies',{'owned':True})
        for name,text in [('package.json','{}'),('requirements.txt','a'*500001),('package-lock.json','[]')]:
            with self.assertRaises(ValueError):d.inventory(name,text)
    def test_pause_persist_daily_schedule_and_failed_results(self):
        self.upload()
        with patch.object(d,'query',return_value=[{'name':'django','version':'2.2.0','ecosystem':'PyPI','advisories':['TEST-1'],'confirmed_exploitable':False}]) as query:
            d.tick(app.db,app.log);query.assert_not_called()
            app.mutate('/api/all-pause',{'paused':False});d.tick(app.db,app.log);query.assert_called_once()
            app.init();d.tick(app.db,app.log);query.assert_called_once()
        p=app.snapshot()['dependency_projects'][0];self.assertEqual(p['package_count'],1);self.assertEqual(p['skipped'],1);self.assertGreater(p['due'],p['checked']+86000)
        with app.db() as c:c.execute('UPDATE dependency_projects SET due=0')
        with patch.object(d,'query',side_effect=TimeoutError):d.tick(app.db,app.log)
        p=app.snapshot()['dependency_projects'][0];self.assertEqual(len(p['result']),1);self.assertIn('failed',p['status'])
        app.mutate('/api/dependencies/delete',{'project':'Test'});self.assertEqual(app.snapshot()['dependency_projects'],[])
    def test_input_trace_and_bound_parameters(self):
        result=sourceaudit.analyze('''def route():
    user = request.args.get("id")
    query = "SELECT * FROM t WHERE id=" + user
    cursor.execute(query)
    cursor.execute("SELECT * FROM t WHERE id=?", (user,))
''')
        flow=[f for f in result['findings'] if f.get('trace_lines')]
        self.assertEqual(len(flow),1);self.assertEqual(flow[0]['trace_lines'],[2,3,4]);self.assertFalse(flow[0]['confirmed'])
    def test_trace_overwrite_and_function_isolation(self):
        result=sourceaudit.analyze('''def first():
    value = input()
    value = "fixed"
    eval(value)
def second():
    eval(value)
''')
        self.assertFalse(any(f.get('trace_lines') for f in result['findings']))
    def test_paginated_response_not_treated_as_clean(self):
        class Reply:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return b'{"results":[{"next_page_token":"more"}]}'
        with patch('urllib.request.OpenerDirector.open',return_value=Reply()):
            with self.assertRaises(ValueError):d.query([{'name':'a','ecosystem':'PyPI','version':'1'}])
