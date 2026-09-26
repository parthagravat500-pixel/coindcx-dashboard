import json
import unittest
from unittest.mock import patch

import projectaudit
import querycheck


QUOTED = '''def route():
 value=input()
 return db.execute("SELECT * FROM records WHERE owner='"+value+"'")
'''
NUMERIC = '''def route():
 value=input()
 return db.execute("SELECT * FROM records WHERE owner="+value)
'''


class QueryCheckTests(unittest.TestCase):
    def review(self,files):
        findings=projectaudit.analyze(files)['findings']
        return list(querycheck.validate(files,findings).values())

    def test_reproduces_text_and_numeric_components_with_controls(self):
        double_quoted='def route():\n value=input()\n return db.execute(\'SELECT * FROM records WHERE owner="\'+value+\'"\')'
        for source in (QUOTED,NUMERIC,double_quoted):
            result=self.review({'web.py':source})[0]
            self.assertTrue(result['component_verified'])
            proof=result['evidence'][0]
            self.assertTrue(all(proof['checks'].values()))
            self.assertEqual(proof['baseline_rows'],1)
            self.assertEqual(proof['comparison_rows'],2)
            self.assertEqual(proof['repeat_rows'],2)
            self.assertFalse(result['application_verified'])
            self.assertFalse(result['runtime_verified'])
            self.assertFalse(result['submission_ready'])

    def test_parameterized_and_numeric_guard_controls_do_not_become_issues(self):
        safe='def route():\n value=input()\n return db.execute("SELECT * FROM records WHERE owner=?",(value,))'
        self.assertEqual(self.review({'web.py':safe}),[])
        guarded=NUMERIC.replace(' return db.execute',' if not value.isdigit():\n  return None\n return db.execute')
        result=self.review({'web.py':guarded})[0]
        self.assertEqual(result['status'],'not_reproduced')
        self.assertFalse(result['component_verified'])

    def test_cross_file_flow_with_real_sqlite_but_no_project_execution(self):
        files={'web.py':'import os\nos.system("MUST_NOT_RUN")\nfrom helper import query\ndef route():\n return query(input())',
               'helper.py':'def query(value):\n return cursor.execute("SELECT * FROM records WHERE owner="+value)'}
        with patch('os.system',side_effect=AssertionError('Never execute project code')),patch('socket.create_connection',side_effect=AssertionError('No network')):
            result=self.review(files)[0]
        self.assertTrue(result['component_verified'])
        self.assertNotIn('MUST_NOT_RUN',json.dumps(result))

    def test_unsupported_paths_schema_and_dialects_stay_unverified(self):
        for source in (QUOTED.replace(' value=input()',' value=input()\n unknown_framework_check(value)'),
                       NUMERIC.replace('SELECT * FROM records','SELECT * FROM records JOIN private ON records.id=private.id'),
                       NUMERIC.replace('SELECT * FROM records WHERE owner=','DELETE FROM records WHERE owner=')):
            result=self.review({'web.py':source})[0]
            self.assertEqual(result['status'],'unsupported')
            self.assertFalse(result['component_verified'])

    def test_sqlite_authorizer_rejects_file_writes_pragmas_and_functions(self):
        fixture=querycheck.Fixture('SELECT * FROM records WHERE owner=17')
        try:
            for query in ("ATTACH DATABASE '/tmp/forbidden.db' AS leaked",'PRAGMA database_list',
                          "SELECT load_extension('forbidden')",'DELETE FROM records','SELECT * FROM sqlite_master',
                          "SELECT * FROM records; DELETE FROM records",'SELECT randomblob(1000000000)'):
                with self.assertRaises(querycheck.Unsupported):fixture.read(query)
            self.assertEqual(len(fixture.read('SELECT * FROM records')),2)
        finally:fixture.close()

    def test_private_literals_and_generated_query_are_not_in_evidence(self):
        source=QUOTED.replace('SELECT *','SELECT private_secret_canary, owner')
        result=self.review({'web.py':source})[0]
        self.assertTrue(result['component_verified'])
        raw=json.dumps(result)
        for forbidden in ('private_secret_canary','scopeguard_owner',"OR 1=1",source):self.assertNotIn(forbidden,raw)

    def test_budget_is_explicit_and_never_promotes_untested_leads(self):
        files={'web.py':'\n'.join(NUMERIC.replace('route()',f'route{i}()') for i in range(15))}
        results=self.review(files)
        self.assertEqual(sum(r['component_verified'] for r in results),querycheck.MAX_LEADS)
        self.assertEqual(sum(r['status']=='limited' for r in results),3)
        self.assertTrue(all(r['attempts']==0 for r in results if r['status']=='limited'))


if __name__=='__main__':unittest.main()
