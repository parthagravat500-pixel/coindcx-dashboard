import json
import sqlite3
import unittest
from unittest.mock import patch

import autoresearch
import pathcheck
import projectaudit
import querycheck


CLASS_SQL='''class Search:
 def route(self):
  return self.lookup(input())
 def lookup(self,value):
  return db.execute("SELECT * FROM records WHERE owner="+value)
'''


class MethodResearchTests(unittest.TestCase):
    def review(self,files):
        result=projectaudit.analyze(files)
        return result,pathcheck.validate(files,result['findings']),querycheck.validate(files,result['findings'])

    def test_instance_method_path_gets_real_local_sqlite_controls(self):
        r,models,components=self.review({'web.py':CLASS_SQL})
        self.assertEqual(r['methods_analyzed'],2);self.assertEqual(r['total_findings'],1)
        finding=r['findings'][0];self.assertIn('web.Search.route',finding['entrypoints'])
        self.assertEqual(models[finding['id']]['status'],'modeled_flow')
        proof=components[finding['id']]
        self.assertTrue(proof['component_verified']);self.assertTrue(all(proof['evidence'][0]['checks'].values()))
        self.assertFalse(proof['application_verified']);self.assertFalse(finding['submission_ready'])

    def test_bound_sql_and_numeric_validation_are_negative_controls(self):
        safe=CLASS_SQL.replace('"SELECT * FROM records WHERE owner="+value','"SELECT * FROM records WHERE owner=?",(value,)')
        self.assertEqual(self.review({'web.py':safe})[0]['total_findings'],0)
        guarded=CLASS_SQL.replace('  return db.execute','  if not value.isdigit():\n   return None\n  return db.execute')
        result=self.review({'web.py':guarded})[2]
        self.assertEqual(next(iter(result.values()))['status'],'not_reproduced')

    def test_methods_follow_cross_file_return_alias_keyword_and_flask_source(self):
        files={'web.py':'from flask import request as rq\nfrom helper import text\nclass Search:\n def route(self):\n  return self.query(value=text(rq.args.get("q")))\n def query(self,value):\n  return db.execute("SELECT * FROM records WHERE owner="+value)',
               'helper.py':'def text(value):\n return value'}
        r,models,components=self.review(files)
        self.assertEqual(r['total_findings'],1)
        self.assertEqual({step['file'] for step in r['findings'][0]['trace']},{'web.py','helper.py'})
        self.assertTrue(next(iter(components.values()))['component_verified'])

    def test_static_methods_work_without_constructing_any_object(self):
        source=CLASS_SQL.replace(' def lookup(self,value):',' @staticmethod\n def lookup(value):')
        self.assertTrue(next(iter(self.review({'web.py':source})[2].values()))['component_verified'])
        source='class Static:\n @staticmethod\n def route():\n  return db.execute("SELECT * FROM records WHERE owner="+input())'
        self.assertTrue(next(iter(self.review({'web.py':source})[2].values()))['component_verified'])

    def test_runtime_class_features_stay_unresolved(self):
        variants=[CLASS_SQL.replace('class Search:','class Search(Base):'),
                  CLASS_SQL.replace('class Search:','class Search(metaclass=Factory):'),
                  '@framework\n'+CLASS_SQL,
                  CLASS_SQL.replace('class Search:','class Search:\n def __init__(self):\n  configure(self)'),
                  CLASS_SQL.replace('class Search:','class Search:\n def __getattribute__(self,name):\n  return dynamic(name)'),
                  CLASS_SQL.replace(' def lookup(self,value):',' @decorator\n def lookup(self,value):'),
                  CLASS_SQL.replace('  return self.lookup(input())','  self.private_state=1\n  return self.lookup(input())')]
        for source in variants:
            with self.subTest(source=source):
                r,models,components=self.review({'web.py':source});self.assertGreater(r['total_findings'],0)
                self.assertTrue(all(not x['component_verified'] for x in components.values()))
                self.assertTrue(all(x['status']=='unsupported' for x in models.values()))

    def test_receiver_reassignment_and_unknown_dispatch_are_not_guessed(self):
        for source in (CLASS_SQL.replace('  return self.lookup(input())','  self=unknown()\n  return self.lookup(input())'),
                       CLASS_SQL.replace('self.lookup(input())','getattr(self,"lookup")(input())'),
                       CLASS_SQL.replace('self.lookup(input())','other.lookup(input())')):
            self.assertEqual(self.review({'web.py':source})[0]['total_findings'],0)

    def test_untrusted_module_and_class_initialization_never_runs_or_leaks(self):
        source='import os\nos.system("SECRET_DO_NOT_RUN")\n'+CLASS_SQL
        with patch('os.system',side_effect=AssertionError('Project code must not run')),patch('socket.create_connection',side_effect=AssertionError('No network')):
            result=self.review({'web.py':source})
        self.assertTrue(next(iter(result[2].values()))['component_verified'])
        self.assertNotIn('SECRET_DO_NOT_RUN',json.dumps(result))
        rebound='staticmethod=unknown\n'+CLASS_SQL.replace(' def lookup(self,value):',' @staticmethod\n def lookup(value):')
        self.assertFalse(any(x['component_verified'] for x in self.review({'web.py':rebound})[2].values()))

    def test_recursive_method_calls_are_bounded(self):
        source='class Loop:\n def start(self):\n  return self.again(input())\n def again(self,value):\n  return self.again(value)'
        self.assertTrue(projectaudit.analyze({'web.py':source})['bounded_or_truncated'])

    def test_large_early_function_cannot_starve_later_class_detection(self):
        files={'a.py':'def large():\n'+''.join(' value='+str(i)+'\n' for i in range(300)),
               'z.py':CLASS_SQL}
        with patch.object(projectaudit,'MAX_VISITS',90):result=projectaudit.analyze(files)
        self.assertGreater(result['work_limited_entries'],0)
        self.assertEqual(result['entrypoints_analyzed'],3);self.assertEqual(result['methods_analyzed'],2)
        self.assertEqual(result['total_findings'],1);self.assertEqual(result['findings'][0]['file'],'z.py')
        self.assertLessEqual(result['analysis_visits'],90);self.assertTrue(result['bounded_or_truncated'])

    def test_saved_results_and_aggregate_health_expose_coverage_without_source(self):
        c=sqlite3.connect(':memory:');c.row_factory=sqlite3.Row
        try:
            c.execute('CREATE TABLE settings(paused INTEGER)');c.execute('INSERT INTO settings VALUES(0)')
            projectaudit.init(c);autoresearch.init(c)
            source=CLASS_SQL.replace(' def route(self):',' def route(self):\n  secret="PRIVATE_LITERAL_CANARY"')
            self.assertTrue(projectaudit.record(c,'ScopeGuard',{'web.py':source}))
            self.assertFalse(projectaudit.record(c,'ScopeGuard',{'web.py':source}))
            receipt=autoresearch.receipt(c,'a'*40)
            self.assertEqual(receipt['owned_methods'],2);self.assertEqual(receipt['owned_component_reproductions'],1)
            self.assertTrue(receipt['owned_engine_current'])
            self.assertEqual(receipt['confirmed_bounty_bugs'],0)
            for value in (receipt,projectaudit.snapshot(c)):
                self.assertNotIn('PRIVATE_LITERAL_CANARY',json.dumps(value))
            self.assertNotIn('web.py',json.dumps(receipt))
            old=json.loads(c.execute("SELECT result FROM project_audits WHERE name='ScopeGuard'").fetchone()[0]);old['engine']='older-engine'
            c.execute("UPDATE project_audits SET result=? WHERE name='ScopeGuard'",(json.dumps(old),))
            self.assertFalse(autoresearch.receipt(c,'a'*40)['owned_engine_current'])
        finally:c.close()


if __name__=='__main__':unittest.main()
