import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import autoresearch
import pathcheck
import projectaudit
import sourceaudit


class AutomaticResearchTests(unittest.TestCase):
    def setUp(self):
        self.c = sqlite3.connect(':memory:')
        self.c.row_factory = sqlite3.Row
        self.c.execute('CREATE TABLE settings(paused INTEGER)')
        self.c.execute('INSERT INTO settings VALUES(0)')
        projectaudit.init(self.c)
        sourceaudit.init(self.c)
        autoresearch.init(self.c)

    def tearDown(self):
        self.c.close()

    def review(self, files):
        projectaudit.record(self.c, 'Owned fixture', files)
        return projectaudit.snapshot(self.c)[0]['result']

    def test_cross_file_path_automatically_gets_experiments_and_draft(self):
        files = {
            'web.py': 'from flask import request\nfrom helper import query\ndef route():\n return query(request.args.get("q"))',
            'helper.py': 'def query(value):\n return db.execute("SELECT * FROM items WHERE name="+value)'
        }
        result = self.review(files)
        f = result['findings'][0]
        self.assertEqual(f['automatic_validation']['status'], 'modeled_flow')
        self.assertEqual(f['automatic_validation']['experiments'], 2)
        self.assertEqual({x['file'] for x in f['automatic_validation']['evidence'][0]['route']}, {'web.py','helper.py'})
        self.assertIn('not submission-ready', f['investigation_draft'])
        self.assertIn('helper.py:2', f['investigation_draft'])
        self.assertEqual(result['confirmed_bugs'], 0)
        self.assertFalse(result['submission_ready'])
        self.assertFalse(f['automatic_validation']['runtime_verified'])

    def test_inert_model_never_executes_imports_sinks_or_project_statements(self):
        source = 'import os\nraise RuntimeError("module must never run")\ndef route():\n value=input()\n return os.system(value)'
        with patch('os.system', side_effect=AssertionError('Must not execute')), patch('socket.create_connection', side_effect=AssertionError('No network')):
            result = self.review({'web.py':source})
        self.assertEqual(result['findings'][0]['automatic_validation']['status'], 'modeled_flow')
        # Unknown calls before a sink are not ignored or invoked.
        result = self.review({'web.py':'def route():\n send_secret()\n return eval(input())'})
        self.assertEqual(result['findings'][0]['automatic_validation']['status'], 'unsupported')

    def test_guarded_overapproximation_stays_unresolved(self):
        source = 'def route():\n value=input()\n if value == "fixed":\n  value="1"\n else:\n  return None\n return eval(value)'
        result = self.review({'web.py':source})
        f = result['findings'][0]
        self.assertEqual(f['automatic_validation']['status'], 'not_reproduced')
        self.assertIn('safety is unresolved', f['automatic_validation']['reason'])
        self.assertFalse(f['set_aside'])
        self.assertIsNone(f['review_note'])

    def test_numeric_guard_requires_numeric_probes_but_proves_no_injection(self):
        source = 'def route():\n value=input()\n if not value.isdigit():\n  return None\n return db.execute("SELECT * FROM items WHERE id="+value)'
        f = self.review({'web.py':source})['findings'][0]
        self.assertEqual(f['automatic_validation']['status'], 'modeled_flow')
        self.assertEqual(f['automatic_validation']['experiments'], 4)
        self.assertEqual(f['automatic_validation']['evidence'][0]['probe_family'], 'integer')
        self.assertFalse(f['confirmed'])

    def test_values_and_source_are_not_saved(self):
        source = 'def route():\n value=input()\n return db.execute("PRIVATE_LITERAL_DO_NOT_SAVE"+value)'
        result = self.review({'web.py':source})
        raw = json.dumps(result)
        self.assertNotIn('PRIVATE_LITERAL_DO_NOT_SAVE', raw)
        self.assertNotIn('scopeguard_alpha', raw)
        self.assertNotIn(source, raw)

    def test_parameter_binding_has_no_invented_lead_or_draft(self):
        result = self.review({'web.py':'def route():\n value=input()\n return db.execute("SELECT * FROM items WHERE name=?",(value,))'})
        self.assertEqual(result['automatic_validation']['experiments'], 0)
        self.assertEqual(result['automatic_validation']['drafts'], 0)
        self.assertEqual(result['findings'], [])

    def test_limits_and_unsupported_features_fail_closed(self):
        for source in (
            'def route():\n value=input()\n while value:\n  value=value\n return eval(value)',
            'def route():\n value=input()\n value=__import__(value)\n return eval(value)',
            'def route():\n value=input()\n value=value*1000000000\n return eval(value)',
            'def route():\n value=input()\n value.encode()\n return eval(value)',
        ):
            f = self.review({'web.py':source})['findings'][0]
            self.assertEqual(f['automatic_validation']['status'], 'unsupported')
        source = '\n'.join('def route'+str(i)+'():\n return eval(input())' for i in range(25))
        r = self.review({'web.py':source})
        self.assertEqual(r['automatic_validation']['leads_processed'], 20)
        self.assertEqual(sum(f['automatic_validation']['status']=='limited' for f in r['findings']), 5)

    def test_calls_on_same_line_are_not_confused(self):
        source = 'def route():\n value=input()\n first=eval("1"); second=eval(value)'
        f = self.review({'web.py':source})['findings'][0]
        # The first real eval is unsupported, so execution does not skip it to
        # falsely claim the second operation was reached.
        self.assertEqual(f['automatic_validation']['status'], 'unsupported')

    def test_worker_pause_restart_change_and_dedup_without_network(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(sourceaudit, 'FILES', ('web.py',)), patch('socket.create_connection', side_effect=AssertionError('No network')):
            root = Path(directory)
            (root/'web.py').write_text('def route():\n return eval(input())')
            log = lambda c, message: None
            self.c.execute('UPDATE settings SET paused=1')
            autoresearch.tick(self.c, root, log)
            self.assertEqual(autoresearch.snapshot(self.c)['state'], 'paused')
            self.assertEqual(self.c.execute('SELECT COUNT(*) FROM project_audits').fetchone()[0], 0)
            self.c.execute('UPDATE settings SET paused=0')
            autoresearch.tick(self.c, root, log)
            first = autoresearch.snapshot(self.c)
            self.assertEqual(first['completed'], 1)
            self.assertEqual(first['projects'][0]['drafts'], 1)
            autoresearch.init(self.c)
            self.c.execute('UPDATE automatic_research_status SET due=0')
            autoresearch.tick(self.c, root, log)
            self.assertEqual(autoresearch.snapshot(self.c)['completed'], 1)
            (root/'web.py').write_text('def route():\n return 1')
            self.c.execute('UPDATE automatic_research_status SET due=0')
            autoresearch.tick(self.c, root, log)
            s = autoresearch.snapshot(self.c)
            self.assertEqual(s['completed'], 2)
            self.assertEqual(s['projects'][0]['drafts'], 0)
            self.assertEqual(s['external_tests'], 0)
            self.assertEqual(s['confirmed_bugs'], 0)

    def test_failed_stage_rolls_back_evidence_and_retries_with_backoff(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(sourceaudit, 'FILES', ('web.py',)):
            root = Path(directory)
            (root/'web.py').write_text('def route():\n return 1')
            log = lambda c, message: None
            autoresearch.tick(self.c, root, log)
            old = self.c.execute('SELECT result FROM project_audits').fetchone()[0]
            (root/'web.py').write_text('def route():\n return eval(input())')
            self.c.execute('UPDATE automatic_research_status SET due=0')
            with patch.object(sourceaudit, 'installed', side_effect=ValueError('PRIVATE_ERROR')):
                autoresearch.tick(self.c, root, log)
            s = autoresearch.snapshot(self.c)
            self.assertEqual(s['state'], 'error')
            self.assertEqual(s['completed'], 1)
            self.assertEqual(s['failure_count'], 1)
            self.assertEqual(self.c.execute('SELECT result FROM project_audits').fetchone()[0], old)
            self.assertNotIn('PRIVATE_ERROR', json.dumps(s))
            autoresearch.tick(self.c, root, log)
            self.assertEqual(autoresearch.snapshot(self.c)['failure_count'], 1)
            self.c.execute('UPDATE automatic_research_status SET due=0')
            autoresearch.tick(self.c, root, log)
            self.assertEqual(autoresearch.snapshot(self.c)['failure_count'], 0)

    def test_missing_source_cannot_produce_partial_success(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(sourceaudit, 'FILES', ('missing.py',)):
            autoresearch.tick(self.c, Path(directory), lambda c,m: None)
        s = autoresearch.snapshot(self.c)
        self.assertEqual(s['state'], 'error')
        self.assertEqual(s['completed'], 0)
        self.c.execute('UPDATE automatic_research_status SET heartbeat=1')
        self.assertEqual(autoresearch.snapshot(self.c)['state'], 'unavailable')


if __name__ == '__main__':
    unittest.main()
