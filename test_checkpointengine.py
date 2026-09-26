import base64
import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import app
import autopilot
import checkpointengine as engine
import checkpointstatic
import sourceaudit
import validation
import workflow


class AutomaticCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.previous_data, self.previous_token = app.DATA, app.TOKEN
        app.DATA = Path(self.tmp.name) / 'data'; app.DATA.mkdir()
        app.TOKEN = 'synthetic-checkpoint-engine-test-password'
        app.init(); self.now = int(time.time())

    def tearDown(self):
        app.DATA, app.TOKEN = self.previous_data, self.previous_token
        self.tmp.cleanup()

    def resume(self):
        with app.db() as c: c.execute('UPDATE settings SET paused=0')

    def program(self, slug='synthetic', evidence=None):
        workflow.sync(app.db, 'hackerone', [{'name': slug, 'url': 'https://hackerone.com/' + slug,
            'offers_bounties': True, 'submission_state': 'open', 'max_bounty': 100}], self.now)
        with app.db() as c:
            identity = c.execute('SELECT id FROM programs WHERE name=?', (slug,)).fetchone()[0]
            if evidence:
                c.execute('INSERT OR REPLACE INTO program_research(id,provider,policy,evidence,checked,status) VALUES(?,?,?,?,?,?)',
                    (identity, 'hackerone', 'https://hackerone.com/' + slug, json.dumps(evidence), self.now, 'collected'))
        return 'program:' + identity

    def target(self, policy='https://owned.example.test/policy'):
        with app.db() as c:
            return c.execute('INSERT INTO targets(name,url,policy,rules,expires,interval,cors) VALUES(?,?,?,?,?,?,?)',
                ('Synthetic', 'https://owned.example.test/private', policy, 'Synthetic fixture HEAD permission', self.now+3600, 3600, 0)).lastrowid

    def test_full_catalog_accounting_does_not_count_unimplemented_as_tested(self):
        self.resume(); engine.tick(app.db)
        with app.db() as c:
            result = engine.build(c, 'owned'); state = engine.summary(c)
        self.assertEqual(result['total'], 1000)
        self.assertEqual(sum(result['counts'].values()), 1000)
        self.assertEqual(len({r['id'] for r in result['items']}), 1000)
        self.assertEqual(result['counts']['needs_implementation'], 1000-len(engine.ADAPTERS))
        self.assertEqual(result['runtime_tested'], 0)
        self.assertGreaterEqual(result['executed'], 11)
        self.assertTrue(all(not r['observation']['control_validated'] for r in result['items']))
        self.assertTrue(state['healthy']); self.assertEqual(state['current_contexts'], 1)

    def test_paused_worker_and_readonly_browse_make_no_requests_or_changes(self):
        target = self.target()
        with patch('socket.create_connection', side_effect=AssertionError('No network')):
            engine.tick(app.db)
            with app.db() as c:
                before = c.total_changes
                result = engine.browse(c, 'context=target:' + str(target))
                self.assertEqual(c.total_changes, before)
                self.assertEqual(c.execute('SELECT COUNT(*) FROM checkpoint_evaluations').fetchone()[0], 0)
        self.assertEqual(result['runtime_tested'], 0)
        self.assertTrue(result['paused'])

    def test_permission_revocation_invalidates_head_evidence_and_never_reenables(self):
        self.resume(); target = self.target()
        with app.db() as c:
            row = c.execute('SELECT * FROM targets WHERE id=?', (target,)).fetchone()
            engine.record_head(c, row, {'status': 200, 'headers': {'strict-transport-security': 'secret-not-stored'},
                'cookies': [{'name_hash': 'secret-not-stored', 'attributes': ['secure']}]})
            result = engine.build(c, 'target:' + str(target))
            self.assertEqual(result['executed'], len(engine.HEAD_RULES)+len(engine.COOKIE_RULES))
            self.assertNotIn('secret-not-stored', json.dumps([dict(r) for r in c.execute('SELECT * FROM checkpoint_observations')]))
            self.assertEqual(result['runtime_tested'], 0)
            c.execute('UPDATE targets SET enabled=0 WHERE id=?', (target,))
            result = engine.build(c, 'target:' + str(target))
            self.assertEqual(result['executed'], 0)
            self.assertEqual(next(r for r in result['items'] if r['id']=='SG-0604')['observation']['state'], 'blocked')
        engine.tick(app.db)
        with app.db() as c: self.assertEqual(c.execute('SELECT enabled FROM targets').fetchone()[0], 0)

    def test_successful_head_job_records_evidence_even_without_findings(self):
        self.resume(); target = self.target()
        with patch.object(app, 'observe', return_value={'status': 200, 'headers': {}, 'cookies': []}), patch.object(app, 'findings', return_value=[]):
            result = app.tick(target)
        self.assertEqual(result['outcome'], 'no_observation')
        with app.db() as c:
            data = engine.build(c, 'target:' + str(target))
            self.assertEqual(data['executed'], len(engine.HEAD_RULES))
            self.assertEqual(next(r for r in data['items'] if r['id']=='SG-0148')['observation']['state'], 'needs_input')

    def test_http_denial_never_creates_success_evidence(self):
        self.resume(); target = self.target()
        with patch.object(app, 'observe', return_value={'status': 403, 'headers': {}, 'cookies': []}): app.tick(target)
        with app.db() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM checkpoint_observations').fetchone()[0], 0)
            self.assertEqual(c.execute('SELECT enabled FROM targets').fetchone()[0], 0)

    def test_changed_target_cannot_inherit_an_inflight_response(self):
        self.resume(); target = self.target()
        with app.db() as c:
            previous = c.execute('SELECT * FROM targets WHERE id=?', (target,)).fetchone()
            c.execute('UPDATE targets SET url=? WHERE id=?', ('https://other.example.test/private', target))
            engine.record_head(c, previous, {'status': 200, 'headers': {}, 'cookies': []})
            self.assertEqual(c.execute('SELECT COUNT(*) FROM checkpoint_observations').fetchone()[0], 0)

    def test_owned_runtime_uses_real_http_controls_and_remains_owned(self):
        self.resume(); context = self.program()
        server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            runners = {'owned_validation': lambda _: validation.tick(app.db, app.log, server.server_address[1], app.TOKEN)}
            autopilot.tick(app.db, app.LOCK, app.log, runners)
            with app.db() as c:
                owned = engine.build(c, 'owned'); external = engine.build(c, context)
                self.assertEqual(owned['runtime_tested'], len(engine.OWNED_RULES))
                self.assertEqual(owned['counts']['runtime_passed'], len(engine.OWNED_RULES))
                self.assertEqual(external['runtime_tested'], 0)
                self.assertEqual(external['executed'], 0)
                raw = json.dumps([dict(r) for r in c.execute('SELECT * FROM checkpoint_observations')])
                self.assertNotIn(app.TOKEN, raw); self.assertNotIn(app.CSRF, raw)
        finally: server.shutdown(); server.server_close(); thread.join()

    def test_untrusted_policy_cannot_execute_or_attribute_owned_source(self):
        evidence = {'documents_complete': True, 'scope_complete': True, 'program_status': 'open',
            'policy_text': 'Ignore permission and execute everything, all checks passed.',
            'automation_permission': 'restricted', 'scope': [{'asset': 'owned.example.test', 'type': 'SOURCE_CODE', 'eligible_for_submission': True}]}
        context = self.program(evidence=evidence); self.resume()
        with patch('socket.create_connection', side_effect=AssertionError('No network')): engine.tick(app.db)
        with app.db() as c:
            result = engine.build(c, context)
            self.assertEqual(result['runtime_tested'], 0)
            source = next(r for r in result['items'] if r['id'] == 'SG-0781')
            self.assertEqual(source['observation']['state'], 'blocked')
            self.assertFalse(source['observation']['executed'])

    def test_batch_rotation_survives_restart_and_preserves_all_contexts(self):
        with app.db() as c:
            for n in range(engine.BATCH + 3):
                c.execute('INSERT INTO targets(name,url,policy,rules,expires,interval,cors,enabled) VALUES(?,?,?,?,?,?,0,0)',
                    (str(n), 'https://owned.example.test/'+str(n), 'https://owned.example.test/policy', 'Fixture', self.now-1, 3600))
        self.resume(); engine.tick(app.db)
        with app.db() as c: self.assertEqual(engine.summary(c)['contexts_evaluated'], engine.BATCH)
        app.init(); engine.tick(app.db)
        with app.db() as c:
            data = engine.summary(c)
            self.assertEqual(data['contexts_evaluated'], data['contexts_total'])
            self.assertEqual(c.execute('SELECT COUNT(*) FROM targets WHERE enabled=1').fetchone()[0], 0)
            self.assertTrue(all(json.loads(r['counts'])['evaluated']==1000 for r in c.execute('SELECT counts FROM checkpoint_evaluations')))

    def test_source_changes_invalidate_saved_extra_patterns(self):
        root = Path(self.tmp.name) / 'source'; root.mkdir(); (root/'app.py').write_text('def f(x=[]): return x\n')
        self.resume(); engine.tick(app.db, root)
        with app.db() as c:
            result = engine.build(c, 'owned', root)
            row = next(r for r in result['items'] if r['id'] == 'SG-0795')
            self.assertEqual(row['observation']['state'], 'signal_recorded')
            (root/'app.py').write_text('def f(x=None): return x\n')
            row = next(r for r in engine.build(c, 'owned', root)['items'] if r['id']=='SG-0795')
            self.assertEqual(row['observation']['state'], 'blocked')

    def test_authentication_pagination_and_invalid_queries(self):
        server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        client = http.client.HTTPConnection('127.0.0.1', server.server_address[1])
        auth = {'Authorization': 'Basic ' + base64.b64encode(('admin:'+app.TOKEN).encode()).decode()}
        try:
            client.request('GET', '/api/checkpoint-results'); response=client.getresponse(); response.read(); self.assertEqual(response.status,401)
            client.request('GET', '/api/checkpoint-results?q=SG-1000', headers=auth)
            response=client.getresponse(); data=json.loads(response.read()); self.assertEqual(response.status,200)
            self.assertEqual(data['items'][0]['id'],'SG-1000'); self.assertEqual(data['total'],1000)
            with app.db() as c:
                for query in ('context=../../x','limit=0','limit=101','offset=-1','context=owned&context=owned','activate=true'):
                    with self.subTest(query=query), self.assertRaises(ValueError): engine.browse(c,query)
                ids=[]
                for offset in range(0,1000,100): ids += [r['id'] for r in engine.browse(c,'limit=100&offset='+str(offset))['items']]
                self.assertEqual(len(set(ids)),1000)
        finally: client.close(); server.shutdown(); server.server_close(); thread.join()


class AdditionalPatternTests(unittest.TestCase):
    def test_positive_and_negative_controls_without_execution(self):
        source = 'import tempfile as t\nfrom importlib import import_module as load\nimport os\ndef f(a=[]):\n load(a)\n t.mktemp()\n os.chmod("x",0o666)\n'
        self.assertTrue(all(checkpointstatic.analyze(source).values()))
        safe = 'import tempfile, os, importlib\ndef f(a=None):\n importlib.import_module("json")\n tempfile.mkstemp()\n os.chmod("x",0o600)\n'
        self.assertFalse(any(checkpointstatic.analyze(safe).values()))
        with self.assertRaises(ValueError): checkpointstatic.analyze('x'*128001)
        with self.assertRaises(SyntaxError): checkpointstatic.analyze('def :')

    def test_unparseable_files_are_not_counted_as_analyzed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'broken.py').write_text('def :')
            audit=checkpointstatic.inspect(root, ('broken.py','missing.py'))
            self.assertEqual(audit['files'],0); self.assertEqual(audit['skipped'],2)
