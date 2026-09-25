import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import app
import readiness
import workflow


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        data = patch.object(app, 'DATA', Path(self.temp.name))
        data.start()
        self.addCleanup(data.stop)
        app.init()
        self.now = int(time.time())

    def program(self, slug='altera/altera'):
        return {'url': 'https://www.intigriti.com/programs/' + slug + '/detail', 'available': 1, 'stale': False, 'stage': 'queue'}

    def assess(self, p):
        with app.db() as c:
            return readiness.assess(p, readiness.context(c, self.now))

    def test_large_rewards_cannot_create_test_readiness_or_targets(self):
        p = self.program()
        p['maximum'] = 1000000
        r = self.assess(p)
        self.assertEqual(r['category'], 'specialist')
        self.assertFalse(r['configured'])
        self.assertFalse(r['grants_permission'])
        self.assertEqual(app.snapshot()['targets'], [])

    def test_every_review_has_an_official_source_and_no_permission_grant(self):
        for slug in readiness.POLICIES:
            r = self.assess(self.program(slug))
            self.assertEqual(r['reviewed_on'], '2026-09-25')
            self.assertTrue(r['sources'][0].startswith('https://app.intigriti.com/'))
            self.assertFalse(r['active'])
            self.assertFalse(r['grants_permission'])

    def test_disabled_expired_and_stale_records_are_not_active(self):
        with app.db() as c:
            c.execute('INSERT INTO targets(name,url,policy,rules,expires,interval,cors,enabled) VALUES(?,?,?,?,?,900,0,0)',
                      ('Fixture', 'https://example.com/', self.program('example/example')['url'], 'Owned fixture', self.now + 3600))
        p = self.program('example/example')
        self.assertFalse(self.assess(p)['configured'])
        with app.db() as c:
            c.execute('UPDATE targets SET enabled=1,expires=0')
        self.assertFalse(self.assess(p)['configured'])
        with app.db() as c:
            c.execute('UPDATE targets SET expires=?', (self.now + 3600,))
            c.execute('UPDATE settings SET paused=0')
        self.assertTrue(self.assess(p)['active'])
        p['stale'] = True
        self.assertFalse(self.assess(p)['active'])
        self.assertEqual(self.assess(p)['category'], 'unavailable')

    def test_configured_header_checks_are_explicitly_limited(self):
        p = self.program('example/example')
        with app.db() as c:
            c.execute('INSERT INTO targets(name,url,policy,rules,expires,interval,cors) VALUES(?,?,?,?,?,900,0)',
                      ('Fixture', 'https://example.com/', p['url'].replace('www.', 'app.'), 'Owned fixture', self.now + 3600))
        self.assertIn('paused', self.assess(p)['label'])
        app.mutate('/api/all-pause', {'paused': False})
        self.assertIn('Header checks only', self.assess(p)['label'])
        with app.db() as c:
            c.execute("INSERT INTO access_checks VALUES(1,'fixture','fixture',?,1,0,0,'Queued','{}')", (self.now + 3600,))
        self.assertIn('access check', self.assess(p)['label'])

    def test_unknown_program_and_hidden_listing_never_report_coverage(self):
        p = self.program('unknown/unknown')
        self.assertEqual(self.assess(p)['category'], 'unknown')
        p['stage'] = 'dismissed'
        self.assertEqual(self.assess(p)['category'], 'unavailable')
        self.assertFalse(self.assess(p)['active'])
