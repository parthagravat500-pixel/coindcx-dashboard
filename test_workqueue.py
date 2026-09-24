import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import app
import workqueue
import workflow
from test_workflow import program


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        p=patch.object(app,'DATA',Path(self.tmp.name));p.start();self.addCleanup(p.stop)
        app.init();self.now=int(time.time())
        workflow.sync(app.db,'intigriti',[program('One'),program('Two')],self.now)

    def test_pause_and_resume_without_network(self):
        with patch('urllib.request.urlopen') as request:
            workqueue.tick(app.db,app.log)
            self.assertEqual(app.snapshot()['background']['completed'],0)
            app.mutate('/api/all-pause',{'paused':False})
            workqueue.tick(app.db,app.log)
            s=app.snapshot();request.assert_not_called()
        self.assertEqual(s['background']['completed'],2)
        self.assertEqual(s['background']['pending'],0)
        self.assertTrue(s['background']['healthy'])
        self.assertEqual(s['targets'],[])

    def test_unchanged_sync_and_restart_do_not_repeat_work(self):
        app.mutate('/api/all-pause',{'paused':False});workqueue.tick(app.db,app.log)
        events=len(app.snapshot()['events'])
        app.init()
        workflow.sync(app.db,'intigriti',[program('One'),program('Two')],self.now+5)
        workqueue.tick(app.db,app.log)
        s=app.snapshot();self.assertEqual(s['background']['completed'],2)
        self.assertEqual(len(s['events']),events)
        self.assertIn('Waiting',s['background']['status'])

    def test_changes_are_reviewed_and_stale_heartbeat_is_visible(self):
        app.mutate('/api/all-pause',{'paused':False});workqueue.tick(app.db,app.log)
        workflow.sync(app.db,'intigriti',[program('One',20000),program('Two')],self.now+5)
        self.assertEqual(app.snapshot()['background']['pending'],1)
        workqueue.tick(app.db,app.log)
        self.assertEqual(app.snapshot()['background']['completed'],3)
        with app.db() as c:c.execute('UPDATE background_status SET heartbeat=1')
        self.assertFalse(app.snapshot()['background']['healthy'])
        self.assertEqual(app.snapshot()['background']['status'],'Worker status unavailable')

    def test_migration_preserves_backoff_and_target_schedule(self):
        with app.db() as c:
            c.execute("DELETE FROM queue_migrations")
            c.execute('UPDATE discovery_sources SET last_attempt=?,due=?,failures=1',(self.now,self.now+20000))
        app.init()
        with app.db() as c:
            self.assertEqual(c.execute('SELECT MIN(due) FROM discovery_sources').fetchone()[0],self.now+20000)
        self.assertEqual(workflow.INTERVAL,900)
