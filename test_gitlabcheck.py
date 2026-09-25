import copy
import json
import sqlite3
import ssl
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
import gitlabcheck as g


class GitLabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.c = sqlite3.connect(':memory:')
        self.addCleanup(self.c.close)
        self.c.row_factory = sqlite3.Row
        self.c.execute('CREATE TABLE settings(paused INTEGER)')
        self.c.execute('INSERT INTO settings VALUES(0)')
        g.init(self.c)
        self.config = {'project':'babe500-security-lab/scopeguard-test','token':'glpat-'+'x'*24,
                       'marker':'scopeguard_'+'a'*32}
        self.form = dict(self.config, own_project=True, policy_permission=True, read_only=True,
                         rules='Owner test only with current explicit production comparison permission.')
        self.info = {'active':True,'revoked':False,'scopes':['read_api']}
        self.project = {'id':42,'path_with_namespace':self.config['project'],'visibility':'private',
                        'description':self.config['marker'],'permissions':{'group_access':{'access_level':50}}}

    @contextmanager
    def db(self):
        yield self.c
        self.c.commit()

    def response(self, status, data=None):
        return dict(status=status,data=data,bytes=10,sha256='0'*64)

    def run_check(self, responses, allowed=lambda:True):
        calls=[]
        def transport(path, token):
            calls.append((path, token))
            return responses.pop(0)
        return g.compare(self.config,allowed,transport,lambda _:None),calls

    def test_normal_denial_empty_repository_needs_no_files(self):
        r,calls=self.run_check([self.response(200,self.info),self.response(200,self.project),self.response(404)])
        self.assertTrue(r['status'].startswith('Passed:'))
        self.assertEqual(len(calls),3)
        self.assertIsNone(calls[-1][1])
        self.assertEqual(calls[-1][0],'/api/v4/projects/babe500-security-lab%2Fscopeguard-test')
        self.assertNotIn(self.config['token'],json.dumps(r))
        self.assertNotIn(self.config['marker'],json.dumps(r))

    def test_reproduction_requires_four_matching_project_controls(self):
        r,calls=self.run_check([self.response(200,self.info)]+[self.response(200,self.project)]*4)
        self.assertTrue(r['reproduced'])
        self.assertFalse(r['submission_ready'])
        self.assertEqual(len(calls),5)
        changed=copy.deepcopy(self.project);changed['visibility']='public'
        r,_=self.run_check([self.response(200,self.info)]+[self.response(200,self.project)]*3+[self.response(200,changed)])
        self.assertFalse(r['reproduced'])

    def test_bad_token_or_write_scope_never_requests_project(self):
        for scopes in (['api'],['read_api','write_repository'],[]):
            r,calls=self.run_check([self.response(200,dict(self.info,scopes=scopes))])
            self.assertEqual(len(calls),1)
            self.assertFalse(r['verified_connection'])

    def test_public_or_unowned_or_missing_marker_blocks_anonymous_request(self):
        for changes in ({'visibility':'public'},{'permissions':{}},{'description':'empty'},{'path_with_namespace':'someone/else'}):
            p=dict(self.project,**changes)
            r,calls=self.run_check([self.response(200,self.info),self.response(200,p)])
            self.assertEqual(len(calls),2)
            self.assertTrue(r['status'].startswith('Setup needed:'))

    def test_non_json_redirect_rate_limit_and_server_error_do_not_pass(self):
        for status in (200,302,429,503):
            r,calls=self.run_check([self.response(200,self.info),self.response(200,self.project),self.response(status)])
            self.assertFalse(r['status'].startswith('Passed:'))
            self.assertFalse(r['reproduced'])
            self.assertEqual(len(calls),3)

    def test_pause_is_checked_before_each_request(self):
        permissions=iter([True,True,False])
        r,calls=self.run_check([self.response(200,self.info),self.response(200,self.project)],lambda:next(permissions))
        self.assertEqual(len(calls),2)
        self.assertTrue(r['status'].startswith('Stopped:'))

    def test_failure_diagnostics_retry_only_temporary_responses_without_private_text(self):
        for status in (401,403,429,500,501,502,503,504):
            r,calls=self.run_check([self.response(status)])
            self.assertEqual(len(calls),1)
            self.assertEqual(g.temporary_failure(r),status in g.TEMPORARY_HTTP)
            self.assertFalse(r['reproduced'])
        for exc,temporary in ((TimeoutError,True),(ConnectionResetError,True),(ssl.SSLError,False),(ValueError,False)):
            def fail(*_):raise exc(self.config['token'])
            r=g.compare(self.config,transport=fail,pace=lambda _:None)
            self.assertEqual(g.temporary_failure(r),temporary)
            self.assertNotIn(self.config['token'],json.dumps(r))

    def test_transient_retries_back_off_persist_and_stop_after_two_retries(self):
        g.configure(self.c,self.root,self.form)
        now=int(time.time())
        failure,_=self.run_check([self.response(503)])
        with patch.object(g,'compare',side_effect=lambda *_:copy.deepcopy(failure)) as compare,patch.object(g.time,'time') as clock:
            for attempt,delay in enumerate((900,1800,3600),1):
                clock.return_value=now
                g.tick(self.db,self.root,lambda *_:None)
                s=g.snapshot(self.c)
                self.assertEqual(s['due'],now+delay)
                self.assertEqual(s['result']['transient_failures'],attempt)
                self.assertEqual(bool(s['enabled']),attempt<=2)
                g.init(self.c)
                g.tick(self.db,self.root,lambda *_:None)
                self.assertEqual(compare.call_count,attempt)
                now+=delay
            clock.return_value=now
            g.tick(self.db,self.root,lambda *_:None)
            self.assertEqual(compare.call_count,3)

    def test_retry_after_is_honored_and_never_extends_permission(self):
        now=int(time.time())
        self.assertEqual(g.retry_after('3600',now),now+3600)
        self.assertEqual(g.retry_after('Wed, 21 Oct 2015 07:28:00 GMT'),1445412480)
        self.assertEqual(g.retry_after('invalid'),0)
        g.configure(self.c,self.root,self.form)
        original_expiry=g.snapshot(self.c)['expires']
        failure,_=self.run_check([dict(self.response(503),retry_at=now+3600)])
        with patch.object(g,'compare',return_value=failure),patch.object(g.time,'time',return_value=now):
            g.tick(self.db,self.root,lambda *_:None)
        s=g.snapshot(self.c)
        self.assertEqual(s['due'],now+3600);self.assertTrue(s['enabled'])
        self.c.execute('UPDATE gitlab_check SET due=0')
        failure,_=self.run_check([dict(self.response(503),retry_at=10**90)])
        with patch.object(g,'compare',return_value=failure),patch.object(g.time,'time',return_value=now):
            g.tick(self.db,self.root,lambda *_:None)
        s=g.snapshot(self.c)
        self.assertFalse(s['enabled']);self.assertEqual(s['expires'],original_expiry)
        self.assertFalse(s['retry_available'])

    def stopped_legacy(self,status=503):
        g.configure(self.c,self.root,self.form)
        now=int(time.time())
        r={'status':'Stopped: request failed or server asked us to stop; no conclusion',
           'evidence':[self.response(status)],'verified_connection':False,'reproduced':False}
        self.c.execute('UPDATE gitlab_check SET enabled=0,checked=?,due=?,result=?',
                       (now-1000,now-100,json.dumps(r)))

    def test_saved_recovery_reuses_token_project_and_existing_permission(self):
        self.stopped_legacy()
        before=g.secret_path(self.root).read_bytes()
        expires=g.snapshot(self.c)['expires']
        self.assertTrue(g.snapshot(self.c)['retry_available'])
        g.retry_saved(self.c,self.root)
        s=g.snapshot(self.c)
        self.assertTrue(s['enabled']);self.assertFalse(s['retry_available'])
        self.assertEqual(s['expires'],expires)
        self.assertEqual(g.secret_path(self.root).read_bytes(),before)
        self.assertNotIn(self.config['token'],json.dumps(s))

    def test_saved_recovery_cannot_bypass_stop_cooldown_pause_expiry_or_missing_secret(self):
        self.stopped_legacy()
        for sql in ('UPDATE settings SET paused=1','UPDATE gitlab_check SET expires=0',
                    'UPDATE gitlab_check SET enabled=1','UPDATE gitlab_check SET checked=9999999999',
                    "UPDATE gitlab_check SET result='{}'", "UPDATE gitlab_check SET revision='changed'"):
            self.c.execute('SAVEPOINT fixture')
            self.c.execute(sql)
            with self.assertRaises(ValueError):g.retry_saved(self.c,self.root)
            self.c.execute('ROLLBACK TO fixture');self.c.execute('RELEASE fixture')
        for status in (401,403,429,501):
            r={'status':'Stopped: request failed or server asked us to stop; no conclusion','evidence':[self.response(status)]}
            self.c.execute('UPDATE gitlab_check SET result=?',(json.dumps(r),))
            with self.assertRaises(ValueError):g.retry_saved(self.c,self.root)
        self.c.execute('UPDATE gitlab_check SET checked=0')
        self.stopped_legacy()
        g.secret_path(self.root).unlink()
        with self.assertRaises(ValueError):g.retry_saved(self.c,self.root)

    def test_private_storage_snapshot_and_disconnect(self):
        g.configure(self.c,self.root,self.form)
        self.assertEqual(g.secret_path(self.root).stat().st_mode & 0o777,0o600)
        self.assertFalse(g.snapshot(self.c)['connected'])
        self.assertNotIn(self.config['token'],json.dumps(g.snapshot(self.c)))
        g.disconnect(self.c,self.root)
        self.assertFalse(g.secret_path(self.root).exists())
        self.assertFalse(g.snapshot(self.c)['configured'])

    def test_opaque_token_and_copy_padding(self):
        token='glpat-'+('x'*24)+'.01.abc_def-123'
        g.configure(self.c,self.root,dict(self.form,token=' \t'+token+' '))
        saved=json.loads(g.secret_path(self.root).read_text())
        self.assertEqual(saved['token'],token)
        self.assertNotIn(token,json.dumps(g.snapshot(self.c)))
        for bad in (token+'\n',token+'\r',token+'\x00',token+'\u200b',token+' more'):
            with self.assertRaises(ValueError):
                g.configure(self.c,self.root,dict(self.form,token=bad))

    def test_reject_url_and_header_injection(self):
        for v in ('https://evil.com/a/b','https://gitlab.com/a/b?token=x','https://u:p@gitlab.com/a/b','a/../b','a/b%2fprojects'):
            with self.assertRaises(ValueError):g.project_path(v)
        for changes in ({'token':'glpat-xxxx\r\nX:evil'},{'policy_permission':False},{'marker':'not-a-marker'}):
            with self.assertRaises(ValueError):g.configure(self.c,self.root,dict(self.form,**changes))
        self.assertEqual(g.project_path('https://gitlab.com/a/b.git'),'a/b')

    def test_worker_pause_expiry_schedule_stop_and_cooldown(self):
        g.configure(self.c,self.root,self.form)
        with patch.object(g,'compare',return_value={'status':'Passed: private','verified_connection':True,'evidence':[],'reproduced':False,'submission_ready':False}) as compare:
            self.c.execute('UPDATE settings SET paused=1')
            g.tick(self.db,self.root,lambda *_:None)
            compare.assert_not_called()
            self.c.execute('UPDATE settings SET paused=0')
            self.c.execute('UPDATE gitlab_check SET expires=0')
            g.tick(self.db,self.root,lambda *_:None)
            compare.assert_not_called()
            self.c.execute('UPDATE gitlab_check SET expires=?',(time.time()+60,))
            g.tick(self.db,self.root,lambda *_:None)
            self.assertTrue(g.snapshot(self.c)['enabled'])
            g.tick(self.db,self.root,lambda *_:None)
            self.assertEqual(compare.call_count,1)
            with self.assertRaises(ValueError):g.configure(self.c,self.root,self.form)
            self.c.execute('UPDATE gitlab_check SET due=0')
            compare.return_value={'status':'Inconclusive','evidence':[],'reproduced':False}
            g.tick(self.db,self.root,lambda *_:None)
            self.assertFalse(g.snapshot(self.c)['enabled'])

    def test_transport_only_fixed_get_host_and_no_redirect_following(self):
        with patch.object(g,'public_addresses',return_value=['203.0.113.1']),patch.object(g.socket,'create_connection') as sock,patch.object(g.ssl,'create_default_context') as ssl,patch.object(g.http.client,'HTTPSConnection') as conn:
            response=conn.return_value.getresponse.return_value
            response.status=302;response.read.return_value=b'{}';response.getheader.side_effect=lambda name,default:default
            g.fetch('/api/v4/projects/a%2Fb',self.config['token'])
            self.assertEqual(conn.call_args.args,('gitlab.com',))
            self.assertEqual(conn.return_value.request.call_args.args,('GET','/api/v4/projects/a%2Fb'))
            self.assertEqual(conn.return_value.request.call_count,1)
            self.assertEqual(ssl.return_value.wrap_socket.call_args.kwargs['server_hostname'],'gitlab.com')
        for path in ('/api/v4/projects','/api/v4/projects/a%2Fb/issues','https://evil.com/x'):
            with self.assertRaises(ValueError):g.fetch(path,None)

if __name__=='__main__':unittest.main()
