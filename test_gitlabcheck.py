import copy
import json
import sqlite3
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

    def test_private_storage_snapshot_and_disconnect(self):
        g.configure(self.c,self.root,self.form)
        self.assertEqual(g.secret_path(self.root).stat().st_mode & 0o777,0o600)
        self.assertFalse(g.snapshot(self.c)['connected'])
        self.assertNotIn(self.config['token'],json.dumps(g.snapshot(self.c)))
        g.disconnect(self.c,self.root)
        self.assertFalse(g.secret_path(self.root).exists())
        self.assertFalse(g.snapshot(self.c)['configured'])

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
