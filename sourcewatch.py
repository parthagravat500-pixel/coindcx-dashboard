"""Commit-pinned public-source review. No credentials, execution or target probing."""
import base64
import hashlib
import http.client
import io
import json
import re
import socket
import ssl
import threading
import time
import zipfile
from urllib.parse import quote

from engine import public_addresses
import projectaudit

INTERVAL = 900
RUN_LOCK = threading.Lock()
REPO = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}')
BRANCH = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,99}')


class FetchError(Exception):
    def __init__(self, message, retry=0):
        super().__init__(message)
        self.retry = retry


def fetch(host, path, limit):
    if host not in ('api.github.com', 'codeload.github.com') or not path.startswith('/'):
        raise ValueError('Only fixed GitHub source endpoints are supported.')
    addresses = public_addresses(host)
    raw = socket.create_connection((addresses[0], 443), timeout=15)
    conn = http.client.HTTPSConnection(host, timeout=15)
    try:
        conn.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        conn.request('GET', path, headers={'User-Agent':'ScopeGuard-PublicSourceReview/1.0',
            'Accept':'application/vnd.github+json' if host=='api.github.com' else 'application/zip',
            'Connection':'close', 'Accept-Encoding':'identity'})
        response = conn.getresponse()
        if response.status in (403,429):
            retry = response.getheader('Retry-After', '')
            reset = response.getheader('X-RateLimit-Reset', '')
            delay = max(3600, int(retry) if retry.isdigit() else 0,
                        int(reset)-int(time.time())+30 if reset.isdigit() else 0)
            raise FetchError('GitHub refused or rate-limited this request; waiting before retry.', delay)
        if response.status >= 500:
            raise FetchError('GitHub source service is temporarily unavailable.', INTERVAL)
        if response.status != 200:
            raise FetchError('Source request stopped: HTTP '+str(response.status)+'. Review repository and branch. Redirects are not followed.')
        size = response.getheader('Content-Length','')
        if size.isdigit() and int(size)>limit:
            raise FetchError('Repository response exceeds the supported size limit.')
        raw_body = response.read(limit+1)
        if len(raw_body)>limit:
            raise FetchError('Repository response exceeds the supported size limit.')
        return raw_body
    finally:
        conn.close()
        raw.close()


def init(c):
    c.executescript('''
      CREATE TABLE IF NOT EXISTS source_watches (
        id TEXT PRIMARY KEY, repository TEXT, branch TEXT, subdirectory TEXT,
        rules TEXT, expires INTEGER, enabled INTEGER, due INTEGER,
        checked INTEGER DEFAULT 0, last_commit TEXT DEFAULT '', engine TEXT DEFAULT '',
        status TEXT DEFAULT 'Queued', failures INTEGER DEFAULT 0, reviews INTEGER DEFAULT 0,
        generation INTEGER DEFAULT 1);
      CREATE TABLE IF NOT EXISTS source_watch_runs (
        id INTEGER PRIMARY KEY, watch TEXT, at INTEGER, revision TEXT, status TEXT,
        details TEXT);
      CREATE TABLE IF NOT EXISTS source_watch_health (
        id INTEGER PRIMARY KEY, heartbeat INTEGER, next_request INTEGER);
      INSERT OR IGNORE INTO source_watch_health VALUES(1,0,0);
    ''')


def configure(c, data):
    if data.get('authorized') is not True:
        raise ValueError('Confirm permission for automated, read-only source review.')
    repository = data.get('repository','')
    branch = data.get('branch','')
    subdir = data.get('subdirectory','')
    rules = data.get('rules','')
    expires = data.get('expires')
    if not isinstance(repository,str) or not REPO.fullmatch(repository) or repository.endswith('.git'):
        raise ValueError('Use owner/repository, without a URL, credentials or .git suffix.')
    if not isinstance(branch,str) or not BRANCH.fullmatch(branch) or '..' in branch or any(x.startswith('.') or x.endswith(('.', '.lock')) or not x for x in branch.split('/')):
        raise ValueError('Use a valid, explicit branch name.')
    if not isinstance(subdir,str) or len(subdir)>160 or (subdir and (not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*',subdir) or any(x in ('.','..') for x in subdir.split('/')))):
        raise ValueError('Use a relative source folder, without traversal or a trailing slash.')
    if not isinstance(rules,str) or not 30<=len(rules.strip())<=2000:
        raise ValueError('Record the ownership or source-review permission, at least 30 characters.')
    if type(expires) is not int or not time.time()<expires<=time.time()+7*86400:
        raise ValueError('Review permission must expire within seven days.')
    repository=repository.lower()
    key=hashlib.sha256(json.dumps([repository,branch,subdir]).encode()).hexdigest()[:24]
    old=c.execute('SELECT * FROM source_watches WHERE id=?',(key,)).fetchone()
    if not old and c.execute('SELECT COUNT(*) FROM source_watches').fetchone()[0]>=3:
        raise ValueError('Maximum three focused source repositories.')
    c.execute('''INSERT INTO source_watches(id,repository,branch,subdirectory,rules,expires,enabled,due)
      VALUES(?,?,?,?,?,?,1,0) ON CONFLICT(id) DO UPDATE SET rules=excluded.rules,
      expires=excluded.expires,enabled=1,generation=generation+1,status='Queued for next permitted check' ''',
      (key,repository,branch,subdir,rules.strip(),expires))
    return key


def disable(c,key):
    if not isinstance(key,str):raise ValueError('Choose a source watch.')
    c.execute("UPDATE source_watches SET enabled=0,generation=generation+1,status='Disabled by owner' WHERE id=?",(key,))


def name(row):
    return 'Repository/'+row['repository']+'@'+row['branch']+('/'+row['subdirectory'] if row['subdirectory'] else '')


def allowed(c,row):
    current=c.execute('SELECT enabled,expires,generation FROM source_watches WHERE id=?',(row['id'],)).fetchone()
    return bool(current and current['enabled'] and current['expires']>time.time() and
                current['generation']==row['generation'] and not c.execute('SELECT paused FROM settings').fetchone()[0])


def append_run(c,row,commit,status,details):
    c.execute('INSERT INTO source_watch_runs(watch,at,revision,status,details) VALUES(?,?,?,?,?)',
              (row['id'],int(time.time()),commit,status,json.dumps(details)))
    c.execute('DELETE FROM source_watch_runs WHERE id NOT IN (SELECT id FROM source_watch_runs ORDER BY id DESC LIMIT 100)')


def tick(db,lock,log):
    if not RUN_LOCK.acquire(blocking=False):return
    try:
        _tick(db,lock,log)
    finally:
        RUN_LOCK.release()


def _tick(db,lock,log):
    now=int(time.time())
    with lock,db() as c:
        c.execute('UPDATE source_watch_health SET heartbeat=? WHERE id=1',(now,))
        c.execute("UPDATE source_watches SET enabled=0,generation=generation+1,status='Permission expired; renew before more requests' WHERE enabled=1 AND expires<=?",(now,))
        if c.execute('SELECT paused FROM settings').fetchone()[0]:return
        if c.execute('SELECT next_request FROM source_watch_health').fetchone()[0]>now:return
        row=c.execute('SELECT * FROM source_watches WHERE enabled=1 AND expires>? AND due<=? ORDER BY due,id LIMIT 1',(now,now)).fetchone()
        if not row:return
        row=dict(row)
        c.execute("UPDATE source_watches SET due=?,status='Checking approved source revision' WHERE id=?",(now+INTERVAL,row['id']))
        c.execute('UPDATE source_watch_health SET next_request=? WHERE id=1',(now+60,))
    commit=''
    def request(host,path,limit):
        # A pause/revoke and request dispatch are serialized. In-flight requests may finish.
        with lock:
            with db() as c:
                if not allowed(c,row):raise FetchError('Paused or permission changed; source review stopped.')
            return fetch(host,path,limit)
    try:
        raw=request('api.github.com','/repos/'+row['repository']+'/git/ref/heads/'+quote(row['branch'],safe='/'),16000)
        data=json.loads(raw)
        if not isinstance(data,dict) or data.get('ref')!='refs/heads/'+row['branch']:
            raise FetchError('GitHub did not return the exact approved branch.')
        obj=data.get('object',{})
        commit=obj.get('sha','') if isinstance(obj,dict) else ''
        if not isinstance(obj,dict) or obj.get('type')!='commit' or not isinstance(commit,str) or not re.fullmatch('[0-9a-f]{40}',commit):
            raise FetchError('Invalid commit identity; no source reviewed.')
        if commit==row['last_commit'] and row['engine']==projectaudit.VERSION:
            with lock,db() as c:
                if not allowed(c,row):return
                c.execute("UPDATE source_watches SET checked=?,status='No new commit; previous review retained',failures=0 WHERE id=?",(int(time.time()),row['id']))
                append_run(c,row,commit,'unchanged',{})
            return
        archive=request('codeload.github.com','/'+row['repository']+'/zip/'+commit,projectaudit.MAX_TOTAL)
        # GitHub's archive root varies with revision; strip only the expected commit root.
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            roots={item.filename.split('/')[0] for item in z.infolist()}
        expected=row['repository'].split('/')[1]+'-'+commit
        if len(roots)!=1 or next(iter(roots)).lower()!=expected:
            raise FetchError('Archive root does not match the pinned repository revision.')
        prefix=next(iter(roots))+'/'
        if row['subdirectory']:prefix+=row['subdirectory']+'/'
        files,skipped=projectaudit.archive(base64.b64encode(archive).decode(),prefix=prefix)
        with lock,db() as c:
            if not allowed(c,row):return
            changed=projectaudit.record(c,name(row),files,skipped)
            audit=c.execute('SELECT result,checked FROM project_audits WHERE name=?',(name(row),)).fetchone()
            result=json.loads(audit[0])
            if not changed:
                result['changes']={'has_baseline':True,'previous_checked':audit[1],'added_files':[],
                    'changed_files':[],'removed_files':[],'new_leads':0,'no_longer_observed':[],
                    'comparison_note':'Python source is identical; previous analysis reused.'}
                for finding in result['findings']:
                    finding['change_status']='Existing lead'
                    finding['changed_trace_files']=[]
                    finding['research_priority']=min(len({t['file'] for t in finding['trace']}),5)
            result['source_revision']={'repository':row['repository'],'branch':row['branch'],'commit':commit,'subdirectory':row['subdirectory'],
                'url':'https://github.com/'+row['repository']+'/commit/'+commit,'analysis_reused':not changed}
            c.execute('UPDATE project_audits SET result=?,checked=? WHERE name=?',(json.dumps(result),int(time.time()),name(row)))
            c.execute("UPDATE source_watches SET last_commit=?,engine=?,checked=?,status=?,failures=0,reviews=reviews+1 WHERE id=?",
                (commit,projectaudit.VERSION,int(time.time()),'Commit reviewed; see project evidence' if changed else 'New commit has identical Python source; previous analysis reused',row['id']))
            append_run(c,row,commit,'reviewed' if changed else 'reused',{'files':result['files_analyzed'],'leads':result['total_findings'],'confirmed_bugs':0,
                'limited':result['bounded_or_truncated'] or bool(result['syntax_skipped'])})
            log(c,'Approved source revision reviewed: '+row['repository']+' '+commit[:12]+'. '+str(result['total_findings'])+' static leads; no exploit test or report sent.')
    except Exception as exc:
        with lock,db() as c:
            if not allowed(c,row):return
            failures=row['failures']+1
            retry=exc.retry if isinstance(exc,FetchError) else (INTERVAL if isinstance(exc,(OSError,TimeoutError,http.client.HTTPException)) else 0)
            message=str(exc) if isinstance(exc,FetchError) else 'Source review failed ('+type(exc).__name__+'); check size, language, paths and connectivity.'
            enabled=bool(retry and failures<3)
            wait=max(INTERVAL*2**min(failures-1,5),retry)
            c.execute('UPDATE source_watches SET status=?,failures=?,enabled=?,due=?,checked=? WHERE id=?',
                (message+(' Retrying later.' if enabled else ' Stopped; review setup.'),failures,int(enabled),int(time.time())+wait,int(time.time()),row['id']))
            if retry:
                c.execute('UPDATE source_watch_health SET next_request=MAX(next_request,?) WHERE id=1',(int(time.time())+retry,))
            append_run(c,row,commit,'error',{'message':message,'retrying':enabled})
            log(c,'Source review needs attention: '+row['repository']+'. '+message)


def snapshot(c):
    return {'watches':[dict(r) for r in c.execute('SELECT * FROM source_watches ORDER BY repository,branch')],
            'runs':[{**dict(r),'details':json.loads(r['details'])} for r in c.execute('SELECT * FROM source_watch_runs ORDER BY id DESC LIMIT 20')],
            'heartbeat':c.execute('SELECT heartbeat FROM source_watch_health').fetchone()[0],
            'interval_seconds':INTERVAL,'maximum_repositories':3,
            'limitation':'Public GitHub Python source only. No remote code execution, live-target testing, LLM calls, or automatic reports.'}
