"""Truthful runtime status and private, unverified local-model review receipts."""
import http.client
import json
import re
import shutil
import socket
import ssl
import threading
import time

import ci_identity
from engine import public_addresses
from sourcewatch import fetch, FetchError

REPO = ci_identity.REPOSITORY
WORKFLOWS = {'.github/workflows/scopeguard-isolated.yml': 'runtime', '.github/workflows/scopeguard-ai.yml': 'ai'}
KEY_LOCK = threading.Lock()
KEY_CACHE = {'at': 0, 'attempt': 0, 'keys': []}
RATE_LOCK = threading.Lock()
REQUEST_TIMES = []


def init(c):
    c.executescript('''
      CREATE TABLE IF NOT EXISTS research_status(id INTEGER PRIMARY KEY, checked INTEGER, due INTEGER, status TEXT, runs TEXT, ai_enabled INTEGER DEFAULT 0);
      INSERT OR IGNORE INTO research_status VALUES(1,0,0,'Waiting for GitHub status','[]',0);
      CREATE TABLE IF NOT EXISTS private_ai_reviews(run TEXT PRIMARY KEY, attempt TEXT, revision TEXT, started INTEGER, updated INTEGER, state TEXT, result TEXT);
    ''')


def admit_request():
    now = time.monotonic()
    with RATE_LOCK:
        REQUEST_TIMES[:] = [x for x in REQUEST_TIMES if now-x < 60]
        if len(REQUEST_TIMES) >= 12:
            return False
        REQUEST_TIMES.append(now)
        return True


def fetch_signing_keys():
    host = 'token.actions.githubusercontent.com'
    raw = socket.create_connection((public_addresses(host)[0], 443), timeout=10)
    conn = http.client.HTTPSConnection(host, timeout=10)
    try:
        conn.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        conn.request('GET', '/.well-known/jwks', headers={'User-Agent':'ScopeGuard-CI/1', 'Accept-Encoding':'identity', 'Connection':'close'})
        response = conn.getresponse()
        if response.status != 200:
            raise ValueError('Signing keys unavailable')
        body = response.read(65537)
        if len(body) > 65536:
            raise ValueError('Signing response too large')
        doc = json.loads(body)
        if not isinstance(doc, dict) or not isinstance(doc.get('keys'), list) or not 1 <= len(doc['keys']) <= 10:
            raise ValueError('Invalid signing keys')
        return doc['keys']
    finally:
        conn.close()
        raw.close()


def claims_for(token):
    with KEY_LOCK:
        cached = dict(KEY_CACHE)
    if time.time()-cached['at'] > 3600 or not cached['keys']:
        raise ValueError('Signing keys are not ready; retry later')
    return ci_identity.verify_token(token, cached)


def normalize_runs(doc):
    if not isinstance(doc, dict) or not isinstance(doc.get('workflow_runs'), list):
        raise ValueError('Invalid GitHub status response')
    runs = []
    seen = set()
    for run in doc['workflow_runs']:
        if not isinstance(run, dict) or not isinstance(run.get('repository'), dict):
            continue
        kind = WORKFLOWS.get(run.get('path'))
        if not kind or kind in seen or run.get('head_branch') != 'scopeguard-app' or run.get('repository', {}).get('full_name') != REPO:
            continue
        if type(run.get('id')) is not int or not re.fullmatch('[0-9a-f]{40}', str(run.get('head_sha', ''))):
            continue
        seen.add(kind)
        runs.append({'kind': kind, 'id': run['id'], 'revision': run['head_sha'],
                     'status': run.get('status') if run.get('status') in ('queued','in_progress','completed','waiting','pending','requested') else 'unknown',
                     'conclusion': run.get('conclusion') if run.get('conclusion') in ('success','failure','cancelled','timed_out','skipped','action_required','neutral','stale') else None,
                     'updated': str(run.get('updated_at', ''))[:40],
                     'url': 'https://github.com/'+REPO+'/actions/runs/'+str(run['id'])})
    return runs


def tick(db):
    now = int(time.time())
    with KEY_LOCK:
        due_keys = now-KEY_CACHE['at'] >= 1800 and now-KEY_CACHE.get('attempt', 0) >= 300
        if due_keys:
            KEY_CACHE['attempt'] = now
    if due_keys:
        try:
            keys = fetch_signing_keys()
            with KEY_LOCK:
                KEY_CACHE.update(at=now, keys=keys)
        except (OSError, ValueError):
            pass
    with db() as c:
        row = c.execute('SELECT * FROM research_status WHERE id=1').fetchone()
        if row['due'] > now:
            return
        c.execute('UPDATE research_status SET due=? WHERE id=1', (now+300,))
        c.execute("UPDATE private_ai_reviews SET state='interrupted' WHERE state='running' AND started<?", (now-1800,))
    try:
        doc = json.loads(fetch('api.github.com','/repos/'+REPO+'/actions/runs?branch=scopeguard-app&per_page=20',300000))
        runs = normalize_runs(doc)
        with db() as c:
            c.execute("UPDATE research_status SET checked=?,status='Synced from GitHub',runs=? WHERE id=1", (now,json.dumps(runs)))
    except (OSError, ValueError, FetchError) as error:
        with db() as c:
            c.execute("UPDATE research_status SET status='Could not refresh GitHub; previous result retained',due=? WHERE id=1",(now+max(300,getattr(error,'retry',0)),))


def configure(c, data):
    if type(data.get('enabled')) is not bool:
        raise ValueError('Choose whether to enable private AI reviews')
    c.execute('UPDATE research_status SET ai_enabled=? WHERE id=1', (int(data['enabled']),))
    if not data['enabled']:
        c.execute("UPDATE private_ai_reviews SET state='cancelled',updated=? WHERE state='running'",(int(time.time()),))


def clean_result(data):
    if not isinstance(data, dict) or data.get('model') != 'Qwen2.5-Coder-7B-Instruct-Q4_K_M':
        raise ValueError('Unexpected review model')
    if data.get('status') not in ('reviewed','calibration_failed','failed'):
        raise ValueError('Invalid review status')
    reviews = data.get('reviews', [])
    if not isinstance(reviews, list) or len(reviews) > 2:
        raise ValueError('Review size exceeded')
    cleaned = []
    for r in reviews:
        if not isinstance(r, dict) or r.get('file') not in ('app.py','ci_identity.py','engine.py','gitlabcheck.py'):
            raise ValueError('Review outside the approved source files')
        if type(r.get('line')) is not int or not 1 <= r['line'] <= 10000:
            raise ValueError('Invalid source line')
        text = r.get('analysis')
        if not isinstance(text, str) or not 1 <= len(text) <= 6000:
            raise ValueError('Invalid review text')
        cleaned.append({'file':r['file'], 'line':r['line'], 'analysis':text, 'status':'Unverified AI hypothesis'})
    calibration = data.get('calibration_passed') is True
    if data['status'] == 'reviewed' and (not calibration or not cleaned):
        raise ValueError('A completed review needs calibration and coverage')
    return {'model':data['model'], 'status':data['status'], 'calibration_passed':calibration,
            'reviews':cleaned, 'confirmed_bugs':0, 'submission_ready':False,
            'scope':'Two bounded excerpts from the owned ScopeGuard repository only',
            'limitation':'Small local model. Synthetic calibration is not an expert benchmark. Suggestions may be wrong; no generated code is executed.'}


def receive(c, claims, payload):
    if not isinstance(payload, dict) or payload.get('revision') != claims['sha']:
        raise ValueError('Receipt revision does not match workload identity')
    enabled = c.execute('SELECT ai_enabled FROM research_status WHERE id=1').fetchone()[0]
    paused = c.execute('SELECT paused FROM settings').fetchone()[0]
    if not enabled or paused:
        return {'accepted':False, 'reason':'AI review is disabled or paused'}
    run, attempt, revision, now = str(claims['run_id']), str(claims['run_attempt']), claims['sha'], int(time.time())
    old = c.execute('SELECT * FROM private_ai_reviews WHERE run=?',(run,)).fetchone()
    if payload.get('stage') == 'start':
        if c.execute("SELECT 1 FROM private_ai_reviews WHERE revision=? AND state='reviewed'",(revision,)).fetchone():
            return {'accepted':False, 'reason':'This revision was already reviewed'}
        if old and old['attempt'] == attempt:
            return {'accepted':old['state']=='running', 'reason':'Existing run'}
        if c.execute("SELECT 1 FROM private_ai_reviews WHERE state='running' AND started>?",(now-1800,)).fetchone():
            return {'accepted':False, 'reason':'Another review is running'}
        c.execute('INSERT INTO private_ai_reviews VALUES(?,?,?,?,?,?,?) ON CONFLICT(run) DO UPDATE SET attempt=excluded.attempt,started=excluded.started,updated=excluded.updated,state=excluded.state,result=excluded.result',
                  (run,attempt,revision,now,now,'running','{}'))
        c.execute('DELETE FROM private_ai_reviews WHERE run NOT IN (SELECT run FROM private_ai_reviews ORDER BY started DESC LIMIT 30)')
        return {'accepted':True}
    if payload.get('stage') != 'result' or not old or old['attempt'] != attempt or old['revision'] != revision or now-old['started'] > 1800:
        raise ValueError('No current authorized review lease')
    if old['state'] != 'running':
        return {'accepted':True, 'reason':'Receipt already recorded; unchanged'}
    result = clean_result(payload.get('result'))
    c.execute('UPDATE private_ai_reviews SET state=?,updated=?,result=? WHERE run=?', (result['status'],now,json.dumps(result),run))
    return {'accepted':True}


def snapshot(c):
    row = dict(c.execute('SELECT * FROM research_status WHERE id=1').fetchone())
    reports = []
    for r in c.execute('SELECT * FROM private_ai_reviews ORDER BY started DESC LIMIT 10'):
        item = dict(r)
        item['result'] = json.loads(item['result'])
        item['url'] = 'https://github.com/'+REPO+'/actions/runs/'+item['run']
        reports.append(item)
    return {'version':'private-research-1','checked':row['checked'],'fresh':bool(row['checked'] and time.time()-row['checked']<900),
            'status':row['status'],'runs':json.loads(row['runs']),'ai_enabled':bool(row['ai_enabled']),
            'identity_ready':bool(shutil.which('openssl') and KEY_CACHE['keys'] and time.time()-KEY_CACHE['at']<3600),
            'ai_reviews':reports,'deployed_revision':__import__('os').environ.get('RENDER_GIT_COMMIT',''),
            'autonomous_bounty_hunting':False,'paid_ai_enabled':False,
            'scope':'Only the owned ScopeGuard repository; no new bounty targets authorized',
            'trigger':'Relevant pushes to scopeguard-app, not continuous scanning',
            'cost':'No paid model APIs or additional hosting; existing hosting fees remain'}
