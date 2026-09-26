"""Durable selection and follow-up for already-authorized, bounded runtime checks.

No discovery result grants permission. Runners retain their own final permission
checks, request limits and stop conditions. This module never handles credentials.
"""
import hashlib
import json
import re
import threading
import time

import programqueue

RUN_LOCK = threading.Lock()
LEASE_SECONDS = 300
PROGRAM_GAP = 60
KINDS = ('headers', 'access', 'gitlab', 'gitlab_pair', 'owned_validation')
COMPLETED = ('observations','no_observation','boundary_held','reproduced_boundary')


def init(c):
    c.executescript('''
      CREATE TABLE IF NOT EXISTS autonomous_status(id INTEGER PRIMARY KEY,heartbeat INTEGER);
      INSERT OR IGNORE INTO autonomous_status VALUES(1,0);
      CREATE TABLE IF NOT EXISTS autonomous_runs (
        id INTEGER PRIMARY KEY, job TEXT, kind TEXT, stamp TEXT, started INTEGER,
        finished INTEGER, lease_until INTEGER, outcome TEXT, evidence TEXT);
      CREATE UNIQUE INDEX IF NOT EXISTS autonomous_one_active
        ON autonomous_runs((1)) WHERE outcome='running';
      CREATE TABLE IF NOT EXISTS autonomous_rotation (
        job TEXT PRIMARY KEY, stamp TEXT, last_started INTEGER, retry_at INTEGER, failures INTEGER);
      CREATE TABLE IF NOT EXISTS autonomous_programs (program TEXT PRIMARY KEY,next_allowed INTEGER);
      CREATE TABLE IF NOT EXISTS autonomous_cases (
        id TEXT PRIMARY KEY,job TEXT,stamp TEXT,first_seen INTEGER,last_seen INTEGER,
        kind TEXT,evidence TEXT,draft TEXT);
      CREATE TABLE IF NOT EXISTS autonomous_totals (
        kind TEXT,outcome TEXT,total INTEGER,last_finished INTEGER,PRIMARY KEY(kind,outcome));
      CREATE TABLE IF NOT EXISTS autonomous_totals_origin (id INTEGER PRIMARY KEY,since INTEGER);
    ''')
    # Import retained history once. Older deleted attempts cannot be reconstructed.
    created = c.execute('INSERT OR IGNORE INTO autonomous_totals_origin VALUES(1,?)',
                        (int(time.time()),)).rowcount
    if created:
        c.execute('''INSERT INTO autonomous_totals SELECT kind,outcome,COUNT(*),MAX(finished)
          FROM autonomous_runs WHERE outcome!='running' GROUP BY kind,outcome''')


def count_result(c,kind,outcome,finished):
    c.execute('''INSERT INTO autonomous_totals VALUES(?,?,1,?)
      ON CONFLICT(kind,outcome) DO UPDATE SET total=total+1,last_finished=MAX(last_finished,excluded.last_finished)''',
      (kind,outcome,finished))


def stop_detail(row,now):
    """Fixed, non-sensitive reasons. Never repeat server or credential text."""
    if row['expires'] <= now: return 'Permission has expired; the program rules need a fresh review.'
    try: result = json.loads(row.get('result','{}'))
    except (ValueError,TypeError): result = {}
    if not isinstance(result,dict): result = {}
    if result.get('reproduced') is True: return 'A possible issue was saved. This test stopped to avoid reading more data.'
    if result.get('authentication_failed') is True: return 'An account connection was rejected. It needs a valid replacement before testing.'
    if result.get('failure_kind') == 'tls': return 'The secure connection failed. Testing stays off until the connection is reviewed.'
    status = str(row.get('status',row.get('state','')))
    if re.search(r'HTTP (401|403)\b',status): return 'The website refused access. Testing stays off until access and permission are reviewed.'
    if re.search(r'HTTP (429|5\d\d)\b',status): return 'The website asked testing to stop or returned a server error. Review is required before restarting.'
    if 'Setup needed' in status or 'Setup needs attention' in status: return 'The saved test setup did not pass its control check. Its connection or test data needs review.'
    if row.get('failures',0) >= 3: return 'Repeated connection failures stopped this test. Its address and connection need review.'
    return 'This test is switched off. It will stay off until its access and permission are reviewed.'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def target_blocker(c, target, now):
    if not target['enabled']: return 'Saved target is disabled'
    if target['expires'] <= now: return 'Testing permission expired'
    return programqueue.target_gate(c, target, now)


def jobs(c, now=None):
    now = int(time.time()) if now is None else now
    result = []
    targets = {row['id']: dict(row) for row in c.execute('SELECT * FROM targets')}
    def add(kind, key, due, identity, program, label, blocker='', detail=''):
        if blocker not in ('Saved target is disabled','Access comparison is disabled','Saved comparison is disabled'):
            detail = {'Testing permission expired':'Permission has expired; the program rules need a fresh review.',
                      'Access-comparison permission expired':'Permission for this private-data test has expired.',
                      'Owner-account approval or connection changed':'The first account’s connection or permission changed. The two-account test needs review.'}.get(blocker,'')
        result.append({'key':kind+':'+str(key), 'kind':kind, 'target':key, 'due':due,
                       'stamp':digest(identity), 'program':digest(program),
                       'label':label, 'blocker':blocker, 'blocker_detail':detail if blocker else ''})
    def identity(t):
        return {k:t[k] for k in ('id','url','policy','rules','expires','interval','cors','enabled')}
    for key,t in targets.items():
        add('headers',key,t['due'],identity(t),t['policy'].rstrip('/'),
            'Saved URL '+str(key)+' · headers',target_blocker(c,t,now),stop_detail(t,now) if not t['enabled'] else '')
    for row in c.execute('SELECT * FROM access_checks'):
        a = dict(row); t = targets.get(a['target'])
        block = ('Approved target missing' if not t else target_blocker(c,t,now))
        block = block or ('Access comparison is disabled' if not a['enabled'] else
                          'Access-comparison permission expired' if a['expires'] <= now else '')
        add('access',a['target'],a['due'],[a['revision'],a['rules'],a['expires'],identity(t) if t else None],
            t['policy'].rstrip('/') if t else 'missing', 'Saved URL '+str(a['target'])+' · access comparison',block,
            stop_detail(t,now) if t and not t['enabled'] else stop_detail(a,now) if not a['enabled'] else '')
    parent = c.execute('SELECT * FROM gitlab_check WHERE id=1').fetchone()
    for kind, table in (('gitlab','gitlab_check'),('gitlab_pair','gitlab_peer')):
        row = c.execute('SELECT * FROM '+table+' WHERE id=1').fetchone()
        if not row: continue
        row = dict(row)
        block = ('Saved comparison is disabled' if not row['enabled'] else
                 'Testing permission expired' if row['expires'] <= now else '')
        if kind == 'gitlab_pair' and (not parent or not parent['enabled'] or parent['expires'] <= now or parent['revision'] != row['parent_revision']):
            block = 'Owner-account approval or connection changed'
        add(kind,1,row['due'],[row['revision'],row['expires'],row['project']],
            'https://hackerone.com/gitlab', 'Owned GitLab '+('two-account comparison' if kind=='gitlab_pair' else 'anonymous comparison'),block,
            stop_detail(row,now) if not row['enabled'] else '')
    validation = c.execute('SELECT * FROM validation_schedule WHERE id=1').fetchone()
    add('owned_validation',1,validation['due'],['owned-loopback-validation-v1'],
        'owned-scopeguard', 'ScopeGuard login and request protection')
    rotations = {r['job']:dict(r) for r in c.execute('SELECT * FROM autonomous_rotation')}
    programs = {r['program']:r['next_allowed'] for r in c.execute('SELECT * FROM autonomous_programs')}
    for job in result:
        old = rotations.get(job['key'], {})
        job['last_started'] = old.get('last_started', 0)
        retry = old.get('retry_at', 0) if old.get('stamp') == job['stamp'] else 0
        job['ready_at'] = max(job['due'], retry, programs.get(job['program'], 0))
    return result


def next_job(c, now=None, supported=KINDS):
    now = int(time.time()) if now is None else now
    if c.execute('SELECT paused FROM settings').fetchone()[0]: return None
    # A focused workflow uses the same global dispatch boundary and program gap.
    if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='hunt_runs'").fetchone():
        if c.execute("SELECT 1 FROM hunt_runs WHERE state='running' AND lease_until>?",(now,)).fetchone():return None
    ready = [j for j in jobs(c,now) if j['kind'] in supported and not j['blocker'] and j['ready_at'] <= now]
    ranks = {'access':0,'gitlab_pair':0,'gitlab':1,'owned_validation':2,'headers':3}
    return min(ready,key=lambda j:(j['last_started'],ranks[j['kind']],j['ready_at'],j['key'])) if ready else None


def evidence(result):
    """Allowlist observations; never retain bodies, identifiers, tokens or errors."""
    clean = []
    rows = result.get('evidence',result.get('checks',[]))
    if not isinstance(rows,list): return []
    for raw in rows[:12]:
        if not isinstance(raw,dict): continue
        row = {}
        # Step labels are generated by the supported runners, not response text.
        for key in ('step','id'):
            if isinstance(raw.get(key),str): row[key] = raw[key][:100]
        for key in ('status','actual_status','expected_status','bytes','response_bytes'):
            if type(raw.get(key)) is int and 0 <= raw[key] <= 1000001: row[key] = raw[key]
        for key in ('json','marker_present','passed','private_state_exposed','private','owner'):
            if type(raw.get(key)) is bool: row[key] = raw[key]
        for key in ('sha256','response_sha256'):
            value = raw.get(key)
            if isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value): row[key] = value
        clean.append(row)
    return clean


def reproduced(kind,result,rows):
    def positive(r):
        return (200 <= r.get('status',0) < 300 and r.get('json') is True
                and r.get('marker_present') is True and 'sha256' in r)
    matrix = ['Account A reads its own resource','Account B reads its own resource',
              'Account B reads account A resource','Repeat account B comparison',
              'Account A reads its own resource','Account B reads its own resource']
    if kind == 'owned_validation':
        checks = {r.get('id'):r for r in rows}
        control = checks.get('control',{})
        if result.get('confirmed_issue') is not True or control.get('actual_status') != 200 or control.get('passed') is not True:
            return False
        for key in ('anonymous-state','wrong-password'):
            pair = [checks.get(k,{}) for k in (key,'repeat-'+key)]
            if all(r.get('actual_status')==200 and r.get('private_state_exposed') is True and 'response_sha256' in r for r in pair):
                return True
        return False
    if result.get('reproduced') is not True: return False
    if kind == 'gitlab':
        labels = ['Verify read-only token','Owner login control','Without login',
                  'Repeat without login','Repeat owner login control']
        return (result.get('verified_connection') is True and [r.get('step') for r in rows]==labels
                and rows[0].get('status')==200 and 'sha256' in rows[0]
                and all(positive(r) for r in rows[1:])
                and all(r.get('private') is True and r.get('owner') is True for r in (rows[1],rows[-1])))
    if kind == 'gitlab_pair':
        if not (result.get('verified_connection') is True and result.get('account_identities_distinct') is True): return False
        if [r.get('step') for r in rows] != ['Verify account A read-only token','Verify account B read-only token']+matrix: return False
        return all(r.get('status')==200 and 'sha256' in r for r in rows[:2]) and all(positive(r) for r in rows[2:])
    labels = matrix if result.get('mode') == 'two_account' else ['Authenticated control','Anonymous comparison','Repeated anonymous comparison','Authenticated control repeated']
    return kind=='access' and [r.get('step') for r in rows]==labels and all(positive(r) for r in rows)


def classify(kind, result):
    if not isinstance(result,dict): return 'skipped'
    if kind == 'headers':
        return {'observations':'observations','no_observation':'no_observation',
                'stopped':'stopped','error':'failed','inconclusive':'inconclusive'}.get(result.get('outcome'),'inconclusive')
    rows = evidence(result)
    if reproduced(kind,result,rows): return 'reproduced_boundary'
    if kind == 'owned_validation':
        if result.get('status') == 'All covered checks passed' and len(rows) == 7 and all(x.get('passed') is True for x in rows):
            return 'boundary_held'
        return 'inconclusive'
    def positive(r):
        return (200 <= r.get('status',0) < 300 and r.get('json') is True
                and r.get('marker_present') is True and 'sha256' in r)
    def denied(r):
        return ('sha256' in r and (r.get('status') in (401,403,404)
                or 200 <= r.get('status',0) < 300 and r.get('json') is True and r.get('marker_present') is False))
    if kind=='access' and result.get('mode')=='anonymous':
        if ([r.get('step') for r in rows]==['Authenticated control','Anonymous comparison']
                and positive(rows[0]) and denied(rows[1])): return 'boundary_held'
    if kind=='gitlab' and result.get('verified_connection') is True:
        if ([r.get('step') for r in rows]==['Verify read-only token','Owner login control','Without login']
                and rows[0].get('status')==200 and 'sha256' in rows[0] and positive(rows[1])
                and rows[1].get('private') is True and rows[1].get('owner') is True
                and rows[2].get('status') in (401,403,404) and denied(rows[2])): return 'boundary_held'
    if kind in ('access','gitlab_pair') and result.get('mode')=='two_account':
        matrix = rows
        if kind=='gitlab_pair':
            if not (result.get('verified_connection') is True and result.get('account_identities_distinct') is True
                    and [r.get('step') for r in rows[:2]]==['Verify account A read-only token','Verify account B read-only token']
                    and all(r.get('status')==200 and 'sha256' in r for r in rows[:2])): return 'inconclusive'
            matrix = rows[2:]
        labels = ['Account A reads its own resource','Account B reads its own resource',
                  'Account B reads account A resource','Account A reads its own resource','Account B reads its own resource']
        if ([r.get('step') for r in matrix]==labels and denied(matrix[2])
                and all(positive(matrix[i]) for i in (0,1,3,4))): return 'boundary_held'
    return 'inconclusive'


def save_case(c,job,observations,now):
    key = digest([job['key'],job['stamp'],'reproduced_boundary'])[:24]
    draft = '\n'.join([
        '# Private investigation draft — eligibility unverified', '',
        job['label'], 'Result: repeated boundary failure reported by the bounded runtime check.',
        'Job: '+job['key'], 'Permission/configuration digest: '+job['stamp'],
        'Evidence: only response hashes, statuses, synthetic-marker booleans and control labels are retained.',
        '', 'Reproduction: use the existing approved profile and its recorded synthetic test resource. '
        'The saved evidence shows the control, comparison and repeated observation order.',
        'Confirm intended access rules, exact scope, actual impact and duplicate status before any report.',
        'This record is not an accepted bounty, payout promise or submission approval.',
        '', json.dumps(observations,indent=2)
    ])
    c.execute('''INSERT INTO autonomous_cases VALUES(?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,evidence=excluded.evidence,draft=excluded.draft''',
      (key,job['key'],job['stamp'],now,now,job['kind'],json.dumps(observations),draft))
    c.execute('DELETE FROM autonomous_cases WHERE id NOT IN (SELECT id FROM autonomous_cases ORDER BY last_seen DESC,id DESC LIMIT 100)')


def tick(db,lock,log,runners):
    if not RUN_LOCK.acquire(blocking=False): return
    try:
        _tick(db,lock,log,runners)
    finally:
        RUN_LOCK.release()


def _tick(db,lock,log,runners):
    now = int(time.time())
    with lock,db() as c:
        c.execute('BEGIN IMMEDIATE')
        c.execute('UPDATE autonomous_status SET heartbeat=? WHERE id=1',(now,))
        programqueue.heartbeat(c,now)
        # An abandoned lease is unknown, not successful. Back off that job;
        # continue other permitted work without immediately repeating the request.
        for r in c.execute("SELECT * FROM autonomous_runs WHERE outcome='running' AND lease_until<=?",(now,)).fetchall():
            c.execute("UPDATE autonomous_runs SET outcome='interrupted',finished=? WHERE id=?",(now,r['id']))
            count_result(c,r['kind'],'interrupted',now)
            c.execute('UPDATE autonomous_rotation SET retry_at=MAX(retry_at,?) WHERE job=?',(now+900,r['job']))
        if c.execute("SELECT 1 FROM autonomous_runs WHERE outcome='running'").fetchone(): return
        job = next_job(c,now,runners)
        if not job: return
        if job['kind'] not in KINDS or job['kind'] not in runners: return
        c.execute('''INSERT INTO autonomous_rotation VALUES(?,?,?,0,0)
          ON CONFLICT(job) DO UPDATE SET stamp=excluded.stamp,last_started=excluded.last_started,
          failures=CASE WHEN stamp=excluded.stamp THEN failures ELSE 0 END''',(job['key'],job['stamp'],now))
        c.execute('INSERT INTO autonomous_programs VALUES(?,?) ON CONFLICT(program) DO UPDATE SET next_allowed=excluded.next_allowed',(job['program'],now+PROGRAM_GAP))
        run = c.execute("INSERT INTO autonomous_runs(job,kind,stamp,started,finished,lease_until,outcome,evidence) VALUES(?,?,?,?,0,?,'running','[]')",
                        (job['key'],job['kind'],job['stamp'],now,now+LEASE_SECONDS)).lastrowid
    result = None
    failed = False
    try:
        # Each runner rechecks its own current scope before individual requests.
        result = runners[job['kind']](job['target'])
    except Exception:
        failed = True
    finished = int(time.time())
    outcome = 'failed' if failed else classify(job['kind'], result)
    clean = evidence(result) if isinstance(result,dict) else []
    with lock,db() as c:
        current = next((j for j in jobs(c,finished) if j['key']==job['key']),None)
        paused = bool(c.execute('SELECT paused FROM settings').fetchone()[0])
        if (paused or not current or current['stamp'] != job['stamp']
                or 'expired' in current['blocker'].lower()):
            outcome = 'inconclusive'
        updated = c.execute("UPDATE autonomous_runs SET finished=?,outcome=?,evidence=? WHERE id=? AND outcome='running'",
                            (finished,outcome,json.dumps(clean),run))
        if not updated.rowcount: return
        count_result(c,job['kind'],outcome,finished)
        if outcome in ('failed','skipped','inconclusive'):
            old = c.execute('SELECT failures FROM autonomous_rotation WHERE job=?',(job['key'],)).fetchone()[0]
            c.execute('UPDATE autonomous_rotation SET failures=failures+1,retry_at=? WHERE job=?',
                      (finished+min(3600,60*2**min(old,6)),job['key']))
        else:
            c.execute('UPDATE autonomous_rotation SET failures=0,retry_at=0 WHERE job=?',(job['key'],))
        c.execute('UPDATE autonomous_programs SET next_allowed=MAX(next_allowed,?) WHERE program=?',(finished+PROGRAM_GAP,job['program']))
        if outcome == 'reproduced_boundary': save_case(c,job,clean,finished)
        import checkpointengine
        checkpointengine.record_runtime(c,job,outcome,clean,finished)
        c.execute("DELETE FROM autonomous_runs WHERE id NOT IN (SELECT id FROM autonomous_runs ORDER BY id DESC LIMIT 200) AND outcome!='running'")
        c.execute('UPDATE autonomous_status SET heartbeat=? WHERE id=1',(finished,))
        log(c,'Automatic runtime task '+job['kind']+': '+outcome+'. Evidence saved; next eligible task will be selected. No report sent.')


def snapshot(c):
    now = int(time.time())
    items = jobs(c,now)
    paused = bool(c.execute('SELECT paused FROM settings').fetchone()[0])
    heartbeat = c.execute('SELECT heartbeat FROM autonomous_status WHERE id=1').fetchone()[0]
    running = c.execute("SELECT job,kind,started,lease_until FROM autonomous_runs WHERE outcome='running' ORDER BY id DESC LIMIT 1").fetchone()
    healthy = bool(heartbeat and 0 <= now-heartbeat < 90 or running and running['lease_until'] > now)
    eligible = [j for j in items if not j['blocker']]
    due = [j for j in eligible if j['ready_at'] <= now]
    state = 'paused' if paused else 'unavailable' if not healthy else 'running' if running else 'ready' if due else 'waiting'
    cases = [{'id':r['id'],'job':r['job'],'kind':r['kind'],'first_seen':r['first_seen'],'last_seen':r['last_seen'],
              'evidence':json.loads(r['evidence']),'draft':r['draft'],'submission_ready':False} for r in c.execute('SELECT * FROM autonomous_cases ORDER BY last_seen DESC LIMIT 30')]
    totals = [dict(r) for r in c.execute('SELECT * FROM autonomous_totals')]
    return {'state':state,'healthy':healthy,'heartbeat':heartbeat,
            'running':dict(running) if running else None,'ready':len(due),'eligible':len(eligible),
            'blocked':sum(bool(j['blocker']) for j in items),
            'next_due':min((j['ready_at'] for j in eligible),default=None),
            'jobs':[{k:j[k] for k in ('key','kind','label','blocker','blocker_detail','ready_at')} for j in items],
            'recent_runs':[dict(r) for r in c.execute('SELECT id,job,kind,started,finished,outcome FROM autonomous_runs ORDER BY id DESC LIMIT 30')],
            'cases':cases,'case_count':c.execute('SELECT COUNT(*) FROM autonomous_cases').fetchone()[0],
            'confirmed_bounty_bugs':0,'automatic_submission':False,
            'progress':{'completed':sum(r['total'] for r in totals if r['outcome'] in COMPLETED),
                        'self_checks':sum(r['total'] for r in totals if r['kind']=='owned_validation' and r['outcome'] in COMPLETED),
                        'unfinished':sum(r['total'] for r in totals if r['outcome'] not in COMPLETED),
                        'last_completed':max((r['last_finished'] for r in totals if r['outcome'] in COMPLETED),default=0),
                        'counting_since':c.execute('SELECT since FROM autonomous_totals_origin WHERE id=1').fetchone()[0],
                        'history_note':'Counts cover this automatic workflow and its retained history. Earlier standalone tests and removed history are not added.'},
            'full_autonomous_bounty_research':False,
            'coverage':'Automatically selects and runs saved header, private-JSON, owned GitLab and owned-app checks. Source review runs separately. New program permission, account enrollment and general exploit discovery are not automated.'}


def diagnostic(c,revision):
    """Minimal host-log health receipt. No target names, URLs, cases or credentials."""
    s = snapshot(c)
    reasons = {}
    details = {}
    kinds = {}
    for job in s['jobs']:
        reason = job['blocker']
        if reason:
            # Reasons are fixed local gate labels, never external response text.
            reasons[reason] = reasons.get(reason,0)+1
            if job['blocker_detail']: details[job['blocker_detail']] = details.get(job['blocker_detail'],0)+1
        else:
            kinds[job['kind']] = kinds.get(job['kind'],0)+1
    return {'kind':'scopeguard_autopilot_health','revision':revision if re.fullmatch('[0-9a-f]{40}',revision or '') else 'unknown',
            'state':s['state'],'healthy':s['healthy'],'ready_jobs':s['ready'],
            'eligible_jobs':s['eligible'],'eligible_kinds':kinds,'blocked_jobs':s['blocked'],
            'blocker_counts':reasons,'blocker_detail_counts':details,'next_due':s['next_due'],
            'running_kind':s['running']['kind'] if s['running'] else None,
            'last_outcome':s['recent_runs'][0]['outcome'] if s['recent_runs'] else None}
