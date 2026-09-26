"""Rotate existing, scoped HEAD checks. Directory intake never grants permission."""
import time
from urllib.parse import urlsplit

COVERAGE = 'Exact saved URLs: HEAD response headers and an optional approved Origin check only. No full-site or exploit coverage.'


def init(c):
    c.executescript('''
      CREATE TABLE IF NOT EXISTS program_rotation(policy TEXT PRIMARY KEY, last_started INTEGER);
      CREATE TABLE IF NOT EXISTS program_attempts(id INTEGER PRIMARY KEY, target INTEGER, policy TEXT,
        started INTEGER, finished INTEGER, outcome TEXT, observations INTEGER);
      CREATE TABLE IF NOT EXISTS program_queue_status(id INTEGER PRIMARY KEY, heartbeat INTEGER, completed INTEGER);
      INSERT OR IGNORE INTO program_queue_status VALUES(1,0,0);
    ''')


def heartbeat(c, now):
    c.execute('UPDATE program_queue_status SET heartbeat=? WHERE id=1', (now,))
    # A crash is inconclusive, never a successful test with zero findings.
    c.execute("UPDATE program_attempts SET outcome='interrupted',finished=? WHERE outcome='running' AND started<?", (now,now-180))


def policy_key(url):
    return url.rstrip('/')


def automation_blocker(policy, url=''):
    """Restrictive standing policy; this never grants testing permission."""
    p = urlsplit(policy)
    hosts = ((urlsplit(url).hostname or '').lower(), (p.hostname or '').lower())
    if (any(h in ('mozilla.org','mozilla.com') or h.endswith(('.mozilla.org','.mozilla.com')) for h in hosts)
            or p.hostname == 'hackerone.com' and p.path.strip('/').split('/')[0] == 'mozilla'):
        return 'Mozilla automated production testing is blocked'
    return ''


def directory_source_blocker(source, now):
    if not source:
        return 'HackerOne directory source is not configured'
    if source['failures']:
        return 'Last HackerOne directory refresh failed; waiting for a successful refresh'
    if not source['last_success']:
        return 'HackerOne directory has never completed a successful refresh'
    if source['last_success'] < now-86400:
        return 'HackerOne directory evidence is older than 24 hours'
    return ''


def directory_gate(c, policy, now):
    if automation_blocker(policy): return automation_blocker(policy)
    p = c.execute('SELECT * FROM programs WHERE rtrim(url,\'/\')=?', (policy_key(policy),)).fetchone()
    if not p:
        return 'Program not present in the current directory' if urlsplit(policy).hostname == 'hackerone.com' else ''
    if not p['available'] or p['stage'] == 'dismissed':
        return 'Program unavailable or dismissed'
    s = c.execute('SELECT * FROM discovery_sources WHERE id=?', (p['source'],)).fetchone()
    if directory_source_blocker(s,now):
        return 'Directory needs a successful refresh; saved permission is not expanded'
    return ''


def target_gate(c, target, now):
    return automation_blocker(target['policy'],target['url']) or directory_gate(c,target['policy'],now)


def eligible(c, now):
    return [dict(t) for t in c.execute('SELECT * FROM targets WHERE enabled=1 AND expires>? ORDER BY due,id', (now,))
            if not target_gate(c,t,now)]


def next_target(c, now=None):
    now = int(time.time()) if now is None else now
    if c.execute('SELECT paused FROM settings').fetchone()[0]:
        return None
    visited = {r['policy']:r['last_started'] for r in c.execute('SELECT * FROM program_rotation')}
    due = [t for t in eligible(c,now) if t['due'] <= now]
    return min(due, key=lambda t:(visited.get(policy_key(t['policy']),0),t['due'],t['id'])) if due else None


def begin(c, target, now):
    key = policy_key(target['policy'])
    c.execute('INSERT INTO program_rotation VALUES(?,?) ON CONFLICT(policy) DO UPDATE SET last_started=excluded.last_started', (key,now))
    cursor = c.execute("INSERT INTO program_attempts(target,policy,started,finished,outcome,observations) VALUES(?,?,?,0,'running',0)", (target['id'],key,now))
    c.execute('DELETE FROM program_attempts WHERE id NOT IN (SELECT id FROM program_attempts ORDER BY id DESC LIMIT 100)')
    return cursor.lastrowid


def finish(c, attempt, outcome, observations=0):
    if attempt is None:
        return
    if outcome not in ('observations','no_observation','stopped','error','inconclusive'):
        raise ValueError('Unknown queue outcome')
    changed = c.execute("UPDATE program_attempts SET finished=?,outcome=?,observations=? WHERE id=? AND outcome='running'", (int(time.time()),outcome,observations,attempt)).rowcount
    if changed and outcome in ('observations','no_observation'):
        c.execute('UPDATE program_queue_status SET completed=completed+1 WHERE id=1')


def snapshot(c):
    now = int(time.time())
    s = dict(c.execute('SELECT * FROM program_queue_status WHERE id=1').fetchone())
    paused = bool(c.execute('SELECT paused FROM settings').fetchone()[0])
    ready = eligible(c,now)
    targets = [dict(t) for t in c.execute('SELECT * FROM targets')]
    rows = []
    for p in c.execute("SELECT * FROM programs WHERE source='hackerone' ORDER BY name"):
        linked = [t for t in targets if policy_key(t['policy']) == policy_key(p['url'])]
        approved = [t for t in ready if policy_key(t['policy']) == policy_key(p['url'])]
        reason = directory_gate(c,p['url'],now)
        if not reason and not approved:
            reason = 'No saved exact URL with current scope and automation permission' if not linked else 'Saved targets are disabled or their permission expired'
        due = sum(t['due'] <= now for t in approved)
        next_due = min((t['due'] for t in approved), default=None)
        status = ('Skipped: '+reason if reason else 'Paused' if paused else
                  'Queued for limited checks' if due else 'Waiting for scheduled check')
        rows.append({'name':p['name'],'policy':p['url'],'approved_urls':len(approved),
                     'due_urls':due,'next_due':next_due,'status':status})
    next_item = next_target(c,now)
    h1_source = c.execute("SELECT * FROM discovery_sources WHERE id='hackerone'").fetchone()
    h1_blocker = directory_source_blocker(h1_source,now)
    healthy = bool(s['heartbeat'] and 0 <= now-s['heartbeat'] < 60)
    due_count = sum(t['due'] <= now for t in ready)
    queue_state = ('paused' if paused else 'worker_unavailable' if not healthy else
                   'no_eligible_targets' if not ready else 'waiting_schedule' if not due_count else 'ready')
    s.update(paused=paused,healthy=healthy,
             listed_h1=len(rows),permission_needed=sum(not r['approved_urls'] for r in rows),
             approved_programs=len({policy_key(t['policy']) for t in ready}),due_targets=due_count,
             next_target=next_item['name'] if next_item else None,coverage=COVERAGE,
             rows=rows[:200],rows_total=len(rows),
             attempts=[dict(r) for r in c.execute('SELECT a.*,t.name,t.url FROM program_attempts a LEFT JOIN targets t ON t.id=a.target ORDER BY a.id DESC LIMIT 30')],
             confirmed_payable=0,automatic_submission=False)
    s.update(queue_state=queue_state,
             saved_targets=len(targets),eligible_targets=len(ready),
             disabled_targets=sum(not t['enabled'] for t in targets),
             expired_targets=sum(bool(t['enabled']) and t['expires']<=now for t in targets),
             directory_blocked_targets=sum(bool(t['enabled']) and t['expires']>now and
                                           bool(target_gate(c,t,now)) for t in targets),
             waiting_targets=len(ready)-due_count,
             next_due=min((t['due'] for t in ready),default=None),
             directory_source={
                 'id':'hackerone',
                 'status':h1_source['status'] if h1_source else 'Not configured',
                 'last_attempt':h1_source['last_attempt'] if h1_source else 0,
                 'last_success':h1_source['last_success'] if h1_source else 0,
                 'failures':h1_source['failures'] if h1_source else 0,
                 'blocked':bool(h1_blocker),
                 'blocker':h1_blocker or None})
    return s
