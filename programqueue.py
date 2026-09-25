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


def directory_gate(c, policy, now):
    p = c.execute('SELECT * FROM programs WHERE rtrim(url,\'/\')=?', (policy_key(policy),)).fetchone()
    if not p:
        return 'Program not present in the current directory' if urlsplit(policy).hostname == 'hackerone.com' else ''
    if not p['available'] or p['stage'] == 'dismissed':
        return 'Program unavailable or dismissed'
    s = c.execute('SELECT * FROM discovery_sources WHERE id=?', (p['source'],)).fetchone()
    if not s or not s['last_success'] or s['last_success'] < now-86400 or s['failures']:
        return 'Directory needs a successful refresh; saved permission is not expanded'
    return ''


def eligible(c, now):
    return [dict(t) for t in c.execute('SELECT * FROM targets WHERE enabled=1 AND expires>? ORDER BY due,id', (now,))
            if not directory_gate(c,t['policy'],now)]


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
        rows.append({'name':p['name'],'policy':p['url'],'approved_urls':len(approved),
                     'status':'Skipped: '+reason if reason else 'Paused' if paused else 'Queued for limited checks'})
    next_item = next_target(c,now)
    s.update(paused=paused,healthy=bool(s['heartbeat'] and now-s['heartbeat']<60),
             listed_h1=len(rows),permission_needed=sum(not r['approved_urls'] for r in rows),
             approved_programs=len({policy_key(t['policy']) for t in ready}),due_targets=sum(t['due']<=now for t in ready),
             next_target=next_item['name'] if next_item else None,coverage=COVERAGE,
             rows=rows[:200],rows_total=len(rows),
             attempts=[dict(r) for r in c.execute('SELECT a.*,t.name,t.url FROM program_attempts a LEFT JOIN targets t ON t.id=a.target ORDER BY a.id DESC LIMIT 30')],
             confirmed_payable=0,automatic_submission=False)
    return s
