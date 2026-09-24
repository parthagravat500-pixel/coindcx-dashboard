import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from engine import validate_url, observe, findings
import supervisor
import workflow
import sourceaudit
import workqueue
import casework
import connections
import reporting

ROOT = Path(__file__).parent
DATA = Path(os.environ.get('DATA_DIR', str(ROOT / 'data')))
DATA.mkdir(parents=True, exist_ok=True)
TOKEN = os.environ.get('ADMIN_PASSWORD', '')
CSRF = secrets.token_urlsafe(32)
LOCK = threading.Lock()
WAKE = threading.Event()


@contextmanager
def db():
    c = sqlite3.connect(DATA / 'bounty.db', timeout=30)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with db() as c:
        c.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, paused INTEGER);
        INSERT OR IGNORE INTO settings VALUES (1,1);
        CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, name TEXT, url TEXT UNIQUE,
        policy TEXT, rules TEXT, expires INTEGER, interval INTEGER, cors INTEGER,
        enabled INTEGER DEFAULT 1, due INTEGER DEFAULT 0, state TEXT DEFAULT 'Waiting', failures INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, target INTEGER, rule TEXT, title TEXT,
        evidence TEXT, severity TEXT, impact TEXT, first_seen INTEGER, last_seen INTEGER,
        feedback TEXT DEFAULT 'unreviewed');
        CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, at INTEGER, message TEXT);
        ''')
        sourceaudit.init(c)
        casework.init(c)
        supervisor.init(c)
        workflow.init(c)
        reporting.init(c)
        workqueue.init(c)
        # Initial install is paused. Explicit operator state survives restarts;
        # expired target authorizations remain blocked independently.


def log(c, message):
    c.execute('INSERT INTO events(at,message) VALUES (?,?)', (int(time.time()), message))
    c.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 500)')


def allowed(target_id):
    with db() as c:
        t = c.execute('SELECT * FROM targets WHERE id=?', (target_id,)).fetchone()
        return bool(t and t['enabled'] and t['expires'] > time.time() and not c.execute('SELECT paused FROM settings').fetchone()[0])


def tick():
    with db() as c:
        if c.execute('SELECT paused FROM settings').fetchone()[0]:
            return
        t = c.execute('SELECT * FROM targets WHERE enabled=1 AND expires>? AND due<=? ORDER BY due,id LIMIT 1', (time.time(), time.time())).fetchone()
    if not t:
        return
    # Lock serializes operator pause/revoke with dispatch; a request already sent may finish.
    try:
        with LOCK:
            if not allowed(t['id']):
                return
            with db() as c:
                c.execute('UPDATE targets SET due=?,state=? WHERE id=?', (int(time.time()) + t['interval'], 'Checking', t['id']))
                log(c, 'HEAD check started for target ' + str(t['id']))
            observation = observe(t['url'])
        cors = None
        if t['cors'] and 200 <= observation['status'] < 300:
            WAKE.wait(10)
            with LOCK:
                if allowed(t['id']):
                    cors = observe(t['url'], 'https://scopeguard.invalid')
        status = max(observation['status'], cors['status'] if cors else 0)
        now = int(time.time())
        with db() as c:
            if status in (401, 403, 429) or status >= 500:
                c.execute('UPDATE targets SET enabled=0,state=? WHERE id=?', ('Stopped: HTTP ' + str(status) + '; review program rules before enabling', t['id']))
                log(c, 'Automatic stop for target ' + str(t['id']) + ': HTTP ' + str(status))
                return
            for f in findings(observation, cors):
                key = hashlib.sha256((str(t['id']) + ':' + f['rule']).encode()).hexdigest()[:24]
                evidence = json.dumps({'observation': observation, 'cors_observation': cors, 'note': f['evidence']})
                c.execute('''INSERT INTO findings(id,target,rule,title,evidence,severity,impact,first_seen,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,evidence=excluded.evidence''',
                          (key, t['id'], f['rule'], f['title'], evidence, f['severity'], f['impact'], now, now))
                supervisor.record(c, key, now)
            c.execute('UPDATE targets SET state=?,failures=0 WHERE id=?', ('Checked HTTP ' + str(status) + ' at ' + time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(now)), t['id']))
            log(c, 'Check completed for target ' + str(t['id']))
    except Exception as e:
        with db() as c:
            count = t['failures'] + 1
            c.execute('UPDATE targets SET failures=?,due=?,enabled=CASE WHEN ?>=3 THEN 0 ELSE enabled END,state=? WHERE id=?',
                      (count, int(time.time()) + min(86400, t['interval'] * 2 ** count), count, 'Check failed (' + type(e).__name__ + '). Review URL, network and TLS; stopped after 3 failures.', t['id']))
            log(c, 'Target ' + str(t['id']) + ' failed: ' + type(e).__name__)


def worker():
    while True:
        try:
            tick()
        except Exception:
            # Preserve scheduler availability without exposing exception contents.
            pass
        WAKE.wait(10)


def reporting_worker():
    while True:
        try:
            with LOCK:
                reporting.tick(db, DATA)
        except Exception:
            pass
        WAKE.wait(60)


def discovery_worker():
    while True:
        try:
            workflow.tick(db)
            workflow.ai_tick(db)
        except Exception:
            pass
        WAKE.wait(30)


def supervisor_worker():
    while True:
        try:
            supervisor.ai_tick(db)
        except Exception:
            pass
        WAKE.wait(30)


def queue_worker():
    while True:
        try:
            with LOCK:
                workqueue.tick(db, log)
                with db() as c:
                    if not c.execute('SELECT paused FROM settings').fetchone()[0]:
                        count=sourceaudit.installed(c,ROOT)
                        if count:log(c,'Source audit completed for '+str(count)+' changed ScopeGuard Python files; pattern matches require review.')
        except Exception:
            with db() as c:
                c.execute("UPDATE background_status SET status='Review failed; retrying on next cycle' WHERE id=1")
        WAKE.wait(10)


def snapshot():
    with db() as c:
        targets = [dict(r) for r in c.execute('SELECT * FROM targets')]
        items = [dict(r) for r in c.execute('SELECT * FROM findings ORDER BY last_seen DESC')]
        # Feedback updates ranking only, never scope, techniques, rate or executable code.
        counts = {}
        for f in items:
            pos, neg = counts.get(f['rule'], (0, 0))
            counts[f['rule']] = (pos + (f['feedback'] == 'accepted'), neg + (f['feedback'] in ('false_positive', 'ineligible')))
        for f in items:
            p, n = counts[f['rule']]
            f['review_priority'] = round((p + 1) / (p + n + 2), 3)
            target = next(t for t in targets if t['id'] == f['target'])
            f['supervisor'] = supervisor.review(c, f, target)
            ai = c.execute('SELECT status,note FROM supervisor_ai WHERE finding=? ORDER BY at DESC LIMIT 1', (f['id'],)).fetchone()
            f['supervisor']['ai_review'] = dict(ai) if ai else None
            f['casework'] = casework.assess(c, f, f['supervisor'])
        return {'paused': bool(c.execute('SELECT paused FROM settings').fetchone()[0]), 'targets': targets,
                'findings': sorted(items, key=lambda f: (f['casework']['priority'], f['review_priority']), reverse=True),
                'supervisor': supervisor.summary(),
                'workflow': workflow.snapshot(c),
                'connection': connections.status(),
                'background': workqueue.snapshot(c),
                'source_audits': sourceaudit.snapshot(c),
                'reporting': reporting.snapshot(c, DATA),
                'events': [dict(r) for r in c.execute('SELECT * FROM events ORDER BY id DESC LIMIT 30')], 'csrf': CSRF}


def mutate(path, data):
    if path in ('/api/reporting/connect', '/api/reporting/disconnect'):
        with LOCK:
            if path.endswith('/connect'):
                reporting.connect(DATA, data)
            else:
                reporting.save(DATA, {'enabled': False})
        return
    if path in ('/api/ai/connect', '/api/ai/disconnect'):
        with LOCK:
            if path == '/api/ai/connect':
                connections.connect(DATA, data)
            else:
                connections.disconnect(DATA)
        return
    with LOCK, db() as c:
        if path.startswith('/api/discovery/') or path in ('/api/program-stage', '/api/submissions/record'):
            workflow.mutate(c, path, data)
        elif path == '/api/source-audit':
            sourceaudit.upload(c, data)
            log(c, 'Uploaded Python source audited; code was not stored or executed.')
        elif path == '/api/evidence':
            casework.save(c, data)
        elif path == '/api/all-pause':
            if not isinstance(data.get('paused'), bool):
                raise ValueError('Choose pause or resume')
            c.execute('UPDATE settings SET paused=?', (int(data['paused']),))
            c.execute('UPDATE discovery_settings SET enabled=?', (int(not data['paused']),))
            log(c, 'All workers paused' if data['paused'] else 'Discovery and approved checks resumed')
        elif path == '/api/pause':
            c.execute('UPDATE settings SET paused=?', (int(bool(data['paused'])),))
            log(c, 'Scheduler paused' if data['paused'] else 'Scheduler resumed')
        elif path == '/api/targets':
            validate_url(data['url'])
            validate_url(data['policy'])
            if not data.get('authorized') or not data.get('automation_allowed'):
                raise ValueError('Confirm written authorization and permission for these automated checks.')
            if len(data.get('rules', '').strip()) < 30:
                raise ValueError('Record the applicable scope, exclusions and rate limits (at least 30 characters).')
            expires = int(data['expires'])
            if not time.time() < expires <= time.time() + 7 * 86400:
                raise ValueError('Authorization review must expire within seven days.')
            interval = int(data['interval'])
            if interval < 3600 or interval > 604800:
                raise ValueError('Check interval must be 1–168 hours.')
            c.execute('INSERT INTO targets(name,url,policy,rules,expires,interval,cors) VALUES (?,?,?,?,?,?,?)',
                      (data['name'][:100], data['url'], data['policy'], data['rules'][:8000], expires, interval, int(bool(data.get('cors')))))
            log(c, 'Added exact URL with authorization attestation: ' + data['url'])
        elif path == '/api/target-schedule':
            if data.get('reviewed') is not True:
                raise ValueError('Review the program automation policy before changing frequency.')
            interval = data.get('interval')
            if type(interval) is not int or not 300 <= interval <= 604800:
                raise ValueError('Check interval must be 5 minutes to 168 hours.')
            rules = data.get('rules', '')
            if not isinstance(rules, str) or not 30 <= len(rules.strip()) <= 8000:
                raise ValueError('Record the reviewed scope and rate limits.')
            target = c.execute('SELECT * FROM targets WHERE id=?', (int(data['id']),)).fetchone()
            if not target or not target['enabled'] or target['expires'] <= time.time():
                raise ValueError('Only active targets with current permission can be rescheduled.')
            delay = data.get('start_delay', 0)
            if type(delay) is not int or not 0 <= delay <= interval:
                raise ValueError('Invalid stagger delay')
            c.execute('UPDATE targets SET interval=?,due=?,rules=? WHERE id=?',
                      (interval, int(time.time()) + delay, rules.strip(), target['id']))
            log(c, 'Schedule updated for ' + target['name'] + ': every ' + str(interval // 60) + ' minutes; scope unchanged.')
        elif path == '/api/target-state':
            c.execute('UPDATE targets SET enabled=? WHERE id=?', (int(bool(data['enabled'])), int(data['id'])))
            log(c, 'Target ' + str(int(data['id'])) + ' enabled=' + str(bool(data['enabled'])))
        elif path == '/api/renew':
            if not data.get('reviewed'):
                raise ValueError('Re-read program policy before renewing.')
            c.execute('UPDATE targets SET expires=? WHERE id=?', (int(time.time()) + 86400, int(data['id'])))
            log(c, 'Authorization reviewed and renewed for target ' + str(int(data['id'])) + ' for 24 hours')
        elif path == '/api/feedback':
            if data['feedback'] not in ('unreviewed', 'validated', 'accepted', 'duplicate', 'false_positive', 'ineligible'):
                raise ValueError('Invalid feedback')
            c.execute('UPDATE findings SET feedback=? WHERE id=?', (data['feedback'], data['id']))
            log(c, 'Finding feedback updated: ' + data['feedback'])
        else:
            raise ValueError('Unknown action')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, content, mime='application/json'):
        raw = content.encode()
        self.send_response(status)
        self.send_header('Content-Type', mime + '; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(raw)

    def authenticate(self):
        try:
            supplied = base64.b64decode(self.headers.get('Authorization', '').split(' ', 1)[1]).decode()
            okay = hmac.compare_digest(supplied.encode(), ('admin:' + TOKEN).encode())
        except Exception:
            okay = False
        if not okay:
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="ScopeGuard"')
            self.send_header('Content-Length', '0')
            self.end_headers()
        return okay

    def do_GET(self):
        if self.path == '/healthz':
            return self.reply(200, '{"ok":true}')
        if not self.authenticate():
            return
        if self.path == '/api/state':
            return self.reply(200, json.dumps(snapshot()))
        assets = {'/': ('index.html', 'text/html'), '/ui.js': ('ui.js', 'text/javascript'), '/style.css': ('style.css', 'text/css')}
        if self.path in assets:
            filename, mime = assets[self.path]
            return self.reply(200, (ROOT / filename).read_text(), mime)
        if self.path.startswith('/report/'):
            key = self.path.removeprefix('/report/')
            with db() as c:
                f = c.execute('SELECT f.*,t.url,t.policy,t.rules FROM findings f JOIN targets t ON t.id=f.target WHERE f.id=?', (key,)).fetchone()
            if f:
                with db() as c:
                    target = dict(c.execute('SELECT * FROM targets WHERE id=?', (f['target'],)).fetchone())
                    review = supervisor.review(c, dict(f), target)
                    case = casework.assess(c, dict(f), review)
                report = '\n'.join(['# DRAFT — manual review required', '', f['title'], 'URL: ' + f['url'], 'Policy: ' + f['policy'],
                    'Recorded scope/rules: ' + f['rules'], 'Status: ' + f['feedback'], 'Severity: Informational; no impact established',
                    '', '## Reproduction', 'Only if current authorization permits: send HEAD to the exact URL above.',
                    'For CORS observations only, include Origin: https://scopeguard.invalid.', 'Redirects are not followed.',
                    '', '## Evidence (cookie values and response bodies are not retained)', f['evidence'], '',
                    '## Impact', f['impact'], '', '## Supervisor review', review['status'], review['reason'],
                    'Independent observations: ' + str(review['repeat_count']) + '/3',
                    'Reporting channel: ' + review['channel']['name'] + ' ' + review['channel']['url'],
                    'Not submitted. AI or repeated headers cannot establish security impact.', '', '## Before submission',
                    'Confirm current scope and eligibility. Establish reproducible security impact. Check duplicates. Add remediation. Submit privately through the program channel.'])
                report += casework.report_section(case)
                return self.reply(200, report, 'text/plain')
        self.reply(404, '{"error":"Not found"}')

    def do_POST(self):
        if not self.authenticate():
            return
        if not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), CSRF):
            return self.reply(403, '{"error":"Refresh the dashboard and try again"}')
        try:
            size = int(self.headers.get('Content-Length', '0'))
            limit=800000 if self.path == '/api/source-audit' else 16000
            if size < 1 or size > limit:
                raise ValueError('Invalid request size')
            mutate(self.path, json.loads(self.rfile.read(size)))
            self.reply(200, '{"ok":true}')
        except (ValueError, KeyError, TypeError, sqlite3.IntegrityError) as e:
            self.reply(400, json.dumps({'error': str(e)}))


if __name__ == '__main__':
    if len(TOKEN) < 24:
        raise SystemExit('Set ADMIN_PASSWORD to a unique password of at least 24 characters.')
    connections.load(DATA)
    init()
    threading.Thread(target=queue_worker, daemon=True).start()
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=supervisor_worker, daemon=True).start()
    threading.Thread(target=discovery_worker, daemon=True).start()
    threading.Thread(target=reporting_worker, daemon=True).start()
    server = ThreadingHTTPServer((os.environ.get('BIND', '127.0.0.1'), int(os.environ.get('PORT', '8080'))), Handler)
    print('ScopeGuard dashboard ready. New installations start paused.', flush=True)
    server.serve_forever()
