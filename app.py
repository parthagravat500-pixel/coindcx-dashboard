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
import projectaudit
import sourcewatch
import dependencies
import validation
import accesscheck
import capitaldemo
import gitlabcheck
import workqueue
import casework
import connections
import reporting
import research
import programqueue
import uberconnect
import autoresearch
import autopilot
import leadwork
import programapi
import programresearch

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
        projectaudit.init(c)
        sourcewatch.init(c)
        dependencies.init(c)
        validation.init(c)
        accesscheck.init(c)
        capitaldemo.init(c)
        gitlabcheck.init(c)
        casework.init(c)
        supervisor.init(c)
        workflow.init(c)
        reporting.init(c)
        workqueue.init(c)
        research.init(c)
        programqueue.init(c)
        autoresearch.init(c)
        autopilot.init(c)
        leadwork.init(c)
        programresearch.init(c)
        # Initial install is paused. Explicit operator state survives restarts;
        # expired target authorizations remain blocked independently.


def log(c, message):
    c.execute('INSERT INTO events(at,message) VALUES (?,?)', (int(time.time()), message))
    c.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 500)')


def allowed(target_id):
    with db() as c:
        t = c.execute('SELECT * FROM targets WHERE id=?', (target_id,)).fetchone()
        return bool(t and t['enabled'] and t['expires'] > time.time() and not c.execute('SELECT paused FROM settings').fetchone()[0]
                    and not programqueue.target_gate(c,t,int(time.time())))


def tick(target_id=None):
    with db() as c:
        programqueue.heartbeat(c, int(time.time()))
        if c.execute('SELECT paused FROM settings').fetchone()[0]:
            return
        t = programqueue.next_target(c) if target_id is None else next((x for x in programqueue.eligible(c,int(time.time())) if x['id']==target_id and x['due']<=time.time()),None)
    if not t:
        return
    attempt = None
    # Lock serializes operator pause/revoke with dispatch; a request already sent may finish.
    try:
        with LOCK:
            if not allowed(t['id']):
                return
            with db() as c:
                if programqueue.directory_gate(c,t['policy'],int(time.time())):
                    return
                c.execute('UPDATE targets SET due=?,state=? WHERE id=?', (int(time.time()) + t['interval'], 'Checking', t['id']))
                attempt = programqueue.begin(c,t,int(time.time()))
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
                programqueue.finish(c,attempt,'stopped')
                c.execute('UPDATE targets SET enabled=0,state=? WHERE id=?', ('Stopped: HTTP ' + str(status) + '; review program rules before enabling', t['id']))
                log(c, 'Automatic stop for target ' + str(t['id']) + ': HTTP ' + str(status))
                return {'outcome':'stopped'}
            leads = findings(observation, cors)
            for f in leads:
                key = hashlib.sha256((str(t['id']) + ':' + f['rule']).encode()).hexdigest()[:24]
                evidence = json.dumps({'observation': observation, 'cors_observation': cors, 'note': f['evidence']})
                c.execute('''INSERT INTO findings(id,target,rule,title,evidence,severity,impact,first_seen,last_seen)
                VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,evidence=excluded.evidence''',
                          (key, t['id'], f['rule'], f['title'], evidence, f['severity'], f['impact'], now, now))
                supervisor.record(c, key, now)
            c.execute('UPDATE targets SET state=?,failures=0 WHERE id=?', ('Checked HTTP ' + str(status) + ' at ' + time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(now)), t['id']))
            complete = 200 <= status < 300 and (not t['cors'] or cors is not None)
            programqueue.finish(c,attempt,('observations' if leads else 'no_observation') if complete else 'inconclusive',len(leads))
            log(c, 'Check completed for target ' + str(t['id']))
            return {'outcome':('observations' if leads else 'no_observation') if complete else 'inconclusive'}
    except Exception as e:
        with db() as c:
            programqueue.finish(c,attempt,'error')
            count = t['failures'] + 1
            c.execute('UPDATE targets SET failures=?,due=?,enabled=CASE WHEN ?>=3 THEN 0 ELSE enabled END,state=? WHERE id=?',
                      (count, int(time.time()) + min(86400, t['interval'] * 2 ** count), count, 'Check failed (' + type(e).__name__ + '). Review URL, network and TLS; stopped after 3 failures.', t['id']))
            log(c, 'Target ' + str(t['id']) + ' failed: ' + type(e).__name__)
        return {'outcome':'error'}


def worker():
    while True:
        try:
            tick()
        except Exception:
            # Preserve scheduler availability without exposing exception contents.
            pass
        WAKE.wait(10)


def autonomous_worker(port):
    runners = {
        'headers': lambda target: tick(target),
        'access': lambda target: accesscheck.tick(db,DATA,log,target),
        'gitlab': lambda target: gitlabcheck.primary_tick(db,DATA,log),
        'gitlab_pair': lambda target: gitlabcheck.gitlabpair.tick(db,DATA,log),
        'owned_validation': lambda target: validation.tick(db,log,port,TOKEN),
    }
    next_receipt = 0
    while True:
        try:
            autopilot.tick(db,LOCK,log,runners)
            if time.time() >= next_receipt:
                with db() as c:
                    receipt = autopilot.diagnostic(c,os.environ.get('RENDER_GIT_COMMIT',''))
                print(json.dumps(receipt),flush=True)
                next_receipt = time.time()+300
        except Exception:
            # Only a fixed error label reaches host logs, never exception text.
            print('{"kind":"scopeguard_autopilot_health","state":"worker_error"}',flush=True)
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


def program_research_worker():
    next_receipt=0
    while True:
        try:
            programresearch.tick(db,DATA,LOCK)
            if time.time()>=next_receipt:
                with db() as c:
                    print(json.dumps(programresearch.receipt(c,DATA,os.environ.get('RENDER_GIT_COMMIT',''))),flush=True)
                next_receipt=time.time()+300
        except Exception:
            # No external error text or credentials enter events or host logs.
            with db() as c:log(c,'Program research could not advance; saved evidence retained.')
        WAKE.wait(programresearch.INTERVAL)


def supervisor_worker():
    while True:
        try:
            supervisor.ai_tick(db)
        except Exception:
            pass
        WAKE.wait(30)


def access_worker():
    while True:
        try:
            accesscheck.tick(db, DATA, log)
        except Exception:
            pass
        WAKE.wait(30)


def validation_worker(port):
    while True:
        try:
            validation.tick(db, log, port, TOKEN)
        except Exception:
            pass
        WAKE.wait(30)


def gitlab_worker():
    while True:
        try:
            gitlabcheck.tick(db, DATA, log)
        except Exception:
            pass
        WAKE.wait(30)


def capital_worker():
    while True:
        try:
            capitaldemo.tick(db, DATA, log)
        except Exception:
            pass
        WAKE.wait(30)


def dependency_worker():
    while True:
        try:
            dependencies.tick(db, log)
        except Exception:
            pass
        WAKE.wait(30)


def queue_worker():
    next_lead_receipt = 0
    while True:
        try:
            with LOCK:
                workqueue.tick(db, log)
                with db() as c:
                    autoresearch.tick(c, ROOT, log)
                    leadwork.sync(c)
                    if time.time() >= next_lead_receipt:
                        print(json.dumps(leadwork.receipt(c,os.environ.get('RENDER_GIT_COMMIT',''))),flush=True)
                        next_lead_receipt = time.time()+300
        except Exception:
            with db() as c:
                c.execute("UPDATE background_status SET status='Review failed; retrying on next cycle' WHERE id=1")
        WAKE.wait(10)


def source_watch_worker():
    while True:
        try:
            sourcewatch.tick(db, LOCK, log)
        except Exception:
            with db() as c:
                log(c, 'Source watch worker failed; previous results retained. Retrying on next cycle.')
        WAKE.wait(15)


def research_worker():
    while True:
        try:
            research.tick(db)
        except Exception:
            pass
        WAKE.wait(60)


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
                'uber_connection': uberconnect.manager.status(),
                'background': workqueue.snapshot(c),
                'program_queue': programqueue.snapshot(c),
                'source_audits': sourceaudit.snapshot(c),
                'project_audits': projectaudit.snapshot(c),
                'automatic_research': autoresearch.snapshot(c),
                'autopilot': autopilot.snapshot(c),
                'lead_inbox': leadwork.snapshot(c),
                'program_research': programresearch.snapshot(c,DATA),
                'source_watch': sourcewatch.snapshot(c),
                'research': research.snapshot(c),
                'dependency_projects': dependencies.snapshot(c),
                'validation': validation.snapshot(c),
                'access_checks': accesscheck.snapshot(c),
                'capital_demo': capitaldemo.snapshot(c),
                'gitlab': gitlabcheck.snapshot(c),
                'reporting': reporting.snapshot(c, DATA),
                'events': [dict(r) for r in c.execute('SELECT * FROM events ORDER BY id DESC LIMIT 30')], 'csrf': CSRF}


def mutate(path, data):
    if path in ('/api/program-api/connect','/api/program-api/disconnect'):
        with LOCK:
            if path.endswith('/connect'):programapi.connect(DATA,data)
            else:programapi.save(DATA,data.get('provider'),{'enabled':False})
        return
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
        elif path == '/api/gitlab/connect':
            gitlabcheck.configure(c,DATA,data)
            log(c,'GitLab project configured; connection verification queued.')
        elif path == '/api/gitlab/disconnect':
            gitlabcheck.disconnect(c,DATA)
        elif path == '/api/gitlab/retry':
            gitlabcheck.retry_saved(c,DATA)
            log(c,'GitLab saved project recovery queued; existing permission and scope retained.')
        elif path == '/api/research-triage':
            research.triage(c,data)
            log(c,'Private AI hypothesis review saved. No bug confirmation or report submission.')
        elif path == '/api/capital-demo/connect':
            capitaldemo.configure(c,DATA,data)
            log(c,'Capital.com demo test configured; awaiting worker.')
        elif path == '/api/capital-demo/disconnect':
            capitaldemo.disconnect(c,DATA)
        elif path == '/api/access-check':
            accesscheck.configure(c,DATA,data)
            log(c,'Private-data access comparison configured for an approved target.')
        elif path == '/api/access-check/remove':
            accesscheck.remove(c,DATA,data.get('target'))
        elif path == '/api/validation/run':
            validation.queue(c)
        elif path == '/api/dependencies':
            dependencies.upload(c, data)
            log(c, 'Dependency inventory queued; original file not retained.')
        elif path == '/api/dependencies/delete':
            c.execute('DELETE FROM dependency_projects WHERE name=?',(data.get('project'),))
        elif path == '/api/project-audit':
            projectaudit.upload(c,data)
            log(c,'Project code reviewed; see file-and-line paths in Project research. No report sent.')
        elif path == '/api/project-research-note':
            projectaudit.save_note(c,data)
        elif path == '/api/source-watch':
            sourcewatch.configure(c,data)
            log(c,'Public-source monitoring configured; no live-target testing authorized by this connection.')
        elif path == '/api/source-watch/disable':
            sourcewatch.disable(c,data.get('id'))
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

    def reply(self, status, content, mime='application/json', headers=None):
        raw = content.encode()
        self.send_response(status)
        self.send_header('Content-Type', mime + '; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
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
        callback_path, _, callback_query = self.path.partition('?')
        if callback_path == uberconnect.CALLBACK_PATH:
            try:
                uberconnect.manager.complete(callback_query, self.headers.get('Cookie', ''))
            except ValueError:
                return self.reply(400, '<p>Uber connection was not completed.</p><p><a href="/">Return to ScopeGuard</a></p>', 'text/html')
            return self.reply(303, '', headers={'Location': '/#uberConnectionCard',
                                               'Set-Cookie': uberconnect.cookie(clear=True)})
        if self.path == '/api/state':
            return self.reply(200, json.dumps(snapshot()))
        if self.path.startswith('/api/program-research?'):
            from urllib.parse import parse_qs
            try:
                identity=parse_qs(self.path.split('?',1)[1]).get('id',[''])[0]
                if len(identity)!=24:raise ValueError()
                with db() as c:result=programresearch.detail(c,identity)
                return self.reply(200,json.dumps(result))
            except ValueError:return self.reply(404,'{"error":"Program research record not found"}')
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
        if self.path == '/api/ci-review':
            if not research.admit_request():
                return self.reply(429, '{"error":"Too many receipt attempts"}')
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 1 <= size <= 32000:
                    return self.reply(400, '{"error":"Invalid receipt size"}')
                auth = self.headers.get('Authorization','')
                if not auth.startswith('Bearer '):
                    return self.reply(401, '{"error":"Workload identity required"}')
                claims = research.claims_for(auth[7:])
                self.connection.settimeout(10)
                payload = json.loads(self.rfile.read(size))
                with LOCK, db() as c:
                    result = research.receive(c, claims, payload)
                return self.reply(200, json.dumps(result))
            except Exception:
                return self.reply(403, '{"error":"Receipt could not be verified"}')
        if not self.authenticate():
            return
        if not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), CSRF):
            return self.reply(403, '{"error":"Refresh the dashboard and try again"}')
        try:
            size = int(self.headers.get('Content-Length', '0'))
            limit=3000000 if self.path in ('/api/dependencies','/api/project-audit') else 800000 if self.path == '/api/source-audit' else 16000
            if size < 1 or size > limit:
                raise ValueError('Invalid request size')
            payload = json.loads(self.rfile.read(size))
            if self.path in ('/api/uber/start', '/api/uber/disconnect'):
                if not isinstance(payload, dict) or set(payload) - {'consent'}:
                    raise ValueError('Uber credentials must never be submitted to this endpoint.')
                if self.path == '/api/uber/start':
                    url, binding = uberconnect.manager.begin(payload.get('consent'))
                    return self.reply(200, json.dumps({'authorization_url': url}),
                                      headers={'Set-Cookie': uberconnect.cookie(binding)})
                uberconnect.manager.disconnect()
                return self.reply(200, '{"ok":true}', headers={'Set-Cookie': uberconnect.cookie(clear=True)})
            if self.path == '/api/research-ai':
                with LOCK, db() as c:
                    research.configure(c, payload)
            else:
                mutate(self.path, payload)
            self.reply(200, '{"ok":true}')
        except (ValueError, KeyError, TypeError, sqlite3.IntegrityError) as e:
            self.reply(400, json.dumps({'error': str(e)}))


if __name__ == '__main__':
    if len(TOKEN) < 24:
        raise SystemExit('Set ADMIN_PASSWORD to a unique password of at least 24 characters.')
    connections.load(DATA)
    init()
    threading.Thread(target=research_worker, daemon=True).start()
    threading.Thread(target=capital_worker, daemon=True).start()
    threading.Thread(target=dependency_worker, daemon=True).start()
    threading.Thread(target=queue_worker, daemon=True).start()
    threading.Thread(target=source_watch_worker, daemon=True).start()
    threading.Thread(target=supervisor_worker, daemon=True).start()
    threading.Thread(target=discovery_worker, daemon=True).start()
    threading.Thread(target=program_research_worker, daemon=True).start()
    threading.Thread(target=reporting_worker, daemon=True).start()
    server = ThreadingHTTPServer((os.environ.get('BIND', '127.0.0.1'), int(os.environ.get('PORT', '8080'))), Handler)
    threading.Thread(target=autonomous_worker, args=(server.server_address[1],), daemon=True).start()
    print('ScopeGuard dashboard ready. New installations start paused.', flush=True)
    server.serve_forever()
