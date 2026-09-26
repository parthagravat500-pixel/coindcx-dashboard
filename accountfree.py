"""One-off, reviewed public-page research and public policy collection.

Catalog entries never authorize requests to application targets. A checked-in,
expiring plan names each page and static-script host explicitly. No credentials,
payloads, forms, browser execution, redirect following or report submission.
"""
import hashlib
import http.client
import json
import re
import socket
import ssl
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from engine import public_addresses, validate_url

VERSION = '2026.09.27.1'
MAX_BODY = 1024 * 1024
PLAN = Path(__file__).parent / 'checkpoints' / 'overnight-2026-09-27.json'
LIMITATION = ('Public HTML/JavaScript inspection only. Patterns need manual validation; '
              'no account access, exploit execution, confirmed bugs or submissions. '
              'Policy collection does not grant testing permission.')


def checked_url(url):
    p = urlsplit(url)
    validate_url(urlunsplit((p.scheme, p.netloc, p.path, '', p.fragment)))
    if len(url) > 2048 or any(ord(x) < 33 or ord(x) > 126 for x in url) or '\\' in url:
        raise ValueError('Unsupported URL')
    return p


def fetch(url, headers=None):
    p = checked_url(url)
    raw = socket.create_connection((public_addresses(p.hostname)[0], 443), timeout=12)
    conn = http.client.HTTPSConnection(p.hostname, timeout=12)
    try:
        conn.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=p.hostname)
        values = {'User-Agent': 'ScopeGuard/3 bounded-public-research',
                  'Accept': 'text/html,application/javascript,text/javascript,text/plain',
                  'Accept-Encoding': 'identity', 'Connection': 'close'}
        for key, value in (headers or {}).items():
            if key != 'X-Bug-Bounty' or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', value):
                raise ValueError('Unsupported research identifier')
            values[key] = value
        conn.request('GET', p.path + ('?' + p.query if p.query else '') or '/', headers=values)
        response = conn.getresponse()
        # Never read denied, redirected or server-error bodies; never retry them.
        if not 200 <= response.status < 300:
            return {'status': response.status, 'body': b'', 'type': '', 'limited': False}
        if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
            return {'status': response.status, 'body': b'', 'type': '', 'limited': True}
        body = response.read(MAX_BODY + 1)
        return {'status': response.status, 'body': body[:MAX_BODY],
                'type': response.getheader('Content-Type', '').split(';')[0].lower(),
                'limited': len(body) > MAX_BODY}
    finally:
        conn.close()
        raw.close()


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts, self.inline, self.words = [], [], []
        self.in_script = False
        self.ignore = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'script':
            self.in_script = True
            if attrs.get('src') and len(self.scripts) < 100:
                self.scripts.append(attrs['src'])
        if tag in ('script', 'style'): self.ignore += 1

    def handle_endtag(self, tag):
        if tag == 'script': self.in_script = False
        if tag in ('script', 'style'): self.ignore = max(0, self.ignore - 1)

    def handle_data(self, data):
        if self.in_script: self.inline.append(data)
        if not self.ignore: self.words.append(data)


# These are narrow syntactic candidates, not a JavaScript data-flow model.
# No code excerpts, token values, page text or response bodies persist in results.
SOURCE = r'(?:window\s*\.\s*)?location\s*\.\s*(?:hash|search|href)'
PATTERNS = {
    'direct_url_to_html': re.compile(r'\.\s*(?:innerHTML|outerHTML)\s*=\s*(?:decodeURIComponent\s*\(\s*)?' + SOURCE),
    'direct_url_to_document_write': re.compile(r'document\s*\.\s*write(?:ln)?\s*\(\s*(?:decodeURIComponent\s*\(\s*)?' + SOURCE),
    'direct_url_to_eval': re.compile(r'\beval\s*\(\s*(?:decodeURIComponent\s*\(\s*)?' + SOURCE),
}


def analyze(body, mime):
    text = body.decode('utf-8', errors='replace')
    # Stop at possible accidental sensitive material; retain no contents or digest.
    if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', text):
        return {'state': 'sensitive_material_stop', 'patterns': []}, []
    if re.search(r'verify (?:that )?you are human|checking your browser|cf-chl-|captcha challenge', text, re.I):
        return {'state': 'access_challenge', 'patterns': []}, []
    page = Page()
    if 'html' in mime:
        page.feed(text)
        code = '\n'.join(page.inline)
    elif any(x in mime for x in ('javascript', 'ecmascript')):
        code = text
    else:
        return {'state': 'unsupported_content', 'patterns': []}, []
    # Avoid trivial false positives in comments. This is deliberately not a full parser.
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.S)
    code = re.sub(r'^\s*//[^\n]*', '', code, flags=re.M)
    patterns = [{'rule': rule, 'occurrences': min(20, len(regex.findall(code))),
                 'status': 'unverified_syntax_candidate'} for rule, regex in PATTERNS.items() if regex.search(code)]
    return {'state': 'reviewed', 'sha256': hashlib.sha256(body).hexdigest(),
            'bytes': len(body), 'patterns': patterns}, page.scripts


def load_plan():
    plan = json.loads(PLAN.read_text())
    if not 0 < plan['expires'] - plan['reviewed'] <= 43200 or len(plan['programs']) > 10:
        raise ValueError('Invalid reviewed batch window')
    ids = set()
    for p in plan['programs']:
        if p['id'] in ids or not re.fullmatch('[a-z0-9-]{1,40}', p['id']): raise ValueError('Invalid program')
        ids.add(p['id'])
        if not 1 <= len(p['pages']) <= 4 or not 1 <= p['budget'] <= 12: raise ValueError('Invalid budget')
        for url in p['pages']: checked_url(url)
    return plan


def init(c):
    c.executescript('''
      CREATE TABLE IF NOT EXISTS public_batches(id TEXT PRIMARY KEY, name TEXT, policy TEXT,
        state TEXT, started INTEGER DEFAULT 0, finished INTEGER DEFAULT 0,
        requests INTEGER DEFAULT 0, result TEXT DEFAULT '{}');
      CREATE TABLE IF NOT EXISTS public_policy_reviews(id TEXT PRIMARY KEY, policy TEXT,
        name TEXT, state TEXT DEFAULT 'queued', checked INTEGER DEFAULT 0,
        result TEXT DEFAULT '{}');
      CREATE TABLE IF NOT EXISTS public_research_health(id INTEGER PRIMARY KEY,
        heartbeat INTEGER DEFAULT 0, next_request INTEGER DEFAULT 0);
      INSERT OR IGNORE INTO public_research_health(id) VALUES(1);
    ''')
    for p in load_plan()['programs']:
        c.execute("INSERT OR IGNORE INTO public_batches(id,name,policy,state) VALUES(?,?,?,'queued')",
                  (p['id'], p['name'], p['policy']))


def run_program(program, admitted, transport=fetch, pace=time.sleep):
    result = {'pages': [], 'requests': 0, 'state': 'complete', 'confirmed_bugs': 0}
    pending = [(url, 'page') for url in program['pages']]
    visited = set()
    script_count = 0
    while pending and result['requests'] < program['budget']:
        url, kind = pending.pop(0)
        if url in visited: continue
        if result['requests']: pace(3)
        if not admitted(): result['state'] = 'stopped'; break
        visited.add(url)
        result['requests'] += 1
        try:
            raw = transport(url, program.get('headers', {}))
        except Exception:
            result['state'] = 'connection_failed'; break
        if not 200 <= raw['status'] < 300:
            result['state'] = 'http_' + str(raw['status']); break
        if raw['limited']:
            result['state'] = 'response_limit'; break
        info, scripts = analyze(raw['body'], raw['type'])
        info.update(url=url, kind=kind, status=raw['status'])
        result['pages'].append(info)
        if info['state'] in ('sensitive_material_stop', 'access_challenge'):
            result['state'] = info['state']; break
        for script in scripts:
            if script_count >= 4: break
            target = urljoin(url, script).split('#')[0]
            try: p = checked_url(target)
            except ValueError: continue
            # Only explicitly reviewed static hosts, actual page script references,
            # and .js filenames. Never navigate links or invent endpoints.
            if p.hostname not in program['script_hosts'] or not p.path.endswith('.js'): continue
            if target not in visited and target not in {item[0] for item in pending}:
                pending.append((target, 'script')); script_count += 1
    result['pending_omitted'] = len(pending)
    result['reviewed'] = sum(p['state'] == 'reviewed' for p in result['pages'])
    result['candidates'] = sum(len(p['patterns']) for p in result['pages'])
    return result


def policy_result(raw):
    if not 200 <= raw['status'] < 300: return {'state': 'http_' + str(raw['status'])}
    if raw['limited']: return {'state': 'response_limit'}
    if 'html' not in raw['type'] and raw['type'] != 'text/plain': return {'state': 'needs_document_reader'}
    page = Page(); page.feed(raw['body'].decode('utf-8', errors='replace'))
    text = ' '.join(' '.join(page.words).split())
    if re.search(r'verify (?:that )?you are human|checking your browser', text, re.I): return {'state': 'access_challenge'}
    if len(text) < 300: return {'state': 'needs_interactive_review'}
    sentences = re.split(r'(?<=[.!?])\s+', text)
    clues = [s[:600] for s in sentences if re.search(r'automat|scanner|requests per|rate.limit|bount|scope|test account', s, re.I)][:10]
    return {'state': 'document_collected', 'sha256': hashlib.sha256(raw['body']).hexdigest(),
            'clues': clues, 'authorization': False,
            'note': 'Unverified passages; linked rules, scope and eligibility still require review.'}


def tick(db, log, transport=fetch, pace=time.sleep):
    now = int(time.time()); plan = load_plan()
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        c.execute('UPDATE public_research_health SET heartbeat=? WHERE id=1', (now,))
        # A crashed batch never starts again. This preserves the finite request budget.
        c.execute("UPDATE public_batches SET state='interrupted',finished=? WHERE state='running' AND started<?", (now, now-600))
        c.execute("UPDATE public_policy_reviews SET state='interrupted' WHERE state='reading' AND checked<?", (now-90,))
        if c.execute('SELECT paused FROM settings').fetchone()[0]: return
        if now >= plan['expires']:
            c.execute("UPDATE public_batches SET state='expired' WHERE state='queued'")
            c.execute("UPDATE public_policy_reviews SET state='deferred_after_window' WHERE state='queued'")
            return
        if c.execute('SELECT next_request FROM public_research_health').fetchone()[0] > now: return
        if c.execute("SELECT 1 FROM public_batches WHERE state='running'").fetchone(): return
        row = c.execute("SELECT * FROM public_batches WHERE state='queued' ORDER BY id LIMIT 1").fetchone()
        if row:
            c.execute("UPDATE public_batches SET state='running',started=? WHERE id=?", (now, row['id']))
        else:
            # Only published policy URLs, not discovered application assets.
            c.execute("INSERT OR IGNORE INTO public_policy_reviews(id,policy,name) SELECT id,url,name FROM programs WHERE source='independent' AND available=1 AND stage!='dismissed'")
            policy = c.execute("SELECT * FROM public_policy_reviews WHERE state='queued' ORDER BY name LIMIT 1").fetchone()
            if not policy: return
            c.execute("UPDATE public_policy_reviews SET state='reading',checked=? WHERE id=?", (now, policy['id']))
        c.execute('UPDATE public_research_health SET next_request=? WHERE id=1', (now+45,))
    def admitted():
        with db() as c:
            if c.execute('SELECT paused FROM settings').fetchone()[0] or time.time() >= plan['expires']: return False
            if c.execute("SELECT state FROM public_batches WHERE id=?", (row['id'],)).fetchone()[0] != 'running': return False
            c.execute('UPDATE public_batches SET requests=requests+1 WHERE id=?', (row['id'],))
            c.execute('UPDATE public_research_health SET heartbeat=? WHERE id=1', (int(time.time()),))
        return True
    if row:
        program = next(p for p in plan['programs'] if p['id'] == row['id'])
        result = run_program(program, admitted, transport, pace)
        with db() as c:
            c.execute('UPDATE public_batches SET state=?,finished=?,result=? WHERE id=?',
                      (result['state'], int(time.time()), json.dumps(result), row['id']))
            log(c, 'Public-page research: '+program['name']+'; '+result['state']+'; '+str(result['reviewed'])+' documents inspected. No confirmed bug.')
    else:
        # Recheck the global pause immediately before the single policy request.
        with db() as c:
            if c.execute('SELECT paused FROM settings').fetchone()[0] or time.time() >= plan['expires']:
                c.execute("UPDATE public_policy_reviews SET state='queued' WHERE id=?", (policy['id'],)); return
        try: result = policy_result(transport(policy['policy'], {}))
        except Exception: result = {'state': 'connection_failed'}
        with db() as c:
            c.execute('UPDATE public_policy_reviews SET state=?,checked=?,result=? WHERE id=?',
                      (result['state'], int(time.time()), json.dumps(result), policy['id']))


def snapshot(c):
    plan = load_plan(); now = int(time.time())
    rows = []
    for r in c.execute('SELECT * FROM public_batches ORDER BY name'):
        item = dict(r); item['result'] = json.loads(item['result']); rows.append(item)
    counts = dict(c.execute('SELECT state,COUNT(*) FROM public_policy_reviews GROUP BY state'))
    health = c.execute('SELECT * FROM public_research_health').fetchone()
    return {'version': VERSION, 'paused': bool(c.execute('SELECT paused FROM settings').fetchone()[0]),
            'healthy': 0 <= now-health['heartbeat'] < 120, 'expires': plan['expires'],
            'window_finished': now >= plan['expires'], 'programs': rows, 'policy_counts': counts,
            'policy_reviewed': sum(v for k,v in counts.items() if k not in ('queued','reading','deferred_after_window')),
            'pages_reviewed': sum(r['result'].get('reviewed', 0) for r in rows),
            'candidates': sum(r['result'].get('candidates', 0) for r in rows),
            'requests': sum(r['requests'] for r in rows), 'confirmed_bugs': 0, 'limitation': LIMITATION}


def receipt(c):
    s = snapshot(c)
    return {'kind': 'scopeguard_accountfree_health', **{k:s[k] for k in
            ('version','paused','healthy','expires','window_finished','policy_counts','policy_reviewed','pages_reviewed','candidates','requests','confirmed_bugs')},
            'batches': [{'name':p['name'], 'state':p['state'], 'requests':p['requests'],
                         'reviewed':p['result'].get('reviewed',0)} for p in s['programs']]}
