"""Read-only comparison of one owner's private GitLab project's synthetic description.
No repository writes, crawling, ID guessing, report submission or exploit payloads.
"""
import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import tempfile
import time
from urllib.parse import quote, urlsplit
from engine import public_addresses

HOST = 'gitlab.com'
INTERVAL = 900
MAX_BODY = 65536


def init(c):
    c.execute('''CREATE TABLE IF NOT EXISTS gitlab_check (
        id INTEGER PRIMARY KEY CHECK(id=1), revision TEXT, project TEXT,
        enabled INTEGER, expires INTEGER, due INTEGER, checked INTEGER,
        status TEXT, result TEXT, runs INTEGER DEFAULT 0)''')


def project_path(value):
    if not isinstance(value, str):
        raise ValueError('Enter your GitLab project link.')
    value = value.strip()
    if value.startswith('https://'):
        p = urlsplit(value)
        if p.netloc != HOST or p.query or p.fragment or p.username:
            raise ValueError('Use a plain https://gitlab.com project link without credentials.')
        value = p.path.strip('/')
    if value.endswith('.git'):
        value = value[:-4]
    if len(value) > 250 or not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)+', value):
        raise ValueError('Use the project link, for example group/project.')
    return value


def secret_path(root):
    return root / 'gitlab-private.json'


def configure(c, root, data):
    if not all(data.get(k) is True for k in ('own_project', 'policy_permission', 'read_only')):
        raise ValueError('Confirm ownership, current permission and the read-only test.')
    project = project_path(data.get('project'))
    token = data.get('token', '')
    if isinstance(token, str):
        token = token.strip(' \t')
    marker = data.get('marker', '')
    rules = data.get('rules', '')
    if not isinstance(token, str) or not token:
        raise ValueError('Paste your GitLab personal access token into the token field.')
    # Treat credentials as opaque. GitLab validates authenticity and scope;
    # locally reject whitespace/control characters unsafe in an HTTP header.
    if not 20 <= len(token) <= 512 or not re.fullmatch(r'[!-~]+', token):
        raise ValueError('The token has an invalid length or contains spaces, line breaks or hidden characters. Copy the complete token again using GitLab’s copy button.')
    if not isinstance(marker, str) or not re.fullmatch(r'scopeguard_[a-f0-9]{32}', marker):
        raise ValueError('Generate the test text and save it in your private project description first.')
    if not isinstance(rules, str) or not 30 <= len(rules.strip()) <= 4000:
        raise ValueError('Record why current program rules permit this exact production test; use a local lab otherwise.')
    now = int(time.time())
    old = c.execute('SELECT * FROM gitlab_check WHERE id=1').fetchone()
    if old and old['checked'] and now < old['checked'] + INTERVAL:
        raise ValueError('Wait 15 minutes after the last check before reconnecting.')
    revision = secrets.token_hex(16)
    config = dict(revision=revision, project=project, token=token, marker=marker, rules=rules.strip())
    fd, name = tempfile.mkstemp(prefix='.gitlab-', dir=root)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(config, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, secret_path(root))
    finally:
        if os.path.exists(name):
            os.unlink(name)
    c.execute('''INSERT INTO gitlab_check VALUES(1,?,?,1,?,0,0,'Waiting to verify connection','{}',0)
        ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,project=excluded.project,
        enabled=1,expires=excluded.expires,due=0,status=excluded.status,result='{}' ''',
        (revision, project, now + 7 * 86400))


def fetch(path, token):
    if path != '/api/v4/personal_access_tokens/self' and not re.fullmatch(r'/api/v4/projects/[A-Za-z0-9_.%-]+', path):
        raise ValueError('Only token verification and the configured project endpoint are supported')
    addresses = public_addresses(HOST)
    raw = socket.create_connection((addresses[0], 443), timeout=10)
    conn = http.client.HTTPSConnection(HOST, timeout=10)
    try:
        conn.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=HOST)
        headers = {'User-Agent': 'ScopeGuard/2.0 owner-private-project-check', 'Accept': 'application/json',
                   'Accept-Encoding': 'identity', 'Cache-Control': 'no-cache', 'Connection': 'close'}
        if token:
            headers['PRIVATE-TOKEN'] = token
        conn.request('GET', path, headers=headers)
        response = conn.getresponse()
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError('Response exceeded 64 KB')
        mime = response.getheader('Content-Type', '').split(';')[0].lower()
        value = None
        if mime == 'application/json' and response.getheader('Content-Encoding', 'identity') == 'identity':
            try:
                value = json.loads(body)
            except (ValueError, UnicodeError):
                pass
        return {'status': response.status, 'data': value, 'bytes': len(body),
                'sha256': hashlib.sha256(body).hexdigest()}
    finally:
        conn.close()
        raw.close()


def compare(config, allowed=lambda: True, transport=fetch, pace=time.sleep):
    evidence = []
    result = {'evidence': evidence, 'verified_connection': False, 'reproduced': False,
              'submission_ready': False, 'severity': 'Not assessed',
              'limitation': 'One private project description only. A passed check is not a vulnerability. Exposure needs manual impact and program eligibility review.'}
    endpoint = '/api/v4/projects/' + quote(config['project'], safe='')

    def observe(label, path, token):
        pace(1)
        if not allowed():
            raise InterruptedError()
        r = transport(path, token)
        evidence.append({k: r[k] for k in ('status', 'bytes', 'sha256')})
        evidence[-1]['step'] = label
        if r['status'] == 429 or r['status'] >= 500:
            raise RuntimeError('Rate limit or server error')
        return r

    def project(r, private=False):
        p = r.get('data')
        return (r['status'] == 200 and isinstance(p, dict)
                and type(p.get('id')) is int and p['id'] > 0
                and p.get('path_with_namespace') == config['project']
                and (not private or p.get('visibility') == 'private'))

    def marker(r):
        p = r.get('data')
        return project(r) and isinstance(p.get('description'), str) and config['marker'] in p['description']

    def owner(r):
        p = r.get('data') or {}
        permissions = p.get('permissions') or {}
        return any(type((permissions.get(k) or {}).get('access_level')) is int and
                   (permissions.get(k) or {})['access_level'] >= 40 for k in ('project_access', 'group_access'))

    try:
        r = observe('Verify read-only token', '/api/v4/personal_access_tokens/self', config['token'])
        info = r.get('data')
        if r['status'] != 200 or not isinstance(info, dict) or info.get('active') is not True or info.get('revoked') is not False or info.get('scopes') != ['read_api']:
            return dict(result, status='Setup needed: use an active personal token with only read_api selected')
        first = observe('Owner login control', endpoint, config['token'])
        if not project(first, True) or not owner(first):
            return dict(result, status='Setup needed: project must be private and your account must be its Maintainer or Owner')
        result['verified_connection'] = True
        if not marker(first):
            return dict(result, status='Setup needed: save the generated test text in the private project description')
        anon = observe('Without login', endpoint, None)
        if anon['status'] in (401, 403, 404):
            return dict(result, status='Passed: private project access was denied without login')
        if not marker(anon):
            return dict(result, status='Inconclusive: no confirmed marker exposure; check stopped')
        again = observe('Repeat without login', endpoint, None)
        last = observe('Repeat owner login control', endpoint, config['token'])
        if marker(again) and marker(last) and project(last, True) and owner(last) and len({r['data']['id'] for r in (first, anon, again, last)}) == 1:
            return dict(result, status='Needs review: private test text appeared without login twice', reproduced=True)
        return dict(result, status='Inconclusive: privacy or response changed; check stopped')
    except Exception as exc:
        return dict(result, status='Stopped: ' + ('paused, disconnected or permission expired' if isinstance(exc, InterruptedError) else 'request failed or server asked us to stop') + '; no conclusion')


def tick(db, root, log):
    now = int(time.time())
    with db() as c:
        if c.execute('SELECT paused FROM settings').fetchone()[0]:
            return
        row = c.execute('SELECT * FROM gitlab_check WHERE enabled=1 AND expires>? AND due<=?', (now, now)).fetchone()
        if not row:
            return
        row = dict(row)
        c.execute("UPDATE gitlab_check SET due=?,status='Checking your private project' WHERE id=1", (now + INTERVAL,))

    def allowed():
        with db() as c:
            r = c.execute('SELECT * FROM gitlab_check WHERE id=1').fetchone()
            return bool(r and r['revision'] == row['revision'] and r['enabled'] and r['expires'] > time.time()
                        and not c.execute('SELECT paused FROM settings').fetchone()[0])
    try:
        config = json.loads(secret_path(root).read_text())
        if config['revision'] != row['revision'] or config['project'] != row['project']:
            raise ValueError('Connection changed')
        result = compare(config, allowed)
    except Exception:
        result = {'status': 'Setup needed: reconnect your project', 'evidence': [], 'verified_connection': False,
                  'reproduced': False, 'submission_ready': False}
    complete = int(time.time())
    enabled = int(result['status'].startswith('Passed:'))
    with db() as c:
        updated = c.execute('''UPDATE gitlab_check SET due=?,checked=?,status=?,result=?,enabled=?,runs=runs+1
            WHERE id=1 AND revision=? AND enabled=1''',
            (complete + INTERVAL, complete, result['status'], json.dumps(result), enabled, row['revision']))
        if updated.rowcount:
            log(c, 'GitLab project check: ' + result['status'] + '. No report sent.')


def disconnect(c, root):
    c.execute("UPDATE gitlab_check SET enabled=0,revision='',status='Disconnected' WHERE id=1")
    secret_path(root).unlink(missing_ok=True)


def snapshot(c):
    r = c.execute('SELECT * FROM gitlab_check WHERE id=1').fetchone()
    if not r:
        return {'configured': False, 'connected': False, 'status': 'Needs your read-only token', 'runs': 0}
    result = json.loads(r['result'])
    return {**{k: r[k] for k in ('project', 'enabled', 'expires', 'due', 'checked', 'status', 'runs')},
            'configured': bool(r['revision']), 'connected': bool(r['revision'] and result.get('verified_connection')),
            'result': result}
