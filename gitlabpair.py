"""Bounded comparison of two separately owned private GitLab test projects.

The primary credential is reused only on the server. Token identity checks plus
the existing six-request matrix make at most eight paced GETs per run.
"""
import json
import os
import re
import secrets
import tempfile
import time
from urllib.parse import quote

import accessmatrix

INTERVAL = 900


def init(c):
    c.execute('''CREATE TABLE IF NOT EXISTS gitlab_peer (
        id INTEGER PRIMARY KEY CHECK(id=1), revision TEXT, parent_revision TEXT,
        project TEXT, enabled INTEGER, expires INTEGER, due INTEGER,
        checked INTEGER, status TEXT, result TEXT, runs INTEGER DEFAULT 0)''')


def secret_path(root):
    return root / 'gitlab-peer-private.json'


def primary(c, root, expected=None):
    import gitlabcheck
    row = c.execute('SELECT * FROM gitlab_check WHERE id=1').fetchone()
    if not row or not row['enabled'] or row['expires'] <= time.time() or not row['revision']:
        raise ValueError('Connect an active first GitLab account before adding the second account.')
    if expected is not None and row['revision'] != expected:
        raise ValueError('The first account changed; reconnect the second account.')
    if json.loads(row['result']).get('verified_connection') is not True:
        raise ValueError('The first GitLab account must pass connection verification first.')
    config = json.loads(gitlabcheck.secret_path(root).read_text())
    if config.get('revision') != row['revision'] or config.get('project') != row['project']:
        raise ValueError('The saved first-account connection changed; reconnect it.')
    return dict(row), config


def configure(c, root, data):
    import gitlabcheck
    if not all(data.get(key) is True for key in ('own_project', 'policy_permission', 'read_only', 'two_accounts_owned')):
        raise ValueError('Confirm two owned accounts, unshared private projects and permission for eight read-only GETs per fifteen minutes.')
    row, owner = primary(c, root)
    project = gitlabcheck.project_path(data.get('project'))
    token = data.get('token', '')
    token = token.strip(' \t') if isinstance(token, str) else token
    marker, rules = data.get('marker', ''), data.get('rules', '')
    if not isinstance(token, str) or not 20 <= len(token) <= 512 or not re.fullmatch(r'[!-~]+', token):
        raise ValueError('Enter a valid second-account personal token with only read_api selected.')
    if project == owner['project'] or token == owner['token']:
        raise ValueError('Use a different account and a different private test project.')
    if not isinstance(marker, str) or not re.fullmatch(r'scopeguard_[a-f0-9]{32}', marker) or marker == owner['marker']:
        raise ValueError('Save a distinct generated test marker in the second project description.')
    if not isinstance(rules, str) or not 30 <= len(rules.strip()) <= 4000:
        raise ValueError('Record current permission for this exact two-account test.')
    old = c.execute('SELECT * FROM gitlab_peer WHERE id=1').fetchone()
    now = int(time.time())
    due = max(now, (old['checked'] + INTERVAL) if old and old['checked'] else now)
    revision = secrets.token_hex(16)
    config = dict(revision=revision, parent_revision=row['revision'], project=project,
                  token=token, marker=marker, rules=rules.strip())
    fd, name = tempfile.mkstemp(prefix='.gitlab-peer-', dir=root)
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
    c.execute('''INSERT INTO gitlab_peer VALUES(1,?,?,?,1,?,?,0,'Waiting to verify both accounts','{}',0)
        ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,parent_revision=excluded.parent_revision,
        project=excluded.project,enabled=1,expires=excluded.expires,due=excluded.due,
        status=excluded.status,result='{}' ''',
        (revision, row['revision'], project, min(row['expires'], now + 7 * 86400), due))


def disconnect(c, root):
    c.execute("UPDATE gitlab_peer SET enabled=0,revision='',status='Disconnected' WHERE id=1")
    secret_path(root).unlink(missing_ok=True)


def compare(owner, peer, allowed=lambda: True, transport=None, pace=time.sleep):
    import gitlabcheck
    transport = transport or gitlabcheck.fetch
    evidence = []
    result = dict(evidence=evidence, verified_connection=False, reproduced=False,
                  submission_ready=False, severity='Not assessed', mode='two_account',
                  limitation='Two token identities and two private project descriptions only; at most eight GETs. Anonymous access is checked separately. No bounty eligibility or impact conclusion.')
    calls = 0

    def request(path, token):
        nonlocal calls
        if calls >= 8:
            raise RuntimeError('Request budget exhausted')
        if not allowed():
            raise InterruptedError()
        pace(1)
        if not allowed():
            raise InterruptedError()
        calls += 1
        response = transport(path, token)
        if response['status'] == 429 or response['status'] >= 500:
            raise gitlabcheck.ServerStop(response['status'], response.get('retry_at', 0))
        return response

    try:
        identities = []
        for label, config in [('A', owner), ('B', peer)]:
            r = request('/api/v4/personal_access_tokens/self', config['token'])
            evidence.append(dict(step='Verify account ' + label + ' read-only token', **{k: r[k] for k in ('status', 'bytes', 'sha256')}))
            info = r.get('data')
            if (r['status'] != 200 or not isinstance(info, dict) or info.get('active') is not True
                    or info.get('revoked') is not False or info.get('scopes') != ['read_api']
                    or type(info.get('user_id')) is not int or info['user_id'] <= 0):
                return dict(result, status='Setup needed: both accounts require active read_api-only personal tokens')
            identities.append(info['user_id'])
        if identities[0] == identities[1]:
            return dict(result, status='Setup needed: the two tokens identify the same GitLab account')
        endpoints = {label: '/api/v4/projects/' + quote(config['project'], safe='')
                     for label, config in [('A', owner), ('B', peer)]}
        shared = False

        def matrix_transport(path, token, marker):
            nonlocal shared
            r = request(path, token)
            p = r.get('data')
            expected = owner if path == endpoints['A'] else peer
            valid = (r['status'] == 200 and isinstance(p, dict)
                     and type(p.get('id')) is int and p['id'] > 0
                     and p.get('path_with_namespace') == expected['project']
                     and p.get('visibility') == 'private')
            permissions = (p.get('permissions') or {}) if isinstance(p, dict) else {}
            levels = [(permissions.get(key) or {}).get('access_level', 0)
                      for key in ('project_access', 'group_access')]
            levels = [level for level in levels if type(level) is int]
            is_control = (path == endpoints['A'] and token == owner['token']) or (path == endpoints['B'] and token == peer['token'])
            if not is_control and valid and any(level > 0 for level in levels):
                shared = True
            found = bool(valid and isinstance(p.get('description'), str) and marker in p['description']
                         and (not is_control or any(level >= 40 for level in levels)))
            return dict(status=r['status'], json=isinstance(p, dict), marker_present=found,
                        bytes=r['bytes'], sha256=r['sha256'])

        matrix = accessmatrix.compare(dict(mode='two_account', url=endpoints['A'],
            authorization=owner['token'], marker=owner['marker'], peer_url=endpoints['B'],
            peer_authorization=peer['token'], peer_marker=peer['marker']), matrix_transport, allowed, lambda _: None)
        result.update(matrix)
        result['evidence'] = evidence + matrix['evidence']
        result['verified_connection'] = not matrix['status'].startswith('Setup needs attention')
        result['account_identities_distinct'] = True
        if shared:
            result.update(status='Setup needed: account B has an assigned role on account A project; check intended sharing',
                          reproduced=False, verified_connection=False)
        return result
    except gitlabcheck.ServerStop as exc:
        return dict(result, status='Stopped: HTTP ' + str(exc.status) + '; no conclusion', provider_stop=True,
                    retry_at=exc.retry_at, verified_connection=False)
    except InterruptedError:
        return dict(result, status='Stopped: permission changed or testing paused; no conclusion')
    except Exception:
        return dict(result, status='Stopped: connection or response needs review; no conclusion')


def tick(db, root, log):
    now = int(time.time())
    with db() as c:
        if c.execute('SELECT paused FROM settings').fetchone()[0]:
            return
        row = c.execute('SELECT * FROM gitlab_peer WHERE enabled=1 AND expires>? AND due<=?', (now, now)).fetchone()
        if not row:
            return
        row = dict(row)
        c.execute("UPDATE gitlab_peer SET due=?,status='Checking both private projects' WHERE id=1", (now + INTERVAL,))

    def allowed():
        with db() as c:
            parent = c.execute('SELECT * FROM gitlab_check WHERE id=1').fetchone()
            current = c.execute('SELECT * FROM gitlab_peer WHERE id=1').fetchone()
            return bool(parent and current and parent['revision'] == row['parent_revision'] and parent['enabled']
                        and current['revision'] == row['revision'] and current['enabled']
                        and min(parent['expires'], current['expires']) > time.time()
                        and not c.execute('SELECT paused FROM settings').fetchone()[0])
    try:
        with db() as c:
            _, owner = primary(c, root, row['parent_revision'])
        peer = json.loads(secret_path(root).read_text())
        if peer.get('revision') != row['revision'] or peer.get('project') != row['project'] or peer.get('parent_revision') != row['parent_revision']:
            raise ValueError('Connection changed')
        result = compare(owner, peer, allowed)
    except Exception:
        result = dict(status='Setup needed: reconnect the saved accounts', evidence=[], verified_connection=False,
                      reproduced=False, submission_ready=False)
    complete = int(time.time())
    enabled = int(result['status'] == 'Second-account boundary held for this test; anonymous access not assessed')
    with db() as c:
        changed = c.execute('''UPDATE gitlab_peer SET due=?,checked=?,status=?,result=?,enabled=?,runs=runs+1
            WHERE id=1 AND revision=? AND enabled=1''',
            (complete + INTERVAL, complete, result['status'], json.dumps(result), enabled, row['revision']))
        if changed.rowcount:
            if result.get('provider_stop'):
                c.execute("UPDATE gitlab_check SET enabled=0,status='Paused after second-account server stop; review required' WHERE id=1 AND revision=?", (row['parent_revision'],))
            log(c, 'GitLab two-account check: ' + result['status'] + '. No report sent.')


def snapshot(c):
    row = c.execute('SELECT * FROM gitlab_peer WHERE id=1').fetchone()
    if not row:
        return dict(configured=False, connected=False, runs=0)
    result = json.loads(row['result'])
    return dict(**{key: row[key] for key in ('project', 'enabled', 'expires', 'due', 'checked', 'status', 'runs')},
                configured=bool(row['revision']), connected=bool(row['revision'] and result.get('verified_connection')),
                result=result)
