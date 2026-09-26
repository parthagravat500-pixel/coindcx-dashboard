"""Scheduled full-catalog evaluation and scoped adapters for authorized runners.

This module makes no network requests and never enables a target. Runtime evidence
comes only from existing permission-checking runners. Unsupported items remain
explicitly untested. Compact receipts avoid storing 1,000 duplicate descriptions
for each program on the persistent disk.
"""
from collections import Counter
import json
import os
import re
import threading
import time
from urllib.parse import parse_qs

import autopilot
import checkpointstatic
import programqueue
import researchcheckpoints as catalog
import sourceaudit

VERSION = '2026.09.26.2'
INTERVAL = 5
REFRESH = 900
BATCH = 16
RUN_LOCK = threading.Lock()
HEAD_RULES = {
    'SG-0604': ('strict-transport-security',),
    'SG-0605': ('x-content-type-options',),
    'SG-0606': ('x-frame-options', 'content-security-policy'),
    'SG-0607': ('content-security-policy',),
    'SG-0610': ('referrer-policy',),
    'SG-0611': ('permissions-policy',),
    'SG-0612': ('cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy'),
    'SG-0613': ('cache-control',),
}
COOKIE_RULES = {'SG-0148': 'secure', 'SG-0149': 'httponly', 'SG-0150': 'samesite'}
OWNED_RULES = {'SG-0166': ('anonymous-state', 'anonymous-write'),
               'SG-0263': ('missing-csrf',), 'SG-0264': ('wrong-csrf',)}
ADAPTERS = {**{k: 'policy' for k in catalog.POLICY_RULES},
            **{k: 'source' for k in catalog.SOURCE_RULES},
            **{k: 'source' for k in checkpointstatic.IDS},
            **{k: 'headers' for k in HEAD_RULES}, **{k: 'headers' for k in COOKIE_RULES},
            **{k: 'owned_validation' for k in OWNED_RULES}, 'SG-0161': 'access'}
LIMITATION = ('All 1,000 checkpoints receive a coverage decision. Only implemented adapters with current '
              'evidence count as executed. Response observations and source patterns do not validate a '
              'whole security control. Runtime results apply only to the recorded resource and method. '
              'No result here is an accepted report or paid bounty.')


def init(c):
    c.executescript('''
      CREATE TABLE IF NOT EXISTS checkpoint_worker(id INTEGER PRIMARY KEY,heartbeat INTEGER,error INTEGER);
      INSERT OR IGNORE INTO checkpoint_worker VALUES(1,0,0);
      CREATE TABLE IF NOT EXISTS checkpoint_evaluations(
        context TEXT PRIMARY KEY,version TEXT,revision TEXT,checked INTEGER,counts TEXT);
      CREATE TABLE IF NOT EXISTS checkpoint_observations(
        context TEXT,job TEXT,kind TEXT,stamp TEXT,checked INTEGER,revision TEXT,results TEXT,
        PRIMARY KEY(context,job));
      CREATE TABLE IF NOT EXISTS checkpoint_versions(version TEXT PRIMARY KEY);
    ''')
    first = c.execute('INSERT OR IGNORE INTO checkpoint_versions VALUES(?)', (VERSION,)).rowcount
    if first and not c.execute('SELECT paused FROM settings').fetchone()[0]:
        # Only the fixed owned-loopback regression job is made due after upgrade.
        # External targets, approvals, and their rate limits are never modified.
        c.execute('UPDATE validation_schedule SET due=MIN(due,MAX(0,last_started+300)) WHERE id=1')


def revision():
    value = os.environ.get('RENDER_GIT_COMMIT', '')
    return value if re.fullmatch('[0-9a-f]{40}', value) else 'local'


def observation(state, note, checked=0, executed=False, tested=False, **extra):
    return {'state': state, 'note': note, 'checked': checked, 'executed': executed,
            'tested': tested, 'control_validated': False, **extra}


def contexts(c):
    items = [{'id': 'owned', 'name': 'ScopeGuard · owned application'}]
    items += [{'id': 'program:' + r['id'], 'name': r['name']} for r in c.execute('SELECT id,name FROM programs ORDER BY name,id')]
    items += [{'id': 'target:' + str(r['id']), 'name': 'Saved URL · ' + r['name']} for r in c.execute('SELECT id,name FROM targets ORDER BY id')]
    return items


def target_contexts(c, target):
    ids = ['target:' + str(target['id'])]
    ids += ['program:' + r['id'] for r in c.execute("SELECT id FROM programs WHERE rtrim(url,'/')=?", (programqueue.policy_key(target['policy']),))]
    return ids


def save(c, context, job, kind, stamp, checked, results):
    c.execute('INSERT OR REPLACE INTO checkpoint_observations VALUES(?,?,?,?,?,?,?)',
              (context, job, kind, stamp, checked, revision(), json.dumps(results)))
    c.execute('UPDATE checkpoint_evaluations SET checked=0 WHERE context=?', (context,))


def record_head(c, target, response, cors=None):
    """Consume the existing HEAD response; retain no header/cookie values or bodies."""
    now = int(time.time())
    job = next((j for j in autopilot.jobs(c, now) if j['key'] == 'headers:' + str(target['id'])), None)
    if not job or job['blocker'] or c.execute('SELECT paused FROM settings').fetchone()[0]: return
    original = {key: target[key] for key in ('id', 'url', 'policy', 'rules', 'expires', 'interval', 'cors', 'enabled')}
    if job['stamp'] != autopilot.digest(original): return
    if not 200 <= response.get('status', 0) < 300: return
    headers = response.get('headers', {}); cookies = response.get('cookies', [])
    rows = {}
    for key, names in HEAD_RULES.items():
        count = sum(bool(headers.get(name)) for name in names)
        rows[key] = observation('observed', str(count) + ' of ' + str(len(names)) +
            ' relevant headers present on the authorized HEAD response. Values, GET behavior, feature relevance and impact need contextual validation.',
            now, True, adapter='headers', response_status=response['status'])
    for key, attribute in COOKIE_RULES.items():
        present = sum(attribute in cookie.get('attributes', []) for cookie in cookies)
        rows[key] = observation('observed' if cookies else 'needs_input',
            str(present) + ' of ' + str(len(cookies)) + ' observed cookies include ' + attribute +
            '. Cookie purpose and authentication relevance are unverified; zero cookies is not a passed test.',
            now, bool(cookies), adapter='headers')
    for context in target_contexts(c, target):
        save(c, context, job['key'], 'headers', job['stamp'], now, rows)


def record_runtime(c, job, outcome, evidence, finished):
    """Called after the scheduler verifies the runner's evidence and current scope."""
    if job['kind'] == 'headers': return
    current = next((j for j in autopilot.jobs(c, finished) if j['key'] == job['key']), None)
    if (not current or current['stamp'] != job['stamp'] or current['blocker']
            or c.execute('SELECT paused FROM settings').fetchone()[0]): return
    keys = OWNED_RULES if job['kind'] == 'owned_validation' else {'SG-0161': ()}
    rows = {}
    checks = {r.get('id'): r for r in evidence}
    for key, required in keys.items():
        valid = outcome in ('boundary_held', 'reproduced_boundary')
        if job['kind'] == 'owned_validation':
            control = checks.get('control', {})
            valid = (control.get('actual_status') == 200 and control.get('passed') is True and
                     'response_sha256' in control and bool(required) and
                     all(k in checks and 'response_sha256' in checks[k] and type(checks[k].get('actual_status')) is int for k in required))
            expected = {'anonymous-state': 401, 'anonymous-write': 401, 'missing-csrf': 403, 'wrong-csrf': 403}
            passed = valid and all(checks[k].get('passed') is True and checks[k]['actual_status'] == expected[k] for k in required)
        else: passed = outcome == 'boundary_held'
        state = ('runtime_passed' if passed else 'runtime_failed') if valid else 'inconclusive'
        rows[key] = observation(state,
            'Completed bounded ' + job['kind'] + ' comparison: ' + outcome +
            '. Applies only to this saved resource and control sequence; other endpoints and the full control remain untested.',
            finished, valid, valid, adapter=job['kind'], evidence_steps=len(evidence),
            evidence_hash=autopilot.digest(evidence))
    if job['kind'] == 'owned_validation': linked = ['owned']
    elif job['kind'] == 'access':
        target = c.execute('SELECT * FROM targets WHERE id=?', (job['target'],)).fetchone()
        linked = target_contexts(c, target) if target else []
    else:
        linked = ['program:' + p['id'] for p in c.execute('SELECT id,url FROM programs')
                  if autopilot.digest(programqueue.policy_key(p['url'])) == job['program']]
    for context in linked: save(c, context, job['key'], job['kind'], job['stamp'], finished, rows)


def _policy(c, context):
    if not context.startswith('program:'): return {}, None, ''
    import programresearch
    program = c.execute('SELECT * FROM programs WHERE id=?', (context[8:],)).fetchone()
    if not program: raise ValueError('Program not found')
    try: detail = programresearch.detail(c, program['id'])
    except ValueError: detail = {}
    checked = detail.get('checked', 0)
    plan = catalog.plan_summary(detail.get('evidence', {}),
        fresh=bool(checked and 0 <= time.time() - checked < 86400 and not detail.get('partial')),
        status=detail.get('status', ''))
    blocker = ''
    if not program['available'] or program['stage'] == 'dismissed': blocker = 'Program is unavailable or dismissed.'
    elif detail.get('evidence', {}).get('automation_permission') == 'restricted': blocker = 'Saved program policy restricts automation.'
    return catalog.policy_support(detail), plan, blocker


def build(c, context, root=catalog.ROOT, now=None):
    now = int(time.time()) if now is None else now
    policy, plan, blocker = _policy(c, context)
    if context.startswith('target:') and not c.execute('SELECT 1 FROM targets WHERE id=?', (int(context[7:]),)).fetchone():
        raise ValueError('Saved target not found')
    support = {k: observation(v['state'], v['note'], v.get('checked', 0),
                            v['state'] != 'needs_evidence', adapter='policy') for k, v in policy.items()}
    if context == 'owned':
        for key, row in catalog.source_support(c, root)['results'].items():
            support[key] = {**row, 'executed': bool(row.get('files')), 'tested': False, 'adapter': 'source'}
    jobs = {j['key']: j for j in autopilot.jobs(c, now)}
    paused = bool(c.execute('SELECT paused FROM settings').fetchone()[0])
    for receipt in c.execute('SELECT * FROM checkpoint_observations WHERE context=? ORDER BY checked,job', (context,)):
        current = jobs.get(receipt['job'])
        if receipt['kind'] == 'source':
            valid = (context == 'owned' and receipt['revision'] == revision() and 0 <= now - receipt['checked'] < REFRESH
                     and receipt['stamp'] == checkpointstatic.fingerprint(root, sourceaudit.FILES))
        else:
            valid = (current and current['stamp'] == receipt['stamp'] and not current['blocker'] and
                     0 <= now - receipt['checked'] < 86400 and not blocker and
                     (receipt['kind'] != 'owned_validation' or receipt['revision'] == revision()))
        for key, row in json.loads(receipt['results']).items():
            if key not in ADAPTERS: continue
            if valid:
                # A later passing resource must not hide another current failed
                # resource in the same program's checkpoint summary.
                if support.get(key, {}).get('state') != 'runtime_failed' or row.get('state') == 'runtime_failed':
                    support[key] = {**row, 'job': receipt['job']}
            elif key not in support:
                support[key] = observation('blocked', 'Saved evidence is stale or its permission/configuration changed. A fresh authorized run is required.')
    rows = []
    for group in catalog._catalog()['categories']:
        suggested = not plan or group['id'] in plan['category_ids']
        for entry in group['checks']:
            key = entry['id']; adapter = ADAPTERS.get(key)
            if key in support: result = support[key]
            elif not adapter:
                result = observation('needs_implementation' if suggested else 'needs_context',
                    'No executable adapter is implemented for this checkpoint. ' + group['prerequisites'] if suggested
                    else 'Saved scope does not establish this feature. Applicability needs review; this is not a passed or excluded test.')
            else:
                state = 'blocked' if blocker else 'needs_input'
                note = blocker or {
                    'policy': 'Select a program with current official policy evidence.',
                    'source': 'Current authorized Python source is required. ScopeGuard source results are never attributed to another program.',
                    'headers': 'Waiting for an existing exact-URL HEAD job with valid program permission and a successful response.',
                    'access': 'Waiting for an approved owned-resource comparison with authenticated controls.',
                    'owned_validation': 'This adapter tests only the owned ScopeGuard app; other apps need a suitable authorized test profile.',
                }[adapter]
                result = observation(state, note)
            rows.append({**entry, 'category': group['title'], 'category_id': group['id'],
                         'adapter': adapter, 'observation': result})
    counts = dict(Counter(r['observation']['state'] for r in rows))
    return {'context': context, 'total': len(rows), 'evaluated': len(rows), 'counts': counts,
            'implemented_adapters': len(ADAPTERS),
            'executed': sum(bool(r['observation'].get('executed')) for r in rows),
            'runtime_tested': sum(bool(r['observation'].get('tested')) for r in rows),
            'paused': paused, 'items': rows, 'plan': plan, 'limitation': LIMITATION}


def tick(db, root=catalog.ROOT):
    if not RUN_LOCK.acquire(blocking=False): return
    try:
        with db() as c:
            now = int(time.time())
            c.execute('UPDATE checkpoint_worker SET heartbeat=?,error=0 WHERE id=1', (now,))
            if c.execute('SELECT paused FROM settings').fetchone()[0]: return
            available = contexts(c)
            saved = {r['context']: dict(r) for r in c.execute('SELECT * FROM checkpoint_evaluations')}
            due = [x for x in available if x['id'] not in saved or saved[x['id']]['version'] != VERSION
                   or saved[x['id']]['revision'] != revision() or saved[x['id']]['checked'] <= now - REFRESH]
            due.sort(key=lambda x: (x['id'] != 'owned', saved.get(x['id'], {}).get('checked', 0), x['id']))
            for item in due[:BATCH]:
                if item['id'] == 'owned':
                    sourceaudit.installed(c, root)
                    audit = checkpointstatic.inspect(root, sourceaudit.FILES)
                    rows = {key: observation('needs_evidence' if not audit['files'] else 'signal_recorded' if signals else 'no_signal_in_saved_files',
                        str(signals) + ' pattern signals in ' + str(audit['files']) + ' owned Python files; ' +
                        str(audit['skipped']) + ' files could not be analyzed. Patterns require contextual review; no finding does not prove security.',
                        now, bool(audit['files']), adapter='source', files=audit['files'], signals=signals)
                        for key, signals in audit['signals'].items()}
                    save(c, 'owned', 'source:extra', 'source', audit['digest'], now, rows)
                result = build(c, item['id'], root, now)
                compact = {key: result[key] for key in ('total', 'evaluated', 'executed', 'runtime_tested', 'counts')}
                c.execute('INSERT OR REPLACE INTO checkpoint_evaluations VALUES(?,?,?,?,?)',
                          (item['id'], VERSION, revision(), now, json.dumps(compact)))
            active = {x['id'] for x in available}
            for stale in set(saved) - active:
                c.execute('DELETE FROM checkpoint_evaluations WHERE context=?', (stale,))
                c.execute('DELETE FROM checkpoint_observations WHERE context=?', (stale,))
    except Exception:
        with db() as c: c.execute('UPDATE checkpoint_worker SET heartbeat=?,error=1 WHERE id=1', (int(time.time()),))
        raise
    finally:
        RUN_LOCK.release()


def summary(c):
    now = int(time.time()); state = dict(c.execute('SELECT * FROM checkpoint_worker WHERE id=1').fetchone())
    receipts = [dict(r) for r in c.execute('SELECT * FROM checkpoint_evaluations')]
    current = [r for r in receipts if r['version'] == VERSION and r['revision'] == revision() and 0 <= now - r['checked'] < REFRESH + 60]
    owned = next((json.loads(r['counts']) for r in current if r['context'] == 'owned'), None)
    return {**state, 'version': VERSION, 'total': catalog.inventory()['total'],
            'implemented_adapters': len(ADAPTERS), 'remaining_adapters': catalog.inventory()['total'] - len(ADAPTERS),
            'paused': bool(c.execute('SELECT paused FROM settings').fetchone()[0]),
            'healthy': bool(not state['error'] and 0 < state['heartbeat'] <= now and now - state['heartbeat'] < 90),
            'contexts_evaluated': len(receipts), 'current_contexts': len(current),
            'contexts_total': 1 + c.execute('SELECT COUNT(*) FROM programs').fetchone()[0] + c.execute('SELECT COUNT(*) FROM targets').fetchone()[0],
            'owned': owned, 'limitation': LIMITATION, 'confirmed_bounty_bugs': 0}


def browse(c, query='', root=catalog.ROOT):
    if len(query) > 1200: raise ValueError('Query too long')
    values = parse_qs(query, keep_blank_values=True, max_num_fields=8)
    if set(values) - {'context', 'q', 'state', 'offset', 'limit'} or any(len(v) != 1 for v in values.values()):
        raise ValueError('Unsupported results filter')
    p = {k: v[0] for k, v in values.items()}; context = p.get('context', 'owned')
    if not re.fullmatch(r'owned|program:[0-9a-f]{24}|target:[1-9][0-9]{0,9}', context): raise ValueError('Invalid context')
    for key, default, maximum in (('offset', '0', 10000), ('limit', '40', 100)):
        value = p.get(key, default)
        if not re.fullmatch(r'\d{1,5}', value) or int(value) > maximum or key == 'limit' and int(value) < 1:
            raise ValueError('Invalid results page')
        p[key] = int(value)
    if len(p.get('q', '')) > 120: raise ValueError('Search too long')
    result = build(c, context, root)
    q = p.get('q', '').casefold(); state = p.get('state', '')
    rows = [r for r in result.pop('items') if (not state or r['observation']['state'] == state)
            and (not q or q in (r['id'] + ' ' + r['title'] + ' ' + r['category']).casefold())]
    run = c.execute('SELECT checked FROM checkpoint_evaluations WHERE context=?', (context,)).fetchone()
    return {**result, 'last_evaluated': run['checked'] if run else 0,
            'matched': len(rows), 'offset': p['offset'],
            'items': rows[p['offset']:p['offset'] + p['limit']],
            'next_offset': p['offset'] + p['limit'] if p['offset'] + p['limit'] < len(rows) else None,
            'contexts': contexts(c)}


def receipt(c):
    data = summary(c)
    return {'kind': 'scopeguard_checkpoint_automation_health', 'revision': revision(),
            **{k: data[k] for k in ('version', 'healthy', 'paused', 'total', 'implemented_adapters',
                'remaining_adapters', 'contexts_evaluated', 'current_contexts', 'contexts_total', 'owned', 'error')}}
