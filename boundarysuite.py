"""Bounded, read-only access matrices. Only caller-supplied owned resources.

The runner does not discover URLs, grant permission, create accounts, or mutate
data. Every comparison is bracketed by a valid owner control and reproduced
twice before it is saved as a candidate. Bodies and credentials never persist.
"""
import hashlib
import json
import time

VERSION = 'matrix-1'
CHECKPOINTS = {
    'private_object': 'SG-0161', 'nested_resource': 'SG-0165',
    'admin_read': 'SG-0166', 'representation': 'SG-0170',
    'export': 'SG-0171', 'search': 'SG-0172', 'preview': 'SG-0178',
}


def positive(response):
    return (type(response.get('status')) is int and 200 <= response['status'] < 300
            and response.get('json') is True and response.get('marker_present') is True
            and len(response.get('sha256', '')) == 64)


def denied(response):
    # A missing marker in a generic 200 is not proof that access was denied.
    return response.get('status') in (401, 403, 404) and len(response.get('sha256', '')) == 64


def safe_receipt(raw, step, resource, actor):
    result = {'step': step, 'resource': resource, 'actor': actor}
    for key in ('status', 'bytes'):
        if type(raw.get(key)) is int: result[key] = raw[key]
    for key in ('json', 'marker_present'):
        result[key] = raw.get(key) is True
    digest = raw.get('sha256', '')
    if isinstance(digest, str) and len(digest) == 64 and all(x in '0123456789abcdef' for x in digest):
        result['sha256'] = digest
    return result


def run(config, transport, allowed=lambda: True, pace=time.sleep, cursor=0):
    accounts = {a['id']: a for a in config['accounts']}
    own_resources = {a:next((r for r in config['resources'] if r['owner']==a),None) for a in accounts}
    tests = [(r, actor) for r in config['resources']
             for actor in [*accounts, 'anonymous'] if actor not in r['allow']]
    tests.sort(key=lambda pair: (config.get('priorities', {}).get(pair[0]['feature'], 0) * -1,
                                pair[0]['id'], pair[1]))
    rows, receipts = [], []
    result = {'version': VERSION, 'tests': rows, 'receipts': receipts, 'requests': 0,
              'total_comparisons': len(tests), 'next_cursor': cursor, 'complete': False,
              'stopped': False, 'stop_reason': '', 'submission_ready': False}
    budget = config['request_budget']
    start = cursor % max(1, len(tests))

    def request(r, actor, step):
        if not allowed(): raise InterruptedError('Permission changed')
        if len(receipts) >= budget: raise InterruptedError('Request budget exhausted')
        if receipts: pace(config['request_gap'])
        if not allowed(): raise InterruptedError('Permission changed')
        auth = accounts[actor]['authorization'] if actor != 'anonymous' else ''
        raw = transport(r['url'], auth, r['marker'])
        receipt = safe_receipt(raw, step, r['id'], actor)
        receipts.append(receipt); result['requests'] = len(receipts)
        if raw.get('status') == 429 or raw.get('status', 0) >= 500:
            raise InterruptedError('Rate limit or server error')
        if 300 <= raw.get('status', 0) < 400:
            raise InterruptedError('Redirect requires review')
        return raw

    try:
        for index in range(start, len(tests)):
            r, actor = tests[index]
            cost=4 if actor=='anonymous' else 6
            if budget - len(receipts) < cost: break
            peer=own_resources.get(actor)
            offset = len(receipts)
            test = {'resource': r['id'], 'actor': actor, 'owner': r['owner'],
                    'checkpoint': CHECKPOINTS[r['feature']], 'feature': r['feature'],
                    'state': 'inconclusive', 'receipt_start': offset,
                    'actor_resource':peer['id'] if peer else None}
            rows.append(test)
            if not positive(request(r, r['owner'], 'owner_before')):
                result.update(stopped=True, stop_reason='Owner control failed'); break
            if actor!='anonymous' and (not peer or not positive(request(peer,actor,'actor_before'))):
                result.update(stopped=True,stop_reason='Comparison account control failed');break
            one = request(r, actor, 'comparison_one')
            two = request(r, actor, 'comparison_two')
            if actor!='anonymous' and not positive(request(peer,actor,'actor_after')):
                result.update(stopped=True,stop_reason='Final comparison account control failed');break
            after = request(r, r['owner'], 'owner_after')
            if not positive(after):
                result.update(stopped=True, stop_reason='Final owner control failed'); break
            test['state'] = ('reproduced' if positive(one) and positive(two) else
                             'boundary_held' if denied(one) and denied(two) else 'inconclusive')
            test['receipt_count'] = len(receipts) - offset
            result['next_cursor'] = (index + 1) % max(1, len(tests))
            if test['state'] == 'reproduced':
                result.update(stopped=True, stop_reason='Repeated private marker exposure'); break
            if index + 1 == len(tests): result['complete'] = True
    except InterruptedError as exc:
        result.update(stopped=True, stop_reason=str(exc))
    except Exception:
        result.update(stopped=True, stop_reason='Transport or response failure')
    if not allowed():
        for test in rows: test['state'] = 'inconclusive'
        result.update(stopped=True, stop_reason='Permission changed')
    result['reproduced'] = sum(t['state'] == 'reproduced' for t in rows)
    result['fingerprint'] = hashlib.sha256(json.dumps(
        [(t['resource'], t['actor'], t['state']) for t in rows], sort_keys=True).encode()).hexdigest()
    return result


def verify_test(result, test):
    """Independent evidence gate; does not trust the runner's reproduced flag."""
    actor=test.get('actor');owner=test.get('owner');resource=test.get('resource');peer=test.get('actor_resource')
    sequence=[('owner_before',resource,owner)]
    if actor!='anonymous':sequence.append(('actor_before',peer,actor))
    sequence.extend([('comparison_one',resource,actor),('comparison_two',resource,actor)])
    if actor!='anonymous':sequence.append(('actor_after',peer,actor))
    sequence.append(('owner_after',resource,owner))
    rows = result.get('receipts', [])[test.get('receipt_start', 0):test.get('receipt_start', 0)+len(sequence)]
    return (test.get('state') == 'reproduced' and len(rows) == len(sequence)
            and [(r.get('step'),r.get('resource'),r.get('actor')) for r in rows] == sequence
            and all(positive(r) for r in rows)
            and (actor=='anonymous' or peer is not None and peer!=resource)
            and test.get('actor') != test.get('owner'))


def benchmark():
    """Fixed regression benchmark, not a claim about production detection rates."""
    a, b = 'lab-owner', 'lab-peer'
    config = {'accounts': [{'id':'a','authorization':a}, {'id':'b','authorization':b}],
              'resources':[{'id':'r1','owner':'a','allow':['a'],'feature':'private_object',
                            'url':'https://fixture.invalid/owned','marker':'synthetic-marker'},
                           {'id':'r2','owner':'b','allow':['b'],'feature':'private_object',
                            'url':'https://fixture.invalid/peer','marker':'synthetic-peer-marker'}],
              'request_budget':24, 'request_gap':0}
    rows = []
    for name in ('vulnerable','cross_account_leak','fixed','broken_owner','broken_peer','generic_200','transient','rate_limited','redirect','revoked'):
        calls = []; permits = [True]
        def fetch(url, auth, marker):
            calls.append(auth)
            if name == 'revoked' and len(calls) == 2: permits[0] = False
            owner=a if url.endswith('/owned') else b
            private = auth == owner or name in ('vulnerable','revoked') or name == 'transient' and len(calls) == 2
            if name=='cross_account_leak' and url.endswith('/owned') and auth==b:private=True
            status = 200 if private or name == 'generic_200' else 403
            if name == 'broken_owner': status, private = 401, False
            if name == 'broken_peer' and auth==b:status,private=401,False
            if name == 'rate_limited' and auth != a: status = 429
            if name == 'redirect' and auth != a: status = 302
            return {'status':status,'json':True,'marker_present':private,
                    'sha256':hashlib.sha256(str((status,private)).encode()).hexdigest(),'bytes':20}
        result = run(config, fetch, lambda: permits[0], lambda _: None)
        detected = any(verify_test(result,t) for t in result['tests'])
        expected = name in ('vulnerable','cross_account_leak')
        rows.append({'name':name,'expected_detection':expected,'detected':detected,
                     'passed':detected == expected, 'requests':len(calls)})
    return {'version':VERSION, 'cases':rows, 'passed':sum(r['passed'] for r in rows),
            'total':len(rows), 'false_positives':sum(r['detected'] and not r['expected_detection'] for r in rows),
            'misses':sum(r['expected_detection'] and not r['detected'] for r in rows),
            'scope':'Synthetic access-matrix fixtures only. Real program accuracy is not measured by these results.'}
