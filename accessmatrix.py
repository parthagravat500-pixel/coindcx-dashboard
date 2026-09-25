"""Two owned accounts, two exact approved JSON resources, at most six GETs.

Method: OWASP WSTG-v42-ATHZ-02 and PortSwigger horizontal access controls.
Evidence establishes only the observed marker boundary, never bounty eligibility.
"""
import hashlib
import time


def compare(config, transport, allowed=lambda: True, pace=time.sleep):
    if config.get('mode') != 'two_account' or config['authorization'] == config['peer_authorization']:
        raise ValueError('Two distinct owned account credentials are required')
    evidence = []
    result = {'mode': 'two_account', 'evidence': evidence, 'reproduced': False,
              'submission_ready': False, 'severity': 'Not assessed',
              'marker_sha256': hashlib.sha256(config['marker'].encode()).hexdigest(),
              'coverage': 'Two supplied accounts and two exact JSON URLs; no anonymous, write or full-site coverage.'}

    def observe(label, url, auth, marker):
        if not allowed():
            raise InterruptedError('Permission changed or testing paused')
        if evidence:
            pace(1)
        if not allowed():
            raise InterruptedError('Permission changed or testing paused')
        if len(evidence) >= 6:
            raise RuntimeError('Request budget exhausted')
        response = transport(url, auth, marker)
        evidence.append({'step': label, **response})
        if response['status'] == 429 or response['status'] >= 500:
            raise RuntimeError('Rate limit or server error; stop testing')
        return response

    def positive(response):
        return 200 <= response['status'] < 300 and response['json'] and response['marker_present']

    def owner_control():
        return observe('Account A reads its own resource', config['url'], config['authorization'], config['marker'])

    def peer_control():
        return observe('Account B reads its own resource', config['peer_url'], config['peer_authorization'], config['peer_marker'])

    if not positive(owner_control()) or not positive(peer_control()):
        return {**result, 'status': 'Setup needs attention: both account controls must return their own markers'}
    probe = observe('Account B reads account A resource', config['url'], config['peer_authorization'], config['marker'])
    repeat = None
    if positive(probe):
        repeat = observe('Repeat account B comparison', config['url'], config['peer_authorization'], config['marker'])
    # A failed or expired control must not turn an access error into a clean result.
    if not positive(owner_control()) or not positive(peer_control()):
        return {**result, 'status': 'Setup needs attention: repeated account control failed; result inconclusive'}
    if repeat and positive(repeat):
        result.update(reproduced=True,
                      status='Account A marker returned to account B in two requests',
                      impact='A synthetic marker designated private to account A was returned using account B credentials. Verify that these are distinct accounts without intended shared access before assessing impact.',
                      reproduction=['Use two separately owned test accounts with no shared access to the test records.',
                                    'Verify each account can read its own synthetic marker at its exact approved URL.',
                                    'Read account A URL twice using account B credentials and observe the account A marker.',
                                    'Repeat both own-account controls to exclude broken sessions.'],
                      remediation='Check resource ownership and account permissions server-side on every request.')
    elif positive(probe):
        result['status'] = 'Inconclusive: second-account exposure did not repeat'
    elif probe['status'] in (401, 403, 404) or (200 <= probe['status'] < 300 and probe['json']):
        result['status'] = 'Second-account boundary held for this test; anonymous access not assessed'
    else:
        result['status'] = 'Inconclusive response; second-account exposure not established'
    return result
