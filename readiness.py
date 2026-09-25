"""Explain practical coverage separately from discovery and authorization.

These dated policy notes are advisory. They never create targets, grant
permission, provide credentials or authorize an additional request.
"""
import json
from urllib.parse import urlsplit

REVIEWED = '2026-09-25'
POLICIES = {
    'altera/altera': ('specialist', 'Needs FPGA and firmware test environment',
        'Bounties cover supported Stratix 10/Agilex hardware and SDM firmware. Web infrastructure is excluded. ScopeGuard has no FPGA or firmware test harness.'),
    'arm/arm': ('specialist', 'Needs GPU driver or firmware test environment',
        'Scope is Mali GPU drivers and CSF firmware, with supported configurations and reproducible impact. ScopeGuard cannot exercise those devices or drivers.'),
    'arm/trustedfirmware': ('specialist', 'Needs supported firmware test environment',
        'TF-A, TF-M, OP-TEE and TF-PSA-Crypto require a realistic reproduction on a supported platform. Web infrastructure is excluded; a simulated function call is insufficient.'),
    'bmw/bmwgroup-automotive': ('specialist', 'Needs owned vehicle or mobile-app test setup',
        'This program covers automotive products and related mobile apps. Research must use your own BMW products. ScopeGuard has no configured automotive or mobile test environment.'),
    'capitalcom/capitalcom': ('setup', 'Needs eligible account and exact API test setup',
        'Only listed assets qualify; automated tooling is capped at 10 requests/second. Scanner-only reports without validated impact are excluded. The existing demo connector needs an eligible owned account; account availability must be checked separately.'),
    'delenprivatebank/privatebankdelen': ('setup', 'Needs eligible test resource and account setup',
        'Check the exact listed asset, current testing rules and account availability before configuring a read-only comparison. A public directory entry provides no test credentials or evidence of security impact.'),
    'monzobank/monzopublicbugbountyprogram': ('setup', 'Needs owned Monzo test account and scoped API',
        'Use only your own accounts. Missing headers and cookie attributes are excluded. Account availability, exact eligible endpoints and permission for the planned comparison still need verification.'),
}

METHODS = [
    {'title': 'Two-account authorization comparison', 'status': 'Implemented; needs two owned accounts and two approved JSON URLs',
     'coverage': 'At most six read-only requests with controls and repeated marker evidence. Stops on uncertain results or revoked permission.',
     'sources': ['https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema/',
                 'https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/access-controls/horizontal-access-controls']},
    {'title': 'Anonymous authorization comparison', 'status': 'Implemented; needs an approved private JSON resource',
     'coverage': 'Owner control, anonymous comparison, repeat and final owner control. Synthetic markers only; no automatic reports.',
     'sources': ['https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema/']},
    {'title': 'Contextual source review', 'status': 'Limited Python analysis and small local-model advisory',
     'coverage': 'Review callers, helpers and protections. Trace a real input to a security consequence; a model hypothesis alone is not evidence.',
     'sources': ['https://owasp.org/www-project-code-review-guide/']},
    {'title': 'Business logic and state transitions', 'status': 'Requires an application-specific test plan; no general automatic tester',
     'coverage': 'Map roles, workflow steps and expected invariants. Use controlled accounts and synthetic data. No production race or payment testing is configured.',
     'sources': ['https://portswigger.net/web-security/logic-flaws',
                 'https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/00-Introduction_to_Business_Logic/']},
]


def policy_key(url):
    p = urlsplit(url)
    if p.hostname in ('app.intigriti.com', 'www.intigriti.com', 'intigriti.com'):
        return 'intigriti:' + p.path.rstrip('/')
    if p.hostname == 'bounty.github.com':
        return 'https://hackerone.com/github'
    return url.rstrip('/')


def context(c, now):
    """Query current configuration once, without reading any credential files."""
    targets = [dict(t) for t in c.execute('SELECT id,policy,enabled,expires FROM targets')]
    profiles = [dict(a) for a in c.execute('SELECT target,enabled,expires FROM access_checks')]
    gitlab = c.execute('SELECT enabled,expires,result FROM gitlab_check WHERE id=1').fetchone()
    gitlab_ready = bool(gitlab and gitlab['enabled'] and gitlab['expires'] > now and json.loads(gitlab['result']).get('verified_connection'))
    return {'targets': targets, 'profiles': profiles, 'gitlab': gitlab_ready,
            'paused': bool(c.execute('SELECT paused FROM settings').fetchone()[0]), 'now': now}


def assess(program, ctx):
    key = policy_key(program['url'])
    parts = urlsplit(program['url']).path.strip('/').split('/')
    slug = '/'.join(parts[1:3]) if len(parts) >= 3 and parts[0] == 'programs' else ''
    note = POLICIES.get(slug)
    category, label, explanation = note or ('unknown', 'No testing configured; policy review needed',
        'Confirm the exact eligible asset, permitted test method, account access and expected private-data boundary. Shortlisting does not run a scan.')
    active = [t for t in ctx['targets'] if policy_key(t['policy']) == key and t['enabled'] and t['expires'] > ctx['now']]
    access = [a for a in ctx['profiles'] if a['enabled'] and a['expires'] > ctx['now'] and any(t['id'] == a['target'] for t in active)]
    configured = bool(active or (key == 'https://hackerone.com/gitlab' and ctx['gitlab']))
    if configured:
        category = 'configured'
        label = 'Read-only access check configured' if access or key == 'https://hackerone.com/gitlab' else 'Header checks only; deeper tests need setup'
        explanation = 'Only the saved, approved resources are covered. No whole-program or whole-site coverage is implied.'
    available = bool(program['available'] and not program['stale'] and program['stage'] != 'dismissed')
    if not available:
        category, label = 'unavailable', 'Unavailable or stale; testing needs review'
    elif configured and ctx['paused']:
        label = 'Configured checks are paused'
    active_now = bool(configured and available and not ctx['paused'])
    return {'category': category, 'label': label, 'explanation': explanation,
            'configured': configured, 'active': active_now,
            'rank': {'configured': 0, 'setup': 1, 'unknown': 2, 'specialist': 3, 'unavailable': 4}[category],
            'reviewed_on': REVIEWED if note else None,
            'sources': ['https://app.intigriti.com/programs/' + slug + '/detail'] if note else [],
            'grants_permission': False}
