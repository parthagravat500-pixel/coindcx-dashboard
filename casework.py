"""Local evidence triage and report preparation, never an exploit validator."""
import json
import time

FIELDS = {
    'scope': 'Current scope and program eligibility',
    'steps': 'Numbered reproduction steps',
    'expected': 'Expected result',
    'actual': 'Actual result and redacted evidence',
    'impact': 'Demonstrated impact on your own test account or data',
    'controls': 'Control test and benign explanations checked',
    'duplicates': 'Known issue / duplicate research',
    'remediation': 'Suggested fix',
}
SOURCES = [
    'https://docs.hackerone.com/en/articles/8475116-quality-reports',
    'https://wstg.owasp.org/v4.2/5-Reporting/',
]


def init(c):
    c.execute('CREATE TABLE IF NOT EXISTS case_notes (finding TEXT PRIMARY KEY, notes TEXT, updated INTEGER)')


def save(c, data):
    key = data.get('finding')
    if not isinstance(key, str) or not c.execute('SELECT 1 FROM findings WHERE id=?', (key,)).fetchone():
        raise ValueError('Finding not found')
    notes = data.get('notes')
    if not isinstance(notes, dict) or set(notes) - set(FIELDS):
        raise ValueError('Use the evidence fields shown in the form')
    clean = {}
    for field in FIELDS:
        value = notes.get(field, '')
        if not isinstance(value, str) or len(value) > 1500:
            raise ValueError('Each evidence field must be text, at most 1500 characters')
        clean[field] = value.strip()
    c.execute('INSERT INTO case_notes VALUES (?,?,?) ON CONFLICT(finding) DO UPDATE SET notes=excluded.notes,updated=excluded.updated',
              (key, json.dumps(clean), int(time.time())))


def guidance(rule):
    if rule == 'cors-reflection':
        return ('Investigate first', 2,
                'An origin was reflected with credentials allowed. This deserves closer review, but HEAD headers do not prove browser-readable private data.',
                ['Verify whether a browser can read sensitive data belonging to your own test account under the permitted test conditions.',
                 'Compare with a public or signed-out response. Public data alone does not establish private data exposure.'],
                'Use an explicit origin allowlist and allow credentials only where necessary.')
    if rule.startswith('cookie-'):
        return ('Low signal', 0,
                'The purpose of this cookie is unknown. Analytics, preference and JavaScript-readable cookies may legitimately omit some flags.',
                ['Determine the cookie purpose using only your own account and redact its value.',
                 'Explain a concrete consequence of the missing flag. Repeated missing flags alone are not impact.'],
                'Choose Secure, HttpOnly and SameSite settings according to the cookie purpose and application requirements.')
    if rule == 'framing':
        return ('Needs context', 1,
                'A frameable page is not automatically a clickjacking vulnerability.',
                ['Identify a sensitive action on an authorized page and whether existing controls prevent unintended execution.',
                 'Use only your own test account; a framed public landing page is insufficient evidence.'],
                'Restrict permitted framing with CSP frame-ancestors where appropriate.')
    return ('Low signal', 0,
            'A missing security header is usually a hardening observation. Its absence alone does not establish a vulnerability.',
            ['Check whether the official program excludes missing-header reports.',
             'Document actual behavior and a concrete security consequence; do not infer impact from a header name.'],
            'Evaluate the relevant header in the application context and deploy a compatible policy.')


def assess(c, finding, review):
    row = c.execute('SELECT notes,updated FROM case_notes WHERE finding=?', (finding['id'],)).fetchone()
    notes = json.loads(row['notes']) if row else {}
    label, priority, explanation, questions, fix = guidance(finding['rule'])
    blockers = ['Security impact has not been independently validated.']
    if not review['scope_active']: blockers.append('Website checks are disabled or permission review has expired.')
    if not review['current_observation']: blockers.append('The latest check did not establish that this observation is still present.')
    if finding['feedback'] in ('false_positive', 'ineligible', 'duplicate'):
        priority = -1
        label = 'Deprioritized by your feedback'
        blockers.append('Recorded feedback: ' + finding['feedback'] + '.')
    related = c.execute('SELECT COUNT(*) FROM findings WHERE target=? AND rule=? AND id!=?',
                        (finding['target'], finding['rule'], finding['id'])).fetchone()[0]
    return {'priority': priority, 'label': label, 'explanation': explanation,
            'questions': questions, 'suggested_fix': fix, 'blockers': blockers,
            'fields': FIELDS, 'notes': notes, 'updated': row['updated'] if row else None,
            'missing_sections': [label for key, label in FIELDS.items() if not notes.get(key)],
            'completed_sections': sum(bool(notes.get(key)) for key in FIELDS),
            'total_sections': len(FIELDS), 'related_local_findings': related,
            'duplicate_status': 'Only local records checked; private reports on bounty platforms are not searchable here.',
            'submission_ready': False, 'sources': SOURCES}


def report_section(case):
    lines = ['', '## Evidence review', case['label'], case['explanation'],
             'These notes are user-provided and unverified. Completed fields do not validate a bug.',
             '', '### Remaining blockers'] + ['- ' + x for x in case['blockers']]
    for key, label in FIELDS.items():
        lines += ['', '### ' + label, case['notes'].get(key) or 'Not provided.']
    lines += ['', '### Contextual remediation guidance', case['suggested_fix'],
              '', '### Duplicate coverage', case['duplicate_status']]
    return '\n'.join(lines)
