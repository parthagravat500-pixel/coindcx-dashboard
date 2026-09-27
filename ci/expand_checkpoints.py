"""Build original research scenario variants; offline, deterministic, no test execution.

The 1,000 original prompts remain unchanged. Each gets nine contextual variants
from its area's reviewed matrix. Variants are hypotheses, not independent
vulnerability classes, standard requirements, or implemented adapters.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def expand(data, matrix):
    groups = data['categories']
    originals = [r for g in groups for r in g['checks'] if not r.get('parent_id')]
    digest = hashlib.sha256(json.dumps(originals, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if len(originals) != 1000 or digest != matrix['original_sha256']:
        raise ValueError('Original checkpoint IDs, wording or order changed')
    if set(matrix['areas']) != {g['id'] for g in groups}:
        raise ValueError('Every area needs an explicit scenario matrix')
    next_id = 1001
    for group in groups:
        base = [r for r in group['checks'] if not r.get('parent_id')]
        conditions = matrix['areas'][group['id']]
        if len(conditions) != 9 or len(set(conditions)) != 9:
            raise ValueError('Each area needs nine distinct conditions')
        group['checks'] = list(base)
        for parent in base:
            for index, condition in enumerate(conditions, 1):
                group['checks'].append({
                    'id': 'SG-' + str(next_id).zfill(4),
                    'title': parent['title'].rstrip('.') + ' — ' + condition + '.',
                    'parent_id': parent['id'],
                    'scenario_id': group['id'] + '-variant-' + str(index),
                    'condition': condition,
                })
                next_id += 1
        additions = ['asvs']
        if 'web' in group['profiles'] or 'api' in group['profiles']:
            additions.append('academy')
        if group['id'] in ('area-41', 'area-42'):
            additions.append('mastg')
        group['references'] = list(dict.fromkeys(group['references'] + additions))
    data.update(version='2026.09.27.3', authored_on='2026-09-27', expected_total=10000)
    data['expansion'] = {
        'core_prompts': 1000, 'scenario_variants': 9000,
        'original_sha256': digest,
        'method': '1,000 preserved core prompts plus nine area-specific scenario variations per prompt. '
                  'These are 10,000 research entries, not 10,000 independent vulnerability classes or executable tests. '
                  'Each variation requires its own applicability decision and evidence; parent evidence is never inherited.',
    }
    data['provenance'] = ('Original ScopeGuard research prompts and systematic scenario variations, informed by '
        'OWASP WSTG, ASVS, API Security, MASVS/MASTG, GenAI guidance and PortSwigger Web Security Academy. '
        'References are background at area level, not one-to-one standard mappings. '
        'This is not a universal checklist used by all top researchers, a certification, or an exhaustive security assessment.')
    data['references'].update({
        'asvs': {'title': 'OWASP Application Security Verification Standard 5.0.0',
                 'url': 'https://github.com/OWASP/ASVS/tree/v5.0.0', 'checked_on': '2026-09-27'},
        'academy': {'title': 'PortSwigger Web Security Academy',
                    'url': 'https://portswigger.net/web-security', 'checked_on': '2026-09-27'},
        'mastg': {'title': 'OWASP Mobile Application Security Testing Guide',
                  'url': 'https://mas.owasp.org/MASTG/', 'checked_on': '2026-09-27'},
    })
    if next_id != 10001:
        raise ValueError('Expansion did not produce exactly 10,000 entries')
    return data


if __name__ == '__main__':
    path = ROOT / 'checkpoints/catalog.json'
    matrix = json.loads((ROOT / 'checkpoints/scenario-matrix.json').read_text())
    path.write_text(json.dumps(expand(json.loads(path.read_text()), matrix), indent=2, ensure_ascii=False) + '\n')
