"""Generate the readable checkpoint list from the reviewed catalog; no network."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def render(data):
    lines=['# ScopeGuard: 1,000 research checkpoints','',
           'Version: '+data['version']+' · Authored: '+data['authored_on'],'',
           data['provenance'],'',data['limits'],'',
           'Each numbered item is an investigation question or expected control, not a completed test. '
           'The dashboard identifies the small subset with existing automatic evidence support. '
           'The rest require contextual review, appropriate tooling, and separate permission.','',
           '## Background references','']
    for r in data['references'].values():
        lines.append('- ['+r['title']+']('+r['url']+') · checked '+r['checked_on'])
    lines+=['','References are background reading at category level, not exact requirement mappings. '
            'Checkpoint wording and identifiers belong to this catalog.','']
    lines+=['## Automatic and AI support','',
            'Eleven entries have partial automatic evidence support: four policy metadata checks '
            '(SG-0001, SG-0002, SG-0006, SG-0008) and seven existing Python pattern checks '
            '(SG-0781 through SG-0787). Evidence support is not whole-control validation.','',
            'Twelve entries are also used as guidance in the existing experimental private AI '
            'review: six per fixed owned-code excerpt. AI suggestions remain unverified and do '
            'not change testing permissions, confirmed-bug counts, or checklist completion.','']
    for group in data['categories']:
        lines+=['## '+group['title'],'',
                'Suggested contexts: '+', '.join(group['profiles'])+'. Method: '+group['method'].replace('_',' ')+'.','',
                '**Before review:** '+group['prerequisites'],'',
                '**Evidence to keep:** '+group['evidence'],'']
        lines+=['- **'+x['id']+'** — '+x['title'] for x in group['checks']]
        lines+=['']
    return '\n'.join(lines)


if __name__=='__main__':
    data=json.loads((ROOT/'checkpoints/catalog.json').read_text())
    (ROOT/'checkpoints/CHECKPOINTS.md').write_text(render(data))
