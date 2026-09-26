"""Automatic owned-source pipeline; no network, credentials or target activation."""
import json
import time
import re

import projectaudit
import sourceaudit


def init(c):
    c.executescript('''
      CREATE TABLE IF NOT EXISTS automatic_research_status (
        id INTEGER PRIMARY KEY, heartbeat INTEGER, checked INTEGER,
        state TEXT, completed INTEGER, failure_count INTEGER, due INTEGER);
      INSERT OR IGNORE INTO automatic_research_status VALUES(1,0,0,'waiting',0,0,0);
    ''')


def tick(c, root, log):
    now = int(time.time())
    c.execute('UPDATE automatic_research_status SET heartbeat=? WHERE id=1', (now,))
    if c.execute('SELECT paused FROM settings').fetchone()[0]:
        return
    row = c.execute('SELECT * FROM automatic_research_status WHERE id=1').fetchone()
    if row['due'] > now:
        return
    try:
        files = {}
        for name in sourceaudit.FILES:
            path = root / name
            if not path.is_file() or path.is_symlink() or path.stat().st_size > sourceaudit.MAX_BYTES:
                raise ValueError('Expected source missing or outside the bounded file limit')
            files[name] = path.read_text(encoding='utf-8')
        # Save all stages together, or retain the preceding complete evidence.
        c.execute('SAVEPOINT automatic_source_review')
        try:
            changed = projectaudit.record(c, 'ScopeGuard', files)
            sourceaudit.installed(c, root)
            c.execute("UPDATE automatic_research_status SET checked=?,state='waiting',completed=completed+?,failure_count=0,due=? WHERE id=1",
                      (now, int(changed), now+60))
        except Exception:
            c.execute('ROLLBACK TO automatic_source_review')
            raise
        finally:
            c.execute('RELEASE automatic_source_review')
        if changed:
            log(c, 'Automatic owned-source review completed: input paths, bounded synthetic experiments and private investigation drafts saved. No external test or confirmed bug.')
    except Exception:
        failures = row['failure_count'] + 1
        c.execute("UPDATE automatic_research_status SET state='error',failure_count=?,due=? WHERE id=1",
                  (failures, now+min(3600, 60*2**min(failures-1, 6))))
        # Source text and exception contents may include secrets; retain neither.
        log(c, 'Automatic owned-source review failed; previous evidence retained. Retry scheduled with backoff.')


def snapshot(c):
    row = dict(c.execute('SELECT * FROM automatic_research_status WHERE id=1').fetchone())
    now = int(time.time())
    row['healthy'] = bool(row['heartbeat'] and 0 <= now-row['heartbeat'] < 90)
    paused = bool(c.execute('SELECT paused FROM settings').fetchone()[0])
    row['state'] = 'paused' if paused else 'unavailable' if not row['healthy'] else row['state']
    row['scope'] = 'Installed ScopeGuard Python source; existing authorized source watches and uploads also use automatic path experiments.'
    row['summary'] = {
        'paused': 'Automatic research is paused with the main switch.',
        'unavailable': 'Research worker has not checked in recently. Previous evidence is retained.',
        'waiting': 'Automatically checks for source changes; saves paths, local experiments and investigation drafts when code changes.',
        'error': 'Last source review failed. Retrying with backoff; previous evidence is retained.'
    }.get(row['state'], 'Waiting for the first source review.')
    row['projects'] = []
    for audit in c.execute('SELECT name,checked,result FROM project_audits ORDER BY checked DESC'):
        result = json.loads(audit['result'])
        v = result.get('automatic_validation')
        if v:
            row['projects'].append({'name': audit['name'], 'checked': audit['checked'],
                                    'files': result['files_analyzed'],
                                    'methods':result.get('methods_analyzed',0), **v})
    row['confirmed_bugs'] = 0
    row['external_tests'] = 0
    return row


def receipt(c,revision):
    """Aggregate operational evidence only; no project names, paths or findings."""
    status=snapshot(c)
    owned=c.execute("SELECT checked,result FROM project_audits WHERE name='ScopeGuard'").fetchone()
    result=json.loads(owned['result']) if owned else {}
    return {'kind':'scopeguard_source_research_health',
            'revision':revision if re.fullmatch('[0-9a-f]{40}',revision or '') else 'unknown',
            'healthy':status['healthy'],'state':status['state'],'completed':status['completed'],
            'failure_count':status['failure_count'],'engine':projectaudit.VERSION,
            'owned_engine_current':result.get('engine')==projectaudit.VERSION,
            'owned_checked':owned['checked'] if owned else 0,
            'owned_files':result.get('files_analyzed',0),'owned_functions':result.get('functions_analyzed',0),
            'owned_methods':result.get('methods_analyzed',0),
            'owned_entrypoints':result.get('entrypoints_analyzed',0),
            'owned_declared_functions':result.get('functions_declared',0),
            'owned_work_limited_entries':result.get('work_limited_entries',0),
            'owned_coverage_limited':bool(result.get('bounded_or_truncated',False)),
            'owned_static_candidates':result.get('total_findings',0),
            'owned_component_reproductions':result.get('component_validation',{}).get('reproduced',0),
            'confirmed_bounty_bugs':0}
