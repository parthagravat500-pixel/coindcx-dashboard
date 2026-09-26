"""Automatic evidence indexing and triage. No network, target activation or reports."""
import hashlib
import json
import re
import time

import autopilot
import projectaudit

QUALIFIED = ('runtime_reproduced','local_reproduction','source_lead')
LABELS = {'runtime_reproduced':'Repeated test evidence','local_reproduction':'Reproduced in a local component',
          'source_lead':'Possible issue in code','not_reproduced':'Not reproduced by covered probes',
          'needs_context':'More context required','set_aside':'Set aside by your review',
          'historical_runtime':'Earlier test evidence','not_observed':'No longer observed; not a proven fix'}


def init(c):
    c.executescript('''
      CREATE TABLE IF NOT EXISTS lead_index (
        id TEXT PRIMARY KEY,kind TEXT,source TEXT,version TEXT,state TEXT,priority INTEGER,
        first_seen INTEGER,updated INTEGER,observed INTEGER,active INTEGER,details TEXT);
      CREATE TABLE IF NOT EXISTS lead_index_health (id INTEGER PRIMARY KEY,heartbeat INTEGER,changes INTEGER);
      INSERT OR IGNORE INTO lead_index_health VALUES(1,0,0);
    ''')


def key(kind,source,finding):
    return hashlib.sha256(json.dumps([kind,source,finding]).encode()).hexdigest()[:24]


def sync(c):
    """Index only existing saved evidence; unchanged work creates no fresh result."""
    now = int(time.time()); seen = set(); changes = 0
    def upsert(identity,kind,source,state,priority,observed,details):
        nonlocal changes
        seen.add(identity)
        payload = json.dumps(details,sort_keys=True)
        version = hashlib.sha256(json.dumps([state,priority,observed,payload]).encode()).hexdigest()
        old = c.execute('SELECT version,active FROM lead_index WHERE id=?',(identity,)).fetchone()
        if old and old['version']==version and old['active']: return
        c.execute('''INSERT INTO lead_index VALUES(?,?,?,?,?,?,?,?,?,1,?) ON CONFLICT(id)
          DO UPDATE SET version=excluded.version,state=excluded.state,priority=excluded.priority,
          updated=excluded.updated,observed=excluded.observed,active=1,details=excluded.details''',
          (identity,kind,source,version,state,priority,now,now,observed,payload))
        changes += 1
    for audit in projectaudit.snapshot(c):
        for finding in audit['result']['findings']:
            component = finding.get('component_validation',{})
            modeled = finding.get('automatic_validation',{})
            if finding.get('set_aside'):
                state,rank,reason,next_step = 'set_aside',0,'Your current review set this version aside.','Reconsider if the code or evidence changes.'
            elif component.get('component_verified') is True:
                state,rank,reason,next_step = 'local_reproduction',80,component['reason'],'Verify the actual application, database dialect, access rules and program scope before calling this a bug.'
            elif component.get('status')=='not_reproduced':
                state,rank,reason,next_step = 'not_reproduced',15,component['reason'],'These probes found no bypass; other paths and runtime behavior remain unresolved.'
            elif modeled.get('status')=='modeled_flow':
                state,rank,reason,next_step = 'source_lead',45,modeled['reason'],'An isolated application test is still required. No live exploit or bounty has been established.'
            else:
                state,rank,reason,next_step = 'needs_context',10,'The supported checks could not validate this path.','The missing runtime or framework context is required before more validation.'
            upsert(key('source',audit['name'],finding['id']),'source',audit['name'],state,
                   rank+min(9,max(0,finding.get('research_priority',0)//10)),audit['checked'],
                   {'title':finding['title'],'file':finding['file'],'line':finding['line'],
                    'source_digest':audit['digest'],'reason':reason,'next_step':next_step,
                    'evidence':component.get('evidence',[]) if component.get('component_verified') else modeled.get('evidence',[]),
                    'draft':finding.get('investigation_draft',''),'application_verified':False,
                    'confirmed_bounty':False,'submission_ready':False})
    current_jobs = {j['key']:j for j in autopilot.jobs(c,now)}
    for row in c.execute('SELECT * FROM autonomous_cases ORDER BY last_seen DESC LIMIT 100'):
        current = current_jobs.get(row['job'])
        current_version = bool(current and current['stamp']==row['stamp'] and
                               (not current['blocker'] or 'possible issue was saved' in current['blocker_detail']))
        state = 'runtime_reproduced' if current_version else 'historical_runtime'
        upsert(key('runtime',row['job'],row['id']),'runtime',row['job'],state,100 if current_version else 25,row['last_seen'],
               {'title':'Repeated access-boundary observation','reason':'A supported bounded test recorded positive controls and repeated exposure.',
                'next_step':'Review intended access, current scope, actual impact and duplicates before any report.',
                'evidence':json.loads(row['evidence']),'draft':row['draft'],
                'application_tested':True,'configuration_current':current_version,
                'application_verified':False,'confirmed_bounty':False,'submission_ready':False})
    for row in c.execute('SELECT id FROM lead_index WHERE active=1').fetchall():
        if row['id'] not in seen:
            c.execute("UPDATE lead_index SET active=0,state='not_observed',updated=? WHERE id=?",(now,row['id']))
            changes += 1
    # Retain all current supported entries (bounded upstream), plus 200 old leads.
    c.execute('DELETE FROM lead_index WHERE active=0 AND id NOT IN (SELECT id FROM lead_index WHERE active=0 ORDER BY updated DESC,id LIMIT 200)')
    c.execute('UPDATE lead_index_health SET heartbeat=?,changes=changes+? WHERE id=1',(now,changes))
    return changes


def snapshot(c):
    h = c.execute('SELECT * FROM lead_index_health WHERE id=1').fetchone(); now=int(time.time())
    counts = {row['state']:row['n'] for row in c.execute('SELECT state,COUNT(*) n FROM lead_index WHERE active=1 GROUP BY state')}
    leads = []
    for row in c.execute('SELECT * FROM lead_index ORDER BY active DESC,priority DESC,observed DESC,id LIMIT 100'):
        leads.append({k:row[k] for k in ('id','kind','source','state','priority','first_seen','updated','observed','active')}|
                     {'label':LABELS[row['state']],'details':json.loads(row['details'])})
    total = c.execute('SELECT COUNT(*) FROM lead_index').fetchone()[0]
    return {'heartbeat':h['heartbeat'],'healthy':bool(h['heartbeat'] and 0<=now-h['heartbeat']<90),
            'paused':bool(c.execute('SELECT paused FROM settings').fetchone()[0]),
            'counts':counts,'active_leads':sum(counts.get(k,0) for k in QUALIFIED),
            'qualified_states':list(QUALIFIED),'leads':leads,'changes':h['changes'],
            'total_records':total,'limited':total>len(leads),
            'confirmed_bounty_bugs':0,'automatic_submission':False,
            'coverage':'Automatically indexes approved source-review paths and repeated runtime observations. Local component reproductions are not verified application bugs.'}


def receipt(c,revision):
    s=snapshot(c)
    return {'kind':'scopeguard_lead_health','revision':revision if re.fullmatch('[0-9a-f]{40}',revision or '') else 'unknown',
            'healthy':s['healthy'],'paused':s['paused'],'counts':s['counts'],
            'active_leads':s['active_leads'],'confirmed_bounty_bugs':0}
