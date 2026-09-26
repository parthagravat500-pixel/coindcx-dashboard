"""Focused research preparation, bounded workflows, evidence and outcome learning."""
from collections import Counter
import hashlib
import json
import os
import re
import secrets
import tempfile
import threading
import time

import accesscheck
import autopilot
import boundarysuite
import programqueue
import researchbrief
import workflowmap
import browserruntime

VERSION='2026.09.26.3'
RUN_LOCK=threading.Lock()
DISPOSITIONS=('unreviewed','validated','false_positive','duplicate','out_of_scope','accepted')


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()


def init(c):
    c.executescript('''
      CREATE TABLE IF NOT EXISTS hunt_profiles (
        id TEXT PRIMARY KEY,name TEXT,policy TEXT,revision TEXT,stamp TEXT,metadata TEXT,
        enabled INTEGER,expires INTEGER,due INTEGER,cursor INTEGER DEFAULT 0,
        stable INTEGER DEFAULT 0,failures INTEGER DEFAULT 0,last_fingerprint TEXT DEFAULT '',
        last_started INTEGER DEFAULT 0,last_finished INTEGER DEFAULT 0,state TEXT DEFAULT 'queued',
        reason TEXT DEFAULT '',interval INTEGER);
      CREATE TABLE IF NOT EXISTS hunt_runs (
        id INTEGER PRIMARY KEY,profile TEXT,revision TEXT,stamp TEXT,kind TEXT,
        started INTEGER,finished INTEGER,lease_until INTEGER,state TEXT,result TEXT);
      CREATE UNIQUE INDEX IF NOT EXISTS hunt_one_running ON hunt_runs((1)) WHERE state='running';
      CREATE TABLE IF NOT EXISTS hunt_cases (
        id TEXT PRIMARY KEY,profile TEXT,revision TEXT,stamp TEXT,feature TEXT,checkpoint TEXT,
        resource TEXT,actor TEXT,first_seen INTEGER,last_seen INTEGER,evidence TEXT,
        disposition TEXT DEFAULT 'unreviewed',impact TEXT DEFAULT '',reviewed INTEGER DEFAULT 0,
        review_checks TEXT DEFAULT '{}');
      CREATE TABLE IF NOT EXISTS hunt_health (
        id INTEGER PRIMARY KEY,heartbeat INTEGER DEFAULT 0,benchmark TEXT DEFAULT '{}',version TEXT DEFAULT '');
      INSERT OR IGNORE INTO hunt_health(id) VALUES(1);
      CREATE TABLE IF NOT EXISTS hunt_maps (
        profile TEXT PRIMARY KEY,revision TEXT,stamp TEXT,checked INTEGER,result TEXT);
    ''')
    for name,definition in (('focus','TEXT DEFAULT \'[]\''),('focus_checked','INTEGER DEFAULT 0')):
        if name not in {r[1] for r in c.execute('PRAGMA table_info(hunt_health)')}:
            c.execute('ALTER TABLE hunt_health ADD COLUMN '+name+' '+definition)
    if 'order_scores' not in {r[1] for r in c.execute('PRAGMA table_info(hunt_profiles)')}:
        c.execute("ALTER TABLE hunt_profiles ADD COLUMN order_scores TEXT DEFAULT '{}'")


def policy_stamp(c, policy, target_ids):
    rows=[]
    for key in sorted(set(target_ids)):
        target=c.execute('SELECT * FROM targets WHERE id=?',(key,)).fetchone()
        rows.append({k:target[k] for k in ('id','url','policy','rules','expires','enabled')} if target else {'id':key,'missing':True})
    research=c.execute("SELECT digest FROM program_research WHERE rtrim(policy,'/')=?",(policy.rstrip('/'),)).fetchone()
    return digest([rows,research['digest'] if research else None])


def path(root,key):
    if not re.fullmatch('[0-9a-f]{24}',key):raise ValueError('Unknown workflow')
    return root/('workflow-'+key+'.json')


def load(root,key):
    try:
        p=path(root,key)
        if p.stat().st_size>100000: return None
        return json.loads(p.read_text())
    except (ValueError,OSError):return None


def configure(c,root,data):
    now=int(time.time())
    if not all(data.get(k) is True for k in ('permission','own_accounts','synthetic_data','read_only_get','expected_access_reviewed')):
        raise ValueError('Verify program permission, owned test accounts, synthetic records, read-only GETs and expected access.')
    name=data.get('name','')
    if not isinstance(name,str) or not 1<=len(name.strip())<=100:raise ValueError('Name the workflow')
    rules=data.get('rules','')
    if not isinstance(rules,str) or not 30<=len(rules.strip())<=8000:raise ValueError('Record the current rules permitting the exact workflow and request budget.')
    interval=data.get('interval',3600);budget=data.get('request_budget',12);gap=data.get('request_gap',2)
    if type(interval) is not int or not 900<=interval<=86400:raise ValueError('Workflow interval must be 15 minutes to 24 hours')
    if type(budget) is not int or not 4<=budget<=24:raise ValueError('Request budget must be 4–24')
    if type(gap) not in (int,float) or not 1<=gap<=10:raise ValueError('Request gap must be 1–10 seconds')
    accounts=data.get('accounts',[]);resources=data.get('resources',[])
    if not isinstance(accounts,list) or not 1<=len(accounts)<=4:raise ValueError('Configure 1–4 owned test accounts')
    if not isinstance(resources,list) or not 1<=len(resources)<=12:raise ValueError('Choose 1–12 owned resources')
    clean_accounts=[];account_ids=set();credentials=set()
    for a in accounts:
        key=a.get('id','');auth=a.get('authorization','');role=a.get('role','member')
        if not isinstance(key,str) or not re.fullmatch('[a-z][a-z0-9_-]{0,19}',key) or key=='anonymous' or key in account_ids:
            raise ValueError('Account labels must be unique short names')
        if not isinstance(auth,str) or not auth.startswith(('Basic ','Bearer ')) or not 15<=len(auth)<=4096 or not all(32<=ord(x)<127 for x in auth) or auth in credentials:
            raise ValueError('Each owned account needs a distinct valid authorization value')
        if role not in ('owner','admin','member','viewer'):raise ValueError('Choose a supported account role')
        account_ids.add(key);credentials.add(auth);clean_accounts.append({'id':key,'role':role,'authorization':auth})
    targets={};clean_resources=[];seen=set();policy=None
    def target(key):
        nonlocal policy
        if type(key) is not int:raise ValueError('Select a saved exact URL')
        row=c.execute('SELECT * FROM targets WHERE id=?',(key,)).fetchone()
        if not row or not row['enabled'] or row['expires']<=now or programqueue.target_gate(c,row,now):
            raise ValueError('A selected URL is disabled, expired or blocked')
        if policy and policy.rstrip('/')!=row['policy'].rstrip('/'):raise ValueError('All URLs must belong to the same program')
        policy=row['policy'];targets[key]=dict(row);return row
    for r in resources:
        t=target(r.get('target'));key=r.get('id','');owner=r.get('owner');allow=r.get('allow',[])
        marker=r.get('marker','');feature=r.get('feature','private_object')
        if not isinstance(key,str) or not re.fullmatch('[a-z][a-z0-9_-]{0,29}',key) or key in seen:raise ValueError('Use unique resource labels')
        if owner not in account_ids or not isinstance(allow,list) or owner not in allow or not set(allow)<=account_ids:raise ValueError('Set the owner and allowed test accounts for each resource')
        if feature not in boundarysuite.CHECKPOINTS:raise ValueError('Unsupported feature')
        if not isinstance(marker,str) or not re.fullmatch('[A-Za-z0-9_-]{24,160}',marker) or marker in t['url']:raise ValueError('Use a unique 24–160 character synthetic marker absent from the URL')
        seen.add(key);clean_resources.append({'id':key,'target':t['id'],'url':t['url'],'owner':owner,
                                             'allow':sorted(set(allow)),'marker':marker,'feature':feature})
    if len({r['marker'] for r in clean_resources})!=len(clean_resources):raise ValueError('Resource markers must be distinct')
    if not account_ids<={r['owner'] for r in clean_resources}:raise ValueError('Each account needs its own private control resource')
    if len(account_ids)>1 and budget<6:raise ValueError('Two-account comparisons need at least six permitted requests per run')
    map_ids=data.get('map_targets',[])
    if not isinstance(map_ids,list) or len(map_ids)>6:raise ValueError('Select at most six pages for mapping')
    if map_ids and data.get('mapping_permission') is not True:raise ValueError('Verify GET permission for the exact mapping pages')
    map_urls=[target(key)['url'] for key in map_ids]
    browser_account=data.get('browser_account',clean_accounts[0]['id'])
    if browser_account not in account_ids:raise ValueError('Select an owned account for page mapping')
    # Identity/header credentials are never forwarded between different origins.
    from urllib.parse import urlsplit
    if len({urlsplit(t['url']).netloc for t in targets.values()})!=1:raise ValueError('A workflow must use one HTTPS origin')
    expires=data.get('expires',min(t['expires'] for t in targets.values()))
    if type(expires) is not int or not now<expires<=min(now+7*86400,*(t['expires'] for t in targets.values())):
        raise ValueError('Workflow permission cannot outlive the reviewed targets or seven days')
    record=c.execute("SELECT status,evidence,checked FROM program_research WHERE rtrim(policy,'/')=?",(policy.rstrip('/'),)).fetchone()
    if record:
        evidence=json.loads(record['evidence'])
        if (record['status']!='collected' or now-record['checked']>=86400 or not evidence.get('documents_complete')
                or evidence.get('automation_permission')=='restricted' or evidence.get('program_status','').lower()!='open'):
            raise ValueError('Refresh and review the program rules before configuring deeper tests')
    key=data.get('id') or secrets.token_hex(12);file=path(root,key)
    if data.get('id') and not c.execute('SELECT 1 FROM hunt_profiles WHERE id=?',(key,)).fetchone():raise ValueError('Workflow not found')
    if not data.get('id') and c.execute('SELECT COUNT(*) FROM hunt_profiles').fetchone()[0]>=20:raise ValueError('Twenty workflow limit reached')
    revision=secrets.token_hex(16);stamp=policy_stamp(c,policy,targets)
    config={'id':key,'revision':revision,'accounts':clean_accounts,'resources':clean_resources,
            'interval':interval,'request_budget':budget,'request_gap':gap,'rules':rules.strip(),
            'map_urls':map_urls,'browser_account':browser_account,'browser':data.get('browser',True) is True}
    metadata={'targets':sorted(targets),'accounts':[{'id':a['id'],'role':a['role']} for a in clean_accounts],
              'resources':[{k:r[k] for k in ('id','target','owner','allow','feature')} for r in clean_resources],
              'map_targets':map_ids,'request_budget':budget,'request_gap':gap,'browser':config['browser']}
    fd,temp=tempfile.mkstemp(prefix='.workflow-',dir=root)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600);json.dump(config,f);f.flush();os.fsync(f.fileno())
        os.replace(temp,file)
    finally:
        if os.path.exists(temp):os.unlink(temp)
    c.execute('''INSERT INTO hunt_profiles(id,name,policy,revision,stamp,metadata,enabled,expires,due,interval)
      VALUES(?,?,?,?,?,?,1,?,0,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,policy=excluded.policy,
      revision=excluded.revision,stamp=excluded.stamp,metadata=excluded.metadata,enabled=1,expires=excluded.expires,
      due=MAX(hunt_profiles.due,hunt_profiles.last_started+excluded.interval),interval=excluded.interval,
      cursor=0,stable=0,failures=0,state='queued',reason='',last_fingerprint='' ''',
      (key,name.strip(),policy,revision,stamp,json.dumps(metadata),expires,interval))
    return key


def blocker(c,row,now=None):
    now=int(time.time()) if now is None else now
    if not row['enabled']:return row['reason'] or 'Workflow disabled'
    if row['expires']<=now:return 'Workflow permission expired'
    meta=json.loads(row['metadata'])
    if policy_stamp(c,row['policy'],meta['targets'])!=row['stamp']:return 'Scope, permission or program rules changed'
    for key in meta['targets']:
        t=c.execute('SELECT * FROM targets WHERE id=?',(key,)).fetchone()
        if not t or not t['enabled'] or t['expires']<=now:return 'Saved target unavailable'
        stop=programqueue.target_gate(c,t,now)
        if stop:return stop
    policy=c.execute("SELECT * FROM program_research WHERE rtrim(policy,'/')=?",(row['policy'].rstrip('/'),)).fetchone()
    if policy:
        evidence=json.loads(policy['evidence'])
        if (not policy['checked'] or now-policy['checked']>=86400 or policy['status']!='collected'
                or evidence.get('automation_permission')=='restricted' or not policy['active']):
            return 'Current complete program review required'
    return ''


def allowed(db,key,revision,stamp):
    with db() as c:
        row=c.execute('SELECT * FROM hunt_profiles WHERE id=?',(key,)).fetchone()
        return bool(row and row['revision']==revision and row['stamp']==stamp
                    and not c.execute('SELECT paused FROM settings').fetchone()[0] and not blocker(c,row))


def learning(c):
    groups={}
    for row in c.execute('SELECT feature,disposition,COUNT(*) n FROM hunt_cases GROUP BY feature,disposition'):
        groups.setdefault(row['feature'],{})[row['disposition']]=row['n']
    observed={}
    for run in c.execute("SELECT result FROM hunt_runs WHERE kind='matrix' AND state IN ('complete','reproduced','stopped') ORDER BY id DESC LIMIT 200"):
        for test in json.loads(run['result']).get('tests',[]):
            counts=observed.setdefault(test['feature'],Counter());counts[test['state']]+=1
    rows=[]
    for feature in sorted(set(groups)|set(observed)):
        counts=groups.get(feature,{});runs=observed.get(feature,{})
        score=(counts.get('validated',0)+counts.get('accepted',0)+1)/(sum(counts.get(k,0) for k in DISPOSITIONS if k!='unreviewed')+2)
        # Repeated inconclusive controls lower selection priority, not scope or confidence.
        score*=1-0.2*runs.get('inconclusive',0)/max(1,sum(runs.values()))
        rows.append({'feature':feature,'outcomes':counts,'observations':dict(runs),'priority':round(score,3)})
    return rows


def save_cases(c,profile,result,now):
    for test in result.get('tests',[]):
        if not boundarysuite.verify_test(result,test):continue
        key=digest([profile['id'],profile['revision'],test['resource'],test['actor'],test['checkpoint']])[:24]
        proof={'test':test,'receipts':result['receipts'][test['receipt_start']:test['receipt_start']+test['receipt_count']]}
        proof['test']={**test,'receipt_start':0}
        c.execute('''INSERT INTO hunt_cases(id,profile,revision,stamp,feature,checkpoint,resource,actor,first_seen,last_seen,evidence)
          VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,evidence=excluded.evidence''',
          (key,profile['id'],profile['revision'],profile['stamp'],test['feature'],test['checkpoint'],
           test['resource'],test['actor'],now,now,json.dumps(proof)))


def tick(db,root,log,transport=accesscheck.fetch,mapper=workflowmap.map_pages,pace=time.sleep):
    if not RUN_LOCK.acquire(blocking=False):return
    try:_tick(db,root,log,transport,mapper,pace)
    finally:RUN_LOCK.release()


def _tick(db,root,log,transport,mapper,pace):
    now=int(time.time());job=None
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        c.execute('UPDATE hunt_health SET heartbeat=? WHERE id=1',(now,))
        health=c.execute('SELECT * FROM hunt_health').fetchone()
        if now-health['focus_checked']>=60:
            c.execute('UPDATE hunt_health SET focus=?,focus_checked=? WHERE id=1',(json.dumps(focus(c)),now))
        if health['version']!=VERSION:
            bench=boundarysuite.benchmark()
            c.execute('UPDATE hunt_health SET benchmark=?,version=? WHERE id=1',(json.dumps(bench),VERSION))
        else:bench=json.loads(health['benchmark'])
        for old in c.execute("SELECT * FROM hunt_runs WHERE state='running' AND lease_until<=?",(now,)).fetchall():
            c.execute("UPDATE hunt_runs SET state='interrupted',finished=? WHERE id=?",(now,old['id']))
            c.execute("UPDATE hunt_profiles SET state='interrupted',due=MAX(due,?),reason='Previous run interrupted' WHERE id=?",(now+900,old['profile']))
        if (c.execute('SELECT paused FROM settings').fetchone()[0] or bench.get('passed')!=bench.get('total')
                or c.execute("SELECT 1 FROM hunt_runs WHERE state='running'").fetchone()):return
        scores={r['feature']:r['priority'] for r in learning(c)}
        candidates=[dict(r) for r in c.execute('SELECT * FROM hunt_profiles WHERE due<=? ORDER BY last_started,id',(now,)) if not blocker(c,r,now)]
        for row in candidates:
            program=digest(row['policy'].rstrip('/'))
            gap=c.execute('SELECT next_allowed FROM autonomous_programs WHERE program=?',(program,)).fetchone()
            if gap and gap[0]>now:continue
            if c.execute("SELECT 1 FROM autonomous_runs WHERE outcome='running'").fetchone():continue
            config=load(root,row['id'])
            if not config or config.get('revision')!=row['revision']:
                c.execute("UPDATE hunt_profiles SET enabled=0,state='blocked',reason='Account configuration missing or changed' WHERE id=?",(row['id'],));continue
            mapped=c.execute('SELECT * FROM hunt_maps WHERE profile=?',(row['id'],)).fetchone()
            kind='map' if config['map_urls'] and (not mapped or mapped['revision']!=row['revision'] or now-mapped['checked']>=86400) else 'matrix'
            run=c.execute("INSERT INTO hunt_runs(profile,revision,stamp,kind,started,finished,lease_until,state,result) VALUES(?,?,?,?,?,0,?,'running','{}')",
                          (row['id'],row['revision'],row['stamp'],kind,now,now+900)).lastrowid
            c.execute("UPDATE hunt_profiles SET last_started=?,due=?,state='running',reason='' WHERE id=?",(now,now+row['interval'],row['id']))
            c.execute('INSERT INTO autonomous_programs VALUES(?,?) ON CONFLICT(program) DO UPDATE SET next_allowed=MAX(next_allowed,excluded.next_allowed)',(program,now+900))
            # Freeze comparison order until every batch in this cycle has run.
            # Feedback arriving mid-cycle must not starve later comparisons.
            ordered=scores if row['cursor']==0 else json.loads(row['order_scores'])
            if row['cursor']==0:c.execute('UPDATE hunt_profiles SET order_scores=? WHERE id=?',(json.dumps(ordered),row['id']))
            config['priorities']=ordered;job=(row,config,kind,run,program);break
    if not job:return
    profile,config,kind,run,program=job
    permit=lambda:allowed(db,profile['id'],profile['revision'],profile['stamp'])
    try:
        result=(mapper(config,permit,pace=pace) if kind=='map' else
                boundarysuite.run(config,transport,permit,pace,profile['cursor']))
    except Exception:result={'state':'stopped','stopped':True,'stop_reason':'Workflow runner failed','tests':[],'requests':0}
    valid=permit();now=int(time.time())
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        current=c.execute('SELECT * FROM hunt_profiles WHERE id=?',(profile['id'],)).fetchone()
        valid=bool(valid and current and current['revision']==profile['revision'] and not blocker(c,current,now)
                   and not c.execute('SELECT paused FROM settings').fetchone()[0])
        state='invalidated' if not valid else ('reproduced' if result.get('reproduced') else
            'stopped' if result.get('stopped') or result.get('state') in ('stopped','unavailable','partial') else 'complete')
        # Invalidated data is never ingested as a case or current coverage.
        c.execute('UPDATE hunt_runs SET state=?,finished=?,result=? WHERE id=?',(state,now,json.dumps(result),run))
        if current and current['revision']==profile['revision']:
            reason=result.get('stop_reason',result.get('reason','')) if valid else 'Permission changed during the run'
            stable=profile['stable']+1 if state=='complete' and result.get('fingerprint')==profile['last_fingerprint'] else 0
            # Backoff only extends the approved interval, never accelerates it.
            delay=min(86400,profile['interval']*2**min(stable,3)) if kind=='matrix' else profile['interval']
            c.execute('''UPDATE hunt_profiles SET last_finished=?,due=MAX(due,?),state=?,reason=?,stable=?,
              last_fingerprint=?,cursor=?,enabled=CASE WHEN ? THEN 0 ELSE enabled END WHERE id=?''',
              (now,now+delay,state,reason,stable,result.get('fingerprint',''),result.get('next_cursor',profile['cursor']),
               int(state in ('stopped','reproduced')),profile['id']))
            if valid and kind=='map':
                c.execute('INSERT OR REPLACE INTO hunt_maps VALUES(?,?,?,?,?)',
                          (profile['id'],profile['revision'],profile['stamp'],now,json.dumps(result)))
            if valid and kind=='matrix':save_cases(c,profile,result,now)
        c.execute('UPDATE autonomous_programs SET next_allowed=? WHERE program=?',(now+60,program))
        c.execute('UPDATE hunt_health SET heartbeat=? WHERE id=1',(now,))
        c.execute('DELETE FROM hunt_runs WHERE id NOT IN (SELECT id FROM hunt_runs ORDER BY id DESC LIMIT 200)')
        log(c,'Focused workflow '+kind+': '+state+'. '+str(result.get('requests',0))+' bounded requests. Evidence saved.')


def review(c,data):
    row=c.execute('SELECT * FROM hunt_cases WHERE id=?',(data.get('id'),)).fetchone()
    if not row:raise ValueError('Investigation not found')
    disposition=data.get('disposition','')
    if disposition not in DISPOSITIONS:raise ValueError('Choose a review outcome')
    impact=data.get('impact','')
    if not isinstance(impact,str) or len(impact)>3000:raise ValueError('Impact note must be under 3,000 characters')
    checks={k:data.get(k) is True for k in ('identities_verified','expected_access_verified','scope_verified','duplicates_checked')}
    if disposition in ('validated','accepted') and (not all(checks.values()) or len(impact.strip())<40):
        raise ValueError('Verify identities, intended access, current scope, known duplicates and actual impact before validation')
    c.execute('UPDATE hunt_cases SET disposition=?,impact=?,reviewed=?,review_checks=? WHERE id=?',
              (disposition,impact.strip(),int(time.time()),json.dumps(checks),row['id']))


def case_view(c,row):
    profile=c.execute('SELECT * FROM hunt_profiles WHERE id=?',(row['profile'],)).fetchone()
    proof=json.loads(row['evidence']);now=int(time.time())
    reviewable=dict(profile) if profile else {}
    if reviewable.get('state')=='reproduced':reviewable['enabled']=1
    current=bool(profile and not blocker(c,reviewable,now) and profile['revision']==row['revision'] and profile['stamp']==row['stamp']
                 and policy_stamp(c,profile['policy'],json.loads(profile['metadata'])['targets'])==row['stamp']
                 and profile['expires']>now and now-row['last_seen']<86400)
    verified=boundarysuite.verify_test(proof,proof['test'])
    checks=json.loads(row['review_checks'])
    ready=bool(current and verified and row['disposition']=='validated' and all(checks.get(k) is True for k in
               ('identities_verified','expected_access_verified','scope_verified','duplicates_checked'))
               and len(row['impact'])>=40)
    return {k:row[k] for k in ('id','profile','feature','checkpoint','resource','actor','first_seen','last_seen','disposition','impact')}|{
        'current':current,'evidence_verified':verified,'report_ready':ready,'evidence':proof,
        'label':'Reproduced access difference' if verified else 'Evidence incomplete',
        'limitation':'Private synthetic marker evidence. Real impact and bounty eligibility require review.'}


def report(c,key):
    row=c.execute('SELECT * FROM hunt_cases WHERE id=?',(key,)).fetchone()
    if not row:raise ValueError('Investigation not found')
    item=case_view(c,row);profile=c.execute('SELECT * FROM hunt_profiles WHERE id=?',(row['profile'],)).fetchone()
    return '\n'.join(['# '+('Reviewed report draft' if item['report_ready'] else 'Investigation draft — review required'),'',
        'Workflow: '+profile['name'],'Program policy: '+profile['policy'],'Resource label: '+row['resource'],
        'Checkpoint: '+row['checkpoint'],'Evidence time (UTC): '+time.strftime('%Y-%m-%d %H:%M:%S',time.gmtime(row['last_seen'])),
        '', '## Reproduction',
        '1. Use the exact saved GET resource and the separately owned accounts in this workflow.',
        '2. Confirm that the owner can read its private synthetic marker.',
        'For an authenticated comparison, also verify that the second account can read its own separate control record before and after the comparison.',
        '3. Read the same resource twice as test actor '+row['actor']+'.',
        '4. Confirm that both responses contain the private marker and repeat the owner control.',
        '5. Verify the documented access rule and that the accounts do not intentionally share this resource.',
        '', '## Impact',row['impact'] or 'Actual application impact has not been reviewed.',
        '', '## Sanitized evidence',json.dumps(item['evidence'],indent=2),
        '', '## Remediation','Enforce the documented resource and role permissions on every server-side read.',
        '', 'Current evidence: '+str(item['current']), 'Ready for report review: '+str(item['report_ready']),
        'No report was submitted. Credentials, response bodies and private record contents are omitted.'])


def focus(c):
    now=int(time.time());jobs=autopilot.jobs(c,now);packs=[]
    for r in c.execute('''SELECT p.id,p.name,p.url,p.maximum,p.currency,p.available,p.stage,
      r.evidence,r.checked,r.status,r.digest FROM programs p LEFT JOIN program_research r ON r.id=p.id'''):
        evidence=json.loads(r['evidence'] or '{}');fresh=bool(r['checked'] and 0<=now-r['checked']<86400)
        brief=researchbrief.build(evidence,fresh=fresh,status=r['status'] or '',assets=True)
        related=[j for j in jobs if j['program']==digest(r['url'].rstrip('/')) and not j['blocker']]
        profiles=[dict(p) for p in c.execute("SELECT * FROM hunt_profiles WHERE rtrim(policy,'/')=?",(r['url'].rstrip('/'),))]
        ready=[p for p in profiles if not blocker(c,p,now)]
        opportunities=[a for a in brief.get('candidates',[]) if a.get('bounty_eligible') is True and a.get('kind')=='web']
        blockers=[]
        if not r['available'] or r['stage']=='dismissed':continue
        if not brief['prepared']:blockers.append(brief['next_step'])
        if evidence.get('automation_permission')=='restricted':blockers.append('Automated testing is restricted')
        if not ready:blockers.append('A permitted account-and-resource workflow is not configured')
        if not opportunities:blockers.append('No exact supported bounty-eligible asset is confirmed in this saved brief')
        score=1000*bool(ready)+500*bool(related)+100*brief['prepared']+10*min(5,len(opportunities))
        if evidence.get('automation_permission')=='restricted':score-=500
        packs.append({'id':r['id'],'name':r['name'],'policy':r['url'],'ready_workflows':len(ready),
                      'existing_jobs':len(related),'status':'Ready for configured tests' if ready else 'Preparing',
                      'blockers':blockers,'candidates':opportunities[:3],'score':score,
                      'suggested_features':list(boundarysuite.CHECKPOINTS),
                      'policy_checked':r['checked'] or 0,'maximum':r['maximum'],'currency':r['currency']})
    return sorted(packs,key=lambda p:(-p['score'],p['name'].casefold()))[:5]


def snapshot(c):
    now=int(time.time());health=dict(c.execute('SELECT * FROM hunt_health').fetchone())
    profiles=[]
    for r in c.execute('SELECT * FROM hunt_profiles ORDER BY name,id'):
        profiles.append({k:r[k] for k in ('id','name','policy','enabled','expires','due','state','reason','last_started','last_finished','interval')}|
                        {'blocker':blocker(c,r,now),'configuration':json.loads(r['metadata'])})
    cases=[case_view(c,r) for r in c.execute('SELECT * FROM hunt_cases ORDER BY last_seen DESC LIMIT 100')]
    maps=[]
    for r in c.execute('SELECT * FROM hunt_maps'):
        p=c.execute('SELECT * FROM hunt_profiles WHERE id=?',(r['profile'],)).fetchone()
        maps.append({'profile':r['profile'],'checked':r['checked'],'current':bool(p and p['revision']==r['revision'] and not blocker(c,p,now)),
                     **json.loads(r['result'])})
    active=[p for p in profiles if not p['blocker']]
    paused=bool(c.execute('SELECT paused FROM settings').fetchone()[0])
    running=c.execute("SELECT lease_until FROM hunt_runs WHERE state='running'").fetchone()
    return {'version':VERSION,'healthy':bool(0<now-health['heartbeat']<90 or health['heartbeat']==now or running and running[0]>now),
        'paused':paused,'heartbeat':health['heartbeat'],'focus':json.loads(health['focus']),
        'focus_checked':health['focus_checked'],'profiles':profiles,'maps':maps,'cases':cases,
        'browser_available':workflowmap.available(),'browser_runtime':browserruntime.status(),
        'benchmark':json.loads(health['benchmark']), 'learning':learning(c),
        'metrics':{'programs_testing':0 if paused else len({p['policy'] for p in active}),
                   'features_configured':sum(len(p['configuration']['resources']) for p in active),
                   'features_mapped':sum(len(m['pages']) for m in maps if m['current']),
                   'suspected':sum(i['current'] and i['disposition']=='unreviewed' for i in cases),
                   'reproduced':sum(i['current'] and i['evidence_verified'] and i['disposition'] not in ('false_positive','out_of_scope') for i in cases),
                   'reports_ready':sum(i['report_ready'] for i in cases)},
        'recent_runs':[dict(r) for r in c.execute('SELECT id,profile,kind,started,finished,state FROM hunt_runs ORDER BY id DESC LIMIT 20')],
        'limitation':'Only configured exact GET workflows run. Browser discoveries do not expand scope. Accounts and program eligibility are never invented. Lab results are separate from external findings.'}


def receipt(c):
    s=snapshot(c)
    return {'kind':'scopeguard_focused_research_health','version':VERSION,'healthy':s['healthy'],'paused':s['paused'],
            'profiles':len(s['profiles']),'browser_available':s['browser_available'],'metrics':s['metrics'],
            'benchmark_passed':s['benchmark'].get('passed',0),'benchmark_total':s['benchmark'].get('total',0)}


def checkpoint_support(c,context):
    """Map only exact configured features with fresh, completed evidence."""
    now=int(time.time());support={}
    if context=='owned':return support
    if context.startswith('program:'):
        p=c.execute('SELECT url FROM programs WHERE id=?',(context[8:],)).fetchone()
        if not p:return support
        policy=p['url'].rstrip('/');target_id=None
    elif context.startswith('target:'):
        target_id=int(context[7:]);p=c.execute('SELECT policy FROM targets WHERE id=?',(target_id,)).fetchone()
        if not p:return support
        policy=p['policy'].rstrip('/')
    else:return support
    for row in c.execute("SELECT * FROM hunt_profiles WHERE rtrim(policy,'/')=?",(policy,)):
        profile=dict(row)
        if profile['state']=='reproduced':profile['enabled']=1
        if blocker(c,profile,now):continue
        resources={r['id']:r for r in json.loads(row['metadata'])['resources']}
        # Only the latest matrix batch is current. Older passes cannot conceal a newer failure.
        run=c.execute("SELECT * FROM hunt_runs WHERE profile=? AND revision=? AND kind='matrix' ORDER BY id DESC LIMIT 1",
                      (row['id'],row['revision'])).fetchone()
        if not run or run['stamp']!=row['stamp'] or run['state'] not in ('complete','reproduced') or not 0<=now-run['finished']<86400:continue
        result=json.loads(run['result'])
        for test in result.get('tests',[]):
            resource=resources.get(test['resource'])
            if not resource or target_id and resource['target']!=target_id:continue
            state='runtime_failed' if boundarysuite.verify_test(result,test) else 'runtime_passed' if test['state']=='boundary_held' else 'inconclusive'
            key=test['checkpoint']
            if support.get(key,{}).get('state')=='runtime_failed':continue
            support[key]={'state':state,'note':'Bounded GET comparison for the configured '+test['feature'].replace('_',' ')+
                ' resource, two comparisons and owner controls. Other actions remain untested.',
                'checked':run['finished'],'executed':True,'tested':state!='inconclusive','control_validated':state!='inconclusive',
                'adapter':'workflow','job':'workflow:'+row['id']}
    return support
