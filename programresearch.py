"""Durable program-rule collection. Never probes assets or grants scan permission."""
import hashlib
import json
import re
import time

import programapi

INTERVAL = 15
REFRESH = 86400
MAX_SCOPES = 2000
MAX_EVIDENCE = 512000
MAX_STORED = 64 * 1024 * 1024
LABELS = {'queued':'Waiting for program rules','collecting':'Reading official rules and scope',
          'collected':'Official documents collected; testing permission unverified',
          'connection_needed':'Platform connection needed','access_blocked':'Platform refused access',
          'unavailable':'Program is unavailable or dismissed','directory_stale':'Waiting for a current directory',
          'unsupported':'Program address needs review','incomplete':'Official evidence is incomplete',
          'retry':'Temporary failure; retry scheduled','changed':'Rules changed; fresh review needed'}
ERRORS = {
    'schema':'The platform returned a document format ScopeGuard cannot read.',
    'response_format':'The platform response was not a JSON document.',
    'program_shape':'The program response did not contain the expected program fields.',
    'program_type':'The platform returned an unexpected program record type.',
    'program_identity':'The returned program did not match the requested program.',
    'program_envelope':'The API response did not contain a program object.',
    'program_attributes':'The API response did not contain program attributes.',
    'program_policy_format':'The policy body was not published as text in this response.',
    'program_state_format':'The API used an unsupported program status format.',
    'resource_metadata':'The API used an unsupported record label format.',
    'catalog_format':'The program catalog did not contain the documented list of programs.',
    'not_in_catalog':'This program was not present in the catalog available to the connected account.',
    'size':'The official document exceeded the configured storage limit.',
    'transport':'The connection failed. A retry is scheduled.',
    'dns':'The official API address did not pass the public address check.',
    'documents_missing':'Required policy text or attached rules are missing from the saved collection.',
    'unknown':'The official request could not be completed.'}


def error_code(value):
    if type(value)is int and 100<=value<=599:return 'http_'+str(value)
    return value if isinstance(value,str) and value in ERRORS else 'unknown'


def error_label(code):
    if re.fullmatch(r'http_[1-5][0-9]{2}',code or ''):
        status=int(code[5:])
        if status==401:return 'The platform rejected this API connection. Replace its connection to resume.'
        if status in (403,404):return 'The platform did not grant access to this program. No further requests are scheduled.'
        if status==429:return 'The platform rate limit was reached. ScopeGuard will wait before retrying.'
        return 'The official API returned HTTP '+str(status)+'. The request did not complete.'
    return ERRORS.get(code,'')


def init(c):
    c.executescript('''
      CREATE TABLE IF NOT EXISTS program_research (
        id TEXT PRIMARY KEY,provider TEXT,policy TEXT,status TEXT DEFAULT 'queued',
        phase TEXT DEFAULT 'policy',page INTEGER DEFAULT 1,due INTEGER DEFAULT 0,
        last_attempt INTEGER DEFAULT 0,checked INTEGER DEFAULT 0,requests INTEGER DEFAULT 0,
        failures INTEGER DEFAULT 0,partial TEXT DEFAULT '{}',evidence TEXT DEFAULT '{}',
        digest TEXT DEFAULT '',changes INTEGER DEFAULT 0,active INTEGER DEFAULT 1);
      CREATE TABLE IF NOT EXISTS program_research_providers (
        provider TEXT PRIMARY KEY,fingerprint TEXT DEFAULT '',blocked INTEGER DEFAULT 0,
        next_request INTEGER DEFAULT 0,last_request INTEGER DEFAULT 0,last_success INTEGER DEFAULT 0,
        status TEXT DEFAULT 'connection_needed',index_checked INTEGER DEFAULT 0,
        offset INTEGER DEFAULT 0,index_complete INTEGER DEFAULT 0,program_index TEXT DEFAULT '{}');
      CREATE TABLE IF NOT EXISTS program_research_health (id INTEGER PRIMARY KEY,heartbeat INTEGER,next_request INTEGER,parser_version INTEGER DEFAULT 4);
      INSERT OR IGNORE INTO program_research_health(id,heartbeat,next_request) VALUES(1,0,0);
    ''')
    # Existing databases keep their progress; only fixed error codes are added.
    for table in ('program_research','program_research_providers'):
        columns={r[1] for r in c.execute('PRAGMA table_info('+table+')')}
        for name in ('last_error','error_phase'):
            if name not in columns:c.execute('ALTER TABLE '+table+' ADD COLUMN '+name+" TEXT DEFAULT ''")
    if 'catalog_mode' not in {r[1] for r in c.execute('PRAGMA table_info(program_research_providers)')}:
        c.execute('ALTER TABLE program_research_providers ADD COLUMN catalog_mode INTEGER DEFAULT 0')
    if 'parser_version' not in {r[1] for r in c.execute('PRAGMA table_info(program_research_health)')}:
        c.execute('ALTER TABLE program_research_health ADD COLUMN parser_version INTEGER DEFAULT 1')
    if c.execute('SELECT parser_version FROM program_research_health WHERE id=1').fetchone()[0]<3:
        # Retry parser failures once after this correction, retaining provider
        # access blocks, rate-limit timers and the global request budget.
        c.execute("UPDATE program_research SET status='queued',due=0,phase='policy',page=1,partial='{}' WHERE status='incomplete' AND checked=0 AND last_error IN ('','program_type','schema')")
        c.execute('UPDATE program_research_health SET parser_version=3 WHERE id=1')
    if c.execute('SELECT parser_version FROM program_research_health WHERE id=1').fetchone()[0]<4:
        if 'program_index' in {r[1] for r in c.execute('PRAGMA table_info(program_research_providers)')}:
            repair_catalog_sources(c)
        c.execute('UPDATE program_research_health SET parser_version=4 WHERE id=1')
    for p in programapi.HOSTS:c.execute('INSERT OR IGNORE INTO program_research_providers(provider) VALUES(?)',(p,))


def evidence_digest(evidence):
    return hashlib.sha256(json.dumps({k:v for k,v in evidence.items() if k!='policy_checked_at'},sort_keys=True).encode()).hexdigest()


def repair_catalog_sources(c):
    provider=c.execute("SELECT catalog_mode,program_index,offset FROM program_research_providers WHERE provider='hackerone'").fetchone()
    if not provider or not provider[0]:return
    seen=json.loads(provider[1]);unknown=False
    for row in c.execute("SELECT id,policy,partial,evidence FROM program_research WHERE provider='hackerone'").fetchall():
        key=programapi.canonical(row[1])
        if seen.get(key) is not True:continue
        # Offset 2 proves only catalog page 1 was processed by the old reader.
        source='https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=100&page%5Bnumber%5D=1' if provider[2]==2 else ''
        values=[]
        for raw in (row[2],row[3]):
            e=json.loads(raw)
            wrong='https://api.hackerone.com/v1/hackers/programs/'+key.split(':',1)[1]
            if e and wrong in e.get('sources',[]):
                e['sources']=[source if s==wrong else s for s in e['sources'] if s!=wrong or source]
                if not source:
                    unknown=True;e['documents_complete']=False;e['source_incomplete']=True
                    e.setdefault('unresolved',[]).append('The catalog page URL was not retained in this older record; fresh collection is required.')
            values.append(e)
        c.execute('UPDATE program_research SET partial=?,evidence=?,digest=? WHERE id=?',
                  (json.dumps(values[0]),json.dumps(values[1]),evidence_digest(values[1]) if values[1] else '',row[0]))
        if source:seen[key]=source
    c.execute("UPDATE program_research_providers SET program_index=? WHERE provider='hackerone'",(json.dumps(seen),))
    if unknown:
        c.execute("UPDATE program_research_providers SET index_complete=0,index_checked=0,offset=0 WHERE provider='hackerone'")
        c.execute("UPDATE program_research SET phase='policy',page=1,due=0,status='queued' WHERE provider='hackerone' AND active=1 AND status NOT IN ('access_blocked','retry')")


def safe_text(value,limit=20000):
    if not isinstance(value,str):raise programapi.APIError('schema')
    if len(value)>limit:raise programapi.APIError('size')
    return value


def resource_type(value):
    # Type names are descriptive API metadata, not program authorization. The
    # observed API uses labels different from its examples. Validate the actual
    # identity and required attributes instead, preserving the source label.
    if value is None:return 'unspecified'
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,79}',value):raise programapi.APIError('resource_metadata')
    return value


def rules_clues(text):
    # Candidate passages help investigation only. No regex can grant permission.
    categories={'automation':r'automat|scanner|robot|bot\b', 'limits':r'per second|per minute|requests?/s|rate.?limit',
                'accounts':r'account|login|log in|sign.in|identity|verification|test.user',
                'exclusions':r'out.of.scope|exclud|prohibit|not.allowed|must.not'}
    lines=[s.strip() for s in re.split(r'[\r\n]+',text) if s.strip()]
    return {k:[s[:700] for s in lines if re.search(pattern,s,re.I)][:12] for k,pattern in categories.items()}


def empty_evidence(policy):
    return {'policy_url':policy,'sources':[],'policy_text':'','scope':[],'exclusions':[],
            'scope_complete':False,'documents_complete':False,'grants_permission':False,
            'testing_activated':False,'automatic_submission':False,'automation_permission':'unverified',
            'program_status':'unknown','requirements':{},'unresolved':[]}


def h1_policy(doc,policy):
    data=doc.get('data')
    if not isinstance(data,dict):raise programapi.APIError('program_envelope')
    attrs=data.get('attributes')
    if not isinstance(attrs,dict):raise programapi.APIError('program_attributes')
    handle=programapi.canonical(policy).removeprefix('hackerone:')
    kind=resource_type(data.get('type'))
    if str(attrs.get('handle','')).lower()!=handle:raise programapi.APIError('program_identity')
    if 'policy' not in attrs or not isinstance(attrs.get('submission_state'),str):raise programapi.APIError('program_shape')
    if attrs['policy'] is not None and not isinstance(attrs['policy'],str):raise programapi.APIError('program_policy_format')
    if attrs.get('state') is not None and not isinstance(attrs['state'],str):raise programapi.APIError('program_state_format')
    out=empty_evidence(policy);out['policy_text']=safe_text(attrs.get('policy') or '',120000)
    out['platform_record_type']=kind
    out['program_status']=safe_text(attrs.get('submission_state') or 'unknown',80)
    out['visibility']=safe_text(attrs.get('state') or 'unknown',80)
    out['offers_bounties']=attrs.get('offers_bounties') is True
    out['sources']=['https://api.hackerone.com/v1/hackers/programs/'+handle]
    return out


def h1_scope(doc,handle,page):
    data=doc.get('data')
    if not isinstance(data,list) or len(data)>100:raise programapi.APIError('schema')
    out=[]
    for row in data:
        if not isinstance(row,dict) or not isinstance(row.get('attributes'),dict):raise programapi.APIError('schema')
        kind=resource_type(row.get('type'))
        a=row['attributes']
        out.append({'asset':safe_text(a.get('asset_identifier'),2000),'type':safe_text(a.get('asset_type'),80),'platform_record_type':kind,
                    'eligible_for_submission':a.get('eligible_for_submission') if type(a.get('eligible_for_submission')) is bool else None,
                    'eligible_for_bounty':a.get('eligible_for_bounty') if type(a.get('eligible_for_bounty')) is bool else None,
                    'instructions':safe_text(a.get('instruction') or ''), 'updated':safe_text(a.get('updated_at') or '',80)})
    links=doc.get('links',{})
    if not isinstance(links,dict):raise programapi.APIError('schema')
    next_link=links.get('next')
    if next_link:
        from urllib.parse import parse_qs,urlsplit
        p=urlsplit(next_link)
        expected=programapi.PREFIXES['hackerone']+'/'+handle+'/structured_scopes'
        if p.scheme!='https' or p.netloc!='api.hackerone.com' or p.path!=expected or p.fragment or not programapi.valid_route('hackerone',p.path+'?'+p.query):raise programapi.APIError('schema')
        if parse_qs(p.query).get('page[number]')!=[str(page+1)]:raise programapi.APIError('schema')
    return out,bool(next_link)


def h1_exclusions(doc):
    rows=doc.get('data')
    if not isinstance(rows,list) or len(rows)>500 or doc.get('links',{}).get('next'):raise programapi.APIError('schema')
    result=[]
    for r in rows:
        if not isinstance(r,dict) or not isinstance(r.get('attributes'),dict):raise programapi.APIError('schema')
        kind=resource_type(r.get('type'))
        a=r['attributes'];result.append({'category':safe_text(a.get('category'),500),'details':safe_text(a.get('details') or ''),'platform_record_type':kind})
    return result


def h1_catalog(doc,page):
    rows=doc.get('data')
    if not isinstance(rows,list) or len(rows)>100:raise programapi.APIError('catalog_format')
    result={}
    for row in rows:
        if not isinstance(row,dict) or not isinstance(row.get('attributes'),dict):raise programapi.APIError('catalog_format')
        handle=row['attributes'].get('handle')
        if not isinstance(handle,str) or not re.fullmatch(programapi.HANDLE,handle):raise programapi.APIError('catalog_format')
        key='hackerone:'+handle.lower()
        if key in result:raise programapi.APIError('catalog_format')
        result[key]=row
    links=doc.get('links') or {}
    if not isinstance(links,dict):raise programapi.APIError('catalog_format')
    next_link=links.get('next')
    if next_link:
        from urllib.parse import parse_qs,urlsplit
        p=urlsplit(next_link)
        if p.scheme!='https' or p.netloc!='api.hackerone.com' or p.path!=programapi.PREFIXES['hackerone'] or p.fragment or not programapi.valid_route('hackerone',p.path+'?'+p.query):raise programapi.APIError('catalog_format')
        if parse_qs(p.query).get('page[number]')!=[str(page+1)] or page>=100:raise programapi.APIError('catalog_format')
    return result,bool(next_link)


def intigriti_index(doc,listed):
    rows=doc.get('records');total=doc.get('maxCount')
    if not isinstance(rows,list) or len(rows)>100 or type(total)is not int or not 0<=total<=10000:raise programapi.APIError('schema')
    result={}
    for r in rows:
        if not isinstance(r,dict):raise programapi.APIError('schema')
        key=programapi.canonical(r.get('webLinks',{}).get('detail'))
        if key in listed:
            identity=r.get('id','')
            if not re.fullmatch(programapi.GUID,identity):raise programapi.APIError('schema')
            result[key]=identity
    return result,total,len(rows)


def intigriti_policy(doc,policy):
    if programapi.canonical(doc.get('webLinks',{}).get('detail'))!=programapi.canonical(policy):raise programapi.APIError('schema')
    out=empty_evidence(policy)
    domains=doc.get('domains',{});rules=doc.get('rulesOfEngagement') or {};content=rules.get('content') or {}
    rows=domains.get('content')
    if not isinstance(rows,list) or len(rows)>MAX_SCOPES:raise programapi.APIError('schema')
    out['program_status']=safe_text(doc.get('status',{}).get('value','unknown'),80)
    out['policy_text']=safe_text(content.get('description') or '',120000)
    out['scope_version']=safe_text(domains.get('id') or '',80);out['rules_version']=safe_text(rules.get('id') or '',80)
    out['requirements']={k:v for k,v in (content.get('testingRequirements') or {}).items()
                         if k in ('intigritiMe','automatedTooling','userAgent','requestHeader') and type(v) in (str,int,bool,type(None))}
    if len(json.dumps(out['requirements']))>20000:raise programapi.APIError('schema')
    for r in rows:
        if not isinstance(r,dict):raise programapi.APIError('schema')
        out['scope'].append({'asset':safe_text(r.get('endpoint'),2000),
                             'type':safe_text(r.get('type',{}).get('value','unknown'),80),
                             'tier':safe_text(r.get('tier',{}).get('value','unknown'),80),
                             'instructions':safe_text(r.get('description') or ''),
                             'eligible_for_submission':None,'eligible_for_bounty':None})
    attachments=rules.get('attachments') or []
    if not isinstance(attachments,list):raise programapi.APIError('schema')
    out['scope_complete']=True
    out['documents_complete']=bool(out['policy_text']) and not attachments
    if attachments:out['unresolved'].append('Rules include attachments that were not downloaded or reviewed.')
    out['unresolved'].append('Intigriti scope tiers and automatedTooling values are preserved as published; their meaning and all applicable conditions require review.')
    return out


def finalize(evidence):
    evidence['rule_passages']=rules_clues(evidence['policy_text']+'\n'+'\n'.join(x['instructions'] for x in evidence['scope']))
    evidence['unresolved'].extend(['Program-specific automation permission and account eligibility are not approved by document collection.',
                                  'Exact permitted test methods, exclusions and any linked rules must be resolved before new testing.'])
    if programapi.canonical(evidence['policy_url'])=='hackerone:mozilla':
        evidence['automation_permission']='restricted'
        evidence['unresolved'].append('Mozilla production automation remains blocked.')
    kinds={x['type'].lower() for x in evidence['scope']}
    evidence['method_candidates']=[]
    if any('source' in k or 'code' in k for k in kinds):evidence['method_candidates'].append('Source review is supported for authorized Python repositories; no repository is enrolled automatically.')
    if any(k in ('url','domain','wildcard') for k in kinds):evidence['method_candidates'].append('Exact URL checks or owned-account comparisons require a permitted method and working test resources.')
    if not evidence['method_candidates']:evidence['method_candidates'].append('No compatible automatic test setup is established for these asset types.')
    return evidence


def reconcile(c,available,now):
    c.execute('UPDATE program_research_health SET heartbeat=? WHERE id=1',(now,))
    for p in c.execute('SELECT * FROM programs').fetchall():
        c.execute('INSERT OR IGNORE INTO program_research(id,provider,policy) VALUES(?,?,?)',(p['id'],p['source'],p['url']))
        source=c.execute('SELECT * FROM discovery_sources WHERE id=?',(p['source'],)).fetchone()
        status=('unavailable' if not p['available'] or p['stage']=='dismissed' else
                'directory_stale' if not source or source['failures'] or source['last_success']<now-REFRESH else
                'unsupported' if not programapi.canonical(p['url']) else
                'connection_needed' if not available.get(p['source']) else '')
        if status:c.execute('UPDATE program_research SET active=0,status=? WHERE id=?',(status,p['id']))
        else:c.execute("UPDATE program_research SET active=1,status=CASE WHEN active=0 THEN 'queued' ELSE status END WHERE id=?",(p['id'],))
    for provider,value in available.items():
        fp=programapi.fingerprint(value)
        old=c.execute('SELECT fingerprint FROM program_research_providers WHERE provider=?',(provider,)).fetchone()[0]
        if fp!=old:
            c.execute("UPDATE program_research_providers SET fingerprint=?,blocked=0,next_request=0,status=?,index_checked=0,offset=0,index_complete=0,program_index='{}',last_error='',error_phase='' WHERE provider=?",(fp,'queued' if value else 'connection_needed',provider))
            c.execute("UPDATE program_research SET due=0,phase='policy',page=1,partial='{}',last_error='',error_phase='',status=CASE WHEN active=1 THEN 'queued' ELSE status END WHERE provider=?",(provider,))
    # A successful HTTP response with no program object is a format failure,
    # not an access refusal. Try the other documented read-only API route.
    if c.execute("SELECT 1 FROM program_research WHERE provider='hackerone' AND last_error='program_envelope' LIMIT 1").fetchone():
        c.execute("UPDATE program_research_providers SET catalog_mode=1 WHERE provider='hackerone'")


def finish(c,job,evidence,now):
    evidence.setdefault('policy_checked_at',0)
    if evidence.get('source_incomplete'):evidence['documents_complete']=False
    evidence=finalize(evidence);raw=json.dumps(evidence,sort_keys=True)
    bounded_storage(c,job['id'],raw)
    digest=evidence_digest(evidence);changed=bool(job['digest'] and job['digest']!=digest)
    status='changed' if changed else 'collected' if evidence['documents_complete'] else 'incomplete'
    c.execute("UPDATE program_research SET evidence=?,digest=?,changes=changes+?,checked=?,status=?,due=?,phase='policy',page=1,partial='{}',failures=0 WHERE id=?",
              (raw,digest,int(changed),now,status,now+REFRESH,job['id']))
    if not evidence['documents_complete']:c.execute("UPDATE program_research SET last_error='documents_missing',error_phase='documents' WHERE id=?",(job['id'],))


def bounded_storage(c,identity,raw,partial=False):
    size=len(raw.encode())
    used=c.execute('SELECT COALESCE(SUM(length(evidence)+length(partial)),0) FROM program_research WHERE id!=?',(identity,)).fetchone()[0]
    if partial:used+=c.execute('SELECT length(evidence) FROM program_research WHERE id=?',(identity,)).fetchone()[0]
    if size>MAX_EVIDENCE or used+size>MAX_STORED:raise programapi.APIError('size')


def tick(db,data_dir,lock,now=None):
    now=int(time.time()) if now is None else now
    with lock:
        available={p:programapi.credentials(data_dir,p) for p in programapi.HOSTS}
        with db() as c:
            reconcile(c,available,now)
            if c.execute('SELECT paused FROM settings').fetchone()[0] or not c.execute('SELECT enabled FROM discovery_settings').fetchone()[0]:return
            if c.execute('SELECT next_request FROM program_research_health').fetchone()[0]>now:return
            providers=[dict(r) for r in c.execute('SELECT * FROM program_research_providers WHERE blocked=0 AND next_request<=? ORDER BY last_request,provider',(now,)) if available.get(r['provider'])]
            chosen=None
            for provider in providers:
                p=provider['provider']
                index_needed=(p=='intigriti' or provider['catalog_mode']) and (not provider['index_complete'] or provider['index_checked']<now-REFRESH)
                job=c.execute("SELECT * FROM program_research WHERE provider=? AND active=1 AND due<=? AND status NOT IN ('access_blocked','unsupported') ORDER BY CASE phase WHEN 'exclusions' THEN 0 WHEN 'scopes' THEN 1 ELSE 2 END,last_attempt,id LIMIT 1",(p,now)).fetchone()
                index_job=index_needed and (p=='intigriti' or not job or job['phase']=='policy')
                if not job and index_job:job=c.execute('SELECT * FROM program_research WHERE provider=? AND active=1 ORDER BY last_attempt,id LIMIT 1',(p,)).fetchone()
                if not job:continue
                job=dict(job)
                if index_job:
                    offset=provider['offset'] if not provider['index_complete'] else 0
                    route=(programapi.PREFIXES[p]+'?limit=100&offset='+str(offset) if p=='intigriti' else
                           programapi.PREFIXES[p]+'?page%5Bsize%5D=100&page%5Bnumber%5D='+str(offset or 1))
                elif p=='intigriti':
                    remote_id=json.loads(provider['program_index']).get(programapi.canonical(job['policy']))
                    if not remote_id:
                        c.execute("UPDATE program_research SET status='access_blocked',due=? WHERE id=?",(now+REFRESH,job['id']));continue
                    route=programapi.PREFIXES[p]+'/'+remote_id
                else:
                    handle=programapi.canonical(job['policy']).split(':',1)[1];route=programapi.PREFIXES[p]+'/'+handle
                    if job['phase']=='policy' and provider['catalog_mode']:
                        c.execute("UPDATE program_research SET status='access_blocked',last_error='not_in_catalog',due=? WHERE id=?",(now+REFRESH,job['id']));continue
                    if job['phase']=='scopes':route+='/structured_scopes?page%5Bsize%5D=100&page%5Bnumber%5D='+str(job['page'])
                    elif job['phase']=='exclusions':route+='/scope_exclusions'
                chosen=(provider,job,index_job,route);break
            if not chosen:return
            provider,job,index_job,route=chosen;p=provider['provider']
            c.execute('UPDATE program_research_health SET next_request=? WHERE id=1',(now+INTERVAL,))
            c.execute("UPDATE program_research_providers SET next_request=?,last_request=?,status='collecting' WHERE provider=?",(now+INTERVAL,now,p))
            if not index_job:c.execute("UPDATE program_research SET last_attempt=?,requests=requests+1,due=?,status='collecting' WHERE id=?",(now,now+INTERVAL,job['id']))
        try:
            doc=programapi.request(p,available[p],route)
            with db() as c:
                if not index_job:c.execute("UPDATE program_research SET last_error='',error_phase='' WHERE id=?",(job['id'],))
                if index_job and p=='hackerone':
                    catalog,more=h1_catalog(doc,offset or 1)
                    seen={} if offset in (0,1) else json.loads(provider['program_index'])
                    for entry in c.execute("SELECT * FROM program_research WHERE provider='hackerone' AND active=1").fetchall():
                        key=programapi.canonical(entry['policy'])
                        if key not in catalog:continue
                        seen[key]='https://'+programapi.HOSTS[p]+route
                        if entry['status']=='access_blocked' and entry['last_error']!='not_in_catalog':continue
                        c.execute('UPDATE program_research SET last_attempt=?,requests=requests+1 WHERE id=?',(now,entry['id']))
                        try:partial=h1_policy({'data':catalog[key]},entry['policy'])
                        except programapi.APIError as e:
                            c.execute("UPDATE program_research SET status='incomplete',last_error=?,error_phase='policy',due=? WHERE id=?",(error_code(e.code),now+REFRESH,entry['id']));continue
                        partial['sources']=[seen[key]];partial['policy_checked_at']=now
                        bounded_storage(c,entry['id'],json.dumps(partial),partial=True)
                        c.execute("UPDATE program_research SET partial=?,phase='scopes',page=1,due=?,status='collecting',last_error='',error_phase='' WHERE id=?",(json.dumps(partial),now,entry['id']))
                    c.execute("UPDATE program_research_providers SET program_index=?,offset=?,index_complete=?,index_checked=?,status='queued' WHERE provider=?",(json.dumps(seen),(offset or 1)+1,int(not more),0 if more else now,p))
                    if not more:
                        for entry in c.execute("SELECT id,policy,status,last_error FROM program_research WHERE provider='hackerone' AND active=1").fetchall():
                            if programapi.canonical(entry['policy']) not in seen and (entry['status']!='access_blocked' or entry['last_error']=='not_in_catalog'):
                                c.execute("UPDATE program_research SET status='access_blocked',last_error='not_in_catalog',error_phase='index',due=? WHERE id=?",(now+REFRESH,entry['id']))
                elif index_job:
                    listed={programapi.canonical(r['policy']) for r in c.execute("SELECT policy FROM program_research WHERE provider='intigriti'")}
                    mappings,total,count=intigriti_index(doc,listed)
                    if count==0 and offset<total:raise programapi.APIError('schema')
                    old={} if offset==0 else json.loads(provider['program_index']);old.update(mappings)
                    done=offset+count>=total
                    c.execute("UPDATE program_research_providers SET program_index=?,offset=?,index_complete=?,index_checked=?,status='queued' WHERE provider=?",(json.dumps(old),offset+count,int(done),now if done else 0,p))
                    if done:
                        for entry in c.execute("SELECT id,policy FROM program_research WHERE provider='intigriti' AND status='access_blocked' AND requests=0").fetchall():
                            if programapi.canonical(entry['policy']) in old:c.execute("UPDATE program_research SET status='queued',due=0 WHERE id=?",(entry['id'],))
                elif p=='intigriti':
                    result=intigriti_policy(doc,job['policy']);result['sources']=['https://'+programapi.HOSTS[p]+route];result['policy_checked_at']=now;finish(c,job,result,now)
                elif job['phase']=='policy':
                    partial=h1_policy(doc,job['policy'])
                    partial['policy_checked_at']=now
                    bounded_storage(c,job['id'],json.dumps(partial),partial=True)
                    c.execute("UPDATE program_research SET partial=?,phase='scopes',page=1 WHERE id=?",(json.dumps(partial),job['id']))
                else:
                    partial=json.loads(job['partial'])
                    if job['phase']=='scopes':
                        rows,more=h1_scope(doc,handle,job['page']);partial['scope'].extend(rows)
                        if len(partial['scope'])>MAX_SCOPES:raise programapi.APIError('size')
                        partial['scope_complete']=not more
                        if more and job['page']>=20:raise programapi.APIError('size')
                        partial['sources'].append('https://'+programapi.HOSTS[p]+route)
                        bounded_storage(c,job['id'],json.dumps(partial),partial=True)
                        c.execute('UPDATE program_research SET partial=?,phase=?,page=? WHERE id=?',(json.dumps(partial),'scopes' if more else 'exclusions',job['page']+1 if more else 1,job['id']))
                    else:
                        partial['exclusions']=h1_exclusions(doc);partial['sources'].append('https://'+programapi.HOSTS[p]+route)
                        partial['documents_complete']=bool(partial['policy_text']) and partial['scope_complete'];finish(c,job,partial,now)
                c.execute("UPDATE program_research_providers SET last_success=?,last_error='',error_phase='' WHERE provider=?",(now,p))
        except Exception as error:
            code=error.code if isinstance(error,programapi.APIError) else 'schema' if isinstance(error,(ValueError,TypeError,KeyError,AttributeError)) else 'transport'
            with db() as c:
                fixed=error_code(code);phase='index' if index_job else job['phase']
                c.execute('UPDATE program_research_providers SET last_error=?,error_phase=? WHERE provider=?',(fixed,phase,p))
                if not index_job:c.execute('UPDATE program_research SET last_error=?,error_phase=? WHERE id=?',(fixed,phase,job['id']))
                if code==401 or index_job and code in (403,404):
                    c.execute("UPDATE program_research_providers SET blocked=1,status='access_blocked' WHERE provider=?",(p,))
                elif code in (403,404):
                    c.execute("UPDATE program_research SET status='access_blocked',due=? WHERE id=?",(now+REFRESH,job['id']))
                elif code in ERRORS and code!='transport' or isinstance(code,int) and 300<=code<500 and code!=429:
                    if index_job:c.execute("UPDATE program_research_providers SET blocked=1,status='incomplete' WHERE provider=?",(p,))
                    else:c.execute("UPDATE program_research SET status='incomplete',phase='policy',page=1,due=? WHERE id=?",(now+REFRESH,job['id']))
                else:
                    delay=max(300*2**min(job['failures'],6),getattr(error,'retry',0))
                    c.execute("UPDATE program_research_providers SET next_request=?,status='retry' WHERE provider=?",(now+delay,p))
                    if not index_job:c.execute("UPDATE program_research SET status='retry',failures=failures+1,due=? WHERE id=?",(now+delay,job['id']))


def snapshot(c,data_dir,details=False):
    now=int(time.time());connections=programapi.status(data_dir)
    health=c.execute('SELECT * FROM program_research_health WHERE id=1').fetchone()
    providers=[];provider_map={}
    for row in c.execute('SELECT * FROM program_research_providers'):
        r={k:row[k] for k in ('provider','blocked','next_request','last_request','last_success','status','index_complete','last_error','error_phase','catalog_mode')}
        r['error_label']=error_label(r['last_error'])
        r.update(connections[r['provider']]);providers.append(r);provider_map[r['provider']]=r
    rows=[];counts={};errors={};phases={};collected=attempted=policy_saved=0
    for row in c.execute('SELECT r.*,p.name FROM program_research r JOIN programs p ON p.id=r.id ORDER BY p.name'):
        provider=provider_map[row['provider']]
        status=('connection_needed' if not provider['connected'] and row['active'] else
                provider['status'] if provider['blocked'] and row['active'] else row['status'])
        counts[status]=counts.get(status,0)+1;attempted+=int(row['requests']>0)
        if status=='collecting':phases[row['phase']]=phases.get(row['phase'],0)+1
        evidence=json.loads(row['evidence']);fresh=bool(row['checked'] and row['checked']>=now-REFRESH)
        partial=json.loads(row['partial']);visible=partial or evidence
        policy_saved+=int(bool(visible.get('policy_text')))
        collected+=int(fresh and evidence.get('documents_complete') is True)
        item={k:row[k] for k in ('id','name','provider','policy','checked','last_attempt','requests','changes','due','last_error','error_phase','phase')}
        if row['last_error']:errors[row['last_error']]=errors.get(row['last_error'],0)+1
        item['error_label']=error_label(row['last_error'])
        item.update(status=status,label=LABELS[status],fresh=fresh,scope_assets=len(visible.get('scope',[])),partial=bool(partial),
                    documents_complete=bool(evidence.get('documents_complete')),grants_permission=False)
        if details:item['evidence']=evidence
        rows.append(item)
    paused=bool(c.execute('SELECT paused FROM settings').fetchone()[0]) or not bool(c.execute('SELECT enabled FROM discovery_settings').fetchone()[0])
    return {'heartbeat':health['heartbeat'],'healthy':bool(health['heartbeat'] and 0<=now-health['heartbeat']<90),
            'paused':paused,'listed':len(rows),'attempted':attempted,'documents_collected':collected,
            'policy_documents_saved':policy_saved,
            'counts':counts,'errors':errors,'phases':phases,'providers':providers,'rows':rows,'next_request':health['next_request'],
            'test_permissions_granted':0,'new_targets_activated':0,
            'coverage':'Collects official policy documents and scope through authorized platform APIs. It does not test assets, interpret every condition, create accounts or authorize new scans.'}


def detail(c,identity):
    row=c.execute('SELECT evidence,partial,checked,status FROM program_research WHERE id=?',(identity,)).fetchone()
    if not row:raise ValueError('Program research record not found')
    partial=json.loads(row['partial']);evidence=finalize(partial) if partial else json.loads(row['evidence'])
    return {'evidence':evidence,'checked':0 if partial else row['checked'],'status':row['status'],
            'partial':bool(partial),'policy_checked_at':evidence.get('policy_checked_at',0)}


def receipt(c,data_dir,revision):
    s=snapshot(c,data_dir)
    return {'kind':'scopeguard_program_research_health','revision':revision if re.fullmatch('[0-9a-f]{40}',revision or '') else 'unknown',
            **{k:s[k] for k in ('healthy','paused','listed','attempted','documents_collected','policy_documents_saved','counts','errors','phases')},
            'connections':{r['provider']:r['connected'] for r in s['providers']},
            'catalog_mode':{r['provider']:bool(r['catalog_mode']) for r in s['providers']},
            'provider_blocked':{r['provider']:bool(r['blocked']) for r in s['providers']}}
