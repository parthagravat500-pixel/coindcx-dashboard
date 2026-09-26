"""Offline research catalog and evidence views. No requests, target writes or execution."""
import copy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import time

ROOT = Path(__file__).parent
SOURCE_RULES = dict(zip(
    ('SG-0781','SG-0782','SG-0783','SG-0784','SG-0785','SG-0786','SG-0787'),
    ('dynamic-code','shell-command','unsafe-deserialization','unsafe-yaml',
     'tls-verification','dynamic-sql','weak-random')))
POLICY_RULES = {'SG-0001','SG-0002','SG-0006','SG-0008'}
PROFILES = {'all','web','api','source','android','ios','desktop','cloud','ai'}
METHODS = {'document_review','source_or_configuration_review','controlled_manual_review'}
SCOPE_PROFILES = {
    'URL':'web','DOMAIN':'web','WILDCARD':'web','API':'api',
    'SOURCE_CODE':'source','ANDROID_APP':'android','GOOGLE_PLAY_APP_ID':'android',
    'IOS_APP':'ios','APPLE_STORE_APP_ID':'ios','WINDOWS_APP':'desktop','OTHER_IPA':'ios',
    'AI_MODEL':'ai',
}
LIMITATION = ('Suggested checkpoints are preparation, not tested controls or permission. '
              'Actual features, exclusions, accounts and methods still need review. '
              'A source pattern or policy flag is not a confirmed vulnerability.')


@lru_cache(maxsize=1)
def _catalog():
    path=ROOT/'checkpoints/catalog.json'
    if path.stat().st_size>1000000:raise ValueError('Checkpoint catalog is too large')
    data=json.loads(path.read_text())
    seen=set();titles=set();groups=set()
    for group in data['categories']:
        if group['id'] in groups or not re.fullmatch(r'area-\d{2}',group['id']):
            raise ValueError('Invalid checkpoint category')
        groups.add(group['id'])
        if not set(group['profiles'])<=PROFILES or not group['profiles'] or group['method'] not in METHODS:
            raise ValueError('Invalid checkpoint context')
        if not group['prerequisites'] or not group['evidence'] or not group['references']:
            raise ValueError('Missing checkpoint guidance')
        if any(r not in data['references'] for r in group['references']):
            raise ValueError('Unknown checkpoint reference')
        for row in group['checks']:
            title=' '.join(row['title'].casefold().split())
            if not re.fullmatch(r'SG-\d{4}',row['id']) or row['id'] in seen or title in titles or len(title)<20:
                raise ValueError('Duplicate or invalid checkpoint')
            seen.add(row['id']);titles.add(title)
    if len(seen)<1000 or not (set(SOURCE_RULES)|POLICY_RULES)<=seen:
        raise ValueError('Checkpoint catalog is incomplete')
    for filename,ids in data.get('ai_context',{}).items():
        if filename not in ('app.py','ci_identity.py') or len(ids)!=6 or len(set(ids))!=6 or not set(ids)<=seen:
            raise ValueError('Invalid bounded AI checkpoint context')
    return data


def inventory():
    data=_catalog();total=sum(len(g['checks']) for g in data['categories'])
    return {'version':data['version'],'total':total,'categories':len(data['categories']),
            'automatic_evidence_support':len(SOURCE_RULES)+len(POLICY_RULES),
            'contextual_review':total-len(SOURCE_RULES)-len(POLICY_RULES),
            'ai_guidance':len({key for ids in data.get('ai_context',{}).values() for key in ids}),
            'execution_enabled':False,'confirmed_bugs_from_catalog':0,
            'limitation':LIMITATION}


def plan_summary(evidence,*,fresh=False,status=''):
    """Suggest areas only from explicit eligible scope types, never policy keywords."""
    complete=evidence.get('documents_complete') is True and evidence.get('scope_complete') is True
    usable=bool(complete and fresh and status in ('collected','changed'))
    profiles={'all'}
    scope=evidence.get('scope',[])
    excluded={r.get('asset') for r in scope if r.get('eligible_for_submission') is False}
    if usable:
        for row in scope:
            if row.get('eligible_for_submission') is True and row.get('asset') not in excluded:
                profile=SCOPE_PROFILES.get(str(row.get('type','')).upper())
                if profile:profiles.add(profile)
    groups=[g for g in _catalog()['categories'] if profiles.intersection(g['profiles'])]
    blockers=[]
    if not usable:blockers.append('Current complete policy and scope evidence is needed; showing preparation areas only.')
    if status=='changed':blockers.append('Saved rules changed and need renewed review.')
    if str(evidence.get('program_status') or '').lower()!='open':blockers.append('Current open program status is unverified or testing is unavailable.')
    if evidence.get('automation_permission')=='restricted':blockers.append('Automation is restricted. No production testing is enabled by this plan.')
    else:blockers.append('Exact methods and testing permission remain unverified by this catalog.')
    return {'suggested':sum(len(g['checks']) for g in groups),'category_ids':[g['id'] for g in groups],
            'profiles':sorted(profiles),'scope_based':usable,'blockers':blockers,
            'tested':0,'testing_enabled':False,'limitation':LIMITATION,
            'basis':'Potential areas from explicit saved scope types. Feature applicability is not established; omitted areas are not declared safe or inapplicable.'}


def policy_support(detail):
    e=detail.get('evidence',{});checked=detail.get('checked',0)
    fresh=bool(isinstance(checked,(int,float)) and 0<=time.time()-checked<86400)
    complete=bool(not detail.get('partial') and fresh and e.get('documents_complete') is True and e.get('scope_complete') is True)
    def result(status,note):return {'state':status,'note':note,'checked':checked,'control_validated':False}
    out={key:result('needs_evidence','Current complete official evidence is not available.') for key in POLICY_RULES}
    if not complete:return out
    out['SG-0001']=result('evidence_recorded','Complete document collection is saved. Its interpretation and testing permission still need review.')
    status=str(e.get('program_status','')).lower()
    out['SG-0002']=result('needs_review' if status=='open' else 'blocked',
                         'Saved platform status: '+(status if status in ('open','paused','closed','disabled') else 'unknown')+'. This does not authorize a method.')
    scope=e.get('scope',[])
    excluded={r.get('asset') for r in scope if r.get('eligible_for_submission') is False}
    conflicts=sum(r.get('eligible_for_submission') is True and r.get('asset') in excluded for r in scope)
    out['SG-0006']=result('needs_review' if conflicts else 'evidence_recorded',
                         str(conflicts)+' exact inclusion/exclusion conflicts in saved scope rows. Wildcards, paths and prose exclusions still require interpretation.')
    restricted=e.get('automation_permission')=='restricted'
    out['SG-0008']=result('blocked' if restricted else 'needs_review',
                         'Saved evidence restricts automation; production testing stays off.' if restricted else 'No automatic permission decision is made from saved text or missing restrictions.')
    return out


@lru_cache(maxsize=128)
def _digest(path,mtime_ns,size):
    # Cache key includes file metadata; no inspected module is imported or executed.
    if size>128000:return ''
    return hashlib.sha256(('flow-v1\n'+Path(path).read_text()).encode()).hexdigest()


def source_support(c,root=ROOT):
    """Link existing owned-source results, never another program's findings."""
    import sourceaudit
    current=[];stale=0;allowed=set(sourceaudit.FILES)
    for row in c.execute("SELECT * FROM source_audits WHERE name LIKE 'ScopeGuard/%'"):
        name=row['name'].removeprefix('ScopeGuard/')
        if name not in allowed:continue
        try:
            path=root/name;stat=path.stat()
            if row['digest']!=_digest(str(path),stat.st_mtime_ns,stat.st_size):
                stale+=1;continue
            result=json.loads(row['result'])
            if result.get('language')!='Python' or result.get('rules_checked')!=len(SOURCE_RULES) or not isinstance(result.get('findings'),list) or not 0<row['checked']<=time.time():
                stale+=1;continue
            current.append((row,result))
        except (OSError,UnicodeError,ValueError,TypeError,AttributeError):
            stale+=1
    checked_files=len(current)
    out={}
    for key,rule in SOURCE_RULES.items():
        matches=sum(sum(x.get('rule')==rule for x in result['findings']) for _,result in current)
        truncated=any(result.get('truncated') for _,result in current)
        state='signal_recorded' if matches else 'no_signal_in_saved_files' if current and not truncated else 'needs_evidence'
        out[key]={'state':state,'note':str(matches)+' saved pattern signals across '+str(checked_files)+' current owned Python files. Patterns can be false positives; absent signals do not establish security.',
                  'checked':max((r['checked'] for r,_ in current),default=0),
                  'files':checked_files,'signals':matches,'truncated':bool(truncated),
                  'control_validated':False}
    return {'results':out,'current_owned_files':checked_files,'stale_owned_files':stale,
            'missing_owned_files':len(allowed)-checked_files-stale,
            'signal_count':sum(x['signals'] for x in out.values()),
            'source_limit':'Only existing saved Python pattern results for this ScopeGuard source revision. No program target was tested; no whole-control validation is claimed.'}


def summary(c,root=ROOT):
    source=source_support(c,root)
    return {**inventory(),**{k:source[k] for k in ('current_owned_files','stale_owned_files','missing_owned_files','signal_count')},
            'policy_evidence_checks':len(POLICY_RULES),'source_evidence_checks':len(SOURCE_RULES)}


def _parameters(query):
    from urllib.parse import parse_qs
    if len(query)>1200:raise ValueError('Checkpoint query is too long')
    values=parse_qs(query,keep_blank_values=True,max_num_fields=10)
    if set(values)-{'q','area','mode','program','context','offset','limit'} or any(len(v)!=1 for v in values.values()):
        raise ValueError('Unsupported checkpoint filter')
    p={k:v[0] for k,v in values.items()}
    if len(p.get('q',''))>120:raise ValueError('Search is limited to 120 characters')
    if p.get('mode','all') not in ('all','automatic','contextual','ai') or p.get('context','catalog') not in ('catalog','owned'):
        raise ValueError('Unsupported checkpoint view')
    if p.get('program') and (not re.fullmatch('[0-9a-f]{24}',p['program']) or p.get('context')=='owned'):
        raise ValueError('Invalid program context')
    for key,default,maximum in (('offset',0,10000),('limit',40,100)):
        value=p.get(key,str(default))
        if not re.fullmatch(r'\d{1,5}',value):raise ValueError('Invalid checkpoint page')
        p[key]=int(value)
        if p[key]>maximum or key=='limit' and p[key]<1:raise ValueError('Invalid checkpoint page')
    return p


def browse(c,query='',root=ROOT):
    p=_parameters(query);data=_catalog();plan=None;support={};context=p.get('context','catalog')
    if p.get('program'):
        program=c.execute('SELECT id,name,available,stage FROM programs WHERE id=?',(p['program'],)).fetchone()
        if not program:raise ValueError('Listed program not found')
        import programresearch
        try:detail=programresearch.detail(c,program['id'])
        except ValueError:detail={}
        e=detail.get('evidence',{});checked=detail.get('checked',0)
        plan=plan_summary(e,fresh=bool(checked and 0<=time.time()-checked<86400 and not detail.get('partial')),status=detail.get('status',''))
        if not program['available'] or program['stage']=='dismissed':plan['blockers'].insert(0,'The directory entry is unavailable or dismissed. This plan does not resume testing.')
        support=policy_support(detail);context='program'
        plan.update(program=program['id'],name=program['name'])
    elif context=='owned':
        support=source_support(c,root)['results']
    categories=[g for g in data['categories'] if not plan or g['id'] in plan['category_ids']]
    if p.get('area') and p['area'] not in {g['id'] for g in categories}:
        raise ValueError('Checkpoint area is not in this view')
    rows=[];q=p.get('q','').casefold();mode=p.get('mode','all')
    ai_ids={key for ids in data.get('ai_context',{}).values() for key in ids}
    for group in categories:
        if p.get('area') and group['id']!=p['area']:continue
        for entry in group['checks']:
            automatic=entry['id'] in SOURCE_RULES or entry['id'] in POLICY_RULES
            if mode=='automatic' and not automatic or mode=='contextual' and automatic:continue
            if mode=='ai' and entry['id'] not in ai_ids:continue
            if q and q not in (entry['id']+' '+entry['title']+' '+group['title']).casefold():continue
            rows.append((group,entry,automatic))
    items=[]
    for group,entry,automatic in rows[p['offset']:p['offset']+p['limit']]:
        tool='Saved owned Python pattern analysis' if entry['id'] in SOURCE_RULES else 'Saved official policy metadata review' if entry['id'] in POLICY_RULES else 'Contextual review; no automatic implementation'
        items.append({**entry,'category':group['title'],'category_id':group['id'],
                      'method':group['method'],'prerequisites':group['prerequisites'],'evidence_needed':group['evidence'],
                      'references':[dict(data['references'][r]) for r in group['references']],
                      'automatic_evidence_support':automatic,'support':tool,
                      'ai_guidance':entry['id'] in ai_ids,
                      'tested':False,'control_validated':False,
                      'observation':copy.deepcopy(support.get(entry['id'],{'state':'not_tested','note':'No checkpoint validation is recorded in this context.'}))})
    return {**inventory(),'context':context,'plan':plan,'matched':len(rows),'offset':p['offset'],
            'next_offset':p['offset']+p['limit'] if p['offset']+p['limit']<len(rows) else None,
            'items':items,'provenance':data['provenance'],
            'areas':[{'id':g['id'],'title':g['title'],'count':len(g['checks'])} for g in categories]}


def receipt(c,revision,root=ROOT):
    return {'kind':'scopeguard_checkpoints_health',
            'revision':revision if re.fullmatch('[0-9a-f]{40}',revision or '') else 'unknown',
            **summary(c,root)}
