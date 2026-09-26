"""Offline preparation from saved scope. Never grants permission or makes requests."""
import re
from urllib.parse import urlsplit

LIMIT = 80
CATEGORIES = {
    'web': 'Exact web addresses to review',
    'source': 'Source repositories to review',
    'choose_url': 'An exact permitted address is still needed',
    'specialist': 'Needs a test method ScopeGuard does not provide',
    'excluded': 'Not eligible for submissions',
    'unknown': 'Scope eligibility needs interpretation',
    'conflict': 'Conflicting scope entries need review',
}


def exact_url(asset):
    """Recognize an explicit HTTPS address only; never invent one from a host."""
    if not isinstance(asset,str) or re.search(r'[\s\x00-\x1f\x7f*\\]',asset):return None
    try:
        p=urlsplit(asset)
        if p.scheme!='https' or not p.hostname or p.username or p.password or p.port not in (None,443) or p.query or p.fragment:return None
        if not re.fullmatch(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}',p.hostname):return None
        if p.hostname.lower().endswith(('.localhost','.local','.internal')):return None
        return p
    except ValueError:return None


def asset_kind(row,excluded):
    eligibility=row.get('eligible_for_submission')
    if eligibility is False:return 'excluded'
    if eligibility is not True:return 'unknown'
    asset=row.get('asset','');kind=row.get('type','').upper()
    if asset in excluded:return 'conflict'
    url=exact_url(asset)
    if kind=='SOURCE_CODE':
        if url and url.hostname=='github.com' and re.fullmatch(r'/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}/?',url.path) and not url.path.rstrip('/').endswith('.git'):
            return 'source'
        return 'specialist'
    if kind in ('URL','DOMAIN','WILDCARD'):
        return 'web' if url and kind!='WILDCARD' else 'choose_url'
    return 'specialist'


def build(evidence,*,fresh=False,status='',assets=False):
    """Describe capability matches, not eligible targets or vulnerability leads.

    Platform submission eligibility alone never authorizes a test. Unknown
    Intigriti tiers, URL patterns, accounts, methods and exclusions stay unresolved.
    All original instructions remain in the evidence alongside this brief.
    """
    rows=evidence.get('scope',[])
    excluded={r.get('asset') for r in rows if r.get('eligible_for_submission') is False}
    counts={key:0 for key in CATEGORIES};candidates=[]
    for index,row in enumerate(rows):
        kind=asset_kind(row,excluded);counts[kind]+=1
        if assets and kind in ('web','source') and len(candidates)<LIMIT:
            candidates.append({'row':index,'asset':row['asset'],'kind':kind,
                               'method':'Read-only Python source analysis' if kind=='source' else 'Exact-address header observation',
                               'requires':'Explicit branch, supported Python content and source-review permission' if kind=='source' else 'Permission for this exact address, HEAD requests and request interval',
                               'bounty_eligible':row.get('eligible_for_bounty'),
                               'testing_enabled':False})
    complete=evidence.get('documents_complete') is True and evidence.get('scope_complete') is True
    prepared=bool(complete and fresh and status in ('collected','changed'))
    if not complete:next_step='Finish collecting current policy, scope and exclusions.'
    elif not fresh:next_step='Refresh the saved rules before preparing new testing.'
    elif status not in ('collected','changed'):next_step='Resolve the program or platform access block before new testing.'
    elif status=='changed':next_step='Review the changed rules before using any earlier test setup.'
    elif evidence.get('program_status','').lower()!='open':next_step='The program is not recorded as open. Verify its current status before testing.'
    elif evidence.get('automation_permission')=='restricted':next_step='Automated production testing is restricted. Keep production checks off.'
    elif counts['web']+counts['source']:next_step='Verify the matching method and all program conditions before configuring a test.'
    else:next_step='Resolve scope eligibility or use a supported, explicitly permitted test method.'
    passages=evidence.get('rule_passages',{})
    conditions=[{'title':title,'passages':len(passages.get(key,[]))} for key,title in (
        ('automation','Automation rules'),('accounts','Account and identity requirements'),
        ('limits','Request limits'),('exclusions','Exclusions and special conditions'))]
    out={'prepared':prepared,'counts':counts,'candidate_count':counts['web']+counts['source'],
         'next_step':next_step,'conditions':conditions,'testing_enabled':False,
         'no_login_testing':'unverified','confirmed_bugs':0,
         'limitation':'Capability matches are research preparation, not testing permission or vulnerability findings. Full policy, scope instructions, exclusions and linked rules still apply.'}
    if assets:
        out['candidates']=candidates if prepared else []
        out['omitted_candidates']=max(0,out['candidate_count']-LIMIT) if prepared else 0
    return out
