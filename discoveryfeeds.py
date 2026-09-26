"""Public directory adapters. No company requests, credentials or authorization."""
import hashlib
import math
import re
from urllib.parse import urlsplit, urlunsplit

BASE = 'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/'
SOURCES = {
    'hackerone': (BASE+'hackerone_data.json', {'hackerone.com'}),
    'intigriti': (BASE+'intigriti_data.json', {'www.intigriti.com','app.intigriti.com'}),
    'bugcrowd': (BASE+'bugcrowd_data.json', {'bugcrowd.com'}),
    'yeswehack': (BASE+'yeswehack_data.json', {'yeswehack.com'}),
    'independent': ('https://raw.githubusercontent.com/disclose/diodb/master/program-list.json', set()),
}
LABELS = {'hackerone':'HackerOne','intigriti':'Intigriti','bugcrowd':'Bugcrowd',
          'yeswehack':'YesWeHack','independent':'Independent companies'}
DIRECTORY_ONLY = frozenset(('bugcrowd','yeswehack','independent'))
PLATFORMS = ('hackerone.com','bugcrowd.com','intigriti.com','yeswehack.com',
             'federacy.com','hackenproof.com','immunefi.com','huntr.com','huntr.dev',
             'bugbounty.jp','bugbounty.com','openbugbounty.org')


def amount(value):
    if type(value) not in (int,float) or not math.isfinite(value) or not 0 <= value <= 1e9:
        return None
    return float(value)


def policy_url(value):
    """Validate links without resolving or requesting their hosts."""
    if not isinstance(value,str) or not 1 <= len(value) <= 1000 or re.search(r'[\s\x00-\x1f\x7f\\]',value):
        raise ValueError('Invalid policy link')
    try:
        p=urlsplit(value)
        if p.scheme!='https' or p.username is not None or p.password is not None or p.port not in (None,443):
            raise ValueError('Invalid policy link')
        host=p.hostname or ''
        if len(host)>253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',host):
            raise ValueError('Invalid policy host')
        if host.endswith(('.localhost','.local','.internal','.invalid','.test','.onion','.home','.lan')):
            raise ValueError('Non-public policy host')
        return urlunsplit(('https',host,p.path.rstrip('/'),p.query,''))
    except (ValueError,TypeError) as exc:
        raise ValueError('Invalid policy link') from exc


def normalize(source,p):
    if source not in DIRECTORY_ONLY or not isinstance(p,dict):
        raise ValueError('Unsupported directory record')
    maximum=minimum=None
    available=True
    reward='Reported bounty; current terms unverified'
    availability='Listed in a directory; current availability unverified'
    if source=='independent':
        if p.get('offers_bounty') not in ('yes','partial'):return None
        url=policy_url(p.get('policy_url'))
        host=urlsplit(url).hostname
        # Platform entries are discovered by their own adapters, not relabelled
        # as independent companies. Never infer duplicates from company names.
        if any(host==x or host.endswith('.'+x) for x in PLATFORMS):return None
        name=p.get('program_name')
        available=p.get('policy_url_status')!='dead'
        if not available:availability='Directory reports a dead policy link; review needed'
        if p['offers_bounty']=='partial':reward='Conditional bounty reported; qualifying conditions unverified'
        requirements=['Verify the company policy, reward eligibility, exact scope, automation rules and accounts.']
        scope_count=None
    else:
        name=p.get('name')
        if source=='bugcrowd':
            maximum=amount(p.get('max_payout'))
            if maximum is None or maximum<=0:return None
            url=policy_url(p.get('url'))
            if urlsplit(url).hostname!='bugcrowd.com' or not re.fullmatch(r'/engagements/[A-Za-z0-9_-]+',urlsplit(url).path):
                raise ValueError('Invalid Bugcrowd engagement')
        else:
            if p.get('public') is not True:return None
            maximum=amount(p.get('max_bounty'));minimum=amount(p.get('min_bounty'))
            if maximum is None or maximum<=0:return None
            slug=p.get('id')
            if not isinstance(slug,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,199}',slug):
                raise ValueError('Invalid YesWeHack slug')
            url='https://yeswehack.com/programs/'+slug
            if type(p.get('disabled')) is not bool:raise ValueError('Missing program state')
            available=not p['disabled']
            if not available:availability='Directory reports a disabled program'
        if urlsplit(url).query:raise ValueError('Unexpected platform link query')
        scopes=p.get('targets',{})
        if not isinstance(scopes,dict) or not isinstance(scopes.get('in_scope',[]),list):
            raise ValueError('Invalid directory scope shape')
        scope_count=len(scopes.get('in_scope',[]))
        requirements=['Review the official program scope, automation limits and platform-account requirements.']
    if not isinstance(name,str) or not name.strip() or len(name)>1000:
        raise ValueError('Program name missing or too long')
    return {'id':hashlib.sha256(url.encode()).hexdigest()[:24], 'name':name.strip()[:160],
            'url':url,'source':source,'minimum':None,'maximum':None,'currency':'',
            'open':available,'requirements':requirements,'scope_count':scope_count,
            'extra':{'availability':availability,'reward_status':reward,
                     'listed_maximum':maximum,'listed_minimum':minimum,'listed_currency':'',
                     'policy_status':'unverified','directory_only':True,
                     'grants_permission':False}}
