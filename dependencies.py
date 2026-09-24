"""Persistent, bounded advisory monitoring of exact versions supplied by the owner.
Only package names and versions go to OSV. No package is installed or executed.
"""
import hashlib
import json
import re
import time
import urllib.request

MAX_BYTES = 500000
MAX_PACKAGES = 500
ENDPOINT = 'https://api.osv.dev/v1/querybatch'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Advisory service redirected')


def init(c):
    c.execute('''CREATE TABLE IF NOT EXISTS dependency_projects (
      name TEXT PRIMARY KEY, digest TEXT, packages TEXT, skipped INTEGER, enabled INTEGER,
      due INTEGER, checked INTEGER, status TEXT, result TEXT, failures INTEGER DEFAULT 0)''')


def inventory(filename, text):
    if not isinstance(text, str) or len(text.encode()) > MAX_BYTES:
        raise ValueError('Use a dependency file up to 500 KB.')
    packages = set(); skipped = 0
    def add(eco, name, version):
        nonlocal skipped
        if not isinstance(name,str) or not isinstance(version,str) or not re.fullmatch(r'(?:@[a-z0-9._-]+/)?[A-Za-z0-9._-]+',name) or len(name)>200 or not re.fullmatch(r'[0-9][A-Za-z0-9.!+_-]*(?:\.[A-Za-z0-9!+_-]+)*',version) or len(version)>100:
            skipped += 1; return
        if eco=='PyPI': name=re.sub(r'[-_.]+','-',name).lower()
        packages.add((eco,name,version))
        if len(packages)>MAX_PACKAGES: raise ValueError('Maximum 500 exact package versions per project.')
    if filename=='requirements.txt':
        for line in text.splitlines():
            line=line.strip()
            if not line or line.startswith('#'): continue
            m=re.fullmatch(r'([A-Za-z0-9._-]+)(?:\[[A-Za-z0-9,._-]+\])?==([^;\s]+)(?:\s+#.*)?',line)
            if m:add('PyPI',*m.groups())
            else:skipped+=1
    elif filename=='package-lock.json':
        try: data=json.loads(text)
        except (ValueError,RecursionError):raise ValueError('Invalid package-lock JSON.') from None
        if not isinstance(data,dict) or data.get('lockfileVersion') not in (2,3) or not isinstance(data.get('packages'),dict):
            raise ValueError('Use npm package-lock version 2 or 3.')
        for path,p in data['packages'].items():
            if path=='':continue
            if not isinstance(p,dict):skipped+=1;continue
            name=p.get('name') or path.rsplit('node_modules/',1)[-1]
            if p.get('link') or str(p.get('resolved','')).startswith(('git','file:')):skipped+=1;continue
            add('npm',name,p.get('version'))
    else: raise ValueError('Choose requirements.txt or package-lock.json.')
    if not packages:raise ValueError('No supported exact versions found. Version ranges and private Git URLs are not scanned.')
    return [{'ecosystem':e,'name':n,'version':v} for e,n,v in sorted(packages)],skipped


def upload(c,data):
    if data.get('owned') is not True or data.get('share_packages') is not True:
        raise ValueError('Confirm ownership and permission to send package names and versions to OSV.')
    name=data.get('project','')
    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}',name):raise ValueError('Use a short project name containing letters, numbers or spaces.')
    packages,skipped=inventory(data.get('filename'),data.get('source'))
    old=c.execute('SELECT * FROM dependency_projects WHERE name=?',(name,)).fetchone()
    if not old and c.execute('SELECT COUNT(*) FROM dependency_projects').fetchone()[0]>=10:raise ValueError('Maximum 10 projects.')
    encoded=json.dumps(packages);digest=hashlib.sha256(encoded.encode()).hexdigest()
    if old and old['digest']==digest and old['enabled']:return
    c.execute('''INSERT INTO dependency_projects VALUES(?,?,?,?,1,0,0,'Queued','[]',0)
      ON CONFLICT(name) DO UPDATE SET digest=excluded.digest,packages=excluded.packages,skipped=excluded.skipped,
      enabled=1,due=0,checked=0,status='Queued',result='[]',failures=0''',(name,digest,encoded,skipped))


def query(packages):
    payload={'queries':[{'package':{'name':p['name'],'ecosystem':p['ecosystem']},'version':p['version']} for p in packages]}
    request=urllib.request.Request(ENDPOINT,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json','User-Agent':'ScopeGuard-DependencyMonitor/1.0'})
    with urllib.request.build_opener(NoRedirect()).open(request,timeout=20) as response:raw=response.read(2000001)
    if len(raw)>2000000:raise ValueError('Advisory response exceeds size limit')
    data=json.loads(raw)
    if not isinstance(data,dict) or not isinstance(data.get('results'),list) or len(data['results'])!=len(packages):raise ValueError('Incomplete advisory response')
    matches=[]
    for package,result in zip(packages,data['results']):
        if not isinstance(result,dict) or result.get('next_page_token'):raise ValueError('Advisory response requires pagination; review incomplete')
        vulns=result.get('vulns',[])
        if not isinstance(vulns,list):raise ValueError('Invalid advisory list')
        ids=set()
        for v in vulns:
            key=v.get('id') if isinstance(v,dict) else None
            if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,150}',key):raise ValueError('Invalid advisory identifier')
            ids.add(key)
        if ids:matches.append({**package,'advisories':sorted(ids),'confirmed_exploitable':False})
    return matches


def tick(db,log):
    now=int(time.time())
    with db() as c:
        if c.execute('SELECT paused FROM settings').fetchone()[0]:return
        row=c.execute('SELECT * FROM dependency_projects WHERE enabled=1 AND due<=? ORDER BY due,name LIMIT 1',(now,)).fetchone()
        if not row:return
        row=dict(row)
        c.execute("UPDATE dependency_projects SET due=?,status='Checking advisory database' WHERE name=?",(now+300,row['name']))
    matches=[]
    try:
        packages=json.loads(row['packages'])
        for start in range(0,len(packages),50):
            with db() as c:
                current=c.execute('SELECT enabled,digest FROM dependency_projects WHERE name=?',(row['name'],)).fetchone()
                if c.execute('SELECT paused FROM settings').fetchone()[0] or not current or not current['enabled'] or current['digest']!=row['digest']:return
            matches.extend(query(packages[start:start+50]))
        with db() as c:
            updated=c.execute("UPDATE dependency_projects SET result=?,checked=?,due=?,status='Review complete — matches need impact validation',failures=0 WHERE name=? AND digest=? AND enabled=1",(json.dumps(matches),now,now+86400,row['name'],row['digest']))
            if updated.rowcount:log(c,'Dependency review completed for '+row['name']+': '+str(len(packages))+' versions checked, '+str(len(matches))+' packages with advisory matches. No exploit test or report sent.')
    except Exception as exc:
        with db() as c:
            c.execute('UPDATE dependency_projects SET status=?,failures=failures+1,due=? WHERE name=? AND digest=?',('Advisory check failed; previous results may be outdated ('+type(exc).__name__+')',now+min(86400,300*2**min(row['failures'],8)),row['name'],row['digest']))


def snapshot(c):
    output=[]
    for row in c.execute('SELECT * FROM dependency_projects ORDER BY name'):
        p=dict(row);p['package_count']=len(json.loads(p.pop('packages')));p['result']=json.loads(p['result']);output.append(p)
    return output
