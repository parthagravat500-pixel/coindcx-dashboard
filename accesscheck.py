"""Bounded authenticated/anonymous comparison on one explicitly approved JSON URL.
Only owner-controlled synthetic markers are retained as hashes in evidence.
"""
import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import tempfile
import time
from engine import validate_url, public_addresses

INTERVAL=900
MAX_BODY=65536


def init(c):
    c.execute('''CREATE TABLE IF NOT EXISTS access_checks (
      target INTEGER PRIMARY KEY, revision TEXT, rules TEXT, expires INTEGER,
      enabled INTEGER, due INTEGER, checked INTEGER, status TEXT, result TEXT)''')


def config_path(root,target):return root/('access-check-'+str(int(target))+'.json')


def configure(c,root,data):
    if not all(data.get(k) is True for k in ('permission','own_data','read_only','private_expected')):
        raise ValueError('Confirm permission, ownership of test data, read-only GET and expected private access.')
    target=c.execute('SELECT * FROM targets WHERE id=?',(data.get('target'),)).fetchone()
    if not target or not target['enabled'] or target['expires']<=time.time():raise ValueError('Choose an active approved exact URL.')
    url=target['url'];validate_url(url)
    marker=data.get('marker','');auth=data.get('authorization','');rules=data.get('rules','')
    if not isinstance(marker,str) or not 24<=len(marker)<=160 or not marker.isascii() or not all(ch.isalnum() or ch in '_-' for ch in marker) or marker in url:
        raise ValueError('Use a unique 24–160 character test marker containing letters, numbers, underscores or hyphens; it must not be in the URL.')
    if not isinstance(auth,str) or not auth.startswith(('Bearer ','Basic ')) or not 15<=len(auth)<=4096 or any(ord(ch)<32 or ord(ch)>126 for ch in auth):
        raise ValueError('Enter a Bearer or Basic authorization value for your own test account.')
    if not isinstance(rules,str) or not 30<=len(rules.strip())<=8000:raise ValueError('Record policy permission for authenticated and anonymous GET comparisons, up to four requests per 15 minutes.')
    revision=secrets.token_hex(16)
    fd,temp=tempfile.mkstemp(prefix='.access-',dir=root)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600);json.dump({'revision':revision,'url':url,'marker':marker,'authorization':auth},f);f.flush();os.fsync(f.fileno())
        os.replace(temp,config_path(root,target['id']))
    finally:
        if os.path.exists(temp):os.unlink(temp)
    c.execute('''INSERT INTO access_checks VALUES(?,?,?,?,1,0,0,'Queued','{}')
      ON CONFLICT(target) DO UPDATE SET revision=excluded.revision,rules=excluded.rules,expires=excluded.expires,
      enabled=1,due=0,checked=0,status='Queued',result='{}' ''',(target['id'],revision,rules.strip(),target['expires']))


def fetch(url,authorization,marker):
    p=validate_url(url);addresses=public_addresses(p.hostname)
    raw=socket.create_connection((addresses[0],443),timeout=10)
    conn=http.client.HTTPSConnection(p.hostname,timeout=10)
    try:
        conn.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=p.hostname)
        headers={'User-Agent':'ScopeGuard/2.0 authorized-owned-data-check','Accept':'application/json','Accept-Encoding':'identity','Cache-Control':'no-cache','Connection':'close'}
        if authorization:headers['Authorization']=authorization
        conn.request('GET',p.path or '/',headers=headers)
        response=conn.getresponse();body=response.read(MAX_BODY+1)
        if len(body)>MAX_BODY:raise ValueError('Response exceeds the 64 KB test limit')
        mime=response.getheader('Content-Type','').split(';',1)[0].strip().lower()
        encoding=response.getheader('Content-Encoding','identity').lower()
        json_body=False;found=False
        if (mime=='application/json' or mime.endswith('+json')) and encoding=='identity':
            try:
                value=json.loads(body);json_body=True
                def contains(v):
                    if isinstance(v,str):return marker in v
                    if isinstance(v,list):return any(contains(x) for x in v)
                    if isinstance(v,dict):return any(contains(x) for x in v.values())
                    return False
                found=contains(value)
            except (ValueError,UnicodeError,RecursionError):pass
        return {'status':response.status,'json':json_body,'marker_present':found,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
    finally:
        conn.close();raw.close()


def compare(config,allowed=lambda:True,transport=fetch):
    evidence=[]
    def observe(label,auth):
        if not allowed():raise InterruptedError('Profile stopped or scope expired')
        r=transport(config['url'],auth,config['marker']);evidence.append({'step':label,**r})
        if r['status']==429 or r['status']>=500:raise RuntimeError('Rate limit or server error; stop testing')
        return r
    def positive(r):return 200<=r['status']<300 and r['json'] and r['marker_present']
    first=observe('Authenticated control',config['authorization'])
    result={'evidence':evidence,'marker_sha256':hashlib.sha256(config['marker'].encode()).hexdigest(),
            'reproduced':False,'submission_ready':False,'severity':'Not assessed'}
    if not positive(first):return {**result,'status':'Setup needs attention: authenticated control did not return the private test marker'}
    anonymous=observe('Anonymous comparison',None)
    if not positive(anonymous):
        return {**result,'status':'Access boundary held for this test' if anonymous['status'] in (401,403,404) or (200<=anonymous['status']<300 and anonymous['json']) else 'Inconclusive response; no exposure established'}
    again=observe('Repeated anonymous comparison',None)
    final=observe('Authenticated control repeated',config['authorization'])
    if positive(again) and positive(final):
        result.update(reproduced=True,status='Private test marker returned without login in two requests',
                      impact='The exact approved URL returned owner-designated private test data without the supplied account credentials. Confirm intended access rules and real security impact before submission.',
                      reproduction=['Create a unique synthetic marker in your own private test resource.','GET the exact URL with the owner account Authorization header: verify the marker in JSON.','GET the same URL twice without Authorization: the marker is present in both responses.','Repeat the authenticated GET as a control.'],
                      remediation='Enforce authorization for the resource on the server and check whether shared caching exposes authenticated responses.')
    else:result['status']='Inconclusive: suspected exposure did not reproduce with working controls'
    return result


def tick(db,root,log):
    now=int(time.time())
    with db() as c:
        if c.execute('SELECT paused FROM settings').fetchone()[0]:return
        row=c.execute('''SELECT a.*,t.url FROM access_checks a JOIN targets t ON t.id=a.target
          WHERE a.enabled=1 AND a.expires>? AND t.enabled=1 AND t.expires>? AND a.due<=? ORDER BY a.due,a.target LIMIT 1''',(now,now,now)).fetchone()
        if not row:return
        row=dict(row);c.execute("UPDATE access_checks SET due=?,status='Checking private-data access' WHERE target=?",(now+INTERVAL,row['target']))
    def allowed():
        with db() as c:
            current=c.execute('''SELECT a.revision,a.enabled,a.expires,t.enabled AS active,t.expires AS scope_expires,t.url
              FROM access_checks a JOIN targets t ON t.id=a.target WHERE a.target=?''',(row['target'],)).fetchone()
            return bool(current and current['revision']==row['revision'] and current['url']==row['url'] and current['enabled'] and current['active'] and min(current['expires'],current['scope_expires'])>time.time() and not c.execute('SELECT paused FROM settings').fetchone()[0])
    try:
        config=json.loads(config_path(root,row['target']).read_text())
        if config['revision']!=row['revision'] or config['url']!=row['url']:raise ValueError('Profile credentials require reconnection')
        result=compare(config,allowed)
        # Stop after a reproduced exposure or bad positive control; do not keep reading data.
        stop=result['reproduced'] or result['status'].startswith('Setup needs attention')
        delay=INTERVAL
    except Exception as exc:
        result={'status':'Check stopped ('+type(exc).__name__+'); no conclusion established','reproduced':False,'submission_ready':False,'evidence':[]}
        stop=True;delay=3600
    with db() as c:
        changed=c.execute('UPDATE access_checks SET checked=?,due=?,enabled=?,status=?,result=? WHERE target=? AND revision=?',
           (now,now+delay,int(not stop),result['status'],json.dumps(result),row['target'],row['revision']))
        if changed.rowcount:log(c,'Private-data access check for target '+str(row['target'])+': '+result['status']+'. No report sent.')


def remove(c,root,target):
    target=int(target)
    c.execute('DELETE FROM access_checks WHERE target=?',(target,))
    config_path(root,target).unlink(missing_ok=True)


def snapshot(c):
    return [{**{k:r[k] for k in ('target','expires','enabled','due','checked','status')},'result':json.loads(r['result'])}
            for r in c.execute('SELECT * FROM access_checks ORDER BY checked DESC,target')]
