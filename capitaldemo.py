"""One bounded Capital.com demo watchlist access test, never trading endpoints."""
import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import tempfile
import time
from engine import public_addresses

HOST='demo-api-capital.backend-capital.com'
POLICY='https://app.intigriti.com/programs/capitalcom/capitalcom/detail'
INTERVAL=900
LIMIT=65536

def init(c):
    c.execute('''CREATE TABLE IF NOT EXISTS capital_demo (id INTEGER PRIMARY KEY CHECK(id=1),
      revision TEXT, enabled INTEGER, expires INTEGER, due INTEGER, checked INTEGER,
      status TEXT, result TEXT, runs INTEGER DEFAULT 0, setup_attempted INTEGER DEFAULT 0)''')

def path(root):return root/'capital-demo-private.json'

def save(root,value):
    fd,name=tempfile.mkstemp(prefix='.capital-',dir=root)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600);json.dump(value,f);f.flush();os.fsync(f.fileno())
        os.replace(name,path(root))
    finally:
        if os.path.exists(name):os.unlink(name)

def configure(c,root,data):
    if not all(data.get(k) is True for k in ('permission','demo_only','own_account','create_watchlist')):
        raise ValueError('Confirm the demo account is yours and current program rules permit this test and one synthetic watchlist.')
    values={}
    for key in ('identifier','api_key','password'):
        v=data.get(key)
        if not isinstance(v,str) or not 1<=len(v)<=512 or any(ord(ch)<32 or ord(ch)>126 for ch in v):
            raise ValueError('Enter your demo account email, API key and API key password in the secure form.')
        values[key]=v
    current=c.execute('SELECT * FROM capital_demo WHERE id=1').fetchone()
    now=int(time.time())
    if current and current['checked']>now-INTERVAL:
        raise ValueError('Please wait 15 minutes after the last run before reconnecting.')
    revision=secrets.token_hex(16)
    # Preserve the marker for reconnecting the same account; no saved session tokens.
    marker='SG_'+secrets.token_hex(8)
    if path(root).exists():
        old=json.loads(path(root).read_text())
        if old.get('identifier')==values['identifier']:marker=old['marker']
    save(root,{**values,'marker':marker,'revision':revision})
    c.execute('''INSERT INTO capital_demo VALUES(1,?,1,?,0,0,'Waiting for first demo test','{}',0,0)
      ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,enabled=1,expires=excluded.expires,
      due=0,status=excluded.status,result='{}',setup_attempted=0 ''',(revision,now+7*86400))

def disconnect(c,root):
    c.execute("UPDATE capital_demo SET enabled=0,status='Disconnected; saved credentials removed' WHERE id=1")
    path(root).unlink(missing_ok=True)

def request(method,endpoint,headers=None,payload=None):
    if (method,endpoint) not in {('POST','/api/v1/session'),('GET','/api/v1/watchlists'),('POST','/api/v1/watchlists')}:
        raise ValueError('Endpoint is not allowed by the demo connector')
    headers=headers or {}
    if not set(headers)<= {'X-CAP-API-KEY','CST','X-SECURITY-TOKEN'} or any(not isinstance(v,str) or not 1<=len(v)<=4096 or any(ord(ch)<32 or ord(ch)>126 for ch in v) for v in headers.values()):
        raise ValueError('Invalid authentication headers')
    if method=='POST':
        expected={'identifier','password','encryptedPassword'} if endpoint.endswith('/session') else {'name','epics'}
        if not isinstance(payload,dict) or set(payload)!=expected:raise ValueError('Invalid demo request')
        if endpoint.endswith('/watchlists') and (payload['epics']!=[] or not isinstance(payload['name'],str) or not payload['name'].startswith('SG_') or len(payload['name'])!=19):raise ValueError('Only an empty synthetic watchlist may be created')
    addresses=public_addresses(HOST)
    raw=socket.create_connection((addresses[0],443),timeout=10)
    conn=http.client.HTTPSConnection(HOST,timeout=10)
    try:
        conn.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=HOST)
        h={'User-Agent':'ScopeGuard/2.0 authorized-demo-watchlist-test','Accept':'application/json','Accept-Encoding':'identity','Cache-Control':'no-cache','Connection':'close',**headers}
        body=None
        if payload is not None:body=json.dumps(payload).encode();h['Content-Type']='application/json'
        conn.request(method,endpoint,body=body,headers=h)
        r=conn.getresponse();body=r.read(LIMIT+1)
        if len(body)>LIMIT:raise ValueError('Response too large')
        mime=r.getheader('Content-Type','').split(';',1)[0].strip().lower()
        data=None
        if (mime=='application/json' or mime.endswith('+json')) and r.getheader('Content-Encoding','identity').lower()=='identity':
            try:data=json.loads(body)
            except (ValueError,UnicodeError,RecursionError):pass
        return {'status':r.status,'data':data,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),
                'tokens':{k:r.getheader(k,'') for k in ('CST','X-SECURITY-TOKEN')}}
    finally:
        conn.close();raw.close()

def run(config,allowed=lambda:True,transport=None,pace=None,claim_setup=lambda:None):
    transport=transport or request;pace=pace or (lambda:time.sleep(1))
    evidence=[]
    result={'reproduced':False,'submission_ready':False,'severity':'Not assessed','evidence':evidence,
            'coverage':'Demo watchlist login boundary only. No cross-account, trading, injection or wider site testing.',
            'marker_sha256':hashlib.sha256(config['marker'].encode()).hexdigest()}
    def call(label,method,endpoint,headers=None,payload=None):
        pace()
        if not allowed():raise InterruptedError('Stopped')
        r=transport(method,endpoint,headers,payload)
        present=False
        if isinstance(r['data'],dict) and isinstance(r['data'].get('watchlists'),list):
            present=any(isinstance(x,dict) and x.get('name')==config['marker'] and x.get('defaultSystemWatchlist') is False for x in r['data']['watchlists'])
        evidence.append({'step':label,'status':r['status'],'marker_present':present,'bytes':r['bytes'],'sha256':r['sha256']})
        if r['status']==429 or r['status']>=500:raise RuntimeError('Rate limit or server error')
        return r,present
    def positive(r,present):return 200<=r['status']<300 and present
    session,_=call('Demo login','POST','/api/v1/session',{'X-CAP-API-KEY':config['api_key']},
                   {'identifier':config['identifier'],'password':config['password'],'encryptedPassword':False})
    if session['status']!=200 or not all(session['tokens'].values()):
        return {**result,'status':'Setup needs attention: demo login failed'}
    headers=session['tokens']
    control,present=call('Authenticated watchlist control','GET','/api/v1/watchlists',headers)
    if not positive(control,present):
        if control['status']!=200 or not isinstance(control['data'],dict) or not isinstance(control['data'].get('watchlists'),list):
            return {**result,'status':'Setup needs attention: could not read your demo watchlists'}
        claim_setup()
        created,_=call('Create one empty synthetic watchlist','POST','/api/v1/watchlists',headers,{'name':config['marker'],'epics':[]})
        if created['status']!=200 or not isinstance(created['data'],dict) or created['data'].get('status')!='SUCCESS':
            return {**result,'status':'Setup needs attention: watchlist creation was not confirmed; review before reconnecting'}
        control,present=call('Authenticated watchlist control after setup','GET','/api/v1/watchlists',headers)
        if not positive(control,present):return {**result,'status':'Setup needs attention: private test marker was not returned'}
    anonymous,present=call('Anonymous watchlist comparison','GET','/api/v1/watchlists')
    if not positive(anonymous,present):
        held=anonymous['status'] in (401,403,404) or (200<=anonymous['status']<300 and isinstance(anonymous['data'],dict) and isinstance(anonymous['data'].get('watchlists'),list))
        return {**result,'status':'Access boundary held for this demo test' if held else 'Inconclusive: anonymous response was not usable'}
    again,present=call('Repeated anonymous comparison','GET','/api/v1/watchlists')
    final,final_present=call('Authenticated control repeated','GET','/api/v1/watchlists',headers)
    if positive(again,present) and positive(final,final_present):
        return {**result,'reproduced':True,'status':'Synthetic private watchlist returned without login twice; manual impact review required'}
    return {**result,'status':'Inconclusive: exposure did not reproduce with working controls'}

def tick(db,root,log):
    now=int(time.time())
    with db() as c:
        if c.execute('SELECT paused FROM settings').fetchone()[0]:return
        row=c.execute('SELECT * FROM capital_demo WHERE enabled=1 AND expires>? AND due<=?',(now,now)).fetchone()
        if not row:return
        row=dict(row);c.execute("UPDATE capital_demo SET due=?,status='Running demo watchlist test' WHERE id=1",(now+INTERVAL,))
    def allowed():
        with db() as c:
            current=c.execute('SELECT * FROM capital_demo WHERE id=1').fetchone()
            return bool(current and current['revision']==row['revision'] and current['enabled'] and current['expires']>time.time() and not c.execute('SELECT paused FROM settings').fetchone()[0])
    try:
        config=json.loads(path(root).read_text())
        if config['revision']!=row['revision']:raise ValueError('Reconnect required')
        def claim_setup():
            with db() as c:
                changed=c.execute('UPDATE capital_demo SET setup_attempted=1 WHERE id=1 AND revision=? AND setup_attempted=0',(row['revision'],))
                if not changed.rowcount:raise ValueError('Watchlist setup already attempted; review before reconnecting')
        result=run(config,allowed,claim_setup=claim_setup)
    except Exception as exc:
        result={'status':'Stopped ('+type(exc).__name__+'); review setup before reconnecting','reproduced':False,'submission_ready':False,'evidence':[]}
    keep=result['status']=='Access boundary held for this demo test'
    with db() as c:
        changed=c.execute('UPDATE capital_demo SET checked=?,enabled=?,status=?,result=?,runs=runs+1 WHERE id=1 AND revision=?',
                          (now,int(keep),result['status'],json.dumps(result),row['revision']))
        if changed.rowcount:log(c,'Capital.com demo test: '+result['status']+'. No report sent.')

def snapshot(c):
    r=c.execute('SELECT * FROM capital_demo WHERE id=1').fetchone()
    if not r:return {'connected':False,'status':'Needs your demo account','runs':0,'result':{}}
    return {**{k:r[k] for k in ('enabled','expires','due','checked','status','runs')},'connected':True,'result':json.loads(r['result'])}
