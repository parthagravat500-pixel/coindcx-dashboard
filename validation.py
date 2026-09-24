"""Executable, read-only security regression checks of this owned app only.
The fixed loopback destination cannot be changed to a third-party target.
Credentials, response bodies and CSRF values are never persisted.
"""
import base64
import hashlib
import http.client
import json
import time

INTERVAL = 3600


def init(c):
    c.executescript('''
      CREATE TABLE IF NOT EXISTS validation_schedule (
        id INTEGER PRIMARY KEY CHECK(id=1), due INTEGER, last_started INTEGER,
        status TEXT, completed INTEGER);
      INSERT OR IGNORE INTO validation_schedule VALUES(1,0,0,'Waiting for first validation',0);
      CREATE TABLE IF NOT EXISTS validation_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER, result TEXT);
    ''')


def request(port,method,path,headers=None,body=None):
    conn=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
    try:
        conn.request(method,path,body=body,headers=headers or {})
        response=conn.getresponse();raw=response.read(1000001)
        if len(raw)>1000000:raise ValueError('Response exceeded validation limit')
        return response.status,raw
    finally:conn.close()


def run(port,token,allowed=lambda:True):
    if not isinstance(port,int) or not 1<=port<=65535 or len(token)<24:raise ValueError('Validation server configuration missing')
    auth={'Authorization':'Basic '+base64.b64encode(('admin:'+token).encode()).decode()}
    checks=[]
    def check(key,title,method,path,expected,headers=None,body=None,private=False):
        if not allowed():raise InterruptedError('Validation paused')
        status,raw=request(port,method,path,headers,body)
        exposed=False
        if private:
            try:
                data=json.loads(raw)
                exposed=isinstance(data,dict) and all(k in data for k in ('targets','findings','csrf','reporting'))
            except (ValueError,UnicodeError):pass
        checks.append({'id':key,'title':title,'method':method,'path':path,'expected_status':expected,
                       'actual_status':status,'passed':status==expected,'private_state_exposed':exposed,
                       'response_bytes':len(raw),'response_sha256':hashlib.sha256(raw).hexdigest()})
        return status,raw
    # Positive control avoids calling a dead server or universally broken login "secure".
    status,raw=check('control','Valid login reaches the private dashboard','GET','/api/state',200,auth)
    try:data=json.loads(raw)
    except (ValueError,UnicodeError):data={}
    control=status==200 and isinstance(data,dict) and all(k in data for k in ('targets','findings','csrf','reporting'))
    if not control:return {'status':'Inconclusive: authenticated control failed','checks':checks,'confirmed_issue':False,'submission_ready':False}
    check('anonymous-state','Private dashboard rejects visitors without login','GET','/api/state',401,private=True)
    check('wrong-password','Private dashboard rejects a wrong password','GET','/api/state',401,{'Authorization':'Basic '+base64.b64encode(b'admin:scopeguard-invalid-test-password').decode()},private=True)
    check('anonymous-report','Private reports require login','GET','/report/scopeguard-validation-missing',401)
    check('anonymous-write','Requests to change settings require login','POST','/api/all-pause',401,{'Content-Type':'application/json'},b'{}')
    # An empty object cannot change settings even if the CSRF check regresses.
    check('missing-csrf','Logged-in requests without CSRF token are rejected','POST','/api/all-pause',403,{**auth,'Content-Type':'application/json'},b'{}')
    check('wrong-csrf','Logged-in requests with a wrong CSRF token are rejected','POST','/api/all-pause',403,{**auth,'Content-Type':'application/json','X-CSRF-Token':'scopeguard-invalid-csrf'},b'{}')
    failures=[x for x in checks if not x['passed']]
    repeated=[]
    for failure in failures:
        if not failure['private_state_exposed']:continue
        headers=None if failure['id']=='anonymous-state' else {'Authorization':'Basic '+base64.b64encode(b'admin:scopeguard-invalid-test-password').decode()}
        check('repeat-'+failure['id'],'Repeat unauthorized access to owned private state','GET','/api/state',401,headers,private=True)
        if checks[-1]['private_state_exposed']:repeated.append(failure['id'])
    return {'status':'Reproduced private-state exposure on owned app' if repeated else 'Checks need investigation' if failures else 'All covered checks passed',
            'checks':checks,'confirmed_issue':bool(repeated),'confirmed_checks':repeated,'submission_ready':False,
            'scope':'Owned ScopeGuard application, local HTTP listener only. External hosting and other sites are not tested.',
            'impact':'Private dashboard state was returned without valid credentials in two requests.' if repeated else 'No private-state exposure demonstrated by these checks.',
            'limitation':'Covers selected login and CSRF boundaries only. Does not assess all vulnerability classes. This owned-app test is not a third-party bounty report.'}


def tick(db,log,port,token):
    now=int(time.time())
    with db() as c:
        if c.execute('SELECT paused FROM settings').fetchone()[0]:return
        s=c.execute('SELECT * FROM validation_schedule WHERE id=1').fetchone()
        if s['due']>now:return
        c.execute("UPDATE validation_schedule SET due=?,last_started=?,status='Running owned-app validation' WHERE id=1",(now+600,now))
    def allowed():
        with db() as c:return not c.execute('SELECT paused FROM settings').fetchone()[0]
    try:result=run(port,token,allowed)
    except InterruptedError:result={'status':'Paused during validation','checks':[],'confirmed_issue':False,'submission_ready':False}
    except Exception as exc:result={'status':'Validation could not finish ('+type(exc).__name__+')','checks':[],'confirmed_issue':False,'submission_ready':False}
    complete=bool(result.get('limitation'))
    with db() as c:
        c.execute('INSERT INTO validation_runs(at,result) VALUES(?,?)',(now,json.dumps(result)))
        c.execute('DELETE FROM validation_runs WHERE id NOT IN (SELECT id FROM validation_runs ORDER BY id DESC LIMIT 20)')
        c.execute('UPDATE validation_schedule SET due=?,status=?,completed=completed+? WHERE id=1',(now+(INTERVAL if complete else 600),result['status'],int(complete)))
        log(c,'Owned-app validation: '+result['status']+'. '+str(len(result['checks']))+' checks recorded; no bounty report sent.')


def queue(c):
    if c.execute('SELECT paused FROM settings').fetchone()[0]:raise ValueError('Resume checks first.')
    s=c.execute('SELECT * FROM validation_schedule WHERE id=1').fetchone()
    if s['last_started']>time.time()-300:raise ValueError('Validation ran recently. Please wait five minutes.')
    c.execute("UPDATE validation_schedule SET due=0,status='Queued' WHERE id=1")


def snapshot(c):
    s=dict(c.execute('SELECT * FROM validation_schedule WHERE id=1').fetchone())
    s['runs']=[{'id':r['id'],'at':r['at'],'result':json.loads(r['result'])} for r in c.execute('SELECT * FROM validation_runs ORDER BY id DESC LIMIT 20')]
    s['interval_minutes']=INTERVAL//60
    return s
