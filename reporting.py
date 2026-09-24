"""HackerOne delivery: private credentials, evidence gate, no blind retries."""
import base64
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import supervisor

API='https://api.hackerone.com/v1'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise ValueError('Reporting endpoint redirected')


def request(credentials,route,payload=None):
    token=base64.b64encode((credentials['username']+':'+credentials['token']).encode()).decode()
    headers={'Authorization':'Basic '+token,'Accept':'application/json','Content-Type':'application/json'}
    req=urllib.request.Request(API+route,headers=headers,data=json.dumps(payload).encode() if payload is not None else None)
    with urllib.request.build_opener(NoRedirect()).open(req,timeout=20) as response:
        raw=response.read(1000001)
        if len(raw)>1000000:raise ValueError('Response too large')
        return json.loads(raw)


def load(data_dir):
    try:
        data=json.loads((data_dir/'reporting-connection.json').read_text())
        return data if data.get('enabled') and data.get('username') and data.get('token') else None
    except (OSError,ValueError):return None


def save(data_dir,data):
    fd,temp=tempfile.mkstemp(prefix='.reporting-',dir=data_dir)
    try:
        with os.fdopen(fd,'w') as file:
            os.fchmod(file.fileno(),0o600);json.dump(data,file);file.flush();os.fsync(file.fileno())
        os.replace(temp,data_dir/'reporting-connection.json')
    finally:
        if os.path.exists(temp):os.unlink(temp)


def connect(data_dir,data):
    username=data.get('username','');token=data.get('token','')
    if (not isinstance(username,str) or not isinstance(token,str) or not 1<=len(username)<=150
        or not 10<=len(token)<=500 or ':' in username or any(ch.isspace() for ch in username+token)):
        raise ValueError('Enter the API username and token from your HackerOne account.')
    if data.get('authorize_delivery') is not True:
        raise ValueError('Confirm permission to submit verified reports through your account.')
    credentials={'username':username,'token':token,'enabled':True,'verified_at':int(time.time())}
    try:
        result=request(credentials,'/hackers/me/reports?page[size]=1')
        if not isinstance(result.get('data'),list):raise ValueError('Unexpected account response')
    except Exception:
        raise ValueError('HackerOne access could not be verified. Check the API username and token. Nothing was saved.') from None
    save(data_dir,credentials)


def init(c):
    c.execute('''CREATE TABLE IF NOT EXISTS report_delivery (finding TEXT PRIMARY KEY, at INTEGER NOT NULL,
                 status TEXT NOT NULL, receipt TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '')''')


def make_payload(f,t,review):
    if review.get('submission_ready') is not True:raise ValueError('No independently validated security impact')
    if not t['enabled'] or t['expires']<=time.time():raise ValueError('Scope approval expired or disabled')
    route=review.get('channel',{}).get('url','');url=urlsplit(route)
    if url.scheme!='https' or url.netloc!='hackerone.com' or url.query or url.fragment:
        raise ValueError('Program does not use a verified HackerOne route')
    handle=url.path.strip('/')
    if not handle or any(ch not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for ch in handle):
        raise ValueError('Invalid program handle')
    # Proof must come from an independently validated report, never an AI opinion or a flag count.
    verified=review.get('validated_report',{})
    reproduction=verified.get('reproduction','');impact=verified.get('impact','')
    if not isinstance(reproduction,str) or not isinstance(impact,str) or len(reproduction.strip())<50 or len(impact.strip())<30:
        raise ValueError('Reproduction steps and demonstrated impact are required')
    if len(reproduction)>20000 or len(impact)>5000:raise ValueError('Report too long')
    return {'data':{'type':'report','attributes':{'team_handle':handle,'title':f['title'][:200],
            'vulnerability_information':reproduction,'impact':impact,'severity_rating':'none'}}}


def tick(db,data_dir):
    credentials=load(data_dir)
    if not credentials:return
    job=None;now=int(time.time())
    with db() as c:
        if c.execute('SELECT paused FROM settings').fetchone()[0]:return
        if c.execute('SELECT 1 FROM report_delivery WHERE at>=?',(now//86400*86400,)).fetchone():return
        for row in c.execute('SELECT * FROM findings ORDER BY last_seen DESC'):
            f=dict(row)
            if c.execute('SELECT 1 FROM report_delivery WHERE finding=?',(f['id'],)).fetchone():continue
            if c.execute('SELECT 1 FROM submissions WHERE finding=?',(f['id'],)).fetchone():continue
            t=dict(c.execute('SELECT * FROM targets WHERE id=?',(f['target'],)).fetchone())
            review=supervisor.review(c,f,t)
            try:payload=make_payload(f,t,review)
            except ValueError:continue
            # Persist before sending. On timeout or crash, do NOT retry automatically.
            c.execute('INSERT INTO report_delivery(finding,at,status,note) VALUES (?,?,?,?)',
                      (f['id'],now,'sending','Awaiting HackerOne receipt. If interrupted, inspect your account before retrying.'))
            job=(f['id'],payload);break
    if not job:return
    status='uncertain';receipt='';note='Delivery not confirmed. Check HackerOne before attempting another submission.'
    try:
        result=request(credentials,'/hackers/reports',job[1]);rid=str(result.get('data',{}).get('id',''))
        if result.get('data',{}).get('type')!='report' or not rid.isdigit():raise ValueError('No valid receipt')
        receipt='https://hackerone.com/reports/'+rid;status='sent';note='HackerOne returned a report ID. This does not mean the report is accepted or paid.'
    except urllib.error.HTTPError as error:
        if 400<=error.code<500:
            status='rejected';note='HackerOne rejected the request. No automatic retry; check account permissions and program requirements.'
    except Exception:pass
    with db() as c:
        c.execute('UPDATE report_delivery SET status=?,receipt=?,note=? WHERE finding=?',(status,receipt,note,job[0]))
        if status=='sent':
            c.execute('INSERT OR IGNORE INTO submissions(finding,channel,receipt,at,origin) VALUES (?,?,?,?,?)',
                      (job[0],'portal',receipt,now,'hackerone_receipt'))


def snapshot(c,data_dir):
    return {'connected':load(data_dir) is not None,'daily_limit':1,
            'attempts':[dict(r) for r in c.execute('SELECT * FROM report_delivery ORDER BY at DESC LIMIT 20')],
            'note':'Only independently validated reports can be sent. Current header observations do not qualify.'}
