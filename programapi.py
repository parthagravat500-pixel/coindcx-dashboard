"""Read-only official program APIs. Credentials and private program data stay local."""
import base64
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import tempfile
import time
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qs, urlsplit

from engine import public_addresses
import reporting

HOSTS = {'hackerone':'api.hackerone.com','intigriti':'api.intigriti.com'}
PREFIXES = {'hackerone':'/v1/hackers/programs','intigriti':'/external/researcher/v1/programs'}
HANDLE = r'[A-Za-z0-9_-]{1,100}'
GUID = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
MAX_BYTES = 2000000


class APIError(Exception):
    def __init__(self, code, retry=0):
        super().__init__('Official program API request was not completed')
        self.code, self.retry = code, retry


def canonical(url):
    if not isinstance(url,str): return ''
    try:
        p=urlsplit(url)
        if p.scheme!='https' or p.username or p.password or p.port not in (None,443) or p.query or p.fragment:return ''
        if p.hostname=='hackerone.com' and re.fullmatch('/'+HANDLE+'/?',p.path):return 'hackerone:'+p.path.strip('/').lower()
        if p.hostname in ('www.intigriti.com','app.intigriti.com','intigriti.com') and re.fullmatch('/programs/'+HANDLE+'/'+HANDLE+'/detail/?',p.path):
            return 'intigriti:'+p.path.strip('/').lower()
    except ValueError:pass
    return ''


def valid_route(provider, route):
    if provider not in HOSTS or not isinstance(route,str):return False
    p=urlsplit(route);prefix=PREFIXES[provider]
    if p.scheme or p.netloc or p.fragment:return False
    if provider=='hackerone':
        pattern=re.escape(prefix)+r'(?:/'+HANDLE+r'(?:/(?:structured_scopes|scope_exclusions))?)?'
        limits={'page[number]':100,'page[size]':100}
    else:
        pattern=re.escape(prefix)+r'(?:/'+GUID+r')?';limits={'limit':500,'offset':10000}
    if not re.fullmatch(pattern,p.path):return False
    try:q=parse_qs(p.query,keep_blank_values=True,strict_parsing=True)
    except ValueError:return False
    return all(k in limits and len(v)==1 and v[0].isdigit() and 0<=int(v[0])<=limits[k] for k,v in q.items())


def retry_after(value, now=None):
    now=time.time() if now is None else now
    try:
        return max(0,int(value)) if str(value).isdigit() else max(0,int(parsedate_to_datetime(value).timestamp()-now)+1)
    except (ValueError,TypeError,OverflowError):return 0


def request(provider, credentials, route):
    if not valid_route(provider,route):raise ValueError('Unsupported official API route')
    host=HOSTS[provider]
    auth=('Basic '+base64.b64encode((credentials['username']+':'+credentials['token']).encode()).decode()
          if provider=='hackerone' else 'Bearer '+credentials['token'])
    raw=None;conn=http.client.HTTPSConnection(host,timeout=20)
    try:
        try:addresses=public_addresses(host)
        except ValueError:raise APIError('dns') from None
        raw=socket.create_connection((addresses[0],443),timeout=20)
        conn.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=host)
        conn.request('GET',route,headers={'Authorization':auth,'Accept':'application/json',
                     'User-Agent':'ScopeGuard-PolicyResearch/1','Accept-Encoding':'identity','Connection':'close'})
        response=conn.getresponse()
        if response.status!=200:raise APIError(response.status,retry_after(response.getheader('Retry-After','')))
        size=response.getheader('Content-Length','')
        if size.isdigit() and int(size)>MAX_BYTES:raise APIError('size')
        body=response.read(MAX_BYTES+1)
        if len(body)>MAX_BYTES:raise APIError('size')
        try:result=json.loads(body)
        except (ValueError,UnicodeError):raise APIError('response_format') from None
        if not isinstance(result,dict):raise APIError('schema')
        return result
    finally:
        conn.close()
        if raw:raw.close()


def configuration(data_dir):
    try:
        value=json.loads((data_dir/'program-api-connections.json').read_text())
        return value if isinstance(value,dict) else {}
    except (OSError,ValueError):return {}


def credentials(data_dir, provider):
    config=configuration(data_dir)
    if provider in config:
        entry=config[provider]
        return entry if isinstance(entry,dict) and entry.get('enabled') is True and entry.get('token') else None
    # A separately disabled research connection never falls back to reporting.
    return reporting.load(data_dir) if provider=='hackerone' else None


def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest() if value else ''


def save(data_dir, provider, entry):
    if provider not in HOSTS:raise ValueError('Unsupported program provider')
    config=configuration(data_dir);config[provider]=entry
    fd,temporary=tempfile.mkstemp(prefix='.program-api-',dir=data_dir)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600);json.dump(config,f);f.flush();os.fsync(f.fileno())
        os.replace(temporary,data_dir/'program-api-connections.json')
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def connect(data_dir,data):
    provider=data.get('provider');token=data.get('token');username=data.get('username','')
    if provider not in HOSTS or data.get('authorize_read') is not True:raise ValueError('Allow reading program rules for the selected account.')
    if not isinstance(token,str) or not 10<=len(token)<=2000 or not token.isascii() or any(x.isspace() for x in token):raise ValueError('Enter a valid private API token.')
    if provider=='hackerone' and (not isinstance(username,str) or not 1<=len(username)<=150 or not username.isascii() or ':' in username or any(x.isspace() for x in username)):
        raise ValueError('Enter your HackerOne API token identifier.')
    entry={'username':username if provider=='hackerone' else '', 'token':token,'enabled':True,'verified_at':int(time.time())}
    route=PREFIXES[provider]+('?page%5Bsize%5D=1' if provider=='hackerone' else '?limit=1&offset=0')
    try:
        result=request(provider,entry,route)
        if not isinstance(result.get('data' if provider=='hackerone' else 'records'),list):raise ValueError()
    except Exception:raise ValueError('Program API access could not be verified. No connection was saved.') from None
    save(data_dir,provider,entry)


def status(data_dir):
    config=configuration(data_dir)
    return {p:{'connected':credentials(data_dir,p) is not None,
               'uses_existing_connection':p=='hackerone' and p not in config and reporting.load(data_dir) is not None,
               'read_only':True} for p in HOSTS}
