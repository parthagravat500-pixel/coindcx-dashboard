"""Permission-bounded browser/HTML maps. Discovered links never become targets."""
import hashlib
import http.client
import importlib.util
import json
import socket
import ssl
import time
import browserruntime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from engine import validate_url, public_addresses

MAX_BODY = 262144


def route_id(url):
    return hashlib.sha256(url.encode()).hexdigest()[:20]


class Structure(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base, self.links, self.forms, self.inputs = base, set(), [], set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ('a','script','link') and len(self.links) < 100:
            value = attrs.get('href',attrs.get('src',''))
            if value and not value.startswith(('javascript:','data:')):
                self.links.add(route_id(urljoin(self.base,value).split('#')[0]))
        if tag == 'form' and len(self.forms) < 30:
            self.forms.append({'method':attrs.get('method','GET').upper()[:12],
                               'destination':route_id(urljoin(self.base,attrs.get('action','')))})
        if tag == 'input': self.inputs.add(attrs.get('type','text')[:20])


def describe(url, body, content_type):
    """Only structural metadata persists. No text, values, URLs or account data."""
    result = {'route':route_id(url),'content_type':content_type[:80],
              'bytes':len(body),'links':[],'forms':[],'input_types':[]}
    if 'html' in content_type:
        parser = Structure(url); parser.feed(body.decode('utf-8',errors='replace'))
        result.update(links=sorted(parser.links), forms=parser.forms, input_types=sorted(parser.inputs))
    elif 'json' in content_type:
        try:
            parsed = json.loads(body)
            result['json_shape'] = type(parsed).__name__
            result['field_count'] = len(parsed) if isinstance(parsed,(dict,list)) else 0
        except (ValueError,UnicodeError): result['json_shape'] = 'invalid'
    result['fingerprint'] = hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest()
    return result


def fetch_page(url, authorization):
    p = validate_url(url)
    addresses = public_addresses(p.hostname)
    raw = socket.create_connection((addresses[0],443),timeout=10)
    conn = http.client.HTTPSConnection(p.hostname,timeout=10)
    try:
        conn.sock = ssl.create_default_context().wrap_socket(raw,server_hostname=p.hostname)
        headers = {'User-Agent':'ScopeGuard/3 authorized-owned-workflow-map',
                   'Accept':'text/html,application/json','Accept-Encoding':'identity',
                   'Cache-Control':'no-cache','Connection':'close'}
        if authorization: headers['Authorization'] = authorization
        conn.request('GET',p.path or '/',headers=headers)
        response = conn.getresponse(); body = response.read(MAX_BODY+1)
        if len(body)>MAX_BODY: raise ValueError('Page exceeds mapping limit')
        if response.getheader('Content-Encoding','identity').lower()!='identity':
            raise ValueError('Encoded page is unsupported')
        return {'status':response.status,'body':body,
                'content_type':response.getheader('Content-Type','application/octet-stream').split(';')[0].lower()}
    finally: conn.close()


def available():
    return browserruntime.status()['ready'] and importlib.util.find_spec('playwright') is not None


def map_pages(config, allowed=lambda:True, transport=fetch_page, pace=time.sleep):
    """Automatic map of exact pages with separate GET permission; no link crawl."""
    rows = []; result = {'engine':'html-structure','pages':rows,'requests':0,'blocked_requests':0,
                         'state':'complete','reason':'','browser_executed':False}
    account = next(a for a in config['accounts'] if a['id']==config['browser_account'])
    urls = config['map_urls']
    if config.get('browser') and available():
        return chromium_map(config,allowed,transport,pace)
    if config.get('browser'): result['reason']='Browser runtime unavailable; HTML structure only.'
    for url in urls[:min(6,config['request_budget'])]:
        if not allowed(): result.update(state='stopped',reason='Permission changed'); break
        if rows: pace(config['request_gap'])
        if not allowed(): result.update(state='stopped',reason='Permission changed'); break
        try:
            raw=transport(url,account['authorization']);result['requests']+=1
            if not 200<=raw['status']<300:
                result.update(state='stopped',reason='Page access requires review'); break
            rows.append({**describe(url,raw['body'],raw['content_type']),'status':raw['status']})
        except Exception:
            result.update(state='stopped',reason='Page could not be mapped'); break
    if not allowed(): result.update(state='stopped',reason='Permission changed')
    return result


def chromium_map(config, allowed, transport, pace):
    """All browser requests are fulfilled by the pinned, exact-URL GET transport.

    Native browser networking is routed to a closed local proxy. WebSockets,
    service workers, downloads, unlisted URLs and all writes are blocked. No
    credentials, DOM text, screenshots or page bodies are saved.
    """
    from playwright.sync_api import sync_playwright
    result={'engine':'chromium','pages':[],'requests':0,'blocked_requests':0,
            'state':'complete','reason':'','browser_executed':False}
    account=next(a for a in config['accounts'] if a['id']==config['browser_account'])
    urls=set(config['map_urls']); seen={}; last=[0.0]
    def handle(route):
        request=route.request; url=request.url.split('#')[0]
        if (request.method!='GET' or url not in urls or not allowed()
                or result['state']=='stopped' or result['requests']>=config['request_budget']):
            result['blocked_requests']+=1;route.abort();return
        if url in seen:
            raw=seen[url]
        else:
            gap=config['request_gap']-(time.monotonic()-last[0])
            if gap>0:pace(gap)
            if not allowed():route.abort();return
            result['requests']+=1;last[0]=time.monotonic()
            try:
                raw=transport(url,account['authorization'])
                if not 200<=raw['status']<300:
                    result.update(state='stopped',reason='Page access requires review');route.abort();return
                seen[url]=raw
                result['pages'].append({**describe(url,raw['body'],raw['content_type']),'status':raw['status']})
            except Exception:
                result.update(state='stopped',reason='Page could not be mapped');route.abort();return
        route.fulfill(status=raw['status'],body=raw['body'],headers={'content-type':raw['content_type'],
            'content-security-policy':"default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'none'; frame-src 'none'; base-uri 'none'"})
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True,args=['--disable-background-networking',
                '--proxy-server=http://127.0.0.1:9','--proxy-bypass-list=<-loopback>',
                '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'])
            try:
                context=browser.new_context(service_workers='block',accept_downloads=False)
                context.route('**/*',handle)
                context.route_web_socket('**/*',lambda ws:ws.close())
                page=context.new_page(); page.set_default_timeout(10000)
                for url in config['map_urls'][:6]:
                    if not allowed() or result['state']=='stopped':break
                    try:
                        page.goto(url,wait_until='domcontentloaded',timeout=15000)
                        features=page.evaluate('''() => ({forms:document.forms.length,
                          links:document.querySelectorAll('a[href]').length,
                          buttons:document.querySelectorAll('button').length})''')
                        for row in result['pages']:
                            if row['route']==route_id(url):row['rendered']=features
                        result['browser_executed']=True
                    except Exception:result.update(state='partial',reason='Some pages could not finish rendering')
            finally:browser.close()
    except Exception:result.update(state='unavailable',reason='Browser runtime could not start')
    if not allowed():result.update(state='stopped',reason='Permission changed')
    return result
