"""Conservative, exact-URL HTTPS observation engine. No crawling or exploitation."""
import hashlib
import http.client
import ipaddress
import socket
import ssl
import time
from urllib.parse import urlsplit


def validate_url(url):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in url):
        raise ValueError('Use an ASCII HTTPS URL without spaces.')
    p = urlsplit(url)
    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.fragment or p.query or p.port not in (None, 443):
        raise ValueError('Only HTTPS port 443, without credentials, queries or fragments is supported.')
    if '%' in p.netloc or '\\' in url or '*' in url:
        raise ValueError('Wildcards, encoded hosts and backslashes are not allowed.')
    return p


def public_addresses(host):
    addresses = sorted({x[4][0] for x in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError('Private, reserved, local and mixed public/private DNS targets are blocked.')
    return addresses


def observe(url, origin=None):
    p = validate_url(url)
    addresses = public_addresses(p.hostname)
    # Connect to the validated IP directly: no second DNS lookup / rebinding window.
    raw = socket.create_connection((addresses[0], 443), timeout=12)
    conn = http.client.HTTPSConnection(p.hostname, timeout=12)
    try:
        conn.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=p.hostname)
        cert = conn.sock.getpeercert()
        headers = {'User-Agent': 'ScopeGuard/1.0 authorized-security-observation', 'Accept': '*/*', 'Connection': 'close'}
        if origin:
            headers['Origin'] = origin
        # No GET bodies, credentials, redirects, links, or response-body collection.
        conn.request('HEAD', p.path or '/', headers=headers)
        response = conn.getresponse()
        pairs = response.getheaders()
        # Store only security-relevant headers, never cookie values or redirects.
        names = {'strict-transport-security', 'content-security-policy', 'x-frame-options',
                 'x-content-type-options', 'access-control-allow-origin', 'access-control-allow-credentials'}
        selected = {k.lower(): v[:2000] for k, v in pairs if k.lower() in names}
        cookies = []
        for key, value in pairs:
            if key.lower() == 'set-cookie':
                pieces = value.split(';')
                cookies.append({'name_hash': hashlib.sha256(pieces[0].split('=')[0].encode()).hexdigest()[:12],
                                'attributes': [x.strip().split('=')[0].lower() for x in pieces[1:]]})
        return {'status': response.status, 'headers': selected, 'cookies': cookies,
                'certificate_expires': cert.get('notAfter'), 'checked_at': int(time.time())}
    finally:
        conn.close()
        raw.close()


def findings(observation, cors=None):
    if observation['status'] < 200 or observation['status'] >= 300:
        return []
    h = observation['headers']
    results = []
    def add(rule, title, evidence):
        results.append({'rule': rule, 'title': title, 'severity': 'Informational',
                        'evidence': evidence, 'impact': 'Not demonstrated. Requires manual validation and program eligibility review.'})
    for header in ('strict-transport-security', 'content-security-policy', 'x-content-type-options'):
        if header not in h:
            add(header, 'Review missing ' + header, 'Header absent on this HEAD response; GET behavior may differ.')
    if 'x-frame-options' not in h and 'frame-ancestors' not in h.get('content-security-policy', '').lower():
        add('framing', 'Review framing protection', 'No frame protection observed. Clickjacking impact has not been tested.')
    for cookie in observation['cookies']:
        missing = sorted({'secure', 'httponly', 'samesite'} - set(cookie['attributes']))
        if missing:
            add('cookie-' + cookie['name_hash'], 'Review cookie attributes', 'Cookie identifier hash ' + cookie['name_hash'] + '; absent: ' + ', '.join(missing) + '. Cookie purpose unknown.')
    if cors and 200 <= cors['status'] < 300:
        ch = cors['headers']
        if ch.get('access-control-allow-origin') == 'https://scopeguard.invalid' and ch.get('access-control-allow-credentials', '').lower() == 'true':
            add('cors-reflection', 'Review credentialed CORS origin reflection', 'HEAD accepts the test Origin with Allow-Credentials true. No authenticated data access or exploitability has been tested.')
    return results
