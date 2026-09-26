"""Opt-in Uber profile OAuth. No scanner, browser-session import or persistent tokens."""
import hashlib
import hmac
import http.client
import json
import os
import secrets
import threading
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlencode, urlsplit

CALLBACK_PATH = '/api/uber/callback'
COOKIE = '__Host-scopeguard_uber'
FLOW_SECONDS = 600
MAX_BODY = 65536
DOCS = 'https://developer.uber.com/docs/consumer-identity/references/api/v3/me-get'
ENDPOINTS = {
    'exchange': ('auth.uber.com', '/oauth/v2/token', 'POST'),
    'profile': ('api.uber.com', '/v3/me', 'GET'),
    'revoke': ('auth.uber.com', '/oauth/v2/revoke', 'POST'),
}


def config():
    """Only deployment configuration can enable OAuth, never a policy record."""
    values = {key: os.environ.get('UBER_' + key.upper(), '')
              for key in ('client_id', 'client_secret', 'redirect_uri')}
    missing = []
    if os.environ.get('UBER_PROFILE_API_APPROVED') != 'true':
        missing.append('Uber approval for the profile API')
    if not 6 <= len(values['client_id']) <= 256 or not all(
            c.isascii() and (c.isalnum() or c in '._-') for c in values['client_id']):
        missing.append('Registered Uber application ID')
    if not 16 <= len(values['client_secret']) <= 4096 or not all(
            33 <= ord(c) <= 126 for c in values['client_secret']):
        missing.append('Private Uber application secret in server configuration')
    try:
        uri = urlsplit(values['redirect_uri'])
        valid_uri = (uri.scheme == 'https' and uri.hostname and '.' in uri.hostname
                     and uri.port in (None, 443) and not uri.username and not uri.password
                     and uri.path == CALLBACK_PATH and not uri.query and not uri.fragment
                     and all(33 <= ord(c) <= 126 for c in values['redirect_uri'])
                     and '\\' not in values['redirect_uri'])
    except ValueError:
        valid_uri = False
    if not valid_uri:
        missing.append('Exact HTTPS callback registered with Uber')
    return values, missing


def fingerprint(values):
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def safe_token(value):
    return isinstance(value, str) and 1 <= len(value) <= 16384 and all(
        33 <= ord(c) <= 126 for c in value)


def request(kind, values, code=None, token=None):
    """Fixed HTTPS destinations, TLS verification, one request, no redirects/retries."""
    host, path, method = ENDPOINTS[kind]
    headers = {'Accept': 'application/json', 'User-Agent': 'ScopeGuard/1.0 (account connection)'}
    body = None
    if kind == 'profile':
        headers['Authorization'] = 'Bearer ' + token
    else:
        data = {'client_id': values['client_id'], 'client_secret': values['client_secret']}
        if kind == 'exchange':
            data.update(grant_type='authorization_code', code=code, redirect_uri=values['redirect_uri'])
        else:
            data['token'] = token
        body = urlencode(data).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    conn = http.client.HTTPSConnection(host, 443, timeout=12)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read(MAX_BODY + 1)
        if response.status != 200 or len(raw) > MAX_BODY:
            raise ValueError('Uber did not accept the connection request. No automatic retry was made.')
        if kind == 'revoke':
            return {}
        if response.getheader('Content-Type', '').split(';')[0].strip().lower() != 'application/json':
            raise ValueError('Uber returned an unexpected response. The connection was stopped.')
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError('Unexpected response')
        return result
    except Exception:
        # Neither provider bodies nor request URLs, codes, tokens or secrets enter logs/state.
        raise ValueError('Uber connection could not be verified. No automatic retry was made.') from None
    finally:
        conn.close()


class UberConnection:
    def __init__(self, transport=None, clock=None):
        self.transport = transport or request
        self.clock = clock or time.time
        self.lock = threading.RLock()
        self.pending = None
        self.generation = 0
        self.token = None
        self.token_config = None
        self.expires = 0
        self.verified = 0
        self.last_status = 'disconnected'
        self.last_message = 'Not connected to Uber.'
        self.revocation_unconfirmed = False

    def status(self):
        with self.lock:
            values, missing = config()
            if self.pending and self.pending['expires'] <= self.clock():
                self.pending = None
                self.generation += 1
                self.last_status = 'expired'
                self.last_message = 'The sign-in attempt expired. No connection was created.'
            connected = bool(not missing and self.token and self.expires > self.clock()
                             and values == self.token_config)
            if missing:
                status, message = 'not_configured', 'Waiting for an approved Uber developer app and server setup.'
            elif self.token and values != self.token_config:
                status, message = 'not_configured', 'Server settings changed. Disconnect the old connection first.'
            elif self.token and self.expires <= self.clock():
                status, message = 'expired', 'Uber access expired. Disconnect before authorizing again.'
            else:
                status, message = self.last_status, self.last_message
            return {'status': status, 'message': message, 'connected': connected,
                    'configured': not missing, 'missing': missing,
                    'can_connect': not missing and not self.token and status not in ('awaiting_uber', 'connecting'),
                    'can_disconnect': bool(self.token or self.pending or status == 'connecting'),
                    'verified_at': self.verified if connected else 0,
                    'expires_at': self.expires if connected else 0,
                    'revocation_unconfirmed': self.revocation_unconfirmed,
                    'scope': 'profile', 'tests_enabled': False, 'authorizes_testing': False,
                    'storage': 'Memory only; restart or expiry requires reconnecting. Uber may retain the app grant.',
                    'documentation_url': DOCS}

    def begin(self, consent):
        with self.lock:
            current = self.status()
            if consent is not True:
                raise ValueError('Account-owner consent is required for a read-only profile connection.')
            if not current['can_connect']:
                raise ValueError('Uber connection is not ready. Review the connection status first.')
            values, _ = config()
            state, binding = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.generation += 1
            self.pending = {'state': digest(state), 'binding': digest(binding),
                            'expires': self.clock() + FLOW_SECONDS,
                            'config': fingerprint(values), 'generation': self.generation}
            self.last_status = 'awaiting_uber'
            self.last_message = 'Waiting for the account owner to authorize the approved app on Uber.'
            params = {'client_id': values['client_id'], 'response_type': 'code',
                      'redirect_uri': values['redirect_uri'], 'scope': 'profile', 'state': state}
            return 'https://auth.uber.com/oauth/v2/authorize?' + urlencode(params), binding

    def _current(self, generation, values):
        current, missing = config()
        return self.generation == generation and not missing and current == values

    def _revoke(self, token, values):
        try:
            self.transport('revoke', values, token=token)
            return True
        except Exception:
            return False

    def complete(self, query, cookie_header):
        try:
            if len(query) > 8192 or len(cookie_header) > 16384:
                raise ValueError()
            params = parse_qs(query, keep_blank_values=True, max_num_fields=8)
            if len(params.get('state', [])) != 1 or any(len(v) != 1 for v in params.values()):
                raise ValueError()
            jar = SimpleCookie()
            jar.load(cookie_header)
            binding = jar[COOKIE].value if COOKIE in jar else ''
            state = params['state'][0]
            if not binding or not state:
                raise ValueError()
        except Exception:
            raise ValueError('The Uber return could not be verified. Start from the dashboard.') from None
        with self.lock:
            self.status()
            pending = self.pending
            values, missing = config()
            if (not pending or missing or pending['config'] != fingerprint(values)
                    or not hmac.compare_digest(pending['state'], digest(state))
                    or not hmac.compare_digest(pending['binding'], digest(binding))):
                raise ValueError('The Uber return could not be verified. Start from the dashboard.')
            # Consume the state before any exchange. The code cannot be replayed or retried.
            self.pending = None
            generation = pending['generation']
            self.last_status = 'connecting'
            self.last_message = 'Verifying the approved read-only profile connection.'
        token = None
        try:
            code = params.get('code', [''])[0]
            if 'error' in params or not safe_token(code) or len(code) > 4096:
                raise ValueError('Uber authorization was not completed.')
            with self.lock:
                if not self._current(generation, values):
                    raise ValueError('The connection attempt was cancelled.')
            response = self.transport('exchange', values, code=code)
            issued_at = int(self.clock())
            candidate = response.get('access_token')
            token = candidate if safe_token(candidate) else None
            expires = response.get('expires_in')
            if (not token or str(response.get('token_type', '')).lower() != 'bearer'
                    or response.get('scope', '').split() != ['profile']
                    or type(expires) is not int or not 1 <= expires <= 366 * 86400):
                raise ValueError('Uber returned an unexpected token or permission scope.')
            with self.lock:
                if not self._current(generation, values):
                    raise ValueError('The connection attempt was cancelled.')
            profile = self.transport('profile', values, token=token)
            if not isinstance(profile.get('sub'), str) or not 1 <= len(profile['sub']) <= 4096:
                raise ValueError('Uber profile access was not verified.')
            with self.lock:
                if not self._current(generation, values) or issued_at + expires <= self.clock():
                    raise ValueError('The connection attempt was cancelled.')
                self.token, self.token_config = token, values
                self.verified = int(self.clock())
                self.expires = issued_at + expires
                self.last_status = 'connected'
                self.last_message = 'Read-only profile access verified. Uber security testing has not been enabled.'
                self.revocation_unconfirmed = False
                # The profile, name, email and phone number are deliberately discarded.
        except Exception:
            revoked = self._revoke(token, values) if token else True
            with self.lock:
                self.revocation_unconfirmed |= not revoked
                if self.generation == generation:
                    self.last_status = 'failed'
                    self.last_message = 'Uber did not complete the connection. No automatic retry was made.'
            raise ValueError('Uber connection was not completed. Return to the dashboard for its status.') from None

    def disconnect(self):
        with self.lock:
            token, values = self.token, self.token_config
            self.generation += 1
            self.pending = None
            self.token = self.token_config = None
            self.expires = self.verified = 0
            self.last_status = 'disconnected'
            self.last_message = 'Disconnected locally. No Uber tests were enabled.'
        if token:
            revoked = self._revoke(token, values)
            with self.lock:
                self.revocation_unconfirmed |= not revoked


manager = UberConnection()


def cookie(value='', clear=False):
    return (COOKIE + '=' + value + '; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='
            + ('0' if clear else str(FLOW_SECONDS)))
