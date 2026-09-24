"""Verify this repository's GitHub workload identity with system OpenSSL.

Signing certificates come only from GitHub's fixed HTTPS JWKS endpoint, not JWT
headers. No shared application password or long-lived CI secret is required.
"""
import base64
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ISSUER = 'https://token.actions.githubusercontent.com'
AUDIENCE = 'scopeguard-private-code-review'
REPOSITORY = 'parthagravat500-pixel/coindcx-dashboard'
BRANCH = 'refs/heads/scopeguard-app'
WORKFLOW = REPOSITORY + '/.github/workflows/scopeguard-ai.yml@' + BRANCH
SUBJECT = 'repo:parthagravat500-pixel@319591622/coindcx-dashboard@1350819047:ref:' + BRANCH


def decode64(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('Invalid identity encoding')
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate identity claim')
        result[key] = value
    return result


def verify_signature(message, signature, certificate):
    if not shutil.which('openssl'):
        raise ValueError('Identity verifier unavailable')
    if not isinstance(certificate, str) or not 100 <= len(certificate) <= 12000:
        raise ValueError('Invalid signing certificate')
    der = base64.b64decode(certificate, validate=True)
    with tempfile.TemporaryDirectory(prefix='scopeguard-identity-') as tmp:
        root = Path(tmp)
        (root/'cert.der').write_bytes(der)
        public = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-in', str(root/'cert.der'), '-pubkey', '-noout'],
                                capture_output=True, timeout=3, check=True).stdout
        (root/'public.pem').write_bytes(public)
        (root/'signature').write_bytes(signature)
        verified = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(root/'public.pem'), '-signature', str(root/'signature')],
                                  input=message, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        if verified.returncode:
            raise ValueError('Invalid identity signature')


def verify_token(token, jwks, now=None):
    now = int(time.time()) if now is None else now
    if not isinstance(token, str) or len(token) > 16000 or token.count('.') != 2:
        raise ValueError('Invalid workload identity')
    header64, claims64, signature64 = token.split('.')
    header = json.loads(decode64(header64), object_pairs_hook=strict_object)
    claims = json.loads(decode64(claims64), object_pairs_hook=strict_object)
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError('Invalid workload identity')
    if header.get('alg') != 'RS256' or header.get('typ') != 'JWT' or any(k in header for k in ('jku', 'jwk', 'x5u', 'crit', 'b64')):
        raise ValueError('Unsupported identity header')
    kid = header.get('kid')
    if not isinstance(kid, str) or not 1 <= len(kid) <= 128:
        raise ValueError('Invalid signing key')
    keys = [k for k in jwks.get('keys', []) if k.get('kid') == kid and k.get('kty') == 'RSA' and k.get('use') == 'sig' and k.get('alg', 'RS256') == 'RS256']
    if len(keys) != 1 or not keys[0].get('x5c'):
        raise ValueError('Signing key is not available')
    verify_signature((header64+'.'+claims64).encode('ascii'), decode64(signature64), keys[0]['x5c'][0])
    expected = {'iss': ISSUER, 'aud': AUDIENCE, 'repository': REPOSITORY,
                'repository_id': '1350819047', 'repository_owner_id': '319591622',
                'ref': BRANCH, 'sub': SUBJECT,
                'workflow_ref': WORKFLOW, 'event_name': 'push', 'runner_environment': 'github-hosted'}
    if any(claims.get(k) != v for k, v in expected.items()):
        raise ValueError('This workflow is not authorized')
    for key in ('iat', 'nbf', 'exp'):
        if type(claims.get(key)) is not int:
            raise ValueError('Invalid identity lifetime')
    if not now-600 <= claims['iat'] <= now+30 or claims['nbf'] > now+30 or claims['exp'] <= now or not 0 < claims['exp']-claims['iat'] <= 600:
        raise ValueError('Expired or invalid identity lifetime')
    if not re.fullmatch('[0-9a-f]{40}', str(claims.get('sha', ''))) or claims.get('workflow_sha') != claims['sha']:
        raise ValueError('Invalid source revision')
    for key in ('run_id', 'run_attempt'):
        if not re.fullmatch('[1-9][0-9]{0,19}', str(claims.get(key, ''))):
            raise ValueError('Invalid run identity')
    return claims
