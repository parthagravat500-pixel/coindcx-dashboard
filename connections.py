"""Private, server-side AI connection settings. Never return credentials to the UI."""
import json
import os
import tempfile
import time
import urllib.error
import urllib.request

MODEL = 'gpt-4.1-mini'
FLAGS = ('SUPERVISOR_AI_ENABLED', 'DISCOVERY_AI_ENABLED')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('AI endpoint redirected; connection was not saved')


def path(data_dir):
    return data_dir / 'ai-connection.json'


def apply(config):
    if config.get('enabled') is True:
        os.environ['OPENAI_API_KEY'] = config['key']
        os.environ['SUPERVISOR_AI_MODEL'] = MODEL
    for flag in FLAGS:
        os.environ[flag] = 'true' if config.get('enabled') is True else 'false'


def load(data_dir):
    p = path(data_dir)
    if not p.exists():
        return  # Preserve explicit deployment environment configuration.
    try:
        config = json.loads(p.read_text())
        if config.get('enabled') is True and not valid_key(config.get('key')):
            raise ValueError('Invalid connection file')
        apply(config)
    except Exception:
        for flag in FLAGS: os.environ[flag] = 'false'


def save(data_dir, config):
    fd, temporary = tempfile.mkstemp(prefix='.ai-', dir=data_dir)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(config, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path(data_dir))
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def valid_key(key):
    return isinstance(key, str) and key.startswith('sk-') and 20 <= len(key) <= 500 and not any(ch.isspace() for ch in key)


def verify_key(key):
    request = urllib.request.Request('https://api.openai.com/v1/models/' + MODEL,
                                    headers={'Authorization': 'Bearer ' + key})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
            data = json.loads(response.read(20000))
        if data.get('id') != MODEL: raise ValueError('Model unavailable')
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise ValueError('OpenAI did not accept this key or its permissions. Check the key and try again.') from None
        raise ValueError('OpenAI could not verify access. The connection was not saved.') from None
    except Exception:
        raise ValueError('Could not verify OpenAI access. The connection was not saved. Try again later.') from None


def connect(data_dir, data):
    key = data.get('key', '')
    if not valid_key(key): raise ValueError('Paste your OpenAI API key in the private key field.')
    if data.get('approve_charges') is not True:
        raise ValueError('Confirm separate API charges before enabling AI reviews.')
    verify_key(key)  # GET model metadata only; no paid generation for this check.
    config = {'enabled': True, 'key': key, 'model': MODEL, 'verified_at': int(time.time())}
    save(data_dir, config)
    apply(config)


def disconnect(data_dir):
    save(data_dir, {'enabled': False})  # Removes the saved key; stays off after restart.
    apply({'enabled': False})
    os.environ.pop('OPENAI_API_KEY', None)


def status():
    configured = bool(os.getenv('OPENAI_API_KEY')) and bool(os.getenv('SUPERVISOR_AI_MODEL'))
    return {'enabled': configured and all(os.getenv(flag) == 'true' for flag in FLAGS),
            'model': os.getenv('SUPERVISOR_AI_MODEL') if configured else MODEL,
            'daily_attempt_limit': 4,
            'description': 'Up to 3 finding reviews and 1 program review per day. API charges are separate.'}
