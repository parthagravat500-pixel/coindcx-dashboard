"""Display saved policy evidence without creating targets or granting permission."""
import json
from pathlib import Path
from urllib.parse import urlsplit

DIRECTORY = Path(__file__).parent / 'reviews'
TEXT_FIELDS = ('availability', 'review_status', 'policy_updated', 'scope_updated',
               'scope_visibility_note', 'automation', 'request_limit_note', 'accounts',
               'note', 'evidence_method', 'live_directory_membership')
LIST_FIELDS = ('in_scope_assets', 'scope_conditions', 'excluded_assets', 'exclusions', 'unresolved')


def research_plan(raw):
    """Expose preparation notes only; never import runner or credential settings."""
    if not isinstance(raw, dict):
        return None
    clean = {'selected': raw.get('selected') is True,
             'status': raw.get('status') if raw.get('status') in
                       ('prepared', 'needs_user', 'blocked', 'complete') else 'blocked',
             'authorizes_testing': False, 'automatically_runs': False}
    for key in ('updated_at', 'summary', 'goal', 'validation', 'result'):
        clean[key] = raw[key][:2000] if isinstance(raw.get(key), str) else ''
    for key in ('completed', 'user_actions', 'blockers', 'planned_checks'):
        values = raw.get(key, [])
        clean[key] = [v[:2000] for v in values[:20] if isinstance(v, str)] if isinstance(values, list) else []
    clean['connection'] = connection_plan(raw.get('connection'))
    return clean


def connection_plan(raw):
    """Display connection prerequisites; policy files cannot create a connection."""
    if not isinstance(raw, dict):
        return None
    result = {'status': raw.get('status') if raw.get('status') in
              ('provider_approval_required', 'not_configured', 'unverified') else 'unverified',
              'connected': False, 'authorizes_testing': False}
    for key in ('summary', 'manual_alternative', 'checked_at'):
        result[key] = raw[key][:2000] if isinstance(raw.get(key), str) else ''
    values = raw.get('requirements', [])
    result['requirements'] = [v[:2000] for v in values[:10] if isinstance(v, str)] if isinstance(values, list) else []
    sources = raw.get('sources', [])
    # Documentation links carry no credentials or OAuth callback parameters.
    result['sources'] = [url for url in sources[:10] if public_url(url)
                         and not urlsplit(url).query] if isinstance(sources, list) else []
    return result


def public_url(value):
    if not isinstance(value, str):
        return None
    try:
        url = urlsplit(value)
        if url.scheme == 'https' and url.hostname and not url.username and not url.password:
            return value
    except ValueError:
        pass
    return None


def record(raw):
    if not isinstance(raw, dict) or not public_url(raw.get('policy_url')):
        raise ValueError('Policy URL missing')
    if any(not isinstance(raw.get(k), str) or not raw[k].strip() for k in ('program', 'checked_at')):
        raise ValueError('Program and checked timestamp required')
    result = {k: raw[k] for k in ('program', 'policy_url', 'checked_at')}
    for key in TEXT_FIELDS:
        result[key] = raw.get(key) if isinstance(raw.get(key), str) else ''
    for key in LIST_FIELDS:
        values = raw.get(key, [])
        result[key] = [v for v in values if isinstance(v, str)] if isinstance(values, list) else []
    sources = raw.get('sources', [])
    result['sources'] = [v for v in sources if public_url(v)] if isinstance(sources, list) else []
    if not result['sources']:
        result['sources'] = [result['policy_url']]
    limit = raw.get('explicit_requests_per_second')
    result['explicit_requests_per_second'] = (limit if type(limit) in (int, float)
        and 0 <= limit <= 1e9 else None)
    result['scope_complete'] = raw.get('scope_complete') is True
    result['research_plan'] = research_plan(raw.get('research_plan'))
    # Evidence is advisory even if a file contains an authorizing flag.
    result['grants_permission'] = False
    result['targets_activated'] = 0
    return result


def snapshot():
    records = {}
    errors = 0
    for path in sorted(DIRECTORY.glob('*batch-*.json')):
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError('Evidence file too large')
            data = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(data, dict) or data.get('schema_version') != 1 or not isinstance(data.get('records'), list):
                raise ValueError('Unsupported evidence format')
        except (OSError, ValueError, UnicodeError):
            errors += 1
            continue
        for raw in data['records']:
            try:
                item = record(raw)
            except ValueError:
                errors += 1
                continue
            key = item['policy_url'].rstrip('/')
            if key not in records or item['checked_at'] > records[key]['checked_at']:
                records[key] = item
    return {'records': sorted(records.values(), key=lambda x: x['program'].casefold()),
            'unavailable_entries': errors, 'grants_permission': False}
