"""Display saved policy evidence without creating targets or granting permission."""
import json
from pathlib import Path
from urllib.parse import urlsplit

DIRECTORY = Path(__file__).parent / 'reviews'
TEXT_FIELDS = ('availability', 'review_status', 'policy_updated', 'scope_updated',
               'scope_visibility_note', 'automation', 'request_limit_note', 'accounts',
               'note', 'evidence_method', 'live_directory_membership')
LIST_FIELDS = ('in_scope_assets', 'scope_conditions', 'excluded_assets', 'exclusions', 'unresolved')


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
