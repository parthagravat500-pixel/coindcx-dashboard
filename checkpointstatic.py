"""Additional offline Python patterns; inspected code is never executed."""
import ast
import hashlib
import json

IDS = ('SG-0795', 'SG-0796', 'SG-0797', 'SG-0798')
IDS += ('SG-0241', 'SG-0243', 'SG-0245', 'SG-0246', 'SG-0247',
        'SG-0316', 'SG-0441', 'SG-0602', 'SG-0623', 'SG-0625')
LIMITS = {
    'SG-0241': 'Literal PyJWT verify_signature=False only; token trust and reachability are unverified.',
    'SG-0243': 'Literal none in a PyJWT decode algorithm list only; a token was not supplied or accepted.',
    'SG-0245': 'Literal PyJWT verify_iss=False only; intended issuer requirements are unknown.',
    'SG-0246': 'Literal PyJWT verify_aud=False only; intended audience requirements are unknown.',
    'SG-0247': 'Literal PyJWT verify_exp=False only; token lifetime and impact are unknown.',
    'SG-0316': 'Explicit Jinja Environment/Template autoescape=False only; text templates may intentionally disable escaping.',
    'SG-0441': 'Explicit lxml XMLParser resolve_entities=True only; external access and trusted-input context are unverified.',
    'SG-0602': 'Assignments of check_hostname=False only; receiver type and later re-enabling are unverified.',
    'SG-0623': 'Explicit ECB mode selection in supported Python crypto calls only; surrounding authentication is unverified.',
    'SG-0625': 'Explicit hashlib MD5/SHA-1 calls only; non-security checksums may be legitimate.',
}


def fingerprint(root, filenames):
    records = []
    for filename in filenames:
        try:
            path = root / filename
            if path.stat().st_size <= 128000:
                records.append((filename, hashlib.sha256(path.read_bytes()).hexdigest()))
        except OSError:
            pass
    return hashlib.sha256(json.dumps(records).encode()).hexdigest()


def analyze(source):
    if not isinstance(source, str) or len(source.encode()) > 128000:
        raise ValueError('Source exceeds the supported size')
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    if len(nodes) > 40000:
        raise ValueError('Source exceeds the supported complexity')
    aliases = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split('.')[0]] = a.name if a.asname else a.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                aliases[a.asname or a.name] = node.module + '.' + a.name
    def name(node):
        if isinstance(node, ast.Name): return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute): return name(node.value) + '.' + node.attr
        return ''
    signals = {key: [] for key in IDS}
    def literal(node, value):
        return isinstance(node, ast.Constant) and type(node.value) is type(value) and node.value == value
    for node in nodes:
        key = None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(isinstance(v, (ast.List, ast.Dict, ast.Set)) for v in node.args.defaults + node.args.kw_defaults):
                key = 'SG-0795'
        if isinstance(node, ast.Call):
            call = name(node.func)
            kw = {k.arg:k.value for k in node.keywords}
            hits = set()
            if call == 'jwt.decode':
                options = kw.get('options')
                if isinstance(options, ast.Dict):
                    # Last literal key wins, matching Python dictionary semantics.
                    opts = {k.value:v for k,v in zip(options.keys,options.values) if isinstance(k,ast.Constant) and isinstance(k.value,str)}
                    for flag, identity in (('verify_signature','SG-0241'),('verify_iss','SG-0245'),
                                           ('verify_aud','SG-0246'),('verify_exp','SG-0247')):
                        if literal(opts.get(flag),False):hits.add(identity)
                algorithms=kw.get('algorithms')
                if isinstance(algorithms,(ast.List,ast.Tuple)) and any(literal(v,'none') for v in algorithms.elts):
                    hits.add('SG-0243')
            if call in ('jinja2.Environment','jinja2.Template') and literal(kw.get('autoescape'),False):
                hits.add('SG-0316')
            if call=='lxml.etree.XMLParser' and literal(kw.get('resolve_entities'),True):
                hits.add('SG-0441')
            if call in ('hashlib.md5','hashlib.sha1') or (call=='hashlib.new' and node.args and
                    isinstance(node.args[0],ast.Constant) and str(node.args[0].value).lower() in ('md5','sha1')):
                hits.add('SG-0625')
            if call in ('Crypto.Cipher.AES.new','Cryptodome.Cipher.AES.new'):
                mode=kw.get('mode') or (node.args[1] if len(node.args)>1 else None)
                if name(mode) in ('Crypto.Cipher.AES.MODE_ECB','Cryptodome.Cipher.AES.MODE_ECB'):
                    hits.add('SG-0623')
            if call=='cryptography.hazmat.primitives.ciphers.modes.ECB':hits.add('SG-0623')
            for identity in hits:signals[identity].append(node.lineno)
            if call in ('__import__', 'builtins.__import__', 'importlib.import_module'):
                if not node.args or not isinstance(node.args[0], ast.Constant): key = 'SG-0796'
            elif call == 'tempfile.mktemp': key = 'SG-0797'
            elif call in ('os.chmod', 'os.fchmod') or call.endswith('.chmod'):
                arg = next((k.value for k in node.keywords if k.arg == 'mode'), None)
                if arg is None and node.args:
                    arg = node.args[1] if call in ('os.chmod', 'os.fchmod') and len(node.args) > 1 else node.args[0]
                if isinstance(arg, ast.Constant) and type(arg.value) is int and arg.value & 0o002:
                    key = 'SG-0798'
        if key: signals[key].append(node.lineno)
        if isinstance(node,(ast.Assign,ast.AnnAssign)) and literal(node.value,False):
            targets=node.targets if isinstance(node,ast.Assign) else [node.target]
            if any(isinstance(t,ast.Attribute) and t.attr=='check_hostname' for t in targets):
                signals['SG-0602'].append(node.lineno)
    return signals


def inspect(root, filenames):
    records = []; results = {key: 0 for key in IDS}; skipped = 0; analyzed = 0
    for filename in filenames:
        path = root / filename
        try:
            if path.stat().st_size > 128000: raise ValueError('Too large')
            data = path.read_bytes()
            records.append((filename, hashlib.sha256(data).hexdigest()))
            for key, lines in analyze(data.decode()).items(): results[key] += len(lines)
            analyzed += 1
        except (OSError, UnicodeError, ValueError, SyntaxError, RecursionError):
            skipped += 1
    return {'digest': hashlib.sha256(json.dumps(records).encode()).hexdigest(),
            'files': analyzed,
            'skipped': skipped, 'signals': results}
