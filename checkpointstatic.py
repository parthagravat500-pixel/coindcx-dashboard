"""Additional offline Python patterns; inspected code is never executed."""
import ast
import hashlib
import json

IDS = ('SG-0795', 'SG-0796', 'SG-0797', 'SG-0798')


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
    for node in nodes:
        key = None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(isinstance(v, (ast.List, ast.Dict, ast.Set)) for v in node.args.defaults + node.args.kw_defaults):
                key = 'SG-0795'
        if isinstance(node, ast.Call):
            call = name(node.func)
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
