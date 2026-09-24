"""Bounded cross-function Python input-flow review. Never executes project code."""
import ast
import base64
import hashlib
import io
import json
from pathlib import PurePosixPath
import stat
import time
import zipfile

VERSION = 'project-flow-1'
MAX_TOTAL = 2000000
MAX_FILE = 128000
MAX_FILES = 80
LIMITATION = ('Static review of Python only: follows direct calls to project functions, arguments and returns, '
               'up to six call levels. Branches are conservatively combined. Dynamic dispatch, class methods, '
               'framework routing, sanitizers and runtime exploitability are not resolved. '
               'These are hypotheses, not confirmed bugs or bounty-eligible reports.')
SKIP = {'.git', '.venv', 'venv', 'node_modules', '__pycache__'}


def archive(encoded):
    if not isinstance(encoded, str) or len(encoded) > 2800000:
        raise ValueError('Choose a ZIP up to 2 MB.')
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > MAX_TOTAL: raise ValueError()
        z = zipfile.ZipFile(io.BytesIO(raw))
    except (ValueError, zipfile.BadZipFile):
        raise ValueError('Choose a valid ZIP up to 2 MB.') from None
    files = {}; skipped = 0; total = 0
    with z:
        entries = z.infolist()
        if len(entries) > 500: raise ValueError('ZIP has more than 500 entries.')
        for item in entries:
            p = PurePosixPath(item.filename)
            if (p.is_absolute() or '..' in p.parts or '\\' in item.filename or
                    any(ord(c) < 32 for c in item.filename) or len(item.filename) > 240 or
                    stat.S_ISLNK(item.external_attr >> 16) or item.flag_bits & 1):
                raise ValueError('ZIP contains an unsafe path, symbolic link or encrypted file.')
            if item.is_dir(): continue
            if p.suffix != '.py' or any(v in SKIP for v in p.parts):
                skipped += 1; continue
            if item.filename in files: raise ValueError('ZIP has duplicate Python paths.')
            total += item.file_size
            if item.file_size > MAX_FILE or total > MAX_TOTAL or len(files) >= MAX_FILES:
                raise ValueError('Use at most 80 Python files, 128 KB each and 2 MB total expanded size.')
            try:
                with z.open(item) as f: content = f.read(MAX_FILE + 1)
                if len(content) > MAX_FILE: raise ValueError()
                files[item.filename] = content.decode('utf-8-sig')
            except (UnicodeError, ValueError, RuntimeError, zipfile.BadZipFile):
                raise ValueError('Python files must be valid UTF-8 and within the size limits.') from None
    if not files: raise ValueError('No Python files found. Ruby and JavaScript are not supported by this analyzer.')
    return files, skipped


def analyze(files):
    modules = {}; functions = {}; aliases = {}; skipped = []; total_nodes = 0
    if not files or len(files) > MAX_FILES or sum(len(v.encode()) for v in files.values()) > MAX_TOTAL:
        raise ValueError('Project exceeds analysis limits.')
    def fullname(node):
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute): return fullname(node.value) + '.' + node.attr
        return ''
    for path, source in sorted(files.items()):
        try:
            tree = ast.parse(source)
            nodes = list(ast.walk(tree)); total_nodes += len(nodes)
            if total_nodes > 120000: raise ValueError('Project is too complex for bounded analysis.')
        except (SyntaxError, RecursionError, MemoryError):
            skipped.append(path); continue
        module = path[:-3].replace('/', '.')
        if module.endswith('.__init__'): module = module[:-9]
        modules[path] = module; aliases[path] = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for a in node.names: aliases[path][a.asname or a.name.split('.')[0]] = a.name if a.asname else a.name.split('.')[0]
            if isinstance(node, ast.ImportFrom) and node.module:
                base = node.module
                if node.level:
                    parts = module.split('.') if path.endswith('/__init__.py') else module.split('.')[:-1]
                    base = '.'.join(parts[:len(parts)-node.level+1] + [node.module])
                for a in node.names: aliases[path][a.asname or a.name] = base + '.' + a.name
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[module + '.' + node.name] = (path, node)
    findings = {}; budget = [0]; stopped = [False]
    def location(path, node, role): return {'file': path, 'line': node.lineno, 'role': role}
    def merge(*paths):
        out = []
        for path in paths:
            for step in path:
                if step not in out: out.append(step)
        return out[:30]
    def resolved(path, node):
        name = fullname(node); head, _, tail = name.partition('.')
        return aliases[path].get(head, head) + ('.' + tail if tail else '')
    def evaluate(key, args, stack):
        if key in stack or len(stack) >= 6:
            stopped[0] = True; return []
        path, fn = functions[key]
        names = [a.arg for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs]
        env = {name: args.get(name, []) for name in names}
        returns = []
        def expr(node):
            if node is None: return []
            budget[0] += 1
            if budget[0] > 60000:
                stopped[0] = True; return []
            if isinstance(node, ast.Name): return env.get(node.id, [])
            if isinstance(node, ast.Call):
                call = resolved(path, node.func)
                if call in ('input', 'builtins.input', 'flask.request.get_json', 'request.get_json') or any(call.startswith(p+'.') for p in ('request.args','request.form','request.values','request.json','flask.request.args','flask.request.form','flask.request.json')):
                    return [location(path, node, 'External input')]
                values = [expr(a) for a in node.args]
                keywords = {k.arg: expr(k.value) for k in node.keywords if k.arg}
                sink = None
                if call in ('eval','exec','builtins.eval','builtins.exec'): sink = 'Untrusted input reaches code execution'
                elif call in ('os.system','os.popen') or (call.startswith('subprocess.') and any(k.arg == 'shell' and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)):
                    sink = 'Untrusted input reaches a shell command'
                elif call.endswith(('.execute','.executemany','.executescript')): sink = 'Untrusted input reaches SQL text'
                elif call in ('pickle.loads','pickle.load','_pickle.loads','_pickle.load'): sink = 'Untrusted input reaches object deserialization'
                flow = values[0] if values else keywords.get('source', keywords.get('command', keywords.get('sql', [])))
                if sink and flow:
                    trace = merge(flow, [location(path,node,'Sensitive operation')])
                    fingerprint = hashlib.sha256(json.dumps([path,node.lineno,sink,trace],sort_keys=True).encode()).hexdigest()[:20]
                    findings[fingerprint] = {'id':fingerprint,'title':sink,'file':path,'line':node.lineno,'trace':trace,
                        'priority':'Review first','confirmed':False,'submission_ready':False,
                        'next_step':'Verify that this path is reachable, check validation and authorization, then reproduce with synthetic data in an isolated copy.'}
                candidate = modules[path] + '.' + call if call not in functions else call
                if candidate not in functions:
                    sibling = modules[path].rsplit('.',1)[0] + '.' + call if '.' in modules[path] else call
                    if sibling in functions: candidate = sibling
                if candidate in functions:
                    _, target = functions[candidate]
                    params = target.args.posonlyargs + target.args.args
                    bound = {p.arg: merge(v,[location(path,node,'Call to project function')]) if v else [] for p,v in zip(params,values)}
                    bound.update({k:merge(v,[location(path,node,'Call to project function')]) if v else [] for k,v in keywords.items()})
                    return evaluate(candidate,bound,stack+(key,))
                return merge(*values,*keywords.values())
            name = resolved(path,node)
            if any(name == p or name.startswith(p + '.') for p in ('request.args','request.form','request.values','request.json','request.data','flask.request.args','flask.request.form','flask.request.json','sys.argv')):
                return [location(path,node,'External input')]
            return merge(*(expr(c) for c in ast.iter_child_nodes(node)))
        def block(body):
            for node in body:
                if budget[0] > 60000: stopped[0] = True; return
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)): continue
                if isinstance(node,(ast.Assign,ast.AnnAssign)):
                    flow = expr(node.value)
                    for target in node.targets if isinstance(node,ast.Assign) else [node.target]:
                        if isinstance(target,ast.Name): env[target.id] = merge(flow,[location(path,node,'Assignment')]) if flow else []
                elif isinstance(node,ast.Return):
                    flow = expr(node.value)
                    if flow: returns.extend(merge(flow,[location(path,node,'Return from project function')]))
                elif isinstance(node,(ast.If,ast.For,ast.While,ast.Try,ast.With,ast.AsyncWith)):
                    before = dict(env); branches = []
                    if hasattr(node,'test'): expr(node.test)
                    for sub in [getattr(node,'body',[]),getattr(node,'orelse',[]),getattr(node,'finalbody',[])] + [h.body for h in getattr(node,'handlers',[])]:
                        env.clear();env.update(before);block(sub);branches.append(dict(env))
                    env.clear();env.update(before)
                    for branch in branches:
                        for name,value in branch.items():env[name] = merge(env.get(name,[]),value)
                else: expr(node)
        block(fn.body)
        return merge(returns)
    for key in functions:
        if budget[0] > 60000: break
        evaluate(key,{},())
    items = sorted(findings.values(),key=lambda f:(-len({t['file'] for t in f['trace']}),f['file'],f['line']))
    return {'engine':VERSION,'files_analyzed':len(modules),'functions_analyzed':len(functions),'syntax_skipped':skipped,
            'bounded_or_truncated':stopped[0] or len(items)>100,'findings':items[:100],'total_findings':len(items),
            'confirmed_bugs':0,'submission_ready':False,'limitation':LIMITATION}


def init(c):
    c.execute('CREATE TABLE IF NOT EXISTS project_audits (name TEXT PRIMARY KEY,digest TEXT,checked INTEGER,result TEXT)')


def record(c,name,files,skipped=0):
    digest = hashlib.sha256((VERSION+json.dumps(files,sort_keys=True)).encode()).hexdigest()
    old = c.execute('SELECT digest FROM project_audits WHERE name=?',(name,)).fetchone()
    if old and old[0] == digest: return False
    result = analyze(files);result['non_python_or_excluded_files'] = skipped
    c.execute('INSERT INTO project_audits VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET digest=excluded.digest,checked=excluded.checked,result=excluded.result',
              (name,digest,int(time.time()),json.dumps(result)))
    return True


def upload(c,data):
    if data.get('owned') is not True: raise ValueError('Confirm you own this code or have permission to review it.')
    name = data.get('name','')
    if not isinstance(name,str) or not 1 <= len(name) <= 100 or any(ord(x)<32 or x in '/\\' for x in name):
        raise ValueError('Use a short project name without slashes.')
    name = 'Uploaded/'+name
    if c.execute('SELECT COUNT(*) FROM project_audits').fetchone()[0] >= 11 and not c.execute('SELECT 1 FROM project_audits WHERE name=?',(name,)).fetchone():
        raise ValueError('Maximum 10 uploaded projects. Replace an existing project to review changes.')
    files,skipped = archive(data.get('archive'))
    record(c,name,files,skipped)


def snapshot(c):
    return [{'name':r['name'],'digest':r['digest'],'checked':r['checked'],'result':json.loads(r['result'])}
            for r in c.execute('SELECT * FROM project_audits ORDER BY checked DESC,name')]
