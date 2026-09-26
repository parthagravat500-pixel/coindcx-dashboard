"""Bounded Python AST checks. Never imports, executes or uploads inspected code."""
import ast
import codeflow
import hashlib
import json
import time

RULES = {
 'dynamic-code': ('Dynamic code execution', 'Remove eval/exec on untrusted input; parse a constrained data format instead.'),
 'shell-command': ('Shell command execution', 'Use an argument list with shell=False; validate externally supplied arguments.'),
 'unsafe-deserialization': ('Unsafe object deserialization', 'Avoid pickle for untrusted data; use a data-only format with schema validation.'),
 'unsafe-yaml': ('Potentially unsafe YAML loader', 'Use yaml.safe_load or an explicitly safe loader for untrusted input.'),
 'tls-verification': ('TLS verification disabled', 'Enable certificate verification with a trusted CA bundle.'),
 'dynamic-sql': ('Dynamically constructed SQL', 'Bind untrusted values through query parameters; allowlist identifiers.'),
 'weak-random': ('Non-cryptographic random generator', 'Use secrets for tokens. Ordinary simulation randomness is not a security bug.'),
}
FILES = ('app.py','engine.py','supervisor.py','workflow.py','workqueue.py','casework.py','connections.py','reporting.py','sourceaudit.py','codeflow.py','dependencies.py','rewards.py','validation.py','accesscheck.py','accessmatrix.py','capitaldemo.py','gitlabcheck.py','gitlabpair.py','projectaudit.py','sourcewatch.py','programqueue.py','readiness.py','research.py','ci_identity.py','policyevidence.py','uberconnect.py','autoresearch.py','pathcheck.py','autopilot.py')
MAX_BYTES=128000


def init(c):
    c.execute('CREATE TABLE IF NOT EXISTS source_audits (name TEXT PRIMARY KEY, digest TEXT, checked INTEGER, result TEXT)')


def analyze(source):
    if not isinstance(source,str) or len(source.encode())>MAX_BYTES:
        raise ValueError('Upload a Python file up to 128 KB.')
    try: tree=ast.parse(source)
    except (SyntaxError,ValueError,RecursionError,MemoryError):
        raise ValueError('Python syntax could not be parsed. No audit was completed.') from None
    aliases={}
    nodes=list(ast.walk(tree))
    if len(nodes)>40000:raise ValueError('File is too complex for this audit.')
    for n in nodes:
        if isinstance(n,ast.Import):
            for a in n.names:aliases[a.asname or a.name.split('.')[0]]=a.name if a.asname else a.name.split('.')[0]
        elif isinstance(n,ast.ImportFrom) and n.module:
            for a in n.names:aliases[a.asname or a.name]=n.module+'.'+a.name
    def name(n):
        if isinstance(n,ast.Name):return aliases.get(n.id,n.id)
        if isinstance(n,ast.Attribute):return name(n.value)+'.'+n.attr
        return ''
    def dynamic(n):
        return isinstance(n,(ast.JoinedStr,ast.BinOp)) or (isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='format')
    results=[]
    for n in nodes:
        if not isinstance(n,ast.Call):continue
        call=name(n.func);kw={k.arg:k.value for k in n.keywords};rule=None
        if call in ('eval','exec','builtins.eval','builtins.exec'):rule='dynamic-code'
        elif call in ('os.system','os.popen') or (call.startswith('subprocess.') and isinstance(kw.get('shell'),ast.Constant) and kw['shell'].value is True):rule='shell-command'
        elif call in ('pickle.load','pickle.loads','_pickle.load','_pickle.loads'):rule='unsafe-deserialization'
        elif call in ('yaml.load','yaml.unsafe_load'):
            loader=kw.get('Loader') or (n.args[1] if len(n.args)>1 else None)
            if name(loader) not in ('yaml.SafeLoader','yaml.CSafeLoader','yaml.BaseLoader','yaml.CBaseLoader'):rule='unsafe-yaml'
        elif call=='ssl._create_unverified_context' or (call.startswith(('requests.','httpx.')) and isinstance(kw.get('verify'),ast.Constant) and kw['verify'].value is False):rule='tls-verification'
        elif isinstance(n.func,ast.Attribute) and n.func.attr in ('execute','executemany','executescript') and n.args and dynamic(n.args[0]):rule='dynamic-sql'
        elif call in ('random.random','random.randint','random.choice','random.choices','random.randrange','random.getrandbits'):rule='weak-random'
        if rule:
            title,fix=RULES[rule]
            results.append({'rule':rule,'line':n.lineno,'title':title,'remediation':fix,'status':'Needs human review','confirmed':False})
    for flow in codeflow.traces(tree):
        existing=next((f for f in results if f['line']==flow['line'] and f['rule']==flow['rule']),None)
        if existing is None:
            title,fix=RULES[flow['rule']]
            existing={'rule':flow['rule'],'line':flow['line'],'title':title,'remediation':fix,'status':'Needs human review','confirmed':False}
            results.append(existing)
        existing.update(flow)
    results.sort(key=lambda f:(not bool(f.get('trace_lines')),f['line']))
    return {'language':'Python','rules_checked':len(RULES),'findings':results[:200],
            'total_findings':len(results),'truncated':len(results)>200,
            'limitation':'Pattern checks plus limited input-flow tracing within functions. Branches are conservatively combined; aliases, wrappers, cross-function flows and runtime behavior may be missed. No exploit validation. No findings does not prove the code is secure.'}


def record(c,name,source):
    digest=hashlib.sha256(('flow-v1\n'+source).encode()).hexdigest()
    old=c.execute('SELECT digest FROM source_audits WHERE name=?',(name,)).fetchone()
    if old and old[0]==digest:return False
    result=analyze(source)
    c.execute('INSERT INTO source_audits VALUES (?,?,?,?) ON CONFLICT(name) DO UPDATE SET digest=excluded.digest,checked=excluded.checked,result=excluded.result',
              (name,digest,int(time.time()),json.dumps(result)))
    return True


def installed(c,root):
    count=0
    for filename in FILES:
        p=root/filename
        if p.is_file() and p.stat().st_size<=MAX_BYTES:
            count+=record(c,'ScopeGuard/'+filename,p.read_text())
    return count


def upload(c,data):
    if data.get('owned') is not True:raise ValueError('Confirm this code is yours or you have permission to audit it.')
    name=data.get('name','')
    if not isinstance(name,str) or not name.endswith('.py') or len(name)>100 or any(ch in name for ch in '/\\\r\n'):
        raise ValueError('Choose a Python .py file with a simple filename.')
    source=data.get('source')
    if not isinstance(source,str):raise ValueError('Python source text is required.')
    if c.execute("SELECT COUNT(*) FROM source_audits WHERE name LIKE 'Uploaded/%'").fetchone()[0]>=20 and not c.execute('SELECT 1 FROM source_audits WHERE name=?',('Uploaded/'+name,)).fetchone():
        raise ValueError('Maximum 20 uploaded filenames; replace an existing file to update its audit.')
    record(c,'Uploaded/'+name,source)


def snapshot(c):
    return [{'name':r['name'],'checked':r['checked'],'digest':r['digest'],'result':json.loads(r['result'])}
            for r in c.execute('SELECT * FROM source_audits ORDER BY checked DESC,name')]
