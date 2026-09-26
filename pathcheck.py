"""Bounded AST path experiments. Inspected Python and sensitive calls never run.

This is an intentionally incomplete model, not a Python sandbox or a runtime
exploit verifier. Unknown operations stop an experiment. Only generated probe
labels and source locations are retained; source values are never persisted.
"""
import ast

VERSION = 'path-model-1'
MAX_LEADS = 20
PAIRS = (('text', 'scopeguard_alpha', 'scopeguard_beta'),
         ('integer', '17', '29'), ('negative_integer', '-17', '-29'))
LIMITATION = ('Experiments use an incomplete AST model with synthetic inputs. '
              'No project code, database query, shell command or deserializer is executed. '
              'Framework routing, authorization, deployment reachability and real impact remain unverified. '
              'A missed path does not prove safety.')


class Unsupported(Exception):
    pass


class Returned(Exception):
    def __init__(self, value):
        self.value = value


class Reached(Exception):
    def __init__(self, value):
        self.value = value


def fullname(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return fullname(node.value) + '.' + node.attr
    return ''


def bounded(value):
    if type(value) not in (str, int, bool, type(None)):
        raise Unsupported('value_type')
    if isinstance(value, str) and len(value) > 4096:
        raise Unsupported('value_limit')
    if type(value) is int and abs(value) > 1000000:
        raise Unsupported('value_limit')
    return value


class Model:
    def __init__(self, files):
        self.functions = {}
        self.modules = {}
        self.aliases = {}
        for path, source in sorted(files.items()):
            try:
                tree = ast.parse(source)
            except (SyntaxError, ValueError, RecursionError):
                continue
            module = path[:-3].replace('/', '.')
            if module.endswith('.__init__'):
                module = module[:-9]
            self.modules[path] = module
            self.aliases[path] = aliases = {}
            for node in tree.body:
                if isinstance(node, ast.Import):
                    for item in node.names:
                        aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    base = node.module
                    if node.level:
                        parts = module.split('.') if path.endswith('/__init__.py') else module.split('.')[:-1]
                        base = '.'.join(parts[:len(parts)-node.level+1] + [node.module])
                    for item in node.names:
                        aliases[item.asname or item.name] = base + '.' + item.name
                elif isinstance(node, ast.FunctionDef):
                    self.functions[module + '.' + node.name] = (path, node)

    def resolve(self, path, node):
        head, _, tail = fullname(node).partition('.')
        return self.aliases[path].get(head, head) + ('.' + tail if tail else '')

    def run(self, entry, finding, probe):
        self.steps = 0
        self.probe = probe
        self.finding = finding
        self.route = []
        try:
            self.call(entry, [], {}, ())
            return {'outcome': 'not_reached'}
        except Reached as reached:
            return {'outcome': 'reached', 'value': reached.value, 'route': self.route[-30:]}
        except Unsupported as error:
            return {'outcome': 'unsupported', 'reason': str(error)}
        except (TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError):
            return {'outcome': 'unsupported', 'reason': 'unsupported_input_or_operation'}

    def step(self):
        self.steps += 1
        if self.steps > 2000:
            raise Unsupported('step_limit')

    def call(self, key, args, kwargs, stack):
        if key not in self.functions:
            raise Unsupported('unknown_function')
        if key in stack or len(stack) >= 6:
            raise Unsupported('call_limit')
        path, fn = self.functions[key]
        if fn.args.vararg or fn.args.kwarg:
            raise Unsupported('variadic_function')
        names = [p.arg for p in fn.args.posonlyargs + fn.args.args]
        all_names = names + [p.arg for p in fn.args.kwonlyargs]
        if len(args) > len(names) or set(kwargs) - set(all_names):
            raise Unsupported('argument_binding')
        env = dict(zip(names, args))
        if set(env) & set(kwargs) or any(p.arg in kwargs for p in fn.args.posonlyargs):
            raise Unsupported('argument_binding')
        env.update(kwargs)
        # Defaults can depend on module initialization; do not guess them.
        if set(env) != set(all_names):
            raise Unsupported('missing_arguments')
        stack = stack + (key,)

        def expr(node):
            self.step()
            if node is None:
                return None
            if isinstance(node, ast.Constant):
                return bounded(node.value)
            if isinstance(node, ast.Name):
                if node.id not in env:
                    raise Unsupported('unknown_name')
                return env[node.id]
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                return bounded(expr(node.left) + expr(node.right))
            if isinstance(node, ast.UnaryOp):
                value = expr(node.operand)
                if isinstance(node.op, ast.Not):
                    return not value
                if isinstance(node.op, ast.USub) and type(value) is int:
                    return bounded(-value)
                raise Unsupported('unary_operation')
            if isinstance(node, ast.JoinedStr):
                pieces = []
                for part in node.values:
                    if isinstance(part, ast.Constant):
                        pieces.append(expr(part))
                    elif isinstance(part, ast.FormattedValue) and part.conversion == -1 and part.format_spec is None:
                        pieces.append(str(expr(part.value)))
                    else:
                        raise Unsupported('string_format')
                return bounded(''.join(pieces))
            if isinstance(node, ast.BoolOp):
                value = expr(node.values[0])
                for other in node.values[1:]:
                    if isinstance(node.op, ast.And) and not value:
                        break
                    if isinstance(node.op, ast.Or) and value:
                        break
                    value = expr(other)
                return value
            if isinstance(node, ast.Compare) and len(node.ops) == 1:
                left, right = expr(node.left), expr(node.comparators[0])
                op = node.ops[0]
                if isinstance(op, ast.Eq): return left == right
                if isinstance(op, ast.NotEq): return left != right
                if isinstance(op, ast.Lt): return left < right
                if isinstance(op, ast.LtE): return left <= right
                if isinstance(op, ast.Gt): return left > right
                if isinstance(op, ast.GtE): return left >= right
                raise Unsupported('comparison')
            if isinstance(node, ast.IfExp):
                return expr(node.body if expr(node.test) else node.orelse)
            if isinstance(node, ast.Call):
                call = self.resolve(path, node.func)
                # Intercept the sensitive operation before evaluating the receiver
                # or calling any real function. Only its first argument is modeled.
                if (path == self.finding['file'] and node.lineno == self.finding['line']
                        and node.col_offset == self.finding['column']):
                    if not node.args:
                        raise Unsupported('sink_arguments')
                    value = expr(node.args[0])
                    self.route.append({'file': path, 'line': node.lineno, 'role': 'Intercepted operation'})
                    raise Reached(value)
                if call in ('input', 'builtins.input'):
                    if call in env or self.modules[path]+'.'+call in self.functions:
                        raise Unsupported('shadowed_input')
                    if node.keywords or len(node.args) > 1:
                        raise Unsupported('input_arguments')
                    if node.args: expr(node.args[0])
                    return self.probe
                sources = ('request.args.get', 'request.form.get', 'request.values.get',
                           'flask.request.args.get', 'flask.request.form.get', 'flask.request.values.get')
                if call in sources:
                    if fullname(node.func).split('.')[0] in env:
                        raise Unsupported('shadowed_request')
                    if node.keywords or not 1 <= len(node.args) <= 2:
                        raise Unsupported('request_arguments')
                    for value in node.args: expr(value)
                    return self.probe
                args = [expr(a) for a in node.args]
                if any(k.arg is None for k in node.keywords):
                    raise Unsupported('expanded_arguments')
                kwargs = {k.arg: expr(k.value) for k in node.keywords}
                if call in ('str', 'int', 'len') and len(args) == 1 and not kwargs and call not in env and call not in self.functions and self.modules[path]+'.'+call not in self.functions:
                    return bounded({'str': str, 'int': int, 'len': len}[call](args[0]))
                if isinstance(node.func, ast.Attribute) and node.func.attr in ('isdigit', 'isalnum', 'isalpha') and not args and not kwargs:
                    value = expr(node.func.value)
                    if type(value) is not str:
                        raise Unsupported('string_predicate')
                    return {'isdigit': str.isdigit, 'isalnum': str.isalnum, 'isalpha': str.isalpha}[node.func.attr](value)
                candidate = call if call in self.functions else self.modules[path]+'.'+call
                if candidate not in self.functions and '.' in self.modules[path]:
                    candidate = self.modules[path].rsplit('.', 1)[0]+'.'+call
                if candidate not in self.functions or fullname(node.func).split('.')[0] in env:
                    raise Unsupported('unknown_call')
                return self.call(candidate, args, kwargs, stack)
            raise Unsupported('unsupported_expression')

        def block(body):
            for node in body:
                self.step()
                self.route.append({'file': path, 'line': node.lineno, 'role': 'Modeled statement'})
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = expr(node.value)
                    for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                        if not isinstance(target, ast.Name):
                            raise Unsupported('assignment_target')
                        env[target.id] = value
                elif isinstance(node, ast.Return):
                    raise Returned(expr(node.value))
                elif isinstance(node, ast.If):
                    block(node.body if expr(node.test) else node.orelse)
                elif isinstance(node, ast.Expr):
                    expr(node.value)
                elif not isinstance(node, ast.Pass):
                    raise Unsupported('unsupported_statement')
        try:
            block(fn.body)
        except Returned as returned:
            return returned.value
        return None


def validate(files, findings):
    model = Model(files)
    results = {}
    for index, finding in enumerate(findings):
        result = {'engine': VERSION, 'status': 'unsupported', 'experiments': 0,
                  'runtime_verified': False, 'limitation': LIMITATION, 'evidence': []}
        results[finding['id']] = result
        if index >= MAX_LEADS:
            result.update(status='limited', reason='Lead budget reached; no experiment attempted.')
            continue
        entries = finding.get('entrypoints', [])[:3]
        complete = False
        for entry in entries:
            for label, first, second in PAIRS:
                pair = [model.run(entry, finding, value) for value in (first, second)]
                result['experiments'] += 2
                if any(x['outcome'] == 'unsupported' for x in pair):
                    continue
                complete = True
                if all(x['outcome'] == 'reached' for x in pair) and pair[0]['value'] != pair[1]['value']:
                    result.update(status='modeled_flow', reason='Changing a benign synthetic input changed the intercepted sensitive argument in the model.')
                    result['evidence'] = [{'probe_family': label, 'input_changed': True,
                                           'argument_changed': True, 'route': pair[0]['route']}]
                    break
            if result['status'] == 'modeled_flow':
                break
        if result['status'] != 'modeled_flow':
            result.update(status='not_reproduced' if complete else 'unsupported',
                          reason='Sampled inputs did not demonstrate influence; safety is unresolved.' if complete else 'The path uses unsupported code or requires runtime context; it remains unresolved.')
    return results


def draft(finding, digest):
    v = finding['automatic_validation']
    # No source literals, evaluated values, credentials or user notes are copied.
    return '\n'.join([
        '# Investigation draft — not submission-ready', '', finding['title'],
        'Source evidence digest: '+digest,
        'Location: '+finding['file']+':'+str(finding['line']),
        'Automatic result: '+v['status']+'. '+v['reason'],
        'Synthetic experiments attempted: '+str(v['experiments']), '',
        'Evidence path:', *['- '+t['file']+':'+str(t['line'])+' — '+t['role'] for t in finding['trace']], '',
        'Still unverified: runtime reachability, authorization, sanitizers, actual impact, program scope and duplicates.',
        LIMITATION, 'No report was submitted. No bounty eligibility is established.'
    ])
