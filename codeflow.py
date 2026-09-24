"""Conservative intra-function input-flow traces; evidence for review, not execution."""
import ast


def traces(tree):
    output=[]
    def walk_block(body,env):
        def fullname(node):
            if isinstance(node,ast.Name):return node.id
            if isinstance(node,ast.Attribute):return fullname(node.value)+'.'+node.attr
            return ''
        def trace(node):
            if node is None:return []
            if isinstance(node,ast.Name):return env.get(node.id,[])[:]
            name=fullname(node)
            if name.startswith(('request.args','request.form','request.values','request.json','request.data','sys.argv')):
                return [node.lineno]
            if isinstance(node,ast.Call) and fullname(node.func) in ('input','request.get_json'):
                return [node.lineno]
            result=[]
            for child in ast.iter_child_nodes(node):
                for line in trace(child):
                    if line not in result:result.append(line)
            return result[:20]
        for statement in body:
            if isinstance(statement,(ast.FunctionDef,ast.AsyncFunctionDef)):
                walk_block(statement.body,{})
                continue
            if isinstance(statement,ast.ClassDef):
                walk_block(statement.body,{})
                continue
            if isinstance(statement,(ast.If,ast.For,ast.AsyncFor,ast.While,ast.Try,ast.With,ast.AsyncWith)):
                branches=[]
                for field in ('body','orelse','finalbody'):
                    block=getattr(statement,field,[])
                    if block:
                        branch={k:v[:] for k,v in env.items()};walk_block(block,branch);branches.append(branch)
                for handler in getattr(statement,'handlers',[]):
                    branch={k:v[:] for k,v in env.items()};walk_block(handler.body,branch);branches.append(branch)
                for branch in branches:
                    for key,lines in branch.items():env[key]=list(dict.fromkeys(env.get(key,[])+lines))[:20]
                continue
            for call in ast.walk(statement):
                if not isinstance(call,ast.Call) or not call.args:continue
                name=fullname(call.func);rule=None
                if name in ('eval','exec','builtins.eval','builtins.exec'):rule='dynamic-code'
                elif name in ('os.system','os.popen') or (name.startswith('subprocess.') and any(k.arg=='shell' and isinstance(k.value,ast.Constant) and k.value.value is True for k in call.keywords)):rule='shell-command'
                elif name.endswith(('.execute','.executemany','.executescript')):rule='dynamic-sql'
                elif name in ('pickle.loads','pickle.load'):rule='unsafe-deserialization'
                lines=trace(call.args[0]) if rule else []
                if lines:
                    output.append({'rule':rule,'line':call.lineno,'trace_lines':list(dict.fromkeys(lines+[call.lineno])),
                                   'flow_status':'Possible external input reaches a sensitive operation; verify path and impact.'})
            if isinstance(statement,(ast.Assign,ast.AnnAssign)):
                targets=statement.targets if isinstance(statement,ast.Assign) else [statement.target]
                lines=trace(statement.value)
                for target in targets:
                    if isinstance(target,ast.Name):env[target.id]=list(dict.fromkeys(lines+[statement.lineno]))[:20] if lines else []
            elif isinstance(statement,ast.AugAssign) and isinstance(statement.target,ast.Name):
                lines=env.get(statement.target.id,[])+trace(statement.value)
                env[statement.target.id]=list(dict.fromkeys(lines+[statement.lineno]))[:20] if lines else []
    walk_block(tree.body,{})
    return output[:200]
