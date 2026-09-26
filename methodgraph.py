"""Declared Python methods for static review and inert, bounded path models."""
import ast


def methods(tree,module):
    result={}
    shadowed=set()
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.ClassDef,ast.AsyncFunctionDef)):shadowed.add(node.name)
        elif isinstance(node,(ast.Import,ast.ImportFrom)):
            shadowed.update(a.asname or a.name.split('.')[0] for a in node.names)
        elif isinstance(node,(ast.Assign,ast.AnnAssign)):
            shadowed.update(n.id for n in ast.walk(node) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store))
    for cls in tree.body:
        if not isinstance(cls,ast.ClassDef):continue
        declared=[n for n in cls.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]
        names=[n.name for n in declared]
        # An abstract receiver is useful only for simple declarations. Real
        # inheritance, initialization, descriptors and metaclasses need context.
        simple=(not cls.bases and not cls.keywords and not cls.decorator_list
                and len(names)==len(set(names)) and not any(n.startswith('__') for n in names)
                and all(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.Pass))
                        or isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str)
                        for n in cls.body))
        for fn in declared:
            decorators=[d.id if isinstance(d,ast.Name) else '' for d in fn.decorator_list]
            kind='static' if decorators==['staticmethod'] and 'staticmethod' not in shadowed else 'instance' if not decorators else 'unknown'
            args=fn.args.posonlyargs+fn.args.args
            receiver=args[0].arg if args and kind!='static' else ''
            rebound=bool(receiver and any(isinstance(n,ast.Name) and n.id==receiver and isinstance(n.ctx,ast.Store) for n in ast.walk(fn)))
            key=module+'.'+cls.name+'.'+fn.name
            result[key]=(fn,{'owner':module+'.'+cls.name,'receiver':receiver,'kind':kind,
                             'model_safe':bool(simple and kind!='unknown' and not rebound
                                               and isinstance(fn,ast.FunctionDef)
                                               and (kind=='static' or receiver)),
                             'receiver_rebound':rebound})
    return result


def receiver_call(key,node,index):
    """Resolve only a direct call through the declared, unreassigned receiver."""
    info=index.get(key)
    if not info or not info['receiver'] or info['receiver_rebound']:return ''
    if not isinstance(node,ast.Attribute) or not isinstance(node.value,ast.Name) or node.value.id!=info['receiver']:return ''
    candidate=info['owner']+'.'+node.attr
    return candidate if candidate in index else ''
