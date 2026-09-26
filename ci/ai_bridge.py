"""Private result delivery using ephemeral GitHub workload identity, never secrets.

This host-side bridge is not copied into the analysis container. It sends results
only to the fixed owner-controlled ScopeGuard receiver; redirects are forbidden.
"""
import ast
import json
import os
from pathlib import Path
import sys
import urllib.parse
import urllib.request
import urllib.error

RECEIVER = 'https://scopeguard-research.onrender.com/api/ci-review'
AUDIENCE = 'scopeguard-private-code-review'
MODEL = 'Qwen2.5-Coder-7B-Instruct-Q4_K_M'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Redirects are not allowed for identity or private receipts')


def request_json(url, headers=None, data=None):
    req = urllib.request.Request(url,headers=headers or {},data=data)
    try:
        with urllib.request.build_opener(NoRedirect).open(req,timeout=30) as response:
            raw=response.read(64001)
            if len(raw)>64000:raise ValueError('Response too large')
            return json.loads(raw)
    except urllib.error.HTTPError as error:
        print(('Private receiver' if url==RECEIVER else 'GitHub identity endpoint')+' returned HTTP '+str(error.code)+'.')
        raise


def workload_token():
    url=os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!='https' or parsed.username or parsed.password or not parsed.hostname.endswith('.actions.githubusercontent.com'):
        raise ValueError('Unexpected GitHub identity endpoint')
    query=urllib.parse.parse_qsl(parsed.query,keep_blank_values=True)
    query=[(k,v) for k,v in query if k!='audience']+ [('audience',AUDIENCE)]
    url=urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))
    result=request_json(url,{'Authorization':'Bearer '+os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
    token=result.get('value','')
    if not isinstance(token,str) or not 100<len(token)<16000:raise ValueError('Invalid identity response')
    return token


def deliver(stage,result=None):
    payload={'stage':stage,'revision':os.environ['GITHUB_SHA']}
    if result is not None:payload['result']=result
    raw=json.dumps(payload).encode()
    if len(raw)>32000:raise ValueError('Receipt too large')
    return request_json(RECEIVER,{'Authorization':'Bearer '+workload_token(),'Content-Type':'application/json'},raw)


def excerpts(root):
    # Trusted, bounded checklist guidance is separate from the untrusted source.
    catalog=json.loads((root/'checkpoints/catalog.json').read_text())
    checkpoints={r['id']:r['title'] for g in catalog['categories'] for r in g['checks']}
    def section(filename,name):
        source=(root/filename).read_text()
        tree=ast.parse(source)
        found=[node for node in ast.walk(tree) if (isinstance(node,ast.FunctionDef) and node.name==name)
               or (isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in node.targets))]
        if len(found)!=1:raise ValueError('Expected one fixed review definition')
        node=found[0]
        lines=source.splitlines()
        return node.lineno,filename+'\n'+'\n'.join(f'{i+1}: {lines[i]}' for i in range(node.lineno-1,node.end_lineno))
    constants=[('ci_identity.py',k) for k in ('ISSUER','AUDIENCE','REPOSITORY','BRANCH','WORKFLOW','SUBJECT')]
    contexts={
        'app.py':[('app.py','CSRF'),('app.py','authenticate'),('research.py','claims_for'),('ci_identity.py','verify_token')]+constants,
        'ci_identity.py':constants+[('ci_identity.py','decode64'),('ci_identity.py','strict_object'),('ci_identity.py','verify_signature'),('research.py','claims_for'),('research.py','fetch_signing_keys')],
    }
    output=[]
    for filename,function in [('app.py','do_POST'),('ci_identity.py','verify_token')]:
        line,text=section(filename,function)
        text+='\n\nSUPPORTING SOURCE FROM THIS SAME COMMIT\n'+'\n\n'.join(section(f,n)[1] for f,n in contexts[filename])
        if len(text)>8500:raise ValueError('Excerpt exceeds review budget')
        ids=catalog['ai_context'][filename]
        if len(ids)!=6 or len(set(ids))!=6:raise ValueError('Invalid checkpoint context')
        guidance=[{'id':key,'title':checkpoints[key]} for key in ids]
        output.append({'file':filename,'line':line,'source':text,'checkpoints':guidance})
    return output


def main():
    stage=sys.argv[1]
    try:
        if stage=='prepare':
            Path(sys.argv[2]).write_text(json.dumps(excerpts(Path.cwd())))
            return 0
        if stage=='start':
            accepted=deliver('start').get('accepted') is True
            with open(os.environ['GITHUB_OUTPUT'],'a') as output:output.write('accepted='+str(accepted).lower()+'\n')
            print('Private review lease '+('accepted.' if accepted else 'not granted; no model run.'))
            return 0
        if stage=='result':
            path=Path(sys.argv[2])
            result=json.loads(path.read_text()) if path.exists() else {'model':MODEL,'status':'failed','calibration_passed':False,'reviews':[]}
            accepted=deliver('result',result).get('accepted') is True
            print('Private result receipt '+('accepted.' if accepted else 'not accepted; check dashboard settings.'))
            return 0 if accepted else 1
        raise ValueError('Unknown stage')
    except Exception as error:
        # Exceptions may include an identity URL, bearer token or model text.
        # Never print them into a public repository's Actions log.
        print('Private bridge failed ('+type(error).__name__+'). No credentials or analysis printed. Check dashboard/runner status.')
        return 1


if __name__=='__main__':sys.exit(main())
