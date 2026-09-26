"""Read-only SQLite component experiments on synthetic data, never project code.

The path model supplies a query; a narrow supported shape supplies a two-row
fixture. This is evidence about an inferred component, not a running application.
Unknown schemas, dialects and paths stay unresolved. No source/query is retained.
"""
import hashlib
import re
import sqlite3

import pathcheck

VERSION = 'synthetic-sqlite-1'
MAX_LEADS = 12
LIMITATION = ('A bounded Python path model supplies SQL to an isolated in-memory SQLite fixture. '
              'The schema and private-row meaning are inferred for the experiment. '
              'No project code or real database is executed. Actual database dialect, routing, '
              'permissions and application impact remain unverified.')
IDENT = r'[A-Za-z_][A-Za-z0-9_]{0,39}'
SELECT = re.compile(r'\s*SELECT\s+(\*|'+IDENT+r'(?:\s*,\s*'+IDENT+r'){0,5})\s+FROM\s+('+IDENT+r')\s+WHERE\s+('+IDENT+r')\s*=\s*(\'scopeguard_owner\'|"scopeguard_owner"|17)\s*;?\s*',re.I)
FAMILIES = (('quoted_text','scopeguard_owner',"' OR 1=1 -- "),
            ('double_quoted_text','scopeguard_owner','" OR 1=1 -- '),
            ('number','17','17 OR 1=1'))


class Unsupported(Exception):
    pass


class Fixture:
    def __init__(self, query):
        match = SELECT.fullmatch(query)
        if not match: raise Unsupported()
        selected,self.table,column,value = match.groups()
        self.column = column
        self.columns = list(dict.fromkeys([column]+([] if selected=='*' else re.split(r'\s*,\s*',selected))))
        self.owner = '17' if value=='17' else 'scopeguard_owner'
        self.other = '29' if value=='17' else 'scopeguard_other'
        self.c = sqlite3.connect(':memory:')
        try: self.initialize(selected,column)
        except Exception:
            self.c.close()
            raise

    def initialize(self,selected,column):
        # Python may be built without this optional API. Fresh connections never
        # enable extensions; the authorizer below also denies every SQL function.
        disable_extensions = getattr(self.c,'enable_load_extension',None)
        if disable_extensions is not None: disable_extensions(False)
        self.c.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,65536)
        self.c.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH,4096)
        self.c.setlimit(sqlite3.SQLITE_LIMIT_COLUMN,12)
        self.c.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH,20)
        self.c.setlimit(sqlite3.SQLITE_LIMIT_COMPOUND_SELECT,4)
        self.c.setlimit(sqlite3.SQLITE_LIMIT_VDBE_OP,30000)
        quote = lambda name:'"'+name+'"'
        columns = ','.join(quote(col)+' TEXT' for col in self.columns)
        self.c.execute('CREATE TABLE '+quote(self.table)+' ('+columns+')')
        for record in (self.owner,self.other):
            self.c.execute('INSERT INTO '+quote(self.table)+' VALUES('+','.join('?' for _ in self.columns)+')',[record]*len(self.columns))
        self.c.commit()
        self.parameterized = 'SELECT '+selected+' FROM '+quote(self.table)+' WHERE '+quote(column)+'=?'
        self.c.execute('PRAGMA query_only=ON')
        self.c.set_authorizer(self.authorize)
        self.c.set_progress_handler(self.progress,100)
        self.steps = 0

    def authorize(self, action, first, second, database, trigger):
        if action == sqlite3.SQLITE_SELECT: return sqlite3.SQLITE_OK
        if (action == sqlite3.SQLITE_READ and database=='main' and first==self.table
                and second in self.columns): return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    def progress(self):
        self.steps += 1
        return int(self.steps > 100)

    def read(self, query, parameters=()):
        if not isinstance(query,str) or len(query)>4096: raise Unsupported()
        self.steps = 0
        try: return self.c.execute(query,parameters).fetchmany(4)
        except (sqlite3.Error,MemoryError,OverflowError): raise Unsupported() from None

    def close(self): self.c.close()


def validate(files, findings):
    model = pathcheck.Model(files)
    results = {}; processed = 0
    for finding in findings:
        result = {'engine':VERSION,'status':'unsupported','attempts':0,'component_verified':False,
                  'runtime_verified':False,'application_verified':False,'submission_ready':False,
                  'reason':'This operation has no supported local component test.','limitation':LIMITATION,'evidence':[]}
        results[finding['id']] = result
        if finding['title'] != 'Untrusted input reaches SQL text': continue
        if processed >= MAX_LEADS:
            result.update(status='limited',reason='Component-test budget reached; no result claimed.');continue
        processed += 1; supported = False
        for entry in finding.get('entrypoints',[])[:3]:
            for family,owner,attack in FAMILIES:
                result['attempts'] += 1
                baseline = model.run(entry,finding,owner)
                if baseline['outcome'] != 'reached' or not isinstance(baseline['value'],str): continue
                try: fixture = Fixture(baseline['value'])
                except (Unsupported,sqlite3.Error,MemoryError): continue
                try:
                    expected = fixture.read(fixture.parameterized,(fixture.owner,))
                    control = fixture.read(baseline['value'])
                    if len(expected)!=1 or control!=expected: continue
                    supported = True
                    probes = [model.run(entry,finding,attack) for _ in range(2)]
                    if any(p['outcome']!='reached' or not isinstance(p['value'],str) for p in probes): continue
                    rows = [fixture.read(p['value']) for p in probes]
                    other = fixture.read(fixture.parameterized,(fixture.other,))
                    binds = fixture.read(fixture.parameterized,(attack,))
                    after = model.run(entry,finding,owner)
                    if after['outcome']!='reached': continue
                    repeated_control = fixture.read(after['value'])
                    checks = {'owner_control':control==expected,'other_row_control':len(other)==1 and other!=expected,
                              'first_extra_row':len(rows[0])==2 and other[0] in rows[0] and expected[0] in rows[0],
                              'repeat_extra_row':rows[1]==rows[0], 'parameter_binding_blocks':not binds,
                              'owner_control_after':repeated_control==expected}
                    if all(checks.values()):
                        result.update(status='reproduced_in_component',component_verified=True,
                                      reason='The modeled query returned an extra synthetic row twice; owner and parameter-binding controls passed.',
                                      evidence=[{'probe_family':family,'checks':checks,'baseline_rows':len(control),
                                                 'comparison_rows':len(rows[0]),'repeat_rows':len(rows[1]),
                                                 'query_sha256':hashlib.sha256(probes[0]['value'].encode()).hexdigest()}])
                        break
                except Unsupported:
                    pass
                finally: fixture.close()
            if result['component_verified']: break
        if not result['component_verified']:
            result.update(status='not_reproduced' if supported else 'unsupported',
                          reason='Supported controls ran but these probes did not reproduce a query bypass. This does not prove safety.' if supported else
                          'No supported query shape and path could be established; application evidence is still needed.')
    return results
