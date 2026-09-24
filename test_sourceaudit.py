import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import app
import sourceaudit

class SourceAuditTests(unittest.TestCase):
    def test_dangerous_patterns_and_import_aliases(self):
        src='''import subprocess as sp
from pickle import loads as decode
import requests as rq
import yaml
import random
value = eval(user_input)
sp.run(command, shell=True)
decode(data)
yaml.load(text)
rq.get(url, verify=False)
cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
random.choice(alphabet)
'''
        self.assertEqual({f['rule'] for f in sourceaudit.analyze(src)['findings']},set(sourceaudit.RULES))
    def test_safe_calls_and_comments_are_not_reported(self):
        src='''import yaml
import subprocess
# eval(user_input)
s = "pickle.loads(data)"
yaml.safe_load(text)
yaml.load(text, Loader=yaml.SafeLoader)
subprocess.run(["echo", value], shell=False)
cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
'''
        self.assertEqual(sourceaudit.analyze(src)['findings'],[])
    def test_source_never_executes_or_leaks_into_report(self):
        src='import os\nos.system("DO_NOT_EXECUTE_SECRET_123")'
        with patch('os.system') as run:
            result=sourceaudit.analyze(src);run.assert_not_called()
        self.assertNotIn('DO_NOT_EXECUTE_SECRET_123',json.dumps(result))
        self.assertFalse(result['findings'][0]['confirmed'])
    def test_invalid_size_syntax_rejected(self):
        for source in ['x'*128001,'def broken(:',None]:
            with self.assertRaises(ValueError):sourceaudit.analyze(source)
    def test_storage_ownership_and_changed_file_deduplication(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(app,'DATA',Path(tmp)):
            app.init()
            data={'name':'example.py','source':'eval("SECRET_SOURCE_MARKER")','owned':True}
            with self.assertRaises(ValueError):app.mutate('/api/source-audit',{**data,'owned':False})
            with self.assertRaises(ValueError):app.mutate('/api/source-audit',{**data,'name':'../outside.py'})
            app.mutate('/api/source-audit',data)
            s=app.snapshot()['source_audits'];self.assertEqual(len(s),1)
            self.assertNotIn('SECRET_SOURCE_MARKER',json.dumps(s))
            with app.db() as c:
                self.assertFalse(sourceaudit.record(c,'Uploaded/example.py',data['source']))
                self.assertTrue(sourceaudit.record(c,'Uploaded/example.py','value = 1'))
            self.assertEqual(app.snapshot()['source_audits'][0]['result']['total_findings'],0)
