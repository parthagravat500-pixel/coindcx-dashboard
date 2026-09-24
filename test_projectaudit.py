import base64
import io
import json
import sqlite3
import unittest
import zipfile
import projectaudit as p

class ProjectTests(unittest.TestCase):
    def test_cross_file_sql_and_safe_binding(self):
        files={'web.py':'from flask import request\nfrom db import search\ndef route():\n return search(request.args.get("q"))',
               'db.py':'def search(q):\n return cursor.execute("SELECT * FROM items WHERE name="+q)'}
        r=p.analyze(files)
        self.assertEqual(r['total_findings'],1)
        self.assertEqual({x['file'] for x in r['findings'][0]['trace']},{'web.py','db.py'})
        self.assertFalse(r['findings'][0]['confirmed'])
        files['db.py']='def search(q):\n return cursor.execute("SELECT * FROM items WHERE name=?", (q,))'
        self.assertEqual(p.analyze(files)['total_findings'],0)

    def test_return_keyword_alias_and_zip_root(self):
        r=p.analyze({'repo/web.py':'from flask import request as rq\nfrom helper import passthrough as passit\nimport os as system\ndef route():\n value=passit(value=rq.args.get("x"))\n system.system(value)',
                     'repo/helper.py':'def passthrough(value):\n return value'})
        self.assertEqual(r['total_findings'],1)
        self.assertIn('repo/helper.py',{x['file'] for x in r['findings'][0]['trace']})

    def test_recursive_and_untrusted_code_not_executed(self):
        r=p.analyze({'app.py':'raise RuntimeError("do not execute")\ndef recurse(q):\n return recurse(q)\ndef route():\n return recurse(input())'})
        self.assertTrue(r['bounded_or_truncated'])
        self.assertFalse(r['submission_ready'])

    def test_syntax_coverage(self):
        r=p.analyze({'bad.py':'def ???','ok.py':'def safe():\n return 1'})
        self.assertEqual(r['syntax_skipped'],['bad.py'])
        self.assertEqual(r['files_analyzed'],1)

    def zip(self,files):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED) as z:
            for name,value in files.items():z.writestr(name,value)
        return base64.b64encode(b.getvalue()).decode()

    def test_archive_limits_paths_and_language(self):
        for files in ({'../escape.py':'a=1'},{'/root.py':'a=1'},{'huge.py':'a'*128001},{'ruby.rb':'puts 1'}):
            with self.assertRaises(ValueError):p.archive(self.zip(files))
        files,skipped=p.archive(self.zip({'root/a.py':'x=1','root/README.md':'hi','root/.venv/a.py':'x=2'}))
        self.assertEqual(list(files),['root/a.py']);self.assertEqual(skipped,2)

    def test_storage_keeps_no_source_and_skips_unchanged(self):
        c=sqlite3.connect(':memory:');c.row_factory=sqlite3.Row;p.init(c)
        source='def sample():\n secret="NEVER_PERSIST_THIS"\n return input()'
        self.assertTrue(p.record(c,'Test',{'a.py':source}))
        self.assertFalse(p.record(c,'Test',{'a.py':source}))
        self.assertNotIn('NEVER_PERSIST_THIS',json.dumps(p.snapshot(c)))
        with self.assertRaises(ValueError):p.upload(c,{'owned':False})
        c.close()

if __name__=='__main__':unittest.main()
