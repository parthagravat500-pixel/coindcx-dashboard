"""Positive/negative controls for executable adapters, never external targets."""
import json
import unittest
from unittest.mock import patch

import checkpointstatic
import checkpointengine as engine
import validation
import test_checkpointengine as fixtures


class StaticSettingTests(unittest.TestCase):
    def test_scheduler_rejects_duplicate_or_fabricated_success_steps(self):
        import autopilot
        rows=[{'id':key,'actual_status':status,'passed':True,'response_sha256':'a'*64}
              for key,status in validation.EXPECTED_STATUSES.items()]
        result={'status':'All covered checks passed','checks':rows}
        self.assertEqual(autopilot.classify('owned_validation',result),'boundary_held')
        rows[-1]=dict(rows[0])
        self.assertEqual(autopilot.classify('owned_validation',result),'inconclusive')
        self.assertEqual(len(autopilot.evidence({'checks':[{}]*100})),24)

    def test_each_setting_has_a_positive_and_negative_control(self):
        cases = [
            ('SG-0241', 'from jwt import decode as d\nd(x, options={"verify_signature": False})', 'from jwt import decode as d\nd(x, options={"verify_signature": True})'),
            ('SG-0243', 'import jwt\njwt.decode(x, algorithms=["none"])', 'import jwt\njwt.decode(x, algorithms=["RS256"])'),
            ('SG-0245', 'import jwt\njwt.decode(x, options={"verify_iss": False})', 'import jwt\njwt.decode(x, options={"verify_iss": True})'),
            ('SG-0246', 'import jwt\njwt.decode(x, options={"verify_aud": False})', 'import jwt\njwt.decode(x, options={"verify_aud": True})'),
            ('SG-0247', 'import jwt\njwt.decode(x, options={"verify_exp": False})', 'import jwt\njwt.decode(x, options={"verify_exp": True})'),
            ('SG-0316', 'from jinja2 import Environment as E\nE(autoescape=False)', 'from jinja2 import Environment as E\nE(autoescape=True)'),
            ('SG-0441', 'from lxml import etree as e\ne.XMLParser(resolve_entities=True)', 'from lxml import etree as e\ne.XMLParser(resolve_entities=False)'),
            ('SG-0602', 'context.check_hostname=False', 'context.check_hostname=True'),
            ('SG-0623', 'from Crypto.Cipher import AES\nAES.new(key, AES.MODE_ECB)', 'from Crypto.Cipher import AES\nAES.new(key, AES.MODE_GCM)'),
            ('SG-0625', 'from hashlib import sha1 as digest\ndigest(value)', 'from hashlib import sha256 as digest\ndigest(value)'),
        ]
        with patch('socket.create_connection', side_effect=AssertionError('No network')):
            for key, positive, negative in cases:
                with self.subTest(key=key):
                    hits=checkpointstatic.analyze(positive)
                    self.assertTrue(hits[key]); self.assertFalse(any(v for k,v in hits.items() if k!=key))
                    self.assertFalse(any(checkpointstatic.analyze(negative).values()))
        self.assertEqual({x[0] for x in cases},set(checkpointstatic.LIMITS))

    def test_combined_settings_and_unresolved_values_remain_patterns(self):
        result=checkpointstatic.analyze('import jwt\njwt.decode(x, options={"verify_signature": False, "verify_aud": False, "verify_exp": False})')
        for key in ('SG-0241','SG-0246','SG-0247'):self.assertEqual(result[key],[2])
        self.assertFalse(any(checkpointstatic.analyze('import jwt\njwt.decode(x, options=settings)').values()))
        self.assertFalse(any(checkpointstatic.analyze('import jwt\njwt.decode(x, options={"verify_exp": False, "verify_exp": True})').values()))
        # A declaration that resembles a library call is not executed by analysis.
        self.assertFalse(any(checkpointstatic.analyze('raise RuntimeError("must never execute")').values()))


class AddedAdapterTests(unittest.TestCase):
    # Reuse fixture setup only, without inheriting and rerunning the whole suite.
    setUp=fixtures.AutomaticCheckpointTests.setUp
    tearDown=fixtures.AutomaticCheckpointTests.tearDown
    resume=fixtures.AutomaticCheckpointTests.resume
    target=fixtures.AutomaticCheckpointTests.target

    def test_cors_requires_the_existing_approved_probe_and_retains_no_headers(self):
        self.resume();target=self.target()
        response={'status':200,'headers':{},'cookies':[]}
        cors={'status':200,'headers':{'access-control-allow-origin':'https://scopeguard.invalid',
            'access-control-allow-credentials':'true','vary':'Accept-Encoding, Origin','private-test':'do-not-store'}}
        import app
        with app.db() as c:
            row=c.execute('SELECT * FROM targets WHERE id=?',(target,)).fetchone()
            engine.record_head(c,row,response,cors)
            first=engine.build(c,'target:'+str(target))
            self.assertFalse(next(r for r in first['items'] if r['id']=='SG-0283')['observation']['executed'])
            c.execute('UPDATE targets SET cors=1 WHERE id=?',(target,))
            row=c.execute('SELECT * FROM targets WHERE id=?',(target,)).fetchone()
            engine.record_head(c,row,response,cors)
            result=engine.build(c,'target:'+str(target))
            mapped={r['id']:r for r in result['items']}
            self.assertTrue(mapped['SG-0283']['observation']['origin_reflected'])
            self.assertTrue(mapped['SG-0291']['observation']['varies_on_origin'])
            self.assertFalse(mapped['SG-0283']['observation']['tested'])
            raw=json.dumps([dict(r) for r in c.execute('SELECT * FROM checkpoint_observations')])
            self.assertNotIn('do-not-store',raw);self.assertNotIn('Accept-Encoding',raw)
            c.execute('UPDATE targets SET enabled=0 WHERE id=?',(target,))
            self.assertEqual(next(r for r in engine.build(c,'target:'+str(target))['items'] if r['id']=='SG-0283')['observation']['state'],'blocked')

    def test_private_api_adapter_needs_each_authenticated_control(self):
        self.resume()
        import app,autopilot,time
        with app.db() as c:
            job=next(j for j in autopilot.jobs(c,int(time.time())) if j['kind']=='owned_validation')
            evidence=[{'id':key,'actual_status':status,'passed':True,'response_sha256':'a'*64}
                for key,status in [('control',200),('anonymous-catalog',401),('anonymous-results',401),('anonymous-coverage',401)]]
            engine.record_runtime(c,job,'boundary_held',evidence,int(time.time()))
            row=next(r for r in engine.build(c,'owned')['items'] if r['id']=='SG-0461')
            self.assertEqual(row['observation']['state'],'inconclusive');self.assertFalse(row['observation']['tested'])
