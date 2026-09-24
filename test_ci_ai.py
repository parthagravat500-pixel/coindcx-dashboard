import unittest
from pathlib import Path
from unittest.mock import patch
from ci import ai_bridge, ai_review


class PrivateAITests(unittest.TestCase):
    def test_only_two_fixed_source_excerpts(self):
        excerpts=ai_bridge.excerpts(Path(__file__).parent)
        self.assertEqual([x['file'] for x in excerpts],['app.py','ci_identity.py'])
        self.assertTrue(all(x['line']>0 and len(x['source'])<=8500 for x in excerpts))

    def test_calibration_rejects_wrong_or_extra_answers(self):
        with patch.object(ai_review,'chat',return_value='{"a":"unsafe","b":"safe"}'):
            self.assertTrue(ai_review.calibration())
        for answer in ['{"a":"safe","b":"safe"}','{"a":"unsafe","b":"unsafe"}','{}','{"a":"unsafe","b":"safe","extra":1}']:
            with self.subTest(answer=answer),patch.object(ai_review,'chat',return_value=answer):
                self.assertFalse(ai_review.calibration())

    def test_identity_endpoint_allowlist(self):
        for url in ['http://x.actions.githubusercontent.com','https://attacker.invalid','https://x.actions.githubusercontent.com.attacker.invalid',
                    'https://user:pass@x.actions.githubusercontent.com']:
            with self.subTest(url=url),patch.dict('os.environ',{'ACTIONS_ID_TOKEN_REQUEST_URL':url}),self.assertRaises(ValueError):
                ai_bridge.workload_token()

    def test_private_receipt_redirects_are_forbidden(self):
        with self.assertRaises(ValueError):ai_bridge.NoRedirect().redirect_request(None,None,302,'',{},'https://other.invalid')

    def test_model_memory_budget_is_bounded(self):
        self.assertTrue(ai_review.isolation_checks({'memory':str(10*1024**3)})['bounded_memory'])
        for memory in ['max','0',str(11*1024**3)]:
            self.assertFalse(ai_review.isolation_checks({'memory':memory})['bounded_memory'])
