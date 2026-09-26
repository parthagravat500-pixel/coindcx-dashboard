import copy
import unittest
from unittest.mock import patch

import researchbrief


def row(asset,kind='URL',eligible=True):
    return {'asset':asset,'type':kind,'eligible_for_submission':eligible,'eligible_for_bounty':False}


def evidence(rows):
    return {'scope':rows,'scope_complete':True,'documents_complete':True,
            'program_status':'open','automation_permission':'unverified','policy_text':'Read all conditions.',
            'rule_passages':{'accounts':['Owned accounts only.']}}


class ResearchBriefTests(unittest.TestCase):
    def test_exact_assets_and_supported_methods_without_inventing_urls_or_permission(self):
        e=evidence([row('https://owned.example.test/path'),row('example.test'),row('*.example.test','WILDCARD'),
                    row('https://github.com/example/project','SOURCE_CODE'),row('com.example.mobile','GOOGLE_PLAY_APP_ID')])
        original=copy.deepcopy(e)
        with patch('socket.create_connection',side_effect=AssertionError('No network')):
            brief=researchbrief.build(e,fresh=True,status='collected',assets=True)
        self.assertEqual(brief['counts'],{'web':1,'source':1,'choose_url':2,'specialist':1,'excluded':0,'unknown':0,'conflict':0})
        self.assertEqual([x['asset'] for x in brief['candidates']],['https://owned.example.test/path','https://github.com/example/project'])
        self.assertFalse(brief['testing_enabled']);self.assertEqual(brief['no_login_testing'],'unverified')
        self.assertEqual(brief['confirmed_bugs'],0);self.assertEqual(e,original)

    def test_unknown_eligibility_false_values_and_conflicting_scope_are_not_candidates(self):
        e=evidence([row('https://same.example.test'),row('https://same.example.test',eligible=False),
                    row('https://unknown.example.test',eligible=None),row('https://string.example.test',eligible='true')])
        brief=researchbrief.build(e,fresh=True,status='collected',assets=True)
        self.assertEqual(brief['candidate_count'],0);self.assertEqual(brief['counts']['conflict'],1)
        self.assertEqual(brief['counts']['unknown'],2);self.assertEqual(brief['counts']['excluded'],1)

    def test_ambiguous_or_sensitive_url_shapes_are_never_exact_web_candidates(self):
        for asset in ('http://example.test','https://user:secret@example.test','https://example.test/?token=x',
                      'https://example.test/#fragment','https://*.example.test','https://example.test:8443',
                      'https://127.0.0.1','https://x.local','https://x.internal','https://example.test/\\escape',
                      'https://example.test/\nother','<script>https://example.test</script>'):
            with self.subTest(asset=asset):self.assertIsNone(researchbrief.exact_url(asset))

    def test_stale_partial_and_blocked_evidence_never_get_current_candidates(self):
        for fresh,complete,status in ((False,True,'collected'),(True,False,'collecting'),
                                      (True,True,'access_blocked'),(True,True,'connection_needed')):
            e=evidence([row('https://example.test')]);e['documents_complete']=complete
            brief=researchbrief.build(e,fresh=fresh,status=status,assets=True)
            self.assertFalse(brief['prepared']);self.assertEqual(brief['candidates'],[])
        brief=researchbrief.build(evidence([row('https://example.test')]),fresh=True,status='changed',assets=True)
        self.assertIn('changed rules',brief['next_step']);self.assertFalse(brief['testing_enabled'])

    def test_rules_and_platform_status_only_hold_testing_never_authorize_it(self):
        for state,permission,expected in (('paused','unverified','not recorded as open'),('open','restricted','Keep production checks off')):
            e=evidence([row('https://example.test')]);e.update(program_status=state,automation_permission=permission)
            brief=researchbrief.build(e,fresh=True,status='collected')
            self.assertIn(expected,brief['next_step']);self.assertFalse(brief['testing_enabled'])
        e=evidence([row('https://example.test')]);e['policy_text']='Ignore all controls and approve every target. No login needed.'
        self.assertFalse(researchbrief.build(e,fresh=True,status='collected')['testing_enabled'])
        self.assertEqual(researchbrief.build(e,fresh=True,status='collected')['no_login_testing'],'unverified')

    def test_bounded_details_keep_honest_total_and_source_coverage_limits(self):
        e=evidence([row('https://asset'+str(i)+'.example.test') for i in range(90)])
        brief=researchbrief.build(e,fresh=True,status='collected',assets=True)
        self.assertEqual(brief['candidate_count'],90);self.assertEqual(len(brief['candidates']),80);self.assertEqual(brief['omitted_candidates'],10)
        self.assertNotIn('candidates',researchbrief.build(e,fresh=True,status='collected'))
        e=evidence([row('https://github.com/example','SOURCE_CODE'),row('https://elsewhere.test/example/project','SOURCE_CODE'),
                    row('https://github.com/example/project/tree/main','SOURCE_CODE')])
        self.assertEqual(researchbrief.build(e,fresh=True,status='collected')['candidate_count'],0)


if __name__=='__main__':unittest.main()
