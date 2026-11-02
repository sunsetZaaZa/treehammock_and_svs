import importlib.util
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('issuer',Path(__file__).resolve().parents[1]/'issue-entitlement-grant.py')
issuer=importlib.util.module_from_spec(spec);spec.loader.exec_module(issuer)
class RestrictedIssuerTests(unittest.TestCase):
    def approval(self):
        return dict(grantId='00000000-0000-0000-0000-000000000001',accountId='00000000-0000-0000-0000-000000000002',accountStamp='00000000-0000-0000-0000-000000000003',catalog='treehammock-v1',tier=2,term=1,cadence=0,approvedStart=None,authorizedEnd='2026-12-01T00:00:00Z',maxCycles=1,redeemBefore='2026-11-01T00:00:00Z',issuerReference='operator-reviewed',startAnchor='redemption',deniedCapabilities=[])
    def test_quote_and_dollar_delimiter_cannot_escape_operator_statement(self):
        a=self.approval();a['issuerReference']="x');drop table accounts;--$operator$"
        sql=issuer.approval_sql(a);self.assertIn("'x'');drop table accounts;--$operator$'",sql)
        self.assertIn('set local standard_conforming_strings=on',sql)
        delimiter=sql.split('do ')[1].split(' ')[0];self.assertNotIn(delimiter,a['issuerReference']);self.assertEqual(sql.count(delimiter),2)
    def test_unknown_authority_fields_are_rejected(self):
        a=self.approval();a['issuer']='ordinary-user'
        with self.assertRaises(ValueError):issuer.approval_sql(a)
    def test_empty_account_authority_is_rejected(self):
        a=self.approval();a['accountStamp']=str(issuer.uuid.UUID(int=0))
        with self.assertRaises(ValueError):issuer.approval_sql(a)
    def test_unsupported_tier_cannot_be_selected(self):
        a=self.approval();a['tier']=8
        with self.assertRaises(ValueError):issuer.approval_sql(a)
    def test_non_utc_boundaries_are_rejected(self):
        a=self.approval();a['approvedStart']='2026-11-01T00:00:00-06:00'
        with self.assertRaises(ValueError):issuer.approval_sql(a)
    def test_bool_is_not_cycle_allowance(self):
        a=self.approval();a['maxCycles']=True
        with self.assertRaises(ValueError):issuer.approval_sql(a)
    def test_missing_review_reference_is_rejected(self):
        a=self.approval();a['issuerReference']=' '
        with self.assertRaises(ValueError):issuer.approval_sql(a)
    def test_ambiguous_term_labels_are_rejected(self):
        for term in (4,5):
            a=self.approval();a['term']=term
            with self.assertRaises(ValueError):issuer.approval_sql(a)
    def test_old_repeat_counts_are_rejected(self):
        a=self.approval();a['cadence']=2
        with self.assertRaises(ValueError):issuer.approval_sql(a)
    def test_indefinite_cannot_repeat(self):
        a=self.approval();a.update(term=11,cadence=1,maxCycles=2)
        with self.assertRaises(ValueError):issuer.approval_sql(a)
    def test_no_repeat_has_one_cycle(self):
        a=self.approval();a['maxCycles']=2
        with self.assertRaises(ValueError):issuer.approval_sql(a)
    def test_anchor_must_match_approved_start(self):
        a=self.approval();a['approvedStart']='2026-11-01T00:00:00Z'
        with self.assertRaises(ValueError):issuer.approval_sql(a)
    def test_unknown_or_injected_capability_is_rejected(self):
        a=self.approval();a['deniedCapabilities']=["xmpp');drop table accounts;--"]
        with self.assertRaises(ValueError):issuer.approval_sql(a)
    def test_supported_denial_and_term_repeat_have_exact_arguments(self):
        a=self.approval();a.update(cadence=1,maxCycles=3,term=6,deniedCapabilities=['account.read'])
        self.assertIn("'redemption',array['account.read']::text[]",issuer.approval_sql(a))
if __name__=='__main__':unittest.main()
