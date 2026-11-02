"""Reject the known ambiguity and unsafe shortcuts; lexical checks never qualify SQL."""
import importlib.util
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('bindings',ROOT/'eng/check-sql-output-bindings.py')
bindings=importlib.util.module_from_spec(spec);spec.loader.exec_module(bindings)

class SqlOutputBindingsTests(unittest.TestCase):
    def setUp(self): self.sql=(ROOT/bindings.CANONICAL).read_text()
    def mutate_function(self,name,old,new):
        definition=bindings.definitions(self.sql)[name]
        self.assertIn(old,definition)
        return self.sql.replace(definition,definition.replace(old,new,1),1)
    def test_current_audit_indexes_every_function_without_claiming_execution(self):
        report=bindings.validate(ROOT)
        self.assertEqual(report['function_count'],176)
        self.assertEqual(report['qualification'],'NotRun')
        self.assertGreater(report['candidate_count'],0)
    def test_original_bare_output_predicate_is_rejected(self):
        sql=self.sql.replace('t.two_factor_index = target_index','two_factor_index = target_index',1)
        with self.assertRaises(ValueError): bindings.validate_critical(sql)
    def test_missing_update_alias_is_rejected(self):
        sql=self.sql.replace('update two_factor_authentications t set token = p_setupTokenHash','update two_factor_authentications set token = p_setupTokenHash',1)
        with self.assertRaises(ValueError): bindings.validate_critical(sql)
    def test_predicate_weakened_to_include_verified_or_revoked_is_rejected(self):
        for token in ('t.verified = false','t.revoked_at is null'):
            sql=self.mutate_function('cor08_authorized_begin_authenticator_app_setup', 'and '+token+';', 'and true;') if token=='t.revoked_at is null' else self.mutate_function('cor08_authorized_begin_authenticator_app_setup', 'and '+token+' and t.revoked_at is null;', 'and true and t.revoked_at is null;')
            with self.subTest(token=token),self.assertRaises(ValueError): bindings.validate_critical(sql)
    def test_conflict_preference_cannot_hide_ambiguity(self):
        for preference in ('use_column','use_variable'):
            sql=self.sql.replace('as $$','as $$\n#variable_conflict '+preference,1)
            with self.subTest(preference=preference),self.assertRaises(ValueError): bindings.validate_critical(sql)
    def test_dynamic_conflict_setting_is_rejected(self):
        sql=self.sql+"\nselect set_config('plpgsql.variable_conflict','use_column',false);\n"
        with self.assertRaises(ValueError): bindings.validate_critical(sql)
    def test_legacy_mutation_is_rejected(self):
        sql=self.mutate_function("disable_activation","return query select false,'ACTIVATION_TRUSTED_GRANT_REQUIRED'::text,null::smallint;","update accounts set verify_status=1; return query select false,'ACTIVATION_TRUSTED_GRANT_REQUIRED'::text,null::smallint;")
        with self.assertRaises(ValueError): bindings.validate_critical(sql)
    def test_literals_and_comments_do_not_become_binding_candidates(self):
        text="select 'two_factor_index'; -- two_factor_index\n/* status */ t.two_factor_index;"
        masked=bindings.mask(text)
        self.assertEqual(len(masked),len(text));self.assertEqual(masked.count('two_factor_index'),1)
    def test_definition_change_changes_audit_identity(self):
        changed=self.sql.replace("'AUTHENTICATOR_SETUP_PENDING'::text","'AUTHENTICATOR_SETUP_CHANGED'::text",1)
        self.assertNotEqual(bindings.audit(changed),bindings.audit(self.sql))

if __name__=='__main__':unittest.main()
