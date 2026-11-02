"""Reconciliation failure tests; static witnesses never qualify the application."""
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('cor23', ROOT / 'eng/reconcile-source-inventory.py')
cor23 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cor23)


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)/'project'
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns(*cor23.IGNORED))

    def tearDown(self):
        self.temp.cleanup()

    def mutate(self, callback):
        p=self.root/cor23.FOLLOWUPS
        data=json.loads(p.read_text())
        callback(data['followups'])
        p.write_text(json.dumps(data))

    def test_current_source_indexes_agree_without_claiming_qualification(self):
        report=cor23.check(self.root)
        self.assertEqual(report['status'],'SourceMappingConsistent')
        self.assertEqual(report['qualification'],'Blocked')
        self.assertEqual(report['followups'],32)
        self.assertEqual(len(cor23.release_blockers(self.root)),271)

    def test_omitted_finding_or_duplicate_owner_is_rejected(self):
        self.mutate(lambda items: items.pop())
        with self.assertRaises(ValueError):cor23.validate_followups(self.root)

    def test_owner_reassignment_is_rejected(self):
        self.mutate(lambda items: items[0].update(pr='COR23B'))
        with self.assertRaises(ValueError):cor23.validate_followups(self.root)

    def test_dependency_cycle_is_rejected(self):
        self.mutate(lambda items: items[0]['dependencies'].append('COR23A'))
        with self.assertRaises(ValueError):cor23.validate_followups(self.root)

    def test_mutual_dependency_cycle_is_rejected(self):
        def cycle(items):
            a=next(i for i in items if i['pr']=='COR23A');b=next(i for i in items if i['pr']=='COR23B')
            a['dependencies'].append('COR23B');b['dependencies'].append('COR23A')
        self.mutate(cycle)
        with self.assertRaises(ValueError):cor23.validate_followups(self.root)

    def test_unsafe_evidence_path_is_rejected(self):
        self.mutate(lambda items: items[0]['target_paths'].append('../outside'))
        with self.assertRaises(ValueError):cor23.validate_followups(self.root)

    def test_changed_frozen_specification_is_rejected(self):
        self.mutate(lambda items: items[0].update(implementation_specification='new source-only acceptance'))
        with self.assertRaises(ValueError):cor23.validate_followups(self.root)

    def test_incomplete_scope_is_rejected(self):
        self.mutate(lambda items: items[0].update(planned_regressions=[]))
        with self.assertRaises(ValueError):cor23.validate_followups(self.root)

    def test_untracked_file_and_changed_source_are_rejected(self):
        (self.root/'unreviewed.cs').write_text('new code')
        with self.assertRaises(ValueError):cor23.check(self.root)
        (self.root/'unreviewed.cs').unlink()
        p=self.root/'Program.cs';p.write_text(p.read_text()+'\n// changed\n')
        with self.assertRaises(ValueError):cor23.check(self.root)

    def test_generated_document_tampering_is_rejected(self):
        (self.root/'docs/release/API_ENDPOINT_MATRIX.md').write_text('release certified')
        with self.assertRaises(ValueError):cor23.check(self.root)

    def test_unknown_http_attribute_expression_is_rejected(self):
        p=self.root/'Controllers/HealthController.cs';p.write_text(p.read_text().replace('[HttpGet("live")]','[HttpGet(RouteValue)]'))
        with self.assertRaises(ValueError):cor23.endpoints(self.root)

    def test_test_source_count_is_not_runtime_or_theory_case_count(self):
        p=self.root/'treehammock.Tests/Unit/SyntheticCases.cs'
        p.write_text('class Fixture { // [Fact] public void Fake() {}\n [Theory][InlineData("public.fake")][InlineData(2)] public void Real(int x) {} }')
        rows=[i for i in cor23.tests(self.root) if i['path'].endswith('SyntheticCases.cs')]
        self.assertEqual([(x['method'],x['attribute']) for x in rows],[('Real','Theory')])

    def test_symlink_outside_source_is_rejected(self):
        (self.root/'external').symlink_to(self.root.parent/'outside')
        (self.root.parent/'outside').write_text('outside')
        with self.assertRaises(ValueError):cor23.source_files(self.root)

    def test_no_sql_declarations_is_rejected(self):
        (self.root/cor23.CANONICAL).write_text('select 1;')
        with self.assertRaises(ValueError):cor23.functions(self.root)

    def test_source_index_cannot_assert_executed_followup(self):
        self.mutate(lambda items: items[0].update(qualification='Passed'))
        with self.assertRaises(ValueError):cor23.validate_followups(self.root)


class TestDeclarationParserTests(unittest.TestCase):
    def parse(self, source):
        return cor23.test_declarations(source, 'fixture.cs')

    def test_separate_and_grouped_data_attributes_each_index_one_method(self):
        rows = self.parse('''class C {
          [Theory][InlineData(1)][InlineData(2)] public void Separate(int x) {}
          [Theory, InlineData(1), InlineData(2)] public async Task Grouped(int x) {}
          [Theory, MemberData(nameof(Rows))] public void Members(int x) {}
          [InlineData(1), Theory] public void Last(int x) {}
          [Fact(Timeout=10), Trait("key", "value")] public void Single() {}
        }''')
        self.assertEqual([(r['method'], r['attribute']) for r in rows],
                         [('Separate','Theory'),('Grouped','Theory'),('Members','Theory'),('Last','Theory'),('Single','Fact')])

    def test_comments_characters_and_all_string_forms_cannot_forge_tests(self):
        source = '''// [Fact] public void Fake1() {}
        /* [Theory, InlineData(1)] public void Fake2() {} */
        string normal = "[Fact] public void Fake3() {}";
        string verbatim = @"[Theory, InlineData(""x"")] public void Fake4() {}";
        string raw = $$$"""[Theory, MemberData("x")] public void Fake5() {}""";
        string interpolated = $"{Call("[Fact] public void Fake6() {}")}";
        char quote = '\\"';
        [Fact] public void Actual() {}'''
        self.assertEqual([r['method'] for r in self.parse(source)], ['Actual'])
        self.assertEqual(self.parse(source)[0]['line'], 8)

    def test_qualified_xunit_and_attribute_suffix_are_explicitly_supported(self):
        rows = self.parse('[global::Xunit.TheoryAttribute, InlineData(1)] public void Row(int x) {} [Xunit.Fact] public void One() {}')
        self.assertEqual([r['attribute'] for r in rows], ['Theory','Fact'])

    def test_unsupported_declarations_fail_instead_of_disappearing(self):
        for source in ['[Theory, InlineData(1)] private void Hidden(int x) {}',
                       '[Fact] public int Property { get; set; }',
                       '[Theory] public void Generic<T>(T x) {}',
                       '[Other.Theory, InlineData(1)] public void Alias(int x) {}',
                       '[Theory, InlineData(1)', '[Fact]']:
            with self.subTest(source=source), self.assertRaises(ValueError): self.parse(source)

    def test_duplicate_mixed_and_ambiguous_method_identities_fail(self):
        for source in ['[Theory, Fact] public void Mixed() {}',
                       '[Fact][Fact] public void Twice() {}',
                       '[Theory] public void Same(int x) {} [Theory] public void Same(string x) {}']:
            with self.subTest(source=source), self.assertRaises(ValueError): self.parse(source)

    def test_unclosed_literals_and_comments_fail(self):
        for source in ['/* [Theory]', 'string x="[Fact]', 'string x="""[Fact]', 'char x=\'a']:
            with self.subTest(source=source), self.assertRaises(ValueError): self.parse(source)

    def test_current_grouped_rfc_tamper_and_cache_methods_are_present_once(self):
        rows = cor23.tests(ROOT)
        for method in ['All_Rfc_vectors_verify', 'Stored_parameters_survive_default_changes_in_both_directions',
                       'Envelope_rejects_tampering_and_wrong_row_binding']:
            matches = [r for r in rows if r['path'].endswith('EnrollmentProtectionTests.cs') and r['method']==method]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]['attribute'], 'Theory')
        self.assertEqual(len([r for r in rows if r['path'].endswith('CacheWriteTests.cs')]), 1)


if __name__ == '__main__':
    unittest.main()
