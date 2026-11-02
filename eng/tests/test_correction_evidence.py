"""Negative evidence/transition tests. Synthetic TRX never qualifies the application."""
import importlib.util
import json
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('correction_evidence', ROOT / 'eng/check-correction-evidence.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class RecoveryPolicyNotesTests(unittest.TestCase):
    def test_current_recovery_reason_preserves_identity_history_and_native_obligations(self):
        docs = ROOT/'docs/corrections'
        gates = json.loads((docs/'REVIEW_GATES.json').read_text())['gates']
        gate = next(g for g in gates if g['id']=='migration-recovery')
        self.assertEqual((gate['kind'],gate['owner'],gate['status']),('migration-recovery','COR02','Open'))
        self.assertEqual(gate['reason_history'][-1]['previous_reason'],'Qualify fresh schema and representative upgrades and rollback.')
        self.assertNotIn('representative upgrades',gate['reason'])
        for required in ['fresh current-schema setup','backup restore','unknown-commit','retained-current-key','Gate remains Open']:
            self.assertIn(required,gate['reason'])
        self.assertEqual(gate['evidence'],[])
        for reference in gate['current_policy_references']:
            self.assertTrue((ROOT/reference).is_file())
        for name in ['PRE_1_0_SCHEMA_POLICY.md','COR24_IMPLEMENTATION.md']:
            text=(docs/name).read_text()
            self.assertIn('COR25.39',text);self.assertIn('reason_history',text)


class BaselineSummaryTests(unittest.TestCase):
    def test_current_workflow_summary_matches_authoritative_ledgers_and_dates_frozen_import(self):
        import collections
        import re
        docs = ROOT/'docs/corrections'
        text = (docs/'BASELINE.md').read_text()
        ledger = json.loads((docs/'FINDING_CLOSURE.json').read_text())['findings']
        gates = json.loads((docs/'REVIEW_GATES.json').read_text())['gates']
        states = collections.Counter(f['status'] for f in ledger)
        expected = {'Findings':len(ledger), **{state:states[state] for state in sorted(evidence.STATES)},
                    'Review/release gates':len(gates),'Open gates':sum(g['status']=='Open' for g in gates),
                    'Passed gates':sum(g['status']=='Passed' for g in gates)}
        section = text.split('## Current authoritative summary\n',1)[1].split('\n## ',1)[0]
        rows = re.findall(r'^\| ([^|]+?) \| ([0-9]+) \|$',section,re.M)
        self.assertEqual(len(rows),len(expected))
        self.assertEqual({name:int(count) for name,count in rows},expected)
        frozen = json.loads((docs/'evidence/Treehammock_Review_Ledger_Through_10I.json').read_text())
        manifest = json.loads((docs/'BASELINE_MANIFEST.json').read_text())
        self.assertIn('## Frozen import — '+frozen['reviewed_on'],text)
        self.assertIn(str(len(frozen['open_findings']))+' Open imported findings',text)
        self.assertIn(str(len(manifest['baseline_paths']))+' original source paths',text)
        self.assertIn('previously reported 83 findings: 53 FixedPendingQualification and 30 Open',text)


class InitialImportedHistoryTests(unittest.TestCase):
    def test_historical_import_requires_explicit_pin(self):
        with self.assertRaisesRegex(ValueError, 'explicitly pinned'):
            evidence.verify_initial_import(ROOT)

    def test_pinned_history_is_continuous_and_all_gates_open(self):
        expected = evidence.digest(ROOT / 'docs/corrections/FINDING_CLOSURE.json')
        evidence.verify_initial_import(ROOT, expected)

    def test_wrong_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, 'pinned digest'):
            evidence.verify_initial_import(ROOT, '0' * 64)

    def test_historic_import_cannot_claim_closed_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / 'docs/corrections'
            docs.mkdir(parents=True)
            originals = ROOT / 'docs/corrections'
            for name in ('FINDING_CLOSURE.json', 'REVIEW_GATES.json'):
                shutil.copy2(originals / name, docs / name)
            path = docs / 'FINDING_CLOSURE.json'
            data = json.loads(path.read_text())
            data['findings'][0]['status'] = 'Closed'
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'cannot close'):
                evidence.verify_initial_import(root, evidence.digest(path))

    def test_historic_import_cannot_skip_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / 'docs/corrections'
            docs.mkdir(parents=True)
            originals = ROOT / 'docs/corrections'
            for name in ('FINDING_CLOSURE.json', 'REVIEW_GATES.json'):
                shutil.copy2(originals / name, docs / name)
            path = docs / 'FINDING_CLOSURE.json'
            data = json.loads(path.read_text())
            data['findings'][0]['history'] = data['findings'][0]['history'][1:]
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'invalid transition'):
                evidence.verify_initial_import(root, evidence.digest(path))


class GitPredecessorResolutionTests(unittest.TestCase):
    """A root commit is not the same thing as an unavailable shallow parent."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='evidence-git-history-')
        self.root = Path(self.temp.name) / 'source'
        self.root.mkdir()
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.email', 'audit@example.test')
        self.git('config', 'user.name', 'Audit Test')
        self.docs = self.root / 'docs/corrections'
        self.docs.mkdir(parents=True)
        self.write_evidence()

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *arguments, cwd=None):
        return subprocess.run(['git', *arguments], cwd=cwd or self.root,
                              check=True, capture_output=True, text=True).stdout.strip()

    def write_evidence(self):
        findings = {'findings': [dict(id='TEST-01', status='InProgress', history=[
            dict(**{'from': 'Open', 'to': 'InProgress', 'reason': 'Reviewed initial import'})]) ]}
        (self.docs / 'FINDING_CLOSURE.json').write_text(json.dumps(findings))
        (self.docs / 'REVIEW_GATES.json').write_text(json.dumps({'gates': [dict(id='release', status='Open')]}))
        (self.docs / 'BASELINE_MANIFEST.json').write_text(json.dumps({'baseline_paths': []}))

    def commit(self, message='source checkpoint'):
        self.git('add', '-A')
        self.git('commit', '-qm', message)

    def test_actual_root_commit_uses_pinned_import_and_no_fabricated_parent(self):
        self.commit('initial import')
        digest = evidence.digest(self.docs / 'FINDING_CLOSURE.json')
        prior, resource = evidence.predecessor_evidence(self.root, 'HEAD^', digest)
        self.assertIsNone(prior)
        self.assertIsNone(resource)
        with self.assertRaisesRegex(ValueError, 'explicitly pinned'):
            evidence.predecessor_evidence(self.root, 'HEAD^')

    def test_unknown_predecessor_oid_never_becomes_a_root_import(self):
        self.commit('initial import')
        with self.assertRaisesRegex(ValueError, 'Predecessor revision is unavailable'):
            evidence.predecessor_evidence(self.root, '0' * 40,
                evidence.digest(self.docs / 'FINDING_CLOSURE.json'))

    def test_parent_snapshot_is_loaded_and_ledger_must_be_complete(self):
        self.commit('initial import')
        (self.root / 'README.md').write_text('new update')
        self.commit('subsequent change')
        prior, resource = evidence.predecessor_evidence(self.root, 'HEAD^')
        try:
            self.assertTrue((prior / 'BASELINE_MANIFEST.json').is_file())
            self.assertEqual((prior / 'FINDING_CLOSURE.json').read_bytes(),
                             (self.docs / 'FINDING_CLOSURE.json').read_bytes())
        finally:
            resource.cleanup()

    def test_shallow_clone_cannot_claim_to_be_a_root_import(self):
        self.commit('initial import')
        (self.root / 'README.md').write_text('new update')
        self.commit('subsequent change')
        clone = Path(self.temp.name) / 'shallow'
        self.git('clone', '--quiet', '--depth', '1', self.root.as_uri(), str(clone))
        self.assertEqual(self.git('rev-parse', '--is-shallow-repository', cwd=clone), 'true')
        with self.assertRaisesRegex(ValueError, 'shallow'):
            evidence.predecessor_evidence(clone, 'HEAD^',
                evidence.digest(clone / 'docs/corrections/FINDING_CLOSURE.json'))

    def test_new_ledger_after_existing_parent_requires_pinned_import(self):
        # This is a normal Git predecessor without any correction files.
        for p in self.docs.glob('*'):
            p.unlink()
        self.git('commit', '--allow-empty', '-qm', 'repository before evidence')
        self.write_evidence()
        self.commit('import evidence')
        with self.assertRaisesRegex(ValueError, 'explicitly pinned'):
            evidence.predecessor_evidence(self.root, 'HEAD^')
        prior, resource = evidence.predecessor_evidence(
            self.root, 'HEAD^', evidence.digest(self.docs / 'FINDING_CLOSURE.json'))
        self.assertIsNone(prior)
        self.assertIsNone(resource)


class RegressionSelectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root/'eng').mkdir()
        shutil.copy2(ROOT/'eng/reconcile-source-inventory.py', self.root/'eng/reconcile-source-inventory.py')
        tests = self.root/'treehammock.Tests'
        tests.mkdir()
        (tests/'Fixture.cs').write_text('namespace Tests; public class Fixture { [Fact] public void One() {} [Theory, InlineData(1)] public void Rows(int x) {} }')

    def tearDown(self):
        self.temp.cleanup()

    def test_methods_class_file_and_missing_scopes_are_distinct(self):
        rows = evidence.regression_selectors(self.root, ['Fixture.One','Tests.Fixture.Rows','Fixture','treehammock.Tests/Fixture.cs','Fixture.Obsolete'])
        self.assertEqual([r['kind'] for r in rows], ['MethodDeclaration','MethodDeclaration','ClassScope','FileScope','Unresolved'])
        self.assertTrue(rows[1]['theory_expansion_required'])
        self.assertTrue(all(r['native_case'] is False for r in rows))

    def test_closure_rejects_placeholders_empty_missing_and_unexpanded_theory(self):
        for selectors in [[], ['Fixture'], ['treehammock.Tests/Fixture.cs'], ['Fixture.Obsolete'], ['Fixture.Rows']]:
            with self.subTest(selectors=selectors), self.assertRaises(ValueError):
                evidence.require_concrete_closure_selectors(self.root, selectors)
        evidence.require_concrete_closure_selectors(self.root, ['Fixture.One','Tests.Fixture.Rows(x: 1)'])

    def test_wrong_namespace_and_ambiguous_bare_method_cannot_resolve(self):
        self.assertEqual(evidence.regression_selectors(self.root, ['Wrong.Fixture.One'])[0]['kind'], 'Unresolved')
        (self.root/'treehammock.Tests/Other.cs').write_text('namespace Other; class Fixture { [Fact] public void One() {} }')
        self.assertEqual(evidence.regression_selectors(self.root, ['Fixture.One'])[0]['kind'], 'AmbiguousMethod')
        evidence.require_concrete_closure_selectors(self.root, ['Tests.Fixture.One'])

    def test_scope_paths_cannot_escape_source(self):
        with self.assertRaises(ValueError): evidence.regression_selectors(self.root, ['../outside.cs'])

    def test_sibling_and_nested_classes_do_not_borrow_each_others_methods(self):
        (self.root/'treehammock.Tests/Fixture.cs').write_text('namespace Tests; class First { [Fact] public void A() {} class Nested { [Fact] public void B() {} } } class Second { [Fact] public void C() {} }')
        rows = evidence.regression_selectors(self.root, ['First.C','Second.A','First.B','Tests.First+Nested.B','Second.C'])
        self.assertEqual([r['kind'] for r in rows], ['Unresolved','Unresolved','Unresolved','MethodDeclaration','MethodDeclaration'])

    def test_affected_current_outbox_selectors_resolve_and_placeholders_remain_pending(self):
        findings = json.loads((ROOT/'docs/corrections/FINDING_CLOSURE.json').read_text())['findings']
        affected = [f for f in findings if f['id'] in ('R02-02','R03-08')]
        cases = [c for f in affected for c in f['regression_cases']]
        rows = evidence.regression_selectors(ROOT, cases)
        self.assertEqual({r['kind'] for r in rows}, {'MethodDeclaration','ClassScope'})
        self.assertEqual(sum(r['kind']=='ClassScope' for r in rows), 3)
        renamed = [r for r in rows if r.get('method')=='Staging_and_nonacceptance_preserve_domain_contract']
        self.assertEqual(len(renamed), 2)
        self.assertTrue(all(r['attribute']=='Theory' for r in renamed))
        self.assertFalse(any('working_predecessor' in c for c in cases))


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'project'
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns('.git', '.correction-results', '.artifacts', '__pycache__', 'bin', 'obj'))
        self.docs = self.root / 'docs/corrections'

    def tearDown(self):
        self.temp.cleanup()

    def mutate(self, filename, callback):
        path = self.docs / filename
        value = json.loads(path.read_text(encoding='utf-8'))
        callback(value)
        path.write_text(json.dumps(value), encoding='utf-8')
        self.refresh_added()

    def refresh_added(self):
        path = self.docs / 'ADDED_FILES.json'
        added = json.loads(path.read_text(encoding='utf-8'))
        for name in added['files']:
            file = self.root / name
            if file.is_file(): added['files'][name] = hashlib.sha256(file.read_bytes()).hexdigest()
        path.write_text(json.dumps(added), encoding='utf-8')

    def reject(self):
        with self.assertRaises((ValueError, KeyError)):
            evidence.validate(self.root)

    def test_current_import_preserves_all_findings_and_files(self):
        self.assertEqual(evidence.validate(self.root)[:2], (84, 451))
        frozen=json.loads((self.docs/'evidence/Treehammock_Review_Ledger_Through_10I.json').read_text())['open_findings']
        self.assertEqual(len(frozen),83)
        self.assertLessEqual({f['id'] for f in frozen},{f['id'] for f in json.loads((self.docs/'FINDING_CLOSURE.json').read_text())['findings']})

    def test_missing_original_finding_rejected(self):
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'].pop(0))
        self.reject()

    def test_duplicate_finding_rejected(self):
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'].append(v['findings'][0]))
        self.reject()

    def test_owner_change_rejected(self):
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'][0].update(owner='COR01'))
        self.reject()

    def test_unknown_owner_is_not_accepted_as_a_familiar_looking_pr_id(self):
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'][0].update(owner='COR24ZZ'))
        self.reject()

    def test_gate_kind_cannot_be_downgraded_to_source_review(self):
        self.mutate('REVIEW_GATES.json', lambda v: next(g for g in v['gates'] if g['id']=='performance').update(kind='source'))
        self.reject()

    def test_unknown_new_finding_without_review_import_rejected(self):
        def change(v):
            extra = dict(v['findings'][0], id='R99-01')
            v['findings'].append(extra)
        self.mutate('FINDING_CLOSURE.json', change)
        self.reject()

    def test_altered_inventory_rejected(self):
        path = self.docs / 'FILE_REVIEW_INVENTORY.csv'
        path.write_text('\n'.join(path.read_text(encoding='utf-8').splitlines()[:-1]), encoding='utf-8')
        self.reject()

    def test_changed_historical_review_rejected(self):
        path = self.docs / 'evidence/Treehammock_Review_01_Authentication_Sessions.md'
        path.write_text(path.read_text(encoding='utf-8') + '\nchanged history\n', encoding='utf-8')
        self.reject()

    def test_changed_baseline_manifest_rejected_even_with_coordinated_owner_edit(self):
        self.mutate('BASELINE_MANIFEST.json', lambda v: v['original_owners'].update({'AUTH-01': 'COR01'}))
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'][0].update(owner='COR01'))
        self.reject()

    def test_close_without_execution_rejected(self):
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'][0].update(status='Closed', closure={'change_id': 'written-patch'}))
        self.reject()

    def test_required_gate_cannot_disappear(self):
        self.mutate('REVIEW_GATES.json', lambda v: v['gates'].pop(0))
        self.reject()

    def test_gate_cannot_pass_on_empty_evidence(self):
        self.mutate('REVIEW_GATES.json', lambda v: v['gates'][0].update(status='Passed'))
        self.reject()

    def test_unapproved_disposition_rejected(self):
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'][0].update(status='Dispositioned', disposition={'rationale': 'ignore'}))
        self.reject()

    def open_transition_fixture(self):
        # Transition rejection must not depend on a live project finding remaining Open.
        # Mutate only this test's private copy; the actual ledger/history is preserved.
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'][0].update(
            status='Open', history=[], closure=None))
        return 0

    def test_transition_requires_append_only_history(self):
        index = self.open_transition_fixture()
        previous = Path(self.temp.name) / 'previous'
        shutil.copytree(self.docs, previous)
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'][index].update(status='InProgress'))
        with self.assertRaises(ValueError):
            evidence.validate(self.root, previous)
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'][index]['history'].append(
            dict(**{'from': 'Open', 'to': 'InProgress'}, reason='Owning PR started')))
        evidence.validate(self.root, previous)
        shutil.rmtree(previous)
        shutil.copytree(self.docs, previous)
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'][index].update(history=[]))
        with self.assertRaises(ValueError):
            evidence.validate(self.root, previous)

    def test_each_appended_transition_is_checked_and_skipped_states_are_rejected(self):
        index = self.open_transition_fixture()
        previous = Path(self.temp.name) / 'previous'
        shutil.copytree(self.docs, previous)
        def legitimate(value):
            finding = value['findings'][index]
            finding.update(status='FixedPendingQualification')
            finding['history'].extend([
                dict(**{'from': 'Open', 'to': 'InProgress'}, reason='Implementation started'),
                dict(**{'from': 'InProgress', 'to': 'FixedPendingQualification'}, reason='Implementation complete; runtime blocked')])
        self.mutate('FINDING_CLOSURE.json', legitimate)
        evidence.validate(self.root, previous)
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'][index]['history'].pop(0))
        with self.assertRaises(ValueError):
            evidence.validate(self.root, previous)

    def test_evidence_path_cannot_escape_project(self):
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'][0].update(review_references=['../../../../outside.json']))
        self.reject()

    def test_duplicate_json_keys_rejected(self):
        path = self.docs / 'FINDING_CLOSURE.json'
        path.write_text('{"schema_version":1,"schema_version":2}', encoding='utf-8')
        self.reject()

    def test_passed_lane_cannot_have_no_test_results(self):
        run = dict(schema_version=1, run_id='00000000-0000-0000-0000-000000000001', source_identity='sha256:'+'0'*64,
            evidence_kind='executed-tooling', configuration='Release', runtime_versions={'dotnet': 'fixture'}, status='Passed',
            lanes=[dict(name='fast', status='Passed', exit_code=0, stages=[{'exit_code': 0}], results=[])])
        with self.assertRaises(ValueError):
            evidence.validate_run(self.root, run)

    def test_aggregate_cannot_hide_blocked_lane(self):
        run = dict(schema_version=1, run_id='00000000-0000-0000-0000-000000000001', source_identity='sha256:'+'0'*64,
            evidence_kind='executed-tooling', configuration='Release', runtime_versions={}, status='Passed',
            lanes=[dict(name='sql', status='Blocked', reason='No database')])
        with self.assertRaises(ValueError):
            evidence.validate_run(self.root, run)

    def test_blocked_execution_cannot_close_finding(self):
        path = self.root / '.correction-results/blocked.json'
        path.parent.mkdir()
        identity = 'sha256:' + '0'*64
        run = dict(schema_version=1, run_id='00000000-0000-0000-0000-000000000001', source_identity=identity,
            evidence_kind='executed-tooling', configuration='Release', runtime_versions={}, status='Blocked',
            lanes=[dict(name='sql', status='Blocked', reason='No database')])
        path.write_text(json.dumps(run), encoding='utf-8')
        ref = dict(path=path.relative_to(self.root).as_posix(), sha256=evidence.digest(path), lane='sql', regression=True)
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'][0].update(status='Closed',
            regression_cases=['required-case'], required_lanes=['sql'], closure=dict(change_id=identity, evidence=[ref])))
        self.reject()

    def test_deleted_added_implementation_file_rejected(self):
        (self.root / 'eng/correction-baseline.py').unlink()
        self.reject()

    def test_untracked_added_file_rejected(self):
        (self.root / 'new-untracked.py').write_text('print(1)', encoding='utf-8')
        self.reject()

    def test_performance_gate_cannot_pass_on_test_counts(self):
        path = self.root / '.correction-results/counts.json'
        path.parent.mkdir()
        reproduced = [dict(kind='test-counts', outcome='Passed', total=100),
            dict(kind='measured-workload',source_identity='sha256:'+'a'*64,profile={'name':'fixture'},runtime_versions={'dotnet':'fixture'},metrics={'test_count':100},budgets={'status':'Approved','authorization_reference':'synthetic-only'},outcome='Passed'),
            dict(kind='measured-workload',source_identity='fixture',profile='nonempty',runtime_versions='nonempty',metrics='nonempty',budgets={'status':'Approved','authorization_reference':'synthetic-only'},outcome='Passed')]
        for receipt in reproduced:
            path.write_text(json.dumps(receipt), encoding='utf-8')
            ref = dict(path=path.relative_to(self.root).as_posix(), sha256=evidence.digest(path))
            self.mutate('REVIEW_GATES.json', lambda v: next(g for g in v['gates'] if g['id']=='performance').update(status='Passed', evidence=[ref]))
            with self.subTest(kind=receipt['kind']):self.reject()

    @unittest.skipUnless(shutil.which('git'), 'Git is required to exercise the CI predecessor route')
    def test_ci_predecessor_initial_import_and_invalid_transition(self):
        saved = Path(self.temp.name) / 'saved-docs'
        shutil.move(str(self.docs), saved)
        commands = [['init', '-q'], ['add', '.'],
            ['-c', 'user.name=COR01 test fixture', '-c', 'user.email=cor01-fixture@example.invalid', 'commit', '-qm', 'before-import']]
        for command in commands:
            subprocess.run(['git'] + command, cwd=self.root, check=True, capture_output=True)
        shutil.move(str(saved), self.docs)
        self.mutate('FINDING_CLOSURE.json', lambda v: [f.update(status='Open', history=[]) for f in v['findings']])
        for command in [['add', '.'], ['-c', 'user.name=COR01 test fixture', '-c', 'user.email=cor01-fixture@example.invalid', 'commit', '-qm', 'initial-import']]:
            subprocess.run(['git'] + command, cwd=self.root, check=True, capture_output=True)
        script = self.root / 'eng/check-correction-evidence.py'
        import sys
        child = subprocess.run([sys.executable, str(script), '--previous-revision', 'HEAD^'], cwd=self.root, capture_output=True)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.mutate('FINDING_CLOSURE.json', lambda v: v['findings'][0].update(status='InProgress'))
        for command in [['add', '.'], ['-c', 'user.name=COR01 test fixture', '-c', 'user.email=cor01-fixture@example.invalid', 'commit', '-qm', 'invalid-transition']]:
            subprocess.run(['git'] + command, cwd=self.root, check=True, capture_output=True)
        child = subprocess.run([sys.executable, str(script), '--previous-revision', 'HEAD^'], cwd=self.root, capture_output=True)
        self.assertNotEqual(child.returncode, 0)


class PerformanceReceiptTests(unittest.TestCase):
    """Synthetic schema/comparator fixtures only. These never approve budgets or qualify workload execution."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'candidate'
        self.make()

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
        return dict(path=path.relative_to(self.root).as_posix(), sha256=evidence.digest(path))

    def make(self, concurrency=None, instances=None):
        if self.root.exists(): shutil.rmtree(self.root)
        (self.root / 'eng').mkdir(parents=True)
        for name in ['probe-resource-utilization.py', 'check-correction-evidence.py']:
            shutil.copy2(ROOT / 'eng' / name, self.root / 'eng' / name)
        (self.root / 'program.cs').write_text('// Synthetic fixture; no application was executed.\n')
        spec = importlib.util.spec_from_file_location('receipt_probe', self.root / 'eng/probe-resource-utilization.py')
        self.probe = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.probe)
        self.versions = dict(dotnet='fixture SDK', database='fixture database', cache='fixture cache', os='fixture OS', architecture='fixture CPU')
        self.workload = dict(schema_version=1, workload_id='synthetic-receipt-fixture', budget_status='Approved',
            review_reference='SYNTHETIC TEST AUTHORIZATION ONLY', measured_requests_per_scenario=1, warmup_requests_per_scenario=0,
            concurrency=concurrency or [1], instances=instances or [1], scenarios=list(self.probe.SCENARIOS), controls=['synthetic controlled profile'],
            budgets={**{s+'.'+m:10 for s in self.probe.SCENARIOS for m in self.probe.METRICS}, **{m:10 for m in self.probe.STORAGE}})
        workload_ref = self.write(self.root / 'eng/resource-workload.json', self.workload)
        self.folder = self.root / '.correction-results/performance'
        self.approval = dict(schema_version=1, kind='resource-budget-approval', status='Approved', approved_by='synthetic unit actor',
            authorization_reference=self.workload['review_reference'], workload_sha256=workload_ref['sha256'], budgets=self.workload['budgets'])
        approval_ref = self.write(self.folder / 'approval.json', self.approval)
        source = evidence.performance_source_identity(self.root)
        self.receipt = dict(schema_version=1, kind='resource-comparison', source_identity_algorithm=evidence.PERFORMANCE_SOURCE_ALGORITHM,
            source_identity=source, baseline_source_identity='sha256:'+'a'*64, workload=workload_ref, budget_approval=approval_ref,
            runtime_versions=self.versions, profiles=[], outcome='Passed')
        for c in self.workload['concurrency']:
            for i in self.workload['instances']:
                pair = {}
                for name, identity in [('baseline', self.receipt['baseline_source_identity']), ('candidate', source)]:
                    run_id = str(__import__('uuid').uuid4())
                    profile = dict(concurrency=c, instances=i, hardware='fixture', runtime=evidence.canonical_json(self.versions),
                        argon_policy='fixture', pool_limits='fixture', cache_tls_profile='fixture', fixture_seed='fixture', provider_profile='fixture')
                    provenance = evidence.canonical_json(dict(kind='measured-resource-capture', collector='synthetic test actor only', source_identity=identity, run_id=run_id))
                    capture = dict(workload_id=self.workload['workload_id'], run_id=run_id, provenance=provenance, profile=profile,
                        requests=[dict(scenario=s, **{m:1 for m in self.probe.METRICS}) for s in self.probe.SCENARIOS], storage={m:1 for m in self.probe.STORAGE})
                    pair[name] = self.write(self.folder / f'{c}-{i}-{name}.json', capture)
                self.receipt['profiles'].append(pair)
                self.recompare(pair)

    def read_ref(self, ref): return json.loads((self.root / ref['path']).read_text())
    def replace_ref(self, ref, value):
        ref.update(self.write(self.root / ref['path'], value))
    def recompare(self, pair):
        report = self.probe.compare(self.read_ref(pair['baseline']), self.read_ref(pair['candidate']), self.workload)
        report['capture_sha256'] = {name:pair[name]['sha256'] for name in ['baseline','candidate']}
        path = self.root / pair['candidate']['path']
        pair['comparison'] = self.write(path.with_name(path.name.replace('candidate', 'comparison')), report)
        return report
    def update_workload(self, update_approval=True):
        self.receipt['workload'] = self.write(self.root / 'eng/resource-workload.json', self.workload)
        self.receipt['source_identity'] = evidence.performance_source_identity(self.root)
        if update_approval:
            self.approval.update(workload_sha256=self.receipt['workload']['sha256'], budgets=self.workload['budgets'])
            self.replace_ref(self.receipt['budget_approval'], self.approval)
    def check(self): return evidence.validate_performance(self.root, self.receipt)
    def reject(self):
        with self.assertRaises((ValueError, KeyError, TypeError)): self.check()

    def test_complete_source_bound_comparison_is_structurally_valid_not_native_qualification(self):
        result = self.check()
        self.assertEqual(result['status'], 'ValidResourceComparisonReceipt')
        self.assertEqual(result['profiles'], 1)
        self.assertEqual(json.loads((ROOT/'eng/resource-workload.json').read_text())['budget_status'], 'Proposed')

    def test_malformed_top_level_and_runtime_structures_never_pass(self):
        for field, value in [('schema_version',True), ('kind','measured-workload'), ('runtime_versions','versions'),
            ('runtime_versions',{'dotnet':'only one version'}), ('profiles','nonempty'), ('outcome','Unknown'),
            ('source_identity_algorithm','unknown')]:
            self.make(); self.receipt[field]=value
            with self.subTest(field=field,value=value): self.reject()
        self.make(); self.receipt['metrics']={'test_count':100}; self.reject()

    def test_every_numeric_budget_and_hashed_approval_is_required(self):
        for mutation in ['missing','extra','count-only','nan','infinity','negative','boolean','huge','proposed','reference']:
            self.make()
            if mutation=='missing': self.workload['budgets'].pop('warm_auth.duration_ms')
            elif mutation=='extra': self.workload['budgets']['test_count']=100
            elif mutation=='count-only': self.workload['budgets']={'test_count':100}
            elif mutation=='proposed': self.workload['budget_status']='Proposed'
            elif mutation=='reference': self.workload['review_reference']='unapproved-other-reference'
            else:self.workload['budgets']['warm_auth.duration_ms']={'nan':float('nan'),'infinity':float('inf'),'negative':-1,'boolean':True,'huge':10**1000}[mutation]
            self.update_workload()
            with self.subTest(mutation=mutation):self.reject()

    def test_authorization_and_approved_workload_hash_or_limits_cannot_be_replaced(self):
        for field,value in [('status','Proposed'),('approved_by',' '),('authorization_reference','unrelated'),
            ('workload_sha256','0'*64),('budgets',{'test_count':100}),('schema_version',True)]:
            self.make(); self.approval[field]=value; self.replace_ref(self.receipt['budget_approval'],self.approval)
            with self.subTest(field=field):self.reject()

    def test_all_bound_artifact_hashes_are_checked(self):
        for name in ['workload','budget_approval','baseline','candidate','comparison']:
            self.make(); ref=self.receipt[name] if name in ['workload','budget_approval'] else self.receipt['profiles'][0][name]
            ref['sha256']='0'*64
            with self.subTest(name=name):self.reject()

    def test_source_change_invalidates_receipt_but_mutable_documentation_does_not(self):
        (self.root/'docs').mkdir();(self.root/'docs/review.md').write_text('Mutable gate-review annotation.')
        self.check()
        (self.root/'program.cs').write_text('// Different measured candidate.\n');self.reject()

    def test_nonfinite_negative_boolean_missing_or_count_only_measurements_are_rejected(self):
        for mutation in ['nan','infinity','negative','boolean','huge','missing','count-only','string-row','storage-string']:
            self.make();pair=self.receipt['profiles'][0];capture=self.read_ref(pair['candidate'])
            if mutation=='missing':capture['requests'][0].pop('duration_ms')
            elif mutation=='count-only':capture['requests']=[{'scenario':'warm_auth','test_count':100}]
            elif mutation=='string-row':capture['requests'][0]='nonempty'
            elif mutation=='storage-string':capture['storage']='nonempty'
            else:capture['requests'][0]['duration_ms']={'nan':float('nan'),'infinity':float('inf'),'negative':-1,'boolean':True,'huge':10**1000}[mutation]
            self.replace_ref(pair['candidate'],capture)
            with self.subTest(mutation=mutation):self.reject()

    def test_profile_runtime_and_sample_controls_must_match(self):
        for mutation in ['hardware','runtime','sample','scenario','axis']:
            self.make();pair=self.receipt['profiles'][0];capture=self.read_ref(pair['candidate'])
            if mutation=='hardware':capture['profile']['hardware']='different hardware'
            elif mutation=='runtime':capture['profile']['runtime']='unstructured versions'
            elif mutation=='sample':capture['requests'].append(dict(capture['requests'][0]))
            elif mutation=='scenario':capture['requests']=capture['requests'][1:]
            else:capture['profile']['concurrency']=99
            self.replace_ref(pair['candidate'],capture)
            with self.subTest(mutation=mutation):self.reject()

    def test_capture_source_run_collector_and_provenance_are_bound_inside_its_hash(self):
        for mutation in ['source','run','collector','unstructured']:
            self.make();pair=self.receipt['profiles'][0];capture=self.read_ref(pair['candidate']);provenance=json.loads(capture['provenance'])
            if mutation=='source':provenance['source_identity']='sha256:'+'b'*64
            elif mutation=='run':provenance['run_id']='different run'
            elif mutation=='collector':provenance['collector']=' '
            capture['provenance']='some string' if mutation=='unstructured' else evidence.canonical_json(provenance)
            self.replace_ref(pair['candidate'],capture)
            with self.subTest(mutation=mutation):self.reject()

    def test_baseline_and_candidate_cannot_reuse_capture_path_hash_or_run(self):
        pair=self.receipt['profiles'][0];pair['candidate']=dict(pair['baseline']);self.reject()
        self.make();pair=self.receipt['profiles'][0];a=self.read_ref(pair['baseline']);b=self.read_ref(pair['candidate']);b['run_id']=a['run_id']
        provenance=json.loads(b['provenance']);provenance['run_id']=b['run_id'];b['provenance']=evidence.canonical_json(provenance)
        self.replace_ref(pair['candidate'],b);self.reject()

    def test_every_concurrency_instance_profile_requires_independent_complete_captures(self):
        self.make([1,8],[1,2]);self.assertEqual(self.check()['profiles'],4)
        self.receipt['profiles'].pop();self.reject()
        self.make([1,8],[1,2]);self.receipt['profiles'][1]=self.receipt['profiles'][0];self.reject()

    def test_over_budget_resources_cannot_be_relabelled_passed(self):
        pair=self.receipt['profiles'][0];capture=self.read_ref(pair['candidate']);capture['requests'][0]['duration_ms']=11
        self.replace_ref(pair['candidate'],capture);report=self.recompare(pair)
        self.assertEqual(report['status'],'Failed');report['status']='Passed';report['violations']=[]
        self.replace_ref(pair['comparison'],report);self.reject()

    def test_reported_percentiles_limits_or_capture_hashes_cannot_be_forged(self):
        for mutation in ['p95','maximum','capture-hash','unknown','status']:
            self.make();ref=self.receipt['profiles'][0]['comparison'];report=self.read_ref(ref)
            if mutation=='p95':report['scenarios']['warm_auth']['duration_ms']['candidate_p95']=0
            elif mutation=='maximum':report['scenarios']['warm_auth']['duration_ms']['maximum']=10000
            elif mutation=='capture-hash':report['capture_sha256']['candidate']='0'*64
            elif mutation=='unknown':report['test_count']=100
            else:report['status']='Unknown'
            self.replace_ref(ref,report)
            with self.subTest(mutation=mutation):self.reject()

    def test_explicit_zero_observations_and_computed_negative_improvement_deltas_are_valid(self):
        pair=self.receipt['profiles'][0];capture=self.read_ref(pair['candidate']);capture['requests'][0]['duration_ms']=0
        self.replace_ref(pair['candidate'],capture);report=self.recompare(pair)
        self.assertLess(report['scenarios']['warm_auth']['duration_ms']['delta'],0)
        self.check()

    def test_escaped_linked_or_unknown_references_are_rejected(self):
        self.receipt['budget_approval']['extra']='unknown';self.reject()
        self.make();self.receipt['budget_approval']['path']='../outside.json';self.reject()
        if hasattr(os,'symlink'):
            self.make();ref=self.receipt['budget_approval'];path=self.root/ref['path'];copy=path.with_name('real-approval.json');path.rename(copy);path.symlink_to(copy.name);self.reject()



if __name__ == '__main__':
    unittest.main()
