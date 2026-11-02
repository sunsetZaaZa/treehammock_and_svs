"""Source mutations and synthetic identity evidence are supplemental only."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
import hashlib
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


guard = load('configuration_guard', 'eng/check-build-configuration.py')
identity = load('identity', 'eng/build-identity.py')
fixture = load('configuration_fixture', 'eng/test-build-configuration.py')
ps_fixture = load('ps_fixture', 'eng/test-powershell-runners.py')


class ConfigurationMutationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name) / 'checkout'
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns('.git', 'bin', 'obj', '.artifacts', '.correction-results', 'TestResults', '__pycache__'))
    def tearDown(self): self.temp.cleanup()
    def reject(self, name, before, after):
        path = self.root / name; text = path.read_text(); self.assertIn(before, text); path.write_text(text.replace(before, after, 1))
        with self.assertRaises(ValueError): guard.validate(self.root)
    def test_consistency_is_not_native_qualification(self): self.assertEqual('NotRun', guard.validate(self.root)['qualification'])
    def test_fast_solution_cannot_map_sandbox_tests_to_debug(self): self.reject('treehammock.sln', '{8D529B76-6D6D-4BA7-B3E0-82D4A6EF3AA4}.Sandbox|Any CPU.ActiveCfg = Sandbox', '{8D529B76-6D6D-4BA7-B3E0-82D4A6EF3AA4}.Sandbox|Any CPU.ActiveCfg = Debug')
    def test_sql_solution_cannot_build_debug_for_sandbox(self): self.reject('eng/treehammock.SqlContracts.sln', '{B7F5C59C-7B72-4B53-98A5-AE898EEBA6A2}.Sandbox|Any CPU.Build.0 = Sandbox', '{B7F5C59C-7B72-4B53-98A5-AE898EEBA6A2}.Sandbox|Any CPU.Build.0 = Debug')
    def test_application_reference_must_match(self): self.reject('treehammock.Tests/treehammock.Tests.csproj', '<SetConfiguration>Configuration=$(Configuration)</SetConfiguration>', '<SetConfiguration>Configuration=Release</SetConfiguration>')
    def test_sql_project_cannot_omit_initializer(self): self.reject('treehammock.Tests.SqlContracts/treehammock.Tests.SqlContracts.csproj', 'Infrastructure\\BuildIdentity.cs', 'Infrastructure\\Other.cs')
    def test_system_project_cannot_omit_initializer(self): self.reject('treehammock.Tests.System/treehammock.Tests.System.csproj', 'Infrastructure\\BuildIdentity.cs', 'Infrastructure\\Other.cs')
    def test_configuration_policy_is_explicit(self): self.reject('Directory.Build.props', 'Debug;Release;Sandbox', 'Debug;Release')
    def test_metadata_must_embed_actual_proof_id(self): self.reject('Directory.Build.props', '<_Parameter1>TreehammockProofRunId</_Parameter1>', '<_Parameter1>Other</_Parameter1>')
    def test_missing_test_binary_cannot_pass(self): self.reject('Directory.Build.targets', "!Exists('$(TargetPath)')", 'false')
    def test_old_receipt_cannot_pass(self): self.reject('Directory.Build.targets', "'@(_TreehammockBuiltIdentity)' !=", "'fresh' !=")
    def test_loaded_binary_must_match_current_id(self): self.reject('treehammock.Tests/Infrastructure/BuildIdentity.cs', 'builtId != runId', 'false')
    def test_loaded_binary_must_match_configuration(self): self.reject('treehammock.Tests/Infrastructure/BuildIdentity.cs', 'builtConfiguration != configuration', 'false')
    def test_loaded_output_path_is_checked(self): self.reject('treehammock.Tests/Infrastructure/BuildIdentity.cs', 'folder.Parent?.Name != configuration', 'false')
    def test_bash_validation_must_start_fresh_build(self): self.reject('eng/validate.sh', 'treehammock_begin_build "$configuration"', 'true')
    def test_powershell_sql_must_start_fresh_build(self): self.reject('eng/sql-contracts.ps1', 'Start-TreehammockBuildIdentity -Configuration $Configuration', 'Write-Output success')
    def test_powershell_parent_identity_is_restored(self): self.reject('eng/native-command.ps1', "$priorBuildConfiguration, 'Process'", "$null, 'Process'")
    def test_docker_unit_build_cannot_reuse_old_proof_arg(self): self.reject('eng/docker-unit-tests.sh', 'TREEHAMMOCK_BUILD_RUN_ID=', 'UNUSED=')
    def test_docker_stages_share_receipt(self): self.reject('Dockerfile', 'cat /tmp/treehammock-build-id', 'cat /tmp/other')
    def test_host_system_tests_cannot_default_to_debug(self): self.reject('eng/docker-host-system-stack-tests.sh', 'System.csproj --configuration Release --no-build', 'System.csproj --no-build')
    def test_container_system_tests_cannot_default_to_debug(self): self.reject('eng/compose-system-proof.sh', 'System.csproj --configuration Release --no-build', 'System.csproj --no-build')
    def test_docker_context_cannot_import_host_results(self): self.reject('.dockerignore', '.correction-results', '# ignored')


class IdentityEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.folder = Path(self.temp.name) / 'bin/Sandbox/net8.0'; self.folder.mkdir(parents=True)
        self.path = self.folder / 'treehammock.Tests.identity.json'
        self.data = dict(run_id=str(uuid.uuid4()), configuration='Sandbox', assemblies=[])
        for name in ['treehammock.Tests', 'treehammock']:
            binary = self.folder / (name + '.dll'); binary.write_bytes(b'SYNTHETIC identity evidence; not a PE/CLR image')
            self.data['assemblies'].append(dict(name=name, path=str(binary), mvid=str(uuid.uuid4()), sha256=hashlib.sha256(binary.read_bytes()).hexdigest()))
        self.receipt = self.folder / 'treehammock.Tests.dll.proof-id'
        self.receipt.write_text(self.data['run_id'] + '|Sandbox|treehammock.Tests|net8.0')
        self.write()
    def tearDown(self): self.temp.cleanup()
    def write(self): self.path.write_text(json.dumps(self.data))
    def validate(self): return identity.validate(self.path, 'Sandbox', 'treehammock.Tests')
    def test_valid_synthetic_evidence(self): self.assertEqual(self.data, self.validate())
    def test_wrong_requested_configuration_fails(self):
        with self.assertRaises(ValueError): identity.validate(self.path, 'Release', 'treehammock.Tests')
    def test_wrong_recorded_configuration_fails(self):
        self.data['configuration'] = 'Debug'; self.write()
        with self.assertRaises(ValueError): self.validate()
    def test_wrong_test_assembly_fails(self):
        self.data['assemblies'][0]['name'] = 'Other'; self.write()
        with self.assertRaises(ValueError): self.validate()
    def test_changed_binary_fails(self):
        Path(self.data['assemblies'][0]['path']).write_bytes(b'changed')
        with self.assertRaises(ValueError): self.validate()
    def test_previous_receipt_fails(self):
        self.receipt.write_text(str(uuid.uuid4()) + '|Sandbox|treehammock.Tests|net8.0')
        with self.assertRaises(ValueError): self.validate()
    def test_missing_binary_fails(self):
        Path(self.data['assemblies'][0]['path']).unlink()
        with self.assertRaises(FileNotFoundError): self.validate()
    def test_invalid_mvid_fails(self):
        self.data['assemblies'][0]['mvid'] = 'invalid'; self.write()
        with self.assertRaises(ValueError): self.validate()
    def test_invalid_run_id_fails(self):
        self.data['run_id'] = 'invalid'; self.write()
        with self.assertRaises(ValueError): self.validate()
    def test_sdk_fixture_requests_each_configuration(self):
        self.assertEqual(['Debug', 'Release', 'Sandbox'], fixture.CONFIGURATIONS)
        self.assertEqual(['bash', 'eng/validate.sh', '--configuration', 'Sandbox'], fixture.wrapper('bash', 'validate', 'Sandbox'))
        self.assertIn('-Configuration', fixture.wrapper('pwsh', 'validate', 'Release'))
    def test_native_matrix_cannot_accept_zero_discovery_skips_or_sql_probe_only(self):
        path = Path(self.temp.name) / 'tests.trx'
        valid = '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><ResultSummary><Counters total="1" executed="1" passed="1" failed="0" notExecuted="0"/></ResultSummary></TestRun>'
        path.write_text(valid); fixture.complete_tests(path)
        with self.assertRaises(ValueError): fixture.complete_tests(path, minimum=2)
        for old, new in [('total="1"', 'total="0"'), ('passed="1"', 'passed="0"'), ('notExecuted="0"', 'notExecuted="1"')]:
            path.write_text(valid.replace(old, new))
            with self.assertRaises(ValueError): fixture.complete_tests(path)
    def test_standalone_coverage_cannot_use_unowned_old_no_build_output(self):
        env = dict(os.environ); env.pop('TREEHAMMOCK_BUILD_RUN_ID', None); env.pop('TREEHAMMOCK_BUILD_CONFIGURATION', None)
        child = subprocess.run([sys.executable, str(ROOT / 'eng/coverage-contract.py'), '--lane', 'unit', '--configuration', 'Sandbox'], env=env, capture_output=True, text=True)
        self.assertEqual(2, child.returncode); self.assertIn('owned current build', child.stderr)
    def test_trace_normalizes_only_valid_unpredictable_uuid(self):
        path = Path(self.temp.name) / 'trace.jsonl'; args = ['build', '--build-arg', 'TREEHAMMOCK_BUILD_RUN_ID=' + str(uuid.uuid4()), '--build-arg', 'BUILD_CONFIGURATION=Sandbox']
        path.write_text(json.dumps(dict(tool='docker', args=args)))
        observed = ps_fixture.entries(path)[0]['args']
        self.assertEqual(args[:2], observed[:2]); self.assertEqual(args[3:], observed[3:])
        path.write_text(json.dumps(dict(tool='docker', args=['TREEHAMMOCK_BUILD_RUN_ID=not-a-uuid'])))
        with self.assertRaises(ValueError): ps_fixture.entries(path)

    @unittest.skipIf(os.name == 'nt', 'Bash host fixture runs on Unix')
    def test_bash_helper_generates_distinct_valid_ids_and_rejects_unsupported_configuration(self):
        script = 'source "$1"; treehammock_begin_build Sandbox; printf "%s\\n" "$TREEHAMMOCK_BUILD_RUN_ID"; treehammock_begin_build Release; printf "%s\\n" "$TREEHAMMOCK_BUILD_RUN_ID"; treehammock_begin_build Unknown'
        child = subprocess.run(['bash', '-c', script, 'fixture', str(ROOT / 'eng/build-identity.sh')], capture_output=True, text=True)
        self.assertEqual(2, child.returncode); ids = child.stdout.splitlines(); self.assertEqual(2, len(ids)); self.assertNotEqual(ids[0], ids[1])
        for value in ids: uuid.UUID(value)


class OwnedUnitCollectorTests(unittest.TestCase):
    """Controlled wrapper/receipt actors test the collector, not Docker or .NET qualification."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.checkout = Path(self.temp.name) / 'checkout with spaces'; self.checkout.mkdir()
        self.saved = Path(self.temp.name) / 'saved'; self.saved.mkdir()
        self.log = self.saved / 'wrapper.log'
        self.run_id = str(uuid.uuid4())
        self.project = 'treehammock-test-' + self.run_id.replace('-', '')
        self.record = dict(schema_version=1, run_id=self.run_id, project=self.project, lane='docker-unit-tests',
            status='Passed', exit_code=0, cleanup='Passed', ownership='Disposable', unit_image=self.project + '-unit:owned')
        self.clean = dict(status='Passed', failures=[], budget_exhausted=False,
            removed=[dict(kind='image', resource='sha256:controlled-owned-image')])
        self.wrapper_code = 0
        self.emit = True
        self.multiple = False
    def tearDown(self): self.temp.cleanup()
    def write_receipts(self, run_id, record, clean):
        folder = self.checkout / 'artifacts/test-runs' / run_id; folder.mkdir(parents=True)
        (folder / 'run.json').write_text(json.dumps(record))
        (folder / 'cleanup.json').write_text(json.dumps(clean))
    def actor(self, command, **kwargs):
        self.assertEqual(kwargs['cwd'], self.checkout)
        if self.emit: self.write_receipts(self.run_id, self.record, self.clean)
        if self.multiple:
            other = str(uuid.uuid4()); self.write_receipts(other, dict(self.record, run_id=other), self.clean)
        return subprocess.CompletedProcess(command, self.wrapper_code)
    def invoke(self, host='bash', configuration='Release'):
        with patch.object(fixture.subprocess, 'run', side_effect=self.actor) as process:
            result = fixture.run_owned_unit(host, configuration, self.checkout, self.log, self.saved)
        return result, process
    def test_all_host_configuration_commands_omit_forbidden_image_override(self):
        for host in ['bash', 'pwsh', 'powershell.exe']:
            for configuration in fixture.CONFIGURATIONS:
                with self.subTest(host=host, configuration=configuration):
                    # Every call needs a genuinely fresh receipt, even in this controlled actor.
                    folder = self.checkout / 'artifacts'
                    if folder.exists(): shutil.rmtree(folder)
                    value, process = self.invoke(host, configuration)
                    extra = ['--no-cache'] if host == 'bash' else ['-NoCache']
                    self.assertEqual(process.call_args.args[0], fixture.wrapper(host, 'docker-unit-tests', configuration, extra))
                    self.assertEqual(process.call_count, 1)  # No collector-issued docker image rm.
                    self.assertEqual(value['unit_image'], self.record['unit_image'])
                    self.assertEqual(value['status'], 'Passed')
                    self.assertEqual(json.loads((self.saved / 'docker-owned-cleanup.json').read_text()), self.clean)
    def test_missing_receipt_does_not_accept_stale_run(self):
        self.write_receipts(self.run_id, self.record, self.clean); self.emit = False
        with self.assertRaisesRegex(ValueError, 'fresh'): self.invoke()
    def test_multiple_new_receipts_are_ambiguous(self):
        self.multiple = True
        with self.assertRaisesRegex(ValueError, 'Exactly one'): self.invoke()
    def test_wrong_lane_or_assigned_image_is_rejected(self):
        for field, value in [('lane', 'docker-all-tests'), ('unit_image', 'developer:do-not-delete'),
            ('project', 'developer'), ('run_id', str(uuid.uuid4()))]:
            with self.subTest(field=field):
                original = self.record[field]; self.record[field] = value
                with self.assertRaises(ValueError): self.invoke()
                self.record[field] = original
                shutil.rmtree(self.checkout / 'artifacts')
    def test_wrapper_failure_retains_exit_and_receipts(self):
        self.wrapper_code = 47; self.record.update(status='Failed', exit_code=47)
        with self.assertRaisesRegex(ValueError, 'exit 47'): self.invoke()
        summary = json.loads((self.saved / 'docker-owned-unit.json').read_text())
        self.assertEqual(summary['wrapper_exit_code'], 47)
        self.assertEqual(json.loads((self.saved / 'docker-owned-run.json').read_text())['exit_code'], 47)
    def test_primary_and_cleanup_failures_both_survive(self):
        self.wrapper_code = 47; self.record.update(status='Failed', exit_code=47, cleanup='Failed')
        self.clean.update(status='Failed', failures=['image-removal'])
        with self.assertRaisesRegex(ValueError, 'exit 47'): self.invoke()
        summary = json.loads((self.saved / 'docker-owned-unit.json').read_text())
        self.assertEqual(summary['cleanup']['failures'], ['image-removal'])
        self.assertEqual(summary['status'], 'Failed')
    def test_successful_wrapper_cannot_hide_bad_cleanup(self):
        for changes in [dict(status='Failed'), dict(failures=['process-cleanup']), dict(budget_exhausted=True),
            dict(retained=True), dict(removed=[])]:
            with self.subTest(changes=changes):
                previous = dict(self.clean); self.clean.update(changes)
                with self.assertRaises(ValueError): self.invoke()
                self.clean = previous; shutil.rmtree(self.checkout / 'artifacts')
    def test_bad_run_outcome_cannot_pass_despite_successful_cleanup(self):
        self.record['exit_code'] = 47
        with self.assertRaises(ValueError): self.invoke()
    def test_missing_cleanup_is_preserved_as_failure(self):
        def missing(command, **kwargs):
            self.actor(command, **kwargs)
            (self.checkout / 'artifacts/test-runs' / self.run_id / 'cleanup.json').unlink()
            return subprocess.CompletedProcess(command, 0)
        with patch.object(fixture.subprocess, 'run', side_effect=missing), self.assertRaises(ValueError):
            fixture.run_owned_unit('bash', 'Release', self.checkout, self.log, self.saved)
        self.assertTrue((self.saved / 'docker-owned-run.json').exists())
        self.assertEqual(json.loads((self.saved / 'docker-owned-unit.json').read_text())['status'], 'Failed')
    def test_owner_report_uses_the_image_assigned_by_run_environment(self):
        owner = load('owned_report', 'eng/test-ownership.py')
        assigned = 'actual-assigned-owned-image'
        run = dict(id=self.run_id, project=self.project, lane='docker-unit-tests', ci_identity=None,
            created_at='controlled', artifacts=str(self.saved), token='private-not-public')
        with patch.object(owner, 'run_environment', return_value=dict(TREEHAMMOCK_TEST_UNIT_IMAGE=assigned)), patch.object(owner, 'write') as write:
            owner.report(run, 0, self.clean)
        report = write.call_args.args[1]
        self.assertEqual(report['unit_image'], assigned)
        self.assertNotIn(run['token'], json.dumps(report))


if __name__ == '__main__': unittest.main()
