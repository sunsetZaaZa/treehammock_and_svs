"""Exercise subprocess control flow only, using a clearly synthetic dotnet executable."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('correction_baseline', ROOT / 'eng/correction-baseline.py')
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


@unittest.skipIf(os.name == 'nt', 'Executable shim tests use a Unix shebang; collector logic is shared on Windows')
class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'project'
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns('.git', '.correction-results', '.artifacts', '__pycache__', 'bin', 'obj'))
        self.bin = Path(self.temp.name) / 'bin'
        self.bin.mkdir()
        self.calls = Path(self.temp.name) / 'calls.jsonl'
        self.env = os.environ.copy()
        self.env['PATH'] = str(self.bin)
        self.env['COR01_SYNTHETIC_CALLS'] = str(self.calls)
        self.env.pop('TREEHAMMOCK_DB_CONTRACT_CONNECTION', None)
        self.env.pop('TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS', None)

    def tearDown(self):
        self.temp.cleanup()

    def shim(self, body):
        path = self.bin / 'dotnet'
        prelude = f'#!{sys.executable}\nimport json, os, sys\nfrom pathlib import Path\n'
        prelude += "with open(os.environ['COR01_SYNTHETIC_CALLS'], 'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
        path.write_text(prelude + body, encoding='utf-8')
        path.chmod(0o700)

    def run_collector(self, lane='fast', timeout=10, collect_coverage=False):
        result = subprocess.run([sys.executable, str(self.root / 'eng/correction-baseline.py'), '--lane', lane,
            '--stage-timeout', str(timeout)] + (['--collect-coverage'] if collect_coverage else []), env=self.env, capture_output=True, text=True, timeout=30)
        manifests = sorted((self.root / '.correction-results').glob('*/run.json'))
        self.assertTrue(manifests, result.stderr)
        return result, json.loads(manifests[-1].read_text(encoding='utf-8'))

    def test_missing_sdk_is_blocked_without_fabricated_counts(self):
        child, run = self.run_collector()
        self.assertEqual(child.returncode, 2)
        self.assertEqual(run['status'], 'Blocked')
        self.assertEqual(run['lanes'][0]['results'], [])

    def test_failed_restore_stops_before_build_or_test(self):
        self.shim("print('SYNTHETIC SDK')\nsys.exit(17 if sys.argv[1] == 'restore' else 0)\n")
        child, run = self.run_collector()
        self.assertEqual(child.returncode, 1)
        calls = [json.loads(line) for line in self.calls.read_text(encoding='utf-8').splitlines()]
        self.assertFalse(any(c[0] in ('build', 'test') for c in calls))
        self.assertEqual(run['lanes'][0]['exit_code'], 17)

    def test_successful_child_without_trx_fails(self):
        self.shim("print('SYNTHETIC SDK')\n")
        child, run = self.run_collector()
        self.assertEqual(child.returncode, 1)
        self.assertEqual(run['status'], 'Failed')
        self.assertIn('TRX', run['lanes'][0]['reason'])

    def test_stale_trx_from_another_run_cannot_satisfy_fresh_results(self):
        stale = self.root / '.correction-results' / 'stale' / 'fast'
        stale.mkdir(parents=True)
        (stale / 'unit.trx').write_text('<TestRun/>', encoding='utf-8')
        self.shim("print('SYNTHETIC SDK')\n")
        child, run = self.run_collector()
        self.assertEqual(child.returncode, 1)
        self.assertEqual(run['lanes'][0]['results'], [])

    def test_skipped_synthetic_result_is_not_a_passing_lane(self):
        self.shim("""print('SYNTHETIC SDK')
if sys.argv[1] == 'test':
    args = sys.argv
    folder = Path(args[args.index('--results-directory')+1])
    name = args[args.index('--logger')+1].split('LogFileName=')[1]
    (folder/name).write_text('<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><Results><UnitTestResult executionId="synthetic" testName="synthetic-only" outcome="NotExecuted"/></Results><ResultSummary><Counters total="1" executed="0" passed="0" failed="0" notExecuted="1"/></ResultSummary></TestRun>')
""")
        child, run = self.run_collector()
        self.assertEqual(child.returncode, 1)
        self.assertEqual(run['status'], 'Failed')

    def coverage_shim(self, emit_coverage=True, fail_code=0):
        from test_coverage_contract import TRX, REPORT
        self.shim("print('SYNTHETIC SDK')\nif sys.argv[1] == 'test':\n" +
            "    folder = Path(sys.argv[sys.argv.index('--results-directory')+1])\n" +
            "    name = sys.argv[sys.argv.index('--logger')+1].split('LogFileName=')[1]\n" +
            "    (folder/name).write_text(" + repr(TRX) + ")\n" +
            ("    (folder/'report.cobertura.xml').write_text(" + repr(REPORT) + ")\n" if emit_coverage else '') +
            "    sys.exit(" + str(fail_code) + ")\n")

    def test_requested_coverage_with_trx_but_no_collector_output_fails_before_integration(self):
        self.coverage_shim(emit_coverage=False)
        child, run = self.run_collector(collect_coverage=True)
        self.assertEqual(1, child.returncode)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(1, sum(c[0] == 'test' for c in calls))
        self.assertIn('Coverage contract', run['lanes'][0]['reason'])

    def test_requested_coverage_records_two_separate_fresh_measurements(self):
        self.coverage_shim()
        child, run = self.run_collector(collect_coverage=True)
        self.assertEqual(0, child.returncode, child.stdout + child.stderr)
        measured = run['lanes'][0]['coverage']
        self.assertEqual({'unit', 'integration'}, {m['lane'] for m in measured})
        self.assertNotEqual(measured[0]['directory'], measured[1]['directory'])
        baseline.evidence.validate_run(self.root, run)
        path = self.root / measured[0]['directory'] / measured[0]['artifact']
        path.write_text(path.read_text().replace('hits="1"', 'hits="0"'))
        with self.assertRaises(ValueError): baseline.evidence.validate_run(self.root, run)

    def test_native_test_failure_code_survives_missing_coverage(self):
        self.coverage_shim(emit_coverage=False, fail_code=47)
        child, run = self.run_collector(collect_coverage=True)
        self.assertEqual(1, child.returncode)
        self.assertEqual(47, run['lanes'][0]['exit_code'])

    def test_imported_passing_coverage_cannot_omit_one_measurement(self):
        self.coverage_shim()
        child, run = self.run_collector(collect_coverage=True)
        self.assertEqual(0, child.returncode, child.stdout + child.stderr)
        run['lanes'][0]['coverage'].pop()
        with self.assertRaises(ValueError): baseline.evidence.validate_run(self.root, run)

    def test_sql_optin_missing_is_blocked_before_child_restore(self):
        self.shim("print('SYNTHETIC SDK')\n")
        child, run = self.run_collector('sql-harness')
        self.assertEqual(child.returncode, 2)
        self.assertEqual(run['lanes'][0]['status'], 'Blocked')
        calls = [json.loads(line) for line in self.calls.read_text(encoding='utf-8').splitlines()]
        self.assertEqual([c[0] for c in calls], ['--version'])

    def test_sql_cache_environment_missing_is_blocked_before_restore(self):
        self.shim("print('SYNTHETIC SDK')\n")
        self.env['TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS'] = 'true'
        self.env['TREEHAMMOCK_DB_CONTRACT_CONNECTION'] = 'synthetic-not-a-real-database'
        self.env.pop('TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT', None)
        self.env.pop('TREEHAMMOCK_CORRECTION_CACHE_PASSWORD', None)
        child, run = self.run_collector('sql-harness')
        self.assertEqual(child.returncode, 2)
        self.assertEqual(run['lanes'][0]['status'], 'Blocked')
        self.assertIn('SQL/cache fixture', run['lanes'][0]['reason'])
        calls = [json.loads(line) for line in self.calls.read_text(encoding='utf-8').splitlines()]
        self.assertEqual([c[0] for c in calls], ['--version'])

    def test_child_deadline_is_a_failure(self):
        self.shim("import time\nprint('SYNTHETIC SDK', flush=True)\nif sys.argv[1] == 'restore': time.sleep(20)\n")
        child, run = self.run_collector(timeout=1)
        self.assertEqual(child.returncode, 1)
        self.assertEqual(run['lanes'][0]['exit_code'], 124)

    def test_known_secret_and_jwt_are_removed_from_diagnostics(self):
        self.env['TREEHAMMOCK_TEST_PASSWORD'] = 'cor01-sensitive-fixture-value'
        self.shim("print('SYNTHETIC SDK')\nprint(os.environ['TREEHAMMOCK_TEST_PASSWORD'])\nprint('eyJheader.eyJpayload.signature')\n")
        self.run_collector()
        logs = '\n'.join(p.read_text(encoding='utf-8') for p in (self.root / '.correction-results').rglob('*.log'))
        self.assertNotIn('cor01-sensitive-fixture-value', logs)
        self.assertNotIn('eyJheader.eyJpayload.signature', logs)
        self.assertIn('[REDACTED]', logs)

    def test_output_cannot_overwrite_source_root(self):
        child = subprocess.run([sys.executable, str(self.root / 'eng/correction-baseline.py'), '--output', str(self.root)],
            env=self.env, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(child.returncode, 0)
        self.assertFalse((self.root / 'run.json').exists())


if __name__ == '__main__':
    unittest.main()
