"""Executable synthetic-result regressions; these do not qualify native coverage."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('coverage_contract', ROOT / 'eng/coverage-contract.py')
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)
TRX = '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><Results><UnitTestResult executionId="1" outcome="Passed"/></Results><ResultSummary><Counters total="1" executed="1" passed="1" failed="0" notExecuted="0"/></ResultSummary></TestRun>'
REPORT = '<coverage lines-valid="2" lines-covered="1"><packages><package name="treehammock"><classes><class name="App" filename="App.cs"><lines><line number="7" hits="1"/><line number="8" hits="0"/></lines></class></classes></package></packages></coverage>'


class CoverageContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='coverage path with spaces ')
        self.root = Path(self.temp.name)
        self.directory = self.root / 'fresh'
        self.directory.mkdir()
        self.trx = self.directory / 'tests.trx'
        self.report = self.directory / 'attachment/report.cobertura.xml'
        self.report.parent.mkdir()
        self.trx.write_text(TRX)
        self.report.write_text(REPORT)

    def tearDown(self):
        self.temp.cleanup()

    def validate(self):
        return coverage.validate_results(self.directory, 'tests.trx')

    def reject_report(self, old, new):
        self.report.write_text(REPORT.replace(old, new))
        with self.assertRaises(ValueError):
            self.validate()

    def test_valid_synthetic_counts_and_hashes(self):
        result = self.validate()
        self.assertEqual((2, 1), (result['lines_valid'], result['lines_covered']))
        self.assertEqual(coverage.digest(self.report), result['sha256'])

    def test_missing_collector_artifact_fails(self):
        self.report.unlink()
        with self.assertRaises(ValueError): self.validate()

    def test_stale_sibling_report_cannot_satisfy_current_run(self):
        self.report.rename(self.root / 'stale.cobertura.xml')
        with self.assertRaises(ValueError): self.validate()

    def test_empty_report_fails(self):
        self.report.write_text('')
        with self.assertRaises(ValueError): self.validate()

    def test_malformed_report_fails(self):
        self.report.write_text('<coverage')
        with self.assertRaises(coverage.ET.ParseError): self.validate()

    def test_wrong_format_fails(self): self.reject_report('coverage', 'CoverageSession')
    def test_zero_executable_lines_fails(self): self.reject_report('lines-valid="2"', 'lines-valid="0"')
    def test_zero_measured_hits_fails(self): self.reject_report('lines-covered="1"', 'lines-covered="0"')
    def test_impossible_summary_fails(self): self.reject_report('lines-covered="1"', 'lines-covered="3"')
    def test_summary_must_match_actual_lines(self): self.reject_report('hits="1"', 'hits="0"')
    def test_missing_source_lines_fails(self): self.reject_report('<line number="7" hits="1"/>', '')
    def test_dependency_only_coverage_fails(self): self.reject_report('name="treehammock"', 'name="ThirdParty"')
    def test_test_assembly_only_coverage_fails(self): self.reject_report('name="treehammock"', 'name="treehammock.Tests"')
    def test_negative_hits_fails(self): self.reject_report('hits="1"', 'hits="-1"')
    def test_zero_line_number_fails(self): self.reject_report('number="7"', 'number="0"')
    def test_missing_source_filename_fails(self): self.reject_report('filename="App.cs"', '')
    def test_entities_are_rejected(self):
        self.report.write_text('<!DOCTYPE coverage [<!ENTITY leak SYSTEM "file:///etc/passwd">]>' + REPORT)
        with self.assertRaises(ValueError): self.validate()

    def test_duplicate_reports_are_rejected(self):
        (self.directory / 'second.cobertura.xml').write_text(REPORT)
        with self.assertRaises(ValueError): self.validate()

    @unittest.skipIf(os.name == 'nt', 'Symlink permissions vary on Windows')
    def test_linked_report_is_rejected(self):
        outside = self.root / 'external.cobertura.xml'
        self.report.rename(outside)
        self.report.symlink_to(outside)
        with self.assertRaises(ValueError): self.validate()

    def test_missing_trx_is_rejected(self):
        self.trx.unlink()
        with self.assertRaises(ValueError): self.validate()

    def test_zero_discovery_is_rejected(self):
        self.trx.write_text(TRX.replace('total="1"', 'total="0"'))
        with self.assertRaises(ValueError): self.validate()

    def test_skipped_tests_are_rejected(self):
        self.trx.write_text(TRX.replace('outcome="Passed"', 'outcome="NotExecuted"'))
        with self.assertRaises(ValueError): self.validate()

    def test_failed_tests_are_rejected(self):
        self.trx.write_text(TRX.replace('passed="1"', 'passed="0"').replace('failed="0"', 'failed="1"'))
        with self.assertRaises(ValueError): self.validate()

    def test_result_count_mismatch_is_rejected(self):
        self.trx.write_text(TRX.replace('total="1"', 'total="2"'))
        with self.assertRaises(ValueError): self.validate()

    def test_existing_run_directory_cannot_be_reused(self):
        with self.assertRaises(FileExistsError): coverage.run_test(['dotnet', 'test'], self.directory)

    def test_test_failure_retains_original_exit_even_with_bad_output(self):
        with patch.object(coverage.subprocess, 'run', return_value=subprocess.CompletedProcess([], 47)):
            code, result = coverage.run_test(['dotnet', 'test'], self.root / 'failed')
        self.assertEqual(47, code)
        self.assertEqual(47, result['test_exit_code'])
        self.assertIsNone(result['coverage'])

    def test_success_without_output_is_failure(self):
        with patch.object(coverage.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
            code, result = coverage.run_test(['dotnet', 'test'], self.root / 'missing')
        self.assertEqual(1, code)
        self.assertEqual('Failed', result['status'])

    def test_missing_native_executable_fails(self):
        with patch.object(coverage.subprocess, 'run', side_effect=FileNotFoundError):
            code, _ = coverage.run_test(['dotnet', 'test'], self.root / 'absent')
        self.assertEqual(127, code)

    def test_success_records_fresh_artifact_and_preserves_argv_spaces(self):
        (self.root / 'settings with spaces.xml').write_text(coverage.SETTINGS.read_text())
        def native(args, cwd):
            directory = Path(args[args.index('--results-directory') + 1])
            (directory / 'tests.trx').write_text(TRX)
            (directory / 'report.cobertura.xml').write_text(REPORT)
            self.assertIn(coverage.COLLECTOR, args)
            self.assertIn('Code Coverage;Format=cobertura', args)
            self.assertIn(str(self.root / 'settings with spaces.xml'), args)
            return subprocess.CompletedProcess(args, 0)
        with patch.object(coverage.subprocess, 'run', side_effect=native):
            code, result = coverage.run_test(['dotnet', 'test'], self.root / 'success', self.root / 'settings with spaces.xml')
        self.assertEqual(0, code)
        self.assertEqual('Passed', result['status'])
        self.assertEqual(result, json.loads((self.root / 'success/coverage-run.json').read_text()))

    def test_native_fixture_branch_line_oracles_match_its_source(self):
        spec = importlib.util.spec_from_file_location('native_coverage', ROOT / 'eng/test-coverage-contract.py')
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        self.assertIn('return 11;', fixture.BRANCH.splitlines()[6])
        self.assertIn('return 29;', fixture.BRANCH.splitlines()[7])
        self.assertEqual(8, len(fixture.CASES))

    def test_cli_rejects_output_outside_owned_artifact_roots(self):
        result = subprocess.run([sys.executable, str(ROOT / 'eng/coverage-contract.py'), '--lane', 'unit', '--output', str(self.root)], capture_output=True)
        self.assertEqual(2, result.returncode)


if __name__ == '__main__': unittest.main()
