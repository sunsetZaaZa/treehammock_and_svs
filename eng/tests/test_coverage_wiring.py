"""Source mutations guard coverage routing; runtime qualification is separate."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('coverage_wiring', ROOT / 'eng/check-coverage-contract.py')
wiring = importlib.util.module_from_spec(spec); spec.loader.exec_module(wiring)


class CoverageWiringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name) / 'checkout'
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns('.git', 'bin', 'obj', '.artifacts', '.correction-results', 'TestResults', '__pycache__'))
    def tearDown(self): self.temp.cleanup()
    def reject(self, path, before, after):
        file = self.root / path; text = file.read_text(); self.assertIn(before, text); file.write_text(text.replace(before, after, 1))
        with self.assertRaises(ValueError): wiring.validate(self.root)
    def test_consistency_is_not_runtime_qualification(self): self.assertEqual('NotRun', wiring.validate(self.root)['qualification'])
    def test_wrong_collector_name_fails(self): self.reject('eng/coverage.runsettings', 'friendlyName="Code Coverage"', 'friendlyName="XPlat Code Coverage"')
    def test_wrong_output_format_fails(self): self.reject('eng/coverage.runsettings', '<Format>cobertura</Format>', '<Format>coverage</Format>')
    def test_test_assembly_cannot_inflate_measurement(self): self.reject('eng/coverage.runsettings', '<IncludeTestAssembly>False', '<IncludeTestAssembly>True')
    def test_application_filter_is_required(self): self.reject('eng/coverage.runsettings', 'treehammock\\.dll$', '.*\\.dll$')
    def test_collector_is_private(self): self.reject('treehammock.Tests/treehammock.Tests.csproj', '<PackageReference Include="Microsoft.NET.Test.Sdk">\n      <PrivateAssets>all</PrivateAssets>', '<PackageReference Include="Microsoft.NET.Test.Sdk">\n      <PrivateAssets>none</PrivateAssets>')
    def test_bash_lane_cannot_bypass_validation(self): self.reject('eng/dotnet-unit-tests.sh', 'coverage-contract.py" --lane unit', 'other.py" --lane unit')
    def test_powershell_lane_cannot_bypass_validation(self): self.reject('eng/dotnet-integration-tests.ps1', "Invoke-TreehammockCoverage -Lane 'integration'", "Invoke-UncheckedCoverage -Lane 'integration'")
    def test_fast_validate_cannot_use_old_collector(self): self.reject('eng/validate.sh', 'coverage-contract.py', 'XPlat Code Coverage')
    def test_evidence_import_must_revalidate_artifacts(self): self.reject('eng/check-correction-evidence.py', 'Coverage evidence content/hash mismatch', 'unchecked')
    def test_first_failure_is_required(self): self.reject('eng/coverage-contract.py', 'original exit code preserved', 'success anyway')
    def test_fresh_directory_is_required(self): self.reject('eng/coverage-contract.py', 'exist_ok=False', 'exist_ok=True')


if __name__ == '__main__': unittest.main()
