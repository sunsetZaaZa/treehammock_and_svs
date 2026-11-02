#!/usr/bin/env python3
"""Actual SDK/collector qualification. Never substitutes synthetic coverage."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('coverage_contract', ROOT / 'eng/coverage-contract.py')
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)
BRANCH = '''namespace CoverageProbe;
public static class BranchProbe
{
    public static int Choose(bool positive)
    {
        if (positive)
            return 11;
        return 29;
    }
}
'''
TESTS = '''using Xunit;
namespace Probe {
 public class Unit {
  [Fact] public void Positive() => Assert.Equal(11, CoverageProbe.BranchProbe.Choose(true));
 }
 public class Integration {
  [Fact] public void Negative() => Assert.Equal(29, CoverageProbe.BranchProbe.Choose(false));
 }
 public class Failure {
  [Fact] public void Fails() => Assert.Equal(99, CoverageProbe.BranchProbe.Choose(true));
 }
}
'''
CASES = ['unit-known-positive-branch', 'integration-known-negative-branch',
         'collector-absent', 'zero-discovery', 'test-failure-retained',
         'stale-sibling-cannot-satisfy-new-run', 'real-project-clean-fast-lanes',
         'application-publish-has-no-test-collector']


def invoke(command, cwd, log):
    with log.open('w', encoding='utf-8') as f:
        result = subprocess.run(command, cwd=cwd, stdout=f, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise ValueError(f'Native stage failed with exit {result.returncode}: {log.name}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', choices=['bash', 'pwsh', 'powershell.exe'], required=True)
    parser.add_argument('--output', type=Path, default=ROOT / '.artifacts/coverage-qualification')
    args = parser.parse_args()
    directory = args.output.resolve() / str(uuid.uuid4())
    directory.mkdir(parents=True, exist_ok=False)
    report = dict(status='Blocked', qualification='NotRun', cases=[], required_cases=CASES)
    missing = [name for name in ['dotnet', args.host] if not shutil.which(name)]
    if missing:
        report['reason'] = 'Required native runtime unavailable: ' + ', '.join(missing)
    else:
        report.update(status='Failed', qualification='Attempted')
        try:
            # Real generated projects remain outside the application checkout so
            # root SDK compile globs never consume the fixture's C# sources.
            with tempfile.TemporaryDirectory(prefix='cor23r real coverage with spaces ') as temp:
                work = Path(temp)
                lib, tests = work / 'library', work / 'tests'
                lib.mkdir(); tests.mkdir()
                versions = {p.get('Include'): p.get('Version') for p in coverage.ET.parse(ROOT / 'Directory.Packages.props').findall('ItemGroup/PackageVersion')}
                (lib / 'CoverageProbe.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>')
                (lib / 'BranchProbe.cs').write_text(BRANCH)
                references = ''.join(f'<PackageReference Include="{p}" Version="{versions[p]}" PrivateAssets="all"/>' for p in ['Microsoft.NET.Test.Sdk', 'xunit.v3', 'xunit.runner.visualstudio'])
                (tests / 'Probe.Tests.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><OutputType>Exe</OutputType><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup><ItemGroup>' + references + '<ProjectReference Include="../library/CoverageProbe.csproj"/></ItemGroup></Project>')
                (tests / 'ProbeTests.cs').write_text(TESTS)
                settings = work / 'coverage settings.runsettings'
                settings.write_text(coverage.SETTINGS.read_text().replace('treehammock', 'CoverageProbe'))
                project = str(tests / 'Probe.Tests.csproj')
                invoke(['dotnet', 'restore', project, '--use-lock-file'], work, directory / 'fixture-restore.log')
                invoke(['dotnet', 'build', project, '-c', 'Debug', '--no-restore'], work, directory / 'fixture-build.log')
                command = ['dotnet', 'test', project, '-c', 'Debug', '--no-build', '--no-restore']
                for lane, line_hit, line_missed in [('Unit', 7, 8), ('Integration', 8, 7)]:
                    output = directory / lane
                    code, measured = coverage.run_test(command + ['--filter', 'FullyQualifiedName~Probe.' + lane], output, settings, 'CoverageProbe', work)
                    if code != 0: raise ValueError('Real collector/fixture lane failed')
                    xml = coverage.xml(output / measured['coverage']['artifact'])
                    lines = {int(line.get('number')): int(line.get('hits')) for c in xml.findall('.//class')
                             if c.get('name', '').endswith('BranchProbe') for line in c.findall('lines/line')}
                    if lines.get(line_hit, 0) <= 0 or lines.get(line_missed, -1) != 0:
                        raise ValueError('Known positive/negative branch measurement disagrees with execution')
                    report['cases'].append(dict(name=CASES[0 if lane == 'Unit' else 1], status='Passed'))
                absent = work / 'absent.runsettings'
                absent.write_text(settings.read_text().replace('friendlyName="Code Coverage"', 'friendlyName="COR23R Missing Collector"'))
                # Do not request Code Coverage on the CLI in the absent-collector
                # case: that would reinstall the valid collector selection.
                absent_command = command + ['--filter', 'FullyQualifiedName~Probe.Unit', '--settings', str(absent),
                    '--results-directory', str(directory / 'absent'), '--logger', 'trx;LogFileName=tests.trx']
                (directory / 'absent').mkdir()
                result = subprocess.run(absent_command, cwd=work)
                try:
                    coverage.validate_results(directory / 'absent', 'tests.trx', 'CoverageProbe')
                except (ValueError, OSError, coverage.ET.ParseError): pass
                else: raise ValueError('Absent collector was accepted')
                report['cases'].append(dict(name='collector-absent', status='Passed', test_exit=result.returncode))
                for name, selector in [('zero-discovery', 'NoMatchingCor23RTest'), ('test-failure-retained', 'Probe.Failure')]:
                    code, result = coverage.run_test(command + ['--filter', 'FullyQualifiedName~' + selector], directory / name, settings, 'CoverageProbe', work)
                    if code == 0 or (name == 'test-failure-retained' and code != result.get('test_exit_code')):
                        raise ValueError('Negative native result was accepted or failure exit was replaced')
                    report['cases'].append(dict(name=name, status='Passed', exit_code=code))
                # The positive Unit report is a genuine stale sibling. A later
                # no-collector attempt must never reuse it.
                fresh = directory / 'stale-rejection'; fresh.mkdir()
                result = subprocess.run(command + ['--filter', 'FullyQualifiedName~Probe.Unit', '--results-directory', str(fresh), '--logger', 'trx;LogFileName=tests.trx'], cwd=work)
                if result.returncode != 0: raise ValueError('Stale fixture test failed before artifact validation')
                try: coverage.validate_results(fresh, 'tests.trx', 'CoverageProbe')
                except ValueError: pass
                else: raise ValueError('A stale sibling report satisfied fresh validation')
                report['cases'].append(dict(name='stale-sibling-cannot-satisfy-new-run', status='Passed'))
                checkout = work / 'real project checkout'
                shutil.copytree(ROOT, checkout, ignore=shutil.ignore_patterns('.git', '.artifacts', '.correction-results', 'bin', 'obj', 'TestResults', '__pycache__'))
                if args.host == 'bash':
                    for script in (checkout / 'eng').glob('*.sh'): script.chmod(0o700)
                    runner = [args.host, 'eng/validate.sh', '--locked-restore', '--collect-coverage']
                else:
                    runner = [args.host, '-NoProfile', '-File', 'eng/validate.ps1', '-LockedRestore', '-CollectCoverage']
                invoke(runner, checkout, directory / 'real-fast-lanes.log')
                manifests = list((checkout / '.artifacts/coverage').glob('*/*/coverage-run.json'))
                if len(manifests) != 2 or any(json.loads(p.read_text())['status'] != 'Passed' for p in manifests):
                    raise ValueError('Real unit/integration lanes have missing or failing coverage')
                shutil.copytree(checkout / '.artifacts/coverage', directory / 'real-project-coverage')
                report['cases'].append(dict(name='real-project-clean-fast-lanes', status='Passed', host=args.host))
                invoke(['dotnet', 'publish', 'treehammock.csproj', '-c', 'Release', '--no-restore', '-o', str(work / 'publish')], checkout, directory / 'publish.log')
                dependencies = json.loads((work / 'publish/treehammock.deps.json').read_text())['libraries']
                if any(p.split('/')[0].lower() in ['microsoft.codecoverage', 'microsoft.net.test.sdk', 'coverlet.collector', 'xunit.v3'] for p in dependencies):
                    raise ValueError('Test collector leaked into application publish')
                if any('codecoverage' in p.name.lower() for p in (work / 'publish').rglob('*')):
                    raise ValueError('Collector binary leaked into application publish')
                report['cases'].append(dict(name='application-publish-has-no-test-collector', status='Passed'))
            report.update(status='Passed', qualification='Passed', reason=None)
        except (ValueError, OSError, coverage.ET.ParseError) as error:
            report['reason'] = str(error)
    (directory / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(status=report['status'], qualification=report['qualification'], report=str(directory / 'qualification.json'))))
    return 0 if report['status'] == 'Passed' else 2 if report['status'] == 'Blocked' else 1


if __name__ == '__main__': raise SystemExit(main())
