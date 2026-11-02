#!/usr/bin/env python3
"""Coverage wiring/source consistency only; native qualification is separate."""
import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition: raise ValueError(message)


def validate(root):
    project = ET.parse(root / 'treehammock.Tests/treehammock.Tests.csproj')
    sdk = project.find("ItemGroup/PackageReference[@Include='Microsoft.NET.Test.Sdk']")
    require(sdk is not None and sdk.findtext('PrivateAssets') == 'all', 'Test SDK/collector must remain private')
    versions = ET.parse(root / 'Directory.Packages.props')
    version = versions.find("ItemGroup/PackageVersion[@Include='Microsoft.NET.Test.Sdk']").get('Version')
    packages = json.loads((root / 'treehammock.Tests/packages.lock.json').read_text())['dependencies']['net8.0']
    require(packages['Microsoft.NET.Test.Sdk']['resolved'] == version == '17.14.1', 'SDK collector pin drift')
    require(packages['Microsoft.NET.Test.Sdk']['dependencies']['Microsoft.CodeCoverage'] == packages['Microsoft.CodeCoverage']['resolved'] == version, 'Existing collector lock drift')
    require('Microsoft.CodeCoverage' not in json.loads((root / 'packages.lock.json').read_text())['dependencies']['net8.0'], 'Collector leaked into app dependency graph')
    settings = ET.parse(root / 'eng/coverage.runsettings')
    collector = settings.find('DataCollectionRunSettings/DataCollectors/DataCollector')
    require(collector is not None and collector.get('friendlyName') == 'Code Coverage', 'Wrong collector')
    require(collector.findtext('Configuration/Format') == 'cobertura', 'Wrong coverage format')
    require(collector.findtext('Configuration/IncludeTestAssembly') == 'False', 'Tests cannot inflate application coverage')
    require(collector.findtext('Configuration/CodeCoverage/ModulePaths/Include/ModulePath') == r'.*[\\/]treehammock\.dll$', 'Expected application module filter drift')
    for lane in ['unit', 'integration']:
        require('coverage-contract.py" --lane ' + lane in (root / f'eng/dotnet-{lane}-tests.sh').read_text(), 'Bash lane bypasses validated collection')
        require("Invoke-TreehammockCoverage -Lane '" + lane + "'" in (root / f'eng/dotnet-{lane}-tests.ps1').read_text(), 'PowerShell lane bypasses validated collection')
    for extension in ['sh', 'ps1']:
        source = (root / f'eng/validate.{extension}').read_text()
        require('XPlat Code Coverage' not in source and 'not qualified yet' not in source, 'Obsolete coverage path')
        require(('coverage-contract.py' if extension == 'sh' else 'Invoke-TreehammockCoverage') in source, 'Fast validation bypasses coverage contract')
    helper = (root / 'eng/coverage-contract.py').read_text()
    for token in ['Code Coverage;Format=cobertura', 'exist_ok=False', 'validate_results(directory, trx_name, expected_package)', "len(artifacts) != 1", "counts['total'] == 0", 'original exit code preserved']:
        require(token in helper, 'Coverage output/exit validation missing: ' + token)
    baseline = (root / 'eng/correction-baseline.py').read_text()
    require('coverage.validate_results' in baseline and '--collect-coverage' in baseline, 'Baseline output does not enforce coverage')
    evidence = (root / 'eng/check-correction-evidence.py').read_text()
    require('Coverage evidence content/hash mismatch' in evidence, 'Coverage artifacts are not revalidated on evidence import')
    return dict(status='SourceContractsConsistent', qualification='NotRun', collector='Microsoft.CodeCoverage 17.14.1 via private SDK', format='cobertura')


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--root', type=Path, default=ROOT); a = p.parse_args()
    try: print(json.dumps(validate(a.root), indent=2)); return 0
    except (ValueError, OSError, KeyError, ET.ParseError) as error: print(str(error)); return 1


if __name__ == '__main__': raise SystemExit(main())
