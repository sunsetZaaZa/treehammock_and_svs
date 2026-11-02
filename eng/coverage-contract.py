#!/usr/bin/env python3
"""Run VSTest coverage and reject missing, empty or unrelated measurements."""
import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = 'Code Coverage;Format=cobertura'
SETTINGS = ROOT / 'eng/coverage.runsettings'


def xml(path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 100 * 1024 * 1024:
        raise ValueError('Missing, empty or oversized result')
    data = path.read_bytes()
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise ValueError('Result must not declare external entities')
    return ET.fromstring(data)


def integer(value):
    if value is None or not value.isdecimal():
        raise ValueError('Missing or invalid measurement')
    return int(value)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def coverage_arguments(directory, settings=SETTINGS):
    return ['--collect', COLLECTOR, '--settings', str(settings), '--results-directory', str(directory)]


def validate_results(directory, trx_name, expected_package='treehammock'):
    """The caller owns a newly created directory used by exactly one test process."""
    directory = Path(directory)
    trx = directory / trx_name
    test = xml(trx)
    ns = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
    counters = test.find('t:ResultSummary/t:Counters', ns)
    if counters is None:
        raise ValueError('TRX counters are missing')
    counts = {k: integer(counters.get(k)) for k in ['total', 'executed', 'passed', 'failed', 'notExecuted']}
    results = test.findall('t:Results/t:UnitTestResult', ns)
    if (counts['total'] == 0 or counts['executed'] != counts['total'] or
        counts['passed'] != counts['total'] or counts['failed'] != 0 or counts['notExecuted'] != 0 or
        len(results) != counts['total'] or any(r.get('outcome') != 'Passed' for r in results)):
        raise ValueError('Zero discovery, failed, skipped or incomplete tests')
    artifacts = sorted(directory.rglob('*.cobertura.xml'))
    if len(artifacts) != 1:
        raise ValueError('Expected exactly one fresh Cobertura artifact; collector may be unavailable')
    path = artifacts[0]
    if not path.resolve().is_relative_to(directory.resolve()) or any(p.is_symlink() for p in path.parents if p != directory.parent):
        raise ValueError('Coverage artifact escapes its owned directory')
    report = xml(path)
    if report.tag != 'coverage':
        raise ValueError('Wrong coverage format')
    valid, covered = integer(report.get('lines-valid')), integer(report.get('lines-covered'))
    if valid == 0 or covered == 0 or covered > valid:
        raise ValueError('Coverage must contain executable and covered application lines')
    packages = report.findall('packages/package')
    # Microsoft Cobertura uses assembly names as packages. Test/dependency-only
    # reports cannot substitute for the selected application module.
    wanted = [p for p in packages if p.get('name') in [expected_package, expected_package + '.dll']]
    if len(wanted) != 1 or len(packages) != 1:
        raise ValueError('Coverage must measure only the expected application assembly')
    classes = wanted[0].findall('classes/class')
    lines = [line for c in classes for line in c.findall('lines/line')]
    if not classes or not lines or any(not c.get('filename') or not c.get('name') for c in classes):
        raise ValueError('Coverage has no source/class measurements')
    measured = {}
    for c in classes:
        for line in c.findall('lines/line'):
            number, hits = integer(line.get('number')), integer(line.get('hits'))
            if number == 0:
                raise ValueError('Coverage source line must be positive')
            key = (c.get('filename'), number)
            measured[key] = max(measured.get(key, 0), hits)
    if valid != len(measured) or covered != sum(h > 0 for h in measured.values()):
        raise ValueError('Coverage summary disagrees with source line measurements')
    return dict(format='cobertura', collector=COLLECTOR, package=expected_package,
        artifact=path.relative_to(directory).as_posix(), sha256=digest(path),
        lines_valid=valid, lines_covered=covered, tests=counts,
        trx=trx_name, trx_sha256=digest(trx))


def run_test(command, directory, settings=SETTINGS, expected_package='treehammock', cwd=ROOT):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    trx_name = 'tests.trx'
    args = command + ['--logger', 'trx;LogFileName=' + trx_name] + coverage_arguments(directory, settings)
    manifest = dict(schema_version=1, run_id=str(uuid.uuid4()), requested=True,
        command=args, expected_package=expected_package, settings_sha256=None,
        started_at=dt.datetime.now(dt.timezone.utc).isoformat(), status='Failed', coverage=None)
    try:
        if not Path(settings).is_file():
            raise ValueError('Coverage settings are missing')
        manifest['settings_sha256'] = digest(settings)
        code = subprocess.run(args, cwd=cwd).returncode
        manifest['test_exit_code'] = code
        if code != 0:
            manifest['reason'] = 'Test process failed; original exit code preserved'
        else:
            manifest['coverage'] = validate_results(directory, trx_name, expected_package)
            manifest.update(status='Passed', reason=None)
    except OSError:
        code = 127
        manifest['reason'] = 'Coverage test process could not start'
    except (ValueError, ET.ParseError):
        code = 1
        manifest['reason'] = 'Coverage contract failed: missing or invalid fresh test/coverage results'
    manifest.update(exit_code=code, completed_at=dt.datetime.now(dt.timezone.utc).isoformat())
    (directory / 'coverage-run.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(f'Coverage {manifest["status"]}: {directory / "coverage-run.json"}', flush=True)
    return code, manifest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lane', choices=['unit', 'integration'], required=True)
    p.add_argument('--configuration', choices=['Debug', 'Release', 'Sandbox'], default='Release')
    p.add_argument('--output', type=Path, default=ROOT / '.artifacts/coverage')
    a = p.parse_args()
    output = a.output.resolve()
    if not any(output.is_relative_to(ROOT / n) for n in ['.artifacts', '.correction-results']):
        p.error('Coverage output must be below .artifacts or .correction-results')
    try:
        uuid.UUID(os.environ.get('TREEHAMMOCK_BUILD_RUN_ID', ''))
    except ValueError:
        p.error('Coverage no-build requires an owned current build; use the unit/integration/validate wrapper')
    if os.environ.get('TREEHAMMOCK_BUILD_CONFIGURATION') != a.configuration:
        p.error('Coverage configuration differs from the owned current build')
    command = ['dotnet', 'test', 'treehammock.Tests/treehammock.Tests.csproj', '--configuration', a.configuration,
        '--no-build', '--no-restore', '--filter', 'FullyQualifiedName~treehammock.Tests.' + a.lane.capitalize()]
    code, _ = run_test(command, output / str(uuid.uuid4()) / a.lane)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
