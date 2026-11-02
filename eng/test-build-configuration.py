#!/usr/bin/env python3
"""Real SDK/host/Docker configuration qualification; no runtime emulation."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('identity', ROOT / 'eng/build-identity.py')
identity = importlib.util.module_from_spec(spec); spec.loader.exec_module(identity)
CONFIGURATIONS = ['Debug', 'Release', 'Sandbox']
CASES = ['clean-fast-lanes-loaded-identity', 'new-run-rejects-stale-output',
         'missing-output-rejected', 'wrong-application-copy-rejected',
         'owned-sql-wrapper-loaded-identity', 'system-project-loaded-identity', 'docker-unit-configuration']


def wrapper(host, name, configuration, extra=None):
    if host == 'bash': return [host, f'eng/{name}.sh', '--configuration', configuration] + (extra or [])
    return [host, '-NoProfile', '-File', f'eng/{name}.ps1', '-Configuration', configuration] + (extra or [])


def run(command, cwd, log, env=None, must_fail=False):
    with log.open('w') as output:
        child = subprocess.run(command, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT)
    if (child.returncode == 0) == must_fail:
        raise ValueError('Unexpected native outcome: ' + log.name)
    return child.returncode


def complete_tests(path, minimum=1):
    counts = ET.parse(path).find('.//t:Counters', {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'})
    if counts is None or int(counts.get('total', '0')) < minimum or any(counts.get(k) != counts.get('total') for k in ['executed', 'passed']) or any(int(counts.get(k, '0')) != 0 for k in ['failed', 'notExecuted']):
        raise ValueError('Real configuration lane has zero, failing, skipped or incomplete discovery')


def run_owned_unit(host, configuration, checkout, log, saved):
    """The wrapper owns image naming/deletion; retain its fresh public receipts even on failure."""
    parent = checkout / 'artifacts/test-runs'
    previous = set(parent.glob('*/run.json'))
    extra = ['--no-cache'] if host == 'bash' else ['-NoCache']
    command = wrapper(host, 'docker-unit-tests', configuration, extra)
    outcome = dict(command=command, configuration=configuration, status='Failed', receipts=[], errors=[])
    primary = None
    try:
        with log.open('w') as output:
            outcome['wrapper_exit_code'] = subprocess.run(command, cwd=checkout, stdout=output,
                stderr=subprocess.STDOUT).returncode
    except OSError as error:
        primary = error
        outcome['errors'].append(type(error).__name__)
    fresh = sorted(set(parent.glob('*/run.json')) - previous)
    try:
        if len(fresh) != 1:
            raise ValueError('Exactly one fresh owned unit run receipt is required')
        path = fresh[0]
        values = {}
        for name in ['run.json', 'cleanup.json']:
            receipt = path.parent / name
            if parent.is_symlink() or path.parent.is_symlink() or receipt.is_symlink() or receipt.stat().st_size > 65536:
                raise ValueError('Linked or oversized owned unit receipt')
            data = receipt.read_bytes()
            target = saved / ('docker-owned-' + name)
            target.write_bytes(data)
            outcome['receipts'].append(target.name)
            values[name] = json.loads(data)
        record, clean = values['run.json'], values['cleanup.json']
        run_id = record['run_id']
        if str(uuid.UUID(run_id)) != run_id or path.parent.name != run_id:
            raise ValueError('Owned unit receipt identity differs from its fresh result directory')
        if (record.get('schema_version') != 1 or record.get('lane') != 'docker-unit-tests'
            or record.get('project') != 'treehammock-test-' + run_id.replace('-', '')
            or record.get('ownership') != 'Disposable'
            or record.get('unit_image') != record['project'] + '-unit:owned'):
            raise ValueError('Owned unit lane, project or assigned image mismatch')
        outcome.update(run_id=run_id, unit_image=record['unit_image'], cleanup=clean)
        if (record.get('exit_code') != 0 or record.get('status') != 'Passed' or record.get('cleanup') != 'Passed'
            or clean.get('status') != 'Passed' or clean.get('failures') != []
            or clean.get('budget_exhausted') is not False or clean.get('retained', False)
            or not any(row.get('kind') == 'image' and row.get('resource') for row in clean.get('removed', []))):
            raise ValueError('Owned unit build or image/process cleanup did not pass')
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        outcome['errors'].append(str(error))
        primary = primary or error
    if outcome.get('wrapper_exit_code') != 0:
        message = 'Owned unit wrapper failed (exit ' + str(outcome.get('wrapper_exit_code')) + ')'
        outcome['errors'].insert(0, message)
        primary = ValueError(message) if primary is None else primary
    if primary is None:
        outcome['status'] = 'Passed'
    (saved / 'docker-owned-unit.json').write_text(json.dumps(outcome, indent=2) + '\n')
    if primary is not None:
        raise ValueError('; '.join(outcome['errors'])) from primary
    return outcome


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host', choices=['bash', 'pwsh', 'powershell.exe'], required=True)
    p.add_argument('--output', type=Path, default=ROOT / '.artifacts/configuration-qualification')
    a = p.parse_args(); output = a.output.resolve() / str(uuid.uuid4()); output.mkdir(parents=True, exist_ok=False)
    report = dict(status='Blocked', qualification='NotRun', host=a.host, configurations=CONFIGURATIONS, required_cases=CASES, cases=[])
    missing = [tool for tool in ['dotnet', a.host, 'docker'] if not shutil.which(tool)]
    if missing: report['reason'] = 'Required native runtime unavailable: ' + ', '.join(missing)
    else:
        report.update(status='Failed', qualification='Attempted')
        try:
            with tempfile.TemporaryDirectory(prefix='cor23s real checkout with spaces ') as temp:
                checkout = Path(temp) / 'checkout'
                shutil.copytree(ROOT, checkout, ignore=shutil.ignore_patterns('.git', 'bin', 'obj', '.artifacts', '.correction-results', 'TestResults', '__pycache__'))
                for script in (checkout / 'eng').glob('*.sh'): script.chmod(0o700)
                previous_ids, previous_mvids = set(), set()
                for configuration in CONFIGURATIONS:
                    # Each advertised configuration must work with no previous binaries.
                    for project in [checkout, checkout / 'treehammock.Tests', checkout / 'treehammock.Tests.SqlContracts', checkout / 'treehammock.Tests.System']:
                        for name in ['bin', 'obj', 'TestResults']: shutil.rmtree(project / name, ignore_errors=True)
                    extra = ['--locked-restore'] if a.host == 'bash' else ['-LockedRestore']
                    run(wrapper(a.host, 'validate', configuration, extra), checkout, output / (configuration + '-fast.log'))
                    binary_dir = checkout / 'treehammock.Tests/bin' / configuration / 'net8.0'
                    evidence = identity.validate(binary_dir / 'treehammock.Tests.identity.json', configuration, 'treehammock.Tests')
                    mvid = next(x['mvid'] for x in evidence['assemblies'] if x['name'] == 'treehammock.Tests')
                    if evidence['run_id'] in previous_ids or mvid in previous_mvids: raise ValueError('A previous build identity was reused')
                    previous_ids.add(evidence['run_id']); previous_mvids.add(mvid)
                    saved = output / configuration; saved.mkdir()
                    for name in ['treehammock.Tests.identity.json', 'treehammock.Tests.dll', 'treehammock.Tests.dll.proof-id', 'treehammock.dll']:
                        shutil.copy2(binary_dir / name, saved / name)
                    trx_paths = list((checkout / 'treehammock.Tests').rglob('treehammock-*-tests.trx'))
                    if len(trx_paths) != 2: raise ValueError('Both fresh fast-lane TRX results are required')
                    for trx in trx_paths:
                        complete_tests(trx)
                        shutil.copy2(trx, saved / trx.name)
                    report['cases'].append(dict(name='clean-fast-lanes-loaded-identity', configuration=configuration, status='Passed', loaded=evidence))
                    command = ['dotnet', 'test', 'treehammock.Tests/treehammock.Tests.csproj', '--configuration', configuration, '--no-build', '--no-restore', '--filter', 'FullyQualifiedName~Cor23SBuildIdentityTests']
                    env = dict(os.environ, TREEHAMMOCK_BUILD_RUN_ID=str(uuid.uuid4()), TREEHAMMOCK_BUILD_CONFIGURATION=configuration)
                    run(command, checkout, output / (configuration + '-stale.log'), env, must_fail=True)
                    report['cases'].append(dict(name='new-run-rejects-stale-output', configuration=configuration, status='Passed'))
                    env['TREEHAMMOCK_BUILD_RUN_ID'] = evidence['run_id']
                    binary = binary_dir / 'treehammock.Tests.dll'; data = binary.read_bytes(); binary.unlink()
                    try: run(command, checkout, output / (configuration + '-missing.log'), env, must_fail=True)
                    finally: binary.write_bytes(data)
                    report['cases'].append(dict(name='missing-output-rejected', configuration=configuration, status='Passed'))
                    # Correct test receipt/assembly with an application from an
                    # earlier invocation must fail in the actual module initializer.
                    if configuration != 'Debug':
                        app = binary_dir / 'treehammock.dll'; data = app.read_bytes()
                        app.write_bytes((output / 'Debug/treehammock.dll').read_bytes())
                        marker = binary_dir / 'treehammock.Tests.identity.json'; marker.unlink()
                        try:
                            run(command, checkout, output / (configuration + '-wrong-app.log'), env, must_fail=True)
                            if marker.exists(): raise ValueError('Wrong application was accepted by the module initializer')
                        finally: app.write_bytes(data)
                        report['cases'].append(dict(name='wrong-application-copy-rejected', configuration=configuration, status='Passed'))
                    run([sys.executable, 'eng/correction-sql-fixture.py', '--configuration-host', a.host, '--configuration', configuration], checkout, output / (configuration + '-sql.log'))
                    sql_dir = checkout / 'treehammock.Tests.SqlContracts/bin' / configuration / 'net8.0'
                    sql = identity.validate(sql_dir / 'treehammock.Tests.SqlContracts.identity.json', configuration, 'treehammock.Tests.SqlContracts')
                    sql_trx = list((checkout / 'treehammock.Tests.SqlContracts').rglob('treehammock-sql-contracts.trx'))
                    if len(sql_trx) != 1: raise ValueError('Fresh SQL TRX missing')
                    complete_tests(sql_trx[0], minimum=2)
                    shutil.copy2(sql_trx[0], saved / sql_trx[0].name)
                    (saved / 'sql-loaded-identity.json').write_text(json.dumps(sql, indent=2))
                    fixture_reports = list((checkout / '.correction-results').glob('fixture-*/fixture.json'))
                    if not fixture_reports: raise ValueError('Owned SQL fixture evidence missing')
                    fixture = json.loads(max(fixture_reports, key=lambda x: x.stat().st_mtime).read_text())
                    if fixture['status'] != 'Passed' or fixture['cleanup']['exit_code'] != 0: raise ValueError('Owned SQL fixture/cleanup did not pass')
                    (saved / 'sql-fixture.json').write_text(json.dumps(fixture, indent=2))
                    report['cases'].append(dict(name='owned-sql-wrapper-loaded-identity', configuration=configuration, status='Passed'))
                    env = dict(os.environ, TREEHAMMOCK_BUILD_RUN_ID=str(uuid.uuid4()), TREEHAMMOCK_BUILD_CONFIGURATION=configuration)
                    system_project = 'treehammock.Tests.System/treehammock.Tests.System.csproj'
                    run(['dotnet', 'restore', system_project, '--locked-mode', '-p:Configuration=' + configuration], checkout, output / (configuration + '-system-restore.log'), env)
                    run(['dotnet', 'build', system_project, '--configuration', configuration, '--no-restore'], checkout, output / (configuration + '-system-build.log'), env)
                    run(['dotnet', 'test', system_project, '--configuration', configuration, '--no-build', '--no-restore', '--filter', 'FullyQualifiedName~BuildIdentityProbe', '--logger', 'trx;LogFileName=system-build-identity.trx'], checkout, output / (configuration + '-system-test.log'), env)
                    system_trx = list((checkout / 'treehammock.Tests.System').rglob('system-build-identity.trx'))
                    if len(system_trx) != 1: raise ValueError('Fresh system probe TRX missing')
                    complete_tests(system_trx[0])
                    shutil.copy2(system_trx[0], saved / system_trx[0].name)
                    system_dir = checkout / 'treehammock.Tests.System/bin' / configuration / 'net8.0'
                    system = identity.validate(system_dir / 'treehammock.Tests.System.identity.json', configuration, 'treehammock.Tests.System')
                    (saved / 'system-loaded-identity.json').write_text(json.dumps(system, indent=2))
                    report['cases'].append(dict(name='system-project-loaded-identity', configuration=configuration, status='Passed'))
                    owned_unit = run_owned_unit(a.host, configuration, checkout, output / (configuration + '-docker.log'), saved)
                    report['cases'].append(dict(name='docker-unit-configuration', configuration=configuration, status='Passed', owned_run=owned_unit))
            report.update(status='Passed', qualification='Passed', reason=None)
        except (ValueError, OSError, KeyError, ET.ParseError) as error: report['reason'] = str(error)
    (output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(status=report['status'], qualification=report['qualification'], report=str(output / 'qualification.json'))))
    return 0 if report['status'] == 'Passed' else 2 if report['status'] == 'Blocked' else 1


if __name__ == '__main__': raise SystemExit(main())
