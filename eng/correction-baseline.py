#!/usr/bin/env python3
"""Collect owned COR01 baseline evidence; never promote finding or review states."""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('evidence', ROOT / 'eng/check-correction-evidence.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)
coverage_spec = importlib.util.spec_from_file_location('coverage_contract', ROOT / 'eng/coverage-contract.py')
coverage = importlib.util.module_from_spec(coverage_spec)
coverage_spec.loader.exec_module(coverage)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def source_identity():
    total = hashlib.sha256()
    ignored = {'.git', '.docker', 'bin', 'obj', 'TestResults', '.artifacts', 'artifacts', '.correction-results', '__pycache__'}
    for path in sorted(ROOT.rglob('*')):
        if path.is_file() and not ignored.intersection(path.relative_to(ROOT).parts):
            total.update(path.relative_to(ROOT).as_posix().encode() + b'\0' + hashlib.sha256(path.read_bytes()).digest())
    return 'sha256:' + total.hexdigest()


def redact(text):
    for name, value in os.environ.items():
        if re.search(r'password|secret|token|connection|fixture_.*key', name, re.I) and len(value) >= 4:
            text = text.replace(value, '[REDACTED]')
    text = re.sub(r'(?i)((?:password|pwd|secret|access.?token|refresh.?token)\s*[=:]\s*)[^\s;\"<]+', r'\1[REDACTED]', text)
    text = re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[REDACTED-JWT]', text)
    return text


def terminate(process):
    if process.poll() is not None:
        return
    if os.name == 'nt':
        subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True, timeout=10)
    else:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=10)


def stage(command, directory, name, timeout):
    started = now()
    with tempfile.TemporaryFile() as raw:
        try:
            process = subprocess.Popen(command, cwd=ROOT, stdout=raw, stderr=subprocess.STDOUT,
                start_new_session=os.name != 'nt', creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
            try:
                exit_code = process.wait(timeout=timeout)
                reason = None if exit_code == 0 else 'Child process returned nonzero'
            except subprocess.TimeoutExpired:
                terminate(process)
                exit_code, reason = 124, 'Child process deadline exceeded; owned process tree terminated'
        except OSError:
            exit_code, reason = 127, 'Child executable could not start'
        raw.seek(0, 2)
        length = raw.tell()
        raw.seek(max(0, length - 1024 * 1024))
        output = redact(raw.read().decode('utf-8', errors='replace'))
    log = directory / (name + '.log')
    log.write_text(output, encoding='utf-8')
    return dict(name=name, command=command, started_at=started, completed_at=now(), exit_code=exit_code,
                reason=reason, log=log.relative_to(ROOT).as_posix(), log_truncated=length > 1024 * 1024)


def lane(name, directory, timeout, sql_filter, collect_coverage=False):
    result = dict(name=name, status='NotRun', reason='Lane not started', exit_code=None, stages=[], results=[])
    if not shutil.which('dotnet'):
        result.update(status='Blocked', reason='Required .NET SDK executable is unavailable')
        return result
    os.environ['TREEHAMMOCK_BUILD_RUN_ID'] = str(uuid.uuid4())
    os.environ['TREEHAMMOCK_BUILD_CONFIGURATION'] = 'Release'
    result['build_run_id'] = os.environ['TREEHAMMOCK_BUILD_RUN_ID']
    result['build_configuration'] = 'Release'
    is_sql = name.startswith('sql')
    if is_sql and (os.environ.get('TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS', '').lower() not in ('true', '1') or
                   not os.environ.get('TREEHAMMOCK_DB_CONTRACT_CONNECTION', '').strip()):
        result.update(status='Blocked', reason='Disposable PostgreSQL opt-in and connection are required')
        return result
    if name == 'system' and (os.environ.get('TREEHAMMOCK_CORRECTION_SYSTEM_OWNED') != 'true' or
                            not os.environ.get('TREEHAMMOCK_SYSTEM_BASE_URL')):
        result.update(status='Blocked', reason='System lane requires an explicitly owned isolated endpoint')
        return result
    if is_sql and (not os.environ.get('TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT') or
                   not os.environ.get('TREEHAMMOCK_CORRECTION_CACHE_PASSWORD')):
        result.update(status='Blocked', reason='Owned SQL/cache fixture environment is required for COR03 cache recovery')
        return result
    projects = ['treehammock.Tests/treehammock.Tests.csproj']
    if is_sql:
        projects = ['treehammock.Tests.SqlContracts/treehammock.Tests.SqlContracts.csproj']
    elif name == 'system':
        projects = ['treehammock.Tests.System/treehammock.Tests.System.csproj']
    tests = [('unit', 'FullyQualifiedName~treehammock.Tests.Unit'),
             ('integration', 'FullyQualifiedName~treehammock.Tests.Integration')] if name == 'fast' else \
            [(name, sql_filter if name == 'sql-harness' else None)]
    commands = [('restore', ['dotnet', 'restore', projects[0], '--locked-mode', '-p:Configuration=Release']),
                ('build', ['dotnet', 'build', projects[0], '--configuration', 'Release', '--no-restore', '-p:ContinuousIntegrationBuild=true'])]
    for test, test_filter in tests:
        test_directory = directory / test if collect_coverage else directory
        if collect_coverage:
            test_directory.mkdir(exist_ok=False)
        command = ['dotnet', 'test', projects[0], '--configuration', 'Release', '--no-build', '--no-restore',
                   '--results-directory', str(test_directory), '--logger', f'trx;LogFileName={test}.trx']
        if collect_coverage:
            command += ['--collect', coverage.COLLECTOR, '--settings', str(coverage.SETTINGS)]
        if test_filter:
            command += ['--filter', test_filter]
        commands.append((test, command))
    for label, command in commands:
        child = stage(command, directory, label, timeout)
        result['stages'].append(child)
        if child['exit_code'] != 0:
            result.update(status='Failed', reason=child['reason'], exit_code=child['exit_code'])
            # Preserve any test results emitted by a failing test command too.
            break
        if collect_coverage and label in [test for test, _ in tests]:
            try:
                trx_path = directory / label / (label + '.trx')
                if trx_path.is_file():
                    trx_path.write_text(redact(trx_path.read_text(encoding='utf-8')), encoding='utf-8')
                measurement = coverage.validate_results(directory / label, label + '.trx')
                result.setdefault('coverage', []).append(dict(lane=label, directory=(directory / label).relative_to(ROOT).as_posix(), **measurement))
            except (ValueError, OSError, coverage.ET.ParseError):
                result.update(status='Failed', reason='Coverage contract failed: missing or invalid fresh results', exit_code=1)
                break
    failed = result['status'] == 'Failed'
    for test, _ in tests:
        path = (directory / test if collect_coverage else directory) / (test + '.trx')
        if not path.is_file():
            if not failed:
                result.update(status='Failed', reason='Child succeeded but expected fresh TRX result is missing', exit_code=1)
            continue
        path.write_text(redact(path.read_text(encoding='utf-8')), encoding='utf-8')
        try:
            counts, _ = evidence.trx_counts(path)
            result['results'].append(dict(path=path.relative_to(ROOT).as_posix(), sha256=evidence.digest(path), counts=counts))
            if not failed and (counts['total'] == 0 or counts['executed'] != counts['total'] or counts['passed'] != counts['total']):
                result.update(status='Failed', reason='Zero discovery, failed, skipped or incomplete test execution', exit_code=1)
        except (ValueError, evidence.ET.ParseError):
            if failed:
                continue
            result.update(status='Failed', reason='Malformed TRX test results', exit_code=1)
    if result['status'] != 'Failed':
        result.update(status='Passed', reason=None, exit_code=0)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=['all', 'fast', 'sql-harness', 'sql', 'system'], default='all')
    parser.add_argument('--output', type=Path, default=ROOT / '.correction-results')
    parser.add_argument('--configuration', choices=['Release'], default='Release')
    parser.add_argument('--locked-restore', action='store_true', help='Accepted for compatibility; locked restore is always required')
    parser.add_argument('--collect-coverage', action='store_true', help='Require fresh validated Cobertura for each fast lane')
    parser.add_argument('--stage-timeout', type=int, default=600)
    args = parser.parse_args()
    if args.collect_coverage and args.lane != 'fast':
        parser.error('Coverage is supported only for the fast unit/integration lanes')
    if args.stage_timeout < 1 or args.stage_timeout > 3600:
        parser.error('Stage timeout must be between 1 and 3600 seconds')
    output = args.output.resolve()
    if not output.is_relative_to(ROOT) or output == ROOT:
        parser.error('Evidence output must be a dedicated directory below the project root')
    # Generated outputs must not change the source identity across repeated runs.
    if not output.is_relative_to(ROOT / '.correction-results') and not output.is_relative_to(ROOT / '.artifacts'):
        parser.error('Output must be under .correction-results or .artifacts')
    run_id = str(uuid.uuid4())
    directory = output / run_id
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.environ['TREEHAMMOCK_CORRECTION_RUN_ID'] = run_id
    started = now()
    run = dict(schema_version=1, evidence_kind='executed-tooling', run_id=run_id, source_identity=source_identity(),
        original_archive_sha256=evidence.ARCHIVE_SHA, configuration='Release', collect_coverage=args.collect_coverage, started_at=started,
        platform=platform.platform(), runtime_versions={'python': platform.python_version(),
            'postgres_image_id': os.environ.get('TREEHAMMOCK_CORRECTION_DB_IMAGE_ID'),
            'cache_image_id': os.environ.get('TREEHAMMOCK_CORRECTION_CACHE_IMAGE_ID')}, lanes=[])
    try:
        evidence.validate(ROOT)
    except (ValueError, KeyError, OSError) as error:
        run['lanes'] = [dict(name='integrity', status='Failed', reason=redact(str(error)), exit_code=1, stages=[], results=[])]
    else:
        if shutil.which('dotnet'):
            version_stage = stage(['dotnet', '--version'], directory, 'sdk-version', min(30, args.stage_timeout))
            if version_stage['exit_code'] == 0:
                run['runtime_versions']['dotnet'] = (directory / 'sdk-version.log').read_text(encoding='utf-8').strip()
        names = ['fast', 'sql-harness', 'sql', 'system'] if args.lane == 'all' else [args.lane]
        sql_filter = 'FullyQualifiedName~SqlContractFixtureTests|FullyQualifiedName~SessionConcurrencyProcedureContractTests|FullyQualifiedName~Cor02TransactionAuthorityTests|FullyQualifiedName~Cor02MigrationTests|FullyQualifiedName~Cor03DependencySqlTests|FullyQualifiedName~Cor03CacheRecoveryTests|FullyQualifiedName~Cor04SecurityOperationTests|FullyQualifiedName~Cor05AtomicCounterTests|FullyQualifiedName~Cor06ReplayLeaseTests|FullyQualifiedName~Cor06DurableReplayTests|FullyQualifiedName~Cor07PasswordCostTests|FullyQualifiedName~Cor08AttemptAndGrantTests|FullyQualifiedName~Cor09SessionFamilyTests|FullyQualifiedName~Cor09RefreshHttpTests|FullyQualifiedName~Cor10LoginProofTests|FullyQualifiedName~Cor10PendingProofCacheTests|FullyQualifiedName~Cor11RegistrationAndUnlockTests|FullyQualifiedName~Cor12DeliveryOutboxTests|FullyQualifiedName~Cor13ResetAuthorizationTests|FullyQualifiedName~Cor15TotpKeyRotationTests|FullyQualifiedName~Cor16FactorEnrollmentTests|FullyQualifiedName~Cor17EmailChangeTests|FullyQualifiedName~Cor18DeleteAuthorityTests|FullyQualifiedName~Cor19TrustedActivationTests|FullyQualifiedName~Cor20EntitlementTests|FullyQualifiedName~Cor22RetentionTests|FullyQualifiedName~Cor21ActivationCreationTests|FullyQualifiedName~ActivationProcedureContractTests|FullyQualifiedName~Cor23AActivationReaderTests|FullyQualifiedName~Cor23BSqlBindingTests|FullyQualifiedName~Cor23CFactorIdentityTests|FullyQualifiedName~Cor23DTestCapabilityHttpTests|FullyQualifiedName~Cor23MAbuseBudgetTests|FullyQualifiedName~Cor23NCacheOwnershipTests|FullyQualifiedName~Cor23OReadinessBudgetTests|FullyQualifiedName~Cor23PTransitionMetricsTests|FullyQualifiedName~Cor23AFAuthenticatorReplacementTests|FullyQualifiedName~SessionCacheWarmupSqlTests'
        for name in names:
            lane_dir = directory / name
            lane_dir.mkdir(mode=0o700)
            print(f'Running {name} baseline lane (run {run_id})', flush=True)
            item = lane(name, lane_dir, args.stage_timeout, sql_filter, args.collect_coverage)
            run['lanes'].append(item)
            print(f'{name}: {item["status"]}', flush=True)
        if not run['runtime_versions'].get('dotnet'):
            for item in run['lanes']:
                if item['status'] == 'Passed':
                    item.update(status='Failed', reason='Resolved SDK version could not be recorded', exit_code=1)
    statuses = [x['status'] for x in run['lanes']]
    run['status'] = 'Failed' if 'Failed' in statuses else 'Blocked' if 'Blocked' in statuses else 'Passed'
    run['completed_at'] = now()
    path = directory / 'run.json'
    path.write_text(json.dumps(run, indent=2) + '\n', encoding='utf-8')
    evidence.validate_run(ROOT, run)
    print(f'Baseline {run["status"]}; evidence: {path.relative_to(ROOT)}')
    return 0 if run['status'] == 'Passed' else 2 if run['status'] == 'Blocked' else 1


if __name__ == '__main__':
    sys.exit(main())
