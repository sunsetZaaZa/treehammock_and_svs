#!/usr/bin/env python3
"""Own a unique loopback PostgreSQL/cache Compose fixture, run the harness, and remove only it."""
import argparse
import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('baseline', ROOT / 'eng/correction-baseline.py')
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


def compose_command(project, cache_product):
    if cache_product not in {'redis', 'dragonfly'}:
        raise ValueError('Unsupported owned cache fixture product')
    command = ['docker', 'compose', '-p', project, '-f', str(ROOT / 'docker-compose.corrections.yml')]
    if cache_product == 'dragonfly':
        command += ['-f', str(ROOT / 'docker-compose.corrections.dragonfly.yml')]
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache-product', choices=['redis', 'dragonfly'], default='redis')
    parser.add_argument('--authenticator-replacement', action='store_true', help='Run COR23AF actual repository/service and native predecessor mutation in this owned fixture')
    parser.add_argument('--configuration-host', choices=['bash', 'pwsh', 'powershell.exe'])
    parser.add_argument('--configuration', choices=['Debug', 'Release', 'Sandbox'], default='Release')
    args = parser.parse_args()
    if args.authenticator_replacement and (args.configuration_host or args.configuration != 'Release'):
        parser.error('Authenticator replacement qualification requires the Release native runner')
    if not args.configuration_host and args.configuration != 'Release':
        parser.error('Alternate configurations require an explicit configuration-host wrapper')
    identity = str(uuid.uuid4())
    project = 'cor01-' + identity
    directory = ROOT / '.correction-results' / ('fixture-' + identity)
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.environ['TREEHAMMOCK_CORRECTION_PROJECT'] = project
    os.environ['TREEHAMMOCK_CORRECTION_DB_PASSWORD'] = secrets.token_hex(32)
    os.environ['TREEHAMMOCK_CORRECTION_CACHE_PASSWORD'] = secrets.token_hex(32)
    compose = compose_command(project, args.cache_product)
    report = dict(schema_version=1, fixture_id=identity, project=project, source_identity=baseline.source_identity(), started_at=baseline.now(),
                  status='Blocked', reason=None, image_id=None, cache_product=args.cache_product, stages=[], cleanup=None)
    started = False
    code = 2
    try:
        if not shutil.which('docker') or not shutil.which('dotnet'):
            report['reason'] = 'Docker CLI and .NET SDK are required for the owned SQL/cache fixture'
            return code
        isolation_spec=importlib.util.spec_from_file_location('fixture_isolation',ROOT/'eng/fixture-isolation.py')
        isolation=importlib.util.module_from_spec(isolation_spec);isolation_spec.loader.exec_module(isolation)
        try:isolation.check_host('published',os.environ)
        except (ValueError,OSError,subprocess.SubprocessError):
            report['reason']='Owned loopback fixture requires local Docker Engine 28 or newer'
            return code
        host = subprocess.run(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'],
                              capture_output=True, text=True, timeout=10)
        endpoint = os.environ.get('DOCKER_HOST') or host.stdout.strip()
        if host.returncode != 0 or not endpoint.startswith(('unix://', 'npipe://')):
            report['reason'] = 'Owned loopback fixture requires a local Docker engine'
            return code
        report['stages'].append(baseline.stage(['docker', 'version'], directory, 'docker-version', 20))
        if report['stages'][-1]['exit_code'] != 0:
            report['reason'] = 'Local Docker engine is unavailable'
            return code
        report['stages'].append(baseline.stage(compose + ['version'], directory, 'compose-version', 20))
        if report['stages'][-1]['exit_code'] != 0:
            report['reason'] = 'Docker Compose is unavailable'
            return code
        # Ownership is established before up, so partial startup is also torn down.
        started = True
        report['stages'].append(baseline.stage(compose + ['up', '-d', '--wait', '--wait-timeout', '60'], directory, 'start', 90))
        if report['stages'][-1]['exit_code'] != 0:
            report.update(status='Failed', reason='Owned PostgreSQL fixture failed to start')
            code = 1
            return code
        port = subprocess.run(compose + ['port', 'postgres', '5432'], capture_output=True, text=True, timeout=10)
        address = port.stdout.strip()
        if port.returncode != 0 or not address.startswith('127.0.0.1:') or not address.split(':')[-1].isdigit():
            report.update(status='Failed', reason='Owned PostgreSQL listener could not be resolved on loopback')
            code = 1
            return code
        image = subprocess.run(compose + ['images', '-q', 'postgres'], capture_output=True, text=True, timeout=10)
        if image.returncode != 0 or not image.stdout.strip():
            report.update(status='Failed', reason='Resolved PostgreSQL image identity is missing')
            code = 1
            return code
        inspected = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', image.stdout.strip()],
                                   capture_output=True, text=True, timeout=10)
        if inspected.returncode != 0 or not inspected.stdout.strip().startswith('sha256:'):
            report.update(status='Failed', reason='Immutable PostgreSQL image identity could not be recorded')
            code = 1
            return code
        report['image_id'] = inspected.stdout.strip()
        cache_port = subprocess.run(compose + ['port', 'cache', '6379'], capture_output=True, text=True, timeout=10)
        cache_address = cache_port.stdout.strip()
        if cache_port.returncode != 0 or not cache_address.startswith('127.0.0.1:') or not cache_address.split(':')[-1].isdigit():
            report.update(status='Failed', reason='Owned cache listener could not be resolved on loopback')
            code = 1
            return code
        cache_image = subprocess.run(compose + ['images', '-q', 'cache'], capture_output=True, text=True, timeout=10)
        cache_inspected = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', cache_image.stdout.strip()],
                                        capture_output=True, text=True, timeout=10)
        if cache_image.returncode != 0 or cache_inspected.returncode != 0 or not cache_inspected.stdout.strip().startswith('sha256:'):
            report.update(status='Failed', reason='Immutable cache image identity could not be recorded')
            code = 1
            return code
        report['cache_image_id'] = cache_inspected.stdout.strip()
        os.environ['TREEHAMMOCK_CORRECTION_CACHE_IMAGE_ID'] = report['cache_image_id']
        os.environ['TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT'] = cache_address
        os.environ['TREEHAMMOCK_CORRECTION_DB_IMAGE_ID'] = report['image_id']
        os.environ['TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS'] = 'true'
        os.environ['TREEHAMMOCK_DB_CONTRACT_CONNECTION'] = (
            f'Host=127.0.0.1;Port={address.split(":")[-1]};Database=treehammock_correction;'
            'Username=treehammock_correction;Password=' + os.environ['TREEHAMMOCK_CORRECTION_DB_PASSWORD'])
        if args.authenticator_replacement:
            command = [sys.executable, str(ROOT / 'eng/test-authenticator-replacement.py'), '--output', str(directory / 'cor23af-native.json')]
        elif args.configuration_host == 'bash':
            command = ['bash', str(ROOT / 'eng/sql-contracts.sh'), '--locked-restore', '--configuration', args.configuration]
        elif args.configuration_host:
            command = [args.configuration_host, '-NoProfile', '-File', str(ROOT / 'eng/sql-contracts.ps1'), '-LockedRestore', '-Configuration', args.configuration]
        else:
            command = [sys.executable, str(ROOT / 'eng/correction-baseline.py'), '--lane', 'sql-harness']
        report['configuration'] = args.configuration
        report['configuration_host'] = args.configuration_host
        report['authenticator_replacement'] = args.authenticator_replacement
        child = baseline.stage(command,
                               directory, 'harness', 900)
        report['stages'].append(child)
        code = child['exit_code']
        report.update(status='Passed' if code == 0 else 'Blocked' if code == 2 else 'Failed',
                      reason=None if code == 0 else 'See the owned baseline run for the harness outcome')
    except (OSError, subprocess.TimeoutExpired, ValueError):
        code = 1
        report.update(status='Failed', reason='Owned fixture orchestration failed or exceeded its deadline')
    finally:
        if started:
            cleanup = baseline.stage(compose + ['down', '--volumes', '--timeout', '5'], directory, 'cleanup', 30)
            report['cleanup'] = cleanup
            if cleanup['exit_code'] != 0:
                code = 1
                report.update(status='Failed', reason='Owned fixture cleanup failed; only this project may be retried')
        report['completed_at'] = baseline.now()
        report['owned_resources_started'] = started
        (directory / 'fixture.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(f'SQL fixture {report["status"]}; evidence: {directory.relative_to(ROOT)}/fixture.json')
    return code


if __name__ == '__main__':
    sys.exit(main())
