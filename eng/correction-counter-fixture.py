#!/usr/bin/env python3
"""COR05 real Redis/Dragonfly scripts, client loss and server restart qualification."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('baseline', ROOT / 'eng/correction-baseline.py')
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)
spec = importlib.util.spec_from_file_location('contracts', ROOT / 'eng/validate-counter-contracts.py')
contracts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contracts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--captcha', action='store_true', help='Qualify COR14 CAPTCHA nonce scripts and native store contracts')
    parser.add_argument('--replay', action='store_true', help='Qualify COR06 replay scripts/native lease fences instead of COR05 counters')
    args = parser.parse_args()
    if args.replay and args.captcha: parser.error('Choose one cache qualification lane')
    pr = 'COR14' if args.captcha else 'COR06' if args.replay else 'COR05'
    contract_file = 'validate-captcha-contracts.py' if args.captcha else 'validate-replay-contracts.py' if args.replay else 'validate-counter-contracts.py'
    native_class = 'Cor14CaptchaNonceContractTests' if args.captcha else 'Cor06ReplayLeaseTests' if args.replay else 'Cor05AtomicCounterTests'
    identity = pr.lower() + '-' + uuid.uuid4().hex
    directory = ROOT / '.correction-results' / identity
    directory.mkdir(parents=True, mode=0o700)
    os.environ['TREEHAMMOCK_CORRECTION_PROJECT'] = identity
    os.environ['TREEHAMMOCK_CORRECTION_CACHE_PASSWORD'] = secrets.token_hex(32)
    compose = ['docker', 'compose', '-p', identity, '-f', str(ROOT / 'docker-compose.counter-fixture.yml')]
    report = dict(pr=pr, source_identity=baseline.source_identity(), project=identity,
                  started_at=baseline.now(), status='Blocked', reason=None, servers=[], cleanup=None,
                  owned_resources_started=False)
    code = 2
    try:
        if not shutil.which('docker'):
            report['reason'] = 'Docker CLI is required for the pinned real cache matrix'
            return code
        isolation_spec=importlib.util.spec_from_file_location('fixture_isolation',ROOT/'eng/fixture-isolation.py')
        isolation=importlib.util.module_from_spec(isolation_spec);isolation_spec.loader.exec_module(isolation)
        try:isolation.check_host('published',os.environ)
        except (ValueError,OSError,subprocess.SubprocessError):
            report['reason']='Owned loopback fixture requires local Docker Engine 28 or newer'
            return code
        context = subprocess.run(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'],
                                 capture_output=True, text=True, timeout=10)
        endpoint = os.environ.get('DOCKER_HOST') or context.stdout.strip()
        if context.returncode or not endpoint.startswith(('unix://', 'npipe://')):
            report['reason'] = 'Owned loopback fixture requires a local Docker engine'
            return code
        report['owned_resources_started'] = True
        stage = baseline.stage(compose + ['up', '-d', '--wait', '--wait-timeout', '45'], directory, 'start', 60)
        report['start'] = stage
        if stage['exit_code']:
            report.update(status='Failed', reason='Pinned cache fixture failed to start')
            code = 1
            return code
        for service in ('redis', 'dragonfly'):
            port = subprocess.run(compose + ['port', service, '6379'], capture_output=True, text=True, timeout=10)
            address = port.stdout.strip()
            if port.returncode or not address.startswith('127.0.0.1:') or not address.rsplit(':', 1)[1].isdigit():
                raise ValueError('Owned cache loopback listener could not be resolved')
            os.environ['TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT'] = address
            image = subprocess.run(compose + ['images', '-q', service], capture_output=True, text=True, timeout=10)
            if image.returncode or not image.stdout.strip():
                raise ValueError('Missing cache image identity')
            inspected = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', image.stdout.strip()],
                                       capture_output=True, text=True, timeout=10)
            if inspected.returncode or not inspected.stdout.strip().startswith('sha256:'):
                raise ValueError('Missing immutable cache image identity')
            server = dict(service=service, image_id=inspected.stdout.strip(), stages=[])
            report['servers'].append(server)
            server['stages'].append(baseline.stage([sys.executable, str(ROOT / 'eng' / contract_file)],
                                                  directory, service + '-contracts-before-restart', 45))
            # Never restart user resources: compose service belongs only to this UUID project.
            server['stages'].append(baseline.stage(compose + ['restart', '--timeout', '5', service],
                                                  directory, service + '-restart', 15))
            deadline = time.monotonic() + 15
            ready = False
            while time.monotonic() < deadline:
                try:
                    with contracts.Client() as client:
                        ready = client.call('PING') == 'PONG'
                    if ready:
                        break
                except (OSError, contracts.RedisError, ConnectionError):
                    time.sleep(.1)
            if not ready:
                raise ValueError('Cache did not recover after owned restart')
            # Both servers intentionally use disposable nonpersistent storage. Restart permits a
            # fresh window; scripts must reload without NOSCRIPT and all new effects retain TTLs.
            server['stages'].append(baseline.stage([sys.executable, str(ROOT / 'eng' / contract_file)],
                                                  directory, service + '-contracts-after-restart', 45))
            if shutil.which('dotnet'):
                server['stages'].append(baseline.stage(
                    ['dotnet', 'test', str(ROOT / 'treehammock.Tests.SqlContracts/treehammock.Tests.SqlContracts.csproj'),
                     '--configuration', 'Release', '-p:RestoreLockedMode=true', '--filter',
                     'FullyQualifiedName~' + native_class + '|FullyQualifiedName~Cor10PendingProofCacheTests', '--logger', 'trx;LogFileName=' + pr.lower() + '.trx',
                     '--results-directory', str(directory / (service + '-native'))],
                    directory, service + '-native', 600))
                trx = directory / (service + '-native') / (pr.lower() + '.trx')
                if not trx.is_file():
                    raise ValueError('Native matrix produced no TRX evidence')
                results = ET.parse(trx).getroot().findall('.//{*}UnitTestResult')
                if len(results) < 3 or any(item.get('outcome') != 'Passed' for item in results):
                    raise ValueError('Native cache regressions were missing or failed')
                server['native_tests_passed'] = len(results)
            else:
                server['native_status'] = 'Blocked: .NET SDK absent'
        stages = [stage for server in report['servers'] for stage in server['stages']]
        code = 1 if any(stage['exit_code'] != 0 for stage in stages) else 2 if not shutil.which('dotnet') else 0
        report.update(status='Failed' if code == 1 else 'Blocked' if code == 2 else 'Passed',
                      script_status='Failed' if any(stage['exit_code'] != 0 for stage in stages
                                                   if '-native' not in stage.get('name', '')) else 'Passed',
                      reason='Native .NET qualification is missing' if code == 2 else None)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        code = 1
        report.update(status='Failed', reason='Owned cache qualification failed or exceeded its deadline')
    finally:
        if report['owned_resources_started']:
            report['cleanup'] = baseline.stage(compose + ['down', '--volumes', '--timeout', '5'], directory, 'cleanup', 20)
            if report['cleanup']['exit_code']:
                code = 1
                report.update(status='Failed', reason='Owned project cleanup failed; retry only this project')
        report['completed_at'] = baseline.now()
        (directory / 'fixture.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'Cache fixture {report["status"]}; evidence: {directory.relative_to(ROOT)}/fixture.json')
    return code


if __name__ == '__main__':
    sys.exit(main())
