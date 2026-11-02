#!/usr/bin/env python3
"""SVS-02 locked build + selected regression reproduction. No live service qualification."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
CLASSES = [
    'BuildCorrectionRegressionTests', 'Cor17EmailChangeTests', 'Cor18DeleteAuthorityTests',
    'TwoFactorAuthenticationPromotionTests', 'PasswordResetRequestOrchestrationTests',
    'Cor23HSmtpPolicyTests', 'SessionCacheWarmupTests', 'Cor20EntitlementTests',
    'SensitiveActionTokenServiceTests', 'AccountControllerAuthorizationMetadataTests',
    'AccountControllerArchitectureTests', 'ControllerAuthorizationIntentTests',
    'DependencyInjectionRegistrationTests', 'SMTPServiceConfigurationTests',
    'JsonWebTokenUtilityTests', 'JsonWebTokenMiddlewareTests', 'Cor09SessionTests',
    'Cor22CacheWriteTests', 'Cor23MAuthoritativeBudgetTests', 'SharedSessionPolicyAdapterTests'
]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dotnet', default='dotnet')
    parser.add_argument('--packages', type=Path)
    parser.add_argument('--source', action='append', default=[])
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env['DOTNET_CLI_TELEMETRY_OPTOUT'] = '1'
    env['SVS02_EVIDENCE_DIRECTORY'] = str(evidence)
    if args.packages:
        env['NUGET_PACKAGES'] = str(args.packages.resolve())
    # An explicit private SDK must also select its matching runtime host.
    if Path(args.dotnet).is_absolute():
        env['DOTNET_ROOT'] = str(Path(args.dotnet).resolve().parent)
    commands = []

    def run(name, argv):
        started = time.monotonic()
        with (evidence / (name + '.log')).open('w') as log:
            result = subprocess.run([args.dotnet, *argv], cwd=ROOT / 'tests', env=env,
                                    stdout=log, stderr=subprocess.STDOUT)
        commands.append(dict(name=name, argv=['dotnet', *argv], exit_code=result.returncode,
                             seconds=round(time.monotonic()-started, 3), log=name+'.log'))
        (evidence / 'COMMANDS.json').write_text(json.dumps(commands, indent=2)+'\n')
        print(f'{name}: {"PASS" if result.returncode == 0 else "FAIL"}', flush=True)
        if result.returncode:
            raise SystemExit(f'Check failed; see {evidence / (name + ".log")}')

    run('sdk-info', ['--info'])
    for name, project in [
        ('core-unit', 'Treehammock.SessionValidation.UnitTests/Treehammock.SessionValidation.UnitTests.csproj'),
        ('application-tests', '../treehammock.Tests/treehammock.Tests.csproj'),
        ('contracts', 'Treehammock.SessionValidation.ContractTests/Treehammock.SessionValidation.ContractTests.csproj')
    ]:
        restore = ['restore', project, '--locked-mode']
        if args.packages:
            restore += ['--packages', str(args.packages.resolve())]
        for source in args.source:
            restore += ['--source', source]
        # Audit is a separate release gate; keep local reproduction independent of network advisory feeds.
        run('restore-'+name, restore + ['-p:NuGetAudit=false'])
        run('build-'+name, ['build', project, '--no-restore', '-c', 'Release', '--disable-build-servers', '-m:1'])

    reports = []
    for framework in ['net8.0', 'net10.0']:
        for label, project in [('core', 'Treehammock.SessionValidation.UnitTests'), ('contracts', 'Treehammock.SessionValidation.ContractTests')]:
            report = evidence / f'{label}-{framework}.xml'
            run(f'{label}-tests-{framework}', [f'{project}/bin/Release/{framework}/{project}.dll',
                '-maxThreads', '2', '-xml', str(report)])
            reports.append(report)
    selected = ['../treehammock.Tests/bin/Release/net8.0/treehammock.Tests.dll']
    for name in CLASSES:
        selected += ['-class', 'treehammock.Tests.Unit.'+name]
    selected += ['-class', 'treehammock.Tests.Integration.Cor23HSmtpTransportTests']
    report = evidence / 'application-regressions.xml'
    run('application-regressions', selected+['-maxThreads', '2', '-xml', str(report)])
    reports.append(report)
    results = []
    for report in reports:
        assembly = ET.parse(report).getroot().find('assembly')
        if assembly is None:
            raise SystemExit(f'Missing test result in {report}')
        item = {'report': report.name, 'environment': assembly.get('environment')}
        item.update({field: int(assembly.get(field, '0')) for field in ['total','passed','failed','skipped','errors','not-run']})
        if item['total'] == 0 or any(item[k] for k in ['failed','skipped','errors','not-run']):
            raise SystemExit(f'Incomplete result: {report}')
        results.append(item)
    summary = dict(pr='SVS-02', status='PASS', total_test_executions=sum(r['passed'] for r in results),
                   results=results, release_ready=False,
                   not_run='Whole repository suite; live YSQL/Dragonfly/mTLS/session issuance/revocation/load/COR gates; advisory audit')
    (evidence / 'VALIDATION.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary, indent=2))

if __name__ == '__main__':
    main()
