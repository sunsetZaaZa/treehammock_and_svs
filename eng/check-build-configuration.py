#!/usr/bin/env python3
"""Configuration/identity source contracts; never native qualification."""
import argparse
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition: raise ValueError(message)


def validate(root):
    solution_counts = {'treehammock.sln': 19, 'eng/treehammock.SqlContracts.sln': 2}
    for name, expected_count in solution_counts.items():
        text = (root / name).read_text(encoding='utf-8-sig')
        entries = re.findall(r'^Project\("\{([^}]+)\}"\) = "[^"]+", "([^"]+)", "(\{[^}]+\})"$', text, re.M)
        # Solution folders provide structure, but are not compiled projects.
        projects = [(path, guid) for kind, path, guid in entries if kind.upper() != '2150E333-8FDC-42A3-9474-1A3956D46DE8']
        require(len(projects) == expected_count and len({guid for _, guid in projects}) == expected_count, 'Solution project inventory drift')
        if name == 'treehammock.sln':
            require(sum('SessionValidation' in path for path, _ in projects) == 17, 'SessionValidation solution membership drift')
        native_only = ('DragonflyTests', 'YsqlTests', 'QualificationTests', 'DisposableCaller', 'PackageHash', 'QualificationBenchmark')
        for path, project in projects:
            require(path.lower().endswith('.csproj') and (root / Path(name).parent / path.replace('\\', '/')).is_file(), 'Solution project path missing: ' + path)
            for configuration in ['Debug', 'Release', 'Sandbox']:
                for field in ['ActiveCfg', 'Build.0']:
                    mapping = f'{project}.{configuration}|Any CPU.{field} = {configuration}|Any CPU'
                    # Native/qualification executables are visible in the IDE but deliberately excluded from Build Solution.
                    excluded = name == 'treehammock.sln' and any(('.' + marker + '/') in path.replace('\\', '/') for marker in native_only)
                    require((mapping not in text) if (field == 'Build.0' and excluded) else (mapping in text), 'Solution build/test configuration mismatch')
    props = (root / 'Directory.Build.props').read_text()
    require('<Configurations>Debug;Release;Sandbox</Configurations>' in props, 'Shared configuration policy missing')
    require('<_Parameter1>TreehammockProofRunId</_Parameter1>' in props and '$(TREEHAMMOCK_BUILD_RUN_ID)' in props, 'Loaded build identity metadata missing')
    for name in ['treehammock.Tests', 'treehammock.Tests.SqlContracts', 'treehammock.Tests.System']:
        project = ET.parse(root / name / (name + '.csproj'))
        require(project.findtext('ItemGroup/ProjectReference/SetConfiguration') == 'Configuration=$(Configuration)', 'Application reference configuration mismatch')
        if name != 'treehammock.Tests':
            require(any(p.get('Include', '').endswith('Infrastructure\\BuildIdentity.cs') for p in project.findall('ItemGroup/Compile')), 'Test project omits loaded identity check')
    targets = (root / 'Directory.Build.targets').read_text()
    target_tree = ET.fromstring(targets)
    record = target_tree.find("Target[@Name='RecordTreehammockBuildIdentity']")
    require(record is not None and record.find('Error').get('Condition') == "!Exists('$(TargetPath)')", 'Build receipt cannot record missing output')
    for token in ['BeforeTargets="PrepareForBuild;VSTest"', 'AfterTargets="Build"', 'BeforeTargets="VSTest"', "!Exists('$(TargetPath)')", 'ReadLinesFromFile', "'@(_TreehammockBuiltIdentity)' !=", '$(TREEHAMMOCK_BUILD_CONFIGURATION)']:
        require(token in targets, 'Fresh no-build output guard missing: ' + token)
    initializer = (root / 'treehammock.Tests/Infrastructure/BuildIdentity.cs').read_text()
    for token in ['[ModuleInitializer]', 'builtId != runId', 'builtConfiguration != configuration', 'folder.Parent?.Name != configuration', 'application.Location', 'ModuleVersionId', 'SHA256.HashData']:
        require(token in initializer, 'Actual loaded assembly check missing: ' + token)
    for name in ['validate', 'dotnet-unit-tests', 'dotnet-integration-tests', 'sql-contracts']:
        require('treehammock_begin_build "$configuration"' in (root / f'eng/{name}.sh').read_text(), 'Bash proof identity missing')
        require('Start-TreehammockBuildIdentity -Configuration $Configuration' in (root / f'eng/{name}.ps1').read_text(), 'PowerShell proof identity missing')
    ps = (root / 'eng/native-command.ps1').read_text()
    require('[Guid]::NewGuid()' in ps and "$priorBuildConfiguration, 'Process'" in ps, 'PowerShell identity is not fresh/restored')
    for name in ['docker-unit-tests', 'docker-api-image']:
        for extension in ['sh', 'ps1']:
            require('TREEHAMMOCK_BUILD_RUN_ID=' in (root / f'eng/{name}.{extension}').read_text(), 'Docker build does not invalidate earlier proof output')
    for extension in ['sh', 'ps1']:
        host = (root / f'eng/docker-host-system-stack-tests.{extension}').read_text()
        require(('treehammock_begin_build Release' if extension == 'sh' else "Start-TreehammockBuildIdentity -Configuration 'Release'") in host, 'Host system identity missing')
        require(('dotnet build treehammock.Tests.System' if extension == 'sh' else "-Stage 'dotnet-build'") in host, 'Host system test must explicitly build Release')
        require(('System.csproj --configuration Release --no-build' if extension == 'sh' else "System.csproj', '--configuration', 'Release', '--no-build'") in host, 'Host system no-build configuration mismatch')
    docker = (root / 'Dockerfile').read_text()
    require('ARG TREEHAMMOCK_BUILD_RUN_ID' in docker and 'FROM build AS unit-test' in docker, 'Docker build identity/stage missing')
    unit=docker.split('FROM build AS unit-test',1)[1].split('\nFROM ',1)[0]
    require('cat /tmp/treehammock-build-id' in unit and 'TREEHAMMOCK_BUILD_CONFIGURATION="$BUILD_CONFIGURATION"' in unit, 'Docker unit stage does not consume the actual build identity/configuration')
    require('.artifacts' in (root / '.dockerignore').read_text() and '.correction-results' in (root / '.dockerignore').read_text(), 'Host proof artifacts can seed Docker output')
    ci = (root / 'docker-compose.ci-system.yml').read_text()
    system = (root / 'eng/compose-system-proof.sh').read_text()
    require('compose-system-proof.sh' in ci and 'treehammock_begin_build Release' in system and 'System.csproj --configuration Release --no-build' in system, 'Container system identity/configuration drift')
    return dict(status='SourceContractsConsistent', qualification='NotRun', configurations=['Debug', 'Release', 'Sandbox'], solutions=2, test_projects=3)


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--root', type=Path, default=ROOT); a = p.parse_args()
    try: print(json.dumps(validate(a.root), indent=2)); return 0
    except (ValueError, OSError, ET.ParseError) as error: print(str(error)); return 1


if __name__ == '__main__': raise SystemExit(main())
