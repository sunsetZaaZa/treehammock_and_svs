#!/usr/bin/env python3
"""Static source-layout and documentation-link verification; not a build or release approval."""
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote

FOLDER_KIND = '2150E333-8FDC-42A3-9474-1A3956D46DE8'
PROJECT = re.compile(r'^Project\("\{([^}]+)\}"\) = "[^"]+", "([^"]+)", "(\{[^}]+\})"$', re.M)
LINK = re.compile(r'(?<!!)\[[^]]+\]\(([^)]+)\)')
CI_PATH = re.compile(r'(?<![A-Za-z0-9._/])(?:eng|deploy|\.gitlab|docs)/[A-Za-z0-9_./\-]+\.(?:py|sh|ps1|sql|json|yaml|yml|md)')
EXPECTED = {'treehammock.sln': (19, 17), 'eng/treehammock.SqlContracts.sln': (2, 0)}


def audit(root: Path):
    root = root.resolve()
    failures = []
    solutions = {}
    for name, (total, svs_count) in EXPECTED.items():
        path = root / name
        if not path.is_file():
            failures.append(f'missing solution: {name}')
            continue
        entries = PROJECT.findall(path.read_text(encoding='utf-8-sig'))
        projects = [(rel.replace('\\', '/'), guid) for kind, rel, guid in entries if kind.upper() != FOLDER_KIND]
        folders = [rel for kind, rel, guid in entries if kind.upper() == FOLDER_KIND]
        if len(projects) != total or len({guid for _, guid in projects}) != total:
            failures.append(f'project inventory mismatch: {name}: {len(projects)} != {total}')
        if sum('SessionValidation' in rel for rel, _ in projects) != svs_count:
            failures.append(f'SessionValidation membership mismatch: {name}')
        for rel, _ in projects:
            if not (path.parent / rel).is_file():
                failures.append(f'missing solution project: {name}: {rel}')
        solutions[name] = {'projects': len(projects), 'session_validation_projects': svs_count, 'folders': len(folders)}

    project_assets = 0
    project_files = 0
    for proj in root.rglob('*.csproj'):
        if set(proj.relative_to(root).parts) & {'docs', '.git', 'bin', 'obj', 'TestResults'}:
            continue  # Historical, non-buildable snapshots are not part of the current project graph.
        project_files += 1
        try:
            elements = ET.parse(proj).getroot().iter()
            for element in elements:
                tag = element.tag.rsplit('}', 1)[-1]
                if tag not in {'ProjectReference', 'EmbeddedResource', 'Content', 'None', 'Compile', 'Import'}:
                    continue
                value = element.get('Include') or element.get('Project')
                if not value or any(symbol in value for symbol in ('$(', '@(', '%(', '*', '?')) or '://' in value:
                    continue
                if '/' not in value and '\\' not in value and not value.endswith('.csproj'):
                    continue
                project_assets += 1
                if not (proj.parent / value.replace('\\', '/')).is_file():
                    failures.append(f'missing project asset: {proj.relative_to(root)}: {value}')
        except ET.ParseError as exc:
            failures.append(f'invalid project XML: {proj.relative_to(root)}: {exc}')

    docs_checked = 0
    for doc in root.rglob('*.md'):
        if set(doc.relative_to(root).parts) & {'.git', 'bin', 'obj', 'TestResults'}:
            continue
        for candidate in LINK.findall(doc.read_text(encoding='utf-8')):
            target = candidate.strip().strip('<>').split(' ', 1)[0]
            if not target or target.startswith(('#', 'https:', 'http:', 'mailto:', 'data:')):
                continue
            target = unquote(target.split('#', 1)[0].split('?', 1)[0])
            if not target:
                continue
            docs_checked += 1
            if not (doc.parent / target).exists():
                failures.append(f'broken documentation link: {doc.relative_to(root)}: {target}')

    ci_files = list((root / '.github').rglob('*.yml')) + list((root / '.gitlab').rglob('*.yml')) + [root / '.gitlab-ci.yml']
    ci_references = 0
    for ci in ci_files:
        if not ci.is_file():
            continue
        for rel in set(CI_PATH.findall(ci.read_text(encoding='utf-8'))):
            ci_references += 1
            if not (root / rel).is_file():
                failures.append(f'missing CI script/input: {ci.relative_to(root)}: {rel}')

    storage = root / 'src/Treehammock.SessionValidation.Storage/Treehammock.SessionValidation.Storage.csproj'
    if storage.is_file():
        tree = ET.parse(storage)
        resources = [(el.get('Include'), el.get('LogicalName')) for el in tree.findall('.//EmbeddedResource')]
        if not any((i or '').replace('\\', '/').endswith('sql/inspect-validator-identity.sql') and logical == 'svs05-inspect-identity.sql' for i, logical in resources):
            failures.append('embedded SQL resource include or stable logical name changed')
    else:
        failures.append('storage project missing')

    return {'verification': 'static only; no .NET/native/security qualification',
            'status': 'PASS' if not failures else 'FAIL', 'solutions': solutions,
            'project_files_inspected': project_files, 'relative_project_assets_inspected': project_assets,
            'relative_markdown_links_inspected': docs_checked, 'ci_declared_paths_inspected': ci_references, 'failures': failures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    result = audit(args.root)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
