#!/usr/bin/env python3
"""Generate greenfield baselines from immutable migrations and pinned SVS read functions."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERN = re.compile(r'^create or replace function (\w+)\(.*?^\$\$;', re.M | re.S)
SVS_READ_SQL = 'deploy/session-validation/sql/validator-read-functions.sql'
SVS_READ_SHA256 = '3af8cfdd5f3e64cfec8d46d7a869bc3de5a7f3669d5b0e73b979a0ac7af7a6b7'


def generate(root):
    directory = root / 'Rigging/Database/Migrations'
    manifest = json.loads((directory / 'manifest.json').read_text())
    if [m['version'] for m in manifest] != list(range(1, len(manifest) + 1)):
        raise ValueError('Migration versions must form an ordered contiguous sequence')
    scripts = []
    for entry in manifest:
        name = entry['name']
        if not re.fullmatch(r'\d{3}_[a-z_]+\.sql', name) or not name.startswith(f"{entry['version']:03}_"):
            raise ValueError('Invalid migration filename')
        raw = (directory / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry['sha256']:
            raise ValueError(f'Immutable migration checksum mismatch: {name}')
        scripts.append(raw.decode('utf-8'))
    sql = scripts[0]
    additions = []
    ddl_additions = []
    for script in scripts[1:]:
        matches = list(PATTERN.finditer(script))
        # Expand migrations may add tables/indexes. Preserve DDL order before
        # routines while retaining immutable migration bytes/signature checks.
        remainder = PATTERN.sub('', script)
        clean = re.sub(r'--[^\n]*', '', remainder).strip()
        if clean:
            for statement in clean.split(';'):
                if statement.strip() and not re.match(r'^create\s+(?:table|(?:unique\s+)?index)\s+[a-z_]+\b', statement.strip(), re.I):
                    raise ValueError('Unsupported non-function migration content')
            ddl_additions.append(remainder.strip())
        for match in matches:
            name, definition = match.group(1), match.group()
            existing = [m for m in PATTERN.finditer(sql) if m.group(1) == name]
            if len(existing) > 1:
                raise ValueError(f'Duplicate function: {name}')
            if existing:
                old = existing[0]
                if old.group().split('as $$')[0] != definition.split('as $$')[0]:
                    raise ValueError(f'Public contract changed: {name}')
                sql = sql[:old.start()] + definition + sql[old.end():]
            else:
                additions.append(definition)
    position = sql.index('create or replace function ')
    sql = sql[:position] + '\n\n'.join(ddl_additions + additions) + '\n\n' + sql[position:]
    sql = re.sub(r'^-- Treehammock.*?\n\n', '', sql, count=1, flags=re.S)
    # The deployment runner bootstraps pgcrypto in public before migration 001.
    # Standalone greenfield baselines must use the same extension placement.
    sql = sql.replace('create extension if not exists pgcrypto;', 'create extension if not exists pgcrypto with schema public;', 1)
    # The private validator functions were supplied as a separately pinned,
    # SELECT-only schema supplement, not as a public migration. Keep the
    # original checked-in baseline bytes and verify the supplement's identity.
    overlay = root / SVS_READ_SQL
    raw = overlay.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SVS_READ_SHA256:
        raise ValueError('Pinned SessionValidation SQL source checksum mismatch')
    return '-- Generated from ordered checksummed migrations; use the migration command for deployment.\n' + sql + '\n\n' + raw.decode('utf-8')


def validate_predecessor(previous, current):
    if len(current) < len(previous) or current[:len(previous)] != previous:
        raise ValueError('Previously recorded migration identity was changed or removed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--previous', type=Path, help='Previous source root')
    parser.add_argument('--previous-revision', help='Previous git revision for CI')
    args = parser.parse_args()
    relative = 'Rigging/Database/Migrations/manifest.json'
    current = json.loads((args.root / relative).read_text())
    if args.previous and args.previous_revision:
        parser.error('Choose one predecessor source')
    if args.previous:
        path = args.previous / relative
        validate_predecessor(json.loads(path.read_text()) if path.exists() else [], current)
    if args.previous_revision:
        revision = args.previous_revision
        if not re.fullmatch(r'[A-Za-z0-9_./^~@{}-]+', revision) or revision.startswith('-'):
            parser.error('Invalid predecessor revision')
        exists = subprocess.run(['git', 'rev-parse', '--verify', revision + '^{commit}'], cwd=args.root, capture_output=True)
        if exists.returncode:
            raise SystemExit('Predecessor revision unavailable')
        snapshot = subprocess.run(['git', 'show', revision + ':' + relative], cwd=args.root, capture_output=True)
        if snapshot.returncode:
            tree = subprocess.run(['git', 'ls-tree', '--name-only', revision, '--', relative], cwd=args.root, capture_output=True)
            if tree.returncode or tree.stdout.strip():
                raise SystemExit('Predecessor manifest could not be read')
        validate_predecessor(json.loads(snapshot.stdout) if snapshot.returncode == 0 else [], current)
    expected = generate(args.root)
    for name in ['000_treehammock_canonical_database.sql', '000_canonical_database.sql']:
        path = args.root / 'Rigging/Database/Baseline' / name
        if args.check:
            if path.read_text() != expected:
                raise SystemExit(f'Generated baseline drift: {name}')
        else:
            path.write_text(expected, encoding='utf-8')
    print('Migration checksums, signatures and both generated baselines agree.')


if __name__ == '__main__':
    main()
