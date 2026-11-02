#!/usr/bin/env python3
"""Refresh the separate added-file catalog after an intentional correction change."""
import argparse
import hashlib
import json
from pathlib import Path

IGNORED = {'.git', '.docker', 'bin', 'obj', 'TestResults', '.correction-results', '.artifacts', 'artifacts', '__pycache__'}
CATALOG = 'docs/corrections/ADDED_FILES.json'


def current(root):
    baseline = json.loads((root / 'docs/corrections/BASELINE_MANIFEST.json').read_text(encoding='utf-8'))['baseline_paths']
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob('*')) if p.is_file() and not IGNORED.intersection(p.relative_to(root).parts)
            and p.relative_to(root).as_posix() not in baseline and p.relative_to(root).as_posix() != CATALOG}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    path = args.root / CATALOG
    path.write_text(json.dumps(dict(schema_version=1, files=current(args.root)), indent=2) + '\n', encoding='utf-8')
    print('Updated separate added-file catalog; original 451-file inventory retained.')


if __name__ == '__main__':
    main()
