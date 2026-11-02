#!/usr/bin/env python3
"""Reject absent, empty, skipped or failed xUnit v3 managed release test reports."""
import sys
from pathlib import Path
import xml.etree.ElementTree as ET


def inspect(path):
    try:
        root = ET.parse(path).getroot()
        assemblies = root.findall('assembly') if root.tag == 'assemblies' else [root] if root.tag == 'assembly' else []
        if not assemblies:
            raise ValueError('No test assemblies')
        total = 0
        for asm in assemblies:
            counts = {k: int(asm.get(k, '-1')) for k in ('total','passed','failed','skipped','errors','not-run')}
            if counts['total'] <= 0 or counts['passed'] != counts['total'] or any(counts[k] != 0 for k in ('failed','skipped','errors','not-run')):
                raise ValueError(f'Incomplete, skipped, or failing tests: {counts}')
            total += counts['passed']
        print(f'{Path(path).name}: {total} managed tests passed')
    except (ValueError, OSError, ET.ParseError) as error:
        print(f'SVS test qualification failed: {error}', file=sys.stderr)
        raise SystemExit(2)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Provide an XML test report')
    inspect(sys.argv[1])
