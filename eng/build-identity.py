#!/usr/bin/env python3
"""Validate loaded-assembly evidence emitted by the native module initializer."""
import hashlib
import json
from pathlib import Path
import uuid


def validate(path, configuration, test_assembly):
    path = Path(path)
    data = json.loads(path.read_text())
    uuid.UUID(data['run_id'])
    if data['configuration'] != configuration:
        raise ValueError('Loaded configuration differs from requested configuration')
    assemblies = data['assemblies']
    if len(assemblies) != 2 or {a['name'] for a in assemblies} != {test_assembly, 'treehammock'}:
        raise ValueError('Wrong loaded assembly set')
    for assembly in assemblies:
        binary = Path(assembly['path'])
        uuid.UUID(assembly['mvid'])
        if binary.name != assembly['name'] + '.dll' or binary.parent.name != 'net8.0' or binary.parent.parent.name != configuration or binary.parent.parent.parent.name != 'bin':
            raise ValueError('Loaded binary is from the wrong configuration/output')
        if binary.parent != path.parent or binary.is_symlink():
            raise ValueError('Loaded application/test binary escapes the evidence output')
        if hashlib.sha256(binary.read_bytes()).hexdigest() != assembly['sha256']:
            raise ValueError('Loaded binary changed after measurement')
    receipt = path.parent / (test_assembly + '.dll.proof-id')
    if receipt.read_text(encoding='utf-8-sig').strip() != '|'.join([data['run_id'], configuration, test_assembly, 'net8.0']):
        raise ValueError('Loaded identity does not match its build receipt')
    return data
