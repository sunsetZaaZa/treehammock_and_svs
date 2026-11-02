#!/usr/bin/env python3
"""Verify the frozen SVS-02 source checkpoint; not live service/native qualification."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = 'docs/session-validation/SVS-02_SOURCE_INVENTORY.json'
IGNORED = {'.git', 'bin', 'obj', '__pycache__', 'TestResults'}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def inventory():
    return {p.relative_to(ROOT).as_posix(): digest(p.read_bytes()) for p in sorted(ROOT.rglob('*'))
            if p.is_file() and not (set(p.relative_to(ROOT).parts) & IGNORED)
            and p.relative_to(ROOT).as_posix() != MANIFEST}

def fragment(text, signature):
    start = text.index(signature)
    end = text.find('\n    private ', start+len(signature))
    return text[start:end if end >= 0 else len(text)].rstrip()

def main():
    manifest = json.loads((ROOT / MANIFEST).read_text())
    actual = inventory()
    if actual != manifest['files']:
        raise SystemExit('FAIL: source drift: '+json.dumps({
            'missing': sorted(manifest['files'].keys()-actual.keys()),
            'extra': sorted(actual.keys()-manifest['files'].keys()),
            'changed': sorted(p for p in actual.keys() & manifest['files'].keys() if actual[p] != manifest['files'][p])}))
    baseline = manifest['baseline_files']
    changed = sorted(p for p in baseline.keys() & actual.keys() if baseline[p] != actual[p])
    added = sorted(actual.keys()-baseline.keys())
    if changed != manifest['expected_modified'] or added != manifest['expected_added'] or baseline.keys()-actual.keys():
        raise SystemExit('FAIL: declared source delta differs')
    for rel in manifest['frozen_paths']:
        if actual[rel] != baseline[rel]:
            raise SystemExit('FAIL: frozen file changed '+rel)
    middleware = (ROOT / 'Rigging/Authentication/JsonWebTokenMiddleware.cs').read_text()
    for signature, expected in manifest['unchanged_middleware_fragments'].items():
        if digest(fragment(middleware, signature).encode()) != expected:
            raise SystemExit('FAIL: original authority/cache I/O fragment changed '+signature)
    utility = (ROOT / 'Rigging/Authentication/JsonWebTokenUtility.cs').read_text()
    start = utility.index('    public string GenerateAccessToken(byte[] refreshToken')
    end = utility.index('    public async Task<(IntraMessage, string?)> ValidateAccessToken(')
    if digest(utility[start:end].encode()) != manifest['unchanged_token_generation_sha256']:
        raise SystemExit('FAIL: token generation changed')
    for rel, expected in manifest['frozen_verifier_fixtures'].items():
        if actual[rel] != expected:
            raise SystemExit('FAIL: frozen differential fixture changed '+rel)
    for p in (ROOT / 'src/Treehammock.SessionValidation.Core').glob('*.cs'):
        if re.search(r'\b(SystemClock|HttpClient|Npgsql|RabbitMQ|File|Directory)\.|DateTimeOffset\.UtcNow|DateTime\.Now|StackExchange\.Redis', p.read_text()):
            raise SystemExit('FAIL: I/O or clock in Core '+p.name)
    tracker = json.loads((ROOT / 'docs/session-validation/SVS_PR_TRACKER.json').read_text())
    if tracker['next_pr'] != 'SVS-03' or tracker['prs'][2]['status'] != 'ImplementedLocalParityTestsPassed':
        raise SystemExit('FAIL: PR status drift')
    report = dict(status='PASS', stage='SVS-02', checked_source_files=len(actual)+1,
        unchanged_baseline_files=len(baseline)-len(changed), modified=changed, added_count=len(added)+1,
        deleted=0, original_authority_cache_IO='byte-identical checked fragments',
        token_generation='byte-identical', frozen_pins_sql_contracts='PASS', qualification='Native/COR not promoted')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
