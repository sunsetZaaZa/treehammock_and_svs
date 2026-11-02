#!/usr/bin/env python3
"""Verify the SVS-03 source checkpoint and unchanged production scope; not native qualification."""
from pathlib import Path
import hashlib
import json

ROOT=Path(__file__).resolve().parents[2]
MANIFEST='docs/session-validation/SVS-03_SOURCE_INVENTORY.json'
IGNORED={'.git','bin','obj','__pycache__','TestResults'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inventory():return {p.relative_to(ROOT).as_posix():sha(p) for p in sorted(ROOT.rglob('*')) if p.is_file() and not (set(p.relative_to(ROOT).parts)&IGNORED) and p.relative_to(ROOT).as_posix()!=MANIFEST}
def mutable(rel):return rel.startswith(('docs/session-validation/','treehammock.Tests/','eng/session-validation/'))

def main():
    m=json.loads((ROOT/MANIFEST).read_text());actual=inventory();before=m['baseline_files']
    if actual!=m['files']:
        raise SystemExit('FAIL source drift: '+json.dumps({'missing':sorted(m['files'].keys()-actual.keys()),'extra':sorted(actual.keys()-m['files'].keys()),'changed':sorted(p for p in actual.keys()&m['files'].keys() if actual[p]!=m['files'][p])}))
    modified=sorted(p for p in before.keys()&actual.keys() if before[p]!=actual[p]);added=sorted(actual.keys()-before.keys())
    if modified!=m['expected_modified'] or added!=m['expected_added'] or before.keys()-actual.keys():raise SystemExit('FAIL declared delta differs')
    if any(not mutable(p) for p in modified+added):raise SystemExit('FAIL unexpected production-scope change')
    for rel,h in before.items():
        if not mutable(rel) and actual.get(rel)!=h:raise SystemExit('FAIL production path changed '+rel)
    for rel in m['frozen_previous_checkpoints']:
        if actual[rel]!=before[rel]:raise SystemExit('FAIL historical checkpoint changed '+rel)
    provenance=json.loads((ROOT/'treehammock.Tests/Fixtures/LegacyParity/baseline-provenance.json').read_text())
    frozen='treehammock.Tests/Infrastructure/PreExtractionMiddleware.cs'
    if actual[frozen]!=provenance['adapted_sha256'] or provenance!=m['frozen_fixture_provenance']:raise SystemExit('FAIL differential fixture provenance differs')
    t=json.loads((ROOT/'docs/session-validation/SVS_PR_TRACKER.json').read_text())
    if t['next_pr']!='SVS-04' or t['prs'][3]['status']!='ImplementedLocalHttpParityPendingNativeAcceptance':raise SystemExit('FAIL PR state drift')
    f02=next(f for f in t['open_findings'] if f['id']=='SVS00-F02')
    if f02['status']!='OpenNativeAdjudicationRequired' or f02['native_cases_executed']!=0:raise SystemExit('FAIL native finding promoted without evidence')
    print(json.dumps(dict(status='PASS',stage='SVS-03',source_files=len(actual)+1,baseline_files=len(before),
        unchanged_baseline_files=len(before)-len(modified),modified=modified,added_count=len(added)+1,deleted=0,
        production_runtime_sql_core_contracts_pins_locks='byte-identical to SVS-02',historical_collectors='unchanged',
        native_F02='OpenNativeAdjudicationRequired',release_ready=False),indent=2))

if __name__=='__main__':main()
