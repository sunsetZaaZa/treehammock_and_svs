#!/usr/bin/env python3
"""Verify exact SVS-04 checkpoint/scope. Static audit only, not native acceptance."""
from pathlib import Path
import hashlib,json,subprocess,sys
ROOT=Path(__file__).resolve().parents[2]
MANIFEST='docs/session-validation/SVS-04_SOURCE_INVENTORY.json'
IGNORED={'.git','bin','obj','__pycache__','TestResults'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inventory():return {p.relative_to(ROOT).as_posix():sha(p) for p in sorted(ROOT.rglob('*')) if p.is_file() and not set(p.relative_to(ROOT).parts)&IGNORED and p.relative_to(ROOT).as_posix()!=MANIFEST}
def main():
    m=json.loads((ROOT/MANIFEST).read_text());actual=inventory();before=m['baseline_files']
    if actual!=m['files']:raise SystemExit('FAIL source drift: '+json.dumps(dict(missing=sorted(m['files'].keys()-actual.keys()),extra=sorted(actual.keys()-m['files'].keys()),changed=sorted(p for p in actual.keys()&m['files'].keys() if actual[p]!=m['files'][p]))))
    changed=sorted(p for p in before.keys()&actual.keys() if before[p]!=actual[p]);added=sorted(actual.keys()-before.keys())
    assert changed==m['expected_modified'] and added==m['expected_added'] and not before.keys()-actual.keys()
    allowed={'Rigging/Database/Baseline/000_canonical_database.sql','Rigging/Database/Baseline/000_treehammock_canonical_database.sql'}
    assert all(p.startswith('docs/session-validation/') or p in allowed for p in changed)
    assert all(p.startswith(('docs/session-validation/','src/Treehammock.SessionValidation.Storage/','tests/Treehammock.SessionValidation.StorageTests/','tests/Treehammock.SessionValidation.YsqlTests/','deploy/session-validation/','eng/session-validation/')) for p in added)
    assert all(before[p]==actual[p] for p in m['frozen_previous_checkpoints'])
    t=json.loads((ROOT/'docs/session-validation/SVS_PR_TRACKER.json').read_text())
    assert t==json.loads((ROOT/'docs/session-validation/design/docs/SVS_PR_TRACKER.json').read_text())
    assert t['next_pr']=='SVS-05' and t['prs'][4]['status']=='ImplementedLocalStorageTestsPendingNativeAcceptance'
    assert [p['status'] for p in t['prs'][:4]]==m['previous_pr_statuses']
    assert next(f for f in t['open_findings'] if f['id']=='SVS00-F02')['status']=='OpenNativeAdjudicationRequired'
    assert next(f for f in t['open_findings'] if f['id']=='SVS00-F01')['status']=='OpenNativeReadonlyQualificationRequired'
    path=ROOT/'eng/session-validation/audit-readonly-sql.py';result=subprocess.run([sys.executable,str(path)],capture_output=True,text=True);assert not result.returncode,result.stderr;audit=json.loads(result.stdout)
    print(json.dumps(dict(stage='SVS-04',status='PASS',source_files=len(actual)+1,baseline_files=len(before),unchanged_baseline_files=len(before)-len(changed),modified=changed,added_count=len(added)+1,deleted=0,legacy_sql='exact prefix preserved, new block only',public_app_core_contracts_existing_locks_pins='byte-identical to SVS-03',readonly_closure=audit['readonly_closure'],native_cases_executed=0,release_ready=False),indent=2))
if __name__=='__main__':main()
