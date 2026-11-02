#!/usr/bin/env python3
"""Verify exact SVS-05 reimplementation source/scope; not native acceptance."""
from pathlib import Path
import hashlib,json,subprocess,sys
ROOT=Path(__file__).resolve().parents[2]
MANIFEST='docs/session-validation/SVS-05_SOURCE_INVENTORY.json'
IGNORE={'.git','bin','obj','__pycache__','TestResults'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inventory():return {p.relative_to(ROOT).as_posix():sha(p) for p in sorted(ROOT.rglob('*')) if p.is_file() and not set(p.relative_to(ROOT).parts)&IGNORE and p.suffix!='.pyc' and p.relative_to(ROOT).as_posix()!=MANIFEST}
def main():
 m=json.loads((ROOT/MANIFEST).read_text());actual=inventory();before=m['baseline_files'];assert actual==m['files'],'Source drift'
 changed=sorted(n for n in before.keys()&actual.keys() if before[n]!=actual[n]);added=sorted(actual.keys()-before.keys())
 assert changed==m['expected_modified'] and added==m['expected_added'] and not before.keys()-actual.keys()
 permitted={'src/Treehammock.SessionValidation.Storage/Treehammock.SessionValidation.Storage.csproj','src/Treehammock.SessionValidation.Storage/YsqlAuthorityDataSource.cs','src/Treehammock.SessionValidation.Storage/YsqlSessionAuthority.cs','tests/Treehammock.SessionValidation.StorageTests/Treehammock.SessionValidation.StorageTests.csproj','tests/Treehammock.SessionValidation.YsqlTests/NativeAuthorityTests.cs'}
 assert all(n in permitted or n.startswith('docs/session-validation/') for n in changed)
 assert all(n.startswith(('src/Treehammock.SessionValidation.Storage/','tests/Treehammock.SessionValidation.StorageTests/','tests/Treehammock.SessionValidation.YsqlTests/','deploy/session-validation/','eng/session-validation/','docs/session-validation/')) for n in added)
 frozen=[n for n in before if n.startswith(('src/Treehammock.SessionValidation.Core/','src/Treehammock.SessionValidation.Contracts/','Rigging/Database/Baseline/','docs/corrections/')) or n.endswith(('packages.lock.json','global.json')) or 'SOURCE_INVENTORY.json' in n]
 assert all(actual[n]==before[n] for n in frozen)
 t=json.loads((ROOT/'docs/session-validation/SVS_PR_TRACKER.json').read_text());assert t==json.loads((ROOT/'docs/session-validation/design/docs/SVS_PR_TRACKER.json').read_text())
 assert t['next_pr']=='SVS-06' and t['prs'][5]['status']=='ImplementedLocalIdentityChecksPendingNativeAcceptance'
 assert [p['status'] for p in t['prs'][:5]]==m['previous_pr_statuses']
 assert next(f for f in t['open_findings'] if f['id']=='SVS00-F01')['status']=='OpenNativeReadonlyQualificationRequired'
 assert next(f for f in t['open_findings'] if f['id']=='SVS00-F02')['status']=='OpenNativeAdjudicationRequired'
 for script in ['inspect-identity-spec.py','audit-readonly-sql.py']:
  r=subprocess.run([sys.executable,str(ROOT/'eng/session-validation'/script)],capture_output=True,text=True);assert not r.returncode,r.stdout+r.stderr
 print(json.dumps(dict(stage='SVS-05',reimplementation=True,status='PASS',baseline='SVS-04',source_files=len(actual)+1,baseline_files=len(before),modified=changed,added_count=len(added)+1,deleted=0,public_application_core_contracts_canonical_sql_pins_existing_locks='byte-identical to SVS-04',native_cases_executed=0,release_ready=False),indent=2))
if __name__=='__main__':main()
