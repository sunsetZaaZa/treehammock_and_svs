#!/usr/bin/env python3
"""Verify exact SVS07 stage bytes and preserved public/shared boundaries; not native acceptance."""
from pathlib import Path
import hashlib,json,subprocess,sys
R=Path(__file__).resolve().parents[2];M='docs/session-validation/SVS-07_SOURCE_INVENTORY.json';IGNORE={'.git','bin','obj','__pycache__','TestResults'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 m=json.loads((R/M).read_text());before=m['baseline_files'];actual={p.relative_to(R).as_posix():sha(p) for p in sorted(R.rglob('*')) if p.is_file() and not set(p.parts)&IGNORE and p.suffix!='.pyc' and p.relative_to(R).as_posix()!=M}
 assert actual==m['files'],'Source drift'
 changed=sorted(n for n in before.keys()&actual.keys() if before[n]!=actual[n]);added=sorted(actual.keys()-before.keys())
 assert changed==m['expected_modified'] and added==m['expected_added'] and not before.keys()-actual.keys()
 allowed={'src/Treehammock.SessionValidation.Storage/AuthorityProjectionMapper.cs','src/Treehammock.SessionValidation.Storage/ValidatorDatabaseIdentity.cs','src/Treehammock.SessionValidation.Storage/YsqlAuthorityDataSource.cs','src/Treehammock.SessionValidation.Storage/Treehammock.SessionValidation.Storage.csproj','tests/Treehammock.SessionValidation.StorageTests/Treehammock.SessionValidation.StorageTests.csproj','tests/Treehammock.SessionValidation.YsqlTests/Treehammock.SessionValidation.YsqlTests.csproj'}
 assert all(n in allowed or n.startswith('docs/session-validation/') for n in changed)
 assert all(n.startswith(('src/Treehammock.SessionValidation.Api/','src/Treehammock.SessionValidation.Storage/','tests/Treehammock.SessionValidation.HostTests/','tests/Treehammock.SessionValidation.StorageTests/','tests/Treehammock.SessionValidation.YsqlTests/','deploy/session-validation/','eng/session-validation/','docs/session-validation/')) for n in added)
 frozen=[n for n in before if n not in allowed and not n.startswith('docs/session-validation/')]
 frozen += [n for n in before if 'SOURCE_INVENTORY.json' in n or n.endswith('_DELIVERY.md')]
 assert all(actual[n]==before[n] for n in frozen)
 t=json.loads((R/'docs/session-validation/SVS_PR_TRACKER.json').read_text());assert t==json.loads((R/'docs/session-validation/design/docs/SVS_PR_TRACKER.json').read_text())
 assert len(t['prs'])==24 and t['prs'][:7]==m['previous_pr_records'] and t['open_findings']==m['previous_open_findings']
 assert t['next_pr']=='SVS-08' and t['prs'][7]['status']=='ImplementedLocalHostAndIdentityCompatibilityPendingNativeAcceptance'
 for script in ['inspect-host-contract.py','inspect-identity-spec.py','audit-readonly-sql.py']:
  p=subprocess.run([sys.executable,str(R/'eng/session-validation'/script)],capture_output=True,text=True);assert not p.returncode,p.stdout+p.stderr
 print(json.dumps(dict(stage='SVS-07',status='PASS',baseline='Verified SVS07 preparation with THS12A',source_files=len(actual)+1,baseline_files=len(before),modified=changed,added_count=len(added)+1,deleted=0,public_core_contracts_canonical_sql_old_locks_pins='Unchanged',cache_codec_reader_coordinator='Unchanged',production_cache_admission='Temporarily unadmitted; real enablement SVS-11',native_cases_executed=0,release_ready=False),indent=2))
if __name__=='__main__':main()
