#!/usr/bin/env python3
"""Verify exact SVS-06 source/scope and preserved predecessor; not native acceptance."""
from pathlib import Path
import hashlib,json,subprocess,sys
ROOT=Path(__file__).resolve().parents[2]
MANIFEST='docs/session-validation/SVS-06_SOURCE_INVENTORY.json'
IGNORE={'.git','bin','obj','__pycache__','TestResults'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inventory():return {p.relative_to(ROOT).as_posix():sha(p) for p in sorted(ROOT.rglob('*')) if p.is_file() and not set(p.relative_to(ROOT).parts)&IGNORE and p.suffix!='.pyc' and p.relative_to(ROOT).as_posix()!=MANIFEST}
def main():
 m=json.loads((ROOT/MANIFEST).read_text());actual=inventory();before=m['baseline_files'];assert actual==m['files'],'Source drift'
 changed=sorted(n for n in before.keys()&actual.keys() if before[n]!=actual[n]);added=sorted(actual.keys()-before.keys())
 assert changed==m['expected_modified'] and added==m['expected_added'] and not before.keys()-actual.keys()
 permitted={'src/Treehammock.SessionValidation.Storage/Treehammock.SessionValidation.Storage.csproj','src/Treehammock.SessionValidation.Storage/packages.lock.json','tests/Treehammock.SessionValidation.StorageTests/packages.lock.json','tests/Treehammock.SessionValidation.YsqlTests/packages.lock.json'}
 assert all(n in permitted or n.startswith('docs/session-validation/') for n in changed),'Unexpected predecessor change'
 assert all(n.startswith(('src/Treehammock.SessionValidation.Storage/','tests/Treehammock.SessionValidation.CacheTests/','tests/Treehammock.SessionValidation.DragonflyTests/','deploy/session-validation/','eng/session-validation/','docs/session-validation/')) or n=='contracts/coherent-cache-v1.schema.json' for n in added),'Unexpected addition'
 frozen=[n for n in before if n not in permitted and not n.startswith('docs/session-validation/')]
 frozen += [n for n in before if 'SOURCE_INVENTORY.json' in n or n.endswith(('SOURCE_SHA256.json','COR25_Q06_HANDOFF_STATE.json','05_CONSISTENCY_AND_REVOCATION.md'))]
 assert all(actual[n]==before[n] for n in frozen),'Protected source/history changed'
 t=json.loads((ROOT/'docs/session-validation/SVS_PR_TRACKER.json').read_text());assert t==json.loads((ROOT/'docs/session-validation/design/docs/SVS_PR_TRACKER.json').read_text())
 assert t['next_pr']=='SVS-07' and t['prs'][6]['status']=='ImplementedLocalCoherentCacheTestsPendingNativeAcceptance'
 assert [p['status'] for p in t['prs'][:6]]==m['previous_pr_statuses']
 assert len(t['prs'])==24 and [p['id'] for p in t['prs']]==[f'SVS-{i:02d}' for i in range(24)]
 assert t['open_findings']==m['previous_open_findings'],'Native findings were promoted'
 assert {p['id']:p.get('depends_on',[]) for p in t['prs']}==m['previous_dependencies']
 for script in ['inspect-cache-contract.py','inspect-identity-spec.py','audit-readonly-sql.py']:
  r=subprocess.run([sys.executable,str(ROOT/'eng/session-validation'/script)],capture_output=True,text=True);assert not r.returncode,r.stdout+r.stderr
 print(json.dumps(dict(stage='SVS-06',status='PASS',baseline='SVS-05 reimplementation',predecessor_archive_sha256=m['predecessor_archive_sha256'],source_files=len(actual)+1,baseline_files=len(before),modified=changed,added_count=len(added)+1,deleted=0,public_application_core_contracts_canonical_sql_identity_pins='byte-identical to SVS-05',production_cache_admission='StructurallyDisabled',native_cases_executed=0,release_ready=False),indent=2))
if __name__=='__main__':main()
