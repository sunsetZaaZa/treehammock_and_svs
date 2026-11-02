#!/usr/bin/env python3
"""Verify the exact SVS10 source and narrowly declared delta; no native qualification."""
from pathlib import Path
import hashlib,json
R=Path(__file__).resolve().parents[2];M='docs/session-validation/SVS-10_SOURCE_INVENTORY.json';IGNORE={'.git','bin','obj','__pycache__','TestResults'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 m=json.loads((R/M).read_text());before=m['baseline_files'];actual={p.relative_to(R).as_posix():sha(p) for p in sorted(R.rglob('*')) if p.is_file() and not set(p.parts)&IGNORE and p.suffix!='.pyc' and p.relative_to(R).as_posix()!=M}
 assert actual==m['files'],'Source drift'
 changed=sorted(n for n in before.keys()&actual.keys() if before[n]!=actual[n]);added=sorted(actual.keys()-before.keys());assert changed==m['expected_modified'] and added==m['expected_added'] and not before.keys()-actual.keys()
 runtime={'src/Treehammock.SessionValidation.Core/TreehammockSessionPolicyEvaluator.cs',*['src/Treehammock.SessionValidation.Storage/'+n for n in ['AuthSessionProjection.cs','CoherentSessionCacheReader.cs','SessionEvidenceCoordinator.cs','AuthorityProjectionMapper.cs']]}
 testprojects={'tests/Treehammock.SessionValidation.HostTests/Treehammock.SessionValidation.HostTests.csproj','tests/Treehammock.SessionValidation.DragonflyTests/Treehammock.SessionValidation.DragonflyTests.csproj'}
 assert all(n in runtime|testprojects or n.startswith('docs/session-validation/') for n in changed)
 assert all(actual[n]==before[n] for n in before if not n.startswith('docs/session-validation/') and n not in runtime|testprojects)
 assert all(actual[n]==before[n] for n in before if n.endswith('.lock.json') or 'SOURCE_INVENTORY.json' in n or n.endswith(('_DELIVERY.md','_READINESS.md')))
 assert all(n.startswith(('tests/Treehammock.SessionValidation.HostTests/','tests/Treehammock.SessionValidation.DragonflyTests/','docs/session-validation/','deploy/session-validation/','eng/session-validation/')) for n in added)
 mapper='src/Treehammock.SessionValidation.Storage/AuthorityProjectionMapper.cs';assert hashlib.sha256((R/mapper).read_text().replace('internal static EntitlementPolicyInputs ParseEntitlements','private static EntitlementPolicyInputs ParseEntitlements').encode()).hexdigest()==before[mapper]
 t=json.loads((R/'docs/session-validation/SVS_PR_TRACKER.json').read_text());assert t==json.loads((R/'docs/session-validation/design/docs/SVS_PR_TRACKER.json').read_text())
 assert len(t['prs'])==24 and t['prs'][:10]==m['previous_pr_records'] and t['open_findings']==m['previous_open_findings'] and t['next_pr']=='SVS-11' and t['prs'][10]['status']=='ImplementedLocalJointConformancePendingNativeAcceptance'
 print(json.dumps(dict(status='PASS',stage='SVS-10',source_files=len(actual)+1,baseline_files=len(before),modified=changed,added=len(added)+1,deleted=0,public_app_sql_sdk_grpc_pins_locks='Unchanged',shared_reconciliation='Five narrow common/internal visibility changes; see SVS10_PEER_PINS.json',native_executions=0,release_ready=False),indent=2))
if __name__=='__main__':main()
