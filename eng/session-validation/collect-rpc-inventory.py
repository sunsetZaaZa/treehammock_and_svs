#!/usr/bin/env python3
"""Verify current SVS08 bytes and immutable predecessor boundaries; no native claims."""
from pathlib import Path
import hashlib,json,xml.etree.ElementTree as ET
R=Path(__file__).resolve().parents[2]
M='docs/session-validation/SVS-08_SOURCE_INVENTORY.json'
IGNORE={'.git','bin','obj','__pycache__','TestResults'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 m=json.loads((R/M).read_text());before=m['baseline_files']
 actual={p.relative_to(R).as_posix():sha(p) for p in sorted(R.rglob('*')) if p.is_file() and not set(p.parts)&IGNORE and p.suffix!='.pyc' and p.relative_to(R).as_posix()!=M}
 assert actual==m['files'],'Source drift'
 changed=sorted(n for n in before.keys()&actual.keys() if before[n]!=actual[n]);added=sorted(actual.keys()-before.keys())
 assert changed==m['expected_modified'] and added==m['expected_added'] and not before.keys()-actual.keys()
 allowed={'Directory.Packages.props','src/Treehammock.SessionValidation.Storage/Treehammock.SessionValidation.Storage.csproj','src/Treehammock.SessionValidation.Storage/CoherentSessionCacheReader.cs','eng/session-validation/inspect-host-contract.py'}
 assert all(n in allowed or n.startswith(('docs/session-validation/','src/Treehammock.SessionValidation.Api/')) or n=='tests/Treehammock.SessionValidation.HostTests/packages.lock.json' for n in changed)
 assert all(n.startswith(('docs/session-validation/','deploy/session-validation/','eng/session-validation/','src/Treehammock.SessionValidation.Api/','tests/Treehammock.SessionValidation.HostTests/')) for n in added)
 historical=[n for n in before if 'SOURCE_INVENTORY.json' in n or n.endswith(('_DELIVERY.md','_READINESS.md'))]
 assert all(actual[n]==before[n] for n in historical)
 assert all(actual[n]==before[n] for n in before if n.startswith(('src/Treehammock.SessionValidation.Core/','src/Treehammock.SessionValidation.Contracts/','contracts/','DataLayer/','Controllers/','Services/','Repos/','Rigging/','RiggingSupport/')))
 oldlocks=[n for n in before if n.endswith('packages.lock.json') and n not in ['src/Treehammock.SessionValidation.Api/packages.lock.json','tests/Treehammock.SessionValidation.HostTests/packages.lock.json']]
 assert all(actual[n]==before[n] for n in oldlocks)
 versions={e.attrib['Include']:e.attrib['Version'] for e in ET.parse(R/'Directory.Packages.props').getroot().iter('PackageVersion')}
 assert versions==m['package_versions'] and versions.pop('Grpc.AspNetCore.Server')=='2.84.0'
 assert versions==m['baseline_package_versions']
 t=json.loads((R/'docs/session-validation/SVS_PR_TRACKER.json').read_text());assert t==json.loads((R/'docs/session-validation/design/docs/SVS_PR_TRACKER.json').read_text())
 assert len(t['prs'])==24 and t['prs'][:8]==m['previous_pr_records'] and t['open_findings']==m['previous_open_findings']
 assert t['next_pr']=='SVS-09' and t['prs'][8]['status']=='ImplementedLocalGrpcAndOwnedRefillPendingNativeAcceptance'
 print(json.dumps(dict(stage='SVS-08',status='PASS',source_files=len(actual)+1,baseline_files=len(before),modified=changed,added_count=len(added)+1,deleted=0,public_core_contracts_canonical_sql='Unchanged',old_locks_except_Api_HostTests='Unchanged',shared_cache_change='Read-only current-epoch query only; qualification remains internal',cache_reader_coordinator_codec='Authorization behavior unchanged',production_admission='Temporarily unadmitted; actual enablement SVS-11',native_executions=0,release_ready=False),indent=2))
if __name__=='__main__':main()
