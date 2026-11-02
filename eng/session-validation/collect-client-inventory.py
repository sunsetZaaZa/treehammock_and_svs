#!/usr/bin/env python3
"""Exact SVS09 bytes and declared boundaries; no native acceptance."""
from pathlib import Path
import hashlib,json,xml.etree.ElementTree as ET
R=Path(__file__).resolve().parents[2];M='docs/session-validation/SVS-09_SOURCE_INVENTORY.json';IGNORE={'.git','bin','obj','__pycache__','TestResults'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 m=json.loads((R/M).read_text());before=m['baseline_files'];actual={p.relative_to(R).as_posix():sha(p) for p in sorted(R.rglob('*')) if p.is_file() and not set(p.parts)&IGNORE and p.suffix!='.pyc' and p.relative_to(R).as_posix()!=M};assert actual==m['files'],'Source drift'
 changed=sorted(n for n in before.keys()&actual.keys() if before[n]!=actual[n]);added=sorted(actual.keys()-before.keys());assert changed==m['expected_modified'] and added==m['expected_added'] and not before.keys()-actual.keys()
 api='src/Treehammock.SessionValidation.Api/ValidationService.cs';allowed={'Directory.Packages.props',api,'tests/Treehammock.SessionValidation.HostTests/Treehammock.SessionValidation.HostTests.csproj','tests/Treehammock.SessionValidation.HostTests/packages.lock.json'}
 assert all(n in allowed or n.startswith('docs/session-validation/') for n in changed)
 assert all(actual[n]==before[n] for n in before if n not in allowed and not n.startswith('docs/session-validation/'))
 assert all(actual[n]==before[n] for n in before if 'SOURCE_INVENTORY.json' in n or n.endswith(('_DELIVERY.md','_READINESS.md')))
 assert all(n.startswith(('src/Treehammock.SessionValidation.Client/','tests/Treehammock.SessionValidation.ClientTests/','docs/session-validation/','deploy/session-validation/','eng/session-validation/')) or n=='tests/Treehammock.SessionValidation.HostTests/SdkIntegrationTests.cs' for n in added)
 s=(R/api).read_text();a=s.index('            // Optional transport ceiling');b=s.index('            using var timeout',a);assert hashlib.sha256((s[:a]+s[b:]).encode()).hexdigest()==before[api]
 versions={e.attrib['Include']:e.attrib['Version'] for e in ET.parse(R/'Directory.Packages.props').getroot().iter('PackageVersion')};assert versions.pop('Grpc.Net.Client')=='2.84.0' and versions==m['baseline_package_versions']
 t=json.loads((R/'docs/session-validation/SVS_PR_TRACKER.json').read_text());assert t==json.loads((R/'docs/session-validation/design/docs/SVS_PR_TRACKER.json').read_text())
 assert len(t['prs'])==24 and t['prs'][:9]==m['previous_pr_records'] and t['open_findings']==m['previous_open_findings'] and t['next_pr']=='SVS-10' and t['prs'][9]['status']=='ImplementedLocalTypedClientPendingNativeAcceptance'
 print(json.dumps(dict(status='PASS',stage='SVS-09',source_files=len(actual)+1,baseline_files=len(before),modified=changed,added=len(added)+1,deleted=0,public_core_contracts_storage_sql='Unchanged',server_delta='Strict optional original deadline ceiling only',native_executions=0,release_ready=False),indent=2))
if __name__=='__main__':main()
