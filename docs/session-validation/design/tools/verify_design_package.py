#!/usr/bin/env python3
"""No network; deterministic design package structural checks, not runtime tests."""
import hashlib,json,pathlib,re,sys
root=pathlib.Path(__file__).resolve().parents[1]
required=['README.md','docs/01_ARCHITECTURE.md','docs/02_TREEHAMMOCK_SOURCE_MAP.md',
'docs/03_PROTOCOL_AND_SDK.md','docs/04_SECURITY_THREAT_MODEL.md','docs/05_CONSISTENCY_AND_REVOCATION.md',
'docs/06_LINUX_DEPLOYMENT_AND_OPERATIONS.md','docs/07_TEST_AND_PERFORMANCE_PLAN.md',
'docs/08_PR_IMPLEMENTATION_PLAN.md','docs/09_ACCEPTANCE_MATRIX.md','docs/10_DECISION_REGISTER.md',
'docs/11_EXECUTIVE_SUMMARY.md','docs/12_SVS-02_READINESS.md','docs/CHANGELOG_v1_1.md','docs/13_SVS-03_READINESS.md','docs/14_SVS-04_READINESS.md','docs/15_SVS-05_READINESS.md','docs/16_SVS-06_READINESS.md','docs/17_SVS-07_READINESS.md','docs/18_CACHE_ONLY_ENABLEMENT.md','docs/19_SVS_THS12A_CONTINUATION.md','docs/20_SVS-08_READINESS.md','docs/21_SVS-09_READINESS.md','docs/22_SVS-08_IMPLEMENTATION.md','docs/23_SVS-10_READINESS.md','docs/24_SVS-09_IMPLEMENTATION.md','docs/25_SVS-10_IMPLEMENTATION.md','docs/26_SVS-11_READINESS.md','docs/SVS_PR_TRACKER.json','contracts/session-validation-v1.proto',
'contracts/auth-state-events-v1.json','provenance/SOURCE_EVIDENCE.json','provenance/SOURCE_STATUS.md']
issues=[f'missing {p}' for p in required if not (root/p).is_file()]
provenance=json.loads((root/'provenance/SOURCE_EVIDENCE.json').read_text())
tracker=json.loads((root/'docs/SVS_PR_TRACKER.json').read_text())
if len(tracker['prs'])!=24 or [p['id'] for p in tracker['prs']]!=[f'SVS-{i:02d}' for i in range(24)]:issues.append('invalid PR track')
plan=(root/'docs/08_PR_IMPLEMENTATION_PLAN.md').read_text()
for i in range(24):
 if len(re.findall(r'^## SVS-'+f'{i:02d}'+r':',plan,re.M))!=1:issues.append(f'missing PR section {i}')
for rel in required:
 if rel.endswith('.md'):
  data=(root/rel).read_text()
  if data.count('```')%2:issues.append(f'unpaired code fence {rel}')
if not provenance.get('source_archive_sha256') or len(provenance['source_archive_sha256'])!=64:issues.append('missing reviewed archive digest')
if 'Blocked/NotRun' not in (root/'provenance/SOURCE_STATUS.md').read_text():issues.append('native release qualification qualification caveat missing')
for n,entry in provenance['files'].items():
 if 'sha256' in entry and len(entry['sha256'])!=64:issues.append(f'invalid source hash for {n}')
if 'Broker-free joint contract conformance' not in plan or tracker.get('auth_messaging') is None:issues.append('current broker-free authentication decision absent')

for i,p in enumerate(tracker['prs']):
 for dep in p.get('depends_on',[]):
  if dep not in [f'SVS-{j:02d}' for j in range(i)]:issues.append(f'invalid dependency {p["id"]}: {dep}')
if tracker.get('next_pr')!='SVS-11' or tracker['prs'][10]['status']!='ImplementedLocalJointConformancePendingNativeAcceptance' or tracker['prs'][9]['status']!='ImplementedLocalTypedClientPendingNativeAcceptance' or tracker['prs'][8]['status']!='ImplementedLocalGrpcAndOwnedRefillPendingNativeAcceptance' or tracker['prs'][7]['status']!='ImplementedLocalHostAndIdentityCompatibilityPendingNativeAcceptance' or tracker['prs'][6]['status']!='ImplementedLocalCoherentCacheTestsPendingNativeAcceptance' or tracker['prs'][5]['status']!='ImplementedLocalIdentityChecksPendingNativeAcceptance' or tracker['prs'][2]['status']!='ImplementedLocalParityTestsPassed' or tracker['prs'][3]['status']!='ImplementedLocalHttpParityPendingNativeAcceptance' or tracker['prs'][4]['status']!='ImplementedLocalStorageTestsPendingNativeAcceptance':issues.append('next PR status drift')
if tracker['prs'][0]['status']!='ImplementedPendingNativeAcceptance' or tracker['prs'][1]['status']!='ImplementedLocalContractTestsPassed':issues.append('completed status reset')
policy=(root/'docs/05_CONSISTENCY_AND_REVOCATION.md').read_text()
for phrase in ['zero per-request YSQL calls','compare-and-replace','single serving primary','fresh **empty** namespace','current authority snapshot']:
 if phrase not in policy:issues.append(f'missing cache-first invariant {phrase}')
if 'SVS-11' not in tracker['prs'][12]['depends_on'] or 'SVS-11' not in tracker['prs'][13]['depends_on']:issues.append('coherence dependency absent')
if tracker.get('design_revision')!='1.6-svs10-joint-conformance-2026-10-19':issues.append('design revision mismatch')
for rel in required:
 if rel.endswith('.md'):
  data=(root/rel).read_text()
  for pattern in [r'every Active requires YSQL',r'All Active decisions require current authoritative YSQL evidence',r'primary-consistent read on every Active response',r'cache never authorizes without DB']:
   if re.search(pattern,data,re.I):issues.append(f'obsolete policy in {rel}')

print(json.dumps({'checked_files':len(required),'pr_count':len(tracker['prs']),
   'status':'PASS' if not issues else 'FAIL','scope':'documentation structure and frozen policy only; no .NET or DB code executed','issues':issues},indent=2))
sys.exit(bool(issues))
