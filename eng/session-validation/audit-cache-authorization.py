#!/usr/bin/env python3
"""CA01-CA08 source review against exact THS-12C. No native attestation."""
import argparse,json,hashlib,re,importlib.util
from pathlib import Path
R=Path(__file__).resolve().parents[2]
S='src/Treehammock.SessionValidation.Storage/';A='src/Treehammock.SessionValidation.Api/'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def audit(peer,output):
 output.mkdir(parents=True,exist_ok=True)
 contract=json.loads((peer/'docs/session-validation/treehammock/THS-12C_SHARED_CONTRACT.json').read_text())
 for n,h in contract['pins'].items():assert sha(peer/n)==h,n
 shared=['AuthorityVersion.cs','AuthorityProjectionBuilder.cs','CacheTransition.cs','CacheCommandWait.cs','ConditionalProjectionPublisher.cs','DragonflyAuthorityStore.cs','PublicationCacheUnavailableException.cs','SvsRefillDatabase.cs','authority-transition.lua','CoherentCacheCodec.cs','CachedAccountAuthority.cs']
 for n in shared:assert (R/S/n).read_bytes()==(peer/S/n).read_bytes(),n
 for f in (R/'src/Treehammock.SessionValidation.Core').glob('*.cs'):assert f.read_bytes()==(peer/f.relative_to(R)).read_bytes(),f.name
 assert (R/'contracts/authority-fleet-v2.schema.json').read_bytes()==(peer/'contracts/authority-fleet-v2.schema.json').read_bytes()
 assert (R/'contracts/coherent-cache-v1.schema.json').read_bytes()==(peer/'contracts/coherent-cache-v1.schema.json').read_bytes()
 for name in ['FleetProtocol.cs','AuthorityFleetGate.cs','FleetPolicyHashes.cs']:
  assert (R/A/'Fleet'/name).read_bytes()==(peer/'Rigging/Fleet'/name).read_bytes(),name
 for f in ['OwnedRefillSender.cs','HttpsRefillTransport.cs']:assert not (R/A/f).exists(),f
 retired=['Services/AuthorityRefillListener.cs','Services/AuthorityRefillWorker.cs','Services/SessionCacheWarmupWorker.cs','Repos/SessionPublicationRepo.cs','Repos/SessionCacheWarmupRepo.cs']
 for f in retired:assert not (peer/f).exists(),f
 # Rerun peer collector on actual source. Its descriptive protocol/pr fields are
 # historical; correct only those labels and retain every actual scan result.
 spec=importlib.util.spec_from_file_location('peer_collector',peer/'eng/session-validation/treehammock-inventory.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);coverage=m.build(peer)
 coverage['pr']='THS-12C reviewed by SVS-11';coverage['private_fleet_listener']['route']='POST /internal/v2/authority-fleet';coverage['private_fleet_listener']['route_review']='Verified against exact FleetProtocol.cs; collector had stale v1 description.'
 assert coverage['private_refill_listener'] is None
 (output/'THS12C_WRITER_COVERAGE_REVIEW.json').write_text(json.dumps(coverage,indent=2,sort_keys=True)+'\n')
 rows=[]
 tests={
 'CA01':['FleetProtocolTests.Exact_THS12C_fixture_hashes_and_binding_decode_with_both_named_policies','peer-selected.xml:Ths03ProjectionBuilderTests'],
 'CA02':['peer-selected.xml:Ths05SessionCallsiteTests/Ths06AccountAuthorityTests/Ths07WorkerInputTests/Ths10PrivilegeBoundaryTests','THS12C_WRITER_COVERAGE_REVIEW.json (conservative source enumeration, not per-routine native execution)'],
 'CA03':['ProjectionOwnershipTests.Cancelled_CAS_retains_guard_until_actual_native_completion','ProjectionOwnershipTests.Timed_out_post_lock_read_keeps_guard_and_fleet_slot_until_raw_read_cleanup','peer-selected.xml:Ths04CacheAuthorityTests/Ths12CRefillOwnershipTests'],
 'CA04':['CoherentHostTests.Drain_waits_for_full_response_and_late_SQL_then_probes_each_actual_named_identity','FleetProtocolTests.Boot_generation_binding_and_single_use_prepare_token_are_enforced_without_native_gate','LifetimeTests.Response_and_downstream_must_both_finish_before_releasing_the_slot'],
 'CA05':['CoherentHostTests.Production_factory_registers_real_coherent_resources_without_manual_admission_flags','CoherentHostTests.Private_v2_activation_enables_normal_signed_cache_hits_with_zero_foreground_SQL_or_refill'],
 'CA06':['CoherentHostTests.Private_v2_activation_enables_normal_signed_cache_hits_with_zero_foreground_SQL_or_refill','peer-selected.xml:Ths12ReaderTests'],
 'CA07':['LocalRefillTests (capacity, deduplication, cooldown, rate, queue age, epoch, late provider, scan drain)','StorageTests:TreehammockIdentityTests','foreground-readonly-audit.log'],
 'CA08':['CoherentHostTests.Drain_waits_for_full_response_and_late_SQL_then_probes_each_actual_named_identity','FleetProtocolTests (named inventories, boot/generation replay, v1 refusal)','peer-selected.xml:Ths11FleetTests/Ths11FleetTlsTests']}
 def row(c,project,root,path,symbol=None,status='ImplementedSourceReviewed'):
  p=root/path;assert p.is_file(),path
  rows.append(dict(requirement_id=c,project=project,source_path=path,symbol=symbol or p.stem,source_sha256=sha(p),implementation_status=status,test_evidence=tests[c],missing_work_owner=None,native_qualification='NotRun; local tests use infrastructure doubles'))
 svs={
 'CA01':[S+n for n in shared]+['contracts/coherent-cache-v1.schema.json'],
 'CA02':[A+'CoherentResources.cs',A+'RefillSettings.cs',S+'SvsRefillDatabase.cs','deploy/session-validation/ths12c/100_svs_refill.sql','deploy/session-validation/ths12c/publication-database-policy.json'],
 'CA03':[S+'AuthorityProjectionBuilder.cs',S+'ConditionalProjectionPublisher.cs',S+'CacheTransition.cs',S+'authority-transition.lua',A+'OwnedProjectionLeases.cs'],
 'CA04':[A+'SvsHost.cs',A+'CoherentResources.cs',A+'FleetAgent.cs',A+'HostLifecycle.cs',A+'ResponseLifetime.cs',A+'RequestLifetime.cs',A+'RuntimeCache.cs',A+'Fleet/AuthorityFleetGate.cs'],
 'CA05':[A+'HostSettings.cs',A+'RefillSettings.cs',A+'SvsHost.cs',A+'CoherentResources.cs',S+'CoherentSessionCacheReader.cs'],
 'CA06':[S+'SessionEvidenceCoordinator.cs',S+'CoherentSessionCacheReader.cs',A+'ValidationService.cs','src/Treehammock.SessionValidation.Core/TreehammockSessionPolicyEvaluator.cs'],
 'CA07':[A+'LocalRefillWorker.cs',A+'CoherentResources.cs',A+'RuntimeCache.cs',S+'SvsRefillDatabase.cs',S+'NpgsqlSnapshotExecutor.cs',S+'YsqlSessionAuthority.cs',S+'ValidatorDatabaseIdentity.cs',S+'TreehammockIdentityPolicy.cs',S+'TreehammockIdentityAuditor.cs'],
 'CA08':[A+'RuntimeCache.cs',A+'CoherentResources.cs',A+'FleetAgent.cs',A+'Fleet/FleetProtocol.cs',A+'Fleet/AuthorityFleetGate.cs',A+'OwnedProjectionLeases.cs']}
 ths={
 'CA01':[S+n for n in shared]+['contracts/coherent-cache-v1.schema.json'],
 'CA02':['Rigging/Authority/SessionMutationGuard.cs','Rigging/Authority/AccountAuthorityRuntime.cs','Services/AuthorityGlobalPolicyBoundary.cs','Services/DatabaseRoleBoundary.cs','Rigging/Database/Current/080_database_roles.sql','Rigging/Database/Current/100_svs_refill.sql','deploy/authority/THS10_DATABASE_POLICY.json'],
 'CA03':['Rigging/Cache/Authority/CacheAuthorityFence.cs','Rigging/Cache/Authority/ConditionalProjectionPublisher.cs','Rigging/Cache/Authority/AuthorityCacheWriterRuntime.cs','Rigging/Authority/SessionMutationGuard.cs',S+'ConditionalProjectionPublisher.cs',S+'authority-transition.lua'],
 'CA04':['Services/AuthorityFleetListener.cs','Services/AuthorityFleetRequestMiddleware.cs','Rigging/Fleet/AuthorityFleetGate.cs','Rigging/Fleet/AuthorityFleetEndpoint.cs','Rigging/Fleet/FleetBindingVerifier.cs','Rigging/Cache/Authority/AuthorityCacheReaderRuntime.cs'],
 'CA05':['Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs','Rigging/Authentication/SessionRequestValidator.cs'],
 'CA06':['Rigging/Authentication/SessionRequestValidator.cs',S+'SessionEvidenceCoordinator.cs',S+'CoherentSessionCacheReader.cs'],
 'CA07':['Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs',S+'SvsRefillDatabase.cs','Rigging/Database/Current/100_svs_refill.sql','Rigging/Cache/Authority/ConditionalProjectionPublisher.cs'],
 'CA08':['Rigging/Fleet/FleetProtocol.cs','Rigging/Fleet/FleetControl.cs','Rigging/Fleet/FleetBindingVerifier.cs','Rigging/Fleet/LegacyFleetUpgrade.cs','Rigging/Fleet/SqlFleetStore.cs','Rigging/Cache/Authority/AuthorityCacheReaderRuntime.cs','Rigging/Cache/Authority/AuthorityCacheAclBoundary.cs']}
 for c,paths in svs.items():
  for n in paths:row(c,'SVS',R,n)
 for c,paths in ths.items():
  for n in paths:row(c,'TreeHammock THS-12C',peer,n)
 # Bind the complete actual caller/SQL/trigger/worker/admin scan, including
 # entitlement paths and proof/history paths which must not be erased wholesale.
 for n in sorted(coverage['source_files']):row('CA02','TreeHammock THS-12C',peer,n,status='EnumeratedConservativeSourceCoverage')
 for name,f in coverage['functions'].items():
  row('CA02','TreeHammock THS-12C',peer,m.SQL,name,'GuardedMutationOrIsolationBoundaryReviewed' if f['decision_changing_or_conservative'] else 'ReadProofOrMaintenancePathEnumerated')
 for trigger in coverage['triggers']:row('CA02','TreeHammock THS-12C',peer,m.SQL,'trigger:'+trigger['name'],'TriggerReachabilityEnumerated')
 checks=[(A+'SvsHost.cs',['new CoherentResources(s)','ResponseLifetime','FleetAgent']), (A+'CoherentResources.cs',['Admission.Admit(_space,_cache','OwnedProjectionLeases','_database.RouteAsync','new RuntimeDatabase(settings),new RuntimeCache(settings)']), (A+'FleetAgent.cs',['Gate.PrepareAsync','Gate.ActivateAsync','Gate.DrainAsync','fleet.ProbeAsync']), (A+'RuntimeCache.cs',['AuthenticationFailure','DemandMaster|CommandFlags.NoRedirect','_raw.DrainAsync','ACL','DRYRUN'])]
 for n,parts in checks:
  text=(R/n).read_text()
  for part in parts:assert part in text,(n,part)
 for f in (R/A).glob('*.cs'):assert not re.search(r'NativePassed|NativeQualificationPassed|PRComplete',f.read_text()),f
 result=dict(pr='SVS-11',peer_archive_sha256='364de19c8a5c65d82e79bbb22f745effeb59281d97a2dd10ae4b8e1d3a5d41b0',status='RequiredCodePresentSourceReviewedPendingNativeQualification',runtime_native_flag_required=False,normal_host_cache_authorization_implemented=True,rows=rows,source_review_counts=coverage['counts'],decision_changing_sql_routines=sum(bool(f['decision_changing_or_conservative']) for f in coverage['functions'].values()),retired_treehammock_background_paths=retired,missing_required_code=[],missing_work_owners=[],native_work_owner='SVS-13/15/19 and TreeHammock native qualification track; deployment owner for actual identities/ACLs/network',native_cases_executed=0,grant_rights=False,release_ready=False,limits=['Conservative static coverage and selected local tests do not prove every control-flow path or deployed privilege.','No live Yugabyte, Dragonfly, cross-host fleet, load, restore or failover execution.','Inherited COR/F01/F02 findings remain open; no release or enforcement acceptance inferred.'])
 (output/'CACHE_AUTHORIZATION_CODE_AUDIT.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--peer-root',type=Path,required=True);p.add_argument('--output',type=Path,default=R/'docs/session-validation');a=p.parse_args();r=audit(a.peer_root.resolve(),a.output.resolve());print(json.dumps({k:v for k,v in r.items() if k!='rows'},indent=2))
