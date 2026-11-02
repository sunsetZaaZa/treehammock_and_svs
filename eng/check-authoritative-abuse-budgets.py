#!/usr/bin/env python3
"""COR23M source contracts; PostgreSQL/cache races and host qualification remain native obligations."""
import argparse,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
CALLERS=['Controllers/AccountControllerBase.LoginHelpers.cs','Controllers/AccountControllerBase.TwoFactorHelpers.cs','Services/DeliveryAbuseThrottleService.cs','Services/PasswordResetService.cs','Services/PasswordResetPublicGate.cs','Services/AccountRecoveryService.cs','Services/AccountService.cs','Services/ActivationService.cs','Rigging/Abuse/SignupAdmissionPolicy.cs','Rigging/Abuse/SensitiveActionAdmissionPolicy.cs']
def require(v,m):
 if not v:raise ValueError(m)
def validate(root):
 read=lambda p:(root/p).read_text()
 store=read('Rigging/Abuse/DragonflyAbuseCounterStore.cs')
 require('AllowWhenCounterStoreUnavailable' not in store and 'AllowWhenPostgreSqlAuthoritativeStateExists' not in store,'Global configuration cannot manufacture admission authority')
 for token in ['_durablePolicies = new(','_requireDurable =','UsesDurableBudget(key)','authoritative = await DurableIncrement(key, limit, cancellationToken)','if (!authoritative.CanAdmit)','authoritative?.CanAdmit == true','CounterStoreAvailability.Unavailable','RecordDurableFailure("reset", ex); return;','_durable.GetCooldownAsync(key, ct)','!authoritative.Unavailable']:
  require(token in store,'Missing authoritative fallback boundary: '+token)
 require(store.index('authoritative = await DurableIncrement')<store.index('Database.ScriptEvaluateAsync'),'SQL budget must be enforced during healthy cache periods, before Redis')
 require(store.count('_requireDurable =')==2,'Both store construction paths must snapshot policy mode')
 catalog=read('Rigging/Abuse/AbuseCounterPolicyCatalog.cs')
 for token in ['Version = 1','AbuseFeature.Login or AbuseFeature.Delivery','AbuseCounterDimension.Account or AbuseCounterDimension.IdentifierFingerprint or AbuseCounterDimension.IpFingerprint','policies.Any(p => !SupportsPostgreSqlBudget(p))','policies.Distinct().Count() != policies.Count','AbuseCounterFailureMode.FailClosed => policies.Count == 0','AbuseCounterFailureMode.RequirePostgreSqlBudgetV1 => policies.Count > 0']:
  require(token in catalog,'Capability catalog/configuration missing: '+token)
 settings=read('Rigging/Config/AbuseControlSettings.cs');require('AbuseCounterPolicyCatalog.ValidConfiguration(this)' in settings and 'RequirePostgreSqlBudgetV1 = 1' in settings and 'AllowWhenPostgreSqlAuthoritativeStateExists' not in settings,'Startup must reject unsupported/unversioned fallback')
 model=read('Rigging/Abuse/AbuseModels.cs');require('CanAdmit => Allowed && !Unavailable' in model and 'BlocksAdmission => Active || Unavailable' in model,'Unavailable may never masquerade as allow/inactive')
 for path in CALLERS:require('CanAdmit' in read(path),'Counter caller must consume availability: '+path)
 repo=read('Rigging/Abuse/PostgreSqlAbuseBudgetStore.cs')
 for token in ['SHA256.HashData','transaction.CommitAsync(token)','set_config(\'statement_timeout\'','set_config(\'lock_timeout\'','AbuseCounterPolicyCatalog.SupportsPostgreSqlBudget(key)','cor23m_increment_budget_v1','cor23m_budget_cooldown_v1','cor23m_reset_budget_v1','cor23m_purge_budgets_v1']:
  require(token in repo,'Production durable owner missing: '+token)
 require(repo.index('transaction.CommitAsync(token)')<repo.index('return result;'),'Durable decision must not return before commit')
 sql=read('Rigging/Database/Baseline/000_treehammock_canonical_database.sql');start=sql.index('create table abuse_admission_budgets_v1');sql=sql[start:]
 for token in ['policy_id in (0,2)','dimension_id in (0,1,2)','octet_length(budget_hash)=32','on conflict(policy_id,dimension_id,budget_hash) do update','returning b.* into v_row','v_now:=clock_timestamp();','v_row.window_expires_at<=v_now','v_row.attempt_count<=p_maximum','v_row.cooldown_until>v_now','retain_until<=v_now','limit p_batch for update skip locked','if p_dry then','set search_path to pg_catalog,%I,public,pg_temp']:
  require(token in sql,'Atomic SQL budget/expiry boundary missing: '+token)
 increment=sql[:sql.index('create or replace function cor23m_budget_cooldown_v1')]
 require('v_now:=clock_timestamp();' in increment,'Increment must sample server clock after row acquisition')
 require(sql.count('limit p_batch for update skip locked')==2,'Both cleanup branches must be bounded and skip locked')
 require(increment.index('returning b.* into v_row')<increment.index('v_now:=clock_timestamp();'),'Budget clock must be sampled after locking existing row')
 worker=read('Services/PostgreSqlAbuseBudgetCleanupWorker.cs');require('budgets.PurgeExpiredAsync(settings.BatchSize,settings.DryRun,ct)' in worker and 'settings.Enabled' in worker and 'RequirePostgreSqlBudgetV1' in worker,'Cleanup must preserve retention controls')
 di=read('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs');require('AddSingleton<IPostgreSqlAbuseBudgetStore, PostgreSqlAbuseBudgetStore>' in di and 'AddHostedService<PostgreSqlAbuseBudgetCleanupWorker>' in di and 'provider.GetRequiredService<IPostgreSqlAbuseBudgetStore>() : null' in di,'Production authoritative budget registration missing')
 for path in ['appsettings.json','appsettings.Example.json']:
  o=json.loads(read(path))['AbuseControlSettings'];require(o['CounterFailureMode']=='FailClosed' and o['PostgreSqlFallbackPolicies']==[],'Default must not enable degraded mode')
 for path in ['treehammock.Tests/Unit/AuthoritativeBudgetTests.cs','treehammock.Tests/Integration/BudgetStartupTests.cs','treehammock.Tests.SqlContracts/Integration/Database/AbuseBudgetTests.cs']:require((root/path).exists(),'Native regression missing: '+path)
 require('FullyQualifiedName~Cor23MAbuseBudgetTests' in read('eng/correction-baseline.py'),'Real SQL/cache regressions must be mandatory')
 require('python3 eng/check-authoritative-abuse-budgets.py' in read('.github/workflows/treehammock-ci.yml'),'CI source guard missing')
 return dict(status='SourceContractsConsistent',qualification='NotRun',version=1,SQL_supported_policies=['Login','Delivery'],dimensions=['Account','IdentifierFingerprint','IpFingerprint'],other_policies='FailClosed on cache failure; no equivalent budget assumed',native_required=['multi-owner PostgreSQL/cache outage/recovery threshold matrix','window/cooldown and observed lock schedules','startup selection rejection and denied work'])
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args()
 try:print(json.dumps(validate(a.root),indent=2));return 0
 except(ValueError,OSError,KeyError) as e:print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
