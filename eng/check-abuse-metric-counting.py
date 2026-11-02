#!/usr/bin/env python3
"""COR23P supplemental source contracts. Does not execute C# providers or PromQL."""
import argparse,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TELEMETRY='Rigging/Observability/AbuseOperationalTelemetry.cs'
STORE='Rigging/Abuse/DragonflyAbuseCounterStore.cs'
DURABLE='Rigging/Abuse/PostgreSqlAbuseBudgetStore.cs'
LUA='Rigging/Abuse/Scripts/increment-v1.lua'
DASHBOARD='ops/grafana/dashboards/abuse-controls-1-0-0.json'
ADMISSIONS='treehammock_abuse_counter_admissions_v2_total'
CREATIONS='treehammock_abuse_cooldowns_created_v2_total'
BLOCKS='treehammock_abuse_cooldown_blocked_attempts_total'
def require(value,message):
 if not value:raise ValueError(message)
def validate(root):
 read=lambda p:(root/p).read_text()
 telemetry,store,durable,lua=map(read,[TELEMETRY,STORE,DURABLE,LUA])
 for name in [ADMISSIONS,CREATIONS,BLOCKS]:require(name in telemetry,'Distinct current counter absent: '+name)
 require('RecordPolicyDenied' not in telemetry and 'RecordPolicyAllowed' not in telemetry,'Generic denied observations must not create or duplicate events')
 admission=telemetry[telemetry.index('public static void RecordCounterAdmission'):telemetry.index('public static void RecordCounterStoreFailure')]
 require('CooldownsStarted.Add' not in admission and 'RecordCooldownStarted' not in admission,'Admission observation must not imply creation')
 require('!decision.CanAdmit && !decision.Unavailable && decision.ReasonCode == AbuseReasonCodes.FailureCooldownActive' in admission,'Blocked attempts must exclude new starts and store failures')
 require('NormalizeTagValue' not in telemetry and 'StringBuilder' not in telemetry,'Sanitization is not a finite value catalog')
 for token in ['Enum.IsDefined(feature)','Enum.IsDefined(dimension)','private static string ReasonName','private static string OperationName','private static string EventName','private static string OutcomeName','private static string DependencyName','_ => "unknown"']:
  require(token in telemetry,'Bounded tag catalog absent: '+token)
 for name in re.findall(r'const string (\w+) =',read('Rigging/Abuse/AbuseReasonCodes.cs')):require('AbuseReasonCodes.'+name+' =>' in telemetry,'Known reason missing from finite catalog: '+name)
 require('CounterDecision decision = await IncrementCoreAsync(key, limit, cancellationToken);' in store and store.count('RecordCounterAdmission(')==1,'Exactly one owner after aggregate admission resolution required')
 raw=store[store.index('private async Task<CounterDecision> CacheIncrementAsync'):store.index('public async Task ResetAsync')]
 for token in ['await Database.ScriptEvaluateAsync','values.Length != 5','created is < 0 or > 1','created != 0','created == 1 &&','CooldownCreated: created == 1','if (decision.CooldownCreated)','RecordCooldownStarted(key.Feature, key.Dimension, AbuseReasonCodes.CounterLimitExceeded, "dragonfly")']:
  require(token in raw,'Raw transition validation/measurement missing: '+token)
 require('Task<CounterDecision> raw = CacheIncrementAsync(key, limit);' in store and 'await WithTimeout(raw, timeout, cancellationToken)' in store,'Raw transition must outlive the caller wait')
 require('bool CooldownCreated = false' in read('Rigging/Abuse/AbuseModels.cs'),'Decision must carry atomic creation result')
 for token in ['started=reader.GetBoolean(4)','result = result with { CooldownCreated = started }','if (started &&','if (admission.Started)','AbuseReasonCodes.CounterLimitExceeded,"postgresql")']:
  require(token in durable,'Committed durable creation missing: '+token)
 require(durable.index('transaction.CommitAsync(token)')<durable.index('if (admission.Started)'),'No durable start before commit')
 require("'PX', cooldown, 'NX'" in lua and 'if created then return {0, count, cooldown, 2, 1} end' in lua,'Only successful atomic NX transition can report creation')
 require('return {0, math.min(count, 2147483647), math.max(1, cooldownTtl), 1, 0}' in lua,'Existing cooldown must not become a start')
 for directory in ['Controllers','Services']:
  for p in (root/directory).rglob('*.cs'):
   source=p.read_text();require('RecordPolicyDenied(' not in source and 'RecordCounterAdmission(' not in source and 'RecordCooldownStarted(' not in source,'Application caller cannot duplicate store telemetry: '+str(p))
 dashboard=json.loads(read(DASHBOARD));expressions=[t['expr'] for p in dashboard['panels'] for t in p.get('targets',[])]
 require(any(ADMISSIONS+'{outcome="denied"}' in e for e in expressions),'Denied panel must count admission owner')
 require(any('sum by (dependency, feature, dimension, reason)' in e and CREATIONS in e for e in expressions),'Creation panel must separate backends')
 require(any(BLOCKS in e for e in expressions),'Blocked attempts panel missing')
 require(all('treehammock_abuse_policy_decisions_total' not in e and 'treehammock_abuse_cooldowns_started_total' not in e for e in expressions),'Old semantics must not be mixed into dashboard queries')
 require('FullyQualifiedName~Cor23PTransitionMetricsTests' in read('eng/correction-baseline.py'),'Actual SQL/cache telemetry tests must be mandatory')
 require('python3 eng/check-abuse-metric-counting.py' in read('.github/workflows/treehammock-ci.yml'),'CI source boundary guard missing')
 for p in ['treehammock.Tests/Unit/TransitionTelemetryTests.cs','treehammock.Tests/Infrastructure/MetricCapture.cs','treehammock.Tests.SqlContracts/Integration/Database/TransitionMetricsTests.cs','ops/prometheus/abuse-counting-contract.test.yml']:
  require((root/p).exists(),'Native metric value/dashboard fixture absent: '+p)
 return dict(status='SourceContractsConsistent',qualification='NotRun',owner='one completed IncrementAsync outcome; not request counts',creation='validated raw Redis NX reply or committed PostgreSQL result',blocked='IncrementAsync denied by existing cooldown',unknown_values='finite unknown bucket',PromQL='NotRun')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args()
 try:print(json.dumps(validate(a.root),indent=2));return 0
 except(ValueError,OSError,KeyError) as e:print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
