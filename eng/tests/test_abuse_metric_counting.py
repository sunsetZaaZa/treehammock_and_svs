"""Supplemental boundary mutations and synthetic event series; native MeterListener/PromQL are separate."""
import importlib.util,json,re,shutil,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('counting',ROOT/'eng/check-abuse-metric-counting.py');counting=importlib.util.module_from_spec(spec);spec.loader.exec_module(counting)
def event_sum(expression,series):
 """Evaluate metric selection/grouping over synthetic event deltas, not PromQL range extrapolation."""
 name=re.search(r'(treehammock_\w+_total)',expression).group(1)
 selector=re.search(r'\{([^}]*)\}',expression);filters=dict(re.findall(r'(\w+)="([^"]+)"',selector.group(1))) if selector else {}
 group=re.search(r'sum by \(([^)]+)\)',expression);labels=tuple(x.strip() for x in group.group(1).split(',')) if group else ()
 out={}
 for metric,tags,delta in series:
  if metric!=name or any(tags.get(k)!=v for k,v in filters.items()):continue
  key=tuple(tags[k] for k in labels);out[key]=out.get(key,0)+delta
 return out
class MetricCountingTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','bin','obj','.correction-results','.artifacts','TestResults','__pycache__'))
 def tearDown(self):self.temp.cleanup()
 def reject(self,path,old,new):
  p=self.root/path;s=p.read_text();self.assertIn(old,s);p.write_text(s.replace(old,new,1))
  with self.assertRaises(ValueError):counting.validate(self.root)
 def test_consistent_source_is_not_native_qualification(self):self.assertEqual('NotRun',counting.validate(self.root)['qualification'])
 def test_admission_metric_has_distinct_semantics(self):self.reject(counting.TELEMETRY,counting.ADMISSIONS,'treehammock_abuse_policy_decisions_total')
 def test_creation_metric_has_distinct_semantics(self):self.reject(counting.TELEMETRY,counting.CREATIONS,'treehammock_abuse_cooldowns_started_total')
 def test_generic_denial_must_not_create_cooldowns(self):self.reject(counting.TELEMETRY,'        PolicyDecisions.Add(1,','        RecordCooldownStarted(feature, dimension, decision.ReasonCode, "dragonfly");\n        PolicyDecisions.Add(1,')
 def test_blocked_attempt_cannot_include_new_start(self):self.reject(counting.TELEMETRY,'decision.ReasonCode == AbuseReasonCodes.FailureCooldownActive','true')
 def test_bounded_enum_catalog(self):self.reject(counting.TELEMETRY,'Enum.IsDefined(feature)','true')
 def test_bounded_dimension_catalog(self):self.reject(counting.TELEMETRY,'Enum.IsDefined(dimension)','true')
 def test_all_known_reasons_are_catalogued(self):self.reject(counting.TELEMETRY,'AbuseReasonCodes.CounterStoreTimeout =>','"private-reason" =>')
 def test_unrestricted_values_are_not_sanitized_into_tags(self):self.reject(counting.TELEMETRY,'private static string ReasonName','private static string NormalizeTagValue')
 def test_terminal_metric_follows_aggregate_resolution(self):self.reject(counting.STORE,'CounterDecision decision = await IncrementCoreAsync(key, limit, cancellationToken);','CounterDecision decision = new(true, 1, 1, limit.Window, null, null);')
 def test_single_counting_owner(self):self.reject(counting.STORE,'        return decision;','        AbuseOperationalTelemetry.RecordCounterAdmission(key.Feature, key.Dimension, decision);\n        return decision;')
 def test_atomic_flag_reaches_decision(self):self.reject(counting.STORE,'CooldownCreated: created == 1','CooldownCreated: false')
 def test_malformed_flag_cannot_create_event(self):self.reject(counting.STORE,'created is < 0 or > 1','false')
 def test_admitted_reply_cannot_claim_creation(self):self.reject(counting.STORE,'created != 0','false')
 def test_raw_creation_survives_abandoned_wait(self):self.reject(counting.STORE,'await WithTimeout(raw, timeout, cancellationToken)','await raw')
 def test_transition_measurement_requires_flag(self):self.reject(counting.STORE,'if (decision.CooldownCreated)','if (true)')
 def test_durable_committed_flag_is_exposed(self):self.reject(counting.DURABLE,'result = result with { CooldownCreated = started }','result = result with { CooldownCreated = false }')
 def test_durable_measurement_requires_flag(self):self.reject(counting.DURABLE,'if (admission.Started)','if (true)')
 def test_NX_result_owns_start(self):self.reject(counting.LUA,'if created then return {0, count, cooldown, 2, 1} end','return {0, count, cooldown, 2, 1}')
 def test_repeat_denial_is_not_start(self):self.reject(counting.LUA,'math.max(1, cooldownTtl), 1, 0','math.max(1, cooldownTtl), 1, 1')
 def test_application_cannot_double_record(self):
  self.reject('Services/AccountRecoveryService.cs','        return AbuseDecision.Deny(reasonCode, decision.RetryAfter);','        AbuseOperationalTelemetry.RecordCounterAdmission(key.Feature, key.Dimension, decision);\n        return AbuseDecision.Deny(reasonCode, decision.RetryAfter);')
 def test_dashboard_separates_backend_creations(self):self.reject(counting.DASHBOARD,'sum by (dependency, feature, dimension, reason)','sum by (feature, dimension, reason)')
 def test_old_metric_series_cannot_contaminate_dashboard(self):self.reject(counting.DASHBOARD,counting.ADMISSIONS,'treehammock_abuse_policy_decisions_total')
 def test_actual_provider_metrics_suite_is_mandatory(self):self.reject('eng/correction-baseline.py','|FullyQualifiedName~Cor23PTransitionMetricsTests','')
 def test_CI_guard_is_mandatory(self):self.reject('.github/workflows/treehammock-ci.yml','python3 eng/check-abuse-metric-counting.py','true')
 def expressions(self):return [t['expr'] for p in json.loads((self.root/counting.DASHBOARD).read_text())['panels'] for t in p.get('targets',[])]
 def test_synthetic_one_start_and_many_denials_do_not_conflate(self):
  tags=dict(feature='login',dimension='account',reason='abuse_counter_limit_exceeded',dependency='dragonfly',outcome='denied')
  series=[(counting.CREATIONS,tags,1),(counting.BLOCKS,tags,12),(counting.ADMISSIONS,tags,13),('treehammock_abuse_cooldowns_started_total',tags,999),('treehammock_abuse_policy_decisions_total',tags,999)]
  exprs=self.expressions()
  for name,total in [(counting.CREATIONS,1),(counting.BLOCKS,12),(counting.ADMISSIONS,13)]:
   expression=next(e for e in exprs if name in e);self.assertEqual(total,sum(event_sum(expression,series).values()))
 def test_synthetic_durable_and_cache_backend_counts_remain_distinct(self):
  common=dict(feature='login',dimension='account',reason='abuse_counter_limit_exceeded');series=[(counting.CREATIONS,dict(common,dependency='dragonfly'),1),(counting.CREATIONS,dict(common,dependency='postgresql'),1)]
  expression=next(e for e in self.expressions() if counting.CREATIONS in e);out=event_sum(expression,series);self.assertEqual(2,len(out));self.assertEqual({1},set(out.values()))
 def test_synthetic_denied_selector_excludes_allowed_admissions(self):
  expression=next(e for e in self.expressions() if counting.ADMISSIONS+'{outcome=' in e)
  self.assertEqual({():1},event_sum(expression,[(counting.ADMISSIONS,dict(outcome='denied'),1),(counting.ADMISSIONS,dict(outcome='allowed'),100)]))
 def test_promtool_fixtures_track_current_dashboard_queries(self):
  import yaml
  fixture=yaml.safe_load((self.root/'ops/prometheus/abuse-counting-contract.test.yml').read_text());exprs=self.expressions()
  for scenario in fixture['tests']:
   for query in scenario['promql_expr_test']:self.assertIn(query['expr'],exprs)
if __name__=='__main__':unittest.main()
