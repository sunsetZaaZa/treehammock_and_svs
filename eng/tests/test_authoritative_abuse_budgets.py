"""Supplemental source mutation witnesses only; native PostgreSQL/cache qualification required."""
import importlib.util,shutil,tempfile,unittest,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('budgets',ROOT/'eng/check-authoritative-abuse-budgets.py');budgets=importlib.util.module_from_spec(spec);spec.loader.exec_module(budgets)
STORE='Rigging/Abuse/DragonflyAbuseCounterStore.cs';CATALOG='Rigging/Abuse/AbuseCounterPolicyCatalog.cs';SQL='Rigging/Database/Baseline/000_treehammock_canonical_database.sql'
class AuthoritativeAbuseBudgetsTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','bin','obj','.artifacts','.correction-results','TestResults','__pycache__'))
 def tearDown(self):self.temp.cleanup()
 def reject(self,path,old,new):
  p=self.root/path;s=p.read_text();self.assertIn(old,s);p.write_text(s.replace(old,new,1))
  with self.assertRaises(ValueError):budgets.validate(self.root)
 def test_consistency_does_not_claim_native_execution(self):self.assertEqual('NotRun',budgets.validate(self.root)['qualification'])
 def test_no_unconditional_outage_allow(self):self.reject(STORE,'authoritative?.CanAdmit == true','true')
 def test_durable_admission_before_cache(self):self.reject(STORE,'authoritative = await DurableIncrement(key, limit, cancellationToken)','authoritative = null')
 def test_denied_SQL_stops_work(self):self.reject(STORE,'if (!authoritative.CanAdmit)','if (false)')
 def test_mode_is_snapshotted(self):self.reject(STORE,'_requireDurable =','_mutableFlag =')
 def test_unsupported_config_rejected(self):self.reject(CATALOG,'policies.Any(p => !SupportsPostgreSqlBudget(p))','false')
 def test_explicit_selected_policies_required(self):self.reject(CATALOG,'AbuseCounterFailureMode.RequirePostgreSqlBudgetV1 => policies.Count > 0','AbuseCounterFailureMode.RequirePostgreSqlBudgetV1 => true')
 def test_unsupported_dimensions_not_SQL_supported(self):self.reject(CATALOG,'AbuseCounterDimension.Account or AbuseCounterDimension.IdentifierFingerprint or AbuseCounterDimension.IpFingerprint','AbuseCounterDimension.Account or AbuseCounterDimension.DeliveryMethod')
 def test_availability_cannot_be_ignored(self):self.reject('Rigging/Abuse/AbuseModels.cs','CanAdmit => Allowed && !Unavailable','CanAdmit => Allowed')
 def test_atomic_upsert_required(self):self.reject(SQL,'on conflict(policy_id,dimension_id,budget_hash) do update','on conflict(policy_id,dimension_id,budget_hash) do nothing')
 def test_server_clock_required(self):self.reject(SQL,'v_now:=clock_timestamp();','v_now:=transaction_timestamp();')
 def test_exact_expiry_required(self):self.reject(SQL,'v_row.window_expires_at<=v_now','v_row.window_expires_at<v_now')
 def test_cooldown_cannot_be_ignored(self):self.reject(SQL,'v_row.cooldown_until>v_now','false')
 def test_budget_threshold_required(self):self.reject(SQL,'v_row.attempt_count<=p_maximum','true')
 def test_cleanup_bounded_and_nonblocking(self):self.reject(SQL,'limit p_batch for update skip locked','for update')
 def test_cleanup_dry_run_preserved(self):self.reject('Services/PostgreSqlAbuseBudgetCleanupWorker.cs','settings.DryRun','false')
 def test_failed_SQL_reset_cannot_clear_cache(self):self.reject(STORE,'RecordDurableFailure("reset", ex); return;','RecordDurableFailure("reset", ex);')
 def test_actual_SQL_suite_mandatory(self):self.reject('eng/correction-baseline.py','|FullyQualifiedName~Cor23MAbuseBudgetTests','')
 def test_CI_source_guard_required(self):self.reject('.github/workflows/treehammock-ci.yml','python3 eng/check-authoritative-abuse-budgets.py','true')
if __name__=='__main__':unittest.main()
