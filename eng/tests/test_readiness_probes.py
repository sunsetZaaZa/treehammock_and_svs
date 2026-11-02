"""Supplemental source mutation witnesses; no native C#/timing/network qualification claim."""
import importlib.util,shutil,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('readiness',ROOT/'eng/check-readiness-probes.py');readiness=importlib.util.module_from_spec(spec);spec.loader.exec_module(readiness)
class ReadinessProbeTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','bin','obj','.correction-results','.artifacts','TestResults','__pycache__'))
 def tearDown(self):self.temp.cleanup()
 def reject(self,path,old,new):
  p=self.root/path;source=p.read_text();self.assertIn(old,source);p.write_text(source.replace(old,new,1))
  with self.assertRaises(ValueError):readiness.validate(self.root)
 def test_consistency_is_not_native_execution(self):self.assertEqual('NotRun',readiness.validate(self.root)['qualification'])
 def test_single_flight_required(self):self.reject(readiness.HEALTH,'if (_flight is null || _flight.IsCompleted)','if (true)')
 def test_pending_raw_work_blocks_new_operation(self):self.reject(readiness.HEALTH,'slot.Work is { IsCompleted: false }','false')
 def test_total_wait_must_be_bounded(self):self.reject(readiness.HEALTH,'flight.WaitAsync(TimeSpan.FromMilliseconds(_settings.TotalTimeoutMilliseconds), _clock, cancellationToken)','flight')
 def test_dependency_wait_must_be_bounded(self):self.reject(readiness.HEALTH,'work.WaitAsync(TimeSpan.FromMilliseconds(budget), _clock)','work')
 def test_completion_age_expiry_is_exclusive(self):self.reject(readiness.HEALTH,'Age(_sample) < _settings.SampleMaxAgeMilliseconds','Age(_sample) <= _settings.SampleMaxAgeMilliseconds')
 def test_stale_delayed_join_cannot_report_ready(self):self.reject(readiness.HEALTH,'Age(sample) >= _settings.SampleMaxAgeMilliseconds','false')
 def test_late_sample_cannot_publish_healthy(self):self.reject(readiness.HEALTH,'duration >= _settings.TotalTimeoutMilliseconds','false')
 def test_late_dependency_success_is_rejected(self):self.reject(readiness.HEALTH,'Elapsed(admitted) >= budget','false')
 def test_queued_work_cannot_start_after_its_deadline(self):self.reject(readiness.HEALTH,'budget - Elapsed(queued)','budget')
 def test_operation_receives_cancellation(self):self.reject(readiness.HEALTH,'_client.ProbeAsync(dependency, operation.Token)','_client.ProbeAsync(dependency, CancellationToken.None)')
 def test_callback_cleanup_is_part_of_ownership(self):self.reject(readiness.HEALTH,'await cancellation.ConfigureAwait(false);','')
 def test_cancellation_callbacks_cannot_block_request_wait(self):self.reject(readiness.HEALTH,'await operation.CancelAsync().ConfigureAwait(false)','operation.Cancel()')
 def test_acquisition_receives_probe_token(self):self.reject(readiness.HEALTH,'await storage.CreateConnection(cancellationToken)','await storage.CreateConnection()')
 def test_late_acquisition_cannot_start_a_command(self):self.reject(readiness.HEALTH,'cancellationToken.ThrowIfCancellationRequested(); // A late acquisition must be disposed without starting a command.','')
 def test_SQL_command_receives_probe_token(self):self.reject(readiness.HEALTH,'command.ExecuteScalarAsync(cancellationToken)','command.ExecuteScalarAsync()')
 def test_raw_PING_is_retained_instead_of_its_shorter_wait(self):self.reject(readiness.HEALTH,'connection.Database.PingAsync()','connection.ExecuteAsync(db => db.PingAsync())')
 def test_HTTP_age_is_present(self):self.reject('Models/Api/HealthStatusResponse.cs','sampleAgeMilliseconds','hiddenAge')
 def test_intermediaries_cannot_cache_readiness(self):self.reject('Controllers/HealthController.cs','ResponseCache(NoStore = true','ResponseCache(NoStore = false')
 def test_dependency_timeout_cannot_exceed_total(self):self.reject('Rigging/Config/HealthProbeSettings.cs','DependencyTimeoutMilliseconds > TotalTimeoutMilliseconds','false')
 def test_native_suite_is_mandatory(self):self.reject('eng/correction-baseline.py','|FullyQualifiedName~Cor23OReadinessBudgetTests','')
 def test_CI_guard_is_mandatory(self):self.reject('.github/workflows/treehammock-ci.yml','python3 eng/check-readiness-probes.py','true')
if __name__=='__main__':unittest.main()
