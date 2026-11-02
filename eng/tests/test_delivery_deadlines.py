"""COR23J source mutation witnesses; native latency and capacity profiling remain mandatory."""
import importlib.util,shutil,tempfile,unittest,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('deadlines',ROOT/'eng/check-delivery-deadlines.py');deadlines=importlib.util.module_from_spec(spec);spec.loader.exec_module(deadlines)
POLICY='Rigging/Delivery/DeliveryExecutionPolicy.cs'
class DeliveryDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','bin','obj','.artifacts','.correction-results','TestResults','__pycache__'))
    def tearDown(self):self.temp.cleanup()
    def reject(self,path,old,new):
        p=self.root/path;s=p.read_text();self.assertIn(old,s);p.write_text(s.replace(old,new,1))
        with self.assertRaises(ValueError):deadlines.validate(self.root)
    def test_source_consistency_does_not_claim_native_execution(self):self.assertEqual(deadlines.validate(self.root)['qualification'],'NotRun')
    def test_unfinished_task_ownership_cannot_be_removed(self):self.reject(POLICY,'ConcurrentDictionary<Guid,Task> _owned','Dictionary<Guid,Task> _owned')
    def test_timeout_cannot_release_unfinished_capacity(self):self.reject(POLICY,'transferred=true;','transferred=false;')
    def test_observer_must_join_before_releasing_slot(self):self.reject(POLICY,'T result=await work;if(lateResult is not null)await lateResult(result);','_capacity.Release();T result=await work;if(lateResult is not null)await lateResult(result);')
    def test_nested_provider_cannot_reset_aggregate_budget(self):self.reject(POLICY,'if(Ambient.Value is { } inherited)return await action(inherited);','// Reset every nested boundary')
    def test_attempt_cannot_exceed_remaining_aggregate_time(self):self.reject(POLICY,'left<_attempt?left:_attempt','_attempt')
    def test_attempt_timeout_must_stop_entire_chain(self):self.reject(POLICY,'_source.Token.Register(stopChain)','default')
    def test_shutdown_must_cancel_owned_work(self):self.reject(POLICY,'_shutdown.Cancel();','// no shutdown cancellation')
    def test_worker_cannot_abandon_unowned_send(self):self.reject('Services/DeliveryOutboxWorker.cs','provider.SendAsync(job.LeaseId!.Value,sendingPayload,budget.Token)','provider.SendAsync(job.LeaseId!.Value,sendingPayload,budget.Token).WaitAsync(budget.Token)')
    def test_worker_must_clamp_to_proof_expiry(self):self.reject('Services/DeliveryOutboxWorker.cs','job.Delivery.ExpiresAt.ToDateTimeUtc()','DateTime.UtcNow.AddDays(1)')
    def test_worker_public_calls_cannot_exceed_single_iteration(self):self.reject('Services/DeliveryOutboxWorker.cs','_iteration.WaitAsync(stopping)','Task.CompletedTask')
    def test_fallback_cannot_start_after_attempt_exhaustion(self):self.reject('Services/SmsSender.cs','if(attempt.Token.IsCancellationRequested)return result;','// continue after exhausted attempt')
    def test_legacy_generic_SMTP_send_must_forward_request_abort(self):self.reject('Services/SMTPService.cs','nameof(Send), token: token)','nameof(Send))')
    def test_throttle_must_share_request_cancellation(self):self.reject('Services/TwoFactorAuthenticateService.cs','ShouldAllowDeliveryAsync(throttleRequest, token)','ShouldAllowDeliveryAsync(throttleRequest)')
    def test_login_unknown_cannot_compensate_by_cancelling_challenge(self):self.reject('Controllers/AccountControllerBase.TwoFactorHelpers.cs','catch (DeliveryAcceptanceUnknownException) { return TwoFactorChallengePreparationResult.ProviderUnknown; }','catch (DeliveryAcceptanceUnknownException) { return await CancelIssuedTwoFactorChallengeAfterProviderFailure(session, hashedPreAuthToken, moment); }')
    def test_capture_cannot_abandon_database_work(self):self.reject('Services/SystemTesting/SystemTestSmsSender.cs','payload.Value,payload.Value,token: token);','payload.Value,payload.Value).WaitAsync(token);')
    def test_lease_must_include_join_and_commit_budgets(self):self.reject('Rigging/Config/DeliveryOutboxSettings.cs','ProviderTimeoutSeconds + CancellationDrainSeconds + 10','ProviderTimeoutSeconds + 5')
    def test_every_profile_uses_bounded_capacity(self):
        p=self.root/'appsettings.Testing.json';o=json.loads(p.read_text());o['DeliveryOutboxSettings']['MaxConcurrentSends']=999;p.write_text(json.dumps(o))
        with self.assertRaises(ValueError):deadlines.validate(self.root)
if __name__=='__main__':unittest.main()
