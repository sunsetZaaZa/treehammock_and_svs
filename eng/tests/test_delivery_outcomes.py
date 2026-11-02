"""COR23I destructive source-mutation witnesses; no provider or PostgreSQL execution."""
import importlib.util,shutil,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('outcomes',ROOT/'eng/check-delivery-outcomes.py');outcomes=importlib.util.module_from_spec(spec);spec.loader.exec_module(outcomes)
SQL='Rigging/Database/Migrations/001_legacy_baseline.sql'
class DeliveryOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'source';shutil.copytree(ROOT,self.root,ignore=shutil.ignore_patterns('.git','bin','obj','.artifacts','.correction-results','TestResults','__pycache__'))
    def tearDown(self):self.temp.cleanup()
    def reject(self,path,old,new):
        p=self.root/path;s=p.read_text();self.assertIn(old,s);p.write_text(s.replace(old,new,1))
        with self.assertRaises(ValueError):outcomes.validate(self.root)
    def test_source_witnesses_do_not_assert_native_qualification(self):self.assertEqual(outcomes.validate(self.root)['qualification'],'NotRun')
    def test_unknown_cannot_enable_retry(self):self.reject('Rigging/Delivery/DeliveryModels.cs','(!CanRetry || State == DeliverySendState.NotSubmitted)','true')
    def test_generic_failure_cannot_become_safe_negative_receipt(self):self.reject('Rigging/Sidewalk/ProviderDeliveryResult.cs','_ => treehammock.Rigging.Delivery.DeliverySendState.Unknown','_ => treehammock.Rigging.Delivery.DeliverySendState.NotSubmitted')
    def test_unknown_sms_cannot_fall_through_to_secondary(self):self.reject('Services/SmsSender.cs','if(result.Succeeded || !result.CanFallback) return result;','if(result.Succeeded) return result;')
    def test_legacy_sms_unknown_cannot_return_false(self):self.reject('Services/SmsSender.cs','if (!result.CanFallback) throw new DeliveryAcceptanceUnknownException();','if (!result.CanFallback) return false;')
    def test_legacy_email_unknown_cannot_trigger_false_compensation(self):self.reject('Services/TwoFactorAuthenticateService.cs','throw new treehammock.Rigging.Delivery.DeliveryAcceptanceUnknownException()','return false')
    def test_smtp_submission_fault_cannot_be_classified_as_pre_send(self):self.reject('Services/SMTPService.cs','submissionStarted = true;','submissionStarted = false;')
    def test_sns_sdk_cannot_replay_uncertain_publish(self):self.reject('Rigging/Sidewalk/AWSService.cs','MaxErrorRetry = 0','MaxErrorRetry = 3')
    def test_twilio_redirect_cannot_replay_post(self):self.reject('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs','AllowAutoRedirect = false, UseCookies = false','AllowAutoRedirect = true, UseCookies = false')
    def test_malformed_sid_cannot_be_accepted(self):self.reject('Services/SmsSender.cs','value.Length==34','value.Length>0')
    def test_worker_uses_attempt_identity(self):self.reject('Services/DeliveryOutboxWorker.cs','provider.SendAsync(job.LeaseId!.Value','provider.SendAsync(job.Delivery.Id')
    def test_failed_receipt_CAS_cannot_publish(self):self.reject('Services/DeliveryOutboxWorker.cs','if(!await repo.RecordAsync(job,result,persist.Token))return true;','await repo.RecordAsync(job,result,persist.Token);')
    def test_unknown_SQL_attempt_cannot_be_requeued(self):self.reject(SQL,"a.state='unknown' and p_state='not_submitted'","false")
    def test_retry_SQL_requires_confirmed_non_submission(self):self.reject(SQL,"p_state='not_submitted' and p_retry and o.state='claimed' and o.attempts<p_max","p_retry and o.attempts<p_max")
    def test_uncertainty_cannot_erase_payload(self):self.reject(SQL,"state='ambiguous',lease_until=null","state='ambiguous',lease_until=null,ciphertext=null")
    def test_receipt_replay_cannot_ignore_attempt_identity(self):self.reject(SQL,'t.attempt_id=p_lease and t.delivery_id=p_id','t.delivery_id=p_id')
    def test_definitive_receipt_cannot_be_mutable(self):self.reject(SQL,'Definitive delivery receipt is immutable','Receipt is mutable')
    def test_history_cascade_cannot_be_removed(self):self.reject(SQL,'references delivery_outbox(delivery_id) on delete cascade','references delivery_outbox(delivery_id)')
if __name__=='__main__':unittest.main()
