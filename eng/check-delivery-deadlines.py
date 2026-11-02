#!/usr/bin/env python3
"""COR23J supplemental deadline/ownership witnesses; not transport or SQL qualification."""
import argparse,json,importlib.util,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def require(value,message):
    if not value:raise ValueError(message)
def validate(root):
    read=lambda p:(root/p).read_text()
    policy=read('Rigging/Delivery/DeliveryExecutionPolicy.cs')
    for token in ['ConcurrentDictionary<Guid,Task> _owned','if(Ambient.Value is { } inherited)return await action(inherited);','await _capacity.WaitAsync(budget.Token)','if(!budget.HasTimeRemaining)return notStarted();','await Task.WhenAny(work,Task.Delay(_drain));','transferred=true;','ObserveOwnedAsync(work,budget,owner,finished,lateResult)','if(!transferred)','T result=await work;if(lateResult is not null)await lateResult(result);','_shutdown.Cancel();','_total-_elapsed.Elapsed','CancellationTokenSource.CreateLinkedTokenSource(caller,shutdown)','_source.Token.Register(stopChain)','left<_attempt?left:_attempt']:
        require(token in policy,'Missing deadline/ownership fence: '+token)
    observer=policy.split('private async Task ObserveOwnedAsync',1)[1].split('public Task StartAsync',1)[0]
    require(observer.index('await work')<observer.index('_capacity.Release()'),'Unfinished work must retain capacity')
    worker=read('Services/DeliveryOutboxWorker.cs')
    for token in ['_iteration.WaitAsync(stopping)','await budget.CheckAuthorityAsync()','provider.SendAsync(job.LeaseId!.Value,sendingPayload,budget.Token)','job.Delivery.ExpiresAt.ToDateTimeUtc()','token=>repo.CanSendAsync(job,token)','late=>PersistLateAsync(job,late.Normalize())','new CancellationTokenSource(TimeSpan.FromSeconds(5))']:
        require(token in worker,'Missing durable lifecycle fence: '+token)
    require('.WaitAsync(budget.Token)' not in worker,'Worker must not abandon an unowned transport task')
    for path in ['Services/SMTPService.cs','Services/SmsSender.cs']:
        s=read(path);require('_execution.RunAsync(token' in s and 'await budget.BeginAttemptAsync(token)' in s,'Missing inherited total/per-attempt budget: '+path)
    smtp=read('Services/SMTPService.cs')
    for name in ['VerificationLetter','ResendVerifyLetter','EmailChangeVerifyLetter','DeleteAccountTwoStepLetter','AccountUnlockLetter','TwoFactorSetupLetter','TwoFactorKeyOutboundLetter','TwoFactorDeleteLetter','PasswordResetCodeLetter','Send']:
        require(re.search(r'public async Task<bool\?> '+name+r'\([^\n]*CancellationToken token = default\)',smtp),'Legacy SMTP token absent: '+name)
        require('nameof('+name+'), token: token)' in smtp,'Legacy SMTP drops token: '+name)
    sms=read('Services/SmsSender.cs');require('if(attempt.Token.IsCancellationRequested)return result;' in sms and 'raw,attempt.Token)' in sms,'No fallback after attempt budget exhausts')
    twofactor=read('Services/TwoFactorAuthenticateService.cs')
    for token in ['ShouldAllowDeliveryAsync(throttleRequest, token)','_emailSubjectSettings.TwoFactorKeyOutbound, codeKey, token)','SendCode(phonenumber, codeKey, token)','RecordProviderFailureAsync(request,token)','catch(OperationCanceledException) when(token.IsCancellationRequested){return false;}']:
        require(token in twofactor,'Caller/throttle drops deadline: '+token)
    require(twofactor.count('ShouldAllowDeliveryAsync(throttleRequest, token)')==2,'Both caller throttles must inherit the cancellation budget')
    helper=read('Controllers/AccountControllerBase.TwoFactorHelpers.cs')
    require(helper.count('token: HttpContext.RequestAborted')==2 and helper.count('catch (DeliveryAcceptanceUnknownException) { return TwoFactorChallengePreparationResult.ProviderUnknown; }')==2,'HTTP cancellation/unknown challenge ownership missing')
    require(helper.count('return TwoFactorChallengePreparationResult.ProviderUnknown;')>=4,'Unexpected provider errors cannot imply proof cancellation')
    capture=read('Services/SystemTesting/SystemTestDeliveryCapture.cs')
    for token in ['await EnsureSchema(token);','_schemaLock.WaitAsync(token)','_storageContext.CreateConnection(token)','command.ExecuteNonQueryAsync(token)']:
        require(token in capture,'Capture must cancel database work: '+token)
    require('.WaitAsync(token)' not in read('Services/SystemTesting/SystemTestSmsSender.cs'),'Capture must not abandon SQL waits')
    settings=read('Rigging/Config/DeliveryOutboxSettings.cs')
    require('ProviderAttemptTimeoutSeconds > ProviderTimeoutSeconds' in settings and 'ProviderTimeoutSeconds + CancellationDrainSeconds + 10' in settings,'Attempt/lease budgets must validate together')
    profiles=sorted(root.glob('appsettings*.json'))
    for p in profiles:
        b=json.loads(p.read_text())['DeliveryOutboxSettings'];require((b['ProviderAttemptTimeoutSeconds'],b['CancellationDrainSeconds'],b['MaxConcurrentSends'])==(10,2,4),'Shipped execution defaults changed: '+p.name)
    di=read('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs')
    require('services.AddSingleton<DeliveryExecutionPolicy>();' in di and 'provider.GetRequiredService<DeliveryExecutionPolicy>()' in di and 'client.Timeout = Timeout.InfiniteTimeSpan; client.MaxResponseContentBufferSize = 16384;' in di,'Singleton ownership/shutdown and HTTP budget missing')
    spec=importlib.util.spec_from_file_location('bindings',root/'eng/check-sql-output-bindings.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    f=mod.definitions(read('Rigging/Database/Migrations/001_legacy_baseline.sql'))['cor23j_delivery_can_send']
    for token in ['perform cor12_lock_delivery(owner);',"o.lease_id is distinct from p_lease",'o.lease_until is null','c.expires_at<=clock_timestamp()',"a.state='claimed'",'c.predecessor is distinct from cor12_delivery_predecessor','a.security_stamp=c.account_stamp','cor19_request_live','cor18_delete_live','cor17_email_live','cor16_require_setup']:
        require(token in f,'Missing pre-attempt SQL authority fence: '+token)
    for path,name in [('treehammock.Tests/Unit/DeliveryBudgetTests.cs','Eight_hung_sends'),('treehammock.Tests/Integration/TransportDeadlineTests.cs','Real_SMTP_blocked_phase'),('treehammock.Tests/Unit/LoginCancellationTests.cs','Actual_login_selection'),('treehammock.Tests.SqlContracts/Integration/Database/DeliveryOutboxTests.cs','Cor23J_noncooperative_provider')]:require(name in read(path),'Native deadline regression missing: '+name)
    return dict(status='SourceContractsConsistent',qualification='NotRun',profiles=len(profiles),aggregate_seconds=20,attempt_seconds=10,drain_seconds=2,transport_capacity=4,worker_concurrency=1,unfinished_work='tracked; capacity retained until actual completion',native_required=['real TLS blocked-phase and socket-close matrix','HTTP/SNS cancellation and aggregate fallback','hung workload capacity profile','actual PostgreSQL lease/expiry/revocation/late receipt','login HTTP request abortion/proof ownership'])
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args()
    try:print(json.dumps(validate(a.root),indent=2));return 0
    except (ValueError,OSError,KeyError) as e:print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
