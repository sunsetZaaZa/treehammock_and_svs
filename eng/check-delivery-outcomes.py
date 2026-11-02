#!/usr/bin/env python3
"""COR23I supplemental acceptance/ownership source witnesses; native execution is mandatory."""
import argparse,json,importlib.util
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def require(value,message):
    if not value:raise ValueError(message)
def validate(root):
    read=lambda path:(root/path).read_text()
    contracts={
      'Rigging/Delivery/DeliveryModels.cs':['DeliverySendState { Accepted, NotSubmitted, Rejected, Unknown }','(!CanRetry || State == DeliverySendState.NotSubmitted)','!Provider.Any(char.IsControl)','!ReceiptId.Any(char.IsControl)','DeliverySendState.Unknown, "DELIVERY_INVALID_OUTCOME"'],
      'Rigging/Sidewalk/ProviderDeliveryResult.cs':['ProviderDeliveryStatus.Sent when !string.IsNullOrWhiteSpace(ProviderMessageId)','_ => treehammock.Rigging.Delivery.DeliverySendState.Unknown','CanFallback => Outcome.State is treehammock.Rigging.Delivery.DeliverySendState.NotSubmitted or treehammock.Rigging.Delivery.DeliverySendState.Rejected'],
      'Services/SMTPService.cs':['bool submissionStarted = false;','submissionStarted = true;','if (!submissionStarted) return new(DeliverySendState.NotSubmitted','SmtpErrorCode.MessageNotAccepted','DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN"','return result.State == DeliverySendState.Unknown ? null'],
      'Services/SmsSender.cs':['if(result.Succeeded || !result.CanFallback) return result;','if (!result.CanFallback) throw new DeliveryAcceptanceUnknownException();','catch { return ProviderDeliveryResult.Unknown(ProviderName); }','response.StatusCode!=HttpStatusCode.Created','value.Length==34','^SM[0-9a-fA-F]{32}$','return ProviderDeliveryResult.Unknown(ProviderName, "SERVER_RESPONSE_UNCERTAIN") with {Health=ProviderHealthEvidence.Outage};'],
      'Rigging/Sidewalk/AWSService.cs':['MaxErrorRetry = 0','!Guid.TryParse(messageId,out _)','ProviderDeliveryResult.Unknown(ProviderName','((int)ex.StatusCode == 400 && IsThrottleError(ex.ErrorCode))'],
      'Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs':['services.AddHttpClient("treehammock-twilio", client => { client.Timeout = Timeout.InfiniteTimeSpan; client.MaxResponseContentBufferSize = 16384; })\n            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });'],
      'Services/DeliveryProviderAdapter.cs':['return result.Outcome;','smtp.SendDurable'],
      'Services/DeliveryOutboxWorker.cs':['provider.SendAsync(job.LeaseId!.Value','new DeliverySendResult(DeliverySendState.Unknown','if(!await repo.RecordAsync(job,result,persist.Token))return true;','if(result.State==DeliverySendState.Accepted)await repo.PublishAsync'],
      'Repos/DeliveryOutboxRepo.cs':['result=result.Normalize();','@provider,@receipt,@retry,@code','await transaction.CommitAsync(operationToken);\n        return valid;'],
      'Services/TwoFactorAuthenticateService.cs':['throw new treehammock.Rigging.Delivery.DeliveryAcceptanceUnknownException()'],
    }
    for path,tokens in contracts.items():
        source=read(path)
        for token in tokens:require(token in source,'Missing delivery outcome boundary: '+path+': '+token)
    smtp=read('Services/SMTPService.cs');require(smtp.index('submissionStarted = true;')<smtp.index('await smtp.SendAsync(email,token);'),'SMTP submission phase must precede send')
    spec=importlib.util.spec_from_file_location('bindings',root/'eng/check-sql-output-bindings.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    sql=read('Rigging/Database/Migrations/001_legacy_baseline.sql');funcs=mod.definitions(sql)
    for token in ['attempt_id uuid primary key','unique(delivery_id,attempt_number)','references delivery_outbox(delivery_id) on delete cascade','check(not can_retry or state=\'not_submitted\')']:
        require(token in sql,'Missing attempt schema fence: '+token)
    for name,tokens in {
      'cor23i_attempt_identity':['new.attempt_id is distinct from old.attempt_id','Definitive delivery receipt is immutable',"old.state='unknown' and new.state not in ('unknown','accepted','rejected')"],
      'cor12_claim_delivery':['insert into delivery_attempts(attempt_id,delivery_id,attempt_number,state)',"state='unknown',code='DELIVERY_ABANDONED'","interval '7 days'","limit 100"],
      'cor12_record_delivery':['perform cor12_lock_delivery(owner);','select t.* into a from delivery_attempts t where t.attempt_id=p_lease and t.delivery_id=p_id;',"a.state='unknown' and p_state='not_submitted'",'a.receipt_id is not distinct from p_receipt',"p_state='not_submitted' and p_retry and o.state='claimed' and o.attempts<p_max","state='ambiguous',lease_until=null","if c.expires_at<=clock_timestamp()",'can_retry=p_retry'],
      'cor12_expire_delivery':['perform cor12_lock_delivery(owner);',"state='unknown',code='DELIVERY_EXPIRED_WITHOUT_RECEIPT'"],
    }.items():
        require(name in funcs,'Missing SQL function: '+name)
        for token in tokens:require(token in funcs[name],'Missing SQL attempt fence: '+name+': '+token)
    abandoned=funcs['cor12_claim_delivery'].split("if o.lease_until<=clock_timestamp() then",1)[1].split('end if;',1)[0];require('ciphertext=null' not in abandoned,'Abandoned unknown claim must retain its encrypted payload')
    record=funcs['cor12_record_delivery'];unknown=record.split("elsif p_state='unknown' then",1)[1].split('else',1)[0];require('ciphertext=null' not in unknown,'Unknown must retain its encrypted payload')
    for path,method in [('treehammock.Tests/Integration/SmtpOutcomeTests.cs','Legacy_mail_surface_preserves_unknown'),('treehammock.Tests/Unit/ProviderOutcomeTests.cs','Twilio_unknown_or_malformed_acceptance'),('treehammock.Tests.SqlContracts/Integration/Database/DeliveryOutboxTests.cs','Cor23I_http_acceptance_uncertainty'),('treehammock.Tests.SqlContracts/Integration/Database/ActivationCreationTests.cs','Cor23I_unknown_activation_receipt')]:
        require(method in read(path),'Native delivery regression absent: '+method)
    return dict(status='SourceContractsConsistent',qualification='NotRun',outcomes=['Accepted','NotSubmitted','Rejected','Unknown'],unknown_retry=False,attempt_identity='immutable lease UUID',native_required=['real MailKit acknowledgement loss','HTTP receipt fault through real worker and PostgreSQL','SNS adapter and locked SDK retry behavior','proof/cancel/expiry/replay/retention'])
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args()
    try:print(json.dumps(validate(a.root),indent=2));return 0
    except (ValueError,OSError,KeyError) as error:print(str(error));return 1
if __name__=='__main__':raise SystemExit(main())
