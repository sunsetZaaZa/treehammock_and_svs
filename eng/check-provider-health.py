#!/usr/bin/env python3
"""COR23K supplemental health/acceptance/circuit ownership witnesses; native cache qualification required."""
import argparse,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def require(v,m):
 if not v:raise ValueError(m)
def validate(root):
 read=lambda p:(root/p).read_text()
 throttle=read('Services/DeliveryAbuseThrottleService.cs')
 require('ProviderFailureKey' not in throttle and 'GetCooldownAsync' not in throttle,'Untyped channel failures must not gate unrelated users')
 for token in ['AbuseCounterDimension.Account','AbuseCounterDimension.IdentifierFingerprint','AbuseCounterDimension.IpFingerprint','_counterStore.IncrementAsync(item.Key, item.Limit, cancellationToken)']:require(token in throttle,'User budget contract missing: '+token)
 health=read('Rigging/Delivery/ProviderHealth.cs')
 for token in ['"delivery:health:v1:"','Convert.ToHexString(SHA256.HashData','_emergency[index]','if(!_settings.Enabled)','CacheConnectionSlot','AbuseCounterScripts.ProviderHealthAcquire','AbuseCounterScripts.ProviderHealthComplete','DependencyDeadline.RunAsync','"cache-unavailable"','catch(OperationCanceledException) when(token.IsCancellationRequested){throw;}','catch(Exception){Metric(permit.Key,"report-unavailable");}']:
  require(token in health,'Missing bounded health contract: '+token)
 require(health.index('_emergency[index]')<health.index('if(!_settings.Enabled)'),'Emergency stop must apply independently of auto-health')
 require('Destination' not in health and 'AccountId' not in health and 'Recipient' not in health,'Circuit keys cannot contain user destinations/accounts')
 acquire=read('Rigging/Abuse/Scripts/provider-health-acquire-v1.lua');complete=read('Rigging/Abuse/Scripts/provider-health-complete-v1.lua')
 for token in ["redis.call('TIME')","KEYS[1]","redis.call('PEXPIRE',key,ttl)",'for slot=1,slots do','untilOpen > now','untilProbe > now',"'probe_until',now+lease"]:require(token in acquire,'Missing acquire fence: '+token)
 for token in ["redis.call('HGET',key,'generation') ~= gen",'~= permit','<= now then return 0','if evidence==1 then','elseif evidence==2 then','if count>=threshold then rotate(now+opened) end',"'window') or '0') <= now","redis.call('PEXPIRE',key,window+opened+lease)"]:
  require(token in complete,'Missing completion fence: '+token)
 require("redis.call('DEL'" not in acquire+complete,'Health must not clear durable user budgets')
 for path,route in [('Services/SMTPService.cs','DeliveryRoute.Smtp'),('Services/SmsSender.cs','DeliveryRoute.Twilio')]:
  s=read(path)
  for token in ['_health.AcquireAsync(',route,'!permit.Allowed','await budget.CheckAuthorityAsync()','_health.CompleteAsync(permit,result.Health,attempt.Token)']:
   require(token in s,'Physical transport health/authority gate missing: '+path+':'+token)
 sms=read('Services/SmsSender.cs');require('if(result.Succeeded || !result.CanFallback) return result;' in sms,'Health outages do not authorize Unknown fallback')
 require('SERVER_RESPONSE_UNCERTAIN") with {Health=ProviderHealthEvidence.Outage}' in sms,'HTTP service outage classification absent')
 smtp=read('Services/SMTPService.cs');require('!token.IsCancellationRequested &&' in smtp and 'StatusCode==421' in smtp,'SMTP cancellation/recipient classification missing')
 result=read('Rigging/Sidewalk/ProviderDeliveryResult.cs')
 require('ProviderDeliveryStatus.HealthBlocked =>' in result and 'Status is ProviderDeliveryStatus.RateLimited or ProviderDeliveryStatus.HealthBlocked' in result,'Denied permit must remain retryable confirmed non-submission')
 aws=read('Rigging/Sidewalk/AWSService.cs');require('ex.StatusCode>=500?ProviderHealthEvidence.Outage:ProviderHealthEvidence.Neutral' in aws,'SNS service classification absent')
 di=read('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs');require('using treehammock.Rigging.Delivery;' in di and 'services.AddSingleton<IProviderHealthService>' in di and 'AddValidatedOptions<ProviderHealthSettings>' in di,'Production health registration missing')
 settings=read('Rigging/Config/ProviderHealthSettings.cs');require('[Range(45,120)]' in settings and '[Range(1,128)]' in settings,'Permit/capacity limits missing')
 for p in root.glob('appsettings*.json'):
  b=json.loads(p.read_text())['ProviderHealthSettings'];require(b['Enabled'] and not b['EmergencyEmailStop'] and not b['EmergencySmsStop'] and (b['FailureThreshold'],b['WindowSeconds'],b['OpenSeconds'],b['PermitSeconds'],b['MaxInFlightPerRoute'])==(5,300,60,45,32),'Shipped health defaults drift: '+p.name)
 old=read('treehammock.Tests/Unit/ProviderOutcomeTests.cs');require('SendSMS(default!,default!,default, cancellationToken:' not in old,'Duplicate native token argument')
 for p,t in [('treehammock.Tests.SqlContracts/Integration/Database/ProviderHealthCacheTests.cs','Real_cache_atomic_outage_threshold'),('treehammock.Tests/Integration/SmtpHealthTests.cs','Real_recipient_rejection'),('treehammock.Tests/Unit/ProviderHealthTests.cs','Real_Twilio_adapter')]:require(t in read(p),'Native health regression missing')
 return dict(status='SourceContractsConsistent',qualification='NotRun',configured_routes=3,health_failure_evidence='explicit outage only; acceptance/retry independent',native_required=['real cache multi-instance threshold, permit and half-open concurrency','owned SMTP recipient/TLS/auth matrix','real HTTP adapter with actual cache and safe fallback','SDK classification and cache outage/report failure'])
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args()
 try:print(json.dumps(validate(a.root),indent=2));return 0
 except(ValueError,OSError,KeyError) as e:print(str(e));return 1
if __name__=='__main__':raise SystemExit(main())
