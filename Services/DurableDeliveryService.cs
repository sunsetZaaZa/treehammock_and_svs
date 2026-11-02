using treehammock.Repos;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Dependencies;
namespace treehammock.Services;

public sealed class DurableDeliveryService(DeliveryOutboxRepo repo, DeliveryPayloadProtector protector,
    IDeliveryAbuseThrottleService throttle) : IDurableDeliveryService
{
    public async Task<bool> AdmitAsync(AbuseFeature feature,string channel,Guid accountId,string destination,CancellationToken token)
    {
        var decision=await AdmitWithReasonAsync(feature,channel,accountId,destination,token);
        if(decision.ReasonCode is AbuseReasonCodes.CounterStoreUnavailable or AbuseReasonCodes.CounterStoreTimeout)
            throw DependencyUnavailableException.Cache("delivery_admission");
        return decision.Allowed;
    }
    public Task<AbuseDecision> AdmitWithReasonAsync(AbuseFeature feature, string channel, Guid accountId, string destination, CancellationToken token)
    {
        if (accountId == Guid.Empty) throw new ArgumentException("Delivery admission requires the server account identity.", nameof(accountId));
        return throttle.ShouldAllowDeliveryAsync(new(feature, channel, accountId,
            DeliveryAbuseThrottleService.SafeDestination(channel, destination)), token);
    }
    public Task<Guid?> ExistingAsync(Guid accountId,Guid stamp,string purpose,CancellationToken token)=>repo.ExistingAsync(accountId,stamp,purpose,token);
    public ProtectedDelivery Protect(DeliveryIntent intent)=>protector.Protect(intent);
    public Task<DeliveryStageResult> EnqueueAsync(DeliveryIntent intent,CancellationToken token)=>repo.StageAsync(Protect(intent),token);
    public Task<DeliveryAccount?> FindVerificationAccountAsync(string email,CancellationToken token)=>repo.FindAccountAsync(email,token);
    public Task<bool> IsPendingAsync(string purpose,string hash,CancellationToken token,Guid? accountId=null)=>repo.IsPendingAsync(purpose,hash,token,accountId);
}
