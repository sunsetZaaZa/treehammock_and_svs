using Microsoft.Extensions.Options;
using NodaTime;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;

namespace treehammock.Tests.Infrastructure;

// Producer boundary fixture. It stages only; it never publishes a domain proof or sends.
public sealed class CapturingDurableDelivery : IDurableDeliveryService
{
    public bool Allowed { get; set; } = true;
    public bool Pending { get; set; }
    public Guid? Existing { get; set; }
    public DeliveryAccount? Account { get; set; }
    public DeliveryStageResult Result { get; set; } = new(true,"DELIVERY_PENDING");
    public List<DeliveryIntent> Intents { get; } = [];
    public List<(AbuseFeature Feature,string Channel,Guid Account,string Destination)> Admissions { get; } = [];
    public Task<AbuseDecision> AdmitWithReasonAsync(AbuseFeature feature,string channel,Guid accountId,string destination,CancellationToken token)
    { token.ThrowIfCancellationRequested();Admissions.Add((feature,channel,accountId,destination));return Task.FromResult(Allowed ? AbuseDecision.Allow() : AbuseDecision.Deny(AbuseReasonCodes.DeliveryThrottleExceeded)); }
    public Task<bool> AdmitAsync(AbuseFeature feature,string channel,Guid accountId,string destination,CancellationToken token)
    { token.ThrowIfCancellationRequested();Admissions.Add((feature,channel,accountId,destination));return Task.FromResult(Allowed); }
    public Task<Guid?> ExistingAsync(Guid accountId,Guid stamp,string purpose,CancellationToken token)=>Task.FromResult(Existing);
    public ProtectedDelivery Protect(DeliveryIntent intent)=>Protector().Protect(intent);
    public Task<DeliveryStageResult> EnqueueAsync(DeliveryIntent intent,CancellationToken token)
    { token.ThrowIfCancellationRequested();Intents.Add(intent);
        return Task.FromResult(Result.Result && intent.Purpose is "factor-1" or "factor-2"
            ? Result with {EnrollmentId=Result.EnrollmentId ?? Guid.NewGuid(),SetupVersion=Result.SetupVersion ?? 1} : Result); }
    public Task<DeliveryAccount?> FindVerificationAccountAsync(string email,CancellationToken token)=>Task.FromResult(Account);
    public Task<bool> IsPendingAsync(string purpose,string hash,CancellationToken token,Guid? accountId=null)=>Task.FromResult(Pending);
    public static DeliveryPayloadProtector Protector()=>new(Options.Create(new DeliveryOutboxSettings {EncryptionKeys=new() {{1,Convert.ToBase64String(new byte[32])}}}));
}
