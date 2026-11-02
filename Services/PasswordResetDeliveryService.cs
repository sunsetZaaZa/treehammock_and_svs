using Microsoft.Extensions.Options;
using NodaTime;
using treehammock.Repos;
using treehammock.DataLayer.Cache;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
namespace treehammock.Services;

public sealed record PasswordResetDeliveryCommand(Guid ResetId, Guid AccountId, string Method, string DeliveryChannel,
    string DestinationMasked, string DestinationAddressOrPhone, string KeyCode, Instant ExpiresAt, string? RequestIpAddress = null);
public interface IPasswordResetDeliveryService
{
    Task<bool> AdmitAsync(Guid accountId,string channel,string destination,CancellationToken token);
    Task<DeliveryStageResult> StageAsync(CreatePasswordResetRequestDbCommand command,PasswordResetDeliveryCommand delivery,CancellationToken token);
    Task<Guid?> ExistingAsync(Guid accountId,Guid stamp,string purpose,CancellationToken token);
    Task<bool> IsPendingAsync(string proofHash,CancellationToken token);
    Task<bool> IsFactorPendingAsync(string proofHash,CancellationToken token);
    Task<DeliveryStageResult> StageFactorAsync(PasswordResetDeliveryCommand command,Guid stamp,PasswordResetSession session,CancellationToken token);
}
public sealed class PasswordResetDeliveryService(IDurableDeliveryService delivery,IOptions<EmailSubjectSettings> subjects) : IPasswordResetDeliveryService
{
    public Task<Guid?> ExistingAsync(Guid accountId,Guid stamp,string purpose,CancellationToken token)=>delivery.ExistingAsync(accountId,stamp,purpose,token);
    public Task<bool> AdmitAsync(Guid accountId,string channel,string destination,CancellationToken token)
        =>delivery.AdmitAsync(AbuseFeature.PasswordResetRequest,channel,accountId,destination,token);
    public Task<bool> IsPendingAsync(string hash,CancellationToken token)=>delivery.IsPendingAsync("reset",hash,token);
    public Task<bool> IsFactorPendingAsync(string hash,CancellationToken token)=>delivery.IsPendingAsync("reset-factor",hash,token);
    public Task<DeliveryStageResult> StageFactorAsync(PasswordResetDeliveryCommand d,Guid stamp,PasswordResetSession s,CancellationToken token)
        =>delivery.EnqueueAsync(new(d.AccountId,stamp,"reset-factor",s.challengeCodeHash!,s.challengeExpiration!.Value,
            new {transition=(short)s.transition,expectedSessionVersion=s.sessionVersion,expectedChallengeVersion=s.challengeVersion,
                resetId=d.ResetId,sessionHash=s.resetAccessTokenHash,bootstrapProof=(short)s.bootstrapProof,state=(short)s.state,
                availableConfigurations=s.availableConfigurationsSnapshot.Select(x=>(short)x).ToArray(),selectedConfiguration=(short?)s.selectedConfiguration,
                requiredMethods=s.requiredMethods.Select(x=>(short)x).ToArray(),completedMethods=s.completedMethods.Select(x=>(short)x).ToArray(),
                currentExpectedMethod=(short?)s.currentExpectedMethod,challengeAttempts=s.challengeAttempts,challengeResends=s.challengeResends,
                nextChallengeAllowedAt=s.nextChallengeAllowedAt,createdOn=s.createdOn,expiresAt=s.expiresAt,selectedAt=s.selectedAt,
                twoFactorCompletedAt=s.twoFactorCompletedAt,passwordChangedAt=s.passwordChangedAt},
            new("reset",d.DeliveryChannel,d.DestinationAddressOrPhone,subjects.Value.PasswordResetCode,d.KeyCode,
                d.ExpiresAt.ToDateTimeOffset().ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'"),d.DestinationMasked)),token);
    public Task<DeliveryStageResult> StageAsync(CreatePasswordResetRequestDbCommand c,PasswordResetDeliveryCommand d,CancellationToken token)
        =>delivery.EnqueueAsync(new(c.AccountId,c.AccountSecurityStampAtRequest,"reset",c.KeyCodeHash!,c.ExpiresAt,
            new {resetId=c.PasswordResetRequestId,method=c.Method,deliveryChannel=c.DeliveryChannel,hashVersion=c.KeyCodeHashVersion,
                destinationFingerprint=c.DestinationFingerprint,destinationMasked=c.DestinationMasked,requiresTotp=c.RequiresTotp,
                maxAttempts=c.MaxAttempts,requestedByIp=c.RequestedByIp,requestedByUserAgent=c.RequestedByUserAgent},
            new("reset",d.DeliveryChannel,d.DestinationAddressOrPhone,subjects.Value.PasswordResetCode,d.KeyCode,
                d.ExpiresAt.ToDateTimeOffset().ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'"),d.DestinationMasked)),token);
}
