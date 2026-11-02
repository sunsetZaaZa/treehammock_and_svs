using NodaTime;
using treehammock.Rigging.Abuse;

namespace treehammock.Rigging.Delivery;

public sealed record DeliveryPayload(string Kind, string Channel, string Destination, string Subject,
    string Value, string? Secondary = null, string? MaskedDestination = null);
public sealed record DeliveryIntent(Guid AccountId, Guid AccountStamp, string Purpose, string ProofHash,
    Instant ExpiresAt, object Metadata, DeliveryPayload Payload, DeliveryIntent? Companion = null);
public sealed record ProtectedDelivery(Guid Id, Guid AccountId, Guid AccountStamp, string Purpose,
    string ProofHash, Instant ExpiresAt, string MetadataJson, int KeyVersion, byte[] Nonce, byte[] Ciphertext, byte[] Tag, ProtectedDelivery? Companion = null);
public sealed record DeliveryStageResult(bool Result, string Code, Guid? DeliveryId = null, Guid? EnrollmentId = null, long? SetupVersion = null);
public sealed record DeliveryAccount(Guid AccountId, Guid Stamp, string Email, short VerificationStatus);
public sealed record DeliveryJob(ProtectedDelivery Delivery, string State, Guid? LeaseId, int Attempts);
public enum DeliverySendState { Accepted, NotSubmitted, Rejected, Unknown }
public sealed record DeliverySendResult(DeliverySendState State, string Code, bool CanRetry = false,
    string Provider = "none", string? ReceiptId = null, ProviderHealthEvidence Health = ProviderHealthEvidence.Neutral)
{
    public DeliverySendResult Normalize()
    {
        bool valid = Enum.IsDefined(Health) && Enum.IsDefined(State) && (!CanRetry || State == DeliverySendState.NotSubmitted) && !string.IsNullOrEmpty(Provider) &&
            !Provider.Any(char.IsControl) && System.Text.RegularExpressions.Regex.IsMatch(Provider, "^[a-z0-9-]{1,32}$") &&
            (ReceiptId is null || (!ReceiptId.Any(char.IsControl) && System.Text.RegularExpressions.Regex.IsMatch(ReceiptId, "^[A-Za-z0-9_.@:-]{1,128}$")));
        if (!valid) return new(DeliverySendState.Unknown, "DELIVERY_INVALID_OUTCOME");
        string code = !string.IsNullOrEmpty(Code) && !Code.Any(char.IsControl) && System.Text.RegularExpressions.Regex.IsMatch(Code, "^[A-Z0-9_]{1,64}$") ? Code : "DELIVERY_OUTCOME";
        return this with { Code = code };
    }
}
public sealed class DeliveryAcceptanceUnknownException() : Exception("Delivery acceptance is unknown; do not retry or revoke its proof as non-delivery.") { }

public interface IDurableDeliveryService
{
    Task<AbuseDecision> AdmitWithReasonAsync(AbuseFeature feature, string channel, Guid accountId, string destination, CancellationToken token);
    Task<bool> AdmitAsync(AbuseFeature feature, string channel, Guid accountId, string destination, CancellationToken token);
    Task<Guid?> ExistingAsync(Guid accountId, Guid stamp, string purpose, CancellationToken token);
    ProtectedDelivery Protect(DeliveryIntent intent);
    Task<DeliveryStageResult> EnqueueAsync(DeliveryIntent intent, CancellationToken token);
    Task<DeliveryAccount?> FindVerificationAccountAsync(string email, CancellationToken token);
    Task<bool> IsPendingAsync(string purpose, string proofHash, CancellationToken token, Guid? accountId = null);
}
public interface IDeliveryProvider
{
    Task<DeliverySendResult> SendAsync(Guid jobId, DeliveryPayload payload, CancellationToken token);
}
