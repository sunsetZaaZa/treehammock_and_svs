using System.Text;
using Google.Protobuf;
using Treehammock.SessionValidation.Contracts.V1;

namespace Treehammock.SessionValidation.Contracts;

public enum ContractError
{
    None, Malformed, TooLarge, UnknownField, DuplicateField, WrongWireType,
    UnsupportedVersion, MissingCaller, CallerDenied, UnknownAction, MissingCredential,
    InvalidCredential, InvalidRequestId, MissingDeadline, DeadlineExceeded, DeadlineTooLong,
    UnknownDecision, InvalidSubject, SubjectOnRefusal, InvalidMetadata, InvalidValidity,
    WrongRequest, WrongPolicy
}

// These are contract ceilings, not measured SLOs or production capacity approval.
public static class ContractLimits
{
    public const uint Version = 1;
    public const uint SessionProtocol = 2;
    public const long MaximumGeneration = 9007199254740991;
    public const int CredentialBytes = 8192;
    public const int BinaryRequestBytes = 9216;
    public const int JsonRequestBytes = 16384;
    public const int BinaryReplyBytes = 1024;
    public const int JsonReplyBytes = 2048;
    public static readonly TimeSpan MaximumDeadline = TimeSpan.FromSeconds(5);
}

// Peer identity MUST be supplied by the authenticated transport adapter, never by the message.
// This value is not itself a certificate or proof of authentication.
public readonly record struct AdmissionContext(string? AuthenticatedPeerIdentity,
    DateTimeOffset StartedAt, DateTimeOffset? Deadline, DateTimeOffset Now);

public readonly record struct ReplyContext(string RequestId, string PolicyVersion,
    DateTimeOffset StartedAt, DateTimeOffset Deadline, DateTimeOffset Now);

public static class ContractRules
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static ContractError CheckRequest(ValidateRequest request, AdmissionContext context, CallerPolicy policy)
    {
        if (request.ContractVersion != ContractLimits.Version) return ContractError.UnsupportedVersion;
        if (string.IsNullOrEmpty(context.AuthenticatedPeerIdentity)) return ContractError.MissingCaller;
        if (context.Deadline is null) return ContractError.MissingDeadline;
        if (context.Now < context.StartedAt || context.Now >= context.Deadline.Value) return ContractError.DeadlineExceeded;
        if (context.Deadline.Value - context.StartedAt > ContractLimits.MaximumDeadline) return ContractError.DeadlineTooLong;
        if (!IsId(request.RequestId)) return ContractError.InvalidRequestId;
        if (!CallerPolicy.IsSupportedAction(request.RequestedAction)) return ContractError.UnknownAction;
        if (!policy.Allows(context.AuthenticatedPeerIdentity, request.RequestedAction)) return ContractError.CallerDenied;
        if (request.AccessCredential.Length == 0) return ContractError.MissingCredential;
        if (request.AccessCredential.Length > ContractLimits.CredentialBytes) return ContractError.TooLarge;
        try
        {
            var credential = StrictUtf8.GetString(request.AccessCredential.Span);
            if (string.IsNullOrWhiteSpace(credential) || credential.Any(char.IsControl)) return ContractError.InvalidCredential;
        }
        catch (DecoderFallbackException) { return ContractError.InvalidCredential; }
        // Shape/admission only. No JWT verification, subject inference or authority decision.
        return ContractError.None;
    }

    public static ContractError CheckReply(ValidateReply reply, ReplyContext context)
    {
        if (reply.ContractVersion != ContractLimits.Version) return ContractError.UnsupportedVersion;
        if (reply.Decision is not (Decision.Active or Decision.Unauthenticated or Decision.Forbidden or Decision.Unavailable))
            return ContractError.UnknownDecision;
        if (!IsId(context.RequestId) || reply.RequestId != context.RequestId) return ContractError.WrongRequest;
        if (!IsPolicyVersion(reply.PolicyVersion) || reply.PolicyVersion != context.PolicyVersion) return ContractError.WrongPolicy;
        if (!IsId(reply.DecisionId)) return ContractError.InvalidMetadata;
        if (context.Deadline - context.StartedAt > ContractLimits.MaximumDeadline ||
            context.Now < context.StartedAt || context.Now >= context.Deadline ||
            reply.CheckedAtUnixMs < context.StartedAt.ToUnixTimeMilliseconds() ||
            reply.CheckedAtUnixMs > context.Now.ToUnixTimeMilliseconds()) return ContractError.InvalidValidity;
        if (reply.Decision != Decision.Active)
            return reply.AccountIdUuid.Length != 0 || reply.SessionFamilyUuid.Length != 0 || reply.Generation != 0 ||
                   reply.SessionProtocolVersion != 0 || reply.ValidUntilUnixMs != 0
                ? ContractError.SubjectOnRefusal : ContractError.None;
        if (!IsUuid(reply.AccountIdUuid) || !IsUuid(reply.SessionFamilyUuid) ||
            reply.Generation is < 1 or > ContractLimits.MaximumGeneration ||
            reply.SessionProtocolVersion != ContractLimits.SessionProtocol) return ContractError.InvalidSubject;
        if (reply.ValidUntilUnixMs <= context.Now.ToUnixTimeMilliseconds() ||
            reply.ValidUntilUnixMs > context.Deadline.ToUnixTimeMilliseconds()) return ContractError.InvalidValidity;
        return ContractError.None;
    }

    public static bool IsId(string? text) => text is { Length: 32 } &&
        text.Any(c => c != '0') && text.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    public static bool IsPolicyVersion(string? text) => text is { Length: >= 1 and <= 64 } &&
        text.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-');

    private static bool IsUuid(ByteString bytes) => bytes.Length == 16 && bytes.Any(b => b != 0);
}

public static class UuidCodec
{
    public static ByteString Encode(Guid value)
    {
        if (value == Guid.Empty) throw new ArgumentException("Empty subject UUID.");
        Span<byte> bytes = stackalloc byte[16];
        value.TryWriteBytes(bytes, bigEndian: true, out _);
        return ByteString.CopyFrom(bytes);
    }

    public static Guid Decode(ByteString bytes)
    {
        if (bytes.Length != 16 || bytes.All(b => b == 0)) throw new ArgumentException("Invalid subject UUID.");
        return new Guid(bytes.Span, bigEndian: true);
    }
}
