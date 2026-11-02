using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Google.Protobuf;
using Grpc.AspNetCore.Server.Model;
using Grpc.Core;
using NodaTime;
using Treehammock.SessionValidation.Contracts;
using Treehammock.SessionValidation.Contracts.V1;
using Treehammock.SessionValidation.Storage;
namespace Treehammock.SessionValidation.Api;

// Explicit operator-owned requirements. Empty is deny-all, never a fabricated backup grant.
public sealed class ActionPolicySettings
{
    public string Version { get; init; } = "svs-actions-denyall.v1";
    public Dictionary<string, string> Requirements { get; init; } = new(StringComparer.Ordinal);
    internal void Validate()
    {
        if (!ContractRules.IsPolicyVersion(Version) || Requirements is null || Requirements.Count > 4 ||
            Requirements.Any(p => !CallerPolicy.IsSupportedAction(p.Key) || p.Value is not ("account.read" or "account.manage")))
            throw new ArgumentException("Explicit bounded action policy required.");
    }
    public override string ToString() => nameof(ActionPolicySettings);
}

// Keep raw protobuf until the strict codec has rejected unknown/duplicate/wrong-wire fields.
// The generated binder would collapse duplicates before the handler could inspect them.
internal sealed class ValidationMethods : IServiceMethodProvider<ValidationService>
{
    public void OnServiceMethodDiscovery(ServiceMethodProviderContext<ValidationService> context) =>
        context.AddUnaryMethod(new Method<byte[], CheckedReply>(MethodType.Unary,
            "treehammock.sessionvalidation.v1.SessionValidator", "Validate",
            Marshallers.Create<byte[]>(b => b, b => b),
            Marshallers.Create<CheckedReply>(r => r.Serialize(), _ => throw new NotSupportedException())),
            [], (service, bytes, call) => service.ValidateAsync(bytes, call));
}

internal sealed class CheckedReply(ValidateReply message, ReplyContext window, CancellationToken token, Func<bool>? evidenceCurrent = null)
{
    internal byte[] Serialize()
    {
        token.ThrowIfCancellationRequested();
        if (evidenceCurrent is not null && !evidenceCurrent()) throw new RpcException(new Status(StatusCode.Unavailable, "Evidence no longer current."));
        if (ContractRules.CheckReply(message, window with { Now = DateTimeOffset.UtcNow }) != ContractError.None)
            throw new RpcException(new Status(StatusCode.DeadlineExceeded, "Reply no longer current."));
        var bytes = message.ToByteArray();
        token.ThrowIfCancellationRequested();
        if (evidenceCurrent is not null && !evidenceCurrent()) { CryptographicOperations.ZeroMemory(bytes); throw new RpcException(new Status(StatusCode.Unavailable, "Evidence no longer current.")); }
        if (bytes.Length > ContractLimits.BinaryReplyBytes || ContractRules.CheckReply(message, window with { Now = DateTimeOffset.UtcNow }) != ContractError.None)
            throw new RpcException(new Status(StatusCode.DeadlineExceeded, "Reply no longer current."));
        return bytes;
    }
}

internal sealed class ValidationService(SessionEvidenceCoordinator coordinator, CallerPolicy callers, HostSettings settings,Metrics? metrics=null)
{
    internal const string StartedKey = "svs08-started";
    internal async Task<CheckedReply> ValidateAsync(byte[] bytes, ServerCallContext call)
    {
        long measuredAt=System.Diagnostics.Stopwatch.GetTimestamp();int measuredDecision=4;
        try
        {
            var http = call.GetHttpContext();
            var started = (DateTimeOffset)http.Items[StartedKey]!;
            var now = DateTimeOffset.UtcNow;
            DateTimeOffset? clientDeadline = call.Deadline == DateTime.MaxValue ? null : new DateTimeOffset(call.Deadline);
            var admission = new AdmissionContext(http.User.FindFirstValue(ClaimTypes.NameIdentifier), started, clientDeadline, now);
            var error = ContractCodec.DecodeRequestBinary(bytes, admission, callers, out var request);
            if (error != ContractError.None) throw Refuse(error);
            var deadline = clientDeadline!.Value < started.AddMilliseconds(settings.RequestTimeoutMilliseconds)
                ? clientDeadline.Value : started.AddMilliseconds(settings.RequestTimeoutMilliseconds);
            // Optional transport ceiling: only shorten the admitted gRPC/server budget.
            var ceilings = call.RequestHeaders.Where(h => h.Key == "svs-deadline-unix-ms").ToArray();
            if (ceilings.Length != 0)
            {
                if (ceilings.Length != 1 || ceilings[0].Value.Length is < 1 or > 15 ||
                    !long.TryParse(ceilings[0].Value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long milliseconds) || milliseconds > 253402300799999)
                    throw Refuse(ContractError.Malformed);
                var ceiling = DateTimeOffset.FromUnixTimeMilliseconds(milliseconds);
                if (ceiling > clientDeadline.Value) throw Refuse(ContractError.Malformed);
                if (ceiling <= now) throw Refuse(ContractError.DeadlineExceeded);
                if (ceiling < deadline) deadline = ceiling;
            }
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(call.CancellationToken, http.RequestAborted);
            var remaining = deadline - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero) throw Refuse(ContractError.DeadlineExceeded);
            timeout.CancelAfter(remaining);
            SessionEvidenceDecision decision;
            if (!settings.ActionPolicy.Requirements.TryGetValue(request!.RequestedAction, out var capability))
                decision = new(Core.SessionDecision.Unavailable);
            else
                decision = await coordinator.ValidateAsync(Encoding.UTF8.GetString(request.AccessCredential.Span), capability,
                    Instant.FromDateTimeOffset(deadline), timeout.Token);
            timeout.Token.ThrowIfCancellationRequested();
            now = DateTimeOffset.UtcNow;
            var reply = new ValidateReply
            {
                Decision = decision.Decision switch { Core.SessionDecision.Active => Decision.Active,
                    Core.SessionDecision.Unauthenticated => Decision.Unauthenticated, Core.SessionDecision.Forbidden => Decision.Forbidden, _ => Decision.Unavailable },
                ContractVersion = ContractLimits.Version, RequestId = request.RequestId,
                PolicyVersion = settings.ActionPolicy.Version, DecisionId = Guid.NewGuid().ToString("N"), CheckedAtUnixMs = now.ToUnixTimeMilliseconds()
            };
            if (reply.Decision == Decision.Active && decision.Subject is { } subject && decision.ValidUntil is { } until)
            {
                reply.AccountIdUuid = UuidCodec.Encode(subject.AccountId); reply.SessionFamilyUuid = UuidCodec.Encode(subject.FamilyId);
                reply.Generation = subject.Generation; reply.SessionProtocolVersion = (uint)subject.ProtocolVersion;
                reply.ValidUntilUnixMs = Math.Min(until.ToUnixTimeMilliseconds(), deadline.ToUnixTimeMilliseconds());
            }
            var window = new ReplyContext(request.RequestId, settings.ActionPolicy.Version, started, deadline, now);
            if (ContractRules.CheckReply(reply, window) != ContractError.None) throw Refuse(ContractError.DeadlineExceeded);
            // Link to request lifetime, not the local CTS that is disposed when this handler returns.
            measuredDecision=reply.Decision switch{Decision.Active=>0,Decision.Unauthenticated=>1,Decision.Forbidden=>2,_=>3};
            return new(reply, window, http.RequestAborted, decision.EvidenceCurrent);
        }
        catch (OperationCanceledException) { throw new RpcException(new Status(StatusCode.DeadlineExceeded, "Validation cancelled.")); }
        finally { CryptographicOperations.ZeroMemory(bytes);metrics?.Record(measuredDecision,System.Diagnostics.Stopwatch.GetElapsedTime(measuredAt)); }
    }
    private static RpcException Refuse(ContractError error) => new(new Status(error switch
    {
        ContractError.MissingCaller => StatusCode.Unauthenticated,
        ContractError.CallerDenied => StatusCode.PermissionDenied,
        ContractError.DeadlineExceeded => StatusCode.DeadlineExceeded,
        ContractError.TooLarge => StatusCode.ResourceExhausted,
        _ => StatusCode.InvalidArgument
    }, "Validation request refused."));
}
