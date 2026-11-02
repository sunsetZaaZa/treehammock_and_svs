using System.Net;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NodaTime;

using treehammock.Rigging.Delivery;
using treehammock.DataLayer.Cache;
using treehammock.Rigging.Authorization;
using treehammock.DataLayer;
using treehammock.Models.Activation;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Services;

public sealed record ActivationCreateResult(bool Result, string Code, Guid? RequestId = null, TimeSpan? RetryAfter = null);
public sealed record ActivationCreationAdmission(bool Result, string Code, Guid? AdmissionId = null, int? RetryAfterSeconds = null);
public sealed record ActivationDisableResult(bool Result, string Code);
public sealed record ActivationVerifyResult(bool Result, string Code, ActivationQuery? Activation, ActivationLifecycleResult? Entitlement = null);

public interface IActivationService
{
    Task<ActivationCreateResult> PlaceActivation(Guid accountId, Guid accountSecurityStamp, ActivationCreationRequest request, Instant createdOn, CancellationToken cancellationToken = default);
    Task<ActivationDisableResult> CancelActivation(Guid accountId, Guid accountSecurityStamp, ActivationUnSubscribeRequest request, Instant moment, CancellationToken cancellationToken = default);
    Task<ActivationDisableResult> DisableActivation(Guid accountId, Guid accountSecurityStamp, ActivationUnSubscribeRequest request, Instant moment, CancellationToken cancellationToken = default);
    Task<ActivationVerifyResult> VerifyActivation(Guid accountId, Guid accountSecurityStamp, ActivationDetailsRequest request, Instant moment, CancellationToken cancellationToken = default);
}

public class ActivationService : IActivationService
{
    public const string CreatedCode = "ACTIVATION_CREATED";
    public const string VerifiedCode = "ACTIVATION_VERIFIED";
    public const string DisabledCode = "ACTIVATION_DISABLED";
    public const string FailedCode = "ACTIVATION_FAILED";
    public const string NotFoundCode = "ACTIVATION_NOT_FOUND";
    public const string SecurityStampMismatchCode = "ACCOUNT_SECURITY_STAMP_MISMATCH";
    public const string EmailMismatchCode = "ACTIVATION_EMAIL_MISMATCH";
    public const string ExpiredCode = "ACTIVATION_EXPIRED";
    public const string CodeMismatchCode = "ACTIVATION_CODE_MISMATCH";
    public const string InvalidCode = "ACTIVATION_INVALID";
    public const string InvalidTermCode = "ACTIVATION_INVALID_TERM";
    public const string InvalidRecycleCode = "ACTIVATION_INVALID_RECYCLE";
    public const string ConflictCode = "ACTIVATION_CONFLICT";
    public const string CreationThrottledCode = "ABUSE_ACTIVATION_CREATION_THROTTLE_EXCEEDED";
    public const string AdmissionRequiredCode = "ACTIVATION_CREATION_ADMISSION_REQUIRED";
    public const string PendingCode = "ACTIVATION_CREATION_PENDING";
    public const string StoredCode = "ACTIVATION_STORED";
    public const string EmailDeliveryFailedCode = "ACTIVATION_EMAIL_DELIVERY_FAILED";
    public const string CleanupFailedCode = "ACTIVATION_CLEANUP_FAILED";

    private const int ActivationCodeByteLength = 18;

    private readonly IDurableDeliveryService? _durableDelivery;
    private readonly IActivationRepo _activationRepo;
    private readonly ISMTPService _smtpService;
    private readonly EmailSubjectSettings _emailSubjectSettings;
    private readonly ILogger<ActivationService> _logger;
    private readonly IDeliveryAbuseThrottleService _deliveryAbuseThrottleService;
    private readonly IActivationAbuseCounterKeyFactory _activationAbuseCounterKeyFactory;
    private readonly IAbuseCounterStore? _abuseCounterStore;
    private readonly AbuseControlSettings _abuseControlSettings;
    private readonly IHttpContextAccessor? _httpContextAccessor;

    public ActivationService(
        IActivationRepo activationRepo,
        ISMTPService smtpService,
        IOptions<EmailSubjectSettings>? emailSubjectSettings,
        ILogger<ActivationService> logger,
        IDeliveryAbuseThrottleService? deliveryAbuseThrottleService = null,
        IActivationAbuseCounterKeyFactory? activationAbuseCounterKeyFactory = null,
        IAbuseCounterStore? abuseCounterStore = null,
        IOptions<AbuseControlSettings>? abuseControlSettings = null,
        IHttpContextAccessor? httpContextAccessor = null,
        IDurableDeliveryService? durableDelivery = null)
    {
        _durableDelivery = durableDelivery;
        _activationRepo = activationRepo;
        _smtpService = smtpService;
        _emailSubjectSettings = emailSubjectSettings?.Value ?? new EmailSubjectSettings();
        _logger = logger;
        _deliveryAbuseThrottleService = deliveryAbuseThrottleService ?? NullDeliveryAbuseThrottleService.Instance;
        _activationAbuseCounterKeyFactory = activationAbuseCounterKeyFactory ?? new ActivationAbuseCounterKeyFactory();
        _abuseCounterStore = abuseCounterStore;
        _abuseControlSettings = abuseControlSettings?.Value ?? new AbuseControlSettings();
        _httpContextAccessor = httpContextAccessor;
    }

    public const string TrustedGrantRequiredCode = "ACTIVATION_TRUSTED_GRANT_REQUIRED";
    public const string ApprovalMismatchCode = "ACTIVATION_APPROVAL_MISMATCH";

    private bool Authority(Guid account, Guid stamp, out Guid family, out string hash)
    {
        family = Guid.Empty; hash = string.Empty;
        var context = _httpContextAccessor?.HttpContext;
        if (context?.Items[AuthContextItems.ActiveSession] is not ActiveSession session ||
            session.accountId != account || session.accountSecurityStamp != stamp ||
            context.Items[AuthContextItems.HashedAccessToken] is not string token || string.IsNullOrWhiteSpace(token)) return false;
        family = session.familyId; hash = token;
        return family != Guid.Empty;
    }

    public async Task<ActivationCreateResult> PlaceActivation(Guid accountId, Guid accountSecurityStamp,
        ActivationCreationRequest request, Instant createdOn, CancellationToken cancellationToken = default)
    {
        if (request.version != 2 || request.grantId == Guid.Empty || request.grantVersion < 1)
            return new(false, TrustedGrantRequiredCode);
        if (!Enum.IsDefined(typeof(FeatureSet), (int)request.featureSet) || !IsSupportedActivationTerm(request.term) || !IsSupportedActivationRecycle(request.recycle))
            return new(false, InvalidCode);
        if (!Authority(accountId, accountSecurityStamp, out Guid family, out string sessionHash))
            return new(false, SecurityStampMismatchCode);
        if (_durableDelivery is null) throw treehammock.Rigging.Dependencies.DependencyUnavailableException.InvalidResponse("activation_delivery_configuration");
        string email = NormalizeEmail(request.emailAddress);
        string code = GenerateActivationCode();
        string proofHash = HashCode(code);
        // Commit creation admission before cache/provider work. A delivery denial never refunds it.
        var admission = await _activationRepo.AdmitCreationAsync(accountId, accountSecurityStamp, sessionHash, family,
            request.grantId, request.grantVersion, proofHash, email, (short)request.featureSet, (short)request.term,
            (short)request.recycle, ActivationAbuseCounterKeyFactory.CreationIpFingerprint(ResolveClientIpAddress()),
            _abuseControlSettings.Activation, cancellationToken);
        if (!admission.Result)
            return new(false, admission.Code, RetryAfter: admission.RetryAfterSeconds is int seconds ? TimeSpan.FromSeconds(seconds) : null);
        if (admission.AdmissionId is null) throw treehammock.Rigging.Dependencies.DependencyUnavailableException.InvalidResponse("activation_creation_admission");
        var deliveryDecision = await _durableDelivery.AdmitWithReasonAsync(AbuseFeature.Activation, "email", accountId, email, cancellationToken);
        if (!deliveryDecision.Allowed)
            return new(false, deliveryDecision.ReasonCode ?? AbuseReasonCodes.DeliveryThrottleExceeded, RetryAfter: deliveryDecision.RetryAfter);
        var result = await _durableDelivery.EnqueueAsync(new(accountId, accountSecurityStamp, "activation", proofHash,
            SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),
            new { admissionId = admission.AdmissionId, grantId = request.grantId, grantVersion = request.grantVersion, sessionHash, familyId = family,
                emailAddress = email, tier = request.featureSet, term = (short)request.term, cadence = (short)request.recycle },
            new("activation-code", "email", email, _emailSubjectSettings.ActivationCode, code)), cancellationToken);
        return new(result.Result, result.Result ? CreatedCode : result.Code, result.DeliveryId);
    }

    public async Task<ActivationDisableResult> DisableActivation(Guid accountId, Guid accountSecurityStamp,
        ActivationUnSubscribeRequest request, Instant moment, CancellationToken cancellationToken = default)
    {
        if (request.version != 2 || request.grantId == Guid.Empty || request.grantVersion < 1)
            return new(false, TrustedGrantRequiredCode);
        if (!Authority(accountId, accountSecurityStamp, out Guid family, out string sessionHash))
            return new(false, SecurityStampMismatchCode);
        var result = await _activationRepo.TransitionAsync(accountId, accountSecurityStamp, sessionHash, family,
            request.grantId, request.grantVersion, request.requestId, null, "disable", cancellationToken);
        return new(result.Result, result.Code);
    }

    public async Task<ActivationDisableResult> CancelActivation(Guid accountId, Guid accountSecurityStamp,
        ActivationUnSubscribeRequest request, Instant moment, CancellationToken cancellationToken = default)
    {
        if (request.version != 2 || request.grantId == Guid.Empty || request.grantVersion < 1 || request.requestId == Guid.Empty)
            return new(false, TrustedGrantRequiredCode);
        if (!Authority(accountId, accountSecurityStamp, out Guid family, out string sessionHash))
            return new(false, SecurityStampMismatchCode);
        var result = await _activationRepo.TransitionAsync(accountId, accountSecurityStamp, sessionHash, family,
            request.grantId, request.grantVersion, request.requestId, null, "cancel", cancellationToken);
        return new(result.Result, result.Code);
    }

    public async Task<ActivationVerifyResult> VerifyActivation(Guid accountId, Guid accountSecurityStamp,
        ActivationDetailsRequest request, Instant moment, CancellationToken cancellationToken = default)
    {
        if (request.version != 2 || request.grantId == Guid.Empty || request.grantVersion < 1 || request.requestId == Guid.Empty)
            return new(false, TrustedGrantRequiredCode, null);
        if (!Authority(accountId, accountSecurityStamp, out Guid family, out string sessionHash))
            return new(false, SecurityStampMismatchCode, null);
        string normalizedEmail = NormalizeEmail(request.emailAddress);
        AbuseDecision decision = await CheckActivationVerifyAttemptPolicy(accountId, normalizedEmail);
        if (!decision.Allowed) return new(false, decision.ReasonCode ?? AbuseReasonCodes.ActivationVerifyAttemptsExceeded, null);
        var result = await _activationRepo.TransitionAsync(accountId, accountSecurityStamp, sessionHash, family,
            request.grantId, request.grantVersion, request.requestId, HashCode(request.code.Trim()), "verify", cancellationToken);
        if (result.Result) await ResetActivationVerifyAttemptPolicy(accountId, normalizedEmail);
        return new(result.Result, result.Code, null, result);
    }

    internal static string HashCode(string code) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(code))).ToLowerInvariant();

    private async Task<AbuseDecision> CheckActivationVerifyAttemptPolicy(Guid accountId, string normalizedEmail)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.Activation.Enabled
            || _abuseCounterStore is null)
        {
            return AbuseDecision.Allow();
        }

        TimeSpan window = TimeSpan.FromSeconds(_abuseControlSettings.Activation.VerifyAttemptWindowSeconds);
        TimeSpan cooldown = TimeSpan.FromSeconds(_abuseControlSettings.Activation.CooldownSecondsAfterExhaustion);
        var accountLimit = new AbuseCounterLimit(
            _abuseControlSettings.Activation.MaxVerifyAttemptsPerAccount,
            window,
            cooldown);
        var identifierLimit = new AbuseCounterLimit(
            _abuseControlSettings.Activation.MaxVerifyAttemptsPerIdentifier,
            window,
            cooldown);
        var ipLimit = new AbuseCounterLimit(
            _abuseControlSettings.Activation.MaxVerifyAttemptsPerIp,
            window,
            cooldown);

        AbuseDecision accountDecision = await IncrementActivationVerifyCounter(
            _activationAbuseCounterKeyFactory.ForVerifyAccount(accountId),
            accountLimit);
        if (!accountDecision.Allowed)
        {
            return accountDecision;
        }

        AbuseDecision identifierDecision = await IncrementActivationVerifyCounter(
            _activationAbuseCounterKeyFactory.ForVerifyIdentifier(normalizedEmail),
            identifierLimit);
        if (!identifierDecision.Allowed)
        {
            return identifierDecision;
        }

        return await IncrementActivationVerifyCounter(
            _activationAbuseCounterKeyFactory.ForVerifyIpAddress(ResolveClientIpAddress()),
            ipLimit);
    }

    private async Task<AbuseDecision> IncrementActivationVerifyCounter(
        AbuseCounterKey key,
        AbuseCounterLimit limit)
    {
        CounterDecision decision = await _abuseCounterStore!.IncrementAsync(key, limit);
        if (decision.CanAdmit)
        {
            return AbuseDecision.Allow();
        }

        string reasonCode = decision.ReasonCode == AbuseReasonCodes.CounterStoreUnavailable || decision.ReasonCode == AbuseReasonCodes.CounterStoreTimeout
            ? decision.ReasonCode!
            : AbuseReasonCodes.ActivationVerifyAttemptsExceeded;

        return AbuseDecision.Deny(reasonCode, decision.RetryAfter);
    }

    private async Task ResetActivationVerifyAttemptPolicy(Guid accountId, string normalizedEmail)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.Activation.Enabled
            || _abuseCounterStore is null)
        {
            return;
        }

        await _abuseCounterStore.ResetAsync(_activationAbuseCounterKeyFactory.ForVerifyAccount(accountId));
        await _abuseCounterStore.ResetAsync(_activationAbuseCounterKeyFactory.ForVerifyIdentifier(normalizedEmail));
        await _abuseCounterStore.ResetAsync(_activationAbuseCounterKeyFactory.ForVerifyIpAddress(ResolveClientIpAddress()));
    }

    private string ResolveClientIpAddress()
    {
        IPAddress? remoteIp = _httpContextAccessor?.HttpContext?.Connection.RemoteIpAddress;
        return remoteIp?.ToString() ?? "unknown";
    }

    internal static string GenerateActivationCode()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(ActivationCodeByteLength);
        string code = Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        return code;
    }

    internal static bool IsSupportedActivationTerm(DayDuration term)
    {
        return CalendarTermCalculator.Supported(term);
    }

    internal static bool IsSupportedActivationRecycle(DurationRepeat recycle)
    {
        return Enum.IsDefined(typeof(DurationRepeat), recycle);
    }

    private static string NormalizeEmail(string emailAddress)
    {
        return emailAddress.Trim().ToLowerInvariant();
    }

    private static string RecipientDomain(string emailAddress)
    {
        int atIndex = emailAddress.LastIndexOf('@');
        return atIndex >= 0 && atIndex < emailAddress.Length - 1
            ? emailAddress[(atIndex + 1)..]
            : "unknown";
    }
}
