using treehammock.Rigging.Security;
using treehammock.Rigging.Delivery;
using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NodaTime;

using treehammock.Models.Recovery;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Services;

public sealed record AccountRecoveryStartResult(bool Result, string Code);
public sealed record AccountRecoveryVerifyResult(bool Result, string Code);

public interface IAccountRecoveryService
{
    Task<AccountRecoveryStartResult> StartRecovery(AccountRecoveryRequest request, Instant createdOn, CancellationToken cancellationToken = default);
    Task<AccountRecoveryVerifyResult> VerifyRecovery(AccountRecoveryVerifyRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// Account recovery is the account-unlock flow for accounts that have reached the password-attempt lockout threshold.
/// It is not a password-reset, username-recovery, or MFA-reset feature.
/// </summary>
public class AccountRecoveryService : IAccountRecoveryService
{
    public const string PendingCode = "ACCOUNT_UNLOCK_PENDING";
    public const string VerifiedCode = "ACCOUNT_UNLOCK_VERIFIED";
    public const string TokenExpiredCode = "ACCOUNT_UNLOCK_TOKEN_EXPIRED";
    public const string TokenMismatchCode = "ACCOUNT_UNLOCK_TOKEN_MISMATCH";
    public const string FailedCode = "ACCOUNT_UNLOCK_FAILED";
    public const string NotLockedCode = "ACCOUNT_UNLOCK_NOT_LOCKED";

    private const int RecoveryTokenByteLength = 32;

    private readonly IAccountRecoveryRepo _accountRecoveryRepo;
    private readonly EmailSubjectSettings _emailSubjectSettings;
    private readonly ILogger<AccountRecoveryService> _logger;
    private readonly IAccountUnlockAbuseCounterKeyFactory _accountUnlockAbuseCounterKeyFactory;
    private readonly IAbuseCounterStore? _abuseCounterStore;
    private readonly AbuseControlSettings _abuseControlSettings;
    private readonly IHttpContextAccessor? _httpContextAccessor;

    private readonly IDurableDeliveryService _delivery;
    public AccountRecoveryService(
        IDurableDeliveryService delivery,
        IAccountRecoveryRepo accountRecoveryRepo,
        IOptions<EmailSubjectSettings>? emailSubjectSettings,
        ILogger<AccountRecoveryService> logger,
        IAccountUnlockAbuseCounterKeyFactory? accountUnlockAbuseCounterKeyFactory = null,
        IAbuseCounterStore? abuseCounterStore = null,
        IOptions<AbuseControlSettings>? abuseControlSettings = null,
        IHttpContextAccessor? httpContextAccessor = null)
    {
        _delivery = delivery;
        _accountRecoveryRepo = accountRecoveryRepo;
        _emailSubjectSettings = emailSubjectSettings?.Value ?? new EmailSubjectSettings();
        _logger = logger;
        _accountUnlockAbuseCounterKeyFactory = accountUnlockAbuseCounterKeyFactory ?? new AccountUnlockAbuseCounterKeyFactory();
        _abuseCounterStore = abuseCounterStore;
        _abuseControlSettings = abuseControlSettings?.Value ?? new AbuseControlSettings();
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<AccountRecoveryStartResult> StartRecovery(AccountRecoveryRequest request, Instant createdOn, CancellationToken cancellationToken = default)
    {
        AccountRecoveryLookupResult? lookup = await _accountRecoveryRepo.LookupLockedAccount(NormalizeIdentifier(request.identifier), createdOn, cancellationToken: cancellationToken);
        if (lookup is null)
        {
            return new AccountRecoveryStartResult(false, FailedCode);
        }

        if (!lookup.Result
            || lookup.AccountId is null
            || lookup.AccountSecurityStamp is null
            || lookup.UnlockWhen is null
            || lookup.LockoutAttemptVersion is null
            || !HasDeliveryDestination(lookup, request.deliveryMethod))
        {
            // Keep unlock start responses generic so unknown, currently-unlocked, or non-deliverable accounts do not leak account state.
            return new AccountRecoveryStartResult(true, PendingCode);
        }

        string channel=request.deliveryMethod==AccountUnlockDeliveryMethod.EMAIL?"email":"sms";
        string destination=channel=="email"?lookup.EmailAddress!:BuildSmsDestination(lookup.PhoneCountryCode,lookup.PhoneNumber)!;
        if(!await _delivery.AdmitAsync(AbuseFeature.AccountUnlock,channel,lookup.AccountId.Value,destination,cancellationToken))return new(true,PendingCode);
        if(await _delivery.ExistingAsync(lookup.AccountId.Value,lookup.AccountSecurityStamp.Value,"unlock",cancellationToken) is not null)return new(true,PendingCode);
        string token=GenerateRecoveryToken();
        var result=await _delivery.EnqueueAsync(new(lookup.AccountId.Value,lookup.AccountSecurityStamp.Value,"unlock",SecretHashUtility.HashToken(token),
            createdOn.Plus(Duration.FromHours(1)),new {method=(short)request.deliveryMethod,lockoutUnlockWhen=lookup.UnlockWhen.Value,lockoutAttemptVersion=lookup.LockoutAttemptVersion.Value},
            new("unlock",channel,destination,_emailSubjectSettings.AccountUnlock,token)),cancellationToken);
        return new(true,PendingCode);
    }

    public async Task<AccountRecoveryVerifyResult> VerifyRecovery(AccountRecoveryVerifyRequest request, CancellationToken cancellationToken = default)
    {
        string token = request.token.Trim();
        if(await _delivery.IsPendingAsync("unlock",SecretHashUtility.HashToken(token),cancellationToken))return new(false,PendingCode);
        AbuseDecision abuseDecision = await CheckUnlockVerifyAttemptPolicy(token);
        if (!abuseDecision.Allowed)
        {
            return new AccountRecoveryVerifyResult(false, abuseDecision.ReasonCode ?? AbuseReasonCodes.AccountUnlockVerifyAttemptsExceeded);
        }

        AccountRecovery_Status? verified = await _accountRecoveryRepo.VerifyUnlock(token, cancellationToken: cancellationToken);
        if (verified == AccountRecovery_Status.COMPLETE)
        {
            await ResetUnlockVerifyAttemptPolicy(token);
            return new AccountRecoveryVerifyResult(true, VerifiedCode);
        }

        return new AccountRecoveryVerifyResult(false, UnlockStatusCode(verified));
    }


    private async Task<AbuseDecision> CheckUnlockVerifyAttemptPolicy(string token)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.AccountUnlock.Enabled
            || _abuseCounterStore is null)
        {
            return AbuseDecision.Allow();
        }

        TimeSpan window = TimeSpan.FromSeconds(_abuseControlSettings.AccountUnlock.VerifyAttemptWindowSeconds);
        TimeSpan cooldown = TimeSpan.FromSeconds(_abuseControlSettings.AccountUnlock.CooldownSecondsAfterExhaustion);
        var tokenLimit = new AbuseCounterLimit(
            _abuseControlSettings.AccountUnlock.MaxVerifyAttemptsPerToken,
            window,
            cooldown);
        var ipLimit = new AbuseCounterLimit(
            _abuseControlSettings.AccountUnlock.MaxVerifyAttemptsPerIp,
            window,
            cooldown);

        AbuseDecision tokenDecision = await IncrementUnlockVerifyCounter(
            _accountUnlockAbuseCounterKeyFactory.ForVerifyToken(token),
            tokenLimit);
        if (!tokenDecision.Allowed)
        {
            return tokenDecision;
        }

        return await IncrementUnlockVerifyCounter(
            _accountUnlockAbuseCounterKeyFactory.ForVerifyIpAddress(ResolveClientIpAddress()),
            ipLimit);
    }

    private async Task<AbuseDecision> IncrementUnlockVerifyCounter(
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
            : AbuseReasonCodes.AccountUnlockVerifyAttemptsExceeded;

        return AbuseDecision.Deny(reasonCode, decision.RetryAfter);
    }

    private async Task ResetUnlockVerifyAttemptPolicy(string token)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.AccountUnlock.Enabled
            || _abuseCounterStore is null)
        {
            return;
        }

        await _abuseCounterStore.ResetAsync(_accountUnlockAbuseCounterKeyFactory.ForVerifyToken(token));
        await _abuseCounterStore.ResetAsync(_accountUnlockAbuseCounterKeyFactory.ForVerifyIpAddress(ResolveClientIpAddress()));
    }

    private string ResolveClientIpAddress()
    {
        IPAddress? remoteIp = _httpContextAccessor?.HttpContext?.Connection.RemoteIpAddress;
        return remoteIp?.ToString() ?? "unknown";
    }

    internal static string GenerateRecoveryToken()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(RecoveryTokenByteLength);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static bool HasDeliveryDestination(AccountRecoveryLookupResult lookup, AccountUnlockDeliveryMethod deliveryMethod)
    {
        return deliveryMethod switch
        {
            AccountUnlockDeliveryMethod.EMAIL => !string.IsNullOrWhiteSpace(lookup.EmailAddress),
            AccountUnlockDeliveryMethod.SMS => !string.IsNullOrWhiteSpace(lookup.PhoneNumber),
            _ => false
        };
    }

    private static string? BuildSmsDestination(string? phoneCountryCode, string? phoneNumber)
    {
        if (string.IsNullOrWhiteSpace(phoneNumber))
        {
            return null;
        }

        string normalizedPhoneNumber = phoneNumber.Trim();
        if (normalizedPhoneNumber.StartsWith('+'))
        {
            return normalizedPhoneNumber;
        }

        string normalizedCountryCode = phoneCountryCode?.Trim().TrimStart('+') ?? string.Empty;
        return string.IsNullOrWhiteSpace(normalizedCountryCode)
            ? normalizedPhoneNumber
            : $"+{normalizedCountryCode}{normalizedPhoneNumber}";
    }

    private static string StartUnlockStatusCode(AccountRecovery_Status? status)
    {
        return status switch
        {
            AccountRecovery_Status.NOT_LOCKED => NotLockedCode,
            _ => FailedCode
        };
    }

    private static string UnlockStatusCode(AccountRecovery_Status? status)
    {
        return status switch
        {
            AccountRecovery_Status.EXPIRED => TokenExpiredCode,
            AccountRecovery_Status.BAD_TOKEN or AccountRecovery_Status.BAD_VERIFY or AccountRecovery_Status.STALE_LOCKOUT => TokenMismatchCode,
            AccountRecovery_Status.NOT_LOCKED => NotLockedCode,
            _ => FailedCode
        };
    }

    private static string NormalizeIdentifier(string identifier)
    {
        return identifier.Trim().ToLowerInvariant();
    }

    private static string RecipientDomain(string emailAddress)
    {
        int atIndex = emailAddress.LastIndexOf('@');
        return atIndex >= 0 && atIndex < emailAddress.Length - 1
            ? emailAddress[(atIndex + 1)..]
            : "unknown";
    }
}
