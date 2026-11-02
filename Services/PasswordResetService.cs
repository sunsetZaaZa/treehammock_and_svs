using treehammock.Rigging.Dependencies;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NodaTime;

using treehammock.DataLayer.Cache;
using treehammock.Models.PasswordReset;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Services;

public interface IPasswordResetService
{
    Task<PasswordResetRequestResult> RequestReset(
        RequestPasswordResetCommand command,
        CancellationToken cancellationToken);

    Task<PasswordResetVerifyResult> VerifyResetToken(
        VerifyPasswordResetTokenCommand command,
        CancellationToken cancellationToken);

    Task<PasswordResetTwoFactorSelectResult> SelectTwoFactorConfiguration(
        SelectPasswordResetTwoFactorConfigurationCommand command,
        CancellationToken cancellationToken);

    Task<PasswordResetTwoFactorVerifyResult> VerifyTwoFactorProof(
        VerifyPasswordResetTwoFactorCommand command,
        CancellationToken cancellationToken);

    Task<PasswordResetFinalizeResult> FinalizeReset(
        FinalizePasswordResetCommand command,
        CancellationToken cancellationToken);
}

public sealed record PasswordResetRequestResult(string Code, Guid ResetId, PasswordResetCaptchaChallenge? CaptchaChallenge = null);

public sealed record PasswordResetFinalizeResult(string Code, int StatusCode);

public sealed record PasswordResetVerifyResult(
    string Code,
    int StatusCode,
    string Status,
    string? ResetAccessToken,
    bool RequiresTwoFactor,
    List<TwoFactorAuthConfiguration> AvailableTwoFactorAuthConfigurations,
    Instant? ExpiresAt);

public sealed record PasswordResetTwoFactorSelectResult(
    string Code,
    int StatusCode,
    string Status,
    string? ResetAccessToken,
    TwoFactorAuthConfiguration? SelectedConfiguration,
    TwoFactorAuthMethod? CurrentRequiredMethod,
    Instant? ChallengeExpiration,
    List<TwoFactorAuthMethod> CompletedTwoFactorAuthMethods,
    List<TwoFactorAuthMethod> RemainingTwoFactorAuthMethods,
    List<TwoFactorAuthConfiguration> AvailableTwoFactorAuthConfigurations,
    Instant? ExpiresAt,
    bool CanChangePassword);

public sealed record PasswordResetTwoFactorVerifyResult(
    string Code,
    int StatusCode,
    string Status,
    string? ResetAccessToken,
    TwoFactorAuthConfiguration? SelectedConfiguration,
    TwoFactorAuthMethod? CurrentRequiredMethod,
    List<TwoFactorAuthMethod> CompletedTwoFactorAuthMethods,
    List<TwoFactorAuthMethod> RemainingTwoFactorAuthMethods,
    Instant? ExpiresAt,
    bool CanChangePassword);

public sealed class PasswordResetService : IPasswordResetService
{
    public const string RequestAcceptedCode = "PASSWORD_RESET_REQUEST_ACCEPTED";
    public const string TokenVerifiedCode = "PASSWORD_RESET_TOKEN_VERIFIED";
    public const string TwoFactorSelectionRequiredCode = "PASSWORD_RESET_TWO_FACTOR_SELECTION_REQUIRED";
    public const string TwoFactorConfigurationNotAvailableCode = "PASSWORD_RESET_TWO_FACTOR_CONFIGURATION_NOT_AVAILABLE";
    public const string TwoFactorChallengeSentCode = "PASSWORD_RESET_TWO_FACTOR_CHALLENGE_SENT";
    public const string TwoFactorAuthenticatorCodeRequiredCode = "PASSWORD_RESET_TWO_FACTOR_AUTHENTICATOR_CODE_REQUIRED";
    public const string TwoFactorSessionPersistenceFailedCode = "PASSWORD_RESET_TWO_FACTOR_SESSION_PERSISTENCE_FAILED";
    public const string TwoFactorChallengeDeliveryUnsupportedCode = "PASSWORD_RESET_TWO_FACTOR_CHALLENGE_DELIVERY_UNSUPPORTED";
    public const string TwoFactorChallengeDeliveryFailedCode = "PASSWORD_RESET_TWO_FACTOR_CHALLENGE_DELIVERY_FAILED";
    public const string TwoFactorProofAcceptedNextProofRequiredCode = "PASSWORD_RESET_TWO_FACTOR_PROOF_ACCEPTED_NEXT_PROOF_REQUIRED";
    public const string TwoFactorCompleteCode = "PASSWORD_RESET_TWO_FACTOR_COMPLETE";
    public const string TwoFactorRequiredCode = "PASSWORD_RESET_TWO_FACTOR_REQUIRED";
    public const string TwoFactorNotCompleteCode = "PASSWORD_RESET_TWO_FACTOR_NOT_COMPLETE";
    public const string TwoFactorMethodNotCurrentlyRequiredCode = "TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED";
    public const string TwoFactorChallengeInvalidCode = "TWO_FACTOR_CHALLENGE_INVALID";
    public const string SessionExpiredCode = "PASSWORD_RESET_SESSION_EXPIRED";
    public const string CompletedCode = "PASSWORD_RESET_COMPLETED";
    public const string RateLimitedCode = "PASSWORD_RESET_RATE_LIMITED";
    public const string AbuseCounterUnavailableCode = "PASSWORD_RESET_ABUSE_COUNTER_UNAVAILABLE";
    public const string RequestCooldownCode = "PASSWORD_RESET_REQUEST_COOLDOWN";
    public const string AttemptsExceededCode = "PASSWORD_RESET_ATTEMPTS_EXCEEDED";
    public const string InvalidProofCode = "PASSWORD_RESET_INVALID_PROOF";
    public const string IneligibleDeliveryChannelCode = "PASSWORD_RESET_DELIVERY_CHANNEL_INELIGIBLE";
    public const string LookupFailedCode = "PASSWORD_RESET_LOOKUP_FAILED";
    public const string CreateFailedCode = "PASSWORD_RESET_CREATE_FAILED";
    public const string DeliveryFailedCode = "PASSWORD_RESET_DELIVERY_FAILED";
    public const string ExpiredCode = "PASSWORD_RESET_EXPIRED";
    public const string ConsumedCode = "PASSWORD_RESET_CONSUMED";
    public const string CancelledCode = "PASSWORD_RESET_CANCELLED";
    public const string NotFoundCode = "PASSWORD_RESET_NOT_FOUND";
    public const string ReadyCode = "PASSWORD_RESET_READY";
    public const string AccountStaleCode = "PASSWORD_RESET_ACCOUNT_STALE";
    public const string AccountMismatchCode = "PASSWORD_RESET_ACCOUNT_MISMATCH";
    public const string AccountNotFoundCode = "PASSWORD_RESET_ACCOUNT_NOT_FOUND";
    public const string PromotionFailedCode = "PASSWORD_RESET_PROMOTION_FAILED";
    public const string ValidationFailedCode = "VALIDATION_FAILED";

    private readonly IPasswordResetRepo _passwordResetRepo;
    private readonly IPasswordResetCodeGenerator _codeGenerator;
    private readonly IPasswordResetCodeHasher _codeHasher;
    private readonly IPasswordResetRateLimitKeyFactory _rateLimitKeyFactory;
    private readonly IPasswordResetAbusePolicy _abusePolicy;
    private readonly IPasswordResetAbuseCounterKeyFactory _abuseCounterKeyFactory;
    private readonly IAbuseCounterStore _abuseCounterStore;
    private readonly AbuseControlSettings _abuseControlSettings;
    private readonly IPasswordResetDeliveryService _deliveryService;
    private readonly IPasswordResetSessionService? _passwordResetSessionService;
    private readonly IPasswordResetTotpVerifier _totpVerifier;
    private readonly IPasswordResetPasswordMaterialFactory _passwordMaterialFactory;
    private readonly PasswordResetSettings _settings;
    private readonly RegistrationSettings _registrationSettings;
    private readonly ILogger<PasswordResetService> _logger;
    private readonly IClock _clock;
    private readonly IPasswordResetPublicGate? _publicGate;
    private static readonly System.Diagnostics.Metrics.Histogram<double> PublicRequestDuration =
        new System.Diagnostics.Metrics.Meter("treehammock.password_reset.public").CreateHistogram<double>("password_reset_public_request_duration_ms");

    public PasswordResetService(
        IPasswordResetRepo passwordResetRepo,
        IPasswordResetCodeGenerator codeGenerator,
        IPasswordResetCodeHasher codeHasher,
        IPasswordResetRateLimitKeyFactory rateLimitKeyFactory,
        IPasswordResetAbusePolicy abusePolicy,
        IPasswordResetAbuseCounterKeyFactory abuseCounterKeyFactory,
        IAbuseCounterStore abuseCounterStore,
        IOptions<AbuseControlSettings> abuseControlSettings,
        IPasswordResetDeliveryService deliveryService,
        IPasswordResetTotpVerifier totpVerifier,
        IPasswordResetPasswordMaterialFactory passwordMaterialFactory,
        IOptions<PasswordResetSettings> settings,
        IOptions<RegistrationSettings> registrationSettings,
        ILogger<PasswordResetService> logger,
        IPasswordResetSessionService? passwordResetSessionService = null,
        IPasswordResetPublicGate? publicGate = null)
        : this(
            passwordResetRepo,
            codeGenerator,
            codeHasher,
            rateLimitKeyFactory,
            abusePolicy,
            abuseCounterKeyFactory,
            abuseCounterStore,
            abuseControlSettings,
            deliveryService,
            totpVerifier,
            passwordMaterialFactory,
            settings,
            registrationSettings,
            logger,
            SystemClock.Instance,
            passwordResetSessionService, publicGate)
    {
    }

    public PasswordResetService(
        IPasswordResetRepo passwordResetRepo,
        IPasswordResetCodeGenerator codeGenerator,
        IPasswordResetCodeHasher codeHasher,
        IPasswordResetRateLimitKeyFactory rateLimitKeyFactory,
        IPasswordResetAbusePolicy abusePolicy,
        IPasswordResetAbuseCounterKeyFactory abuseCounterKeyFactory,
        IAbuseCounterStore abuseCounterStore,
        IOptions<AbuseControlSettings> abuseControlSettings,
        IPasswordResetDeliveryService deliveryService,
        IPasswordResetTotpVerifier totpVerifier,
        IPasswordResetPasswordMaterialFactory passwordMaterialFactory,
        IOptions<PasswordResetSettings> settings,
        IOptions<RegistrationSettings> registrationSettings,
        ILogger<PasswordResetService> logger,
        IClock clock,
        IPasswordResetSessionService? passwordResetSessionService = null,
        IPasswordResetPublicGate? publicGate = null)
    {
        _passwordResetRepo = passwordResetRepo;
        _codeGenerator = codeGenerator;
        _codeHasher = codeHasher;
        _rateLimitKeyFactory = rateLimitKeyFactory;
        _abusePolicy = abusePolicy;
        _abuseCounterKeyFactory = abuseCounterKeyFactory;
        _abuseCounterStore = abuseCounterStore;
        _abuseControlSettings = abuseControlSettings.Value;
        _deliveryService = deliveryService;
        _passwordResetSessionService = passwordResetSessionService;
        _totpVerifier = totpVerifier;
        _passwordMaterialFactory = passwordMaterialFactory;
        _settings = settings.Value;
        _registrationSettings = registrationSettings.Value;
        _logger = logger;
        _clock = clock;
        _publicGate = publicGate;
        if (_settings.CaptchaChallengeEnabled && publicGate is null)
            throw new InvalidOperationException("Enabled CAPTCHA requires the public request gate.");
    }

    public async Task<PasswordResetRequestResult> RequestReset(RequestPasswordResetCommand command, CancellationToken cancellationToken)
    {
        var started = System.Diagnostics.Stopwatch.StartNew();
        try { return await RequestResetCore(command, cancellationToken); }
        catch (DependencyUnavailableException)
        {
            _logger.LogWarning("Password reset request admission or delivery staging dependency was unavailable.");
            return Accepted(Guid.NewGuid());
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException)
        {
            _logger.LogWarning("Password reset request staging did not yield an acknowledged outcome.");
            return Accepted(Guid.NewGuid());
        }
        finally
        {
            double remaining = _settings.PublicRequestResponseFloorMilliseconds + RandomNumberGenerator.GetInt32(51) - started.Elapsed.TotalMilliseconds;
            if (remaining > 0) await Task.Delay(TimeSpan.FromMilliseconds(remaining), cancellationToken);
            PublicRequestDuration.Record(started.Elapsed.TotalMilliseconds);
        }
    }

    private async Task<PasswordResetRequestResult> RequestResetCore(
        RequestPasswordResetCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        string identifier = NormalizeIdentifier(command.Identifier);
        string deliveryChannel = PasswordResetDeliveryChannels.Normalize(command.DeliveryChannel);
        Guid publicResetId = Guid.NewGuid();
        Instant now = _clock.GetCurrentInstant();

        if (!PasswordResetDeliveryChannels.IsSupported(deliveryChannel))
        {
            return Accepted(publicResetId);
        }

        if (_publicGate is not null)
        {
            var admission = await _publicGate.AdmitRequestAsync(command, cancellationToken);
            if (!admission.Allowed) return new(RequestAcceptedCode, publicResetId, admission.Challenge);
        }

        if (!await CheckPasswordResetRequestAbusePolicy(identifier, command.RequestIpAddress, cancellationToken))
        {
            return Accepted(publicResetId);
        }

        bool ipAllowed = await RegisterRateLimit(
            _rateLimitKeyFactory.ForIpAddress(command.RequestIpAddress),
            _settings.DailyRequestLimitPerIp,
            now,
            cancellationToken);
        if (!ipAllowed)
        {
            _logger.LogInformation("Password reset request was rate limited by IP scope.");
            return Accepted(publicResetId);
        }

        PasswordResetAccountLookupResult? lookup = await _passwordResetRepo.LookupPasswordResetAccountAsync(
            identifier,
            now,
            cancellationToken);

        if (lookup == null)
        {
            _logger.LogWarning("Password reset account lookup failed before a non-enumerating response was returned.");
            return Accepted(publicResetId);
        }

        if (!lookup.Result || lookup.AccountId is null || lookup.AccountSecurityStamp is null)
        {
            return Accepted(publicResetId);
        }

        if (!await CheckPasswordResetRequestAccountPolicy(lookup.AccountId.Value, cancellationToken))
        {
            return Accepted(publicResetId);
        }

        PasswordResetEligibility eligibility = BuildEligibility(deliveryChannel, lookup);
        if (!eligibility.Eligible)
        {
            _logger.LogInformation(
                "Password reset delivery channel {DeliveryChannel} was not eligible for account {AccountId}; returning generic response.",
                deliveryChannel,
                lookup.AccountId);
            return Accepted(publicResetId);
        }

        string destinationFingerprint = FingerprintDestination(eligibility.DestinationKind, eligibility.DestinationValue);
        bool accountAllowed = await RegisterRateLimit(
            _rateLimitKeyFactory.ForAccount(lookup.AccountId.Value),
            _settings.DailyRequestLimitPerAccount,
            now,
            cancellationToken);
        bool destinationAllowed = await RegisterRateLimit(
            _rateLimitKeyFactory.ForDestinationFingerprint(destinationFingerprint),
            _settings.DailyRequestLimitPerDestination,
            now,
            cancellationToken);

        if (!accountAllowed || !destinationAllowed)
        {
            _logger.LogInformation(
                "Password reset request was rate limited for account {AccountId} or destination {DestinationMasked}.",
                lookup.AccountId,
                eligibility.DestinationMasked);
            return Accepted(publicResetId);
        }

        if(!await _deliveryService.AdmitAsync(lookup.AccountId.Value,eligibility.DeliveryChannel!,eligibility.DestinationValue,cancellationToken))
            return Accepted(publicResetId);
        if(await _deliveryService.ExistingAsync(lookup.AccountId.Value,lookup.AccountSecurityStamp.Value,"reset",cancellationToken) is Guid)return Accepted(publicResetId);
        Guid resetId = publicResetId;
        string? keyCode = eligibility.RequiresKeyCode ? _codeGenerator.GenerateKeyCode() : null;
        string? keyCodeHash = keyCode is null ? null : _codeHasher.HashCode(resetId, keyCode);
        int? keyCodeHashVersion = keyCodeHash is null ? null : _codeHasher.HashVersion;
        Instant expiresAt = now.Plus(Duration.FromMinutes(_settings.ExpirationMinutes));

        var resetCommand=new CreatePasswordResetRequestDbCommand(resetId,lookup.AccountId.Value,eligibility.Method,
            eligibility.DeliveryChannel,keyCodeHash,keyCodeHashVersion,destinationFingerprint,eligibility.DestinationMasked,
            eligibility.RequiresKeyCode,eligibility.RequiresTotp,expiresAt,_settings.MaxAttempts,command.RequestIpAddress,command.UserAgent,
            lookup.AccountSecurityStamp.Value);
        var staged=await _deliveryService.StageAsync(resetCommand,new(resetId,lookup.AccountId.Value,eligibility.Method,
            eligibility.DeliveryChannel!,eligibility.DestinationMasked,eligibility.DestinationValue,keyCode!,expiresAt,command.RequestIpAddress),cancellationToken);
        return Accepted(publicResetId);
    }

    public async Task<PasswordResetVerifyResult> VerifyResetToken(
        VerifyPasswordResetTokenCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (command.ResetId == Guid.Empty || string.IsNullOrWhiteSpace(command.KeyCode))
        {
            return VerifyFailure(ValidationFailedCode, StatusCodes.Status400BadRequest);
        }

        if (_publicGate is not null && !await _publicGate.AdmitProofAsync(command.RequestIpAddress, cancellationToken))
            return VerifyFailure(InvalidProofCode, StatusCodes.Status401Unauthorized);

        if(await _deliveryService.IsPendingAsync(_codeHasher.HashCode(command.ResetId,command.KeyCode),cancellationToken))
            return new("PASSWORD_RESET_DELIVERY_PENDING",StatusCodes.Status202Accepted,"pending",null,false,[],null);
        PasswordResetFinalizeResult? abuseDecision = await CheckPasswordResetTokenVerificationAbusePolicy(command.ResetId, cancellationToken);
        if (abuseDecision is not null)
        {
            return VerifyFailure(abuseDecision.Code, abuseDecision.StatusCode);
        }

        PasswordResetFinalizeRecord? reset = await _passwordResetRepo.GetPasswordResetRequestForFinalizeAsync(
            command.ResetId,
            cancellationToken);

        if (reset is null || reset.PasswordResetRequestId is null || reset.AccountId is null)
        {
            return VerifyFailure(InvalidProofCode, StatusCodes.Status401Unauthorized);
        }

        if (reset.Result != true)
        {
            return VerifyFailureFromResetLookupCode(reset.Code);
        }

        if (reset.RequiresKeyCode != true || string.IsNullOrWhiteSpace(reset.KeyCodeHash))
        {
            _logger.LogWarning(
                "Password reset token verification found a reset artifact without a usable key-code proof.");
            return await RegisterFailedVerificationProof(command.ResetId, cancellationToken);
        }

        bool keyCodeValid = _codeHasher.VerifyCode(command.ResetId, command.KeyCode, reset.KeyCodeHash);
        if (!keyCodeValid)
        {
            return await RegisterFailedVerificationProof(command.ResetId, cancellationToken);
        }

        List<TwoFactorAuthConfiguration> availableConfigurations = ResolveAvailablePasswordResetConfigurations(reset);
        bool requiresTwoFactor = availableConfigurations.Count > 0;
        string resetAccessToken = CreateResetAccessToken(reset);
        if (await GetOrCreateResetAuthorization(reset, cancellationToken) is null)
            return VerifyFailure(SessionExpiredCode, StatusCodes.Status409Conflict);

        return new PasswordResetVerifyResult(
            requiresTwoFactor ? TwoFactorSelectionRequiredCode : TokenVerifiedCode,
            StatusCodes.Status200OK,
            requiresTwoFactor ? "two_factor_selection_required" : "verified",
            resetAccessToken,
            requiresTwoFactor,
            availableConfigurations,
            reset.ExpiresAt);
    }

    // Called only after verifying the bootstrap code at the public endpoint boundary.
    private async Task<PasswordResetSession?> GetOrCreateResetAuthorization(
        PasswordResetFinalizeRecord reset, CancellationToken cancellationToken)
    {
        if (reset.AccountId is not Guid accountId || reset.ExpiresAt is not Instant expiresAt)
            return null;
        string hash = AccessTokenHashUtility.Hash(CreateResetAccessToken(reset));
        var availableConfigurations = ResolveAvailablePasswordResetConfigurations(reset);
        if (_passwordResetSessionService is null)
            throw DependencyUnavailableException.Database("pending_reset_authorization", DependencyStage.Acquire);
        var session = await _passwordResetSessionService.GetSession(hash, cancellationToken);
        if (session is null)
        {
            Instant now = _clock.GetCurrentInstant();
            session = new PasswordResetSession(accountId, hash, BootstrapProofFromResetRecord(reset),
                availableConfigurations, now, expiresAt, passwordResetRequestId: reset.PasswordResetRequestId)
            { bootstrapCodeHash = reset.KeyCodeHash };
            if (await _passwordResetSessionService.TransitionSession(hash, session,
                RemainingResetSessionTtl(session, now), cancellationToken: cancellationToken) != true)
            {
                // Another bootstrap may have won. A revoked parent/session never has a readable winner.
                session = await _passwordResetSessionService.GetSession(hash, cancellationToken);
                if (session is null) return null;
            }
        }
        if (session.expiresAt <= _clock.GetCurrentInstant() || session.state is PasswordResetSessionState.Expired or PasswordResetSessionState.Failed or PasswordResetSessionState.PasswordChanged)
            return null;

        return session;
    }

    public async Task<PasswordResetTwoFactorSelectResult> SelectTwoFactorConfiguration(
        SelectPasswordResetTwoFactorConfigurationCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        string resetAccessToken = command.ResetAccessToken?.Trim() ?? string.Empty;
        if (command.Destination is not null and not 0)
            return SelectFailure(ValidationFailedCode, StatusCodes.Status400BadRequest);
        if (string.IsNullOrWhiteSpace(resetAccessToken) || command.Configuration is TwoFactorAuthConfiguration.NONE or TwoFactorAuthConfiguration.CUSTOM)
        {
            return SelectFailure(ValidationFailedCode, StatusCodes.Status400BadRequest);
        }

        if (!TryReadResetIdFromAccessToken(resetAccessToken, out Guid resetId))
        {
            return SelectFailure(InvalidProofCode, StatusCodes.Status401Unauthorized);
        }

        if (_publicGate is not null && !await _publicGate.AdmitProofAsync(command.RequestIpAddress, cancellationToken))
            return SelectFailure(InvalidProofCode, StatusCodes.Status401Unauthorized);

        PasswordResetFinalizeRecord? reset = await _passwordResetRepo.GetPasswordResetRequestForFinalizeAsync(
            resetId,
            cancellationToken);

        if (reset is null || reset.PasswordResetRequestId is null || reset.AccountId is null)
        {
            return SelectFailure(InvalidProofCode, StatusCodes.Status401Unauthorized);
        }

        if (reset.Result != true)
        {
            PasswordResetFinalizeResult lookup = StatusFromResetLookupCode(reset.Code);
            return SelectFailure(lookup.Code, lookup.StatusCode);
        }

        if (!ResetAccessTokenMatches(resetAccessToken, reset))
        {
            return SelectFailure(InvalidProofCode, StatusCodes.Status401Unauthorized);
        }

        List<TwoFactorAuthConfiguration> availableConfigurations = ResolveAvailablePasswordResetConfigurations(reset);
        if (!availableConfigurations.Contains(command.Configuration))
        {
            return SelectFailure(
                TwoFactorConfigurationNotAvailableCode,
                StatusCodes.Status400BadRequest,
                resetAccessToken: resetAccessToken,
                availableConfigurations: availableConfigurations,
                expiresAt: reset.ExpiresAt);
        }

        string resetAccessTokenHash = AccessTokenHashUtility.Hash(resetAccessToken);
        Instant now = _clock.GetCurrentInstant();
        Instant expiresAt = reset.ExpiresAt ?? now.Plus(Duration.FromMinutes(_settings.ExpirationMinutes));

        if (expiresAt <= now)
        {
            return SelectFailure(ExpiredCode, StatusCodes.Status409Conflict);
        }

        if (_passwordResetSessionService is null)
            throw DependencyUnavailableException.Database("pending_reset_authorization", DependencyStage.Acquire);
        var session = await _passwordResetSessionService.GetSession(resetAccessTokenHash, cancellationToken);
        if (session is null || session.passwordResetRequestId != resetId || session.accountId != reset.AccountId
            || session.expiresAt <= now || session.state is PasswordResetSessionState.Expired or PasswordResetSessionState.Failed or PasswordResetSessionState.PasswordChanged)
            return SelectFailure(SessionExpiredCode, StatusCodes.Status409Conflict);
        if (session.nextChallengeAllowedAt.HasValue && session.nextChallengeAllowedAt > now)
            return SelectFailure("PASSWORD_RESET_CHALLENGE_COOLDOWN", StatusCodes.Status409Conflict);
        if (session.challengeResends >= _settings.MaxAttempts)
            return SelectFailure("PASSWORD_RESET_MAX_ATTEMPTS", StatusCodes.Status409Conflict);

        try
        {
            session.SelectConfiguration(command.Configuration, now);
        }
        catch (ArgumentException)
        {
            return SelectFailure(
                TwoFactorConfigurationNotAvailableCode,
                StatusCodes.Status400BadRequest,
                resetAccessToken: resetAccessToken,
                availableConfigurations: availableConfigurations,
                expiresAt: expiresAt);
        }

        if (session.currentExpectedMethod is null || session.currentExpectedMethod.Value == TwoFactorAuthMethod.NONE)
        {
            return SelectFailure(TwoFactorSessionPersistenceFailedCode, StatusCodes.Status500InternalServerError);
        }

        string resultCode;
        PasswordResetDeliveryCommand? deliveryCommand = null;
        if (session.currentExpectedMethod.Value == TwoFactorAuthMethod.AUTHENTICATOR_APP)
        {
            resultCode = TwoFactorAuthenticatorCodeRequiredCode;
        }
        else
        {
            if(!TryBuildResetTwoFactorDeliveryCommand(reset,session.currentExpectedMethod.Value,string.Empty,expiresAt,out var destinationCommand))
                return SelectFailure(TwoFactorChallengeDeliveryUnsupportedCode,StatusCodes.Status501NotImplemented);
            if(!await _deliveryService.AdmitAsync(reset.AccountId.Value,destinationCommand!.DeliveryChannel,destinationCommand.DestinationAddressOrPhone,cancellationToken))
                return SelectFailure("PASSWORD_RESET_DELIVERY_PENDING",StatusCodes.Status202Accepted);
            if(await _deliveryService.ExistingAsync(reset.AccountId.Value,reset.AccountSecurityStampAtRequest!.Value,"reset-factor",cancellationToken) is not null)
                return SelectFailure("PASSWORD_RESET_DELIVERY_PENDING",StatusCodes.Status202Accepted);
            string challengeCode = _codeGenerator.GenerateKeyCode();
            Instant challengeExpiration = now.Plus(Duration.FromMinutes(_settings.ExpirationMinutes));
            if (challengeExpiration > session.expiresAt)
            {
                challengeExpiration = session.expiresAt;
            }

            session.StartChallenge(
                _codeHasher.HashCode(resetId, challengeCode),
                challengeExpiration,
                now.Plus(Duration.FromSeconds(_settings.RequestCooldownSeconds)));

            if (!TryBuildResetTwoFactorDeliveryCommand(reset, session.currentExpectedMethod.Value, challengeCode, challengeExpiration, out deliveryCommand))
            {
                return SelectFailure(
                    TwoFactorChallengeDeliveryUnsupportedCode,
                    StatusCodes.Status501NotImplemented,
                    resetAccessToken: resetAccessToken,
                    selectedConfiguration: session.selectedConfiguration,
                    currentRequiredMethod: session.currentExpectedMethod,
                    completedMethods: session.completedMethods,
                    remainingMethods: session.remainingMethods,
                    availableConfigurations: availableConfigurations,
                    expiresAt: expiresAt);
            }

            resultCode = TwoFactorChallengeSentCode;
        }

        if(deliveryCommand is not null)
        {
            var staged=await _deliveryService.StageFactorAsync(deliveryCommand,reset.AccountSecurityStampAtRequest!.Value,session,cancellationToken);
            return new(staged.Result?"PASSWORD_RESET_DELIVERY_PENDING":staged.Code,staged.Result?StatusCodes.Status202Accepted:StatusCodes.Status409Conflict,
                "challenge_pending",resetAccessToken,session.selectedConfiguration,session.currentExpectedMethod,session.challengeExpiration,
                session.completedMethods.ToList(),session.remainingMethods.ToList(),availableConfigurations,expiresAt,false);
        }
        if (_passwordResetSessionService is null)
        {
            return SelectFailure(TwoFactorSessionPersistenceFailedCode, StatusCodes.Status500InternalServerError);
        }

        bool? stored;
        try
        {
            stored = await _passwordResetSessionService.TransitionSession(resetAccessTokenHash, session, RemainingResetSessionTtl(session, now), cancellationToken: cancellationToken);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex) {
            _logger.LogWarning(ex, "Password reset 2FA session could not be persisted for account {AccountId}.", reset.AccountId.Value);
            return SelectFailure(TwoFactorSessionPersistenceFailedCode, StatusCodes.Status500InternalServerError);
        }

        if (stored != true)
        {
            _logger.LogWarning("Password reset 2FA session write failed for account {AccountId}.", reset.AccountId.Value);
            return SelectFailure(TwoFactorSessionPersistenceFailedCode, StatusCodes.Status500InternalServerError);
        }

        return new PasswordResetTwoFactorSelectResult(
            resultCode,
            StatusCodes.Status200OK,
            session.currentExpectedMethod.Value == TwoFactorAuthMethod.AUTHENTICATOR_APP ? "authenticator_code_required" : "challenge_sent",
            resetAccessToken,
            session.selectedConfiguration,
            session.currentExpectedMethod,
            session.challengeExpiration,
            session.completedMethods.ToList(),
            session.remainingMethods.ToList(),
            session.availableConfigurationsSnapshot.ToList(),
            session.expiresAt,
            session.canChangePassword);
    }


    public async Task<PasswordResetTwoFactorVerifyResult> VerifyTwoFactorProof(
        VerifyPasswordResetTwoFactorCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        string resetAccessToken = command.ResetAccessToken?.Trim() ?? string.Empty;
        string code = command.Code?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(resetAccessToken)
            || string.IsNullOrWhiteSpace(code)
            || command.Method == TwoFactorAuthMethod.NONE)
        {
            return VerifyTwoFactorFailure(ValidationFailedCode, StatusCodes.Status400BadRequest);
        }

        if (!TryReadResetIdFromAccessToken(resetAccessToken, out Guid resetId))
        {
            return VerifyTwoFactorFailure(InvalidProofCode, StatusCodes.Status401Unauthorized);
        }

        if (_publicGate is not null && !await _publicGate.AdmitProofAsync(command.RequestIpAddress, cancellationToken))
            return VerifyTwoFactorFailure(InvalidProofCode, StatusCodes.Status401Unauthorized);

        if(await _deliveryService.IsFactorPendingAsync(_codeHasher.HashCode(resetId,code),cancellationToken))
            return VerifyTwoFactorFailure("PASSWORD_RESET_DELIVERY_PENDING",StatusCodes.Status202Accepted);
        PasswordResetFinalizeResult? abuseDecision = await CheckPasswordResetTwoFactorProofAbusePolicy(resetId, cancellationToken);
        if (abuseDecision is not null)
        {
            return VerifyTwoFactorFailure(abuseDecision.Code, abuseDecision.StatusCode);
        }

        if (_passwordResetSessionService is null)
        {
            return VerifyTwoFactorFailure(TwoFactorSessionPersistenceFailedCode, StatusCodes.Status500InternalServerError);
        }

        PasswordResetFinalizeRecord? reset = await _passwordResetRepo.GetPasswordResetRequestForFinalizeAsync(
            resetId,
            cancellationToken);

        if (reset is null || reset.PasswordResetRequestId is null || reset.AccountId is null)
        {
            return VerifyTwoFactorFailure(InvalidProofCode, StatusCodes.Status401Unauthorized);
        }

        if (reset.Result != true)
        {
            PasswordResetFinalizeResult lookup = StatusFromResetLookupCode(reset.Code);
            return VerifyTwoFactorFailure(lookup.Code, lookup.StatusCode);
        }

        if (!ResetAccessTokenMatches(resetAccessToken, reset))
        {
            return VerifyTwoFactorFailure(InvalidProofCode, StatusCodes.Status401Unauthorized);
        }

        string resetAccessTokenHash = AccessTokenHashUtility.Hash(resetAccessToken);
        PasswordResetSession? session;
        try
        {
            session = await _passwordResetSessionService.GetSession(resetAccessTokenHash, cancellationToken: cancellationToken);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex)  when (ex is StalePendingTwoFactorCachePayloadException or ArgumentException)
        {
            _logger.LogWarning(ex, "Password reset 2FA session payload was not usable for reset {ResetId}.", resetId);
            await SafeRevokePasswordResetSession(resetAccessTokenHash);
            return VerifyTwoFactorFailure(SessionExpiredCode, StatusCodes.Status409Conflict);
        }

        if (session is null || !string.Equals(session.resetAccessTokenHash, resetAccessTokenHash, StringComparison.Ordinal))
        {
            return VerifyTwoFactorFailure(SessionExpiredCode, StatusCodes.Status409Conflict);
        }

        Instant now = _clock.GetCurrentInstant();
        if (session.expiresAt <= now || session.state is PasswordResetSessionState.Expired or PasswordResetSessionState.Failed)
        {
            session.MarkExpired();
            await SafeRevokePasswordResetSession(resetAccessTokenHash);
            return VerifyTwoFactorFailure(SessionExpiredCode, StatusCodes.Status409Conflict);
        }

        if (!session.IsCurrentlyExpecting(command.Method))
        {
            return VerifyTwoFactorFailure(
                TwoFactorMethodNotCurrentlyRequiredCode,
                StatusCodes.Status400BadRequest,
                resetAccessToken,
                session);
        }

        bool verified;
        if (command.Method == TwoFactorAuthMethod.AUTHENTICATOR_APP)
        {
            PasswordResetTotpVerificationResult totpResult = await _totpVerifier.VerifyTotpForPasswordReset(
                session.accountId,
                code,
                cancellationToken);
            if (totpResult.Status == ProofVerificationStatus.DependencyUnavailable)
                return VerifyTwoFactorFailure(totpResult.Code, StatusCodes.Status503ServiceUnavailable, resetAccessToken, session);
            verified = totpResult.Verified;

            if (!verified)
            {
                _logger.LogInformation(
                    "Password reset 2FA authenticator proof failed for account {AccountId}; result code {ResultCode}.",
                    session.accountId,
                    totpResult.Code);
            }
        }
        else
        {
            if (session.challengeExpiration is null || session.challengeExpiration.Value <= now || string.IsNullOrWhiteSpace(session.challengeCodeHash))
            {
                session.RegisterFailedChallengeAttempt();
                await PersistPasswordResetSessionOrRevoke(resetAccessTokenHash, session, now, cancellationToken: cancellationToken);
                return VerifyTwoFactorFailure(
                    SessionExpiredCode,
                    StatusCodes.Status409Conflict,
                    resetAccessToken,
                    session);
            }

            verified = _codeHasher.VerifyCode(resetId, code, session.challengeCodeHash);
        }

        if (!verified)
        {
            session.RegisterFailedChallengeAttempt();
            if (!await PersistPasswordResetSessionOrRevoke(resetAccessTokenHash, session, now, cancellationToken: cancellationToken))
                return VerifyTwoFactorFailure("PASSWORD_RESET_SESSION_STALE", StatusCodes.Status409Conflict);
            return VerifyTwoFactorFailure(
                TwoFactorChallengeInvalidCode,
                StatusCodes.Status401Unauthorized,
                resetAccessToken,
                session);
        }

        session.MarkCurrentProofAccepted();
        if (session.remainingMethods.Count == 0)
        {
            session.MarkTwoFactorComplete(now);
        }

        bool persisted = await PersistPasswordResetSessionOrRevoke(resetAccessTokenHash, session, now, cancellationToken: cancellationToken);
        if (!persisted)
        {
            return VerifyTwoFactorFailure(TwoFactorSessionPersistenceFailedCode, StatusCodes.Status500InternalServerError);
        }

        bool complete = session.isTwoFactorComplete;
        return new PasswordResetTwoFactorVerifyResult(
            complete ? TwoFactorCompleteCode : TwoFactorProofAcceptedNextProofRequiredCode,
            StatusCodes.Status200OK,
            complete ? "two_factor_complete" : "next_proof_required",
            resetAccessToken,
            session.selectedConfiguration,
            session.currentExpectedMethod,
            session.completedMethods.ToList(),
            session.remainingMethods.ToList(),
            session.expiresAt,
            session.canChangePassword);
    }

    public async Task<PasswordResetFinalizeResult> FinalizeReset(
        FinalizePasswordResetCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (string.IsNullOrWhiteSpace(command.Password)
            || string.IsNullOrWhiteSpace(command.VerifyPassword)
            || !string.Equals(command.Password, command.VerifyPassword, StringComparison.Ordinal))
        {
            return new PasswordResetFinalizeResult(ValidationFailedCode, StatusCodes.Status400BadRequest);
        }

        if (!PasswordMeetsConfiguredPolicy(command.Password))
        {
            return new PasswordResetFinalizeResult(ValidationFailedCode, StatusCodes.Status400BadRequest);
        }

        string resetAccessToken = command.ResetAccessToken?.Trim() ?? string.Empty;
        bool hasResetAccessToken = !string.IsNullOrWhiteSpace(resetAccessToken);
        Guid resetId = command.ResetId;

        if (hasResetAccessToken)
        {
            if (!TryReadResetIdFromAccessToken(resetAccessToken, out resetId))
            {
                return new PasswordResetFinalizeResult(InvalidProofCode, StatusCodes.Status401Unauthorized);
            }
        }
        else if (resetId == Guid.Empty)
        {
            return new PasswordResetFinalizeResult(ValidationFailedCode, StatusCodes.Status400BadRequest);
        }

        if (_publicGate is not null && !await _publicGate.AdmitProofAsync(command.RequestIpAddress, cancellationToken))
            return new(InvalidProofCode, StatusCodes.Status401Unauthorized);

        if(!hasResetAccessToken && !string.IsNullOrWhiteSpace(command.KeyCode) && await _deliveryService.IsPendingAsync(_codeHasher.HashCode(resetId,command.KeyCode),cancellationToken))
            return new("PASSWORD_RESET_DELIVERY_PENDING",StatusCodes.Status202Accepted);
        PasswordResetFinalizeResult? abuseDecision = await CheckPasswordResetFinalizeAbusePolicy(resetId, cancellationToken);
        if (abuseDecision is not null)
        {
            return abuseDecision;
        }

        PasswordResetFinalizeRecord? reset = await _passwordResetRepo.GetPasswordResetRequestForFinalizeAsync(
            resetId,
            cancellationToken);

        if (reset is null || reset.PasswordResetRequestId is null || reset.AccountId is null)
        {
            return new PasswordResetFinalizeResult(InvalidProofCode, StatusCodes.Status401Unauthorized);
        }

        if (reset.Result != true)
        {
            return StatusFromResetLookupCode(reset.Code);
        }

        if (hasResetAccessToken)
        {
            if (!ResetAccessTokenMatches(resetAccessToken, reset))
            {
                return new PasswordResetFinalizeResult(InvalidProofCode, StatusCodes.Status401Unauthorized);
            }

            PasswordResetFinalizeResult? gateDecision = await GatePasswordChangeOnResetSessionCompletion(
                resetAccessToken,
                reset,
                cancellationToken);
            if (gateDecision is not null)
            {
                return gateDecision;
            }

            var tokenAuthorization = await _passwordResetSessionService!.GetSession(AccessTokenHashUtility.Hash(resetAccessToken), cancellationToken);
            if (tokenAuthorization is null || !tokenAuthorization.canChangePassword)
                return new PasswordResetFinalizeResult(TwoFactorNotCompleteCode, StatusCodes.Status409Conflict);
            PasswordResetFinalizeResult promoted = await PromotePasswordReset(reset, command.Password, resetId, tokenAuthorization, cancellationToken);
            if (promoted.Code == CompletedCode)
            {
                await SafeRevokePasswordResetSession(AccessTokenHashUtility.Hash(resetAccessToken));
            }

            return promoted;
        }

        if (reset.RequiresTotp == true && reset.RequiresKeyCode != true)
        {
            _logger.LogWarning(
                "Password reset finalize found a reset requiring TOTP without a delivery key-code proof; rejecting the reset artifact.");
            return await RegisterFailedProof(resetId, cancellationToken);
        }

        if (reset.RequiresKeyCode == true)
        {
            if (string.IsNullOrWhiteSpace(command.KeyCode))
            {
                return new PasswordResetFinalizeResult(ValidationFailedCode, StatusCodes.Status400BadRequest);
            }

            if (string.IsNullOrWhiteSpace(reset.KeyCodeHash))
            {
                _logger.LogWarning(
                    "Password reset finalize found a reset requiring a key code but without a stored key-code hash.");
                return await RegisterFailedProof(resetId, cancellationToken);
            }

            bool keyCodeValid = _codeHasher.VerifyCode(resetId, command.KeyCode, reset.KeyCodeHash);
            if (!keyCodeValid)
            {
                return await RegisterFailedProof(resetId, cancellationToken);
            }
        }

        List<TwoFactorAuthConfiguration> availableConfigurations = ResolveAvailablePasswordResetConfigurations(reset);
        if (availableConfigurations.Count > 0)
        {
            return new PasswordResetFinalizeResult(TwoFactorRequiredCode, StatusCodes.Status409Conflict);
        }

        if (reset.RequiresTotp == true)
        {
            if (string.IsNullOrWhiteSpace(command.TotpCode))
            {
                return new PasswordResetFinalizeResult(ValidationFailedCode, StatusCodes.Status400BadRequest);
            }

            PasswordResetTotpVerificationResult totpResult = await _totpVerifier.VerifyTotpForPasswordReset(
                reset.AccountId.Value,
                command.TotpCode,
                cancellationToken);

            if (totpResult.Status == ProofVerificationStatus.DependencyUnavailable)
                return new PasswordResetFinalizeResult(totpResult.Code, StatusCodes.Status503ServiceUnavailable);
            if (!totpResult.Verified)
            {
                _logger.LogInformation(
                    "Password reset TOTP proof failed for account {AccountId}; result code {ResultCode}.",
                    reset.AccountId.Value,
                    totpResult.Code);
                return await RegisterFailedProof(resetId, cancellationToken);
            }
        }

        var authorization = await GetOrCreateResetAuthorization(reset, cancellationToken);
        if (authorization is null || !authorization.canChangePassword)
            return new PasswordResetFinalizeResult(TwoFactorNotCompleteCode, StatusCodes.Status409Conflict);
        return await PromotePasswordReset(reset, command.Password, resetId, authorization, cancellationToken);
    }

    private async Task<PasswordResetFinalizeResult?> GatePasswordChangeOnResetSessionCompletion(
        string resetAccessToken,
        PasswordResetFinalizeRecord reset,
        CancellationToken cancellationToken)
    {
        List<TwoFactorAuthConfiguration> availableConfigurations = ResolveAvailablePasswordResetConfigurations(reset);
        if (_passwordResetSessionService is null)
        {
            _logger.LogWarning(
                "Password reset finalize requires reset 2FA completion for account {AccountId}, but the reset session service is unavailable.",
                reset.AccountId);
            return new PasswordResetFinalizeResult(TwoFactorNotCompleteCode, StatusCodes.Status409Conflict);
        }

        string resetAccessTokenHash = AccessTokenHashUtility.Hash(resetAccessToken);
        PasswordResetSession? session;
        try
        {
            session = await _passwordResetSessionService.GetSession(resetAccessTokenHash, cancellationToken: cancellationToken);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex)  when (ex is StalePendingTwoFactorCachePayloadException or ArgumentException)
        {
            _logger.LogWarning(ex, "Password reset finalize found an unusable reset 2FA session payload.");
            await SafeRevokePasswordResetSession(resetAccessTokenHash);
            return new PasswordResetFinalizeResult(SessionExpiredCode, StatusCodes.Status409Conflict);
        }

        if (session is null)
        {
            return new PasswordResetFinalizeResult(TwoFactorNotCompleteCode, StatusCodes.Status409Conflict);
        }

        if (!string.Equals(session.resetAccessTokenHash, resetAccessTokenHash, StringComparison.Ordinal)
            || session.accountId != reset.AccountId)
        {
            _logger.LogWarning(
                "Password reset finalize rejected a reset 2FA session whose token hash or account did not match the reset artifact.");
            return new PasswordResetFinalizeResult(InvalidProofCode, StatusCodes.Status401Unauthorized);
        }

        Instant now = _clock.GetCurrentInstant();
        if (session.expiresAt <= now || session.state is PasswordResetSessionState.Expired or PasswordResetSessionState.Failed)
        {
            session.MarkExpired();
            await SafeRevokePasswordResetSession(resetAccessTokenHash);
            return new PasswordResetFinalizeResult(SessionExpiredCode, StatusCodes.Status409Conflict);
        }

        if (session.selectedConfiguration.HasValue
            && !availableConfigurations.Contains(session.selectedConfiguration.Value))
        {
            _logger.LogInformation(
                "Password reset finalize rejected stale reset 2FA configuration {Configuration} for account {AccountId}.",
                session.selectedConfiguration.Value,
                reset.AccountId);
            await SafeRevokePasswordResetSession(resetAccessTokenHash);
            return new PasswordResetFinalizeResult(TwoFactorNotCompleteCode, StatusCodes.Status409Conflict);
        }

        if (!session.canChangePassword)
        {
            return new PasswordResetFinalizeResult(TwoFactorNotCompleteCode, StatusCodes.Status409Conflict);
        }

        return null;
    }

    private async Task<PasswordResetFinalizeResult> PromotePasswordReset(
        PasswordResetFinalizeRecord reset,
        string password,
        Guid resetId,
        PasswordResetSession authorization,
        CancellationToken cancellationToken)
    {
        if (reset.PasswordResetRequestId is null || reset.AccountId is null)
        {
            return new PasswordResetFinalizeResult(InvalidProofCode, StatusCodes.Status401Unauthorized);
        }

        PasswordResetPasswordMaterial passwordMaterial;
        try
        {
            passwordMaterial = await _passwordMaterialFactory.CreatePasswordMaterialAsync(password, cancellationToken);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex)  when (ex is ArgumentException or InvalidOperationException)
        {
            _logger.LogWarning(ex, "Password reset could not create password material.");
            return new PasswordResetFinalizeResult(ValidationFailedCode, StatusCodes.Status400BadRequest);
        }

        Instant promotedAt = _clock.GetCurrentInstant();
        Guid newSecurityStamp = Guid.NewGuid();

        PromotePasswordResetResult? promoted = await _passwordResetRepo.PromotePasswordResetAsync(
            new PromotePasswordResetDbCommand(
                reset.PasswordResetRequestId.Value,
                reset.AccountId.Value,
                passwordMaterial.HashedPassword,
                passwordMaterial.SaltOne,
                passwordMaterial.Siv,
                passwordMaterial.Nonce,
                newSecurityStamp,
                promotedAt,
                authorization.resetAccessTokenHash,
                authorization.sessionVersion,
                authorization.challengeVersion),
            cancellationToken);

        if (promoted?.Result == true && promoted.Code == CompletedCode)
        {
            await ResetPasswordResetResetScopedAbusePolicies(resetId, cancellationToken);
            return new PasswordResetFinalizeResult(CompletedCode, StatusCodes.Status200OK);
        }

        _logger.LogWarning(
            "Password reset promotion failed for account {AccountId}; result code {PromotionCode}.",
            reset.AccountId.Value,
            promoted?.Code ?? "<null>");

        return StatusFromPromotionCode(promoted?.Code);
    }

    private async Task<PasswordResetVerifyResult> RegisterFailedVerificationProof(
        Guid resetId,
        CancellationToken cancellationToken)
    {
        PasswordResetFinalizeResult failed = await RegisterFailedProof(resetId, cancellationToken);
        return VerifyFailure(failed.Code, failed.StatusCode);
    }

    private static PasswordResetTwoFactorSelectResult SelectFailure(
        string code,
        int statusCode,
        string? resetAccessToken = null,
        TwoFactorAuthConfiguration? selectedConfiguration = null,
        TwoFactorAuthMethod? currentRequiredMethod = null,
        Instant? challengeExpiration = null,
        List<TwoFactorAuthMethod>? completedMethods = null,
        List<TwoFactorAuthMethod>? remainingMethods = null,
        List<TwoFactorAuthConfiguration>? availableConfigurations = null,
        Instant? expiresAt = null)
    {
        return new PasswordResetTwoFactorSelectResult(
            code,
            statusCode,
            "failed",
            resetAccessToken,
            selectedConfiguration,
            currentRequiredMethod,
            challengeExpiration,
            completedMethods ?? [],
            remainingMethods ?? [],
            availableConfigurations ?? [],
            expiresAt,
            false);
    }


    private static PasswordResetTwoFactorVerifyResult VerifyTwoFactorFailure(
        string code,
        int statusCode,
        string? resetAccessToken = null,
        PasswordResetSession? session = null)
    {
        return new PasswordResetTwoFactorVerifyResult(
            code,
            statusCode,
            "failed",
            resetAccessToken,
            session?.selectedConfiguration,
            session?.currentExpectedMethod,
            session?.completedMethods.ToList() ?? [],
            session?.remainingMethods.ToList() ?? [],
            session?.expiresAt,
            session?.canChangePassword ?? false);
    }

    private async Task<bool> PersistPasswordResetSessionOrRevoke(
        string resetAccessTokenHash, PasswordResetSession session, Instant now, CancellationToken cancellationToken = default)
    {
        if (_passwordResetSessionService is null)
            throw DependencyUnavailableException.Database("pending_reset_session_store", DependencyStage.Acquire);
        bool? stored = await _passwordResetSessionService.TransitionSession(resetAccessTokenHash, session,
            RemainingResetSessionTtl(session, now), cancellationToken: cancellationToken);
        if (stored is null) throw DependencyUnavailableException.InvalidResponse("transition_pending_reset_session");
        return stored == true;
    }

    private async Task<bool> SafeRevokePasswordResetSession(string resetAccessTokenHash)
    {
        if (_passwordResetSessionService is null)
        {
            return false;
        }

        try
        {
            return await _passwordResetSessionService.RevokeSession(resetAccessTokenHash);
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex) {
            _logger.LogWarning(ex, "Password reset 2FA session could not be revoked.");
            return false;
        }
    }

    private static bool TryReadResetIdFromAccessToken(string resetAccessToken, out Guid resetId)
    {
        resetId = Guid.Empty;

        string[] parts = resetAccessToken.Split('.', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || parts[0].Length != 32 || parts[1].Length < 32)
        {
            return false;
        }

        return Guid.TryParseExact(parts[0], "N", out resetId);
    }

    private bool ResetAccessTokenMatches(string suppliedResetAccessToken, PasswordResetFinalizeRecord reset)
    {
        string expectedResetAccessToken;
        try
        {
            expectedResetAccessToken = CreateResetAccessToken(reset);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning("Password reset access-token validation could not recreate expected material.");
            throw new DependencyUnavailableException(new("reset_secret", "recreate_reset_access_token",
                DependencyFailureKind.Unavailable, DependencyStage.Execute), ex);
        }

        byte[] supplied = Encoding.UTF8.GetBytes(suppliedResetAccessToken);
        byte[] expected = Encoding.UTF8.GetBytes(expectedResetAccessToken);
        return supplied.Length == expected.Length && CryptographicOperations.FixedTimeEquals(supplied, expected);
    }

    private static TimeSpan RemainingResetSessionTtl(PasswordResetSession session, Instant moment)
    {
        Duration remaining = session.expiresAt - moment;
        if (remaining <= Duration.Zero)
        {
            return TimeSpan.FromSeconds(1);
        }

        return remaining.ToTimeSpan();
    }

    private string CreateResetAccessToken(PasswordResetFinalizeRecord reset)
    {
        if (reset.PasswordResetRequestId is null || reset.AccountId is null || reset.KeyCodeHash is null || reset.AccountSecurityStampAtRequest is null)
        {
            throw new InvalidOperationException("Password reset access tokens require reset id, account id, key-code hash, and account security stamp material.");
        }

        string pepper = _settings.CodeHashPepper;
        if (string.IsNullOrWhiteSpace(pepper))
        {
            throw new InvalidOperationException("PasswordResetSettings:CodeHashPepper is required before reset access tokens can be created.");
        }

        string material = string.Join(
            ':',
            "pwdreset",
            "access",
            "v1",
            reset.PasswordResetRequestId.Value.ToString("N"),
            reset.AccountId.Value.ToString("N"),
            reset.KeyCodeHash,
            reset.AccountSecurityStampAtRequest.Value.ToString("N"));

        byte[] key = Encoding.UTF8.GetBytes(pepper);
        byte[] message = Encoding.UTF8.GetBytes(material);
        byte[] digest = HMACSHA256.HashData(key, message);
        string signature = Convert.ToHexString(digest).ToLowerInvariant();

        return $"{reset.PasswordResetRequestId.Value:N}.{signature}";
    }


    private static bool TryBuildResetTwoFactorDeliveryCommand(
        PasswordResetFinalizeRecord reset,
        TwoFactorAuthMethod method,
        string challengeCode,
        Instant challengeExpiration,
        out PasswordResetDeliveryCommand? deliveryCommand)
    {
        deliveryCommand = null;
        if (reset.PasswordResetRequestId is null || reset.AccountId is null)
        {
            return false;
        }

        string channel;
        string destination;
        string masked;
        string resetMethod;
        switch (method)
        {
            case TwoFactorAuthMethod.EMAIL when reset.EmailVerified == true && !string.IsNullOrWhiteSpace(reset.CurrentEmailAddress):
                channel = "email";
                destination = reset.CurrentEmailAddress.Trim();
                masked = MaskEmail(destination);
                resetMethod = PasswordResetDeliveryChannels.Email;
                break;
            case TwoFactorAuthMethod.SMS_KEY when reset.SmsVerified == true && !string.IsNullOrWhiteSpace(reset.CurrentPhoneNumber):
                channel = "sms";
                destination = NormalizePhoneDestination(reset.CurrentPhoneCountryCode, reset.CurrentPhoneNumber);
                masked = MaskPhone(destination);
                resetMethod = PasswordResetDeliveryChannels.Sms;
                break;
            default:
                return false;
        }

        deliveryCommand = new PasswordResetDeliveryCommand(
            reset.PasswordResetRequestId.Value,
            reset.AccountId.Value,
            resetMethod,
            channel,
            masked,
            destination,
            challengeCode,
            challengeExpiration);
        return true;
    }

    private static List<TwoFactorAuthConfiguration> ResolveAvailablePasswordResetConfigurations(
        PasswordResetFinalizeRecord reset)
    {
        if (reset.EmailVerified.HasValue || reset.SmsVerified.HasValue || reset.AuthenticatorVerified.HasValue)
        {
            return PasswordResetTwoFactorConfigurationResolver.AvailableFromAccountSnapshot(
                reset.EmailVerified == true,
                reset.SmsVerified == true,
                reset.AuthenticatorVerified == true,
                BootstrapProofFromResetRecord(reset));
        }

        if (reset.RequiresTotp != true)
        {
            return [];
        }

        return PasswordResetTwoFactorConfigurationResolver.AvailableFromMethods(
            VerifiedMethodsFromResetRecord(reset),
            BootstrapProofFromResetRecord(reset));
    }

    private static List<TwoFactorAuthMethod> VerifiedMethodsFromResetRecord(PasswordResetFinalizeRecord reset)
    {
        var methods = new List<TwoFactorAuthMethod>();
        string deliveryChannel = PasswordResetDeliveryChannels.Normalize(reset.DeliveryChannel ?? reset.Method);

        if (string.Equals(deliveryChannel, PasswordResetDeliveryChannels.Email, StringComparison.Ordinal))
        {
            methods.Add(TwoFactorAuthMethod.EMAIL);
        }

        if (string.Equals(deliveryChannel, PasswordResetDeliveryChannels.Sms, StringComparison.Ordinal))
        {
            methods.Add(TwoFactorAuthMethod.SMS_KEY);
        }

        if (reset.RequiresTotp == true)
        {
            methods.Add(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        }

        return methods;
    }

    private static PasswordResetBootstrapProof BootstrapProofFromResetRecord(PasswordResetFinalizeRecord reset)
    {
        string deliveryChannel = PasswordResetDeliveryChannels.Normalize(reset.DeliveryChannel ?? reset.Method);
        if (string.Equals(deliveryChannel, PasswordResetDeliveryChannels.Email, StringComparison.Ordinal))
        {
            return PasswordResetBootstrapProof.EmailResetToken;
        }

        if (string.Equals(deliveryChannel, PasswordResetDeliveryChannels.Sms, StringComparison.Ordinal))
        {
            return PasswordResetBootstrapProof.SmsResetToken;
        }

        return PasswordResetBootstrapProof.None;
    }

    private static PasswordResetVerifyResult VerifyFailure(string code, int statusCode)
    {
        return new PasswordResetVerifyResult(
            code,
            statusCode,
            "failed",
            null,
            false,
            [],
            null);
    }

    private static PasswordResetVerifyResult VerifyFailureFromResetLookupCode(string code)
    {
        PasswordResetFinalizeResult finalizeResult = StatusFromResetLookupCode(code);
        return VerifyFailure(finalizeResult.Code, finalizeResult.StatusCode);
    }

    private bool PasswordResetAbuseControlsEnabled =>
        _abuseControlSettings.Enabled && _abuseControlSettings.PasswordReset.Enabled;

    private async Task<bool> CheckPasswordResetRequestAbusePolicy(
        string identifier,
        string? ipAddress,
        CancellationToken cancellationToken)
    {
        if (!PasswordResetAbuseControlsEnabled)
        {
            return true;
        }

        PasswordResetAbusePolicySettings settings = _abuseControlSettings.PasswordReset;
        AbuseCounterLimit ipLimit = BuildPasswordResetRequestLimit(settings.MaxRequestsPerIpPerHour);
        CounterDecision ipDecision = await _abuseCounterStore.IncrementAsync(
            _abuseCounterKeyFactory.ForRequestIpAddress(ipAddress),
            ipLimit,
            cancellationToken);

        if (!ipDecision.CanAdmit)
        {
            AbuseOperationalTelemetry.RecordPasswordResetThrottled(
                AbuseFeature.PasswordResetRequest,
                AbuseCounterDimension.IpFingerprint,
                ipDecision.ReasonCode ?? AbuseReasonCodes.PasswordResetRequestThrottleExceeded);
            LogSuppressedPasswordResetRequest("ip", ipDecision);
            return false;
        }

        AbuseCounterLimit identifierLimit = BuildPasswordResetRequestLimit(settings.MaxRequestsPerIdentifierPerHour);
        CounterDecision identifierDecision = await _abuseCounterStore.IncrementAsync(
            _abuseCounterKeyFactory.ForRequestIdentifier(identifier),
            identifierLimit,
            cancellationToken);

        if (!identifierDecision.CanAdmit)
        {
            AbuseOperationalTelemetry.RecordPasswordResetThrottled(
                AbuseFeature.PasswordResetRequest,
                AbuseCounterDimension.IdentifierFingerprint,
                identifierDecision.ReasonCode ?? AbuseReasonCodes.PasswordResetRequestThrottleExceeded);
            LogSuppressedPasswordResetRequest("identifier", identifierDecision);
            return false;
        }

        return true;
    }

    private async Task<bool> CheckPasswordResetRequestAccountPolicy(
        Guid accountId,
        CancellationToken cancellationToken)
    {
        if (!PasswordResetAbuseControlsEnabled)
        {
            return true;
        }

        PasswordResetAbusePolicySettings settings = _abuseControlSettings.PasswordReset;
        CounterDecision decision = await _abuseCounterStore.IncrementAsync(
            _abuseCounterKeyFactory.ForRequestAccount(accountId),
            BuildPasswordResetRequestLimit(settings.MaxRequestsPerAccountPerHour),
            cancellationToken);

        if (decision.CanAdmit)
        {
            return true;
        }

        AbuseOperationalTelemetry.RecordPasswordResetThrottled(
            AbuseFeature.PasswordResetRequest,
            AbuseCounterDimension.Account,
            decision.ReasonCode ?? AbuseReasonCodes.PasswordResetRequestThrottleExceeded);
        LogSuppressedPasswordResetRequest("account", decision);
        return false;
    }

    private Task<PasswordResetFinalizeResult?> CheckPasswordResetTokenVerificationAbusePolicy(
        Guid resetId,
        CancellationToken cancellationToken)
    {
        if (!PasswordResetAbuseControlsEnabled)
        {
            return Task.FromResult<PasswordResetFinalizeResult?>(null);
        }

        PasswordResetAbusePolicySettings settings = _abuseControlSettings.PasswordReset;
        return CheckPasswordResetResetScopedAbusePolicy(
            resetId,
            _abuseCounterKeyFactory.ForTokenVerificationReset(resetId),
            AbuseFeature.PasswordResetTokenVerification,
            BuildPasswordResetResetScopedLimit(
                settings.MaxTokenVerificationAttemptsPerResetId,
                settings.TokenVerificationAttemptWindowSeconds),
            AbuseReasonCodes.PasswordResetTokenVerificationThrottleExceeded,
            "token verification",
            cancellationToken);
    }

    private Task<PasswordResetFinalizeResult?> CheckPasswordResetTwoFactorProofAbusePolicy(
        Guid resetId,
        CancellationToken cancellationToken)
    {
        if (!PasswordResetAbuseControlsEnabled)
        {
            return Task.FromResult<PasswordResetFinalizeResult?>(null);
        }

        PasswordResetAbusePolicySettings settings = _abuseControlSettings.PasswordReset;
        return CheckPasswordResetResetScopedAbusePolicy(
            resetId,
            _abuseCounterKeyFactory.ForTwoFactorProofReset(resetId),
            AbuseFeature.PasswordResetTwoFactorProof,
            BuildPasswordResetResetScopedLimit(
                settings.MaxTwoFactorProofAttemptsPerResetId,
                settings.TwoFactorProofAttemptWindowSeconds),
            AbuseReasonCodes.PasswordResetTwoFactorProofThrottleExceeded,
            "2FA proof",
            cancellationToken);
    }

    private Task<PasswordResetFinalizeResult?> CheckPasswordResetFinalizeAbusePolicy(
        Guid resetId,
        CancellationToken cancellationToken)
    {
        if (!PasswordResetAbuseControlsEnabled)
        {
            return Task.FromResult<PasswordResetFinalizeResult?>(null);
        }

        PasswordResetAbusePolicySettings settings = _abuseControlSettings.PasswordReset;
        return CheckPasswordResetResetScopedAbusePolicy(
            resetId,
            _abuseCounterKeyFactory.ForFinalizeReset(resetId),
            AbuseFeature.PasswordResetFinalize,
            BuildPasswordResetResetScopedLimit(
                settings.MaxFinalizeAttemptsPerResetId,
                settings.FinalizeAttemptWindowSeconds),
            AbuseReasonCodes.PasswordResetFinalizeThrottleExceeded,
            "finalize",
            cancellationToken);
    }

    private async Task<PasswordResetFinalizeResult?> CheckPasswordResetResetScopedAbusePolicy(
        Guid resetId,
        AbuseCounterKey key,
        AbuseFeature feature,
        AbuseCounterLimit limit,
        string throttleReasonCode,
        string stageName,
        CancellationToken cancellationToken)
    {
        if (!PasswordResetAbuseControlsEnabled)
        {
            return null;
        }

        CounterDecision decision = await _abuseCounterStore.IncrementAsync(
            key,
            limit,
            cancellationToken);

        if (decision.CanAdmit)
        {
            return null;
        }

        AbuseOperationalTelemetry.RecordPasswordResetThrottled(
            feature,
            AbuseCounterDimension.Reset,
            decision.ReasonCode ?? throttleReasonCode);

        if (IsCounterStoreUnavailable(decision.ReasonCode))
        {
            _logger.LogWarning(
                "Password reset {StageName} abuse counter store was unavailable for reset fingerprint; failing closed with reason {ReasonCode}.",
                stageName,
                decision.ReasonCode);
            return new PasswordResetFinalizeResult(AbuseCounterUnavailableCode, StatusCodes.Status503ServiceUnavailable);
        }

        _logger.LogInformation(
            "Password reset {StageName} was throttled by reset scope; reason {ReasonCode}, retry after {RetryAfterSeconds} seconds.",
            stageName,
            decision.ReasonCode ?? throttleReasonCode,
            decision.RetryAfter.HasValue ? Math.Ceiling(decision.RetryAfter.Value.TotalSeconds).ToString(CultureInfo.InvariantCulture) : "unknown");
        return new PasswordResetFinalizeResult(InvalidProofCode, StatusCodes.Status401Unauthorized);
    }

    private async Task ResetPasswordResetResetScopedAbusePolicies(
        Guid resetId,
        CancellationToken cancellationToken)
    {
        if (!PasswordResetAbuseControlsEnabled)
        {
            return;
        }

        await Task.CompletedTask; // Shared bounded buckets retain their fixed windows after success.
    }

    private AbuseCounterLimit BuildPasswordResetRequestLimit(int maxAttempts)
    {
        PasswordResetAbusePolicySettings settings = _abuseControlSettings.PasswordReset;
        return new AbuseCounterLimit(
            maxAttempts,
            TimeSpan.FromHours(1),
            TimeSpan.FromSeconds(settings.CooldownSecondsAfterExhaustion));
    }

    private AbuseCounterLimit BuildPasswordResetResetScopedLimit(int maxAttempts, int windowSeconds)
    {
        PasswordResetAbusePolicySettings settings = _abuseControlSettings.PasswordReset;
        return new AbuseCounterLimit(
            maxAttempts,
            TimeSpan.FromSeconds(windowSeconds),
            TimeSpan.FromSeconds(settings.CooldownSecondsAfterExhaustion));
    }

    private void LogSuppressedPasswordResetRequest(string scope, CounterDecision decision)
    {
        if (IsCounterStoreUnavailable(decision.ReasonCode))
        {
            _logger.LogWarning(
                "Password reset request was suppressed because the abuse counter store was unavailable for {Scope} scope; reason {ReasonCode}.",
                scope,
                decision.ReasonCode);
            return;
        }

        _logger.LogInformation(
            "Password reset request was throttled by {Scope} scope; reason {ReasonCode}, retry after {RetryAfterSeconds} seconds.",
            scope,
            decision.ReasonCode ?? AbuseReasonCodes.PasswordResetRequestThrottleExceeded,
            decision.RetryAfter.HasValue ? Math.Ceiling(decision.RetryAfter.Value.TotalSeconds).ToString(CultureInfo.InvariantCulture) : "unknown");
    }

    private static bool IsCounterStoreUnavailable(string? reasonCode)
    {
        return reasonCode == AbuseReasonCodes.CounterStoreUnavailable
            || reasonCode == AbuseReasonCodes.CounterStoreTimeout;
    }

    private async Task<PasswordResetFinalizeResult> RegisterFailedProof(
        Guid resetId,
        CancellationToken cancellationToken)
    {
        RegisterPasswordResetFailedAttemptResult? result = await _passwordResetRepo.RegisterFailedAttemptAsync(
            resetId,
            _clock.GetCurrentInstant(),
            cancellationToken);

        return new PasswordResetFinalizeResult(InvalidProofCode, StatusCodes.Status401Unauthorized);
    }

    private bool PasswordMeetsConfiguredPolicy(string password)
    {
        uint length = (uint)password.Length;
        return length >= _registrationSettings.MinPasswordLength
            && length <= _registrationSettings.MaxPasswordLength;
    }

    private static PasswordResetFinalizeResult StatusFromPromotionCode(string? code)
    {
        return code switch
        {
            "PASSWORD_RESET_AUTHORIZATION_INVALID" => new PasswordResetFinalizeResult("PASSWORD_RESET_AUTHORIZATION_INVALID", StatusCodes.Status409Conflict),
            CompletedCode => new PasswordResetFinalizeResult(CompletedCode, StatusCodes.Status200OK),
            ExpiredCode => new PasswordResetFinalizeResult(ExpiredCode, StatusCodes.Status409Conflict),
            ConsumedCode => new PasswordResetFinalizeResult(ConsumedCode, StatusCodes.Status409Conflict),
            CancelledCode => new PasswordResetFinalizeResult(CancelledCode, StatusCodes.Status409Conflict),
            AccountStaleCode => new PasswordResetFinalizeResult(AccountStaleCode, StatusCodes.Status409Conflict),
            AccountMismatchCode => new PasswordResetFinalizeResult(AccountMismatchCode, StatusCodes.Status409Conflict),
            AccountNotFoundCode => new PasswordResetFinalizeResult(AccountNotFoundCode, StatusCodes.Status409Conflict),
            AttemptsExceededCode => new PasswordResetFinalizeResult(AttemptsExceededCode, StatusCodes.Status429TooManyRequests),
            _ => new PasswordResetFinalizeResult(PromotionFailedCode, StatusCodes.Status500InternalServerError)
        };
    }

    private static PasswordResetFinalizeResult StatusFromResetLookupCode(string code)
    {
        return new PasswordResetFinalizeResult(InvalidProofCode, StatusCodes.Status401Unauthorized);
    }

    private async Task<bool> RegisterRateLimit(
        string key,
        int limit,
        Instant now,
        CancellationToken cancellationToken)
    {
        PasswordResetRateLimitResult? result = await _passwordResetRepo.RegisterRequestRateLimitAsync(
            new PasswordResetRateLimitDbCommand(
                key,
                now,
                TimeSpanToPeriod(_abusePolicy.DailyRequestWindow),
                limit,
                TimeSpanToPeriod(_abusePolicy.RequestCooldown),
                TimeSpanToPeriod(_abusePolicy.RateLimitBlockPeriod)),
            cancellationToken);

        return result?.Result == true;
    }

    private PasswordResetEligibility BuildEligibility(string deliveryChannel, PasswordResetAccountLookupResult lookup)
    {
        return deliveryChannel switch
        {
            PasswordResetDeliveryChannels.Sms => SmsEligibility(lookup),
            PasswordResetDeliveryChannels.Email => EmailEligibility(lookup),
            _ => PasswordResetEligibility.Ineligible(deliveryChannel)
        };
    }


    private static PasswordResetEligibility EmailEligibility(PasswordResetAccountLookupResult lookup)
    {
        bool eligible = lookup.EmailVerified
            && !string.IsNullOrWhiteSpace(lookup.EmailAddress);

        return eligible
            ? PasswordResetEligibility.EligibleEmail(lookup.EmailAddress!, MaskEmail(lookup.EmailAddress!))
            : PasswordResetEligibility.Ineligible(PasswordResetDeliveryChannels.Email);
    }

    private static PasswordResetEligibility SmsEligibility(PasswordResetAccountLookupResult lookup)
    {
        bool eligible = lookup.SmsVerified
            && !string.IsNullOrWhiteSpace(lookup.PhoneNumber);

        if (!eligible)
        {
            return PasswordResetEligibility.Ineligible(PasswordResetDeliveryChannels.Sms);
        }

        string destination = NormalizePhoneDestination(lookup.PhoneCountryCode, lookup.PhoneNumber!);
        return PasswordResetEligibility.EligibleSms(destination, MaskPhone(destination));
    }

    private string FingerprintDestination(string kind, string destination)
    {
        string pepper = _settings.CodeHashPepper;
        if (string.IsNullOrWhiteSpace(pepper))
        {
            throw new InvalidOperationException("PasswordResetSettings:CodeHashPepper is required before password reset destination fingerprints can be created.");
        }

        string normalizedDestination = kind switch
        {
            "email" => destination.Trim().ToLowerInvariant(),
            _ => DigitsOnly(destination)
        };

        byte[] key = Encoding.UTF8.GetBytes(pepper);
        byte[] message = Encoding.UTF8.GetBytes($"pwdreset:destination:{kind}:{normalizedDestination}");
        byte[] digest = HMACSHA256.HashData(key, message);

        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    private static string NormalizeIdentifier(string identifier)
    {
        return identifier.Trim();
    }

    private static string NormalizePhoneDestination(string? countryCode, string phoneNumber)
    {
        return PhoneDestinationNormalizer.Normalize(countryCode, phoneNumber);
    }

    private static string MaskEmail(string emailAddress)
    {
        string trimmed = emailAddress.Trim();
        int atIndex = trimmed.IndexOf('@');
        if (atIndex <= 0)
        {
            return "***";
        }

        string local = trimmed[..atIndex];
        string domain = trimmed[atIndex..];
        string maskedLocal = local.Length switch
        {
            1 => "*",
            2 => $"{local[0]}*",
            _ => $"{local[0]}***{local[^1]}"
        };

        return maskedLocal + domain;
    }

    private static string MaskPhone(string phoneNumber)
    {
        string digits = DigitsOnly(phoneNumber);
        if (digits.Length <= 4)
        {
            return "***";
        }

        return $"***-***-{digits[^4..]}";
    }

    private static string DigitsOnly(string value)
    {
        StringBuilder builder = new(value.Length);
        foreach (char current in value)
        {
            if (char.IsDigit(current))
            {
                builder.Append(current);
            }
        }

        return builder.ToString();
    }

    private static Period TimeSpanToPeriod(TimeSpan value)
    {
        long seconds = Math.Max(0, (long)Math.Ceiling(value.TotalSeconds));
        return Period.FromSeconds((int)Math.Min(int.MaxValue, seconds));
    }

    private static PasswordResetRequestResult Accepted(Guid resetId)
    {
        return new PasswordResetRequestResult(RequestAcceptedCode, resetId);
    }

    private sealed record PasswordResetEligibility(
        bool Eligible,
        string Method,
        string? DeliveryChannel,
        string DestinationKind,
        string DestinationValue,
        string DestinationMasked,
        bool RequiresKeyCode,
        bool RequiresTotp)
    {
        public static PasswordResetEligibility Ineligible(string deliveryChannel)
        {
            return new PasswordResetEligibility(false, deliveryChannel, null, string.Empty, string.Empty, string.Empty, false, false);
        }


        public static PasswordResetEligibility EligibleEmail(string destination, string masked)
        {
            return new PasswordResetEligibility(true, PasswordResetDeliveryChannels.Email, PasswordResetDeliveryChannels.Email, "email", destination, masked, true, false);
        }

        public static PasswordResetEligibility EligibleSms(string destination, string masked)
        {
            return new PasswordResetEligibility(true, PasswordResetDeliveryChannels.Sms, PasswordResetDeliveryChannels.Sms, "sms", destination, masked, true, false);
        }
    }
}
