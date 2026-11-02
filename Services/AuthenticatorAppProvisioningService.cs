using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NodaTime;

using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Services;

public interface IAuthenticatorAppSecretGenerator
{
    byte[] GenerateSecret();
}

public sealed class AuthenticatorAppSecretGenerator : IAuthenticatorAppSecretGenerator
{
    private readonly TotpSettings _settings;

    public AuthenticatorAppSecretGenerator(IOptions<TotpSettings> settings)
    {
        _settings = settings.Value;
    }

    public byte[] GenerateSecret()
    {
        int secretBytes = Math.Clamp(_settings.SecretBytes, TotpSettings.MinimumSecretBytes, TotpSettings.MaximumSecretBytes);
        return RandomNumberGenerator.GetBytes(secretBytes);
    }
}

public interface IAuthenticatorAppBase32Encoder
{
    string Encode(ReadOnlySpan<byte> value);
}

public sealed class AuthenticatorAppBase32Encoder : IAuthenticatorAppBase32Encoder
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public string Encode(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
        {
            throw new ArgumentException("A non-empty value is required.", nameof(value));
        }

        StringBuilder result = new((value.Length + 4) / 5 * 8);
        int buffer = 0;
        int bitsLeft = 0;

        foreach (byte current in value)
        {
            buffer = (buffer << 8) | current;
            bitsLeft += 8;

            while (bitsLeft >= 5)
            {
                int index = (buffer >> (bitsLeft - 5)) & 0x1f;
                result.Append(Alphabet[index]);
                bitsLeft -= 5;
            }
        }

        if (bitsLeft > 0)
        {
            int index = (buffer << (5 - bitsLeft)) & 0x1f;
            result.Append(Alphabet[index]);
        }

        return result.ToString();
    }
}

public sealed record AuthenticatorAppProvisioningUriCommand(
    string AccountName,
    string ManualEntryKey,
    string? Label = null);

public sealed record AuthenticatorAppProvisioningMaterial(
    byte[] Secret,
    string ManualEntryKey,
    string OtpauthUri,
    string Issuer,
    string AccountName,
    int PeriodSeconds,
    int Digits,
    string HashAlgorithm,
    TotpProviderType ProviderType);

public interface IAuthenticatorAppProvisioningUriBuilder
{
    string Build(AuthenticatorAppProvisioningUriCommand command);
}

public sealed class AuthenticatorAppProvisioningUriBuilder : IAuthenticatorAppProvisioningUriBuilder
{
    private readonly TotpSettings _settings;

    public AuthenticatorAppProvisioningUriBuilder(IOptions<TotpSettings> settings)
    {
        _settings = settings.Value;
    }

    public string Build(AuthenticatorAppProvisioningUriCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.AccountName))
        {
            throw new ArgumentException("An account name is required.", nameof(command));
        }

        if (string.IsNullOrWhiteSpace(command.ManualEntryKey))
        {
            throw new ArgumentException("A manual-entry key is required.", nameof(command));
        }

        string issuer = _settings.Issuer.Trim();
        string accountName = command.AccountName.Trim();
        string displayLabel = string.IsNullOrWhiteSpace(command.Label)
            ? accountName
            : $"{accountName} ({command.Label.Trim()})";
        string label = $"{issuer}:{displayLabel}";
        string algorithm = _settings.HashAlgorithm.Trim().ToUpperInvariant();

        return string.Concat(
            "otpauth://totp/",
            Uri.EscapeDataString(label),
            "?secret=",
            Uri.EscapeDataString(command.ManualEntryKey),
            "&issuer=",
            Uri.EscapeDataString(issuer),
            "&algorithm=",
            Uri.EscapeDataString(algorithm),
            "&digits=",
            _settings.Digits.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "&period=",
            _settings.PeriodSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }
}

public interface ITotpProvider
{
    TotpProviderType ProviderType { get; }

    AuthenticatorAppProvisioningMaterial CreateProvisioningMaterial(string accountName, string? label = null);
}

public sealed class LocalTotpProvider : ITotpProvider
{
    private readonly IAuthenticatorAppSecretGenerator _secretGenerator;
    private readonly IAuthenticatorAppBase32Encoder _base32Encoder;
    private readonly IAuthenticatorAppProvisioningUriBuilder _uriBuilder;
    private readonly TotpSettings _settings;

    public LocalTotpProvider(
        IAuthenticatorAppSecretGenerator secretGenerator,
        IAuthenticatorAppBase32Encoder base32Encoder,
        IAuthenticatorAppProvisioningUriBuilder uriBuilder,
        IOptions<TotpSettings> settings)
    {
        _secretGenerator = secretGenerator;
        _base32Encoder = base32Encoder;
        _uriBuilder = uriBuilder;
        _settings = settings.Value;
    }

    public TotpProviderType ProviderType => TotpProviderType.LOCAL_RFC6238;

    public AuthenticatorAppProvisioningMaterial CreateProvisioningMaterial(string accountName, string? label = null)
    {
        byte[] secret = _secretGenerator.GenerateSecret();

        try
        {
            string manualEntryKey = _base32Encoder.Encode(secret);
            string otpauthUri = _uriBuilder.Build(new AuthenticatorAppProvisioningUriCommand(accountName, manualEntryKey, label));

            return new AuthenticatorAppProvisioningMaterial(
                secret,
                manualEntryKey,
                otpauthUri,
                _settings.Issuer,
                accountName,
                _settings.PeriodSeconds,
                _settings.Digits,
                _settings.HashAlgorithm.Trim().ToUpperInvariant(),
                ProviderType);
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            Array.Clear(secret);
            throw;
        }
    }
}

public interface ITotpProviderRegistry
{
    ITotpProvider DefaultProvider { get; }

    ITotpProvider GetRequiredProvider(TotpProviderType providerType);
}

public sealed class TotpProviderRegistry : ITotpProviderRegistry
{
    private readonly IReadOnlyDictionary<TotpProviderType, ITotpProvider> _providers;

    public TotpProviderRegistry(IEnumerable<ITotpProvider> providers)
    {
        _providers = providers.ToDictionary(provider => provider.ProviderType);
    }

    public ITotpProvider DefaultProvider => GetRequiredProvider(TotpProviderType.LOCAL_RFC6238);

    public ITotpProvider GetRequiredProvider(TotpProviderType providerType)
    {
        if (_providers.TryGetValue(providerType, out ITotpProvider? provider))
        {
            return provider;
        }

        throw new InvalidOperationException($"TOTP provider '{providerType}' is not registered.");
    }
}

public sealed record StartAuthenticatorAppSetupCommand(
    Guid AccountId,
    Guid AccountSecurityStamp,
    string AccountName,
    string? Label,
    bool Required,
    TotpProviderType ProviderType = TotpProviderType.LOCAL_RFC6238,
    treehammock.DataLayer.Security.SensitiveActionGrant? Grant = null, Guid? ExpectedEnrollmentId = null, long? ExpectedVersion = null);

public sealed record StartAuthenticatorAppSetupResult(
    bool Succeeded,
    string Code,
    string? SetupId = null,
    string? OtpauthUri = null,
    string? ManualEntryKey = null,
    string? Issuer = null,
    string? AccountName = null,
    int? PeriodSeconds = null,
    int? Digits = null,
    string? HashAlgorithm = null,
    TotpProviderType? ProviderType = null,
    Instant? Expiration = null, Guid? EnrollmentId = null, long? SetupVersion = null);

public sealed record CancelAuthenticatorAppSetupServiceCommand(
    Guid AccountId,
    Guid AccountSecurityStamp,
    string SetupId);

public sealed record CancelAuthenticatorAppSetupResult(
    bool Succeeded,
    string Code);

public sealed record VerifyAuthenticatorAppSetupAndRotateSessionCommand(
    Guid AccountId,
    Guid AccountSecurityStamp,
    string SetupId,
    string TotpCode,
    string ExpectedOldAccessTokenHash,
    string NewAccessTokenHash,
    byte[] RefreshToken,
    short Refreshes,
    short RefreshLimit,
    Instant CreatedOn,
    Period SessionLifespan,
    Instant AccessExpiration,
    Instant SessionExpiration,
    Instant? CutOff,
    FeatureSet Features,
    Guid SessionSecurityStamp);

public sealed record VerifyAuthenticatorAppSetupAndRotateSessionResult(
    bool Succeeded,
    string Code,
    Guid? NewAccountSecurityStamp = null,
    long? TwoFactorIndex = null, treehammock.DataLayer.Entitlements.EntitlementProjection? Entitlements = null);

public interface IAuthenticatorAppSetupService
{
    Task<StartAuthenticatorAppSetupResult> StartSetupAsync(
        StartAuthenticatorAppSetupCommand command,
        CancellationToken cancellationToken = default);

    Task<VerifyAuthenticatorAppSetupAndRotateSessionResult> VerifySetupAndRotateSessionAsync(
        VerifyAuthenticatorAppSetupAndRotateSessionCommand command,
        CancellationToken cancellationToken = default);

    Task<CancelAuthenticatorAppSetupResult> CancelSetupAsync(
        CancelAuthenticatorAppSetupServiceCommand command,
        CancellationToken cancellationToken = default);
}

public sealed class AuthenticatorAppSetupService : IAuthenticatorAppSetupService
{
    public const string SetupStartedCode = "AUTHENTICATOR_SETUP_STARTED";
    public const string SetupVerifiedSessionRotatedCode = "AUTHENTICATOR_SETUP_VERIFIED_SESSION_ROTATED";
    public const string SetupCancelledCode = "AUTHENTICATOR_SETUP_CANCELLED";
    public const string AuthenticatorAppAlreadyAttachedCode = "TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED";
    public const string UnsupportedProviderCode = "AUTHENTICATOR_SETUP_PROVIDER_UNSUPPORTED";
    public const string SetupStartFailedCode = "AUTHENTICATOR_SETUP_START_FAILED";
    public const string SetupVerifyFailedCode = "AUTHENTICATOR_SETUP_VERIFY_FAILED";
    public const string SetupCancelFailedCode = "AUTHENTICATOR_SETUP_CANCEL_FAILED";
    public const string InvalidRequestCode = "AUTHENTICATOR_SETUP_INVALID_REQUEST";
    public const string SetupInvalidSecretCode = "AUTHENTICATOR_SETUP_INVALID_SECRET";

    private readonly IAuthenticatorAppEnrollmentRepo _repo;
    private readonly ITotpProviderRegistry _providerRegistry;
    private readonly ITotpSecretProtector _secretProtector;
    private readonly ITotpCodeVerifier _totpCodeVerifier;
    private readonly TotpSettings _settings;
    private readonly ILogger<AuthenticatorAppSetupService> _logger;

    public AuthenticatorAppSetupService(
        IAuthenticatorAppEnrollmentRepo repo,
        ITotpProviderRegistry providerRegistry,
        ITotpSecretProtector secretProtector,
        ITotpCodeVerifier totpCodeVerifier,
        IOptions<TotpSettings> settings,
        ILogger<AuthenticatorAppSetupService> logger)
    {
        _repo = repo;
        _providerRegistry = providerRegistry;
        _secretProtector = secretProtector;
        _totpCodeVerifier = totpCodeVerifier;
        _settings = settings.Value;
        _logger = logger;
    }

    public async Task<StartAuthenticatorAppSetupResult> StartSetupAsync(
        StartAuthenticatorAppSetupCommand command,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (command.AccountId == Guid.Empty || command.AccountSecurityStamp == Guid.Empty || string.IsNullOrWhiteSpace(command.AccountName))
        {
            return new StartAuthenticatorAppSetupResult(false, InvalidRequestCode);
        }

        if (command.ProviderType != TotpProviderType.LOCAL_RFC6238)
        {
            return new StartAuthenticatorAppSetupResult(false, UnsupportedProviderCode, ProviderType: command.ProviderType);
        }

        if (command.Grant is null || command.Grant.CanonicalTarget != treehammock.Rigging.Security.SensitiveActionTargets.AuthenticatorSetup(command.Label, command.Required, command.ProviderType, command.ExpectedEnrollmentId, command.ExpectedVersion))
            return new StartAuthenticatorAppSetupResult(false, "SENSITIVE_ACTION_GRANT_REQUIRED");

        AuthenticatorAppProvisioningMaterial? material = null;
        byte[]? secret = null;
        byte[]? ciphertext = null;
        byte[]? nonce = null;
        byte[]? tag = null;

        try
        {
            ITotpProvider provider = _providerRegistry.GetRequiredProvider(command.ProviderType);
            material = provider.CreateProvisioningMaterial(command.AccountName, command.Label);
            secret = material.Secret;
            ProtectedTotpSecret protectedSecret = _secretProtector.Protect(secret, new TotpEnrollmentContext(command.AccountId, Guid.NewGuid(),
                new TotpParameters(material.HashAlgorithm.ToUpperInvariant(), material.Digits, material.PeriodSeconds, _settings.AllowedClockSkewSteps)));
            ciphertext = protectedSecret.Ciphertext;
            nonce = protectedSecret.Nonce;
            tag = protectedSecret.Tag;

            Instant now = SystemClock.Instance.GetCurrentInstant();
            Instant expiration = now.Plus(Duration.FromMinutes(_settings.SetupExpirationMinutes));
            string setupId = AccountVerificationTokenUtility.GenerateToken(_settings.SetupIdBytes);
            string setupTokenHash = AccountVerificationTokenUtility.HashToken(setupId);

            AuthenticatorAppSetupBeginCommandResult? begin = await _repo.BeginAuthenticatorAppSetupAsync(
                new BeginAuthenticatorAppSetupCommand(
                    command.AccountId,
                    command.AccountSecurityStamp,
                    setupTokenHash,
                    now,
                    expiration,
                    ResolveAuthId(command.Label),
                    command.Required,
                    command.ProviderType,
                    ciphertext,
                    nonce,
                    tag,
                    protectedSecret.Version, command.Grant, protectedSecret.KeyId, protectedSecret.Context, command.ExpectedEnrollmentId, command.ExpectedVersion),
                cancellationToken);

            if (begin?.Result != true || begin.Expiration is null)
            {
                return new StartAuthenticatorAppSetupResult(
                    false,
                    begin?.Code ?? SetupStartFailedCode,
                    ProviderType: command.ProviderType);
            }

            return new StartAuthenticatorAppSetupResult(
                true,
                string.IsNullOrWhiteSpace(begin.Code) ? SetupStartedCode : begin.Code,
                setupId,
                material.OtpauthUri,
                material.ManualEntryKey,
                material.Issuer,
                material.AccountName,
                material.PeriodSeconds,
                material.Digits,
                material.HashAlgorithm,
                material.ProviderType,
                begin.Expiration, protectedSecret.Context.EnrollmentId, (command.ExpectedVersion ?? 0) + 1);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex) {
            _logger.LogWarning(ex, "Authenticator-app local provisioning setup failed closed for account {AccountId}.", command.AccountId);
            return new StartAuthenticatorAppSetupResult(false, SetupStartFailedCode, ProviderType: command.ProviderType);
        }
        finally
        {
            if (secret is not null)
            {
                Array.Clear(secret);
            }

            if (ciphertext is not null)
            {
                Array.Clear(ciphertext);
            }

            if (nonce is not null)
            {
                Array.Clear(nonce);
            }

            if (tag is not null)
            {
                Array.Clear(tag);
            }
        }
    }


    public async Task<VerifyAuthenticatorAppSetupAndRotateSessionResult> VerifySetupAndRotateSessionAsync(
        VerifyAuthenticatorAppSetupAndRotateSessionCommand command,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (command.AccountId == Guid.Empty ||
            command.AccountSecurityStamp == Guid.Empty ||
            string.IsNullOrWhiteSpace(command.SetupId) ||
            string.IsNullOrWhiteSpace(command.TotpCode) ||
            string.IsNullOrWhiteSpace(command.ExpectedOldAccessTokenHash) ||
            string.IsNullOrWhiteSpace(command.NewAccessTokenHash) ||
            command.RefreshToken.Length == 0 ||
            command.SessionSecurityStamp == Guid.Empty)
        {
            return new VerifyAuthenticatorAppSetupAndRotateSessionResult(false, InvalidRequestCode);
        }

        string setupTokenHash = AccountVerificationTokenUtility.HashToken(command.SetupId);
        PendingAuthenticatorAppSetupRecord? pending = await _repo.GetPendingAuthenticatorAppSetupAsync(
            new GetPendingAuthenticatorAppSetupCommand(
                command.AccountId,
                command.AccountSecurityStamp,
                setupTokenHash,
                command.CreatedOn),
            cancellationToken);

        if (pending?.Result != true)
        {
            return new VerifyAuthenticatorAppSetupAndRotateSessionResult(false, pending?.Code ?? SetupVerifyFailedCode);
        }

        if (pending.TotpProviderType is not (short)TotpProviderType.LOCAL_RFC6238 ||
            pending.TotpSecretCiphertext is null ||
            pending.TotpSecretNonce is null ||
            pending.TotpSecretTag is null ||
            pending.TotpSecretVersion is null || pending.TotpKeyId is null ||
            pending.Context is null || pending.Context.AccountId != command.AccountId)
        {
            await RecordFailure(command, setupTokenHash, cancellationToken);
            return new VerifyAuthenticatorAppSetupAndRotateSessionResult(false, SetupInvalidSecretCode);
        }

        byte[]? secret = null;
        try
        {
            secret = _secretProtector.Unprotect(new ProtectedTotpSecret(
                pending.TotpSecretCiphertext,
                pending.TotpSecretNonce,
                pending.TotpSecretTag,
                pending.TotpSecretVersion.Value, pending.TotpKeyId, pending.Context));

            TotpVerificationResult verification = _totpCodeVerifier.Verify(
                secret,
                command.TotpCode,
                command.CreatedOn,
                pending.TotpLastUsedStep, pending.Context.Parameters);

            if (!verification.Verified || verification.AcceptedTimeStep is null)
            {
                AuthenticatorAppSetupFailureCommandResult? failure = await RecordFailure(command, setupTokenHash, cancellationToken);
                return new VerifyAuthenticatorAppSetupAndRotateSessionResult(
                    false,
                    failure?.Code ?? verification.Code);
            }

            AuthenticatorAppSetupCompletionCommandResult? completed = await _repo.CompleteAuthenticatorAppSetupAndRotateSessionAsync(
                new CompleteAuthenticatorAppSetupAndRotateSessionCommand(
                    command.AccountId,
                    command.AccountSecurityStamp,
                    setupTokenHash,
                    verification.AcceptedTimeStep.Value,
                    command.ExpectedOldAccessTokenHash,
                    command.NewAccessTokenHash,
                    command.RefreshToken,
                    command.Refreshes,
                    command.RefreshLimit,
                    command.CreatedOn,
                    command.SessionLifespan.ToDuration(),
                    command.AccessExpiration,
                    command.SessionExpiration,
                    command.CutOff,
                    command.Features,
                    command.SessionSecurityStamp),
                cancellationToken);

            if (completed?.Result != true || completed.AccountSecurityStamp is null)
            {
                return new VerifyAuthenticatorAppSetupAndRotateSessionResult(false, completed?.Code ?? SetupVerifyFailedCode);
            }

            return new VerifyAuthenticatorAppSetupAndRotateSessionResult(
                true,
                string.IsNullOrWhiteSpace(completed.Code) ? SetupVerifiedSessionRotatedCode : completed.Code,
                completed.AccountSecurityStamp,
                completed.TwoFactorIndex, completed.Entitlements);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex) {
            _logger.LogWarning(ex, "Authenticator-app setup verification failed closed for account {AccountId}.", command.AccountId);
            return new VerifyAuthenticatorAppSetupAndRotateSessionResult(false, SetupVerifyFailedCode);
        }
        finally
        {
            if (secret is not null)
            {
                Array.Clear(secret);
            }
        }
    }

    public async Task<CancelAuthenticatorAppSetupResult> CancelSetupAsync(
        CancelAuthenticatorAppSetupServiceCommand command,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (command.AccountId == Guid.Empty || command.AccountSecurityStamp == Guid.Empty || string.IsNullOrWhiteSpace(command.SetupId))
        {
            return new CancelAuthenticatorAppSetupResult(false, InvalidRequestCode);
        }

        string setupTokenHash = AccountVerificationTokenUtility.HashToken(command.SetupId);
        AuthenticatorAppSetupCancelCommandResult? result = await _repo.CancelAuthenticatorAppSetupAsync(
            new treehammock.Repos.CancelAuthenticatorAppSetupCommand(
                command.AccountId,
                command.AccountSecurityStamp,
                setupTokenHash),
            cancellationToken);

        if (result?.Result != true)
        {
            return new CancelAuthenticatorAppSetupResult(false, result?.Code ?? SetupCancelFailedCode);
        }

        return new CancelAuthenticatorAppSetupResult(
            true,
            string.IsNullOrWhiteSpace(result.Code) ? SetupCancelledCode : result.Code);
    }

    private async Task<AuthenticatorAppSetupFailureCommandResult?> RecordFailure(
        VerifyAuthenticatorAppSetupAndRotateSessionCommand command,
        string setupTokenHash,
        CancellationToken cancellationToken)
    {
        return await _repo.RecordAuthenticatorAppSetupFailureAsync(
            new RecordAuthenticatorAppSetupFailureCommand(
                command.AccountId,
                command.AccountSecurityStamp,
                setupTokenHash,
                _settings.SetupMaxAttempts,
                command.CreatedOn),
            cancellationToken);
    }

    private static string ResolveAuthId(string? label)
    {
        return string.IsNullOrWhiteSpace(label)
            ? "authenticator-app"
            : label.Trim();
    }
}
