using Microsoft.Extensions.Logging;
using NodaTime;

using treehammock.Repos;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Services;

public interface IAuthenticatorAppLoginVerifier
{
    Task<AuthenticatorAppLoginVerificationResult> VerifyForLoginAsync(
        Guid accountId,
        string totpCode,
        Instant now,
        CancellationToken cancellationToken = default);
}

public sealed record AuthenticatorAppLoginVerificationResult(bool Verified, string Code)
{
    public ProofVerificationStatus Status => Verified ? ProofVerificationStatus.Verified :
        Code is AuthenticatorAppLoginVerifier.EnrollmentUnavailableCode or AuthenticatorAppLoginVerifier.SecretUnavailableCode or
        AuthenticatorAppLoginVerifier.ProviderUnsupportedCode or AuthenticatorAppLoginVerifier.StepMarkFailedCode
            ? ProofVerificationStatus.DependencyUnavailable : ProofVerificationStatus.Rejected;
    public static AuthenticatorAppLoginVerificationResult Success()
    {
        return new AuthenticatorAppLoginVerificationResult(true, AuthenticatorAppLoginVerifier.VerifiedCode);
    }

    public static AuthenticatorAppLoginVerificationResult Failed(string code)
    {
        return new AuthenticatorAppLoginVerificationResult(false, code);
    }
}

/// <summary>
/// Verifies login 2FA proof against a verified local authenticator-app enrollment.
/// The verifier is deliberately backend-local for RFC 6238/OATH TOTP apps such as
/// Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden, Aegis,
/// and FreeOTP. Provider-managed verification is intentionally kept out of this local lane.
/// </summary>
public sealed class AuthenticatorAppLoginVerifier : IAuthenticatorAppLoginVerifier
{
    public const string VerifiedCode = "AUTHENTICATOR_LOGIN_TOTP_VERIFIED";
    public const string InvalidShapeCode = "AUTHENTICATOR_LOGIN_TOTP_INVALID_SHAPE";
    public const string EnrollmentUnavailableCode = "AUTHENTICATOR_LOGIN_TOTP_ENROLLMENT_UNAVAILABLE";
    public const string EnrollmentNotFoundCode = "AUTHENTICATOR_LOGIN_TOTP_ENROLLMENT_NOT_FOUND";
    public const string SecretUnavailableCode = "AUTHENTICATOR_LOGIN_TOTP_SECRET_UNAVAILABLE";
    public const string ProviderUnsupportedCode = "AUTHENTICATOR_LOGIN_TOTP_PROVIDER_UNSUPPORTED";
    public const string IncorrectCode = "AUTHENTICATOR_LOGIN_TOTP_INCORRECT";
    public const string ReplayDetectedCode = "AUTHENTICATOR_LOGIN_TOTP_REPLAY_DETECTED";
    public const string StepMarkFailedCode = "AUTHENTICATOR_LOGIN_TOTP_STEP_MARK_FAILED";

    private readonly IAuthenticatorAppEnrollmentRepo _enrollmentRepo;
    private readonly ITotpSecretProtector _secretProtector;
    private readonly ITotpCodeVerifier _codeVerifier;
    private readonly ILogger<AuthenticatorAppLoginVerifier> _logger;

    public AuthenticatorAppLoginVerifier(
        IAuthenticatorAppEnrollmentRepo enrollmentRepo,
        ITotpSecretProtector secretProtector,
        ITotpCodeVerifier codeVerifier,
        ILogger<AuthenticatorAppLoginVerifier> logger)
    {
        _enrollmentRepo = enrollmentRepo;
        _secretProtector = secretProtector;
        _codeVerifier = codeVerifier;
        _logger = logger;
    }

    public async Task<AuthenticatorAppLoginVerificationResult> VerifyForLoginAsync(
        Guid accountId,
        string totpCode,
        Instant now,
        CancellationToken cancellationToken = default)
    {
        if (accountId == Guid.Empty || string.IsNullOrWhiteSpace(totpCode))
        {
            return AuthenticatorAppLoginVerificationResult.Failed(InvalidShapeCode);
        }

        VerifiedTotpEnrollmentRecord? enrollment;
        try
        {
            enrollment = await _enrollmentRepo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, now, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex) {
            _logger.LogError(ex, "Login authenticator-app TOTP enrollment lookup failed for account {AccountId}.", accountId);
            return AuthenticatorAppLoginVerificationResult.Failed(EnrollmentUnavailableCode);
        }

        if (enrollment is null)
        {
            _logger.LogInformation("Login authenticator-app TOTP proof failed because account {AccountId} has no usable enrollment.", accountId);
            return AuthenticatorAppLoginVerificationResult.Failed(EnrollmentNotFoundCode);
        }

        if (enrollment.TotpProviderType != (short)TotpProviderType.LOCAL_RFC6238)
        {
            return AuthenticatorAppLoginVerificationResult.Failed(ProviderUnsupportedCode);
        }

        if (enrollment.TotpSecretCiphertext is null ||
            enrollment.TotpSecretNonce is null ||
            enrollment.TotpSecretTag is null ||
            enrollment.TotpSecretVersion is null || enrollment.TotpKeyId is null ||
            enrollment.Context is null || enrollment.Context.AccountId != accountId)
        {
            return AuthenticatorAppLoginVerificationResult.Failed(SecretUnavailableCode);
        }

        byte[]? secret = null;
        try
        {
            secret = _secretProtector.Unprotect(new ProtectedTotpSecret(
                enrollment.TotpSecretCiphertext,
                enrollment.TotpSecretNonce,
                enrollment.TotpSecretTag,
                enrollment.TotpSecretVersion.Value, enrollment.TotpKeyId, enrollment.Context));

            TotpVerificationResult verification = _codeVerifier.Verify(
                secret,
                totpCode,
                now,
                enrollment.TotpLastUsedStep, enrollment.Context.Parameters);

            if (!verification.Verified || verification.AcceptedTimeStep is null)
            {
                return AuthenticatorAppLoginVerificationResult.Failed(MapVerificationFailure(verification.Code));
            }

            TotpStepReplayCommandResult? marked = await _enrollmentRepo.MarkTotpStepUsedAsync(
                accountId,
                enrollment.TwoFactorIndex,
                verification.AcceptedTimeStep.Value, enrollment.Context.EnrollmentId,
                cancellationToken);

            if (marked?.Result == true)
            {
                return AuthenticatorAppLoginVerificationResult.Success();
            }

            _logger.LogInformation(
                "Login authenticator-app TOTP step marking failed for account {AccountId}, two-factor index {TwoFactorIndex}, result code {ResultCode}.",
                accountId,
                enrollment.TwoFactorIndex,
                marked?.Code ?? "<null>");

            return AuthenticatorAppLoginVerificationResult.Failed(MapStepMarkFailure(marked?.Code));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex) {
            _logger.LogWarning(ex, "Login authenticator-app TOTP proof failed closed for account {AccountId}.", accountId);
            return AuthenticatorAppLoginVerificationResult.Failed(SecretUnavailableCode);
        }
        finally
        {
            if (secret is not null)
            {
                Array.Clear(secret);
            }
        }
    }

    private static string MapVerificationFailure(string code)
    {
        return code switch
        {
            TotpVerificationResult.InvalidShapeCode => InvalidShapeCode,
            TotpVerificationResult.InvalidSecretCode => SecretUnavailableCode,
            TotpVerificationResult.ReplayDetectedCode => ReplayDetectedCode,
            _ => IncorrectCode
        };
    }

    private static string MapStepMarkFailure(string? code)
    {
        return string.Equals(code, "TOTP_REPLAY_DETECTED", StringComparison.OrdinalIgnoreCase)
            ? ReplayDetectedCode
            : StepMarkFailedCode;
    }
}
