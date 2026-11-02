using Microsoft.Extensions.Logging;
using NodaTime;

using treehammock.Repos;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Services;

public interface IPasswordResetTotpVerifier
{
    Task<PasswordResetTotpVerificationResult> VerifyTotpForPasswordReset(
        Guid accountId,
        string totpCode,
        CancellationToken cancellationToken);
}

public sealed record PasswordResetTotpVerificationResult(bool Verified, string Code)
{
    public ProofVerificationStatus Status => Verified ? ProofVerificationStatus.Verified :
        Code is PasswordResetTotpVerifier.EnrollmentUnavailableCode or PasswordResetTotpVerifier.SecretUnavailableCode or
        PasswordResetTotpVerifier.ProviderUnsupportedCode or PasswordResetTotpVerifier.StepMarkFailedCode
            ? ProofVerificationStatus.DependencyUnavailable : ProofVerificationStatus.Rejected;
    public static PasswordResetTotpVerificationResult Success()
    {
        return new PasswordResetTotpVerificationResult(true, PasswordResetTotpVerifier.VerifiedCode);
    }

    public static PasswordResetTotpVerificationResult Failed(string code)
    {
        return new PasswordResetTotpVerificationResult(false, code);
    }
}

/// <summary>
/// Verifies password-reset TOTP proof against the shared verified authenticator-app enrollment.
/// Password reset consumes enrollment proof only. It does not create, replace, disable, reset,
/// or otherwise mutate authenticator enrollment outside the shared replay marker.
/// </summary>
public sealed class PasswordResetTotpVerifier : IPasswordResetTotpVerifier
{
    public const string VerifiedCode = "PASSWORD_RESET_TOTP_VERIFIED";
    public const string InvalidShapeCode = "PASSWORD_RESET_TOTP_INVALID_SHAPE";
    public const string EnrollmentUnavailableCode = "PASSWORD_RESET_TOTP_ENROLLMENT_UNAVAILABLE";
    public const string EnrollmentNotFoundCode = "PASSWORD_RESET_TOTP_ENROLLMENT_NOT_FOUND";
    public const string SecretUnavailableCode = "PASSWORD_RESET_TOTP_SECRET_UNAVAILABLE";
    public const string ProviderUnsupportedCode = "PASSWORD_RESET_TOTP_PROVIDER_UNSUPPORTED";
    public const string IncorrectCode = "PASSWORD_RESET_TOTP_INCORRECT";
    public const string ReplayDetectedCode = "PASSWORD_RESET_TOTP_REPLAY_DETECTED";
    public const string StepMarkFailedCode = "PASSWORD_RESET_TOTP_STEP_MARK_FAILED";

    private readonly IAuthenticatorAppEnrollmentRepo _enrollmentRepo;
    private readonly ITotpSecretProtector _secretProtector;
    private readonly ITotpCodeVerifier _codeVerifier;
    private readonly ILogger<PasswordResetTotpVerifier> _logger;

    public PasswordResetTotpVerifier(
        IAuthenticatorAppEnrollmentRepo enrollmentRepo,
        ITotpSecretProtector secretProtector,
        ITotpCodeVerifier codeVerifier,
        ILogger<PasswordResetTotpVerifier> logger)
    {
        _enrollmentRepo = enrollmentRepo;
        _secretProtector = secretProtector;
        _codeVerifier = codeVerifier;
        _logger = logger;
    }

    public async Task<PasswordResetTotpVerificationResult> VerifyTotpForPasswordReset(
        Guid accountId,
        string totpCode,
        CancellationToken cancellationToken)
    {
        if (accountId == Guid.Empty || string.IsNullOrWhiteSpace(totpCode))
        {
            return PasswordResetTotpVerificationResult.Failed(InvalidShapeCode);
        }

        Instant now = SystemClock.Instance.GetCurrentInstant();
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
        catch (Exception ex)
        {
            _logger.LogError(ex, "Password reset TOTP enrollment lookup failed for account {AccountId}.", accountId);
            return PasswordResetTotpVerificationResult.Failed(EnrollmentUnavailableCode);
        }

        if (enrollment is null)
        {
            _logger.LogInformation("Password reset TOTP proof failed because account {AccountId} has no usable authenticator-app enrollment.", accountId);
            return PasswordResetTotpVerificationResult.Failed(EnrollmentNotFoundCode);
        }

        if (enrollment.TotpProviderType != (short)TotpProviderType.LOCAL_RFC6238)
        {
            return PasswordResetTotpVerificationResult.Failed(ProviderUnsupportedCode);
        }

        if (enrollment.TotpSecretCiphertext is null ||
            enrollment.TotpSecretNonce is null ||
            enrollment.TotpSecretTag is null ||
            enrollment.TotpSecretVersion is null || enrollment.TotpKeyId is null ||
            enrollment.Context is null || enrollment.Context.AccountId != accountId)
        {
            return PasswordResetTotpVerificationResult.Failed(SecretUnavailableCode);
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
                return PasswordResetTotpVerificationResult.Failed(MapVerificationFailure(verification.Code));
            }

            TotpStepReplayCommandResult? marked = await _enrollmentRepo.MarkTotpStepUsedAsync(
                accountId,
                enrollment.TwoFactorIndex,
                verification.AcceptedTimeStep.Value, enrollment.Context.EnrollmentId,
                cancellationToken);

            if (marked?.Result == true)
            {
                return PasswordResetTotpVerificationResult.Success();
            }

            _logger.LogInformation(
                "Password reset TOTP step marking failed for account {AccountId}, two-factor index {TwoFactorIndex}, result code {ResultCode}.",
                accountId,
                enrollment.TwoFactorIndex,
                marked?.Code ?? "<null>");

            return PasswordResetTotpVerificationResult.Failed(MapStepMarkFailure(marked?.Code));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Password reset TOTP proof failed closed for account {AccountId}.", accountId);
            return PasswordResetTotpVerificationResult.Failed(SecretUnavailableCode);
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
