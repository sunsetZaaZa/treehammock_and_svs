using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;

using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class PasswordResetTotpVerifierTests
{
    [Fact]
    public async Task VerifyTotpForPasswordReset_succeeds_for_valid_shared_enrollment_code_and_step_mark()
    {
        TotpSettings settings = Settings();
        byte[] secret = Secret();
        Guid accountId = Guid.NewGuid();
        ProtectedTotpSecret protectedSecret = Protect(settings, secret, accountId);
        long twoFactorIndex = 4_294_967_296L;
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(accountId, twoFactorIndex, protectedSecret, lastUsedStep: null)));
        repo.MarkTotpStepUsedAsync(accountId, twoFactorIndex, Arg.Any<long>(), Arg.Any<Guid>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<TotpStepReplayCommandResult?>(new TotpStepReplayCommandResult(true, "TOTP_STEP_ACCEPTED")));
        PasswordResetTotpVerifier verifier = Verifier(settings, repo);
        string code = CurrentCode(settings, secret);

        PasswordResetTotpVerificationResult result = await verifier.VerifyTotpForPasswordReset(accountId, code, CancellationToken.None);

        result.Verified.ShouldBeTrue();
        result.Code.ShouldBe(PasswordResetTotpVerifier.VerifiedCode);
        await repo.Received(1).GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>());
        await repo.Received(1).MarkTotpStepUsedAsync(accountId, twoFactorIndex, Arg.Any<long>(), Arg.Any<Guid>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyTotpForPasswordReset_fails_closed_when_enrollment_is_missing()
    {
        TotpSettings settings = Settings();
        Guid accountId = Guid.NewGuid();
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(null));
        PasswordResetTotpVerifier verifier = Verifier(settings, repo);

        PasswordResetTotpVerificationResult result = await verifier.VerifyTotpForPasswordReset(accountId, "123456", CancellationToken.None);

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(PasswordResetTotpVerifier.EnrollmentNotFoundCode);
        await repo.DidNotReceiveWithAnyArgs().MarkTotpStepUsedAsync(default, default, default, default, default);
    }

    [Fact]
    public async Task VerifyTotpForPasswordReset_fails_for_managed_provider_until_provider_contract_exists()
    {
        TotpSettings settings = Settings();
        Guid accountId = Guid.NewGuid();
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(
                accountId,
                3,
                protectedSecret: null,
                lastUsedStep: null,
                providerType: TotpProviderType.TWILIO_VERIFY_TOTP)));
        PasswordResetTotpVerifier verifier = Verifier(settings, repo);

        PasswordResetTotpVerificationResult result = await verifier.VerifyTotpForPasswordReset(accountId, "123456", CancellationToken.None);

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(PasswordResetTotpVerifier.ProviderUnsupportedCode);
        await repo.DidNotReceiveWithAnyArgs().MarkTotpStepUsedAsync(default, default, default, default, default);
    }

    [Fact]
    public async Task VerifyTotpForPasswordReset_fails_closed_when_secret_cannot_be_unprotected()
    {
        TotpSettings settings = Settings();
        byte[] secret = Secret();
        Guid accountId = Guid.NewGuid();
        ProtectedTotpSecret protectedSecret = Protect(settings, secret, accountId);
        byte[] tamperedTag = protectedSecret.Tag.ToArray();
        tamperedTag[0] ^= 0xff;
        protectedSecret = protectedSecret with { Tag = tamperedTag };
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(accountId, 1, protectedSecret, lastUsedStep: null)));
        PasswordResetTotpVerifier verifier = Verifier(settings, repo);

        PasswordResetTotpVerificationResult result = await verifier.VerifyTotpForPasswordReset(accountId, "123456", CancellationToken.None);

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(PasswordResetTotpVerifier.SecretUnavailableCode);
        await repo.DidNotReceiveWithAnyArgs().MarkTotpStepUsedAsync(default, default, default, default, default);
    }

    [Fact]
    public async Task VerifyTotpForPasswordReset_fails_for_wrong_code_without_marking_step_used()
    {
        TotpSettings settings = Settings();
        byte[] secret = Secret();
        Guid accountId = Guid.NewGuid();
        ProtectedTotpSecret protectedSecret = Protect(settings, secret, accountId);
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(accountId, 1, protectedSecret, lastUsedStep: null)));
        PasswordResetTotpVerifier verifier = Verifier(settings, repo);

        PasswordResetTotpVerificationResult result = await verifier.VerifyTotpForPasswordReset(accountId, "000000", CancellationToken.None);

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(PasswordResetTotpVerifier.IncorrectCode);
        await repo.DidNotReceiveWithAnyArgs().MarkTotpStepUsedAsync(default, default, default, default, default);
    }

    [Fact]
    public async Task VerifyTotpForPasswordReset_fails_when_shared_step_marking_rejects_replay()
    {
        TotpSettings settings = Settings();
        byte[] secret = Secret();
        Guid accountId = Guid.NewGuid();
        ProtectedTotpSecret protectedSecret = Protect(settings, secret, accountId);
        long twoFactorIndex = 4;
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(accountId, twoFactorIndex, protectedSecret, lastUsedStep: null)));
        repo.MarkTotpStepUsedAsync(accountId, twoFactorIndex, Arg.Any<long>(), Arg.Any<Guid>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<TotpStepReplayCommandResult?>(new TotpStepReplayCommandResult(false, "TOTP_REPLAY_DETECTED")));
        PasswordResetTotpVerifier verifier = Verifier(settings, repo);
        string code = CurrentCode(settings, secret);

        PasswordResetTotpVerificationResult result = await verifier.VerifyTotpForPasswordReset(accountId, code, CancellationToken.None);

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(PasswordResetTotpVerifier.ReplayDetectedCode);
        await repo.Received(1).MarkTotpStepUsedAsync(accountId, twoFactorIndex, Arg.Any<long>(), Arg.Any<Guid>(), Arg.Any<CancellationToken>());
    }


    [Theory]
    [InlineData("lookup")]
    [InlineData("unprotect")]
    [InlineData("marker")]
    public async Task Cor03_faults_are_unavailable_not_incorrect_proofs(string fault)
    {
        var settings = Settings();
        byte[] secret = Secret();
        Guid accountId = Guid.NewGuid();
        var repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        var protectedSecret = Protect(settings, secret, accountId);
        if (fault == "unprotect")
        {
            byte[] tag = protectedSecret.Tag.ToArray(); tag[0] ^= 1;
            protectedSecret = protectedSecret with { Tag = tag };
        }
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(_ => fault == "lookup"
                ? Task.FromException<VerifiedTotpEnrollmentRecord?>(new InvalidOperationException("lookup unavailable"))
                : Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(accountId, 1, protectedSecret, null)));
        repo.MarkTotpStepUsedAsync(accountId, 1, Arg.Any<long>(), Arg.Any<Guid>(), Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<TotpStepReplayCommandResult?>(new InvalidOperationException("marker unavailable")));
        PasswordResetTotpVerificationResult result = await Verifier(settings, repo).VerifyTotpForPasswordReset(accountId, CurrentCode(settings, secret), CancellationToken.None);
        result.Status.ShouldBe(ProofVerificationStatus.DependencyUnavailable);
        result.Verified.ShouldBeFalse();
        if (fault != "marker") await repo.DidNotReceiveWithAnyArgs().MarkTotpStepUsedAsync(default, default, default, default, default);
    }

    private static PasswordResetTotpVerifier Verifier(TotpSettings settings, IAuthenticatorAppEnrollmentRepo repo)
    {
        return new PasswordResetTotpVerifier(
            repo,
            new TotpSecretProtector(Options.Create(settings)),
            new TotpCodeVerifier(),
            NullLogger<PasswordResetTotpVerifier>.Instance);
    }

    private static VerifiedTotpEnrollmentRecord Enrollment(
        Guid accountId,
        long twoFactorIndex,
        ProtectedTotpSecret? protectedSecret,
        long? lastUsedStep,
        TotpProviderType providerType = TotpProviderType.LOCAL_RFC6238)
    {
        return new VerifiedTotpEnrollmentRecord(
            accountId,
            twoFactorIndex,
            3,
            (short)providerType,
            providerType == TotpProviderType.TWILIO_VERIFY_TOTP ? "managed-enrollment" : null,
            providerType == TotpProviderType.TWILIO_VERIFY_TOTP ? "binding-hash" : null,
            protectedSecret?.Ciphertext,
            protectedSecret?.Nonce,
            protectedSecret?.Tag,
            protectedSecret?.Version,
            lastUsedStep, protectedSecret?.KeyId, protectedSecret?.Context, 1);
    }

    private static ProtectedTotpSecret Protect(TotpSettings settings, byte[] secret, Guid accountId)
    {
        return new TotpSecretProtector(Options.Create(settings)).Protect(secret, new(accountId, Guid.NewGuid(), TotpParameters.FromDefaults(settings)));
    }

    private static string CurrentCode(TotpSettings settings, byte[] secret)
    {
        Instant now = SystemClock.Instance.GetCurrentInstant();
        long step = now.ToUnixTimeSeconds() / settings.PeriodSeconds;
        return TotpCodeVerifier.ComputeCode(secret, step, settings.Digits, settings.HashAlgorithm);
    }

    private static byte[] Secret()
    {
        return "12345678901234567890"u8.ToArray();
    }

    private static TotpSettings Settings()
    {
        return new TotpSettings
        {
            Issuer = "Treehammock",
            Digits = 6,
            PeriodSeconds = 30,
            AllowedClockSkewSteps = 1,
            HashAlgorithm = "SHA1",
            SecretBytes = 20,
            ActiveProtectionKeyId = "test", ProtectionKeys = new() { ["test"] = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)) },
            SetupIdBytes = 32,
            SetupExpirationMinutes = 10,
            SetupMaxAttempts = 5
        };
    }
}
