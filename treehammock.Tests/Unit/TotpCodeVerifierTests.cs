using Microsoft.Extensions.Options;
using NodaTime;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class TotpCodeVerifierTests
{
    [Fact]
    public void Verify_accepts_valid_current_totp_code()
    {
        TotpSettings settings = Settings();
        var verifier = new TotpCodeVerifier();
        byte[] secret = Secret();
        Instant now = Instant.FromUnixTimeSeconds(1_700_000_000);
        long step = now.ToUnixTimeSeconds() / settings.PeriodSeconds;
        string code = TotpCodeVerifier.ComputeCode(secret, step, settings.Digits, settings.HashAlgorithm);

        TotpVerificationResult result = verifier.Verify(secret, code, now, lastUsedStep: null, parameters: TotpParameters.FromDefaults(settings));

        result.Verified.ShouldBeTrue();
        result.AcceptedTimeStep.ShouldBe(step);
        result.Code.ShouldBe(TotpVerificationResult.VerifiedCode);
    }

    [Fact]
    public void Verify_accepts_previous_step_within_configured_skew()
    {
        TotpSettings settings = Settings(allowedClockSkewSteps: 1);
        var verifier = new TotpCodeVerifier();
        byte[] secret = Secret();
        Instant now = Instant.FromUnixTimeSeconds(1_700_000_000);
        long step = now.ToUnixTimeSeconds() / settings.PeriodSeconds;
        string code = TotpCodeVerifier.ComputeCode(secret, step - 1, settings.Digits, settings.HashAlgorithm);

        TotpVerificationResult result = verifier.Verify(secret, code, now, lastUsedStep: null, parameters: TotpParameters.FromDefaults(settings));

        result.Verified.ShouldBeTrue();
        result.AcceptedTimeStep.ShouldBe(step - 1);
    }

    [Fact]
    public void Verify_rejects_code_outside_configured_skew()
    {
        TotpSettings settings = Settings(allowedClockSkewSteps: 0);
        var verifier = new TotpCodeVerifier();
        byte[] secret = Secret();
        Instant now = Instant.FromUnixTimeSeconds(1_700_000_000);
        long step = now.ToUnixTimeSeconds() / settings.PeriodSeconds;
        string code = TotpCodeVerifier.ComputeCode(secret, step - 1, settings.Digits, settings.HashAlgorithm);

        TotpVerificationResult result = verifier.Verify(secret, code, now, lastUsedStep: null, parameters: TotpParameters.FromDefaults(settings));

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(TotpVerificationResult.IncorrectCode);
    }

    [Fact]
    public void Verify_rejects_replayed_step()
    {
        TotpSettings settings = Settings();
        var verifier = new TotpCodeVerifier();
        byte[] secret = Secret();
        Instant now = Instant.FromUnixTimeSeconds(1_700_000_000);
        long step = now.ToUnixTimeSeconds() / settings.PeriodSeconds;
        string code = TotpCodeVerifier.ComputeCode(secret, step, settings.Digits, settings.HashAlgorithm);

        TotpVerificationResult result = verifier.Verify(secret, code, now, lastUsedStep: step, parameters: TotpParameters.FromDefaults(settings));

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(TotpVerificationResult.IncorrectCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12x456")]
    public void Verify_rejects_malformed_codes(string submittedCode)
    {
        TotpSettings settings = Settings();
        var verifier = new TotpCodeVerifier();

        TotpVerificationResult result = verifier.Verify(Secret(), submittedCode, Instant.FromUnixTimeSeconds(1_700_000_000), lastUsedStep: null, parameters: TotpParameters.FromDefaults(settings));

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(TotpVerificationResult.InvalidShapeCode);
    }

    [Fact]
    public void ComputeCode_matches_known_RFC_6238_sha1_test_vector()
    {
        byte[] secret = "12345678901234567890"u8.ToArray();
        Instant timestamp = Instant.FromUnixTimeSeconds(59);
        long step = timestamp.ToUnixTimeSeconds() / 30;

        string code = TotpCodeVerifier.ComputeCode(secret, step, digits: 8, hashAlgorithm: "SHA1");

        code.ShouldBe("94287082");
    }

    private static TotpSettings Settings(int allowedClockSkewSteps = 1)
    {
        return new TotpSettings
        {
            Issuer = "Treehammock",
            Digits = 6,
            PeriodSeconds = 30,
            AllowedClockSkewSteps = allowedClockSkewSteps,
            HashAlgorithm = "SHA1",
            SecretBytes = 20,
            ActiveProtectionKeyId = "test", ProtectionKeys = new() { ["test"] = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)) }
        };
    }

    private static byte[] Secret()
    {
        return "12345678901234567890"u8.ToArray();
    }
}
