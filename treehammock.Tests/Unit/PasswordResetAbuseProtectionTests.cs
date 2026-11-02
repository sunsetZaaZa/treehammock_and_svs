using Microsoft.Extensions.Options;
using Shouldly;

using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class PasswordResetAbuseProtectionTests
{
    [Fact]
    public void Rate_limit_key_factory_uses_account_destination_and_hashed_ip_keys()
    {
        var accountId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var factory = new PasswordResetRateLimitKeyFactory(Options.Create(Settings()));

        factory.ForAccount(accountId).ShouldBe("account:11111111111111111111111111111111:password_reset");
        factory.ForDestinationFingerprint("  ABCDEF  ").ShouldBe("destination:abcdef:password_reset");

        string ipKey = factory.ForIpAddress("127.0.0.1");
        ipKey.ShouldStartWith("ip-bucket:");
        ipKey.ShouldEndWith(":password_reset");
        ipKey.Contains("127.0.0.1", StringComparison.Ordinal).ShouldBeFalse();
    }


    [Fact]
    public void Abuse_counter_key_factory_uses_safe_fingerprints_for_identifier_ip_and_reset_id()
    {
        Guid resetId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var factory = new PasswordResetAbuseCounterKeyFactory(Options.Create(Settings()));

        AbuseCounterKey identifier = factory.ForRequestIdentifier("Reader@Example.com");
        AbuseCounterKey ip = factory.ForRequestIpAddress("127.0.0.1");
        AbuseCounterKey tokenVerification = factory.ForTokenVerificationReset(resetId);
        AbuseCounterKey twoFactorProof = factory.ForTwoFactorProofReset(resetId);
        AbuseCounterKey finalize = factory.ForFinalizeReset(resetId);

        identifier.Feature.ShouldBe(AbuseFeature.PasswordResetRequest);
        identifier.Dimension.ShouldBe(AbuseCounterDimension.IdentifierFingerprint);
        identifier.Value.ShouldNotContain("reader", Case.Insensitive);
        identifier.Value.ShouldNotContain("example", Case.Insensitive);
        ip.Feature.ShouldBe(AbuseFeature.PasswordResetRequest);
        ip.Dimension.ShouldBe(AbuseCounterDimension.IpFingerprint);
        ip.Value.ShouldNotContain("127.0.0.1");
        tokenVerification.Feature.ShouldBe(AbuseFeature.PasswordResetTokenVerification);
        tokenVerification.Dimension.ShouldBe(AbuseCounterDimension.Reset);
        tokenVerification.Value.ShouldNotContain(resetId.ToString("N"), Case.Insensitive);
        twoFactorProof.Feature.ShouldBe(AbuseFeature.PasswordResetTwoFactorProof);
        twoFactorProof.Dimension.ShouldBe(AbuseCounterDimension.Reset);
        twoFactorProof.Value.ShouldNotContain(resetId.ToString("N"), Case.Insensitive);
        finalize.Feature.ShouldBe(AbuseFeature.PasswordResetFinalize);
        finalize.Dimension.ShouldBe(AbuseCounterDimension.Reset);
        finalize.Value.ShouldNotContain(resetId.ToString("N"), Case.Insensitive);
    }

    [Fact]
    public void Abuse_counter_key_factory_uses_account_scope_without_raw_identifier_material()
    {
        var accountId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var factory = new PasswordResetAbuseCounterKeyFactory(Options.Create(Settings()));

        AbuseCounterKey account = factory.ForRequestAccount(accountId);

        account.Feature.ShouldBe(AbuseFeature.PasswordResetRequest);
        account.Dimension.ShouldBe(AbuseCounterDimension.Account);
        account.SafeId.ShouldBe("11111111111111111111111111111111");
        account.Value.Contains("@", StringComparison.Ordinal).ShouldBeFalse();
    }

    [Fact]
    public void Abuse_counter_key_factory_rejects_empty_abuse_inputs()
    {
        var factory = new PasswordResetAbuseCounterKeyFactory(Options.Create(Settings()));

        Should.Throw<ArgumentException>(() => factory.ForRequestAccount(Guid.Empty));
        Should.Throw<ArgumentException>(() => factory.ForRequestIdentifier(" "));
        Should.Throw<ArgumentException>(() => factory.ForTokenVerificationReset(Guid.Empty));
        Should.Throw<ArgumentException>(() => factory.ForTwoFactorProofReset(Guid.Empty));
        Should.Throw<ArgumentException>(() => factory.ForFinalizeReset(Guid.Empty));
    }

    [Fact]
    public void Abuse_policy_uses_backend_password_reset_configuration()
    {
        var policy = new PasswordResetAbusePolicy(Options.Create(new PasswordResetSettings
        {
            CodeHashPepper = "unit-test-password-reset-pepper",
            RequestCooldownSeconds = 90,
            DailyRequestWindowHours = 12,
            RateLimitBlockMinutes = 45,
            CaptchaChallengeEnabled = true,
            CaptchaChallengeAfterRequests = 3
        }));

        policy.RequestCooldown.ShouldBe(TimeSpan.FromSeconds(90));
        policy.DailyRequestWindow.ShouldBe(TimeSpan.FromHours(12));
        policy.RateLimitBlockPeriod.ShouldBe(TimeSpan.FromMinutes(45));
        policy.ShouldRequireCaptcha(2).ShouldBeFalse();
        policy.ShouldRequireCaptcha(3).ShouldBeTrue();
    }

    [Fact]
    public void Rate_limit_key_factory_rejects_empty_rate_limit_inputs()
    {
        var factory = new PasswordResetRateLimitKeyFactory(Options.Create(Settings()));

        Should.Throw<ArgumentException>(() => factory.ForAccount(Guid.Empty));
        Should.Throw<ArgumentException>(() => factory.ForDestinationFingerprint(" "));
    }

    private static PasswordResetSettings Settings() => new()
    {
        CodeHashPepper = "unit-test-password-reset-pepper"
    };
}
