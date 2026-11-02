using Shouldly;

using treehammock.Rigging.Abuse;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class AccountUnlockAbuseProtectionTests
{
    [Fact]
    public void Account_unlock_abuse_counter_key_factory_uses_safe_fingerprints_for_token_and_ip()
    {
        var factory = new AccountUnlockAbuseCounterKeyFactory();

        AbuseCounterKey token = factory.ForVerifyToken("unlock-token-123");
        AbuseCounterKey ip = factory.ForVerifyIpAddress("203.0.113.42");

        token.Feature.ShouldBe(AbuseFeature.AccountUnlock);
        token.Dimension.ShouldBe(AbuseCounterDimension.TokenFingerprint);
        token.Value.ShouldNotContain("unlock-token-123");
        token.Value.ShouldNotContain("token-123");

        ip.Feature.ShouldBe(AbuseFeature.AccountUnlock);
        ip.Dimension.ShouldBe(AbuseCounterDimension.IpFingerprint);
        ip.Value.ShouldNotContain("203.0.113.42");
        ip.Value.ShouldStartWith("abuse:accountunlock:ipfingerprint:");
    }

    [Fact]
    public void Account_unlock_abuse_counter_key_factory_rejects_blank_tokens()
    {
        var factory = new AccountUnlockAbuseCounterKeyFactory();

        Should.Throw<ArgumentException>(() => factory.ForVerifyToken("   "));
    }
}
