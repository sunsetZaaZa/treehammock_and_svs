using Shouldly;

using treehammock.Rigging.Abuse;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class LoginAbuseCounterKeyFactoryTests
{
    [Fact]
    public void Factory_builds_safe_account_identifier_and_ip_keys_without_raw_material()
    {
        var accountId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var factory = new LoginAbuseCounterKeyFactory();

        AbuseCounterKey account = factory.ForAccount(accountId);
        AbuseCounterKey email = factory.ForIdentifier("email", "Reader@Example.com");
        AbuseCounterKey username = factory.ForIdentifier("username", "ReaderName");
        AbuseCounterKey ip = factory.ForIpAddress("203.0.113.42");

        account.Feature.ShouldBe(AbuseFeature.Login);
        account.Dimension.ShouldBe(AbuseCounterDimension.Account);
        account.SafeId.ShouldBe("11111111111111111111111111111111");

        email.Feature.ShouldBe(AbuseFeature.Login);
        email.Dimension.ShouldBe(AbuseCounterDimension.IdentifierFingerprint);
        email.SafeId.ShouldStartWith("email-");
        email.Value.Contains("reader", StringComparison.OrdinalIgnoreCase).ShouldBeFalse();
        email.Value.Contains("example", StringComparison.OrdinalIgnoreCase).ShouldBeFalse();
        email.Value.Contains("@", StringComparison.Ordinal).ShouldBeFalse();

        username.Dimension.ShouldBe(AbuseCounterDimension.IdentifierFingerprint);
        username.SafeId.ShouldStartWith("username-");
        username.Value.Contains("readername", StringComparison.OrdinalIgnoreCase).ShouldBeFalse();

        ip.Feature.ShouldBe(AbuseFeature.Login);
        ip.Dimension.ShouldBe(AbuseCounterDimension.IpFingerprint);
        ip.Value.Contains("203.0.113.42", StringComparison.Ordinal).ShouldBeFalse();
    }

    [Fact]
    public void Factory_rejects_unsafe_or_empty_inputs()
    {
        var factory = new LoginAbuseCounterKeyFactory();

        Should.Throw<ArgumentException>(() => factory.ForAccount(Guid.Empty));
        Should.Throw<ArgumentException>(() => factory.ForIdentifier(" ", "reader@example.com"));
        Should.Throw<ArgumentException>(() => factory.ForIdentifier("email", " "));
        Should.Throw<ArgumentException>(() => factory.ForIdentifier("email:raw", "reader@example.com"));
    }
}
