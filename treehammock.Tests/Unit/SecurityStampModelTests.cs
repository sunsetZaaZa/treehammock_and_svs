using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using NodaTime;
using Shouldly;

namespace treehammock.Tests.Unit;

public class SecurityStampModelTests
{
    private static readonly Guid AccountSecurityStamp = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    [Fact]
    public void Account_security_stamp_guard_rejects_null_stamp()
    {
        Should.Throw<ArgumentException>(() => AccountSecurityStampGuard.Require(null));
    }

    [Fact]
    public void Account_security_stamp_guard_rejects_empty_stamp()
    {
        Should.Throw<ArgumentException>(() => AccountSecurityStampGuard.Require(Guid.Empty));
    }

    [Fact]
    public void ActiveSession_generates_non_empty_security_stamp_when_not_provided()
    {
        var session = BuildActiveSession(securityStamp: null, accountSecurityStamp: AccountSecurityStamp);

        session.securityStamp.ShouldNotBe(Guid.Empty);
        session.accountSecurityStamp.ShouldBe(AccountSecurityStamp);
    }

    [Fact]
    public void ActiveSession_replaces_empty_security_stamp_with_non_empty_stamp()
    {
        var session = BuildActiveSession(securityStamp: Guid.Empty, accountSecurityStamp: AccountSecurityStamp);

        session.securityStamp.ShouldNotBe(Guid.Empty);
        session.accountSecurityStamp.ShouldBe(AccountSecurityStamp);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public void ActiveSession_rejects_missing_or_empty_account_security_stamp(string? stampText)
    {
        Guid? stamp = stampText is null ? null : Guid.Parse(stampText);

        Should.Throw<ArgumentException>(() => BuildActiveSession(accountSecurityStamp: stamp));
    }

    [Fact]
    public void Session_generates_non_empty_security_stamp_when_not_provided()
    {
        var session = BuildSession(securityStamp: null, accountSecurityStamp: AccountSecurityStamp);

        session.securityStamp.ShouldNotBe(Guid.Empty);
        session.accountSecurityStamp.ShouldBe(AccountSecurityStamp);
    }

    [Fact]
    public void Session_replaces_empty_security_stamp_with_non_empty_stamp()
    {
        var session = BuildSession(securityStamp: Guid.Empty, accountSecurityStamp: AccountSecurityStamp);

        session.securityStamp.ShouldNotBe(Guid.Empty);
        session.accountSecurityStamp.ShouldBe(AccountSecurityStamp);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public void Session_rejects_missing_or_empty_account_security_stamp(string? stampText)
    {
        Guid? stamp = stampText is null ? null : Guid.Parse(stampText);

        Should.Throw<ArgumentException>(() => BuildSession(accountSecurityStamp: stamp));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public void TwoFactorSession_rejects_missing_or_empty_account_security_stamp(string? stampText)
    {
        Guid? stamp = stampText is null ? null : Guid.Parse(stampText);

        Should.Throw<ArgumentException>(() => new TwoFactorSession(
            Guid.NewGuid(),
            "web-key",
            new byte[] { 9, 8, 7 },
            [TwoFactorAuthMethod.EMAIL],
            null,
            null,
            null,
            ["reader@example.com"],
            null,
            null,
            0,
            0,
            0,
            Instant.FromUtc(2026, 5, 16, 12, 0),
            Instant.FromUtc(2026, 5, 16, 12, 5),
            FeatureSet.basic,
            null,
            stamp));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public void IntraAccount_rejects_missing_or_empty_account_security_stamp(string? stampText)
    {
        Guid? stamp = stampText is null ? null : Guid.Parse(stampText);

        Should.Throw<ArgumentException>(() => new IntraAccount(
            accountId: Guid.NewGuid(),
            hashedPassword: new byte[AccountCryptoSizes.PasswordHashBytes],
            webKey: "web-key",
            refreshToken: null,
            refreshes: 0,
            limit: 5,
            createdOn: Instant.FromUtc(2026, 5, 16, 12, 0),
            lifespan: null,
            saltOne: new byte[AccountCryptoSizes.SaltOneBytes],
            siv: new byte[AccountCryptoSizes.SivBytes],
            nonce: new byte[AccountCryptoSizes.NonceBytes],
            unlockWhen: null,
            loginFailures: 0,
            verifyStatus: VerificationStatus.SUCCESSFUL,
            features: FeatureSet.basic,
            twoFactorAccessToken: null,
            twoFactorAuthMethod: TwoFactorAuthMethod.NONE,
            twoAuthUsage: 0,
            accountSecurityStamp: stamp));
    }

    private static ActiveSession BuildActiveSession(Guid? securityStamp = null, Guid? accountSecurityStamp = null)
    {
        return treehammock.Tests.Support.EntitlementTestData.Attach(new ActiveSession(
            Guid.NewGuid(),
            new byte[] { 1, 2, 3 },
            0,
            Instant.FromUtc(2026, 5, 16, 12, 0),
            Period.FromMinutes(30),
            Instant.FromUtc(2026, 5, 16, 12, 10),
            Instant.FromUtc(2026, 5, 16, 12, 30),
            null,
            FeatureSet.basic,
            securityStamp: securityStamp,
            accountSecurityStamp: accountSecurityStamp));
    }

    private static Session BuildSession(Guid? securityStamp = null, Guid? accountSecurityStamp = null)
    {
        return treehammock.Tests.Support.EntitlementTestData.Attach(new Session(
            Guid.NewGuid(),
            new byte[] { 1, 2, 3 },
            0,
            5,
            Instant.FromUtc(2026, 5, 16, 12, 0),
            Period.FromMinutes(30),
            Instant.FromUtc(2026, 5, 16, 12, 10),
            Instant.FromUtc(2026, 5, 16, 12, 30),
            accountSecurityStamp: accountSecurityStamp,
            securityStamp: securityStamp));
    }
}
