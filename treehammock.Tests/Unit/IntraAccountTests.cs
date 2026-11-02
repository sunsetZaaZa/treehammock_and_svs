using NodaTime;
using Shouldly;

using treehammock.DataLayer.Account;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Tests.Unit;

public class IntraAccountTests
{
    [Fact]
    public void Constructor_allows_nullable_refresh_token_so_not_logged_in_branch_is_reachable()
    {
        var account = new IntraAccount(
            Guid.NewGuid(),
            new byte[AccountCryptoSizes.PasswordHashBytes],
            "web-key",
            VerificationStatus.SUCCESSFUL,
            new byte[AccountCryptoSizes.SaltOneBytes],
            new byte[AccountCryptoSizes.SivBytes],
            new byte[AccountCryptoSizes.NonceBytes],
            null,
            null,
            0,
            3,
            Period.FromHours(1),
            0,
            null,
            0,
            0,
            0,
            false,
            Country.NONE,
            null,
            null,
            FeatureSet.basic,
            accountSecurityStamp: Guid.Parse("66666666-7777-8888-9999-aaaaaaaaaaaa"));

        account.refreshToken.ShouldBeNull();
        account.hasTwoFactorAuth.ShouldBeFalse();
        account.accountSecurityStamp.ShouldBe(Guid.Parse("66666666-7777-8888-9999-aaaaaaaaaaaa"));
    }
}
