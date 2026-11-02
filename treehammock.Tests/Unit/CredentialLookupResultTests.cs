using System.Reflection;

using NodaTime;
using Shouldly;

using treehammock.DataLayer.Account;
using treehammock.Repos;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Tests.Unit;

public class CredentialLookupResultTests
{
    [Fact]
    public void Found_requires_an_account()
    {
        Should.Throw<ArgumentNullException>(() => CredentialLookupResult.Found(null!));
    }

    [Fact]
    public void Found_always_carries_the_account()
    {
        IntraAccount account = BuildAccount();

        CredentialLookupResult result = CredentialLookupResult.Found(account);

        result.Status.ShouldBe(CredentialLookupStatus.Found);
        result.Account.ShouldBeSameAs(account);
        result.Succeeded.ShouldBeTrue();
    }

    [Theory]
    [InlineData(CredentialLookupStatus.NotFound)]
    [InlineData(CredentialLookupStatus.Failed)]
    public void Non_found_results_never_carry_an_account(CredentialLookupStatus expectedStatus)
    {
        CredentialLookupResult result = expectedStatus == CredentialLookupStatus.NotFound
            ? CredentialLookupResult.NotFound()
            : CredentialLookupResult.Failed();

        result.Status.ShouldBe(expectedStatus);
        result.Account.ShouldBeNull();
        result.Succeeded.ShouldBeFalse();
    }

    [Fact]
    public void Result_state_cannot_be_bypassed_with_public_constructor()
    {
        ConstructorInfo[] publicConstructors = typeof(CredentialLookupResult).GetConstructors(BindingFlags.Public | BindingFlags.Instance);

        publicConstructors.ShouldBeEmpty();
    }

    private static IntraAccount BuildAccount()
    {
        return new IntraAccount(
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
    }
}
