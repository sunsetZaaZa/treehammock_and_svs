using System.Reflection;

using Shouldly;

using treehammock.DataLayer.Account;
using treehammock.Repos;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Tests.Unit;

public class TwoFactorDetailsLookupResultTests
{
    [Fact]
    public void Found_requires_details()
    {
        Should.Throw<ArgumentNullException>(() => TwoFactorDetailsLookupResult.Found(null!));
    }

    [Fact]
    public void Found_always_carries_the_details()
    {
        TwoFactorDetails details = BuildDetails();

        TwoFactorDetailsLookupResult result = TwoFactorDetailsLookupResult.Found(details);

        result.Status.ShouldBe(TwoFactorDetailsLookupStatus.Found);
        result.Details.ShouldBeSameAs(details);
        result.Succeeded.ShouldBeTrue();
    }

    [Theory]
    [InlineData(TwoFactorDetailsLookupStatus.NotConfigured)]
    [InlineData(TwoFactorDetailsLookupStatus.Failed)]
    public void Non_found_results_never_carry_details(TwoFactorDetailsLookupStatus expectedStatus)
    {
        TwoFactorDetailsLookupResult result = expectedStatus == TwoFactorDetailsLookupStatus.NotConfigured
            ? TwoFactorDetailsLookupResult.NotConfigured()
            : TwoFactorDetailsLookupResult.Failed();

        result.Status.ShouldBe(expectedStatus);
        result.Details.ShouldBeNull();
        result.Succeeded.ShouldBeFalse();
    }

    [Fact]
    public void Result_state_cannot_be_bypassed_with_public_constructor()
    {
        ConstructorInfo[] publicConstructors = typeof(TwoFactorDetailsLookupResult).GetConstructors(BindingFlags.Public | BindingFlags.Instance);

        publicConstructors.ShouldBeEmpty();
    }

    private static TwoFactorDetails BuildDetails()
    {
        return new TwoFactorDetails(
            [TwoFactorAuthMethod.EMAIL],
            null,
            null,
            null,
            ["reader@example.com"]);
    }
}
