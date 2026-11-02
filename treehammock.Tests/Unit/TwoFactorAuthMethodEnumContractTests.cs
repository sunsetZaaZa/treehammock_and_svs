using System.Reflection;
using treehammock.RiggingSupport.Enum;
using Shouldly;

namespace treehammock.Tests.Unit;

public sealed class TwoFactorAuthMethodEnumContractTests
{
    [Fact]
    public void Authenticator_app_replaces_legacy_provider_key_at_value_three()
    {
        ((short)TwoFactorAuthMethod.NONE).ShouldBe((short)0);
        ((short)TwoFactorAuthMethod.EMAIL).ShouldBe((short)1);
        ((short)TwoFactorAuthMethod.SMS_KEY).ShouldBe((short)2);
        ((short)TwoFactorAuthMethod.AUTHENTICATOR_APP).ShouldBe((short)3);

        typeof(TwoFactorAuthMethod)
            .GetMember("AU" + "THY" + "_KEY", BindingFlags.Public | BindingFlags.Static)
            .ShouldBeEmpty();
    }

    [Theory]
    [MemberData(nameof(TwoFactorConfigurationCases))]
    public void Two_factor_configuration_resolver_maps_supported_account_options(List<TwoFactorAuthMethod> methods, TwoFactorAuthConfiguration expected)
    {
        TwoFactorAuthConfigurationResolver.FromMethods(methods).ShouldBe(expected);
    }

    public static TheoryData<List<TwoFactorAuthMethod>, TwoFactorAuthConfiguration> TwoFactorConfigurationCases()
    {
        return new TheoryData<List<TwoFactorAuthMethod>, TwoFactorAuthConfiguration>
        {
            { [], TwoFactorAuthConfiguration.NONE },
            { [TwoFactorAuthMethod.SMS_KEY], TwoFactorAuthConfiguration.SMS },
            { [TwoFactorAuthMethod.EMAIL], TwoFactorAuthConfiguration.EMAIL },
            { [TwoFactorAuthMethod.AUTHENTICATOR_APP], TwoFactorAuthConfiguration.AUTHENTICATOR_APP },
            { [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP], TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP },
            { [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP], TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP },
            { [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.SMS_KEY], TwoFactorAuthConfiguration.CUSTOM },
            { [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP], TwoFactorAuthConfiguration.CUSTOM }
        };
    }


    [Theory]
    [MemberData(nameof(AvailableTwoFactorConfigurationCases))]
    public void Two_factor_configuration_resolver_advertises_selectable_login_options(List<TwoFactorAuthMethod> methods, List<TwoFactorAuthConfiguration> expected)
    {
        TwoFactorAuthConfigurationResolver.AvailableFromMethods(methods).ShouldBe(expected);
    }

    public static TheoryData<List<TwoFactorAuthMethod>, List<TwoFactorAuthConfiguration>> AvailableTwoFactorConfigurationCases()
    {
        return new TheoryData<List<TwoFactorAuthMethod>, List<TwoFactorAuthConfiguration>>
        {
            { [], [] },
            { [TwoFactorAuthMethod.SMS_KEY], [TwoFactorAuthConfiguration.SMS] },
            { [TwoFactorAuthMethod.EMAIL], [TwoFactorAuthConfiguration.EMAIL] },
            { [TwoFactorAuthMethod.AUTHENTICATOR_APP], [TwoFactorAuthConfiguration.AUTHENTICATOR_APP] },
            { [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP], [TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP] },
            { [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP], [TwoFactorAuthConfiguration.EMAIL, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP] },
            { [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.SMS_KEY], [TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.EMAIL] },
            { [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP], [TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.EMAIL, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP] }
        };
    }

    [Fact]
    public void Two_factor_configuration_enum_values_are_stable_for_api_contracts()
    {
        ((short)TwoFactorAuthConfiguration.NONE).ShouldBe((short)0);
        ((short)TwoFactorAuthConfiguration.SMS).ShouldBe((short)1);
        ((short)TwoFactorAuthConfiguration.EMAIL).ShouldBe((short)2);
        ((short)TwoFactorAuthConfiguration.AUTHENTICATOR_APP).ShouldBe((short)3);
        ((short)TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP).ShouldBe((short)4);
        ((short)TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP).ShouldBe((short)5);
        ((short)TwoFactorAuthConfiguration.CUSTOM).ShouldBe((short)6);
    }
}
