using treehammock.RiggingSupport.Enum;
using Shouldly;

namespace treehammock.Tests.Unit;

public sealed class PasswordResetTwoFactorConfigurationResolverTests
{
    [Theory]
    [MemberData(nameof(EmailBootstrapCases))]
    public void Email_reset_bootstrap_excludes_email_based_reset_two_factor_options(
        List<TwoFactorAuthMethod> methods,
        List<TwoFactorAuthConfiguration> expected)
    {
        PasswordResetTwoFactorConfigurationResolver
            .AvailableFromMethods(methods, PasswordResetBootstrapProof.EmailResetToken)
            .ShouldBe(expected);
    }

    public static TheoryData<List<TwoFactorAuthMethod>, List<TwoFactorAuthConfiguration>> EmailBootstrapCases()
    {
        return new TheoryData<List<TwoFactorAuthMethod>, List<TwoFactorAuthConfiguration>>
        {
            { [], [] },
            { [TwoFactorAuthMethod.EMAIL], [] },
            { [TwoFactorAuthMethod.SMS_KEY], [TwoFactorAuthConfiguration.SMS] },
            { [TwoFactorAuthMethod.AUTHENTICATOR_APP], [TwoFactorAuthConfiguration.AUTHENTICATOR_APP] },
            { [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.EMAIL], [TwoFactorAuthConfiguration.SMS] },
            { [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP], [TwoFactorAuthConfiguration.AUTHENTICATOR_APP] },
            { [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP], [TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP] },
            { [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP], [TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP] }
        };
    }

    [Fact]
    public void Email_reset_bootstrap_never_advertises_email_only_or_email_authenticator_combo()
    {
        List<TwoFactorAuthConfiguration> available = PasswordResetTwoFactorConfigurationResolver.AvailableFromMethods(
            [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP],
            PasswordResetBootstrapProof.EmailResetToken);

        available.ShouldNotContain(TwoFactorAuthConfiguration.EMAIL);
        available.ShouldNotContain(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP);
        available.ShouldBe([
            TwoFactorAuthConfiguration.SMS,
            TwoFactorAuthConfiguration.AUTHENTICATOR_APP,
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP]);
    }

    [Fact]
    public void Email_reset_bootstrap_preserves_sms_after_authenticator_removal()
    {
        PasswordResetTwoFactorConfigurationResolver
            .AvailableFromMethods([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.EMAIL], PasswordResetBootstrapProof.EmailResetToken)
            .ShouldBe([TwoFactorAuthConfiguration.SMS]);
    }

    [Fact]
    public void Email_reset_bootstrap_preserves_authenticator_after_sms_removal()
    {
        PasswordResetTwoFactorConfigurationResolver
            .AvailableFromMethods([TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP], PasswordResetBootstrapProof.EmailResetToken)
            .ShouldBe([TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);
    }

    [Fact]
    public void Email_reset_bootstrap_ignores_none_and_duplicates()
    {
        PasswordResetTwoFactorConfigurationResolver
            .AvailableFromMethods([
                TwoFactorAuthMethod.NONE,
                TwoFactorAuthMethod.EMAIL,
                TwoFactorAuthMethod.SMS_KEY,
                TwoFactorAuthMethod.SMS_KEY,
                TwoFactorAuthMethod.AUTHENTICATOR_APP], PasswordResetBootstrapProof.EmailResetToken)
            .ShouldBe([
                TwoFactorAuthConfiguration.SMS,
                TwoFactorAuthConfiguration.AUTHENTICATOR_APP,
                TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP]);
    }

    [Fact]
    public void Account_snapshot_overload_maps_verified_flags_to_email_bootstrap_options()
    {
        PasswordResetTwoFactorConfigurationResolver
            .AvailableFromAccountSnapshot(
                emailVerified: true,
                smsVerified: true,
                authenticatorVerified: true,
                bootstrapProof: PasswordResetBootstrapProof.EmailResetToken)
            .ShouldBe([
                TwoFactorAuthConfiguration.SMS,
                TwoFactorAuthConfiguration.AUTHENTICATOR_APP,
                TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP]);
    }

    [Fact]
    public void Admin_bootstrap_keeps_login_style_options_because_no_user_factor_was_bootstrapped()
    {
        PasswordResetTwoFactorConfigurationResolver
            .AvailableFromMethods([
                TwoFactorAuthMethod.SMS_KEY,
                TwoFactorAuthMethod.EMAIL,
                TwoFactorAuthMethod.AUTHENTICATOR_APP], PasswordResetBootstrapProof.AdminIssuedToken)
            .ShouldBe([
                TwoFactorAuthConfiguration.SMS,
                TwoFactorAuthConfiguration.EMAIL,
                TwoFactorAuthConfiguration.AUTHENTICATOR_APP,
                TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP,
                TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP]);
    }

    [Fact]
    public void Sms_reset_bootstrap_excludes_sms_based_options_for_future_sms_bootstrap_support()
    {
        PasswordResetTwoFactorConfigurationResolver
            .AvailableFromMethods([
                TwoFactorAuthMethod.SMS_KEY,
                TwoFactorAuthMethod.EMAIL,
                TwoFactorAuthMethod.AUTHENTICATOR_APP], PasswordResetBootstrapProof.SmsResetToken)
            .ShouldBe([
                TwoFactorAuthConfiguration.EMAIL,
                TwoFactorAuthConfiguration.AUTHENTICATOR_APP,
                TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP]);
    }

    [Fact]
    public void Password_reset_bootstrap_proof_enum_values_are_stable_for_api_and_sql_contracts()
    {
        ((short)PasswordResetBootstrapProof.None).ShouldBe((short)0);
        ((short)PasswordResetBootstrapProof.EmailResetToken).ShouldBe((short)1);
        ((short)PasswordResetBootstrapProof.SmsResetToken).ShouldBe((short)2);
        ((short)PasswordResetBootstrapProof.AdminIssuedToken).ShouldBe((short)3);
    }
}
