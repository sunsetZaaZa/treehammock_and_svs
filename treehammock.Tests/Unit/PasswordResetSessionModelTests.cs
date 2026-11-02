using NodaTime;
using Shouldly;

using treehammock.DataLayer.Cache;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Tests.Unit;

public sealed class PasswordResetSessionModelTests
{
    [Fact]
    public void Constructor_starts_in_selection_required_when_reset_eligible_options_exist()
    {
        var session = BuildEmailBootstrapSession([
            TwoFactorAuthMethod.SMS_KEY,
            TwoFactorAuthMethod.EMAIL,
            TwoFactorAuthMethod.AUTHENTICATOR_APP]);

        session.bootstrapProof.ShouldBe(PasswordResetBootstrapProof.EmailResetToken);
        session.state.ShouldBe(PasswordResetSessionState.TwoFactorSelectionRequired);
        session.isSelectionRequired.ShouldBeTrue();
        session.requiresTwoFactor.ShouldBeTrue();
        session.canChangePassword.ShouldBeFalse();
        session.selectedConfiguration.ShouldBeNull();
        session.requiredMethods.ShouldBeEmpty();
        session.completedMethods.ShouldBeEmpty();
        session.currentExpectedMethod.ShouldBeNull();
        session.remainingMethods.ShouldBeEmpty();
        session.availableConfigurationsSnapshot.ShouldBe([
            TwoFactorAuthConfiguration.SMS,
            TwoFactorAuthConfiguration.AUTHENTICATOR_APP,
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP]);
    }

    [Fact]
    public void Constructor_allows_password_change_after_token_verification_when_no_reset_eligible_options_exist()
    {
        var session = BuildEmailBootstrapSession([TwoFactorAuthMethod.EMAIL]);

        session.state.ShouldBe(PasswordResetSessionState.ResetTokenVerified);
        session.requiresTwoFactor.ShouldBeFalse();
        session.isSelectionRequired.ShouldBeFalse();
        session.canChangePassword.ShouldBeTrue();
        session.availableConfigurationsSnapshot.ShouldBeEmpty();
    }

    [Fact]
    public void SelectConfiguration_records_ordered_required_methods_and_first_expected_proof()
    {
        var now = Instant.FromUtc(2026, 5, 21, 18, 0);
        var session = BuildEmailBootstrapSession([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);

        session.SelectConfiguration(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, now);

        session.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        session.selectedAt.ShouldBe(now);
        session.state.ShouldBe(PasswordResetSessionState.AwaitingSmsCode);
        session.requiredMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.completedMethods.ShouldBeEmpty();
        session.currentExpectedMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        session.remainingMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.requiredProofCount.ShouldBe(2);
        session.completedProofCount.ShouldBe(0);
        session.canChangePassword.ShouldBeFalse();
    }

    [Fact]
    public void SelectConfiguration_rejects_configuration_not_in_reset_snapshot()
    {
        var session = BuildEmailBootstrapSession([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.EMAIL]);

        Should.Throw<ArgumentException>(() => session.SelectConfiguration(
            TwoFactorAuthConfiguration.EMAIL,
            Instant.FromUtc(2026, 5, 21, 18, 0)));
    }

    [Fact]
    public void StartChallenge_sets_challenge_state_for_current_expected_method()
    {
        var now = Instant.FromUtc(2026, 5, 21, 18, 0);
        var session = BuildEmailBootstrapSession([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.SelectConfiguration(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, now);

        session.StartChallenge(" sms-code-hash ", now.Plus(Duration.FromMinutes(2)), now.Plus(Duration.FromSeconds(30)));

        session.IsCurrentlyExpecting(TwoFactorAuthMethod.SMS_KEY).ShouldBeTrue();
        session.state.ShouldBe(PasswordResetSessionState.AwaitingSmsCode);
        session.challengeCodeHash.ShouldBe("sms-code-hash");
        session.challengeExpiration.ShouldBe(now.Plus(Duration.FromMinutes(2)));
        session.nextChallengeAllowedAt.ShouldBe(now.Plus(Duration.FromSeconds(30)));
        session.challengeAttempts.ShouldBe(0);
        session.challengeResends.ShouldBe(1);
    }

    [Fact]
    public void Proof_progression_tracks_completed_and_remaining_methods_until_two_factor_complete()
    {
        var now = Instant.FromUtc(2026, 5, 21, 18, 0);
        var session = BuildEmailBootstrapSession([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.SelectConfiguration(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, now);
        session.StartChallenge("sms-code-hash", now.Plus(Duration.FromMinutes(2)), now.Plus(Duration.FromSeconds(30)));

        session.MarkCurrentProofAccepted();

        session.completedMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY]);
        session.remainingMethods.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.currentExpectedMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        session.state.ShouldBe(PasswordResetSessionState.AwaitingAuthenticatorCode);
        session.completedProofCount.ShouldBe(1);
        session.canChangePassword.ShouldBeFalse();
        session.challengeCodeHash.ShouldBeNull();

        session.MarkCurrentProofAccepted();
        session.MarkTwoFactorComplete(now.Plus(Duration.FromMinutes(1)));

        session.state.ShouldBe(PasswordResetSessionState.TwoFactorComplete);
        session.isTwoFactorComplete.ShouldBeTrue();
        session.canChangePassword.ShouldBeTrue();
        session.remainingMethods.ShouldBeEmpty();
        session.currentExpectedMethod.ShouldBeNull();
        session.twoFactorCompletedAt.ShouldBe(now.Plus(Duration.FromMinutes(1)));
    }

    [Fact]
    public void MarkPasswordChanged_requires_verified_token_or_completed_two_factor()
    {
        var now = Instant.FromUtc(2026, 5, 21, 18, 0);
        var session = BuildEmailBootstrapSession([TwoFactorAuthMethod.SMS_KEY]);

        Should.Throw<InvalidOperationException>(() => session.MarkPasswordChanged(now));

        session.SelectConfiguration(TwoFactorAuthConfiguration.SMS, now);
        session.MarkCurrentProofAccepted();
        session.MarkTwoFactorComplete(now.Plus(Duration.FromSeconds(30)));
        session.MarkPasswordChanged(now.Plus(Duration.FromMinutes(1)));

        session.state.ShouldBe(PasswordResetSessionState.PasswordChanged);
        session.isPasswordChanged.ShouldBeTrue();
        session.passwordChangedAt.ShouldBe(now.Plus(Duration.FromMinutes(1)));
    }

    [Fact]
    public void MarkPasswordChanged_allows_no_eligible_2fa_reset_after_token_verification()
    {
        var now = Instant.FromUtc(2026, 5, 21, 18, 0);
        var session = BuildEmailBootstrapSession([TwoFactorAuthMethod.EMAIL]);

        session.MarkPasswordChanged(now);

        session.state.ShouldBe(PasswordResetSessionState.PasswordChanged);
        session.passwordChangedAt.ShouldBe(now);
    }

    [Theory]
    [InlineData(TwoFactorAuthConfiguration.SMS, new[] { TwoFactorAuthMethod.SMS_KEY })]
    [InlineData(TwoFactorAuthConfiguration.EMAIL, new[] { TwoFactorAuthMethod.EMAIL })]
    [InlineData(TwoFactorAuthConfiguration.AUTHENTICATOR_APP, new[] { TwoFactorAuthMethod.AUTHENTICATOR_APP })]
    [InlineData(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, new[] { TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP })]
    [InlineData(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP, new[] { TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP })]
    public void RequiredMethodsForConfiguration_uses_strict_reset_proof_order(
        TwoFactorAuthConfiguration configuration,
        TwoFactorAuthMethod[] expected)
    {
        PasswordResetSession.RequiredMethodsForConfiguration(configuration).ShouldBe(expected.ToList());
    }

    [Fact]
    public void Password_reset_session_state_enum_values_are_stable_for_sql_and_api_contracts()
    {
        ((short)PasswordResetSessionState.ResetTokenIssued).ShouldBe((short)1);
        ((short)PasswordResetSessionState.ResetTokenVerified).ShouldBe((short)2);
        ((short)PasswordResetSessionState.TwoFactorSelectionRequired).ShouldBe((short)3);
        ((short)PasswordResetSessionState.AwaitingSmsCode).ShouldBe((short)4);
        ((short)PasswordResetSessionState.AwaitingEmailCode).ShouldBe((short)5);
        ((short)PasswordResetSessionState.AwaitingAuthenticatorCode).ShouldBe((short)6);
        ((short)PasswordResetSessionState.TwoFactorComplete).ShouldBe((short)7);
        ((short)PasswordResetSessionState.PasswordChanged).ShouldBe((short)8);
        ((short)PasswordResetSessionState.Expired).ShouldBe((short)9);
        ((short)PasswordResetSessionState.Failed).ShouldBe((short)10);
    }

    private static PasswordResetSession BuildEmailBootstrapSession(List<TwoFactorAuthMethod> methods)
    {
        return new PasswordResetSession(
            Guid.Parse("33333333-3333-3333-3333-333333333333"),
            " reset-access-token-hash ",
            methods,
            PasswordResetBootstrapProof.EmailResetToken,
            Instant.FromUtc(2026, 5, 21, 18, 0),
            Instant.FromUtc(2026, 5, 21, 18, 10));
    }
}
