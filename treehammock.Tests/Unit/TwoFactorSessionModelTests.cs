using NodaTime;
using Shouldly;

using treehammock.DataLayer.Cache;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Tests.Unit;

public class TwoFactorSessionModelTests
{
    [Fact]
    public void Constructor_starts_in_selection_required_state_with_available_configuration_snapshot()
    {
        var session = BuildSession([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);

        session.isSelectionRequired.ShouldBeTrue();
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
    public void SelectConfiguration_records_ordered_required_methods_and_first_expected_proof()
    {
        var session = BuildSession([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);

        session.SelectConfiguration(
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP,
            [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);

        session.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        session.state.ShouldBe(TwoFactorSessionState.AwaitingSmsCode);
        session.requiredMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.completedMethods.ShouldBeEmpty();
        session.currentExpectedMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        session.remainingMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.requiredProofCount.ShouldBe((short)2);
        session.completedProofCount.ShouldBe((short)0);
    }

    [Fact]
    public void SelectConfiguration_rejects_unavailable_configuration()
    {
        var session = BuildSession([TwoFactorAuthMethod.SMS_KEY]);

        Should.Throw<ArgumentException>(() => session.SelectConfiguration(
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP,
            [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]));
    }

    [Fact]
    public void Proof_progression_tracks_completed_and_remaining_methods()
    {
        var session = BuildSession([TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.SelectConfiguration(
            TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP,
            [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP]);

        session.MarkCurrentProofAccepted();
        session.SetCurrentExpectedMethod(session.NextRequiredMethod());

        session.completedMethods.ShouldBe([TwoFactorAuthMethod.EMAIL]);
        session.remainingMethods.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.currentExpectedMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        session.state.ShouldBe(TwoFactorSessionState.AwaitingAuthenticatorCode);
        session.completedProofCount.ShouldBe((short)1);

        session.MarkCurrentProofAccepted();
        session.NextRequiredMethod().ShouldBeNull();
        session.MarkComplete();

        session.isComplete.ShouldBeTrue();
        session.remainingMethods.ShouldBeEmpty();
        session.currentExpectedMethod.ShouldBeNull();
        session.state.ShouldBe(TwoFactorSessionState.Complete);
    }

    [Fact]
    public void StartChallenge_sets_current_challenge_without_losing_selected_configuration()
    {
        var now = Instant.FromUtc(2026, 5, 21, 18, 0);
        var session = BuildSession([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.SelectConfiguration(
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP,
            [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);

        session.StartChallenge(
            TwoFactorAuthMethod.SMS_KEY,
            0,
            now.Plus(Duration.FromMinutes(2)),
            now.Plus(Duration.FromSeconds(30)));

        session.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        session.state.ShouldBe(TwoFactorSessionState.AwaitingSmsCode);
        session.challengedMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        session.chosenDestination.ShouldBe((short)0);
        session.challengeExpiration.ShouldBe(now.Plus(Duration.FromMinutes(2)));
        session.nextChallengeAllowedAt.ShouldBe(now.Plus(Duration.FromSeconds(30)));
        session.challengeAttempts.ShouldBe((short)0);
        session.challengeResends.ShouldBe((short)1);
    }

    [Fact]
    public void ClearIssuedChallengeState_resets_challenge_but_preserves_selected_flow()
    {
        var now = Instant.FromUtc(2026, 5, 21, 18, 0);
        var session = BuildSession([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.SelectConfiguration(
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP,
            [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.StartChallenge(
            TwoFactorAuthMethod.SMS_KEY,
            0,
            now.Plus(Duration.FromMinutes(2)),
            now.Plus(Duration.FromSeconds(30)));
        session.challengeCodeHash = "code-hash";
        session.intraCodeKey = "code-hash";
        session.challengeProviderTransactionId = "provider-transaction";

        session.ClearIssuedChallengeState(now.Plus(Duration.FromMinutes(1)), 2, 3, now.Plus(Duration.FromSeconds(45)));

        session.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        session.requiredMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.currentExpectedMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        session.challengedMethod.ShouldBeNull();
        session.chosenDestination.ShouldBeNull();
        session.challengeCodeHash.ShouldBeNull();
        session.intraCodeKey.ShouldBeNull();
        session.challengeProviderTransactionId.ShouldBeNull();
        session.challengeExpiration.ShouldBe(now.Plus(Duration.FromMinutes(1)));
        session.challengeAttempts.ShouldBe((short)2);
        session.challengeResends.ShouldBe((short)3);
        session.nextChallengeAllowedAt.ShouldBe(now.Plus(Duration.FromSeconds(45)));
    }

    private static TwoFactorSession BuildSession(List<TwoFactorAuthMethod> methods)
    {
        return new TwoFactorSession(
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            "web-key",
            [9, 8, 7, 6],
            methods,
            methods.Contains(TwoFactorAuthMethod.AUTHENTICATOR_APP) ? ["authenticator-app-user"] : null,
            methods.Contains(TwoFactorAuthMethod.SMS_KEY) ? ["4045550100"] : null,
            methods.Contains(TwoFactorAuthMethod.SMS_KEY) ? ["1"] : null,
            methods.Contains(TwoFactorAuthMethod.EMAIL) ? ["reader@example.com"] : null,
            null,
            null,
            methods.Contains(TwoFactorAuthMethod.AUTHENTICATOR_APP) ? (short)1 : (short)0,
            0,
            methods.Contains(TwoFactorAuthMethod.SMS_KEY) ? (short)1 : (short)0,
            Instant.FromUtc(2026, 5, 21, 18, 0),
            Instant.FromUtc(2026, 5, 21, 18, 2),
            FeatureSet.basic,
            null,
            Guid.Parse("55555555-5555-5555-5555-555555555555"));
    }
}
