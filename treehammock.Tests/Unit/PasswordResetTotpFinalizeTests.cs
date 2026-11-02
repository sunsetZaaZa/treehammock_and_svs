using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;

using treehammock.DataLayer.Cache;
using treehammock.Models.PasswordReset;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class PasswordResetTotpFinalizeTests
{
    [Fact]
    public async Task VerifyResetToken_returns_selection_required_when_email_reset_requires_totp()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true, method: PasswordResetDeliveryChannels.Email);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetVerifyResult result = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.TwoFactorSelectionRequiredCode);
        result.StatusCode.ShouldBe(StatusCodes.Status200OK);
        result.Status.ShouldBe("two_factor_selection_required");
        result.ResetAccessToken.ShouldNotBeNull();
        result.ResetAccessToken!.ShouldStartWith(resetId.ToString("N") + ".");
        result.RequiresTwoFactor.ShouldBeTrue();
        result.AvailableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task VerifyResetToken_returns_verified_when_no_reset_eligible_2fa_exists()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: false, method: PasswordResetDeliveryChannels.Email);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetVerifyResult result = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.TokenVerifiedCode);
        result.StatusCode.ShouldBe(StatusCodes.Status200OK);
        result.Status.ShouldBe("verified");
        result.ResetAccessToken.ShouldNotBeNull();
        result.RequiresTwoFactor.ShouldBeFalse();
        result.AvailableTwoFactorAuthConfigurations.ShouldBeEmpty();
    }

    [Fact]
    public async Task SelectTwoFactorConfiguration_persists_authenticator_session_when_reset_access_token_is_valid()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true, method: PasswordResetDeliveryChannels.Email);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);
        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        PasswordResetTwoFactorSelectResult selected = await harness.Service.SelectTwoFactorConfiguration(
            new SelectPasswordResetTwoFactorConfigurationCommand(verified.ResetAccessToken!, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, null, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        selected.Code.ShouldBe(PasswordResetService.TwoFactorAuthenticatorCodeRequiredCode);
        selected.StatusCode.ShouldBe(StatusCodes.Status200OK);
        selected.Status.ShouldBe("authenticator_code_required");
        selected.ResetAccessToken.ShouldBe(verified.ResetAccessToken);
        selected.SelectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        selected.CurrentRequiredMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        selected.CompletedTwoFactorAuthMethods.ShouldBeEmpty();
        selected.RemainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        selected.AvailableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);
        selected.CanChangePassword.ShouldBeFalse();
        await harness.PasswordResetSessionService.Received(1).TransitionSession(
            AccessTokenHashUtility.Hash(verified.ResetAccessToken!),
            Arg.Is<PasswordResetSession>(session =>
                session.accountId == accountId
                && session.selectedConfiguration == TwoFactorAuthConfiguration.AUTHENTICATOR_APP
                && session.currentExpectedMethod == TwoFactorAuthMethod.AUTHENTICATOR_APP
                && session.state == PasswordResetSessionState.AwaitingAuthenticatorCode),
            Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SelectTwoFactorConfiguration_rejects_configuration_not_in_verified_snapshot()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true, method: PasswordResetDeliveryChannels.Email);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        PasswordResetTwoFactorSelectResult selected = await harness.Service.SelectTwoFactorConfiguration(
            new SelectPasswordResetTwoFactorConfigurationCommand(verified.ResetAccessToken!, TwoFactorAuthConfiguration.SMS, null, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        selected.Code.ShouldBe(PasswordResetService.TwoFactorConfigurationNotAvailableCode);
        selected.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        selected.AvailableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);
        await harness.PasswordResetSessionService.DidNotReceive().TransitionSession(Arg.Any<string>(), Arg.Is<PasswordResetSession>(s => s.transition == PasswordResetTransition.Select), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SelectTwoFactorConfiguration_rejects_tampered_reset_access_token()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true, method: PasswordResetDeliveryChannels.Email);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        string tamperedToken = verified.ResetAccessToken![..^1] + (verified.ResetAccessToken.EndsWith("0", StringComparison.Ordinal) ? "1" : "0");
        PasswordResetTwoFactorSelectResult selected = await harness.Service.SelectTwoFactorConfiguration(
            new SelectPasswordResetTwoFactorConfigurationCommand(tamperedToken, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, null, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        selected.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        selected.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        await harness.PasswordResetSessionService.DidNotReceive().TransitionSession(Arg.Any<string>(), Arg.Is<PasswordResetSession>(s => s.transition == PasswordResetTransition.Select), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyResetToken_registers_failed_attempt_when_key_code_is_wrong()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "00000000", "stored-hash").Returns(false);
        harness.Repo.RegisterFailedAttemptAsync(resetId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new RegisterPasswordResetFailedAttemptResult(
                true,
                "PASSWORD_RESET_ATTEMPT_RECORDED",
                accountId,
                1,
                5,
                null)));

        PasswordResetVerifyResult result = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "00000000", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        result.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        result.ResetAccessToken.ShouldBeNull();
        result.RequiresTwoFactor.ShouldBeFalse();
        await harness.Repo.Received(1).RegisterFailedAttemptAsync(resetId, Arg.Any<Instant>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task FinalizeReset_requires_reset_twofactor_flow_when_mock_totp_reset_has_verified_key_code()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", null, "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.TwoFactorRequiredCode);
        result.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
        await harness.Repo.DidNotReceiveWithAnyArgs().RegisterFailedAttemptAsync(default, default, default);
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task FinalizeReset_rejects_mock_totp_proof_even_when_totp_code_is_supplied()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", "123456", "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.TwoFactorRequiredCode);
        result.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
        await harness.Repo.DidNotReceiveWithAnyArgs().RegisterFailedAttemptAsync(default, default, default);
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task FinalizeReset_promotes_password_when_reset_access_token_session_is_complete()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);
        harness.AllowPromotion(resetId, accountId);

        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);
        string resetAccessTokenHash = AccessTokenHashUtility.Hash(verified.ResetAccessToken!);
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var session = new PasswordResetSession(
            accountId,
            resetAccessTokenHash,
            PasswordResetBootstrapProof.EmailResetToken,
            [TwoFactorAuthConfiguration.AUTHENTICATOR_APP],
            now,
            now.Plus(Duration.FromMinutes(10)));
        session.SelectConfiguration(TwoFactorAuthConfiguration.AUTHENTICATOR_APP, now);
        session.MarkCurrentProofAccepted();
        session.MarkTwoFactorComplete(now);
        harness.PasswordResetSessionService.GetSession(resetAccessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetSession?>(session));
        harness.PasswordResetSessionService.RevokeSession(resetAccessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(Guid.Empty, null, null, "new-password", "new-password", "192.0.2.10", "unit-test", verified.ResetAccessToken),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.CompletedCode);
        result.StatusCode.ShouldBe(StatusCodes.Status200OK);
        await harness.Repo.DidNotReceiveWithAnyArgs().RegisterFailedAttemptAsync(default, default, default);
        await harness.Repo.Received(1).PromotePasswordResetAsync(
            Arg.Is<PromotePasswordResetDbCommand>(command =>
                command.PasswordResetRequestId == resetId
                && command.AccountId == accountId
                && command.HashedPassword.Length == AccountCryptoSizes.PasswordHashBytes
                && command.SaltOne.Length == AccountCryptoSizes.SaltOneBytes
                && command.Siv.Length == AccountCryptoSizes.SivBytes
                && command.Nonce.Length == AccountCryptoSizes.NonceBytes),
            Arg.Any<CancellationToken>());
        await harness.PasswordResetSessionService.Received(1).RevokeSession(resetAccessTokenHash, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task FinalizeReset_rejects_reset_access_token_until_reset_twofactor_session_is_complete()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);
        string resetAccessTokenHash = AccessTokenHashUtility.Hash(verified.ResetAccessToken!);
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var session = new PasswordResetSession(
            accountId,
            resetAccessTokenHash,
            PasswordResetBootstrapProof.EmailResetToken,
            [TwoFactorAuthConfiguration.AUTHENTICATOR_APP],
            now,
            now.Plus(Duration.FromMinutes(10)));
        session.SelectConfiguration(TwoFactorAuthConfiguration.AUTHENTICATOR_APP, now);
        harness.PasswordResetSessionService.GetSession(resetAccessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetSession?>(session));

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(Guid.Empty, null, null, "new-password", "new-password", "192.0.2.10", "unit-test", verified.ResetAccessToken),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.TwoFactorNotCompleteCode);
        result.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task FinalizeReset_does_not_require_totp_for_non_totp_reset()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: false);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);
        harness.AllowPromotion(resetId, accountId);

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", null, "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.CompletedCode);
        result.StatusCode.ShouldBe(StatusCodes.Status200OK);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
    }

    [Fact]
    public async Task FinalizeReset_registers_failed_attempt_when_key_code_is_wrong()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "00000000", "stored-hash").Returns(false);
        harness.Repo.RegisterFailedAttemptAsync(resetId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new RegisterPasswordResetFailedAttemptResult(
                false,
                PasswordResetService.AttemptsExceededCode,
                accountId,
                5,
                5,
                SystemClock.Instance.GetCurrentInstant())));

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "00000000", "123456", "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        result.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
    }


    [Fact]
    public async Task FinalizeReset_rejects_mock_totp_only_reset_without_key_code_requirement()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(
            resetId,
            accountId,
            method: "authenticator_app_totp",
            requiresKeyCode: false,
            requiresTotp: true,
            deliveryChannel: null,
            keyCodeHash: null);
        harness.Repo.RegisterFailedAttemptAsync(resetId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new RegisterPasswordResetFailedAttemptResult(
                true,
                "PASSWORD_RESET_ATTEMPT_RECORDED",
                accountId,
                1,
                5,
                null)));

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, null, "123456", "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        result.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        harness.Hasher.DidNotReceiveWithAnyArgs().VerifyCode(default, default!, default!);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
        await harness.Repo.Received(1).RegisterFailedAttemptAsync(resetId, Arg.Any<Instant>(), Arg.Any<CancellationToken>());
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task FinalizeReset_requires_key_code_when_reset_row_requires_key_code()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: false);

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, null, null, "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.ValidationFailedCode);
        result.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        harness.Hasher.DidNotReceiveWithAnyArgs().VerifyCode(default, default!, default!);
        await harness.Repo.DidNotReceiveWithAnyArgs().RegisterFailedAttemptAsync(default, default, default);
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task FinalizeReset_rejects_password_that_fails_configured_length_policy_before_promotion()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: false);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", null, "short", "short", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.ValidationFailedCode);
        result.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task FinalizeReset_throttles_per_reset_id_before_lookup()
    {
        Harness harness = CreateHarness();
        harness.AbuseControlSettings.PasswordReset.Enabled = true;
        Guid resetId = Guid.NewGuid();
        harness.AbuseCounterStore.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key =>
                    key.Feature == AbuseFeature.PasswordResetFinalize
                    && key.Dimension == AbuseCounterDimension.Reset),
                Arg.Any<AbuseCounterLimit>(),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    false,
                    limit.MaxAttempts + 1,
                    limit.MaxAttempts,
                    limit.Window,
                    TimeSpan.FromMinutes(15),
                    AbuseReasonCodes.PasswordResetFinalizeThrottleExceeded));
            });

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", "123456", "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        result.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        await harness.Repo.DidNotReceiveWithAnyArgs().GetPasswordResetRequestForFinalizeAsync(default, default);
        harness.Hasher.DidNotReceiveWithAnyArgs().VerifyCode(default, default!, default!);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
    }

    [Fact]
    public async Task FinalizeReset_fails_closed_before_lookup_when_abuse_counter_store_is_unavailable()
    {
        Harness harness = CreateHarness();
        harness.AbuseControlSettings.PasswordReset.Enabled = true;
        Guid resetId = Guid.NewGuid();
        harness.AbuseCounterStore.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key =>
                    key.Feature == AbuseFeature.PasswordResetFinalize
                    && key.Dimension == AbuseCounterDimension.Reset),
                Arg.Any<AbuseCounterLimit>(),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    false,
                    0,
                    limit.MaxAttempts,
                    limit.Window,
                    null,
                    AbuseReasonCodes.CounterStoreUnavailable));
            });

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", "123456", "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.AbuseCounterUnavailableCode);
        result.StatusCode.ShouldBe(StatusCodes.Status503ServiceUnavailable);
        await harness.Repo.DidNotReceiveWithAnyArgs().GetPasswordResetRequestForFinalizeAsync(default, default);
        harness.Hasher.DidNotReceiveWithAnyArgs().VerifyCode(default, default!, default!);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
    }

    [Fact]
    public async Task FinalizeReset_preserves_shared_finalize_budget_after_successful_promotion()
    {
        Harness harness = CreateHarness();
        harness.AbuseControlSettings.PasswordReset.Enabled = true;
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: false);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);
        harness.AllowPromotion(resetId, accountId);

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", null, "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.CompletedCode);
        result.StatusCode.ShouldBe(StatusCodes.Status200OK);
        await harness.AbuseCounterStore.DidNotReceiveWithAnyArgs().ResetAsync(default!, default);
    }

    [Fact]
    public async Task FinalizeReset_abuse_limit_uses_configured_attempt_window_and_cooldown()
    {
        Harness harness = CreateHarness();
        harness.AbuseControlSettings.PasswordReset.Enabled = true;
        harness.AbuseControlSettings.PasswordReset.MaxFinalizeAttemptsPerResetId = 7;
        harness.AbuseControlSettings.PasswordReset.FinalizeAttemptWindowSeconds = 1200;
        harness.AbuseControlSettings.PasswordReset.CooldownSecondsAfterExhaustion = 1800;
        Guid resetId = Guid.NewGuid();
        AbuseCounterLimit? capturedLimit = null;
        harness.AbuseCounterStore.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.PasswordResetFinalize),
                Arg.Do<AbuseCounterLimit>(limit => capturedLimit = limit),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(true, 1, limit.MaxAttempts, limit.Window, null, null));
            });
        harness.Repo.GetPasswordResetRequestForFinalizeAsync(resetId, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetFinalizeRecord?>(new PasswordResetFinalizeRecord(
                false,
                PasswordResetService.AttemptsExceededCode,
                resetId,
                Guid.NewGuid(),
                PasswordResetDeliveryChannels.Email,
                "email",
                "stored-hash",
                1,
                true,
                false,
                SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),
                null,
                null,
                7,
                7,
                Guid.NewGuid())));

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", null, "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        capturedLimit.ShouldNotBeNull();
        capturedLimit!.MaxAttempts.ShouldBe(7);
        capturedLimit.Window.ShouldBe(TimeSpan.FromSeconds(1200));
        capturedLimit.Cooldown.ShouldBe(TimeSpan.FromSeconds(1800));
    }

    [Theory]
    [InlineData(PasswordResetTotpVerifier.EnrollmentUnavailableCode)]
    [InlineData(PasswordResetTotpVerifier.SecretUnavailableCode)]
    [InlineData(PasswordResetTotpVerifier.StepMarkFailedCode)]
    public async Task Cor03_reset_dependency_fault_does_not_change_pending_attempts_or_failed_proof_count(string code)
    {
        Harness harness = CreateHarness(); Guid resetId = Guid.NewGuid(); Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);
        var verified = await harness.Service.VerifyResetToken(new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "test"), CancellationToken.None);
        string hash = AccessTokenHashUtility.Hash(verified.ResetAccessToken!); Instant now = SystemClock.Instance.GetCurrentInstant();
        var session = new PasswordResetSession(accountId, hash, PasswordResetBootstrapProof.EmailResetToken,
            [TwoFactorAuthConfiguration.AUTHENTICATOR_APP], now, now.Plus(Duration.FromMinutes(10)));
        session.SelectConfiguration(TwoFactorAuthConfiguration.AUTHENTICATOR_APP, now);
        harness.PasswordResetSessionService.GetSession(hash, Arg.Any<CancellationToken>()).Returns(Task.FromResult<PasswordResetSession?>(session));
        harness.TotpVerifier.VerifyTotpForPasswordReset(accountId, "123456", Arg.Any<CancellationToken>()).Returns(Task.FromResult(PasswordResetTotpVerificationResult.Failed(code)));
        harness.Repo.RegisterFailedAttemptAsync(resetId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new(true, "FAILED_PROOF_RECORDED", accountId, 1, 5, null)));
        var result = await harness.Service.VerifyTwoFactorProof(new VerifyPasswordResetTwoFactorCommand(verified.ResetAccessToken!, TwoFactorAuthMethod.AUTHENTICATOR_APP, "123456", "192.0.2.10", "test"), CancellationToken.None);
        result.StatusCode.ShouldBe(503);
        session.canChangePassword.ShouldBeFalse();
        await harness.Repo.DidNotReceiveWithAnyArgs().RegisterFailedAttemptAsync(default, default, default);
        await harness.PasswordResetSessionService.DidNotReceive().TransitionSession(Arg.Any<string>(), Arg.Is<PasswordResetSession>(s => s.transition == PasswordResetTransition.ValidProof || s.transition == PasswordResetTransition.InvalidProof), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.PasswordResetSessionService.DidNotReceiveWithAnyArgs().RevokeSession(default!, default);
    }

    [Fact]
    public async Task Cor03_pending_session_outage_does_not_revoke_or_debit()
    {
        Harness harness = CreateHarness(); Guid resetId = Guid.NewGuid(); Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);
        var verified = await harness.Service.VerifyResetToken(new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "test"), CancellationToken.None);
        harness.PasswordResetSessionService.GetSession(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(_ =>
            Task.FromException<PasswordResetSession?>(treehammock.Rigging.Dependencies.DependencyUnavailableException.Database("pending_reset", treehammock.Rigging.Dependencies.DependencyStage.Acquire)));
        await Should.ThrowAsync<treehammock.Rigging.Dependencies.DependencyUnavailableException>(() => harness.Service.VerifyTwoFactorProof(
            new VerifyPasswordResetTwoFactorCommand(verified.ResetAccessToken!, TwoFactorAuthMethod.AUTHENTICATOR_APP, "123456", "192.0.2.10", "test"), CancellationToken.None));
        await harness.Repo.DidNotReceiveWithAnyArgs().RegisterFailedAttemptAsync(default, default, default);
        await harness.PasswordResetSessionService.DidNotReceiveWithAnyArgs().RevokeSession(default!, default);
    }

    [Fact]
    public async Task Cor03_reset_token_secret_failure_does_not_debit_or_revoke_pending_state()
    {
        var settings = Settings(); var harness = CreateHarness(settings); Guid resetId = Guid.NewGuid(); Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);
        var verified = await harness.Service.VerifyResetToken(new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "test"), CancellationToken.None);
        settings.CodeHashPepper = "";
        await Should.ThrowAsync<treehammock.Rigging.Dependencies.DependencyUnavailableException>(() => harness.Service.VerifyTwoFactorProof(
            new VerifyPasswordResetTwoFactorCommand(verified.ResetAccessToken!, TwoFactorAuthMethod.AUTHENTICATOR_APP, "123456", "192.0.2.10", "test"), CancellationToken.None));
        await harness.Repo.DidNotReceiveWithAnyArgs().RegisterFailedAttemptAsync(default, default, default);
        await harness.PasswordResetSessionService.DidNotReceiveWithAnyArgs().RevokeSession(default!, default);
    }

    [Theory]
    [InlineData((short)1)]
    [InlineData((short)2)]
    public async Task Cor13_destination_indices_beyond_saved_destination_are_rejected(short destination)
    {
        var harness = CreateHarness();
        var result = await harness.Service.SelectTwoFactorConfiguration(new SelectPasswordResetTwoFactorConfigurationCommand(
            "unused-token", TwoFactorAuthConfiguration.SMS, destination, null, null), CancellationToken.None);
        result.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        await harness.Repo.DidNotReceiveWithAnyArgs().GetPasswordResetRequestForFinalizeAsync(default, default);
    }

    [Theory]
    [InlineData(null)]
    [InlineData((short)0)]
    public async Task Cor13_omitted_or_zero_destination_selects_the_saved_factor(short? destination)
    {
        var harness=CreateHarness();var id=Guid.NewGuid();var account=Guid.NewGuid();
        harness.ReadyReset(id,account,requiresTotp:true);harness.Hasher.VerifyCode(id,"49382710","stored-hash").Returns(true);
        var verified=await harness.Service.VerifyResetToken(new(id,"49382710",null,null),CancellationToken.None);
        var selected=await harness.Service.SelectTwoFactorConfiguration(new(verified.ResetAccessToken!,
            TwoFactorAuthConfiguration.AUTHENTICATOR_APP,destination,null,null),CancellationToken.None);
        selected.StatusCode.ShouldBe(StatusCodes.Status200OK);
        selected.CurrentRequiredMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
    }

    [Fact]
    public async Task Cor13_revoked_no_factor_authorization_is_required_even_when_current_menu_is_empty()
    {
        var harness=CreateHarness();var id=Guid.NewGuid();var account=Guid.NewGuid();
        harness.ReadyReset(id,account,requiresTotp:false);harness.Hasher.VerifyCode(id,"49382710","stored-hash").Returns(true);
        var verified=await harness.Service.VerifyResetToken(new(id,"49382710",null,null),CancellationToken.None);
        await harness.PasswordResetSessionService.RevokeSession(AccessTokenHashUtility.Hash(verified.ResetAccessToken!));
        var result=await harness.Service.FinalizeReset(new(Guid.Empty,null,null,"new-password","new-password",null,null,verified.ResetAccessToken),CancellationToken.None);
        result.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!,default);
        var oldCode=await harness.Service.VerifyResetToken(new(id,"49382710",null,null),CancellationToken.None);
        oldCode.ResetAccessToken.ShouldBeNull();
    }

    [Theory]
    [InlineData("eligible")] [InlineData("unknown")] [InlineData("expired")] [InlineData("cancelled")]
    public async Task Cor14_six_invalid_bootstrap_attempts_have_identical_public_protocol(string state)
    {
        var h = CreateHarness(); Guid id = Guid.NewGuid(), account = Guid.NewGuid();
        if (state != "unknown") h.ReadyReset(id, account, requiresTotp: false);
        var observed = await h.Repo.GetPasswordResetRequestForFinalizeAsync(id, default);
        if (state is "expired" or "cancelled")
            h.Repo.GetPasswordResetRequestForFinalizeAsync(id, Arg.Any<CancellationToken>()).Returns(observed! with {
                Result = false, Code = state == "expired" ? PasswordResetService.ExpiredCode : PasswordResetService.CancelledCode });
        h.Hasher.VerifyCode(id, "00000000", "stored-hash").Returns(false);
        int count = 0;
        h.Repo.RegisterFailedAttemptAsync(id, Arg.Any<Instant>(), Arg.Any<CancellationToken>()).Returns(_ =>
            Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new(false,
                ++count >= 5 ? PasswordResetService.AttemptsExceededCode : PasswordResetService.InvalidProofCode, account, count, 5, null)));
        for (int attempt = 1; attempt <= 6; attempt++)
        {
            var result = await h.Service.VerifyResetToken(new(id, "00000000", "192.0.2.10", "test"), default);
            result.Code.ShouldBe(PasswordResetService.InvalidProofCode); result.StatusCode.ShouldBe(401);
            result.Status.ShouldBe("failed"); result.ResetAccessToken.ShouldBeNull(); result.RequiresTwoFactor.ShouldBeFalse();
            result.AvailableTwoFactorAuthConfigurations.ShouldBeEmpty(); result.ExpiresAt.ShouldBeNull();
            if (state == "eligible" && attempt == 5)
                h.Repo.GetPasswordResetRequestForFinalizeAsync(id, Arg.Any<CancellationToken>()).Returns(observed! with { Result = false, Code = PasswordResetService.CancelledCode });
        }
        if (state == "eligible") count.ShouldBe(5);
    }

    private static Harness CreateHarness(PasswordResetSettings? providedSettings = null)
    {
        var repo = Substitute.For<IPasswordResetRepo>();
        var generator = Substitute.For<IPasswordResetCodeGenerator>();
        var hasher = Substitute.For<IPasswordResetCodeHasher>();
        var delivery = Substitute.For<IPasswordResetDeliveryService>();
        var totpVerifier = Substitute.For<IPasswordResetTotpVerifier>();
        var passwordMaterialFactory = Substitute.For<IPasswordResetPasswordMaterialFactory>();
        var passwordResetSessionService = Substitute.For<IPasswordResetSessionService>();
        var sessionRows = new treehammock.Tests.Support.Cor13ResetSessionStore();
        passwordResetSessionService.GetSession(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(call => Task.FromResult(sessionRows.Read(call.ArgAt<string>(0))));
        passwordResetSessionService.TransitionSession(Arg.Any<string>(), Arg.Any<PasswordResetSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(call => Task.FromResult<bool?>(sessionRows.Apply(call.ArgAt<PasswordResetSession>(1))));
        passwordResetSessionService.RevokeSession(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(call => { sessionRows.Revoke(call.ArgAt<string>(0)); return Task.FromResult(true); });
        PasswordResetSettings settings = providedSettings ?? Settings();
        var keyFactory = new PasswordResetRateLimitKeyFactory(Options.Create(settings));
        var abusePolicy = new PasswordResetAbusePolicy(Options.Create(settings));
        var abuseCounterKeyFactory = new PasswordResetAbuseCounterKeyFactory(Options.Create(settings));
        var abuseCounterStore = Substitute.For<IAbuseCounterStore>();
        AbuseControlSettings abuseControlSettings = new()
        {
            PasswordReset = new PasswordResetAbusePolicySettings { Enabled = false }
        };
        abuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    true,
                    1,
                    limit.MaxAttempts,
                    limit.Window,
                    null,
                    null));
            });
        abuseCounterStore.ResetAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);
        var service = new PasswordResetService(
            repo,
            generator,
            hasher,
            keyFactory,
            abusePolicy,
            abuseCounterKeyFactory,
            abuseCounterStore,
            Options.Create(abuseControlSettings),
            delivery,
            totpVerifier,
            passwordMaterialFactory,
            Options.Create(settings),
            Options.Create(RegistrationSettings()),
            NullLogger<PasswordResetService>.Instance,
            passwordResetSessionService);

        return new Harness(service, repo, hasher, totpVerifier, passwordMaterialFactory, passwordResetSessionService, abuseCounterStore, abuseControlSettings);
    }

    private static PasswordResetSettings Settings()
    {
        return new PasswordResetSettings
        {
            CodeLength = 8,
            CodeHashPepper = "unit-test-password-reset-pepper",
            ExpirationMinutes = 2,
            MaxAttempts = 5,
            RequestCooldownSeconds = 60,
            DailyRequestLimitPerAccount = 5,
            DailyRequestLimitPerDestination = 5,
            DailyRequestLimitPerIp = 20,
            DailyRequestWindowHours = 24,
            RateLimitBlockMinutes = 30,
            CaptchaChallengeEnabled = false,
            CaptchaChallengeAfterRequests = 3
        };
    }

    private static RegistrationSettings RegistrationSettings()
    {
        return new RegistrationSettings
        { PublicOrigin = "http://localhost.test",
            MinUsernameLength = 3,
            MaxUsernameLength = 30,
            MinPasswordLength = 8,
            MaxPasswordLength = 128,
            MaxEmailAddressLength = 255,
            AccountMetaDataRetries = 3,
            VerifyAccountPeriodDays = 1,
            EmailChangeVerifyPeriodDays = 1,
            AccountDeleteTokenPeriodDays = 1
        };
    }

    private sealed record Harness(
        PasswordResetService Service,
        IPasswordResetRepo Repo,
        IPasswordResetCodeHasher Hasher,
        IPasswordResetTotpVerifier TotpVerifier,
        IPasswordResetPasswordMaterialFactory PasswordMaterialFactory,
        IPasswordResetSessionService PasswordResetSessionService,
        IAbuseCounterStore AbuseCounterStore,
        AbuseControlSettings AbuseControlSettings)
    {
        public void AllowPromotion(Guid resetId, Guid accountId)
        {
            PasswordMaterialFactory.CreatePasswordMaterialAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(new PasswordResetPasswordMaterial(
                    Enumerable.Repeat((byte)1, AccountCryptoSizes.PasswordHashBytes).ToArray(),
                    Enumerable.Repeat((byte)2, AccountCryptoSizes.SaltOneBytes).ToArray(),
                    Enumerable.Repeat((byte)3, AccountCryptoSizes.SivBytes).ToArray(),
                    Enumerable.Repeat((byte)4, AccountCryptoSizes.NonceBytes).ToArray()));

            Repo.PromotePasswordResetAsync(Arg.Any<PromotePasswordResetDbCommand>(), Arg.Any<CancellationToken>())
                .Returns(call =>
                {
                    PromotePasswordResetDbCommand command = call.Arg<PromotePasswordResetDbCommand>();
                    return Task.FromResult<PromotePasswordResetResult?>(new PromotePasswordResetResult(
                        true,
                        PasswordResetService.CompletedCode,
                        command.AccountId,
                        command.NewSecurityStamp,
                        command.PromotedAt));
                });
        }

        public void ReadyReset(
            Guid resetId,
            Guid accountId,
            bool requiresTotp,
            string? method = null,
            bool requiresKeyCode = true,
            string? deliveryChannel = "email",
            string? keyCodeHash = "stored-hash")
        {
            Repo.GetPasswordResetRequestForFinalizeAsync(resetId, Arg.Any<CancellationToken>())
                .Returns(Task.FromResult<PasswordResetFinalizeRecord?>(new PasswordResetFinalizeRecord(
                    true,
                    PasswordResetService.ReadyCode,
                    resetId,
                    accountId,
                    method ?? PasswordResetDeliveryChannels.Email,
                    deliveryChannel,
                    keyCodeHash,
                    keyCodeHash is null ? null : 1,
                    requiresKeyCode,
                    requiresTotp,
                    SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),
                    null,
                    null,
                    0,
                    5,
                    Guid.NewGuid())));
        }
    }
}
