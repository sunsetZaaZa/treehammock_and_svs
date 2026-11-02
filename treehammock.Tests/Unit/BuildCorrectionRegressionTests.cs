using Microsoft.AspNetCore.Http;
using NSubstitute;
using Shouldly;
using treehammock.DataLayer.Cache;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Models.Account;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class BuildCorrectionRegressionTests
{
    [Fact]
    public async Task Two_factor_promotion_publishes_only_the_durable_promotion_projection()
    {
        var (harness, pending, hash) = TwoFactorAuthenticationPromotionTests.Prepare();
        harness.ProofState.Stored[hash].features = FeatureSet.premium;
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = TwoFactorAuthenticationPromotionTests.Token;
        var current = treehammock.Tests.Support.EntitlementTestData.ForAccount(pending.accountId, FeatureSet.basic);
        harness.LoginProofs.PromoteAsync(Arg.Any<string>(), Arg.Any<TwoFactorSession>(), Arg.Any<string>(),
            Arg.Any<ActiveSession>(), Arg.Any<CancellationToken>()).Returns(call =>
            {
                var active = call.ArgAt<ActiveSession>(3);
                active.entitlements.ShouldBeNull();
                // Model the existing repository's authoritative projection load on promotion.
                active.entitlements = current;
                active.features = current.Features;
                return Task.FromResult(new LoginProofTransition(true, "TWO_FACTOR_NEW_LOGIN_PROMOTED"));
            });
        harness.ActiveUserCacheService.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(),
            cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));

        var data = AccountControllerHarness.ExtractData(await controller.TwoFactorAuthenticate(
            new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL)), StatusCodes.Status200OK);

        data.session!.entitlements.ShouldBeSameAs(current);
        await harness.ActiveUserCacheService.Received(1).SetSession(Arg.Any<string>(),
            Arg.Is<ActiveSession>(session => session.features == FeatureSet.basic && ReferenceEquals(session.entitlements, current)),
            Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Shared_sensitive_action_check_preserves_all_bindings_and_request_cancellation(bool delete)
    {
        var harness = new AccountControllerHarness();
        var profile = delete ? null : harness.CreateProfileController();
        var deletion = delete ? harness.CreateDeleteController() : null;
        const string sessionHash = "fixture-session-binding";
        var session = harness.SetAuthenticatedSession(hashedAccessToken: sessionHash);
        using var cancellation = new CancellationTokenSource();
        harness.HttpContext.RequestAborted = cancellation.Token;
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName] = "fixture-fresh-proof";
        harness.SensitiveActionService.ValidateAsync(Arg.Any<SensitiveActionValidationCommand>(), Arg.Any<CancellationToken>())
            .Returns(new SensitiveActionValidationResult(false, HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATION_FAILED,
                AccountSensitiveActionService.TokenValidationFailedCode));

        if (delete)
            AccountControllerHarness.ExtractEnvelope(await deletion!.DeleteAccount(null), StatusCodes.Status401Unauthorized).success.ShouldBeFalse();
        else
            AccountControllerHarness.ExtractEnvelope(await profile!.ModifyAccount(new AccountEditRequest("NEW@example.test", null)), StatusCodes.Status401Unauthorized).success.ShouldBeFalse();

        var purpose = delete ? SensitiveActionPurpose.ACCOUNT_DELETE : SensitiveActionPurpose.ACCOUNT_EMAIL_CHANGE;
        string target = delete ? SensitiveActionTargets.AccountDelete(null) : SensitiveActionTargets.EmailChange("new@example.test");
        await harness.SensitiveActionService.Received(1).ValidateAsync(
            Arg.Is<SensitiveActionValidationCommand>(command =>
                command.AccountId == session.accountId && command.AccountSecurityStamp == session.accountSecurityStamp &&
                command.SessionBindingHash == sessionHash && command.Token == "fixture-fresh-proof" &&
                command.Purpose == purpose && command.Target == target && !command.Consume), cancellation.Token);
        harness.AccountService.ReceivedCalls().Any(call => call.GetMethodInfo().Name is "RequestEmailChange" or "RequestAccountDelete").ShouldBeFalse();
    }
}
