using Microsoft.AspNetCore.Http;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Models.Api;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class TwoFactorSelectionEndpointTests
{
    [Fact]
    public async Task SelectTwoFactorConfiguration_sends_sms_first_for_sms_and_authenticator_app()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-selection-token";
        var session = BuildPendingSession(
            methods: [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP],
            phoneNumbers: ["5555550101"],
            phoneCountryCodes: ["1"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.TwoFactorService.SMS("+15555550101", Arg.Any<string>(), token: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        var controller = harness.CreateTwoFactorController();

        var actionResult = await controller.SelectTwoFactorConfiguration(
            new SelectTwoFactorConfigurationRequest(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, twoFactorAccessToken: preAuthToken));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status200OK);
        response.outcome.ShouldBeTrue();
        response.result.ShouldBe(HttpMessage.TWOFACTOR_WAITING_SMS_KEY);
        response.method.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        response.currentRequiredMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        response.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        response.completedTwoFactorAuthMethods.ShouldBeEmpty();
        response.remainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session = harness.ProofState.Stored[AccessTokenHashUtility.Hash(preAuthToken)];
        session.state.ShouldBe(TwoFactorSessionState.AwaitingSmsCode);
        session.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        session.requiredMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.currentExpectedMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        await harness.TwoFactorService.Received(1).SMS("+15555550101", Arg.Any<string>(), token: Arg.Any<CancellationToken>());
        await harness.LoginProofs.Received(1).IssueAsync(hash, Arg.Any<TwoFactorSession>(), Arg.Any<short>(), Arg.Any<int>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SelectTwoFactorConfiguration_sends_email_first_for_email_and_authenticator_app()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-selection-token";
        var session = BuildPendingSession(
            methods: [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP],
            emailAddresses: ["reader@example.com"]);
        _ = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.TwoFactorService.Email("reader@example.com", Arg.Any<string>(), token: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers[AccessTokenTransport.AccessTokenHeaderName] = preAuthToken;

        var actionResult = await controller.SelectTwoFactorConfiguration(
            new SelectTwoFactorConfigurationRequest(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status200OK);
        response.outcome.ShouldBeTrue();
        response.result.ShouldBe(HttpMessage.TWOFACTOR_WAITING_INTRA_EMAIL);
        response.method.ShouldBe(TwoFactorAuthMethod.EMAIL);
        response.currentRequiredMethod.ShouldBe(TwoFactorAuthMethod.EMAIL);
        response.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP);
        response.remainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session = harness.ProofState.Stored[AccessTokenHashUtility.Hash(preAuthToken)];
        session.state.ShouldBe(TwoFactorSessionState.AwaitingEmailCode);
        session.requiredMethods.ShouldBe([TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        await harness.TwoFactorService.Received(1).Email("reader@example.com", Arg.Any<string>(), token: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SelectTwoFactorConfiguration_prepares_authenticator_app_without_delivery()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-selection-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        _ = PrepareValidPendingSession(harness, preAuthToken, session);
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers[AccessTokenTransport.AccessTokenHeaderName] = preAuthToken;

        var actionResult = await controller.SelectTwoFactorConfiguration(
            new SelectTwoFactorConfigurationRequest(TwoFactorAuthConfiguration.AUTHENTICATOR_APP));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status200OK);
        response.outcome.ShouldBeTrue();
        response.result.ShouldBe(HttpMessage.TWOFACTOR_WAITING_AUTHENTICATOR_APP);
        response.method.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        response.currentRequiredMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        response.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        response.remainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session = harness.ProofState.Stored[AccessTokenHashUtility.Hash(preAuthToken)];
        session.state.ShouldBe(TwoFactorSessionState.AwaitingAuthenticatorCode);
        session.requiredMethods.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().SMS(default!, default!, token: Arg.Any<CancellationToken>());
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!, token: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SelectTwoFactorConfiguration_rejects_unavailable_combination_without_delivery()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-selection-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.SMS_KEY], phoneNumbers: ["5555550101"], phoneCountryCodes: ["1"]);
        _ = PrepareValidPendingSession(harness, preAuthToken, session);
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers[AccessTokenTransport.AccessTokenHeaderName] = preAuthToken;

        var actionResult = await controller.SelectTwoFactorConfiguration(
            new SelectTwoFactorConfigurationRequest(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP));

        ApiResponse<LayeredAuthenticateMethodsResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.ShouldContain(error => error.field == nameof(SelectTwoFactorConfigurationRequest.configuration));
        session.selectedConfiguration.ShouldBeNull();
        session = harness.ProofState.Stored[AccessTokenHashUtility.Hash(preAuthToken)];
        session.state.ShouldBe(TwoFactorSessionState.SelectionRequired);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().SMS(default!, default!, token: Arg.Any<CancellationToken>());
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!, token: Arg.Any<CancellationToken>());
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SelectTwoFactorConfiguration_uses_durable_cooldown_for_second_selection()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-selection-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.selectedConfiguration = TwoFactorAuthConfiguration.AUTHENTICATOR_APP;
        session.requiredMethods = [TwoFactorAuthMethod.AUTHENTICATOR_APP];
        session.currentExpectedMethod = TwoFactorAuthMethod.AUTHENTICATOR_APP;
        session.state = TwoFactorSessionState.AwaitingAuthenticatorCode;
        session.nextChallengeAllowedAt = SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromSeconds(30));
        _ = PrepareValidPendingSession(harness, preAuthToken, session);
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers[AccessTokenTransport.AccessTokenHeaderName] = preAuthToken;

        var actionResult = await controller.SelectTwoFactorConfiguration(
            new SelectTwoFactorConfigurationRequest(TwoFactorAuthConfiguration.AUTHENTICATOR_APP));

        ApiResponse<LayeredAuthenticateMethodsResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_CODE_TIMEOUT.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().SMS(default!, default!, token: Arg.Any<CancellationToken>());
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!, token: Arg.Any<CancellationToken>());
    }

    private static string PrepareValidPendingSession(AccountControllerHarness harness, string preAuthToken, TwoFactorSession session)
    {
        string hash = AccessTokenHashUtility.Hash(preAuthToken);
        harness.ProofState.Stored[hash] = session;
        harness.JwtUtility.ValidateAccessToken(preAuthToken, Arg.Any<byte[]>(), Arg.Any<Instant>(), session.expiration, JsonWebTokenPurpose.PreAuthTwoFactor)
            .Returns(Task.FromResult<(IntraMessage, string?)>((IntraMessage.TOKEN_PASSED_VALIDATION, session.webKey)));
        harness.TwoFactorSessionService.SetSession(hash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<bool?>(true));
        return hash;
    }

    private static TwoFactorSession BuildPendingSession(
        List<TwoFactorAuthMethod> methods,
        List<string>? userAuthIds = null,
        List<string>? phoneNumbers = null,
        List<string>? phoneCountryCodes = null,
        List<string>? emailAddresses = null)
    {
        Instant now = SystemClock.Instance.GetCurrentInstant();
        return new TwoFactorSession(
            Guid.NewGuid(),
            "web-key",
            Enumerable.Repeat((byte)7, 64).ToArray(),
            methods,
            userAuthIds,
            phoneNumbers,
            phoneCountryCodes,
            emailAddresses,
            null,
            null,
            (short)methods.Count(method => method == TwoFactorAuthMethod.AUTHENTICATOR_APP),
            0,
            (short)methods.Count(method => method == TwoFactorAuthMethod.SMS_KEY),
            now,
            now.Plus(Duration.FromMinutes(2)),
            FeatureSet.basic,
            cutOff: null,
            accountSecurityStamp: Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-000000000003"));
    }
}
