using Microsoft.AspNetCore.Http;
using NodaTime;
using NSubstitute;
using Shouldly;

using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Models.Authentication;
using treehammock.Models.Api;
using treehammock.Rigging.Authorization;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class AccountControllerApiShapeTests
{
    [Fact]
    public async Task Authenticate_invalid_payload_returns_400_envelope()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateLoginController();
        var payload = harness.LoginPayload(password: "short");

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors.ShouldContain(error => error.field == nameof(AuthenticateLogin.password));
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
    }

    [Fact]
    public async Task Authenticate_auth_failure_returns_401_envelope()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.NotFound()));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.errors.ShouldBeNull();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
    }

    [Fact]
    public async Task Authenticate_credential_lookup_failure_returns_500_envelope()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Failed()));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("LOGIN_ATTEMPT_PERSISTENCE_FAILED");
        envelope.errors.ShouldBeNull();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().SetLoginFailures(default, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().SetLockOut(default, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_locked_account_returns_423_envelope()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(unlockWhen: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)));
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status423Locked);
        envelope.success.ShouldBeFalse();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_TIME_LOCKED);
        envelope.data.lockoutDuration.ShouldNotBeNull();
    }


    [Fact]
    public async Task Authenticate_bad_password_returns_401_envelope()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload(password: "WrongPassword1!");
        var account = harness.Account(loginFailures: 1);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.RecordLoginFailure(account.accountId, account.accountSecurityStamp, 1, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(true, "RECORDED", 2, null, Guid.NewGuid()));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
        envelope.errors.ShouldBeNull();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
    }

    [Fact]
    public async Task Authenticate_session_persistence_failure_returns_500_envelope()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns("active-access-token");
        harness.SessionRepo.SetSession(Arg.Any<string>(), Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IntraMessage?>(IntraMessage.NONE));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
    }
}
