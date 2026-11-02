using System.Net;

using Microsoft.AspNetCore.Http;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Models.Authentication;
using treehammock.Models.Api;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Abuse;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class AccountControllerAuthenticateTests
{
    [Fact]
    public async Task Authenticate_rejects_invalid_password_shape_without_loading_account()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateLoginController();
        var payload = harness.LoginPayload(password: "short");

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().GetCredentials(default!, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Theory]
    [MemberData(nameof(LoginIdentifierCases))]
    public async Task Authenticate_resolves_login_identifier_once_before_loading_account(AuthenticateLogin payload, AccountLoginAction expectedAction)
    {
        var harness = new AccountControllerHarness();
        harness.AccountRepo.GetCredentials(payload, expectedAction, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.NotFound()));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        await harness.AccountRepo.Received(1).GetCredentials(payload, expectedAction, cancellationToken: Arg.Any<CancellationToken>());
    }


    [Theory]
    [MemberData(nameof(InvalidLoginIdentifierCases))]
    public async Task Authenticate_rejects_invalid_login_identifier_without_loading_account(AuthenticateLogin payload)
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors.ShouldNotBeEmpty();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().GetCredentials(default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Theory]
    [MemberData(nameof(SuppliedInvalidLoginIdentifierCases))]
    public async Task Authenticate_rejects_supplied_invalid_identifier_even_when_other_identifier_is_valid(AuthenticateLogin payload, string expectedField)
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors.ShouldContain(error => error.field == expectedField);
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().GetCredentials(default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_returns_duplicate_when_middleware_already_authenticated_request()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateLoginController();
        harness.HttpContext.Items["hashedAccessToken"] = "already-authenticated";

        var actionResult = await controller.Authenticate(harness.LoginPayload());

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_DUPLICATE);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().GetCredentials(default!, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(VerificationStatus.SENT)]
    [InlineData(VerificationStatus.REFRESHED)]
    public async Task Authenticate_returns_verification_pending_after_password_check(VerificationStatus status)
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(verificationStatus: status);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING);
        _ = harness.AccountRepo.DidNotReceive().RemoveLockOut(account.accountId, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SetLoginFailures(account.accountId, Arg.Any<int>(), cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_bad_password_on_unverified_account_does_not_disclose_verification_state()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload(password: "WrongPassword1!");
        var account = harness.Account(verificationStatus: VerificationStatus.SENT, loginFailures: 1);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.RecordLoginFailure(account.accountId, account.accountSecurityStamp, 1, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(true, "RECORDED", 2, null, Guid.NewGuid()));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult, StatusCodes.Status401Unauthorized);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        await harness.AccountRepo.Received(1).RecordLoginFailure(account.accountId, account.accountSecurityStamp, 1, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_expired_verification_below_retry_limit_requests_renewal()
    {
        var harness = new AccountControllerHarness();
        harness.LoginSettings.PasswordRetryLimit = 5;
        var payload = harness.LoginPayload();
        var account = harness.Account(verificationStatus: VerificationStatus.EXPIRED, loginFailures: 1);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.RecordLoginFailure(account.accountId, account.accountSecurityStamp, 3, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(true, "RECORDED", 3, null, Guid.NewGuid()));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult, StatusCodes.Status401Unauthorized);
        response.result.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_RENEW);
        await harness.AccountRepo.Received(1).RecordLoginFailure(account.accountId, account.accountSecurityStamp, 3, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().SetLockOut(Arg.Any<Guid>(), Arg.Any<short?>(), cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_expired_verification_returns_locked_when_failure_increment_triggers_lockout()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(verificationStatus: VerificationStatus.EXPIRED, loginFailures: 1);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.RecordLoginFailure(account.accountId, account.accountSecurityStamp, 3, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(true, "LOCKED", 3, SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromHours(8)), Guid.NewGuid()));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status423Locked);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.ACCOUNT_LOCKED.ToString());
        envelope.errors.ShouldBeNull();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_LOCKED);
        await harness.AccountRepo.Received(1).RecordLoginFailure(account.accountId, account.accountSecurityStamp, 3, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SetLoginFailures(account.accountId, Arg.Any<int>(), cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_active_lockout_returns_time_locked_and_does_not_attempt_session_work()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(unlockWhen: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.ACCOUNT_TIME_LOCKED);
        response.lockoutDuration.ShouldNotBeNull();
        _ = harness.AccountRepo.DidNotReceive().RemoveLockOut(account.accountId, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_expired_lockout_is_removed_before_successful_login()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(unlockWhen: SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1)));
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.ClearLoginAttempts(account.accountId, account.accountSecurityStamp, Arg.Any<Guid>(), Arg.Any<short>(), Arg.Any<Instant?>(), true, Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(true, "CLEARED", 0, null, Guid.NewGuid()));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns("new-access-token");
        harness.SessionRepo.SetSession(Arg.Any<string>(), Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<IntraMessage?>(IntraMessage.SUCCESSFUL));
        harness.ActiveUserCacheService.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        await harness.AccountRepo.Received(1).ClearLoginAttempts(account.accountId, account.accountSecurityStamp, Arg.Any<Guid>(), Arg.Any<short>(), Arg.Any<Instant?>(), true, Arg.Any<CancellationToken>());
        await harness.SessionRepo.Received(1).SetSession(Arg.Any<string>(), Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_expired_lockout_cleanup_resets_failure_count_before_next_bad_password()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload(password: "WrongPassword1!");
        var account = harness.Account(
            unlockWhen: SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1)),
            loginFailures: 2);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.ClearLoginAttempts(account.accountId, account.accountSecurityStamp, Arg.Any<Guid>(), Arg.Any<short>(), Arg.Any<Instant?>(), true, Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(true, "CLEARED", 0, null, Guid.NewGuid()));
        harness.AccountRepo.RecordLoginFailure(account.accountId, account.accountSecurityStamp, 1, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(true, "RECORDED", 1, null, Guid.NewGuid()));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        await harness.AccountRepo.Received(1).ClearLoginAttempts(account.accountId, account.accountSecurityStamp, Arg.Any<Guid>(), Arg.Any<short>(), Arg.Any<Instant?>(), true, Arg.Any<CancellationToken>());
        await harness.AccountRepo.Received(1).RecordLoginFailure(account.accountId, account.accountSecurityStamp, 1, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().SetLockOut(Arg.Any<Guid>(), Arg.Any<short?>(), cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(null)]
    public async Task Authenticate_expired_lockout_cleanup_failure_returns_500(bool? cleanupResult)
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(unlockWhen: SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1)));
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.ClearLoginAttempts(account.accountId, account.accountSecurityStamp, Arg.Any<Guid>(), Arg.Any<short>(), Arg.Any<Instant?>(), true, Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(cleanupResult == true, "CLEARED", 0, null, Guid.NewGuid()));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("LOCKOUT_CLEANUP_FAILED");
        envelope.errors.ShouldBeNull();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        await harness.AccountRepo.Received(1).ClearLoginAttempts(account.accountId, account.accountSecurityStamp, Arg.Any<Guid>(), Arg.Any<short>(), Arg.Any<Instant?>(), true, Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().RotateActiveSession(default, default!, default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().SMS(default!, default!, token: Arg.Any<CancellationToken>());
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!, token: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SuccessfulLogin(account.accountId, account.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_bad_password_increments_failure_count()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload(password: "WrongPassword1!");
        var account = harness.Account(loginFailures: 1);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.RecordLoginFailure(account.accountId, account.accountSecurityStamp, 1, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(true, "RECORDED", 2, null, Guid.NewGuid()));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        await harness.AccountRepo.Received(1).RecordLoginFailure(account.accountId, account.accountSecurityStamp, 1, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_bad_password_at_retry_limit_sets_lockout_and_returns_423()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload(password: "WrongPassword1!");
        var account = harness.Account(loginFailures: 2);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.RecordLoginFailure(account.accountId, account.accountSecurityStamp, 1, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(true, "LOCKED", 3, SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromHours(8)), Guid.NewGuid()));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status423Locked);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.ACCOUNT_LOCKED.ToString());
        envelope.errors.ShouldBeNull();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_LOCKED);
        await harness.AccountRepo.Received(1).RecordLoginFailure(account.accountId, account.accountSecurityStamp, 1, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SetLoginFailures(account.accountId, Arg.Any<int>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(null)]
    public async Task Authenticate_bad_password_login_failure_persistence_failure_returns_500(bool? persistenceResult)
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload(password: "WrongPassword1!");
        var account = harness.Account(loginFailures: 1);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.RecordLoginFailure(account.accountId, account.accountSecurityStamp, 1, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(persistenceResult == true, "RECORDED", 2, null, Guid.NewGuid()));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("LOGIN_ATTEMPT_PERSISTENCE_FAILED");
        envelope.errors.ShouldBeNull();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        await harness.AccountRepo.Received(1).RecordLoginFailure(account.accountId, account.accountSecurityStamp, 1, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().SetLockOut(Arg.Any<Guid>(), Arg.Any<short?>(), cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(null)]
    public async Task Authenticate_bad_password_lockout_persistence_failure_returns_500(bool? persistenceResult)
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload(password: "WrongPassword1!");
        var account = harness.Account(loginFailures: 2);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.RecordLoginFailure(account.accountId, account.accountSecurityStamp, 1, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(persistenceResult == true, "LOCKED", 3, SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromHours(8)), Guid.NewGuid()));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("LOGIN_ATTEMPT_PERSISTENCE_FAILED");
        envelope.errors.ShouldBeNull();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        await harness.AccountRepo.Received(1).RecordLoginFailure(account.accountId, account.accountSecurityStamp, 1, harness.LoginSettings.PasswordRetryLimit, Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SetLoginFailures(account.accountId, Arg.Any<int>(), cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }


    [Fact]
    public async Task Authenticate_cutoff_expired_not_logged_in_returns_401_without_creating_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(
            refreshToken: null,
            hasTwoFactorAuth: false,
            cutOff: SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1)));
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_EXPIRED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_EXPIRED);
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().RotateActiveSession(default, default!, default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SuccessfulLogin(account.accountId, account.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_cutoff_expired_two_factor_account_returns_401_without_pending_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(
            refreshToken: null,
            hasTwoFactorAuth: true,
            twoFactorAuthMethod: TwoFactorAuthMethod.SMS_KEY,
            smsUsage: 1,
            cutOff: SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1)));
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_EXPIRED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_EXPIRED);
        _ = harness.AccountRepo.DidNotReceive().GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.LoginProofs.DidNotReceiveWithAnyArgs().BeginAsync(default!, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_not_logged_in_without_two_factor_creates_active_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns("active-access-token");
        harness.SessionRepo.SetSession(Arg.Any<string>(), Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<IntraMessage?>(IntraMessage.SUCCESSFUL));
        harness.ActiveUserCacheService.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        string expectedHash = AccessTokenHashUtility.Hash("active-access-token");
        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        response.accessToken.ShouldBe("active-access-token");
        harness.HttpContext.Request.Headers["AccessToken"].ToString().ShouldBe(string.Empty);
        await harness.SessionRepo.Received(1).SetSession(expectedHash, Arg.Is<Session>(session => session.accountId == account.accountId), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).SetSession(expectedHash, Arg.Is<ActiveSession>(session => session.accountId == account.accountId), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.AccountRepo.Received(1).ClearLoginAttempts(account.accountId, account.accountSecurityStamp, Arg.Any<Guid>(), Arg.Any<short>(), Arg.Any<Instant?>(), false, Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SetLoginFailures(account.accountId, 0, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_not_logged_in_future_cutoff_is_copied_into_active_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        Instant cutoff = SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(45));
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false, cutOff: cutoff);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns("active-access-token-active-cutoff-copy");
        harness.SessionRepo.SetSession(Arg.Any<string>(), Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<IntraMessage?>(IntraMessage.SUCCESSFUL));
        harness.ActiveUserCacheService.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        string expectedHash = AccessTokenHashUtility.Hash("active-access-token-active-cutoff-copy");
        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        await harness.SessionRepo.Received(1).SetSession(
            expectedHash,
            Arg.Is<Session>(session =>
                session.accountId == account.accountId &&
                session.cutOff == cutoff &&
                session.accessExpiration < cutoff &&
                session.sessionExpiration > cutoff), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).SetSession(
            expectedHash,
            Arg.Is<ActiveSession>(session =>
                session.cutOff == cutoff &&
                session.EffectiveSessionExpiration == cutoff),
            Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_not_logged_in_without_cutoff_uses_short_access_expiration()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns("active-access-token-short-expiration");
        harness.SessionRepo.SetSession(Arg.Any<string>(), Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<IntraMessage?>(IntraMessage.SUCCESSFUL));
        harness.ActiveUserCacheService.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        var controller = harness.CreateLoginController();
        Instant before = SystemClock.Instance.GetCurrentInstant();

        var actionResult = await controller.Authenticate(payload);

        Instant after = SystemClock.Instance.GetCurrentInstant();
        string expectedHash = AccessTokenHashUtility.Hash("active-access-token-short-expiration");
        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        await harness.ActiveUserCacheService.Received(1).SetSession(
            expectedHash,
            Arg.Is<ActiveSession>(session =>
                session.accessExpiration >= before.Plus(Duration.FromMinutes(harness.JwtSettings.RefreshTokenAliveMinutes_Short)) &&
                session.accessExpiration <= after.Plus(Duration.FromMinutes(harness.JwtSettings.RefreshTokenAliveMinutes_Short)) &&
                session.accessExpiration < before.Plus(Duration.FromHours(harness.JwtSettings.RefreshTokenAliveHours) + Duration.FromMinutes(harness.JwtSettings.RefreshTokenAliveMinutes))),
            Arg.Is<TimeSpan>(ttl => ttl <= TimeSpan.FromMinutes(harness.JwtSettings.RefreshTokenAliveMinutes_Short) && ttl > TimeSpan.Zero), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_not_logged_in_cutoff_after_short_period_still_uses_short_access_expiration()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        Instant cutoff = SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(45));
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false, cutOff: cutoff);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns("active-access-token-cutoff-after-short");
        harness.SessionRepo.SetSession(Arg.Any<string>(), Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<IntraMessage?>(IntraMessage.SUCCESSFUL));
        harness.ActiveUserCacheService.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        var controller = harness.CreateLoginController();
        Instant before = SystemClock.Instance.GetCurrentInstant();

        var actionResult = await controller.Authenticate(payload);

        Instant after = SystemClock.Instance.GetCurrentInstant();
        string expectedHash = AccessTokenHashUtility.Hash("active-access-token-cutoff-after-short");
        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        await harness.ActiveUserCacheService.Received(1).SetSession(
            expectedHash,
            Arg.Is<ActiveSession>(session =>
                session.accessExpiration >= before.Plus(Duration.FromMinutes(harness.JwtSettings.RefreshTokenAliveMinutes_Short)) &&
                session.accessExpiration <= after.Plus(Duration.FromMinutes(harness.JwtSettings.RefreshTokenAliveMinutes_Short)) &&
                session.accessExpiration < cutoff &&
                session.EffectiveSessionExpiration == cutoff),
            Arg.Is<TimeSpan>(ttl => ttl <= TimeSpan.FromMinutes(harness.JwtSettings.RefreshTokenAliveMinutes_Short) && ttl > TimeSpan.Zero), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_not_logged_in_cutoff_before_short_period_caps_access_expiration()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        Instant cutoff = SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(8));
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false, cutOff: cutoff);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns("active-access-token-cutoff-before-short");
        harness.SessionRepo.SetSession(Arg.Any<string>(), Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<IntraMessage?>(IntraMessage.SUCCESSFUL));
        harness.ActiveUserCacheService.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        string expectedHash = AccessTokenHashUtility.Hash("active-access-token-cutoff-before-short");
        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        await harness.ActiveUserCacheService.Received(1).SetSession(
            expectedHash,
            Arg.Is<ActiveSession>(session =>
                session.accessExpiration == cutoff &&
                session.EffectiveSessionExpiration == cutoff),
            Arg.Is<TimeSpan>(ttl => ttl <= TimeSpan.FromMinutes(8) && ttl > TimeSpan.Zero), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_not_logged_in_db_session_write_failure_returns_no_token()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns("active-access-token");
        harness.SessionRepo.SetSession(Arg.Any<string>(), Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<IntraMessage?>(IntraMessage.NONE));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACTIVE_SESSION_DB_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        envelope.data.accessToken.ShouldBeNull();
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SuccessfulLogin(account.accountId, account.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_not_logged_in_redis_session_write_failure_still_returns_token_without_db_rollback()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns("active-access-token");
        harness.SessionRepo.SetSession(Arg.Any<string>(), Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<IntraMessage?>(IntraMessage.SUCCESSFUL));
        harness.ActiveUserCacheService.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(false));
        string hash = AccessTokenHashUtility.Hash("active-access-token");
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        response.accessToken.ShouldBe("active-access-token");
        await harness.ActiveUserCacheService.Received(1).SetSession(hash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.DidNotReceive().RevokeSession(hash, cancellationToken: Arg.Any<CancellationToken>());
        await harness.SessionRepo.DidNotReceive().ExpireSession(hash, null, cancellationToken: Arg.Any<CancellationToken>());
        await harness.AccountRepo.Received(1).ClearLoginAttempts(account.accountId, account.accountSecurityStamp, Arg.Any<Guid>(), Arg.Any<short>(), Arg.Any<Instant?>(), false, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_stale_success_clear_denies_before_cache_or_db_session_publication()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns("active-access-token");
        harness.SessionRepo.SetSession(Arg.Any<string>(), Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<IntraMessage?>(IntraMessage.SUCCESSFUL));
        harness.ActiveUserCacheService.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        harness.AccountRepo.ClearLoginAttempts(account.accountId, account.accountSecurityStamp, Arg.Any<Guid>(), Arg.Any<short>(), Arg.Any<Instant?>(), false, Arg.Any<CancellationToken>()).Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(false,"LOGIN_ATTEMPT_STATE_CHANGED",1,null,Guid.NewGuid()));
        string hash = AccessTokenHashUtility.Hash("active-access-token");
        harness.ActiveUserCacheService.RevokeSession(hash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        harness.SessionRepo.ExpireSession(hash, null, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult, StatusCodes.Status409Conflict);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        response.accessToken.ShouldBeNull();
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!,default!,default,cancellationToken:Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!,default!,Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_already_logged_in_rotation_db_failure_does_not_revoke_old_cache_or_publish_new_cache_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var originalRefreshToken = Enumerable.Repeat((byte)7, harness.JwtSettings.RefreshTokenBytes).ToArray();
        const string rotatedToken = "rotated-access-token";
        string oldHash = AccessTokenHashUtility.Hash("stored-old-access-token");
        string rotatedHash = AccessTokenHashUtility.Hash(rotatedToken);
        var account = harness.Account(refreshToken: originalRefreshToken, hasTwoFactorAuth: false, activeAccessTokenHash: oldHash);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns(rotatedToken);
        harness.SessionRepo.RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Failed)));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult, StatusCodes.Status500InternalServerError);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        response.accessToken.ShouldBeNull();
        await harness.SessionRepo.Received(1).RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.DidNotReceive().RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().ExpireSession(default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SuccessfulLogin(account.accountId, account.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_already_logged_in_without_two_factor_rotates_session_db_first_then_cache_then_best_effort_old_revoke()
    {
        var harness = new AccountControllerHarness();
        var calls = new List<string>();
        var payload = harness.LoginPayload();
        var originalRefreshToken = Enumerable.Repeat((byte)7, harness.JwtSettings.RefreshTokenBytes).ToArray();
        string oldHash = AccessTokenHashUtility.Hash("stored-old-access-token");
        var account = harness.Account(refreshToken: originalRefreshToken, hasTwoFactorAuth: false, activeAccessTokenHash: oldHash);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns("rotated-access-token");
        string rotatedHash = AccessTokenHashUtility.Hash("rotated-access-token");
        harness.SessionRepo.RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ =>
            {
                calls.Add("db-rotate");
                return Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded));
            });
        harness.ActiveUserCacheService.SetSession(rotatedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ =>
            {
                calls.Add("new-cache-set");
                return Task.FromResult(true);
            });
        harness.ActiveUserCacheService.RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ =>
            {
                calls.Add("old-cache-revoke");
                return Task.FromResult(true);
            });
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        response.accessToken.ShouldBe("rotated-access-token");
        calls.ShouldBe(new List<string> { "db-rotate", "new-cache-set", "old-cache-revoke" });
        harness.HttpContext.Request.Headers["AccessToken"].ToString().ShouldBe(string.Empty);
        await harness.SessionRepo.Received(1).RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Is<Session>(session => session.accountId == account.accountId && !session.refreshToken.SequenceEqual(originalRefreshToken)), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).SetSession(rotatedHash, Arg.Is<ActiveSession>(session => session.accountId == account.accountId), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SuccessfulLogin(account.accountId, account.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
        await harness.SessionRepo.DidNotReceive().ExpireSession(oldHash, null, cancellationToken: Arg.Any<CancellationToken>());
        harness.JwtUtility.Received(1).GenerateAccessToken(Arg.Any<byte[]>(), account.webKey);
    }


    [Fact]
    public async Task Authenticate_already_logged_in_password_rotation_resets_refresh_count_and_database_lifespan()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var originalRefreshToken = Enumerable.Repeat((byte)7, harness.JwtSettings.RefreshTokenBytes).ToArray();
        const string rotatedToken = "rotated-access-token";
        string oldHash = AccessTokenHashUtility.Hash("stored-old-access-token");
        string rotatedHash = AccessTokenHashUtility.Hash(rotatedToken);
        Instant cutoff = SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromHours(1));
        Period staleCredentialLifespan = Period.FromMinutes(5);
        Period expectedFreshLifespan = Period.FromDays(7);
        var account = harness.Account(
            refreshToken: originalRefreshToken,
            refreshes: 2,
            lifespan: staleCredentialLifespan,
            hasTwoFactorAuth: false,
            cutOff: cutoff,
            activeAccessTokenHash: oldHash);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns(rotatedToken);
        harness.SessionRepo.RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        harness.ActiveUserCacheService.SetSession(rotatedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        harness.ActiveUserCacheService.RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        response.accessToken.ShouldBe(rotatedToken);
        await harness.SessionRepo.Received(1).RotateActiveSession(
            account.accountId,
            oldHash,
            rotatedHash,
            Arg.Is<Session>(session =>
                session.refreshes == 0
                && session.sessionLifespan != null
                && session.sessionLifespan.Equals(expectedFreshLifespan)
                && session.cutOff == cutoff
                && session.accountSecurityStamp == account.accountSecurityStamp
                && !session.sessionLifespan.Equals(staleCredentialLifespan)), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).SetSession(
            rotatedHash,
            Arg.Is<ActiveSession>(session =>
                session.refreshes == 0
                && session.sessionLifespan.Equals(expectedFreshLifespan)
                && session.cutOff == cutoff
                && session.accountSecurityStamp == account.accountSecurityStamp
                && !session.sessionLifespan.Equals(staleCredentialLifespan)),
            Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_already_logged_in_without_stored_active_hash_fails_without_rotating_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var originalRefreshToken = Enumerable.Repeat((byte)7, harness.JwtSettings.RefreshTokenBytes).ToArray();
        var account = harness.Account(refreshToken: originalRefreshToken, hasTwoFactorAuth: false, activeAccessTokenHash: null);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult, StatusCodes.Status500InternalServerError);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        response.accessToken.ShouldBeNull();
        _ = harness.JwtUtility.DidNotReceiveWithAnyArgs().GenerateAccessToken(default!, default!, default!);
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().RotateActiveSession(default, default!, default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SuccessfulLogin(account.accountId, account.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
    }


    [Fact]
    public async Task Authenticate_already_logged_in_old_active_cache_revoke_false_after_success_still_returns_token()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var originalRefreshToken = Enumerable.Repeat((byte)7, harness.JwtSettings.RefreshTokenBytes).ToArray();
        const string rotatedToken = "rotated-access-token";
        string oldHash = AccessTokenHashUtility.Hash("stored-old-access-token");
        string rotatedHash = AccessTokenHashUtility.Hash(rotatedToken);
        var account = harness.Account(refreshToken: originalRefreshToken, hasTwoFactorAuth: false, activeAccessTokenHash: oldHash);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns(rotatedToken);
        harness.SessionRepo.RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        harness.ActiveUserCacheService.SetSession(rotatedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        harness.ActiveUserCacheService.RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(false));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        response.accessToken.ShouldBe(rotatedToken);
        await harness.SessionRepo.Received(1).RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).SetSession(rotatedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>());
        await harness.SessionRepo.DidNotReceive().ExpireSession(oldHash, null, cancellationToken: Arg.Any<CancellationToken>());
        await harness.SessionRepo.DidNotReceive().ExpireSession(rotatedHash, null, cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.DidNotReceive().RevokeSession(rotatedHash, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_already_logged_in_old_hash_mismatch_does_not_revoke_old_cache_or_write_new_cache()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var originalRefreshToken = Enumerable.Repeat((byte)7, harness.JwtSettings.RefreshTokenBytes).ToArray();
        const string rotatedToken = "rotated-access-token";
        string oldHash = AccessTokenHashUtility.Hash("stored-old-access-token");
        string rotatedHash = AccessTokenHashUtility.Hash(rotatedToken);
        var account = harness.Account(refreshToken: originalRefreshToken, hasTwoFactorAuth: false, activeAccessTokenHash: oldHash);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns(rotatedToken);
        harness.SessionRepo.RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.OldSessionMismatch)));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult, StatusCodes.Status500InternalServerError);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        response.accessToken.ShouldBeNull();
        await harness.SessionRepo.Received(1).RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.DidNotReceive().RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        await harness.SessionRepo.DidNotReceive().ExpireSession(rotatedHash, null, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_already_logged_in_new_cache_write_failure_still_returns_token_without_db_rollback()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var originalRefreshToken = Enumerable.Repeat((byte)7, harness.JwtSettings.RefreshTokenBytes).ToArray();
        const string rotatedToken = "rotated-access-token";
        string oldHash = AccessTokenHashUtility.Hash("stored-old-access-token");
        string rotatedHash = AccessTokenHashUtility.Hash(rotatedToken);
        var account = harness.Account(refreshToken: originalRefreshToken, hasTwoFactorAuth: false, activeAccessTokenHash: oldHash);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns(rotatedToken);
        harness.SessionRepo.RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        harness.ActiveUserCacheService.SetSession(rotatedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(false));
        harness.ActiveUserCacheService.RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        response.accessToken.ShouldBe(rotatedToken);
        await harness.SessionRepo.Received(1).RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).SetSession(rotatedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.SessionRepo.DidNotReceive().ExpireSession(oldHash, null, cancellationToken: Arg.Any<CancellationToken>());
        await harness.SessionRepo.DidNotReceive().ExpireSession(rotatedHash, null, cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.DidNotReceive().RevokeSession(rotatedHash, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_already_logged_in_old_active_cache_revoke_exception_after_success_still_returns_token()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var originalRefreshToken = Enumerable.Repeat((byte)7, harness.JwtSettings.RefreshTokenBytes).ToArray();
        const string rotatedToken = "rotated-access-token";
        string oldHash = AccessTokenHashUtility.Hash("stored-old-access-token");
        string rotatedHash = AccessTokenHashUtility.Hash(rotatedToken);
        var account = harness.Account(refreshToken: originalRefreshToken, hasTwoFactorAuth: false, activeAccessTokenHash: oldHash);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns(rotatedToken);
        harness.SessionRepo.RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        harness.ActiveUserCacheService.SetSession(rotatedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        harness.ActiveUserCacheService.RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<bool>(new InvalidOperationException("active cache revoke failed")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        response.accessToken.ShouldBe(rotatedToken);
        await harness.SessionRepo.Received(1).RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).SetSession(rotatedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.Received(1).RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>());
        await harness.SessionRepo.DidNotReceive().ExpireSession(oldHash, null, cancellationToken: Arg.Any<CancellationToken>());
        await harness.SessionRepo.DidNotReceive().ExpireSession(rotatedHash, null, cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.DidNotReceive().RevokeSession(rotatedHash, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData("LOGIN_ATTEMPT_STATE_CHANGED")]
    [InlineData("ACCOUNT_SECURITY_STAMP_MISMATCH")]
    public async Task Authenticate_guarded_clear_conflict_prevents_publication_and_does_not_charge_wrong_password(string reason)
    {
        var harness = new AccountControllerHarness(); var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false);
        account.loginAttemptVersion = Guid.NewGuid(); account.loginFailures = 2;
        Guid observed = account.loginAttemptVersion;
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(CredentialLookupResult.Found(account));
        harness.AccountRepo.ClearLoginAttempts(account.accountId,account.accountSecurityStamp,observed,2,null,false,Arg.Any<CancellationToken>())
            .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(false,reason,3,null,Guid.NewGuid()));
        var result = await harness.CreateLoginController().Authenticate(payload);
        AccountControllerHarness.ExtractEnvelope(result,StatusCodes.Status409Conflict).code.ShouldBe("LOGIN_ATTEMPT_STATE_CHANGED");
        await harness.AccountRepo.Received(1).ClearLoginAttempts(account.accountId,account.accountSecurityStamp,observed,2,null,false,Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().RecordLoginFailure(default,default,default,default,Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!,default!,Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!,default!,default,cancellationToken:Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_not_logged_in_cache_write_failure_never_expires_created_db_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false);
        const string token = "active-access-token";
        string hash = AccessTokenHashUtility.Hash(token);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns(token);
        harness.SessionRepo.SetSession(hash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<IntraMessage?>(IntraMessage.SUCCESSFUL));
        harness.ActiveUserCacheService.SetSession(hash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(false));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        response.accessToken.ShouldBe(token);
        await harness.ActiveUserCacheService.Received(1).SetSession(hash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.DidNotReceive().RevokeSession(hash, cancellationToken: Arg.Any<CancellationToken>());
        await harness.SessionRepo.DidNotReceive().ExpireSession(hash, null, cancellationToken: Arg.Any<CancellationToken>());
        await harness.AccountRepo.Received(1).ClearLoginAttempts(account.accountId, account.accountSecurityStamp, Arg.Any<Guid>(), Arg.Any<short>(), Arg.Any<Instant?>(), false, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_already_logged_in_new_cache_write_failure_never_expires_promoted_db_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var originalRefreshToken = Enumerable.Repeat((byte)7, harness.JwtSettings.RefreshTokenBytes).ToArray();
        const string rotatedToken = "rotated-access-token";
        string oldHash = AccessTokenHashUtility.Hash("stored-old-access-token");
        string rotatedHash = AccessTokenHashUtility.Hash(rotatedToken);
        var account = harness.Account(refreshToken: originalRefreshToken, hasTwoFactorAuth: false, activeAccessTokenHash: oldHash);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns(rotatedToken);
        harness.SessionRepo.RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        harness.ActiveUserCacheService.SetSession(rotatedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(false));
        harness.ActiveUserCacheService.RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        response.accessToken.ShouldBe(rotatedToken);
        await harness.SessionRepo.Received(1).RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).SetSession(rotatedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.SessionRepo.DidNotReceive().ExpireSession(oldHash, null, cancellationToken: Arg.Any<CancellationToken>());
        await harness.SessionRepo.DidNotReceive().ExpireSession(rotatedHash, null, cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.DidNotReceive().RevokeSession(rotatedHash, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_two_factor_creates_pending_session_instead_of_active_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(
            refreshToken: null,
            hasTwoFactorAuth: true,
            twoFactorAuthMethod: TwoFactorAuthMethod.SMS_KEY,
            smsUsage: 2);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(BuildTwoFactorDetails(account))));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-two-factor-token");
        harness.TwoFactorSessionService.SetSession(Arg.Any<string>(), Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        harness.LoginProofs.BeginAsync(AccessTokenHashUtility.Hash("pending-two-factor-token"), Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(new LoginProofTransition(true, "PENDING_TWO_FACTOR_SET")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED);
        response.accessToken.ShouldBeNull();
        response.twoFactorAccessToken.ShouldBe("pending-two-factor-token");
        response.twoFactorAuthMethods.ShouldBe(new List<TwoFactorAuthMethod> { TwoFactorAuthMethod.SMS_KEY });
        response.availableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.SMS]);
        harness.HttpContext.Request.Headers["AccessToken"].ToString().ShouldBe(string.Empty);
        string expectedHash = AccessTokenHashUtility.Hash("pending-two-factor-token");
        await harness.TwoFactorSessionService.Received(1).SetSession(
            expectedHash,
            Arg.Is<TwoFactorSession>(session =>
                session.accountId == account.accountId &&
                session.webKey == account.webKey &&
                session.preAuthRefreshToken.Length == harness.JwtSettings.RefreshTokenBytes &&
                session.methods.Single() == TwoFactorAuthMethod.SMS_KEY &&
                session.state == TwoFactorSessionState.SelectionRequired &&
                session.selectedConfiguration == null &&
                session.currentExpectedMethod == null &&
                session.availableConfigurationsSnapshot.SequenceEqual(new[] { TwoFactorAuthConfiguration.SMS }) &&
                session.phoneNumbers != null &&
                session.phoneNumbers.Count == 2 &&
                session.smsUsage == 2 &&
                session.features == account.features &&
                session.expiration > session.createdOn),
            Arg.Is<TimeSpan>(ttl => ttl == TimeSpan.FromMinutes(2)), cancellationToken: Arg.Any<CancellationToken>());
        await harness.LoginProofs.Received(1).BeginAsync(expectedHash, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SuccessfulLogin(account.accountId, account.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_two_factor_future_cutoff_is_copied_into_pending_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        Instant cutoff = SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(45));
        var account = harness.Account(
            refreshToken: null,
            hasTwoFactorAuth: true,
            twoFactorAuthMethod: TwoFactorAuthMethod.EMAIL,
            cutOff: cutoff);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(BuildTwoFactorDetails(account))));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-two-factor-token-cutoff-copy");
        harness.TwoFactorSessionService.SetSession(Arg.Any<string>(), Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        string expectedHash = AccessTokenHashUtility.Hash("pending-two-factor-token-cutoff-copy");
        harness.LoginProofs.BeginAsync(expectedHash, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(new LoginProofTransition(true, "PENDING_TWO_FACTOR_SET")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED);
        await harness.TwoFactorSessionService.Received(1).SetSession(
            expectedHash,
            Arg.Is<TwoFactorSession>(session =>
                session.accountId == account.accountId &&
                session.cutOff == cutoff &&
                session.features == account.features),
            Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_already_logged_in_with_two_factor_captures_prior_active_session_hash_for_final_rotation()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var existingRefreshToken = Enumerable.Repeat((byte)7, harness.JwtSettings.RefreshTokenBytes).ToArray();
        const string priorActiveHash = "old-active-token-hash";
        var account = harness.Account(
            refreshToken: existingRefreshToken,
            activeAccessTokenHash: priorActiveHash,
            hasTwoFactorAuth: true,
            twoFactorAuthMethod: TwoFactorAuthMethod.SMS_KEY,
            smsUsage: 4);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(BuildTwoFactorDetails(account))));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-two-factor-token");
        harness.TwoFactorSessionService.SetSession(Arg.Any<string>(), Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        harness.LoginProofs.BeginAsync(AccessTokenHashUtility.Hash("pending-two-factor-token"), Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(new LoginProofTransition(true, "PENDING_TWO_FACTOR_SET")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED);
        response.accessToken.ShouldBeNull();
        response.twoFactorAccessToken.ShouldBe("pending-two-factor-token");
        response.twoFactorAuthMethods.ShouldBe(new List<TwoFactorAuthMethod> { TwoFactorAuthMethod.SMS_KEY });
        await harness.TwoFactorSessionService.Received(1).SetSession(
            AccessTokenHashUtility.Hash("pending-two-factor-token"),
            Arg.Is<TwoFactorSession>(session =>
                session.accountId == account.accountId &&
                session.methods.Single() == TwoFactorAuthMethod.SMS_KEY &&
                session.phoneNumbers != null &&
                session.phoneNumbers.Count == 4 &&
                session.smsUsage == 4 &&
                session.priorActiveAccessTokenHash == priorActiveHash &&
                session.preAuthRefreshToken.Length == harness.JwtSettings.RefreshTokenBytes),
            Arg.Is<TimeSpan>(ttl => ttl == TimeSpan.FromMinutes(2)), cancellationToken: Arg.Any<CancellationToken>());
        await harness.LoginProofs.Received(1).BeginAsync(AccessTokenHashUtility.Hash("pending-two-factor-token"), Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().RevokeSession(default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SuccessfulLogin(account.accountId, account.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_two_factor_revokes_previous_pending_session_after_replacing_database_pointer()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        const string previousPendingHash = "previous-pending-hash";
        const string newPreAuthToken = "pending-two-factor-token";
        string newPendingHash = AccessTokenHashUtility.Hash(newPreAuthToken);
        var account = harness.Account(
            refreshToken: null,
            hasTwoFactorAuth: true,
            twoFactorAuthMethod: TwoFactorAuthMethod.EMAIL,
            twoFactorAccessToken: previousPendingHash);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(BuildTwoFactorDetails(account))));
        var stateTransitions = new List<string>();
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns(newPreAuthToken);
        harness.TwoFactorSessionService.SetSession(newPendingHash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        harness.TwoFactorSessionService.RevokeSession(previousPendingHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ =>
            {
                stateTransitions.Add("revoke-previous-pending-cache");
                return Task.FromResult(true);
            });
        harness.LoginProofs.BeginAsync(newPendingHash, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>()).Returns(_ => { stateTransitions.Add("replace-database-pointer"); return Task.FromResult(new LoginProofTransition(true, "PENDING_TWO_FACTOR_SET")); });
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED);
        response.accessToken.ShouldBeNull();
        response.twoFactorAccessToken.ShouldBe(newPreAuthToken);
        stateTransitions.ShouldBe(new[] { "replace-database-pointer", "revoke-previous-pending-cache" });
        await harness.LoginProofs.Received(1).BeginAsync(newPendingHash, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>());
        await harness.TwoFactorSessionService.Received(1).RevokeSession(previousPendingHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.TwoFactorSessionService.DidNotReceive().RevokeSession(newPendingHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_two_factor_cache_failure_preserves_durable_pending_token()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(
            refreshToken: null,
            hasTwoFactorAuth: true,
            twoFactorAuthMethod: TwoFactorAuthMethod.SMS_KEY,
            smsUsage: 2);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(BuildTwoFactorDetails(account))));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-two-factor-token");
        harness.TwoFactorSessionService.SetSession(Arg.Any<string>(), Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(false));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED);
        _ = harness.LoginProofs.ReceivedWithAnyArgs(1).BeginAsync(default!, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_two_factor_SQL_denial_does_not_write_or_revoke_pending_cache()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(
            refreshToken: null,
            hasTwoFactorAuth: true,
            twoFactorAuthMethod: TwoFactorAuthMethod.SMS_KEY,
            smsUsage: 2);
        string expectedHash = AccessTokenHashUtility.Hash("pending-two-factor-token");
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(BuildTwoFactorDetails(account))));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-two-factor-token");
        harness.TwoFactorSessionService.SetSession(Arg.Any<string>(), Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        harness.TwoFactorSessionService.RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        harness.LoginProofs.BeginAsync(expectedHash, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(new LoginProofTransition(false, "PENDING_TWO_FACTOR_MISMATCH")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.code.ShouldBe("TWO_FACTOR_PREAUTH_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.TwoFactorSessionService.DidNotReceive().RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_two_factor_SQL_denial_is_independent_of_cache_revoke_failure()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(
            refreshToken: null,
            hasTwoFactorAuth: true,
            twoFactorAuthMethod: TwoFactorAuthMethod.SMS_KEY,
            smsUsage: 2);
        string expectedHash = AccessTokenHashUtility.Hash("pending-two-factor-token");
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(BuildTwoFactorDetails(account))));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-two-factor-token");
        harness.TwoFactorSessionService.SetSession(Arg.Any<string>(), Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        harness.TwoFactorSessionService.RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(false));
        harness.LoginProofs.BeginAsync(expectedHash, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(new LoginProofTransition(false, "PENDING_TWO_FACTOR_MISMATCH")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.code.ShouldBe("TWO_FACTOR_PREAUTH_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.TwoFactorSessionService.DidNotReceive().RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_two_factor_but_no_available_methods_fails_without_creating_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: true, twoFactorAuthMethod: TwoFactorAuthMethod.NONE);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.NotConfigured()));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-two-factor-token");
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.code.ShouldBe("TWO_FACTOR_DETAILS_NOT_CONFIGURED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_two_factor_details_found_but_only_none_method_fails_without_creating_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: true, twoFactorAuthMethod: TwoFactorAuthMethod.NONE);
        var unusableDetails = new TwoFactorDetails(
            [TwoFactorAuthMethod.NONE],
            null,
            null,
            null,
            null);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(unusableDetails)));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.code.ShouldBe("TWO_FACTOR_DETAILS_NOT_CONFIGURED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.JwtUtility.DidNotReceiveWithAnyArgs().GenerateAccessToken(default!, default!, default!);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.LoginProofs.DidNotReceiveWithAnyArgs().BeginAsync(default!, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_two_factor_details_found_but_missing_destination_fails_without_creating_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: true, twoFactorAuthMethod: TwoFactorAuthMethod.EMAIL);
        var unusableDetails = new TwoFactorDetails(
            [TwoFactorAuthMethod.EMAIL],
            null,
            null,
            null,
            ["   "]);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(unusableDetails)));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.code.ShouldBe("TWO_FACTOR_DETAILS_NOT_CONFIGURED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.JwtUtility.DidNotReceiveWithAnyArgs().GenerateAccessToken(default!, default!, default!);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.LoginProofs.DidNotReceiveWithAnyArgs().BeginAsync(default!, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_verified_method_details_ignores_legacy_selected_account_method()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: true, twoFactorAuthMethod: TwoFactorAuthMethod.SMS_KEY);
        var verifiedEmailDetails = new TwoFactorDetails(
            [TwoFactorAuthMethod.EMAIL],
            null,
            null,
            null,
            ["reader@example.com"]);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(verifiedEmailDetails)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-email-token");
        harness.TwoFactorSessionService.SetSession(Arg.Any<string>(), Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        string expectedHash = AccessTokenHashUtility.Hash("pending-email-token");
        harness.LoginProofs.BeginAsync(expectedHash, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(new LoginProofTransition(true, "PENDING_TWO_FACTOR_SET")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED);
        response.accessToken.ShouldBeNull();
        response.twoFactorAccessToken.ShouldBe("pending-email-token");
        response.twoFactorAuthMethods.ShouldBe(new List<TwoFactorAuthMethod> { TwoFactorAuthMethod.EMAIL });
        response.availableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.EMAIL]);
        await harness.TwoFactorSessionService.Received(1).SetSession(
            expectedHash,
            Arg.Is<TwoFactorSession>(session =>
                session.accountId == account.accountId &&
                session.methods.Single() == TwoFactorAuthMethod.EMAIL &&
                session.emailAddresses != null &&
                session.emailAddresses.Single() == "reader@example.com"),
            Arg.Is<TimeSpan>(ttl => ttl == TimeSpan.FromMinutes(2)), cancellationToken: Arg.Any<CancellationToken>());
        await harness.LoginProofs.Received(1).BeginAsync(expectedHash, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_authenticator_app_only_two_factor_details_creates_pending_session()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(
            refreshToken: null,
            hasTwoFactorAuth: true,
            twoFactorAuthMethod: TwoFactorAuthMethod.AUTHENTICATOR_APP,
            authenticatorAppUsage: 1);
        var authenticatorAppOnlyDetails = new TwoFactorDetails(
            [TwoFactorAuthMethod.AUTHENTICATOR_APP],
            ["authenticator-app-user-1"],
            null,
            null,
            null);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(authenticatorAppOnlyDetails)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-authenticator-token");
        harness.TwoFactorSessionService.SetSession(Arg.Any<string>(), Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        string expectedHash = AccessTokenHashUtility.Hash("pending-authenticator-token");
        harness.LoginProofs.BeginAsync(expectedHash, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(new LoginProofTransition(true, "PENDING_TWO_FACTOR_SET")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED);
        response.accessToken.ShouldBeNull();
        response.twoFactorAccessToken.ShouldBe("pending-authenticator-token");
        response.twoFactorAuthMethods.ShouldBe(new List<TwoFactorAuthMethod> { TwoFactorAuthMethod.AUTHENTICATOR_APP });
        response.availableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);
        await harness.TwoFactorSessionService.Received(1).SetSession(
            expectedHash,
            Arg.Is<TwoFactorSession>(session =>
                session.accountId == account.accountId &&
                session.methods.Single() == TwoFactorAuthMethod.AUTHENTICATOR_APP &&
                session.authenticatorAppUsage == 1 &&
                session.userAuthIds != null &&
                session.userAuthIds.Single() == "authenticator-app-user-1" &&
                session.phoneNumbers == null &&
                session.emailAddresses == null),
            Arg.Is<TimeSpan>(ttl => ttl == TimeSpan.FromMinutes(2)), cancellationToken: Arg.Any<CancellationToken>());
        await harness.LoginProofs.Received(1).BeginAsync(expectedHash, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_email_sms_and_authenticator_app_details_advertises_all_verified_methods()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(
            refreshToken: null,
            hasTwoFactorAuth: true,
            twoFactorAuthMethod: TwoFactorAuthMethod.AUTHENTICATOR_APP,
            authenticatorAppUsage: 1,
            smsUsage: 1);
        var allVerifiedDetails = new TwoFactorDetails(
            [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP],
            ["authenticator-app-user-1"],
            ["5555550101"],
            ["1"],
            ["reader@example.com"]);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(allVerifiedDetails)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-all-methods-token");
        harness.TwoFactorSessionService.SetSession(Arg.Any<string>(), Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        string expectedHash = AccessTokenHashUtility.Hash("pending-all-methods-token");
        harness.LoginProofs.BeginAsync(expectedHash, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(new LoginProofTransition(true, "PENDING_TWO_FACTOR_SET")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        var response = AccountControllerHarness.ExtractAuthenticate(actionResult);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED);
        response.accessToken.ShouldBeNull();
        response.twoFactorAccessToken.ShouldBe("pending-all-methods-token");
        response.twoFactorAuthMethods.ShouldBe(new List<TwoFactorAuthMethod>
        {
            TwoFactorAuthMethod.EMAIL,
            TwoFactorAuthMethod.SMS_KEY,
            TwoFactorAuthMethod.AUTHENTICATOR_APP
        });
        response.availableTwoFactorAuthConfigurations.ShouldBe(new List<TwoFactorAuthConfiguration>
        {
            TwoFactorAuthConfiguration.SMS,
            TwoFactorAuthConfiguration.EMAIL,
            TwoFactorAuthConfiguration.AUTHENTICATOR_APP,
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP,
            TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP
        });
        await harness.TwoFactorSessionService.Received(1).SetSession(
            expectedHash,
            Arg.Is<TwoFactorSession>(session =>
                session.accountId == account.accountId &&
                session.methods.SequenceEqual(new[]
                {
                    TwoFactorAuthMethod.EMAIL,
                    TwoFactorAuthMethod.SMS_KEY,
                    TwoFactorAuthMethod.AUTHENTICATOR_APP
                }) &&
                session.emailAddresses != null &&
                session.emailAddresses.Single() == "reader@example.com" &&
                session.phoneNumbers != null &&
                session.phoneNumbers.Single() == "5555550101" &&
                session.phoneCountryCode != null &&
                session.phoneCountryCode.Single() == "1" &&
                session.userAuthIds != null &&
                session.userAuthIds.Single() == "authenticator-app-user-1" &&
                session.smsUsage == 1 &&
                session.authenticatorAppUsage == 1),
            Arg.Is<TimeSpan>(ttl => ttl == TimeSpan.FromMinutes(2)), cancellationToken: Arg.Any<CancellationToken>());
        await harness.LoginProofs.Received(1).BeginAsync(expectedHash, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_two_factor_details_lookup_failure_returns_lookup_failure()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(
            refreshToken: null,
            hasTwoFactorAuth: true,
            twoFactorAuthMethod: TwoFactorAuthMethod.SMS_KEY,
            smsUsage: 2);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Failed()));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-two-factor-token");
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.code.ShouldBe("TWO_FACTOR_DETAILS_LOOKUP_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.LoginProofs.DidNotReceiveWithAnyArgs().BeginAsync(default!, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_two_factor_cache_exception_preserves_durable_pending_token()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(
            refreshToken: null,
            hasTwoFactorAuth: true,
            twoFactorAuthMethod: TwoFactorAuthMethod.SMS_KEY,
            smsUsage: 2);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(BuildTwoFactorDetails(account))));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-two-factor-token");
        harness.TwoFactorSessionService.SetSession(Arg.Any<string>(), Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<bool?>(new InvalidOperationException("redis write failed")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED);
        _ = harness.LoginProofs.ReceivedWithAnyArgs(1).BeginAsync(default!, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_with_two_factor_SQL_denial_is_independent_of_cache_revoke_exception()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(
            refreshToken: null,
            hasTwoFactorAuth: true,
            twoFactorAuthMethod: TwoFactorAuthMethod.SMS_KEY,
            smsUsage: 2);
        string expectedHash = AccessTokenHashUtility.Hash("pending-two-factor-token");
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(BuildTwoFactorDetails(account))));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-two-factor-token");
        harness.TwoFactorSessionService.SetSession(Arg.Any<string>(), Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        harness.TwoFactorSessionService.RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<bool>(new InvalidOperationException("redis revoke failed")));
        harness.LoginProofs.BeginAsync(expectedHash, Arg.Any<TwoFactorSession>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult(new LoginProofTransition(false, "PENDING_TWO_FACTOR_MISMATCH")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.code.ShouldBe("TWO_FACTOR_PREAUTH_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.TwoFactorSessionService.DidNotReceive().RevokeSession(expectedHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }




    [Fact]
    public async Task Authenticate_login_abuse_policy_increments_ip_and_identifier_before_account_lookup()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload(emailAddress: "Reader@Example.com");
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.NotFound()));
        var controller = harness.CreateLoginController();
        harness.HttpContext.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.42");

        var actionResult = await controller.Authenticate(payload);

        AccountControllerHarness.ExtractAuthenticate(actionResult, StatusCodes.Status401Unauthorized)
            .result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        await harness.AbuseCounterStore.Received(1).IncrementAsync(
            Arg.Is<AbuseCounterKey>(key =>
                key.Feature == AbuseFeature.Login &&
                key.Dimension == AbuseCounterDimension.IpFingerprint &&
                !key.Value.Contains("203.0.113.42", StringComparison.Ordinal)),
            Arg.Is<AbuseCounterLimit>(limit =>
                limit.MaxAttempts == harness.AbuseControlSettings.Login.MaxAttemptsPerIpPerWindow &&
                limit.Window == TimeSpan.FromSeconds(harness.AbuseControlSettings.Login.WindowSeconds) &&
                limit.Cooldown == TimeSpan.FromSeconds(harness.AbuseControlSettings.Login.CooldownSeconds)),
            Arg.Any<CancellationToken>());
        await harness.AbuseCounterStore.Received(1).IncrementAsync(
            Arg.Is<AbuseCounterKey>(key =>
                key.Feature == AbuseFeature.Login &&
                key.Dimension == AbuseCounterDimension.IdentifierFingerprint &&
                key.SafeId.StartsWith("email-", StringComparison.Ordinal) &&
                !key.Value.Contains("reader", StringComparison.OrdinalIgnoreCase) &&
                !key.Value.Contains("example.com", StringComparison.OrdinalIgnoreCase)),
            Arg.Is<AbuseCounterLimit>(limit => limit.MaxAttempts == harness.AbuseControlSettings.Login.MaxAttemptsPerIdentifierPerWindow),
            Arg.Any<CancellationToken>());
        await harness.AccountRepo.Received(1).GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>());
        await harness.AbuseCounterStore.DidNotReceive().IncrementAsync(
            Arg.Is<AbuseCounterKey>(key => key.Dimension == AbuseCounterDimension.Account),
            Arg.Any<AbuseCounterLimit>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_login_ip_throttle_returns_429_before_account_lookup()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        harness.AbuseCounterStore.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.Login && key.Dimension == AbuseCounterDimension.IpFingerprint),
                Arg.Any<AbuseCounterLimit>(),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    Allowed: false,
                    CurrentCount: limit.MaxAttempts + 1,
                    Limit: limit.MaxAttempts,
                    Window: limit.Window,
                    RetryAfter: TimeSpan.FromSeconds(60),
                    ReasonCode: AbuseReasonCodes.CounterLimitExceeded));
            });
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status429TooManyRequests);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(AbuseReasonCodes.LoginThrottleExceeded);
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        harness.HttpContext.Response.Headers["Retry-After"].ToString().ShouldBe("60");
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().GetCredentials(default!, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_login_counter_unavailable_fails_closed_before_account_lookup()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        harness.AbuseCounterStore.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.Login && key.Dimension == AbuseCounterDimension.IpFingerprint),
                Arg.Any<AbuseCounterLimit>(),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    Allowed: false,
                    CurrentCount: 0,
                    Limit: limit.MaxAttempts,
                    Window: limit.Window,
                    RetryAfter: null,
                    ReasonCode: AbuseReasonCodes.CounterStoreUnavailable));
            });
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status503ServiceUnavailable);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(AbuseReasonCodes.CounterStoreUnavailable);
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().GetCredentials(default!, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_login_account_throttle_runs_after_sql_lockout_check()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(unlockWhen: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status423Locked);
        envelope.code.ShouldBe(HttpMessage.ACCOUNT_TIME_LOCKED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_TIME_LOCKED);
        await harness.AbuseCounterStore.DidNotReceive().IncrementAsync(
            Arg.Is<AbuseCounterKey>(key => key.Dimension == AbuseCounterDimension.Account),
            Arg.Any<AbuseCounterLimit>(),
            Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_login_account_throttle_denies_generically_before_password_verification_and_sql_failure_increment()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload(password: "WrongPassword1!");
        var account = harness.Account(loginFailures: 1);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.AbuseCounterStore.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.Login && key.Dimension == AbuseCounterDimension.Account),
                Arg.Any<AbuseCounterLimit>(),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    Allowed: false,
                    CurrentCount: limit.MaxAttempts + 1,
                    Limit: limit.MaxAttempts,
                    Window: limit.Window,
                    RetryAfter: TimeSpan.FromSeconds(45),
                    ReasonCode: AbuseReasonCodes.CounterLimitExceeded));
            });
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.AccountRepo.DidNotReceive().SetLoginFailures(account.accountId, Arg.Any<int>(), cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().SetLockOut(Arg.Any<Guid>(), Arg.Any<short?>(), cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_successful_password_resets_account_and_identifier_login_abuse_counters()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload(emailAddress: "Reader@Example.com");
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false);
        const string token = "active-access-token";
        string hash = AccessTokenHashUtility.Hash(token);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(treehammock.Repos.CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns(token);
        harness.SessionRepo.SetSession(hash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<IntraMessage?>(IntraMessage.SUCCESSFUL));
        harness.ActiveUserCacheService.SetSession(hash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        AccountControllerHarness.ExtractAuthenticate(actionResult).result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        await harness.AbuseCounterStore.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key =>
                key.Feature == AbuseFeature.Login &&
                key.Dimension == AbuseCounterDimension.Account &&
                key.SafeId == account.accountId.ToString("N")),
            Arg.Any<CancellationToken>());
        await harness.AbuseCounterStore.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key =>
                key.Feature == AbuseFeature.Login &&
                key.Dimension == AbuseCounterDimension.IdentifierFingerprint &&
                key.SafeId.StartsWith("email-", StringComparison.Ordinal) &&
                !key.Value.Contains("reader", StringComparison.OrdinalIgnoreCase)),
            Arg.Any<CancellationToken>());
        await harness.AbuseCounterStore.DidNotReceive().ResetAsync(
            Arg.Is<AbuseCounterKey>(key => key.Dimension == AbuseCounterDimension.IpFingerprint),
            Arg.Any<CancellationToken>());
    }

    private static TwoFactorDetails BuildTwoFactorDetails(treehammock.DataLayer.Account.IntraAccount account)
    {
        int count = account.twoFactorAuthMethod switch
        {
            TwoFactorAuthMethod.AUTHENTICATOR_APP => Math.Max(1, (int)account.authenticatorAppUsage),
            TwoFactorAuthMethod.SMS_KEY => Math.Max(1, (int)account.smsUsage),
            TwoFactorAuthMethod.EMAIL => 1,
            _ => 0
        };

        List<TwoFactorAuthMethod> methods = Enumerable.Repeat(account.twoFactorAuthMethod, count).ToList();
        List<string>? authenticatorAppIds = account.twoFactorAuthMethod == TwoFactorAuthMethod.AUTHENTICATOR_APP
            ? Enumerable.Range(1, count).Select(index => $"authenticator-app-user-{index}").ToList()
            : null;
        List<string>? phoneNumbers = account.twoFactorAuthMethod == TwoFactorAuthMethod.SMS_KEY
            ? Enumerable.Range(1, count).Select(index => $"555555010{index}").ToList()
            : null;
        List<string>? countryCodes = account.twoFactorAuthMethod == TwoFactorAuthMethod.SMS_KEY
            ? Enumerable.Repeat("1", count).ToList()
            : null;
        List<string>? emails = account.twoFactorAuthMethod == TwoFactorAuthMethod.EMAIL
            ? ["reader@example.com"]
            : null;

        return new TwoFactorDetails(methods, authenticatorAppIds, phoneNumbers, countryCodes, emails);
    }


    public static IEnumerable<object[]> InvalidLoginIdentifierCases()
    {
        yield return new object[] { new AuthenticateLogin("not-an-email", AccountControllerHarness.ValidPassword) };
        yield return new object[] { new AuthenticateLogin("", AccountControllerHarness.ValidPassword) };
        yield return new object[] { new AuthenticateLogin("   ", AccountControllerHarness.ValidPassword) };
        yield return new object[] { new AuthenticateLogin(null!, "ab", AccountControllerHarness.ValidPassword) };
        yield return new object[] { new AuthenticateLogin(null!, "", AccountControllerHarness.ValidPassword) };
        yield return new object[] { new AuthenticateLogin(null!, "   ", AccountControllerHarness.ValidPassword) };
        yield return new object[] { new AuthenticateLogin(new string('a', 260) + "@example.com", AccountControllerHarness.ValidPassword) };
    }

    public static IEnumerable<object[]> SuppliedInvalidLoginIdentifierCases()
    {
        yield return new object[] { new AuthenticateLogin("not-an-email", "reader", AccountControllerHarness.ValidPassword), nameof(AuthenticateLogin.emailAddress) };
        yield return new object[] { new AuthenticateLogin("reader@example.com", "ab", AccountControllerHarness.ValidPassword), nameof(AuthenticateLogin.username) };
        yield return new object[] { new AuthenticateLogin("reader@example.com", new string('u', 31), AccountControllerHarness.ValidPassword), nameof(AuthenticateLogin.username) };
    }

    public static IEnumerable<object[]> LoginIdentifierCases()
    {
        yield return new object[] { new AuthenticateLogin("reader@example.com", AccountControllerHarness.ValidPassword), AccountLoginAction.EMAIL };
        yield return new object[] { new AuthenticateLogin(null!, "reader", AccountControllerHarness.ValidPassword), AccountLoginAction.USERNAME };
        yield return new object[] { new AuthenticateLogin("reader@example.com", "reader", AccountControllerHarness.ValidPassword), AccountLoginAction.BOTH };
    }
}
