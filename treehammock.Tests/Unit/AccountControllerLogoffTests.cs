using Microsoft.AspNetCore.Http;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.Controllers;
using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Models.Api;
using treehammock.Models.Authentication;
using treehammock.Rigging.Authorization;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class AccountControllerLogoffTests
{
    [Fact]
    public async Task LogoffAccount_success_expires_current_db_session_revokes_cache_and_clears_client_token()
    {
        var harness = new AccountControllerHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        const string accessTokenHash = "current-access-token-hash";
        ActiveSession activeSession = BuildActiveSession(accountId, accountSecurityStamp);

        harness.SessionRepo.LogoutCurrentSession(accountId, accessTokenHash, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "CURRENT_SESSION_LOGGED_OUT")));
        harness.ActiveUserCacheService.RevokeSession(accessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));

        AccountSessionController controller = harness.CreateSessionController();
        SetAuthenticatedContext(harness, accessTokenHash, activeSession);

        var actionResult = await controller.LogoffAccount(new AuthenticateLogoffRequest());

        ApiResponse<AuthenticateLogoffResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("LOGOFF_SUCCEEDED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_LOGOFF_SUCCEEDED);
        harness.HttpContext.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        await harness.SessionRepo.Received(1).LogoutCurrentSession(accountId, accessTokenHash, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).RevokeSession(accessTokenHash, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LogoffAccount_accepts_missing_body_as_empty_logout_request()
    {
        var harness = new AccountControllerHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        const string accessTokenHash = "current-access-token-hash";
        ActiveSession activeSession = BuildActiveSession(accountId, accountSecurityStamp);

        harness.SessionRepo.LogoutCurrentSession(accountId, accessTokenHash, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "CURRENT_SESSION_LOGGED_OUT")));
        harness.ActiveUserCacheService.RevokeSession(accessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));

        AccountSessionController controller = harness.CreateSessionController();
        SetAuthenticatedContext(harness, accessTokenHash, activeSession);

        var actionResult = await controller.LogoffAccount(null);

        ApiResponse<AuthenticateLogoffResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("LOGOFF_SUCCEEDED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_LOGOFF_SUCCEEDED);
        await harness.SessionRepo.Received(1).LogoutCurrentSession(accountId, accessTokenHash, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LogoffAccount_returns_success_with_warning_when_cache_revoke_fails_after_db_success()
    {
        var harness = new AccountControllerHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        const string accessTokenHash = "current-access-token-hash";
        ActiveSession activeSession = BuildActiveSession(accountId, accountSecurityStamp);

        harness.SessionRepo.LogoutCurrentSession(accountId, accessTokenHash, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "CURRENT_SESSION_LOGGED_OUT")));
        harness.ActiveUserCacheService.RevokeSession(accessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(false));

        AccountSessionController controller = harness.CreateSessionController();
        SetAuthenticatedContext(harness, accessTokenHash, activeSession);

        var actionResult = await controller.LogoffAccount(new AuthenticateLogoffRequest());

        ApiResponse<AuthenticateLogoffResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("LOGOFF_CACHE_REVOKE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_LOGOFF_SUCCEEDED);
        harness.HttpContext.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        await harness.SessionRepo.Received(1).LogoutCurrentSession(accountId, accessTokenHash, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).RevokeSession(accessTokenHash, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LogoffAccount_database_failure_does_not_revoke_cache()
    {
        var harness = new AccountControllerHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        const string accessTokenHash = "current-access-token-hash";
        ActiveSession activeSession = BuildActiveSession(accountId, accountSecurityStamp);

        harness.SessionRepo.LogoutCurrentSession(accountId, accessTokenHash, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(false, "ACCOUNT_SECURITY_STAMP_MISMATCH")));

        AccountSessionController controller = harness.CreateSessionController();
        SetAuthenticatedContext(harness, accessTokenHash, activeSession);

        var actionResult = await controller.LogoffAccount(new AuthenticateLogoffRequest());

        ApiResponse<AuthenticateLogoffResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_LOGOFF_FAILED);
        await harness.SessionRepo.Received(1).LogoutCurrentSession(accountId, accessTokenHash, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().RevokeSession(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LogoffAccount_missing_authenticated_session_context_returns_unauthorized_without_repo_work()
    {
        var harness = new AccountControllerHarness();
        AccountSessionController controller = harness.CreateSessionController();

        var actionResult = await controller.LogoffAccount(new AuthenticateLogoffRequest());

        ApiResponse<AuthenticateLogoffResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().LogoutCurrentSession(default, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().RevokeSession(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LogoffAllAccount_success_rotates_account_stamp_revokes_current_cache_and_clears_client_token()
    {
        var harness = new AccountControllerHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Guid newAccountSecurityStamp = Guid.NewGuid();
        const string accessTokenHash = "current-access-token-hash";
        ActiveSession activeSession = BuildActiveSession(accountId, accountSecurityStamp);

        harness.SessionRepo.LogoutAllSessions(accountId, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountStampRotationResult?>(new AccountStampRotationResult(true, "ALL_SESSIONS_LOGGED_OUT", newAccountSecurityStamp)));
        harness.ActiveUserCacheService.RevokeSession(accessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));

        AccountSessionController controller = harness.CreateSessionController();
        SetAuthenticatedContext(harness, accessTokenHash, activeSession);

        var actionResult = await controller.LogoffAllAccount(new AuthenticateLogoffAllRequest());

        ApiResponse<AuthenticateLogoffAllResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("LOGOFF_ALL_SUCCEEDED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_LOGOFF_ALL_SUCCEEDED);
        harness.HttpContext.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        await harness.SessionRepo.Received(1).LogoutAllSessions(accountId, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).RevokeSession(accessTokenHash, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LogoffAllAccount_accepts_missing_body_as_default_request()
    {
        var harness = new AccountControllerHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Guid newAccountSecurityStamp = Guid.NewGuid();
        const string accessTokenHash = "current-access-token-hash";
        ActiveSession activeSession = BuildActiveSession(accountId, accountSecurityStamp);

        harness.SessionRepo.LogoutAllSessions(accountId, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountStampRotationResult?>(new AccountStampRotationResult(true, "ALL_SESSIONS_LOGGED_OUT", newAccountSecurityStamp)));
        harness.ActiveUserCacheService.RevokeSession(accessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));

        AccountSessionController controller = harness.CreateSessionController();
        SetAuthenticatedContext(harness, accessTokenHash, activeSession);

        var actionResult = await controller.LogoffAllAccount(null);

        ApiResponse<AuthenticateLogoffAllResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("LOGOFF_ALL_SUCCEEDED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_LOGOFF_ALL_SUCCEEDED);
        await harness.SessionRepo.Received(1).LogoutAllSessions(accountId, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LogoffAllAccount_rejects_include_current_session_false()
    {
        var harness = new AccountControllerHarness();
        AccountSessionController controller = harness.CreateSessionController();

        var actionResult = await controller.LogoffAllAccount(new AuthenticateLogoffAllRequest { includeCurrentSession = false });

        ApiResponse<AuthenticateLogoffAllResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.Any(e => e.field == nameof(AuthenticateLogoffAllRequest.includeCurrentSession)).ShouldBeTrue();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_LOGOFF_FAILED);
    }

    [Fact]
    public async Task LogoffAllAccount_database_failure_does_not_revoke_cache()
    {
        var harness = new AccountControllerHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        const string accessTokenHash = "current-access-token-hash";
        ActiveSession activeSession = BuildActiveSession(accountId, accountSecurityStamp);

        harness.SessionRepo.LogoutAllSessions(accountId, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountStampRotationResult?>(new AccountStampRotationResult(false, "ACCOUNT_SECURITY_STAMP_MISMATCH", null)));

        AccountSessionController controller = harness.CreateSessionController();
        SetAuthenticatedContext(harness, accessTokenHash, activeSession);

        var actionResult = await controller.LogoffAllAccount(new AuthenticateLogoffAllRequest());

        ApiResponse<AuthenticateLogoffAllResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_LOGOFF_FAILED);
        await harness.SessionRepo.Received(1).LogoutAllSessions(accountId, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().RevokeSession(default!, cancellationToken: Arg.Any<CancellationToken>());
    }



    [Fact]
    public async Task ListActiveSessions_success_returns_session_summaries_without_cache_mutation()
    {
        var harness = new AccountControllerHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        const string accessTokenHash = "current-access-token-hash";
        ActiveSession activeSession = BuildActiveSession(accountId, accountSecurityStamp);
        AccountSessionSummary summary = BuildSessionSummary(isCurrent: true);

        harness.SessionRepo.ListActiveSessions(accountId, accountSecurityStamp, accessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IReadOnlyList<AccountSessionSummary>?>(new[] { summary }));

        AccountSessionController controller = harness.CreateSessionController();
        SetAuthenticatedContext(harness, accessTokenHash, activeSession);

        var actionResult = await controller.ListActiveSessions();

        ApiResponse<AccountSessionsResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("SESSIONS_LISTED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_SESSIONS_LISTED);
        envelope.data.sessions.Count.ShouldBe(1);
        envelope.data.sessions[0].sessionId.ShouldBe(summary.sessionId);
        envelope.data.sessions[0].isCurrent.ShouldBeTrue();
        await harness.SessionRepo.Received(1).ListActiveSessions(accountId, accountSecurityStamp, accessTokenHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().RevokeSession(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RevokeSession_success_expires_owned_session_without_revoking_current_cache()
    {
        var harness = new AccountControllerHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Guid targetSessionId = Guid.NewGuid();
        const string accessTokenHash = "current-access-token-hash";
        ActiveSession activeSession = BuildActiveSession(accountId, accountSecurityStamp);

        harness.SessionRepo.RevokeSessionForAccount(accountId, targetSessionId, accountSecurityStamp, accessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "SESSION_REVOKED")));

        AccountSessionController controller = harness.CreateSessionController();
        SetAuthenticatedContext(harness, accessTokenHash, activeSession);

        var actionResult = await controller.RevokeSession(new AccountSessionRevokeRequest(targetSessionId));

        ApiResponse<AccountSessionRevokeResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("SESSION_REVOKED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_SESSION_REVOKED);
        harness.HttpContext.Response.Headers.ContainsKey("AppStatus").ShouldBeFalse();
        await harness.SessionRepo.Received(1).RevokeSessionForAccount(accountId, targetSessionId, accountSecurityStamp, accessTokenHash, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().RevokeSession(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RevokeSession_preserves_already_missing_or_stale_success_code()
    {
        var harness = new AccountControllerHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Guid targetSessionId = Guid.NewGuid();
        const string accessTokenHash = "current-access-token-hash";
        ActiveSession activeSession = BuildActiveSession(accountId, accountSecurityStamp);

        harness.SessionRepo.RevokeSessionForAccount(accountId, targetSessionId, accountSecurityStamp, accessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "SESSION_ALREADY_MISSING_OR_STALE")));

        AccountSessionController controller = harness.CreateSessionController();
        SetAuthenticatedContext(harness, accessTokenHash, activeSession);

        var actionResult = await controller.RevokeSession(new AccountSessionRevokeRequest(targetSessionId));

        ApiResponse<AccountSessionRevokeResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("SESSION_ALREADY_MISSING_OR_STALE");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_SESSION_REVOKED);
        harness.HttpContext.Response.Headers.ContainsKey("AppStatus").ShouldBeFalse();
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().RevokeSession(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RevokeSession_stale_account_stamp_returns_unauthorized_without_cache_revoke()
    {
        var harness = new AccountControllerHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Guid targetSessionId = Guid.NewGuid();
        const string accessTokenHash = "current-access-token-hash";
        ActiveSession activeSession = BuildActiveSession(accountId, accountSecurityStamp);

        harness.SessionRepo.RevokeSessionForAccount(accountId, targetSessionId, accountSecurityStamp, accessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(false, "ACCOUNT_SECURITY_STAMP_MISMATCH")));

        AccountSessionController controller = harness.CreateSessionController();
        SetAuthenticatedContext(harness, accessTokenHash, activeSession);

        var actionResult = await controller.RevokeSession(new AccountSessionRevokeRequest(targetSessionId));

        ApiResponse<AccountSessionRevokeResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_SESSION_REVOKE_FAILED);
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().RevokeSession(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RevokeSession_current_session_revokes_cache_and_clears_client_token()
    {
        var harness = new AccountControllerHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Guid targetSessionId = Guid.NewGuid();
        const string accessTokenHash = "current-access-token-hash";
        ActiveSession activeSession = BuildActiveSession(accountId, accountSecurityStamp);

        harness.SessionRepo.RevokeSessionForAccount(accountId, targetSessionId, accountSecurityStamp, accessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "CURRENT_SESSION_REVOKED")));
        harness.ActiveUserCacheService.RevokeSession(accessTokenHash, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));

        AccountSessionController controller = harness.CreateSessionController();
        SetAuthenticatedContext(harness, accessTokenHash, activeSession);

        var actionResult = await controller.RevokeSession(new AccountSessionRevokeRequest(targetSessionId));

        ApiResponse<AccountSessionRevokeResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("CURRENT_SESSION_REVOKED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_SESSION_REVOKED);
        harness.HttpContext.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        await harness.SessionRepo.Received(1).RevokeSessionForAccount(accountId, targetSessionId, accountSecurityStamp, accessTokenHash, cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.Received(1).RevokeSession(accessTokenHash, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RevokeSession_rejects_empty_session_id_as_validation_failure()
    {
        var harness = new AccountControllerHarness();
        AccountSessionController controller = harness.CreateSessionController();

        var actionResult = await controller.RevokeSession(new AccountSessionRevokeRequest(Guid.Empty));

        ApiResponse<AccountSessionRevokeResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_SESSION_REVOKE_FAILED);
    }

    private static ActiveSession BuildActiveSession(Guid accountId, Guid accountSecurityStamp)
    {
        Instant now = SystemClock.Instance.GetCurrentInstant();
        return treehammock.Tests.Support.EntitlementTestData.Attach(new ActiveSession(
            accountId,
            new byte[64],
            0,
            now,
            Period.FromHours(1),
            now.Plus(Duration.FromMinutes(15)),
            now.Plus(Duration.FromHours(1)),
            null,
            FeatureSet.basic,
            accountSecurityStamp: accountSecurityStamp));
    }



    private static AccountSessionSummary BuildSessionSummary(bool isCurrent)
    {
        Instant now = SystemClock.Instance.GetCurrentInstant();
        return new AccountSessionSummary(
            Guid.NewGuid(),
            now.Minus(Duration.FromMinutes(5)),
            now.Plus(Duration.FromMinutes(15)),
            now.Plus(Duration.FromHours(1)),
            FeatureSet.basic,
            isCurrent);
    }

    private static void SetAuthenticatedContext(AccountControllerHarness harness, string accessTokenHash, ActiveSession activeSession)    {
        harness.HttpContext.Items[AuthContextItems.HashedAccessToken] = accessTokenHash;
        harness.HttpContext.Items[AuthContextItems.ActiveSession] = activeSession;
    }
}
