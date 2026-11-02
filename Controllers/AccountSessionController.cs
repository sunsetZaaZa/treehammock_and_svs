using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Globalization;

using NodaTime;
using Geralt;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Models.Authentication;
using treehammock.Models.Account;
using treehammock.Repos;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Authorization;
using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Services;
using treehammock.RiggingSupport.Status;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.Entities;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;
using treehammock.Rigging.Security;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Replay;
using treehammock.Models.Api;

namespace treehammock.Controllers;

[Authenticate]
[ApiController]
[Route("account")]
[Produces("application/json")]
public sealed class AccountSessionController : AccountControllerBase
{
    [AllowAnonymous]
    [HttpPost("refresh")]
    [ProducesResponseType(typeof(ApiResponse<RefreshSessionResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<RefreshSessionResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<RefreshSessionResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<RefreshSessionResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<RefreshSessionResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<RefreshSessionResponse>>> Refresh([FromBody] RefreshSessionRequest payload)
    {
        // The endpoint validates a separate refresh credential; [AllowAnonymous]
        // does not grant ordinary access to an expired/superseded access token.
        treehammock.Rigging.Hosting.SecurityResponseCacheMiddleware.Apply(Response);
        var operationSettings = HttpContext.RequestServices.GetRequiredService<IOptions<SecurityOperationSettings>>().Value;
        var key = Request.Headers[treehammock.Rigging.Operations.SecurityOperationMiddleware.KeyHeader].ToString();
        var recovery = Request.Headers[treehammock.Rigging.Operations.SecurityOperationMiddleware.RecoveryHeader].ToString();
        if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(recovery))
            return ToActionResult(new ApiOutcome<RefreshSessionResponse>(new(), 428, "SECURITY_OPERATION_KEYS_REQUIRED"));
        _ = treehammock.DataLayer.Operations.SecurityOperationKey.Parse(key, operationSettings.RetentionSeconds);
        byte[] recoveryBytes = treehammock.DataLayer.Operations.SecurityOperationKey.ParseRecoveryKey(recovery);
        CryptographicOperations.ZeroMemory(recoveryBytes);
        var outcome = await HttpContext.RequestServices.GetRequiredService<SessionRefreshService>().RefreshAsync(payload, HttpContext.RequestAborted);
        if (outcome.Session is not null) SessionProtocol.WriteHeaders(Response, outcome.Session);
        if (outcome.Status == 429) Response.Headers.RetryAfter = _jwtSettings.MinimumRefreshIntervalSeconds.ToString(CultureInfo.InvariantCulture);
        return ToActionResult(new ApiOutcome<RefreshSessionResponse>(outcome.Response, outcome.Status, outcome.Code));
    }

    public AccountSessionController(IAccountRepo accountRepo, ISessionRepo sessionRepo, IActiveUserCacheService activeUserCacheService, ITwoFactorSessionService twoFactorSessionService,
                                IJsonWebTokenUtility jwtUtility, ITwoFactorAuthenticateService twoFactorService, IAccountService accountService,
                                IAbuseCounterStore abuseCounterStore, ILoginAbuseCounterKeyFactory loginAbuseCounterKeyFactory,
                                IOptions<RegistrationSettings> registrationSettings, IOptions<JWTSettings> jwtSettings, IOptions<LoginSettings> loginSettings,
                                IOptions<AbuseControlSettings> abuseControlSettings,
                                IOptions<EmailTemplateSettings>? emailTemplateSettings = null,
                                IAccountTokenVerificationAbuseCounterKeyFactory? accountTokenVerificationAbuseCounterKeyFactory = null,
                                IAuthenticatedMutationIdempotencyService? authenticatedMutationIdempotencyService = null)
        : base(accountRepo,
        sessionRepo,
        activeUserCacheService,
        twoFactorSessionService,
        jwtUtility,
        twoFactorService,
        accountService,
        abuseCounterStore,
        loginAbuseCounterKeyFactory,
        registrationSettings,
        jwtSettings,
        loginSettings,
        abuseControlSettings,
        emailTemplateSettings,
        accountTokenVerificationAbuseCounterKeyFactory,
        authenticatedMutationIdempotencyService)
    {
    }


    [HttpPost("reauthenticate")]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status423Locked)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<ReauthenticateResponse>>> Reauthenticate([FromBody] ReauthenticateRequest? payload)
    {
        var validation = ValidateReauthenticateRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<ReauthenticateResponse>(
                new ReauthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        IAccountSensitiveActionService? sensitiveActionService = HttpContext.RequestServices.GetService<IAccountSensitiveActionService>();
        if (sensitiveActionService is null)
        {
            return ToActionResult(new ApiOutcome<ReauthenticateResponse>(
                new ReauthenticateResponse(HttpMessage.SENSITIVE_ACTION_TOKEN_ISSUE_FAILED),
                StatusCodes.Status500InternalServerError,
                AccountSensitiveActionService.TokenIssueFailedCode));
        }

        SensitiveActionIssueResult result = await sensitiveActionService.ReauthenticateAsync(
            new SensitiveActionReauthenticationCommand(
                activeSession.accountId,
                activeSession.accountSecurityStamp,
                hashedAccessToken,
                payload!.password,
                payload.purpose, payload.target, ResolveRemoteIpAddress()),
            HttpContext.RequestAborted);

        int statusCode = result.StatusCode ?? (result.Succeeded
            ? StatusCodes.Status200OK
            : result.Result == HttpMessage.SENSITIVE_ACTION_REAUTHENTICATION_FAILED
                ? StatusCodes.Status401Unauthorized
                : StatusCodes.Status500InternalServerError);

        return ToActionResult(new ApiOutcome<ReauthenticateResponse>(
            new ReauthenticateResponse(
                result.Result,
                result.Token,
                result.Purpose,
                result.Expiration, result.ProofSession),
            statusCode,
            result.Code));
    }

    [HttpPost("reauthenticate/factor")]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<ReauthenticateResponse>>> CompleteSensitiveFactorProof([FromBody] SensitiveFactorProofRequest? payload)
    {
        if (payload is null || string.IsNullOrEmpty(payload.proofSession) || string.IsNullOrEmpty(payload.code) || payload.proofSession.Length is < 16 or > 512 || payload.code.Length is < 6 or > 8 || !payload.code.All(char.IsAsciiDigit))
            return ToActionResult(ApiResponses.InvalidPayload(new ReauthenticateResponse(HttpMessage.SENSITIVE_ACTION_REAUTHENTICATION_FAILED), "proofSession", "A proof session and six-digit existing-factor code are required."));
        if (!TryGetAuthenticatedSession(out string hash, out ActiveSession session))
            return ToActionResult(new ApiOutcome<ReauthenticateResponse>(new(HttpMessage.AUTHENTICATION_FAILED), 401, "AUTHENTICATION_FAILED"));
        var service = HttpContext.RequestServices.GetService<IAccountSensitiveActionService>();
        if (service is null) return ToActionResult(new ApiOutcome<ReauthenticateResponse>(new(HttpMessage.SENSITIVE_ACTION_TOKEN_ISSUE_FAILED), 503, "SENSITIVE_ACTION_FACTOR_UNAVAILABLE"));
        var result = await service.CompleteFactorProofAsync(new(session.accountId, session.accountSecurityStamp, hash, payload.proofSession, payload.code, ResolveRemoteIpAddress()), HttpContext.RequestAborted);
        return ToActionResult(new ApiOutcome<ReauthenticateResponse>(new(result.Result, result.Token, result.Purpose, result.Expiration), result.StatusCode ?? 503, result.Code));
    }

    [HttpPost("logoff")]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<AuthenticateLogoffResponse>>> LogoffAccount([FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] AuthenticateLogoffRequest? payload = null)
    {
        var validation = ValidateLogoffAccountRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AuthenticateLogoffResponse>(
                new AuthenticateLogoffResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/logoff", payload: payload);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new AuthenticateLogoffResponse(HttpMessage.AUTHENTICATION_LOGOFF_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome<AuthenticateLogoffResponse>(idempotency);
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<AuthenticateLogoffResponse>>> CompleteAndReturn(ApiOutcome<AuthenticateLogoffResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome);
            return ToActionResult(outcome);
        }

        DbCommandResult? dbResult = await SafeLogoutCurrentSession(
            activeSession.accountId,
            hashedAccessToken,
            activeSession.accountSecurityStamp);

        if (dbResult?.Result != true)
        {
            return await CompleteAndReturn(new ApiOutcome<AuthenticateLogoffResponse>(
                new AuthenticateLogoffResponse(HttpMessage.AUTHENTICATION_LOGOFF_FAILED),
                AuthStateConflictStatus(dbResult?.Code),
                dbResult?.Code ?? LogoffFailedCode));
        }

        ActiveSessionRevokeResult cacheResult = await SafeRevokeActiveSession(hashedAccessToken);
        Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();

        return await CompleteAndReturn(new ApiOutcome<AuthenticateLogoffResponse>(
            new AuthenticateLogoffResponse(HttpMessage.AUTHENTICATION_LOGOFF_SUCCEEDED),
            StatusCodes.Status200OK,
            cacheResult.Revoked ? LogoffSucceededCode : LogoffCacheRevokeFailedCode));
    }
    [HttpPost("logoff/all")]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<AuthenticateLogoffAllResponse>>> LogoffAllAccount([FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] AuthenticateLogoffAllRequest? payload = null)
    {
        var validation = ValidateLogoffAllAccountRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AuthenticateLogoffAllResponse>(
                new AuthenticateLogoffAllResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/logoff/all", requireKey: true, payload: payload);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new AuthenticateLogoffAllResponse(HttpMessage.AUTHENTICATION_LOGOFF_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome<AuthenticateLogoffAllResponse>(idempotency);
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<AuthenticateLogoffAllResponse>>> CompleteAndReturn(ApiOutcome<AuthenticateLogoffAllResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome);
            return ToActionResult(outcome);
        }

        AccountStampRotationResult? dbResult = await SafeLogoutAllSessions(
            activeSession.accountId,
            activeSession.accountSecurityStamp);

        if (dbResult?.Result != true)
        {
            return await CompleteAndReturn(new ApiOutcome<AuthenticateLogoffAllResponse>(
                new AuthenticateLogoffAllResponse(HttpMessage.AUTHENTICATION_LOGOFF_FAILED),
                AuthStateConflictStatus(dbResult?.Code),
                dbResult?.Code ?? LogoffAllFailedCode));
        }

        _ = await SafeRevokeActiveSession(hashedAccessToken);
        Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();

        return await CompleteAndReturn(new ApiOutcome<AuthenticateLogoffAllResponse>(
            new AuthenticateLogoffAllResponse(HttpMessage.AUTHENTICATION_LOGOFF_ALL_SUCCEEDED),
            StatusCodes.Status200OK,
            LogoffAllSucceededCode));
    }
    [RequireCapability("account.read")]
    [HttpGet("sessions")]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionsResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionsResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionsResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<AccountSessionsResponse>>> ListActiveSessions()
    {
        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AccountSessionsResponse>(
                new AccountSessionsResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        IReadOnlyList<AccountSessionSummary>? sessions = await SafeListActiveSessions(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            hashedAccessToken);

        if (sessions == null)
        {
            return ToActionResult(new ApiOutcome<AccountSessionsResponse>(
                new AccountSessionsResponse(HttpMessage.AUTHENTICATION_SESSIONS_LOOKUP_FAILED),
                StatusCodes.Status500InternalServerError,
                SessionsLookupFailedCode));
        }

        return ToActionResult(new ApiOutcome<AccountSessionsResponse>(
            new AccountSessionsResponse(HttpMessage.AUTHENTICATION_SESSIONS_LISTED, sessions),
            StatusCodes.Status200OK,
            SessionsListedCode));
    }
    [RequireCapability("account.manage")]
    [HttpPost("sessions/revoke")]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<AccountSessionRevokeResponse>>> RevokeSession([FromBody] AccountSessionRevokeRequest? payload)
    {
        var validation = ValidateRevokeSessionRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AccountSessionRevokeResponse>(
                new AccountSessionRevokeResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/sessions/revoke", requireKey: true, payload: payload);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new AccountSessionRevokeResponse(HttpMessage.AUTHENTICATION_SESSION_REVOKE_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome<AccountSessionRevokeResponse>(idempotency);
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<AccountSessionRevokeResponse>>> CompleteAndReturn(ApiOutcome<AccountSessionRevokeResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome);
            return ToActionResult(outcome);
        }

        DbCommandResult? dbResult = await SafeRevokeSessionForAccount(
            activeSession.accountId,
            payload!.sessionId,
            activeSession.accountSecurityStamp,
            hashedAccessToken);

        if (dbResult?.Result != true)
        {
            return await CompleteAndReturn(new ApiOutcome<AccountSessionRevokeResponse>(
                new AccountSessionRevokeResponse(HttpMessage.AUTHENTICATION_SESSION_REVOKE_FAILED),
                AuthStateConflictStatus(dbResult?.Code),
                dbResult?.Code ?? SessionRevokeFailedCode));
        }

        string responseCode = !string.IsNullOrWhiteSpace(dbResult.Code)
            ? dbResult.Code
            : SessionRevokeSucceededCode;

        if (string.Equals(dbResult.Code, CurrentSessionRevokeSucceededCode, StringComparison.Ordinal))
        {
            ActiveSessionRevokeResult cacheResult = await SafeRevokeActiveSession(hashedAccessToken);
            Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
            responseCode = cacheResult.Revoked ? CurrentSessionRevokeSucceededCode : SessionRevokeCacheRevokeFailedCode;
        }

        return await CompleteAndReturn(new ApiOutcome<AccountSessionRevokeResponse>(
            new AccountSessionRevokeResponse(HttpMessage.AUTHENTICATION_SESSION_REVOKED),
            StatusCodes.Status200OK,
            responseCode));
    }

}
