using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Options;
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
public sealed class AccountDeleteController : AccountControllerBase
{
    public AccountDeleteController(IAccountRepo accountRepo, ISessionRepo sessionRepo, IActiveUserCacheService activeUserCacheService, ITwoFactorSessionService twoFactorSessionService,
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

    [RequireCapability("account.manage")]
    [HttpPost("wipeout")]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<AccountDeleteResponse>>> DeleteAccount([FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] AccountDeleteRequest? payload = null)
    {
        var validation = ValidateDeleteAccountRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AccountDeleteResponse>(
                new AccountDeleteResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/wipeout", requireKey: true, payload: payload);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new AccountDeleteResponse(HttpMessage.ACCOUNT_DELETE_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome<AccountDeleteResponse>(idempotency);
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<AccountDeleteResponse>>> CompleteAndReturn(ApiOutcome<AccountDeleteResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome);
            return ToActionResult(outcome);
        }

        if(MissingSensitiveActionToken()) return await CompleteAndReturn(new(new AccountDeleteResponse(HttpMessage.ACCOUNT_DELETE_FAILED),428,"SENSITIVE_ACTION_GRANT_REQUIRED"));
        string target=SensitiveActionTargets.AccountDelete(payload?.passPhrase);
        var approval=await ValidateSensitiveActionToken(HttpContext.RequestServices.GetRequiredService<IAccountSensitiveActionService>(),activeSession,hashedAccessToken,consume:false,purpose:SensitiveActionPurpose.ACCOUNT_DELETE,target:target);
        if(!approval.Succeeded || approval.Grant is null || approval.Grant.CanonicalTarget!=target || approval.Grant.SessionHash!=hashedAccessToken)
            return await CompleteAndReturn(new(new AccountDeleteResponse(HttpMessage.ACCOUNT_DELETE_FAILED),401,"SENSITIVE_ACTION_GRANT_REQUIRED"));

        AccountDeleteCommandResult? dbResult = await SafeRequestAccountDelete(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload?.passPhrase,approval.Grant);

        if (dbResult?.Result == true)
        {
            string successCode = string.IsNullOrWhiteSpace(dbResult.Code) ? AccountDeletePendingCode : dbResult.Code;
            return await CompleteAndReturn(new ApiOutcome<AccountDeleteResponse>(
                new AccountDeleteResponse(AccountDeleteMessage(successCode)),
                StatusCodes.Status202Accepted,
                successCode));
        }

        string code = dbResult is null || string.IsNullOrWhiteSpace(dbResult.Code) ? AccountDeleteFailedCode : dbResult.Code;
        return await CompleteAndReturn(new ApiOutcome<AccountDeleteResponse>(
            new AccountDeleteResponse(AccountDeleteMessage(code)),
            AccountDeleteFailureStatus(code),
            code));
    }
    [AllowAnonymous]
    [HttpGet("wipeout/verify")]
    [Produces("text/html")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public ContentResult DeleteAccountConfirmation([FromQuery] string? payload)
    {
        DeleteConfirmationHeaders();
        string token = payload?.Trim() ?? string.Empty;
        if (token.Length is < 1 or > AccountDeleteVerifyRequest.MaxDeleteTokenLength)
            return new ContentResult { ContentType = "text/html; charset=utf-8", StatusCode = 400,
                Content = "<!doctype html><html lang=\"en\"><title>Deletion confirmation</title><p>This confirmation link is invalid.</p></html>" };
        string encoded = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(token);
        string operationKey = treehammock.DataLayer.Operations.SecurityOperationKey.Create();
        string recovery = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        return new ContentResult { ContentType = "text/html; charset=utf-8", StatusCode = 200,
            Content = $"<!doctype html><html lang=\"en\"><head><meta name=\"referrer\" content=\"no-referrer\"><title>Confirm deletion request</title></head><body><h1>Confirm your deletion request</h1><p>Confirming verifies this mailbox proof. Complete deletion separately while signed in.</p><form method=\"post\" action=\"/account/wipeout/verify\"><input type=\"hidden\" name=\"deleteToken\" value=\"{encoded}\"><input type=\"hidden\" name=\"operationKey\" value=\"{operationKey}\"><input type=\"hidden\" name=\"operationRecovery\" value=\"{recovery}\"><button type=\"submit\">Confirm deletion request</button></form></body></html>" };
    }

    private void DeleteConfirmationHeaders()
    {
        Response.Headers["Cache-Control"] = "no-store";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        Response.Headers["Content-Security-Policy"] = "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
    }

    [AllowAnonymous]
    [HttpPost("wipeout/verify")]
    [Consumes("application/x-www-form-urlencoded")]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status503ServiceUnavailable)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<AccountDeleteResponse>>> VerifyDeleteAccount([FromForm(Name = "deleteToken")] string? payload)
    {
        DeleteConfirmationHeaders();
        var validation = ValidateDeleteVerifyPayload(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        string deleteToken = payload!.Trim();
        AccountDeleteCommandResult? dbResult = await SafeVerifyAccountDeleteToken(deleteToken);
        if (dbResult?.Result == true)
        {
            string successCode = string.IsNullOrWhiteSpace(dbResult.Code) ? AccountDeleteVerifiedCode : dbResult.Code;
            return ToActionResult(new ApiOutcome<AccountDeleteResponse>(
                new AccountDeleteResponse(AccountDeleteMessage(successCode), dbResult.Workflow),
                StatusCodes.Status200OK,
                successCode));
        }

        string code = dbResult is null || string.IsNullOrWhiteSpace(dbResult.Code) ? AccountDeleteFailedCode : dbResult.Code;
        return ToActionResult(new ApiOutcome<AccountDeleteResponse>(
            new AccountDeleteResponse(AccountDeleteMessage(code)),
            AccountDeleteFailureStatus(code),
            code));
    }
    [RequireCapability("account.manage")]
    [HttpPost("wipeout/finalize")]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status503ServiceUnavailable)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<AccountDeleteResponse>>> FinalizeDeleteAccount([FromBody] AccountDeleteFinalizeRequest? payload)
    {
        var validation = ValidateFinalizeDeleteRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AccountDeleteResponse>(
                new AccountDeleteResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/wipeout/finalize", requireKey: true, payload: payload);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new AccountDeleteResponse(HttpMessage.ACCOUNT_DELETE_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome<AccountDeleteResponse>(idempotency);
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<AccountDeleteResponse>>> CompleteAndReturn(ApiOutcome<AccountDeleteResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome);
            return ToActionResult(outcome);
        }

        AccountDeleteCommandResult? dbResult = await SafeFinalizeAccountDelete(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload!.deleteToken,
            payload.passPhrase,hashedAccessToken);

        if (dbResult?.Result == true)
        {
            _ = await SafeRevokeActiveSession(hashedAccessToken);
            Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();

            string successCode = string.IsNullOrWhiteSpace(dbResult.Code) ? AccountDeleteSucceededCode : dbResult.Code;
            return await CompleteAndReturn(new ApiOutcome<AccountDeleteResponse>(
                new AccountDeleteResponse(AccountDeleteMessage(successCode)) { completedCredentialStamp=activeSession.accountSecurityStamp },
                StatusCodes.Status200OK,
                successCode));
        }

        string code = dbResult is null || string.IsNullOrWhiteSpace(dbResult.Code) ? AccountDeleteFailedCode : dbResult.Code;
        return await CompleteAndReturn(new ApiOutcome<AccountDeleteResponse>(
            new AccountDeleteResponse(AccountDeleteMessage(code)),
            AccountDeleteFailureStatus(code),
            code));
    }

}
