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
public sealed class AccountProfileController : AccountControllerBase
{
    public AccountProfileController(IAccountRepo accountRepo, ISessionRepo sessionRepo, IActiveUserCacheService activeUserCacheService, ITwoFactorSessionService twoFactorSessionService,
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
    [HttpPost("adjust")]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<AccountEditResponse>>> ModifyAccount([FromBody] AccountEditRequest? payload)
    {
        var validation = ValidateModifyAccountRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if(payload!.emailAddress is not null)payload.emailAddress=payload.emailAddress.ToLowerInvariant();

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AccountEditResponse>(
                new AccountEditResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/adjust", requireKey: true, payload: payload);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new AccountEditResponse(HttpMessage.ACCOUNT_ADJUST_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome<AccountEditResponse>(idempotency);
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<AccountEditResponse>>> CompleteAndReturn(ApiOutcome<AccountEditResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome);
            return ToActionResult(outcome);
        }

        treehammock.DataLayer.Security.SensitiveActionGrant? grant=null;
        if(payload!.emailAddress is not null)
        {
            if(MissingSensitiveActionToken()) return await CompleteAndReturn(new(new AccountEditResponse(HttpMessage.ACCOUNT_ADJUST_FAILED),428,"SENSITIVE_ACTION_GRANT_REQUIRED"));
            string target=SensitiveActionTargets.EmailChange(payload.emailAddress);
            var approval=await ValidateSensitiveActionToken(HttpContext.RequestServices.GetRequiredService<IAccountSensitiveActionService>(),activeSession,hashedAccessToken,consume:false,purpose:SensitiveActionPurpose.ACCOUNT_EMAIL_CHANGE,target:target);
            if(!approval.Succeeded || approval.Grant is null || approval.Grant.CanonicalTarget!=target || approval.Grant.SessionHash!=hashedAccessToken)
                return await CompleteAndReturn(new(new AccountEditResponse(HttpMessage.ACCOUNT_ADJUST_FAILED),401,"SENSITIVE_ACTION_GRANT_REQUIRED"));
            grant=approval.Grant;
        }

        AccountAdjustResult? dbResult = payload!.emailAddress is not null
            ? await SafeRequestEmailChange(activeSession.accountId, activeSession.accountSecurityStamp, payload.emailAddress,grant!)
            : await SafeModifyUsername(activeSession.accountId, activeSession.accountSecurityStamp, payload.username!);

        if (dbResult?.Result == true)
        {
            string successCode = string.IsNullOrWhiteSpace(dbResult.Code)
                ? (payload.emailAddress is not null ? AccountAdjustEmailVerificationPendingCode : AccountAdjustSucceededCode)
                : dbResult.Code;
            int successStatus = successCode == AccountAdjustEmailVerificationPendingCode
                ? StatusCodes.Status202Accepted
                : StatusCodes.Status200OK;

            return await CompleteAndReturn(new ApiOutcome<AccountEditResponse>(
                new AccountEditResponse(AccountAdjustMessage(successCode)),
                successStatus,
                successCode));
        }

        string code = dbResult is null || string.IsNullOrWhiteSpace(dbResult.Code) ? AccountAdjustFailedCode : dbResult.Code;
        return await CompleteAndReturn(new ApiOutcome<AccountEditResponse>(
            new AccountEditResponse(AccountAdjustMessage(code)),
            AccountAdjustFailureStatus(code),
            code));
    }
    [AllowAnonymous]
    [HttpGet("adjust/email/verify")]
    [Produces("text/html")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public ContentResult VerifyEmailChange([FromQuery] string? payload)
    {
        EmailConfirmationHeaders();
        string token=payload?.Trim() ?? "";
        if(token.Length is <1 or >AccountEmailChangeVerifyRequest.MaxEmailChangeTokenLength)
            return new ContentResult {ContentType="text/html; charset=utf-8",StatusCode=400,Content="<!doctype html><html lang=\"en\"><title>Email confirmation</title><p>This confirmation link is invalid.</p></html>"};
        string encoded=System.Text.Encodings.Web.HtmlEncoder.Default.Encode(token);
        string operationKey=treehammock.DataLayer.Operations.SecurityOperationKey.Create();
        string recovery=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        return new ContentResult {ContentType="text/html; charset=utf-8",StatusCode=200,Content=$"<!doctype html><html lang=\"en\"><head><meta name=\"referrer\" content=\"no-referrer\"><title>Confirm email change</title></head><body><h1>Confirm your new email address</h1><p>Press Confirm to complete the email change you approved. This will sign out your existing sessions.</p><form method=\"post\" action=\"/account/adjust/email/verify\"><input type=\"hidden\" name=\"verifyToken\" value=\"{encoded}\"><input type=\"hidden\" name=\"operationKey\" value=\"{operationKey}\"><input type=\"hidden\" name=\"operationRecovery\" value=\"{recovery}\"><button type=\"submit\">Confirm email change</button></form></body></html>"};
    }

    [AllowAnonymous]
    [HttpPost("adjust/email/verify")]
    [Consumes("application/x-www-form-urlencoded")]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>),StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>),StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>),StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>),StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<AccountEditResponse>),StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<AccountEditResponse>>> ConfirmEmailChange([FromForm] AccountEmailChangeVerifyRequest? payload)
    {
        EmailConfirmationHeaders();
        var validation=ValidateEmailChangeVerifyPayload(payload?.verifyToken);
        if(validation is not null)return ToActionResult(validation);
        var dbResult=await SafeCompleteEmailChange(payload!.verifyToken.Trim());
        string code=string.IsNullOrWhiteSpace(dbResult?.Code)?AccountAdjustFailedCode:dbResult.Code;
        return ToActionResult(new ApiOutcome<AccountEditResponse>(new AccountEditResponse(AccountAdjustMessage(code)),
            dbResult?.Result==true?StatusCodes.Status200OK:AccountAdjustFailureStatus(code),code));
    }

    private void EmailConfirmationHeaders()
    {
        Response.Headers["Cache-Control"]="no-store";
        Response.Headers["Referrer-Policy"]="no-referrer";
        Response.Headers["Content-Security-Policy"]="default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
        Response.Headers["X-Content-Type-Options"]="nosniff";
    }

    [RequireCapability("account.read")]
    [HttpGet("view")]
    [ProducesResponseType(typeof(ApiResponse<AccountDetailsResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AccountDetailsResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AccountDetailsResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<AccountDetailsResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<AccountDetailsResponse>>> ViewAccount()
    {
        if (!TryGetAuthenticatedSession(out _, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AccountDetailsResponse>(
                new AccountDetailsResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AccountViewResult? dbResult = await SafeViewAccount(
            activeSession.accountId,
            activeSession.accountSecurityStamp);

        if (dbResult?.Result == true && dbResult.Profile is not null)
        {
            return ToActionResult(new ApiOutcome<AccountDetailsResponse>(
                new AccountDetailsResponse(HttpMessage.ACCOUNT_VIEW_SUCCEEDED, dbResult.Profile),
                StatusCodes.Status200OK,
                string.IsNullOrWhiteSpace(dbResult.Code) ? AccountViewSucceededCode : dbResult.Code));
        }

        string code = dbResult is null || string.IsNullOrWhiteSpace(dbResult.Code) ? AccountViewFailedCode : dbResult.Code;
        return ToActionResult(new ApiOutcome<AccountDetailsResponse>(
            new AccountDetailsResponse(AccountViewFailureMessage(code)),
            AccountViewFailureStatus(code),
            code));
    }

}
