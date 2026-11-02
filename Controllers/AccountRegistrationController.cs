using treehammock.Rigging.Delivery;
using Microsoft.Extensions.DependencyInjection;
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
public sealed class AccountRegistrationController : AccountControllerBase
{
    public AccountRegistrationController(IAccountRepo accountRepo, ISessionRepo sessionRepo, IActiveUserCacheService activeUserCacheService, ITwoFactorSessionService twoFactorSessionService,
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

    [AllowAnonymous]
    [HttpPost("setupaccount")]
    [ProducesResponseType(typeof(ApiResponse<AccountCreationResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AccountCreationResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountCreationResponse>), StatusCodes.Status423Locked)]
    [ProducesResponseType(typeof(ApiResponse<AccountCreationResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<AccountCreationResponse>), StatusCodes.Status503ServiceUnavailable)]
    [ProducesResponseType(typeof(ApiResponse<AccountCreationResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<AccountCreationResponse>>> AccountSetup([FromBody] AccountCreationRequest payload)
    {
        if (payload == null)
        {
            return ToActionResult(PayloadInvalid(
                new AccountCreationResponse(HttpMessage.ACCOUNT_CREATION_FAILED, null),
                string.Empty,
                RequestBodyRequiredMessage));
        }

        if (HttpContext.Items[AuthContextItems.WebKey] != null)
        {
            return ToActionResult(new ApiOutcome<AccountCreationResponse>(
                new AccountCreationResponse(HttpMessage.AUTHENTICATION_DUPLICATE, null),
                StatusCodes.Status400BadRequest,
                HttpMessage.AUTHENTICATION_DUPLICATE.ToString()));
        }

        if (string.IsNullOrEmpty(payload.password) ||
            payload.password.Length < _registrationSettings.MinPasswordLength ||
            payload.password.Length > _registrationSettings.MaxPasswordLength)
        {
            return ToActionResult(PayloadInvalid(
                new AccountCreationResponse(HttpMessage.ACCOUNT_CREATION_PASSWORD_REQUIREMENT, null),
                nameof(AccountCreationRequest.password),
                $"password must be between {_registrationSettings.MinPasswordLength} and {_registrationSettings.MaxPasswordLength} characters."));
        }

        var validationErrors = new List<ApiValidationError>();

        bool validEmailAddress = !string.IsNullOrWhiteSpace(payload.emailAddress) &&
            payload.emailAddress.Length <= _registrationSettings.MaxEmailAddressLength &&
            _emailValidator.IsValid(payload.emailAddress);

        if (!validEmailAddress)
        {
            validationErrors.Add(ValidationError(
                nameof(AccountCreationRequest.emailAddress),
                $"emailAddress must be a valid email address no longer than {_registrationSettings.MaxEmailAddressLength} characters."));
        }

        bool usernameSupplied = !string.IsNullOrWhiteSpace(payload.username);
        bool validUsername = usernameSupplied &&
            payload.username!.Length >= _registrationSettings.MinUsernameLength &&
            payload.username.Length <= _registrationSettings.MaxUsernameLength;

        if (usernameSupplied && !validUsername)
        {
            validationErrors.Add(ValidationError(
                nameof(AccountCreationRequest.username),
                $"username must be between {_registrationSettings.MinUsernameLength} and {_registrationSettings.MaxUsernameLength} characters when supplied."));
        }

        if (!IsDefinedCountry(payload.country))
        {
            validationErrors.Add(ValidationError(
                nameof(AccountCreationRequest.country),
                "A supported country is required."));
        }

        if (validationErrors.Count > 0)
        {
            return ToActionResult(PayloadInvalid(
                new AccountCreationResponse(HttpMessage.ACCOUNT_CREATION_FAILED, null),
                validationErrors));
        }

        AccountSetupAction step = validUsername ? AccountSetupAction.BOTH : AccountSetupAction.EMAIL;
        string? username = validUsername ? payload.username : null;

        Instant createdOn = SystemClock.Instance.GetCurrentInstant();
        HttpMessage outcome = await _accountService.SetupUserAccount(payload.emailAddress, username, payload.password, payload.country, createdOn, step, cancellationToken: HttpContext.RequestAborted);

        var response = new AccountCreationResponse(
            outcome,
            outcome is HttpMessage.ACCOUNT_CREATION_SUCCESSED or HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING ? createdOn : null);

        int statusCode = AccountSetupStatus(outcome);
        return ToActionResult(new ApiOutcome<AccountCreationResponse>(response, statusCode, outcome.ToString()));
    }
    [AllowAnonymous]
    [HttpPost("verifyaccount/resend")]
    [ProducesResponseType(typeof(ApiResponse<AccountVerificationResendResponse>), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ApiResponse<AccountVerificationResendResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountVerificationResendResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<AccountVerificationResendResponse>>> ResendAccountVerification([FromBody] AccountVerificationResendRequest? payload)
    {
        if (payload == null)
        {
            return ToActionResult(ApiResponses.InvalidPayload(
                new AccountVerificationResendResponse(HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED),
                string.Empty,
                RequestBodyRequiredMessage));
        }

        if (!HasValidEmailShape(payload.emailAddress, (int)_registrationSettings.MaxEmailAddressLength))
        {
            return ToActionResult(ApiResponses.InvalidPayload(
                new AccountVerificationResendResponse(HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED),
                nameof(AccountVerificationResendRequest.emailAddress),
                $"emailAddress must be a valid email address no longer than {_registrationSettings.MaxEmailAddressLength} characters."));
        }

        HttpMessage outcome = await _accountService.ResendAccountVerification(payload.emailAddress, cancellationToken: HttpContext.RequestAborted);
        int statusCode = outcome switch
        {
            HttpMessage.ACCOUNT_CREATION_VERIFICATION_RESENT
                or HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING => StatusCodes.Status202Accepted,
            HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED => StatusCodes.Status500InternalServerError,
            _ => StatusCodes.Status500InternalServerError
        };

        string code = outcome == HttpMessage.ACCOUNT_CREATION_VERIFICATION_RESENT
            ? VerificationResendSucceededCode
            : outcome == HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING
                ? VerificationResendPendingCode
                : outcome.ToString();

        return ToActionResult(new ApiOutcome<AccountVerificationResendResponse>(
            new AccountVerificationResendResponse(outcome),
            statusCode,
            code));
    }
    [AllowAnonymous]
    [HttpGet("verifyaccount")]
    [Produces("text/html")]
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    public async Task<ContentResult> VerifyAccountCreation([FromQuery] string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return AccountVerificationContent(_unsuccessfulAccountVerifyHtml);
        }

        string verifyToken = payload.Trim();
        if (verifyToken.Length > MaxPublicAccountVerificationTokenLength)
        {
            return AccountVerificationContent(_unsuccessfulAccountVerifyHtml);
        }

        if(await HttpContext.RequestServices.GetRequiredService<IDurableDeliveryService>().IsPendingAsync("verify",AccountVerificationTokenUtility.HashToken(verifyToken),HttpContext.RequestAborted))
            return AccountVerificationContent("<p>Your verification delivery is pending. Try again shortly.</p>");

        AbuseDecision abuseDecision = await CheckPublicTokenVerificationPolicy("account-verify", verifyToken);
        if (!abuseDecision.Allowed)
        {
            return AccountVerificationContent(_unsuccessfulAccountVerifyHtml);
        }

        AccountVerification? record = await _accountRepo.VerifyAccountForUse(verifyToken, cancellationToken: HttpContext.RequestAborted);
        if (record == null)
        {
            return AccountVerificationContent(_unsuccessfulAccountVerifyHtml);
        }

        if (record.verifyStatus == VerificationStatus.SUCCESSFUL)
        {
            return AccountVerificationContent(_alreadyVerifiedAccountVerifyHtml);
        }

        if (record.verifyStatus == VerificationStatus.EXPIRED)
        {
            return AccountVerificationContent(_expiredAccountVerifyHtml);
        }

        if (record.sentWhen == null || record.expiration == null || string.IsNullOrWhiteSpace(record.verifyKey))
        {
            return AccountVerificationContent(_unsuccessfulAccountVerifyHtml);
        }

        var moment = SystemClock.Instance.GetCurrentInstant();
        var expiresAt = record.sentWhen.Value.Plus(record.expiration.ToDuration());
        if (moment >= expiresAt)
        {
            bool? expired = await _accountRepo.AccountVerificationExpired(record, cancellationToken: HttpContext.RequestAborted);
            return AccountVerificationContent(expired == true
                ? _expiredAccountVerifyHtml
                : _unsuccessfulAccountVerifyHtml);
        }

        if ((record.verifyStatus is VerificationStatus.SENT or VerificationStatus.REFRESHED) && VerificationPayloadMatchesRecord(verifyToken, record.verifyKey))
        {
            bool? completed = await _accountRepo.AccountPassedVerification(record, cancellationToken: HttpContext.RequestAborted);
            if (completed == true)
            {
                await ResetPublicTokenVerificationPolicy("account-verify", verifyToken);
            }

            return AccountVerificationContent(completed == true
                ? _successfulAccountVerifyHtml
                : _unsuccessfulAccountVerifyHtml);
        }

        return AccountVerificationContent(_unsuccessfulAccountVerifyHtml);
    }

}
