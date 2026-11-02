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
public sealed class AccountLoginController : AccountControllerBase
{
    public AccountLoginController(IAccountRepo accountRepo, ISessionRepo sessionRepo, IActiveUserCacheService activeUserCacheService, ITwoFactorSessionService twoFactorSessionService,
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
    [HttpPost("requestaccess")]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateResponse>), StatusCodes.Status423Locked)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<AuthenticateResponse>>> Authenticate([FromBody] AuthenticateLogin payload)
    {
        if (payload == null)
        {
            return ToActionResult(ApiResponses.InvalidPayload(
                new AuthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
                string.Empty,
                RequestBodyRequiredMessage));
        }

        if (HttpContext.Items[AuthContextItems.HashedAccessToken] != null)
        {
            return ToActionResult(SerializeAuthenticate(HttpMessage.AUTHENTICATION_DUPLICATE));
        }

        if (!HasValidPasswordShape(payload))
        {
            return ToActionResult(ApiResponses.InvalidPayload(
                new AuthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
                nameof(AuthenticateLogin.password),
                $"password must be between {_registrationSettings.MinPasswordLength} and {_registrationSettings.MaxPasswordLength} characters."));
        }

        LoginIdentifierValidation identifierValidation = ValidateLoginIdentifiers(payload);
        if (identifierValidation.Errors.Count > 0)
        {
            return ToActionResult(ApiResponses.InvalidPayload(
                new AuthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
                identifierValidation.Errors));
        }

        ApiOutcome<AuthenticateResponse>? preLookupAbuse = await CheckLoginPreLookupAbusePolicy(payload);
        if (preLookupAbuse != null)
        {
            return ToActionResult(preLookupAbuse);
        }

        CredentialLookupResult? credentialLookup = await SafeGetCredentials(payload, identifierValidation.Action);
        if (credentialLookup == null || credentialLookup.Status == CredentialLookupStatus.Failed)
        {
            return ToActionResult(LoginAttemptPersistenceFailed());
        }

        if (!credentialLookup.Succeeded)
        {
            return ToActionResult(SerializeAuthenticate(HttpMessage.AUTHENTICATION_FAILED));
        }

        IntraAccount singleAccount = credentialLookup.Account!;

        Instant moment = SystemClock.Instance.GetCurrentInstant();
        ApiOutcome<AuthenticateResponse>? lockoutResult = await CheckLockout(singleAccount, moment);
        if (lockoutResult != null)
        {
            return ToActionResult(lockoutResult);
        }

        ApiOutcome<AuthenticateResponse>? accountAbuse = await CheckLoginAccountAbusePolicy(singleAccount.accountId);
        if (accountAbuse != null)
        {
            return ToActionResult(accountAbuse);
        }

        var passwordWork = HttpContext.RequestServices.GetService<IPasswordWorkService>()
            ?? PasswordWorkService.Default(Microsoft.Extensions.Options.Options.Create(_loginSettings));
        var proof = await passwordWork.VerifyAndUpgradeAsync(singleAccount.hashedPassword, payload.password, HttpContext.RequestAborted);
        if (!proof.Verified)
        {
            return ToActionResult(await FailPasswordAttempt(singleAccount));
        }

        if (proof.UpgradedHash is byte[] replacement)
        {
            bool saved = await _accountRepo.UpgradePasswordHash(singleAccount.accountId, singleAccount.accountSecurityStamp,
                singleAccount.hashedPassword, replacement, HttpContext.RequestAborted);
            if (!saved) return ToActionResult(new ApiOutcome<AuthenticateResponse>(new(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status409Conflict, "PASSWORD_CREDENTIAL_CHANGED"));
            singleAccount.hashedPassword = replacement;
        }

        var successState = await _accountRepo.ClearLoginAttempts(singleAccount.accountId, singleAccount.accountSecurityStamp,
            singleAccount.loginAttemptVersion, singleAccount.loginFailures, singleAccount.unlockWhen, false, HttpContext.RequestAborted);
        if (!successState.Result) return ToActionResult(new ApiOutcome<AuthenticateResponse>(new(HttpMessage.AUTHENTICATION_FAILED),
            StatusCodes.Status409Conflict, "LOGIN_ATTEMPT_STATE_CHANGED"));
        singleAccount.loginAttemptVersion = successState.Version; singleAccount.loginFailures = successState.Failures;
        await ResetLoginAbusePolicyAfterSuccessfulPassword(singleAccount.accountId, payload);

        ApiOutcome<AuthenticateResponse>? verificationResult = await CheckVerificationStatus(singleAccount);
        if (verificationResult != null)
        {
            return ToActionResult(verificationResult);
        }

        if (IsCutOffExpired(singleAccount, moment))
        {
            return ToActionResult(SerializeAuthenticate(HttpMessage.AUTHENTICATION_EXPIRED));
        }

        // Keep the two main session-state branches explicit. The checks above are shared so
        // both branches enforce the same validation, lockout, and password-failure behavior.
        if (singleAccount.refreshToken != null)
        {
            return ToActionResult(await AuthenticateAlreadyLoggedIn(singleAccount, moment));
        }

        return ToActionResult(await AuthenticateNotLoggedIn(singleAccount, moment));
    }

}
