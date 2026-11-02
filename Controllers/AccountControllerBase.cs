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

public abstract partial class AccountControllerBase : ControllerBase
{
    protected enum LoginSessionPersistenceStatus
    {
        Success,
        DatabaseSessionFailed
    }

    protected enum ActiveSessionRollbackStatus
    {
        Success,
        DatabaseExpireFailed,
        CacheAndDatabaseFailed
    }

    protected enum LoginFailurePersistenceResult
    {
        Recorded,
        Locked,
        Failed
    }

    protected enum TwoFactorChallengePreparationResult
    {
        Prepared,
        InvalidDestination,
        ProviderUnknown,
        ProviderFailed,
        ProviderCleanupFailed,
        PersistenceFailed,
        Cooldown,
        RetryLimit,
        Expired,
        Stale
    }

    protected sealed record TwoFactorChallengeVerification(
        TwoFactorAuthOutcome Outcome,
        HttpMessage? FailureReason = null,
        int? StatusCode = null,
        string? Code = null);

    protected sealed record TwoFactorProofAdvanceResult(
        bool Complete,
        HttpMessage? FailureReason = null,
        int? StatusCode = null,
        string? Code = null);

    protected sealed record PendingTwoFactorSessionLoad(
        string? HashedPreAuthToken,
        TwoFactorSession? Session,
        HttpMessage? FailureReason = null,
        int? StatusCode = null,
        string? Code = null);

    protected sealed record ActiveCacheWriteResult(
        bool Stored,
        bool ExceptionThrown = false);

    protected sealed record PendingSessionWriteResult(
        bool? Stored,
        bool ExceptionThrown = false);

    protected sealed record PendingSessionRevokeResult(
        bool Revoked,
        bool ExceptionThrown = false);

    protected sealed record ActiveSessionRevokeResult(
        bool Revoked,
        bool ExceptionThrown = false);

    protected sealed record ActiveSessionRollbackResult(
        ActiveSessionRollbackStatus Status)
    {
        public bool Succeeded => Status == ActiveSessionRollbackStatus.Success;
    }

    protected sealed record LoginSessionPersistenceResult(
        LoginSessionPersistenceStatus Status,
        ActiveSessionRollbackResult? Rollback = null)
    {
        public bool Succeeded => Status == LoginSessionPersistenceStatus.Success;
    }

    protected sealed record LoginIdentifierValidation(
        AccountLoginAction Action,
        IReadOnlyList<ApiValidationError> Errors);

    protected const string TwoFactorInvalidDestinationCode = "TWO_FACTOR_INVALID_DESTINATION";
    protected const string TwoFactorProviderFailedCode = "TWO_FACTOR_PROVIDER_FAILED";
    protected const string TwoFactorChallengeCleanupFailedCode = "TWO_FACTOR_CHALLENGE_CLEANUP_FAILED";
    protected const string TwoFactorAttemptPersistenceFailedCode = "TWO_FACTOR_ATTEMPT_PERSISTENCE_FAILED";
    protected const string TwoFactorSessionRevokeFailedCode = "TWO_FACTOR_SESSION_REVOKE_FAILED";
    protected const string TwoFactorChallengePersistenceFailedCode = "TWO_FACTOR_CHALLENGE_PERSISTENCE_FAILED";
    protected const string TwoFactorDurableChallengePersistenceFailedCode = "TWO_FACTOR_DURABLE_CHALLENGE_PERSISTENCE_FAILED";
    protected const string TwoFactorDetailsLookupFailedCode = "TWO_FACTOR_DETAILS_LOOKUP_FAILED";
    protected const string TwoFactorDetailsNotConfiguredCode = "TWO_FACTOR_DETAILS_NOT_CONFIGURED";
    protected const string TwoFactorSetupPendingCode = "TWO_FACTOR_SETUP_PENDING";
    protected const string TwoFactorSetupFailedCode = "TWO_FACTOR_SETUP_FAILED";
    protected const string TwoFactorSetupPersistenceFailedCode = "TWO_FACTOR_SETUP_PERSISTENCE_FAILED";
    protected const string TwoFactorSetupProviderFailedCode = "TWO_FACTOR_SETUP_PROVIDER_FAILED";
    protected const string TwoFactorSetupVerifiedCode = "TWO_FACTOR_SETUP_VERIFIED";
    protected const string TwoFactorSetupVerifyPersistenceFailedCode = "TWO_FACTOR_SETUP_VERIFY_PERSISTENCE_FAILED";
    protected const string TwoFactorSetupIncorrectCode = "TWO_FACTOR_SETUP_INCORRECT";
    protected const string TwoFactorSetupExpiredCode = "TWO_FACTOR_SETUP_EXPIRED";
    protected const string TwoFactorSetupAttemptLimitCode = "TWO_FACTOR_SETUP_ATTEMPT_LIMIT";
    protected const string TwoFactorSetupNotFoundCode = "TWO_FACTOR_SETUP_NOT_FOUND";
    protected const string TwoFactorSetupCleanupFailedCode = "TWO_FACTOR_SETUP_CLEANUP_FAILED";
    protected const string TwoFactorSetupDuplicateCode = "TWO_FACTOR_SETUP_DUPLICATE";
    protected const string TwoFactorSetupUnsupportedMethodCode = "TWO_FACTOR_SETUP_UNSUPPORTED_METHOD";
    protected const string TwoFactorSetupInvalidDestinationCode = "TWO_FACTOR_SETUP_INVALID_DESTINATION";
    protected const string TwoFactorSetupInvalidTokenCode = "TWO_FACTOR_SETUP_INVALID_TOKEN";
    protected const string TwoFactorSetupInvalidExpirationCode = "TWO_FACTOR_SETUP_INVALID_EXPIRATION";
    protected const string TwoFactorMethodRemovedCode = "TWO_FACTOR_METHOD_REMOVED";
    protected const string TwoFactorMethodNotConfiguredCode = "TWO_FACTOR_METHOD_NOT_CONFIGURED";
    protected const string TwoFactorMethodRemoveUnsupportedMethodCode = "TWO_FACTOR_METHOD_REMOVE_UNSUPPORTED_METHOD";
    protected const string TwoFactorMethodRemoveFailedCode = "TWO_FACTOR_METHOD_REMOVE_FAILED";
    protected const string TwoFactorPreAuthPersistenceFailedCode = "TWO_FACTOR_PREAUTH_PERSISTENCE_FAILED";
    protected const string TwoFactorAccountFinalizationFailedCode = "TWO_FACTOR_ACCOUNT_FINALIZATION_FAILED";
    protected const string TwoFactorPendingSessionMismatchCode = "TWO_FACTOR_PENDING_SESSION_MISMATCH";
    protected const string TwoFactorPendingSessionValidationFailedCode = "TWO_FACTOR_PENDING_SESSION_VALIDATION_FAILED";
    protected const string ActiveSessionRollbackFailedCode = "ACTIVE_SESSION_ROLLBACK_FAILED";
    protected const string ActiveSessionDbExpireFailedCode = "ACTIVE_SESSION_DB_EXPIRE_FAILED";
    protected const string ActiveSessionDbPersistenceFailedCode = "ACTIVE_SESSION_DB_PERSISTENCE_FAILED";
    protected const string TwoFactorRotationAfterFinalizationFailedCode = "TWO_FACTOR_ROTATION_AFTER_FINALIZATION_FAILED";
    protected const string TwoFactorFinalizationRollbackFailedCode = "TWO_FACTOR_FINALIZATION_ROLLBACK_FAILED";
    protected const string LoginAttemptPersistenceFailedCode = "LOGIN_ATTEMPT_PERSISTENCE_FAILED";
    protected const string LockoutCleanupFailedCode = "LOCKOUT_CLEANUP_FAILED";
    protected const string SupportedTwoFactorMethodRequiredMessage = "A supported two-factor method is required.";
    protected const string TwoFactorMethodNotAvailableMessage = "The selected two-factor method is not available for this session.";
    protected const string TwoFactorConfigurationNotAvailableCode = "TWO_FACTOR_CONFIGURATION_NOT_AVAILABLE";
    protected const string TwoFactorSelectionPersistenceFailedCode = "TWO_FACTOR_SELECTION_PERSISTENCE_FAILED";
    protected const string TwoFactorSelectionAlreadyMadeCode = "TWO_FACTOR_SELECTION_ALREADY_MADE";
    protected const string TwoFactorMethodNotCurrentlyRequiredCode = "TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED";
    protected const string TwoFactorNextProofChallengePersistenceFailedCode = "TWO_FACTOR_NEXT_PROOF_CHALLENGE_PERSISTENCE_FAILED";
    protected const string SelectableTwoFactorConfigurationRequiredMessage = "A selectable two-factor configuration is required.";
    protected const string TwoFactorConfigurationNotAvailableMessage = "The selected two-factor configuration is not available for this session.";
    protected const string RequestBodyRequiredMessage = "The request body is required.";
    protected const int MaxPublicAccountVerificationTokenLength = 512;
    protected const string LogoffSucceededCode = "LOGOFF_SUCCEEDED";
    protected const string LogoffAllSucceededCode = "LOGOFF_ALL_SUCCEEDED";
    protected const string LogoffFailedCode = "LOGOFF_FAILED";
    protected const string LogoffAllFailedCode = "LOGOFF_ALL_FAILED";
    protected const string LogoffCacheRevokeFailedCode = "LOGOFF_CACHE_REVOKE_FAILED";
    protected const string AccountSecurityStampMismatchCode = "ACCOUNT_SECURITY_STAMP_MISMATCH";
    protected const string SessionsListedCode = "SESSIONS_LISTED";
    protected const string SessionsLookupFailedCode = "SESSIONS_LOOKUP_FAILED";
    protected const string SessionRevokeSucceededCode = "SESSION_REVOKED";
    protected const string CurrentSessionRevokeSucceededCode = "CURRENT_SESSION_REVOKED";
    protected const string SessionRevokeFailedCode = "SESSION_REVOKE_FAILED";
    protected const string SessionRevokeCacheRevokeFailedCode = "SESSION_REVOKE_CACHE_REVOKE_FAILED";
    protected const string VerificationResendSucceededCode = "ACCOUNT_CREATION_VERIFICATION_RESENT";
    protected const string VerificationResendPendingCode = "ACCOUNT_CREATION_VERIFICATION_PENDING";
    protected const string AccountViewSucceededCode = "ACCOUNT_VIEW_SUCCEEDED";
    protected const string AccountViewFailedCode = "ACCOUNT_VIEW_FAILED";
    protected const string AccountAdjustSucceededCode = "ACCOUNT_ADJUST_SUCCEEDED";
    protected const string AccountAdjustFailedCode = "ACCOUNT_ADJUST_FAILED";
    protected const string AccountAdjustDuplicateEmailCode = "ACCOUNT_ADJUST_DUPLICATE_EMAIL";
    protected const string AccountAdjustDuplicateUsernameCode = "ACCOUNT_ADJUST_DUPLICATE_USERNAME";
    protected const string AccountAdjustEmailVerificationPendingCode = "ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING";
    protected const string AccountAdjustEmailDeliveryFailedCode = "ACCOUNT_ADJUST_EMAIL_DELIVERY_FAILED";
    protected const string AccountAdjustEmailChangeCleanupFailedCode = "ACCOUNT_ADJUST_EMAIL_CHANGE_CLEANUP_FAILED";
    protected const string AccountAdjustTokenExpiredCode = "ACCOUNT_ADJUST_TOKEN_EXPIRED";
    protected const string AccountAdjustTokenMismatchCode = "ACCOUNT_ADJUST_TOKEN_MISMATCH";
    protected const string AccountDeletePendingCode = "ACCOUNT_DELETE_PENDING";
    protected const string AccountDeleteVerifiedCode = "ACCOUNT_DELETE_VERIFIED";
    protected const string AccountDeleteSucceededCode = "ACCOUNT_DELETE_SUCCEEDED";
    protected const string AccountDeleteFailedCode = "ACCOUNT_DELETE_FAILED";
    protected const string AccountDeleteTokenExpiredCode = "ACCOUNT_DELETE_TOKEN_EXPIRED";
    protected const string AccountDeleteTokenMismatchCode = "ACCOUNT_DELETE_TOKEN_MISMATCH";
    protected const string AccountDeleteRateLimitedCode = "ACCOUNT_DELETE_RATE_LIMITED";
    protected const string AccountDeleteAttemptLimitedCode = "ACCOUNT_DELETE_ATTEMPT_LIMITED";
    protected const string AccountDeleteVerifyRequiredCode = "ACCOUNT_DELETE_VERIFY_REQUIRED";
    protected const string AccountDeleteEmailDeliveryFailedCode = "ACCOUNT_DELETE_EMAIL_DELIVERY_FAILED";
    protected const string AccountDeleteRequestCleanupFailedCode = "ACCOUNT_DELETE_REQUEST_CLEANUP_FAILED";
    protected const string AccountNotFoundCode = "ACCOUNT_NOT_FOUND";

    protected ActionResult<ApiResponse<T>> ToActionResult<T>(ApiOutcome<T> outcome)
    {
        return ApiResponses.FromOutcome(this, outcome);
    }

    protected async Task<AuthenticatedMutationIdempotencyBeginResult> BeginAuthenticatedMutationIdempotency(
        ActiveSession activeSession, string route, bool requireKey = false, object? payload = null)
    {
        var values = Request.Headers[AuthenticatedMutationIdempotencyConstants.HeaderName];
        if (values.Count > 1) return AuthenticatedMutationIdempotencyBeginResult.InvalidKeyResult();
        string? key = values.Count == 1 ? values[0] : null;
        byte[] canonical = AuthenticatedMutationCanonicalRequest.FromHttp(HttpContext, payload);
        try
        {
            var result = await _authenticatedMutationIdempotencyService.BeginAsync(new(
                activeSession.accountId, HttpMethods.Post, route, key, requireKey,
                activeSession.accountSecurityStamp, canonical), HttpContext.RequestAborted);
            if (result.OperationId is Guid id && (result.Status is AuthenticatedMutationIdempotencyStatus.RecoveryRequired or AuthenticatedMutationIdempotencyStatus.Expired))
                Response.Headers["Security-Operation-Id"] = id.ToString("N");
            return result;
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(canonical); }
    }

    protected async Task CompleteAuthenticatedMutationIdempotency<T>(
        AuthenticatedMutationIdempotencyBeginResult idempotency, ApiOutcome<T> outcome)
    {
        if (idempotency.Reservation is null) return;
        await _authenticatedMutationIdempotencyService.CompleteStoredAsync(idempotency.Reservation,
            AuthenticatedMutationSafeResult.Capture(outcome, Response.Headers["AppStatus"].FirstOrDefault()),
            HttpContext.RequestAborted);
    }

    protected static ApiOutcome<T>? IdempotencyBlockingOutcome<T>(
        AuthenticatedMutationIdempotencyBeginResult idempotency,
        T failureBody)
    {
        return idempotency.Status switch
        {
            AuthenticatedMutationIdempotencyStatus.MissingRequiredKey => new ApiOutcome<T>(
                failureBody,
                StatusCodes.Status428PreconditionRequired,
                AuthenticatedMutationIdempotencyConstants.MissingRequiredKeyCode),
            AuthenticatedMutationIdempotencyStatus.InvalidKey => ApiResponses.InvalidPayload(
                failureBody,
                AuthenticatedMutationIdempotencyConstants.HeaderName,
                "Idempotency-Key must be 16 to 128 characters and contain only letters, digits, underscore, dash, period, or colon."),
            AuthenticatedMutationIdempotencyStatus.StoreUnavailable => new ApiOutcome<T>(
                failureBody,
                StatusCodes.Status503ServiceUnavailable,
                AuthenticatedMutationIdempotencyConstants.StoreUnavailableCode),
            AuthenticatedMutationIdempotencyStatus.ContentConflict => new ApiOutcome<T>(failureBody,
                StatusCodes.Status409Conflict, AuthenticatedMutationIdempotencyConstants.ContentConflictCode),
            AuthenticatedMutationIdempotencyStatus.RecoveryRequired => new ApiOutcome<T>(failureBody,
                StatusCodes.Status409Conflict, AuthenticatedMutationIdempotencyConstants.RecoveryRequiredCode),
            AuthenticatedMutationIdempotencyStatus.AuthorityChanged => new ApiOutcome<T>(failureBody,
                StatusCodes.Status401Unauthorized, AuthenticatedMutationIdempotencyConstants.AuthorityChangedCode),
            AuthenticatedMutationIdempotencyStatus.Expired => new ApiOutcome<T>(failureBody,
                StatusCodes.Status410Gone, AuthenticatedMutationIdempotencyConstants.ExpiredCode),
            AuthenticatedMutationIdempotencyStatus.ReplayInProgress => new ApiOutcome<T>(
                failureBody,
                StatusCodes.Status409Conflict,
                AuthenticatedMutationIdempotencyConstants.ReplayInProgressCode),
            _ => null
        };
    }

    protected ApiOutcome<T>? IdempotencyReplayOutcome<T>(AuthenticatedMutationIdempotencyBeginResult idempotency)
    {
        if (idempotency.Status != AuthenticatedMutationIdempotencyStatus.ReplayCompleted || idempotency.StoredResult is null) return null;
        return AuthenticatedMutationSafeResult.Restore<T>(idempotency.StoredResult, Response);
    }

    protected static ApiOutcome<T> PayloadInvalid<T>(T body, string field, string message)
    {
        return ApiResponses.InvalidPayload(body, field, message);
    }

    protected static ApiOutcome<T> PayloadInvalid<T>(T body, IReadOnlyList<ApiValidationError> errors)
    {
        return ApiResponses.InvalidPayload(body, errors);
    }

    protected static ApiValidationError ValidationError(string field, string message)
    {
        return ApiResponses.ValidationError(field, message);
    }

    protected static bool IsSupportedTwoFactorMethod(TwoFactorAuthMethod method)
    {
        return method is TwoFactorAuthMethod.EMAIL
            or TwoFactorAuthMethod.SMS_KEY
            or TwoFactorAuthMethod.AUTHENTICATOR_APP;
    }

    protected static bool IsSupportedTwoFactorSetupMethod(TwoFactorAuthMethod method)
    {
        return method is TwoFactorAuthMethod.EMAIL or TwoFactorAuthMethod.SMS_KEY;
    }

    protected static bool IsSelectableTwoFactorConfiguration(TwoFactorAuthConfiguration configuration)
    {
        return configuration is TwoFactorAuthConfiguration.SMS
            or TwoFactorAuthConfiguration.EMAIL
            or TwoFactorAuthConfiguration.AUTHENTICATOR_APP
            or TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP
            or TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP;
    }

    protected static bool IsValidTwoFactorDestination(short? destination)
    {
        return !destination.HasValue || destination.Value >= 0;
    }

    protected static bool IsDefinedCountry(Country country)
    {
        return Enum.IsDefined(typeof(Country), country) && country != Country.NONE;
    }

    protected static bool IsCutOffExpired(IntraAccount singleAccount, Instant moment)
    {
        return singleAccount.cutOff is not null && singleAccount.cutOff.Value <= moment;
    }

    protected static bool IsCutOffExpired(TwoFactorSession session, Instant moment)
    {
        return session.cutOff is not null && session.cutOff.Value <= moment;
    }

    protected static bool HasValidEmailShape(string? emailAddress, int maxLength)
    {
        return !string.IsNullOrWhiteSpace(emailAddress) &&
            emailAddress.Length <= maxLength &&
            new EmailAddressAttribute().IsValid(emailAddress);
    }

    protected static string? TrimOptionalAdjustmentField(string? value)
    {
        return value is null ? null : value.Trim();
    }

    protected static ApiValidationError SupportedTwoFactorMethodRequired(string field)
    {
        return ValidationError(field, SupportedTwoFactorMethodRequiredMessage);
    }

    protected static ApiValidationError RequiredField(string field)
    {
        return ValidationError(field, $"{field} is required.");
    }

    protected static int AccountSetupStatus(HttpMessage result)
    {
        return result switch
        {
            HttpMessage.ACCOUNT_CREATION_SUCCESSED => StatusCodes.Status200OK,

            HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING
                or HttpMessage.ACCOUNT_CREATION_VERIFICATION_RESENT
                => StatusCodes.Status202Accepted,

            HttpMessage.ACCOUNT_CREATION_PASSWORD_REQUIREMENT
                or HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL
                or HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME
                or HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME_EMAIL
                => StatusCodes.Status400BadRequest,

            HttpMessage.ACCOUNT_CREATION_RATE_LIMITED => StatusCodes.Status429TooManyRequests,
            HttpMessage.ACCOUNT_CREATION_ADMISSION_UNAVAILABLE => StatusCodes.Status503ServiceUnavailable,

            HttpMessage.ACCOUNT_CREATION_LOCKED => StatusCodes.Status423Locked,

            HttpMessage.ACCOUNT_CREATION_FAILED
                or HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED
                => StatusCodes.Status500InternalServerError,

            _ => StatusCodes.Status500InternalServerError
        };
    }

    protected static int LoginStatus(HttpMessage result)
    {
        return result switch
        {
            HttpMessage.AUTHENTICATION_PASSED
                or HttpMessage.AUTHENTICATION_REFRESHED
                or HttpMessage.AUTHENTICATION_TWO_FACTOR_AUTH_REQUESTED
                or HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED
                or HttpMessage.AUTHENTICATION_TWO_FACTOR_PASSED
                or HttpMessage.AUTHENTICATION_TWO_FACTOR_PROOF_ACCEPTED_NEXT_PROOF_REQUIRED
                => StatusCodes.Status200OK,

            HttpMessage.AUTHENTICATION_DUPLICATE => StatusCodes.Status400BadRequest,

            HttpMessage.ACCOUNT_LOCKED
                or HttpMessage.ACCOUNT_TIME_LOCKED
                => StatusCodes.Status423Locked,

            HttpMessage.AUTHENTICATION_FAILED
                or HttpMessage.AUTHENTICATION_BAD_PASSWORD
                or HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED
                or HttpMessage.AUTHENTICATION_EXPIRED
                or HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING
                or HttpMessage.ACCOUNT_CREATION_VERIFICATION_EXPIRED
                or HttpMessage.ACCOUNT_CREATION_VERIFICATION_RENEW
                or HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED
                => StatusCodes.Status401Unauthorized,

            _ => StatusCodes.Status500InternalServerError
        };
    }

    protected static int TwoFactorMethodStatus(HttpMessage result)
    {
        return result switch
        {
            HttpMessage.TWOFACTOR_WAITING_INTRA_EMAIL
                or HttpMessage.TWOFACTOR_WAITING_SMTP_RELAY
                or HttpMessage.TWOFACTOR_WAITING_SMS_KEY
                or HttpMessage.TWOFACTOR_WAITING_AUTHENTICATOR_APP
                => StatusCodes.Status200OK,

            HttpMessage.AUTHENTICATION_TWO_FACTOR_CODE_TIMEOUT
                or HttpMessage.TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED
                => StatusCodes.Status400BadRequest,

            HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED
                or HttpMessage.AUTHENTICATION_EXPIRED
                => StatusCodes.Status401Unauthorized,

            _ => StatusCodes.Status500InternalServerError
        };
    }

    protected static int TwoFactorAuthenticateStatus(TwoFactorAuthOutcome result)
    {
        return result switch
        {
            TwoFactorAuthOutcome.SUCCESS => StatusCodes.Status200OK,
            TwoFactorAuthOutcome.INCORRECT or TwoFactorAuthOutcome.FAILURE => StatusCodes.Status401Unauthorized,
            _ => StatusCodes.Status500InternalServerError
        };
    }

    protected static int TwoFactorAuthenticateStatus(HttpMessage failureReason)
    {
        return failureReason switch
        {
            HttpMessage.AUTHENTICATION_EXPIRED
                or HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED
                => StatusCodes.Status401Unauthorized,

            HttpMessage.AUTHENTICATION_TWO_FACTOR_CODE_TIMEOUT
                or HttpMessage.TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED
                => StatusCodes.Status400BadRequest,

            _ => StatusCodes.Status500InternalServerError
        };
    }


    protected static int TwoFactorSetupStatus(string? code)
    {
        return code switch
        {
            TwoFactorSetupPendingCode => StatusCodes.Status202Accepted,
            "DELIVERY_CANDIDATE_CONFLICT" or "DELIVERY_STALE_CANDIDATE" or "TWO_FACTOR_SETUP_CONFLICT" or "TWO_FACTOR_SETUP_DELIVERY_PENDING" or "TWO_FACTOR_SETUP_DUPLICATE" => StatusCodes.Status409Conflict,
            TwoFactorSetupUnsupportedMethodCode
                or TwoFactorSetupInvalidDestinationCode
                or TwoFactorSetupInvalidTokenCode
                or TwoFactorSetupInvalidExpirationCode
                => StatusCodes.Status400BadRequest,
            AccountSecurityStampMismatchCode or "SENSITIVE_ACTION_GRANT_REQUIRED" => StatusCodes.Status401Unauthorized,
            AccountNotFoundCode => StatusCodes.Status404NotFound,
            _ => StatusCodes.Status500InternalServerError
        };
    }

    protected static int TwoFactorSetupVerifyStatus(string? code)
    {
        return code switch
        {
            TwoFactorSetupVerifiedCode => StatusCodes.Status200OK,
            "TWO_FACTOR_SETUP_CONFLICT" or "TWO_FACTOR_SETUP_AUTHORITY_CHANGED" or "TWO_FACTOR_SETUP_DELIVERY_PENDING" => StatusCodes.Status409Conflict,
            TwoFactorSetupIncorrectCode
                or TwoFactorSetupAttemptLimitCode
                or TwoFactorSetupInvalidTokenCode
                or TwoFactorSetupUnsupportedMethodCode => StatusCodes.Status400BadRequest,
            TwoFactorSetupExpiredCode => StatusCodes.Status400BadRequest,
            AccountSecurityStampMismatchCode or "SENSITIVE_ACTION_GRANT_REQUIRED" => StatusCodes.Status401Unauthorized,
            AccountNotFoundCode or TwoFactorSetupNotFoundCode => StatusCodes.Status404NotFound,
            _ => StatusCodes.Status500InternalServerError
        };
    }

    protected static TwoFactorAuthOutcome TwoFactorSetupVerifyOutcome(string? code)
    {
        return code switch
        {
            TwoFactorSetupIncorrectCode or TwoFactorSetupAttemptLimitCode => TwoFactorAuthOutcome.INCORRECT,
            _ => TwoFactorAuthOutcome.FAILURE
        };
    }

    protected static ApiOutcome<SetupLayeredAuthenticateMethodResponse> SerializeTwoFactorSetup(
        bool status,
        int statusCode,
        string code)
    {
        return new ApiOutcome<SetupLayeredAuthenticateMethodResponse>(
            new SetupLayeredAuthenticateMethodResponse(status),
            statusCode,
            code);
    }

    internal const string HTML_SUCCESSFUL_ACCOUNT_VERIFY = "<html><body><h1>Account verified</h1></body></html>";
    internal const string HTML_UNSUCCESSFUL_ACCOUNT_VERIFY = "<html><body><h1>Account verification failed</h1></body></html>";
    internal const string HTML_EXPIRED_ACCOUNT_VERIFY = "<html><body><h1>Account verification expired</h1></body></html>";
    internal const string HTML_ALREADY_VERIFIED_ACCOUNT_VERIFY = "<html><body><h1>Account already verified</h1></body></html>";

    protected IAccountRepo _accountRepo { get; set; }
    protected ISessionRepo _sessionRepo { get; set; }
    protected IAccountService _accountService { get; set; }
    protected IActiveUserCacheService _activeUserCacheService { get; set; }
    protected ITwoFactorSessionService _twoFactorSessionService { get; set; }
    protected IJsonWebTokenUtility _jwtUtility { get; set; }
    protected ITwoFactorAuthenticateService _twoFactorService { get; set; }
    protected IAbuseCounterStore _abuseCounterStore { get; set; }
    protected ILoginAbuseCounterKeyFactory _loginAbuseCounterKeyFactory { get; set; }
    protected IAccountTokenVerificationAbuseCounterKeyFactory _accountTokenVerificationAbuseCounterKeyFactory { get; set; }
    protected IAuthenticatedMutationIdempotencyService _authenticatedMutationIdempotencyService { get; set; }
    protected RegistrationSettings _registrationSettings { get; set; }
    protected JWTSettings _jwtSettings { get; set; }
    protected LoginSettings _loginSettings { get; set; }
    protected AbuseControlSettings _abuseControlSettings { get; set; }
    protected EmailAddressAttribute _emailValidator { get; set; }
    protected readonly string _successfulAccountVerifyHtml;
    protected readonly string _unsuccessfulAccountVerifyHtml;
    protected readonly string _expiredAccountVerifyHtml;
    protected readonly string _alreadyVerifiedAccountVerifyHtml;


    protected AccountControllerBase(IAccountRepo accountRepo, ISessionRepo sessionRepo, IActiveUserCacheService activeUserCacheService, ITwoFactorSessionService twoFactorSessionService,
                                IJsonWebTokenUtility jwtUtility, ITwoFactorAuthenticateService twoFactorService, IAccountService accountService,
                                IAbuseCounterStore abuseCounterStore, ILoginAbuseCounterKeyFactory loginAbuseCounterKeyFactory,
                                IOptions<RegistrationSettings> registrationSettings, IOptions<JWTSettings> jwtSettings, IOptions<LoginSettings> loginSettings,
                                IOptions<AbuseControlSettings> abuseControlSettings,
                                IOptions<EmailTemplateSettings>? emailTemplateSettings = null,
                                IAccountTokenVerificationAbuseCounterKeyFactory? accountTokenVerificationAbuseCounterKeyFactory = null,
                                IAuthenticatedMutationIdempotencyService? authenticatedMutationIdempotencyService = null)
    {
        this._accountRepo = accountRepo;
        this._sessionRepo = sessionRepo;

        this._activeUserCacheService = activeUserCacheService;
        this._twoFactorSessionService = twoFactorSessionService;

        this._accountService = accountService;

        this._jwtUtility = jwtUtility;
        this._twoFactorService = twoFactorService;
        this._abuseCounterStore = abuseCounterStore;
        this._loginAbuseCounterKeyFactory = loginAbuseCounterKeyFactory;
        this._accountTokenVerificationAbuseCounterKeyFactory = accountTokenVerificationAbuseCounterKeyFactory ?? new AccountTokenVerificationAbuseCounterKeyFactory();
        this._authenticatedMutationIdempotencyService = authenticatedMutationIdempotencyService ?? NoOpAuthenticatedMutationIdempotencyService.Instance;
        this._registrationSettings = registrationSettings.Value;
        this._jwtSettings = jwtSettings.Value;
        this._loginSettings = loginSettings.Value;
        this._abuseControlSettings = abuseControlSettings.Value;

        this._emailValidator = new EmailAddressAttribute();

        EmailTemplateSettings? templates = emailTemplateSettings?.Value;
        this._successfulAccountVerifyHtml = LoadAccountVerificationHtmlTemplate(templates?.AccountVerificationSuccessPage, HTML_SUCCESSFUL_ACCOUNT_VERIFY);
        this._unsuccessfulAccountVerifyHtml = LoadAccountVerificationHtmlTemplate(templates?.AccountVerificationFailurePage, HTML_UNSUCCESSFUL_ACCOUNT_VERIFY);
        this._expiredAccountVerifyHtml = LoadAccountVerificationHtmlTemplate(templates?.AccountVerificationExpiredPage, HTML_EXPIRED_ACCOUNT_VERIFY);
        this._alreadyVerifiedAccountVerifyHtml = LoadAccountVerificationHtmlTemplate(templates?.AccountVerificationAlreadyVerifiedPage, HTML_ALREADY_VERIFIED_ACCOUNT_VERIFY);
    }

    protected static string LoadAccountVerificationHtmlTemplate(string? configuredPath, string fallback)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return fallback;
        }

        string rootedPath = Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.Combine(AppContext.BaseDirectory, configuredPath);

        if (!System.IO.File.Exists(rootedPath))
        {
            rootedPath = Path.Combine(Directory.GetCurrentDirectory(), configuredPath);
        }

        return System.IO.File.Exists(rootedPath)
            ? System.IO.File.ReadAllText(rootedPath)
            : fallback;
    }







    protected bool TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession)
    {
        hashedAccessToken = string.Empty;
        activeSession = null!;

        if (HttpContext.Items[AuthContextItems.HashedAccessToken] is not string tokenHash ||
            string.IsNullOrWhiteSpace(tokenHash))
        {
            return false;
        }

        if (HttpContext.Items[AuthContextItems.ActiveSession] is not ActiveSession session)
        {
            return false;
        }

        hashedAccessToken = tokenHash;
        activeSession = session;
        return true;
    }






}
