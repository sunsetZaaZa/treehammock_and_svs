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

public abstract partial class AccountControllerBase
{

    protected static ApiOutcome<StartAuthenticatorAppSetupResponse>? ValidateStartAuthenticatorAppSetupRequest(StartAuthenticatorAppSetupRequest? payload)
    {
        var body = new StartAuthenticatorAppSetupResponse(HttpMessage.AUTHENTICATOR_SETUP_FAILED);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        var errors = new List<ApiValidationError>();
        if (payload.expectedEnrollmentId.HasValue != payload.expectedVersion.HasValue ||
            payload.expectedEnrollmentId == Guid.Empty || payload.expectedVersion is <= 0 or > 9007199254740991)
            errors.Add(ValidationError(nameof(payload.expectedVersion), "The pending enrollment ID and version must be supplied together and be valid."));
        if (!string.IsNullOrWhiteSpace(payload.label) && payload.label.Trim().Length > StartAuthenticatorAppSetupRequest.MaxLabelLength)
        {
            errors.Add(ValidationError(
                nameof(StartAuthenticatorAppSetupRequest.label),
                $"label must be no longer than {StartAuthenticatorAppSetupRequest.MaxLabelLength} characters."));
        }

        if (payload.provider is not TotpProviderType.LOCAL_RFC6238)
        {
            errors.Add(ValidationError(
                nameof(StartAuthenticatorAppSetupRequest.provider),
                "provider must be LOCAL_RFC6238 until a managed TOTP provider contract is implemented."));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    protected static ApiOutcome<VerifyAuthenticatorAppSetupResponse>? ValidateVerifyAuthenticatorAppSetupRequest(VerifyAuthenticatorAppSetupRequest? payload)
    {
        var body = new VerifyAuthenticatorAppSetupResponse(HttpMessage.AUTHENTICATOR_SETUP_FAILED);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        var errors = new List<ApiValidationError>();
        if (string.IsNullOrWhiteSpace(payload.setupId))
        {
            errors.Add(RequiredField(nameof(VerifyAuthenticatorAppSetupRequest.setupId)));
        }
        else if (payload.setupId.Length > VerifyAuthenticatorAppSetupRequest.MaxSetupIdLength)
        {
            errors.Add(ValidationError(
                nameof(VerifyAuthenticatorAppSetupRequest.setupId),
                $"setupId must be no longer than {VerifyAuthenticatorAppSetupRequest.MaxSetupIdLength} characters."));
        }

        if (string.IsNullOrWhiteSpace(payload.totpCode))
        {
            errors.Add(RequiredField(nameof(VerifyAuthenticatorAppSetupRequest.totpCode)));
        }
        else if (payload.totpCode.Length > VerifyAuthenticatorAppSetupRequest.MaxTotpCodeLength)
        {
            errors.Add(ValidationError(
                nameof(VerifyAuthenticatorAppSetupRequest.totpCode),
                $"totpCode must be no longer than {VerifyAuthenticatorAppSetupRequest.MaxTotpCodeLength} characters."));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    protected static ApiOutcome<CancelAuthenticatorAppSetupResponse>? ValidateCancelAuthenticatorAppSetupRequest(CancelAuthenticatorAppSetupRequest? payload)
    {
        var body = new CancelAuthenticatorAppSetupResponse(HttpMessage.AUTHENTICATOR_SETUP_FAILED);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        var errors = new List<ApiValidationError>();
        if (string.IsNullOrWhiteSpace(payload.setupId))
        {
            errors.Add(RequiredField(nameof(CancelAuthenticatorAppSetupRequest.setupId)));
        }
        else if (payload.setupId.Length > CancelAuthenticatorAppSetupRequest.MaxSetupIdLength)
        {
            errors.Add(ValidationError(
                nameof(CancelAuthenticatorAppSetupRequest.setupId),
                $"setupId must be no longer than {CancelAuthenticatorAppSetupRequest.MaxSetupIdLength} characters."));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    protected static ApiOutcome<SetupLayeredAuthenticateMethodResponse>? ValidateSetupTwoFactorMethodRequest(SetupLayeredAuthenticateMethodRequest? payload)
    {
        var body = new SetupLayeredAuthenticateMethodResponse(false);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        var errors = new List<ApiValidationError>();
        if (!IsSupportedTwoFactorSetupMethod(payload.method))
        {
            errors.Add(SupportedTwoFactorMethodRequired(nameof(SetupLayeredAuthenticateMethodRequest.method)));
        }

        if (string.IsNullOrWhiteSpace(payload.contact))
        {
            errors.Add(RequiredField(nameof(SetupLayeredAuthenticateMethodRequest.contact)));
        }
        else if (payload.contact.Length > SetupLayeredAuthenticateMethodRequest.MaxContactLength)
        {
            errors.Add(ValidationError(
                nameof(SetupLayeredAuthenticateMethodRequest.contact),
                $"contact must be no longer than {SetupLayeredAuthenticateMethodRequest.MaxContactLength} characters."));
        }
        else if (payload.method == TwoFactorAuthMethod.EMAIL &&
                 !HasValidEmailShape(payload.contact.Trim(), SetupLayeredAuthenticateMethodRequest.MaxContactLength))
        {
            errors.Add(ValidationError(
                nameof(SetupLayeredAuthenticateMethodRequest.contact),
                $"contact must be a valid email address no longer than {SetupLayeredAuthenticateMethodRequest.MaxContactLength} characters for email two-factor setup."));
        }

        if (payload.countryCode.HasValue && payload.countryCode.Value < 1)
        {
            errors.Add(ValidationError(
                nameof(SetupLayeredAuthenticateMethodRequest.countryCode),
                "countryCode must be greater than or equal to 1 when supplied."));
        }

        if (payload.method == TwoFactorAuthMethod.SMS_KEY && !payload.countryCode.HasValue)
        {
            errors.Add(ValidationError(
                nameof(SetupLayeredAuthenticateMethodRequest.countryCode),
                "countryCode is required for SMS two-factor setup."));
        }

        if (payload.expectedEnrollmentId.HasValue != payload.expectedVersion.HasValue || payload.expectedEnrollmentId == Guid.Empty || payload.expectedVersion is <= 0 or > 9007199254740991)
            errors.Add(ValidationError(nameof(payload.expectedEnrollmentId), "Replacement requires the pending enrollment ID and version."));
        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    protected static ApiOutcome<LayeredAuthenticateResponse>? ValidateVerifyTwoFactorMethodRequest(VerifyLayeredAuthenticateMethodRequest? payload)
    {
        var body = new LayeredAuthenticateResponse(TwoFactorAuthOutcome.FAILURE);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        var errors = new List<ApiValidationError>();
        if (!IsSupportedTwoFactorSetupMethod(payload.method))
        {
            errors.Add(SupportedTwoFactorMethodRequired(nameof(VerifyLayeredAuthenticateMethodRequest.method)));
        }

        if (string.IsNullOrWhiteSpace(payload.codeKey))
        {
            errors.Add(RequiredField(nameof(VerifyLayeredAuthenticateMethodRequest.codeKey)));
        }
        else if (payload.codeKey.Length > VerifyLayeredAuthenticateMethodRequest.MaxCodeLength)
        {
            errors.Add(ValidationError(
                nameof(VerifyLayeredAuthenticateMethodRequest.codeKey),
                $"codeKey must be no longer than {VerifyLayeredAuthenticateMethodRequest.MaxCodeLength} characters."));
        }

        if (payload.enrollmentId == Guid.Empty) errors.Add(ValidationError(nameof(payload.enrollmentId), "The pending enrollment ID is required."));
        if (payload.setupVersion is <= 0 or > 9007199254740991) errors.Add(ValidationError(nameof(payload.setupVersion), "A valid pending setup version is required."));
        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    protected static ApiOutcome<RemoveTwoFactorMethodResponse>? ValidateRemoveTwoFactorMethodRequest(RemoveTwoFactorMethodRequest? payload)
    {
        var body = new RemoveTwoFactorMethodResponse(false, HttpMessage.TWO_FACTOR_METHOD_REMOVE_UNSUPPORTED_METHOD);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        var errors = new List<ApiValidationError>();
        if (!IsSupportedTwoFactorMethod(payload.method))
        {
            errors.Add(SupportedTwoFactorMethodRequired(nameof(RemoveTwoFactorMethodRequest.method)));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }


    protected static ApiOutcome<LayeredAuthenticateMethodsResponse>? ValidateTwoFactorMethodRequest(LayeredAuthenticateMethodsRequest? payload)
    {
        var body = new LayeredAuthenticateMethodsResponse(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        var errors = new List<ApiValidationError>();
        if (!IsSupportedTwoFactorMethod(payload.method))
        {
            errors.Add(SupportedTwoFactorMethodRequired(nameof(LayeredAuthenticateMethodsRequest.method)));
        }

        if (!IsValidTwoFactorDestination(payload.destination))
        {
            errors.Add(ValidationError(
                nameof(LayeredAuthenticateMethodsRequest.destination),
                "destination must be greater than or equal to 0 when supplied."));
        }

        if (payload.method == TwoFactorAuthMethod.AUTHENTICATOR_APP && payload.destination.HasValue && payload.destination.Value != 0)
        {
            errors.Add(ValidationError(
                nameof(LayeredAuthenticateMethodsRequest.destination),
                "destination must be omitted or 0 for authenticator-app challenges."));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    protected static ApiOutcome<LayeredAuthenticateMethodsResponse>? ValidateSelectTwoFactorConfigurationRequest(SelectTwoFactorConfigurationRequest? payload)
    {
        var body = new LayeredAuthenticateMethodsResponse(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        var errors = new List<ApiValidationError>();
        if (!IsSelectableTwoFactorConfiguration(payload.configuration))
        {
            errors.Add(ValidationError(
                nameof(SelectTwoFactorConfigurationRequest.configuration),
                SelectableTwoFactorConfigurationRequiredMessage));
        }

        if (!IsValidTwoFactorDestination(payload.destination))
        {
            errors.Add(ValidationError(
                nameof(SelectTwoFactorConfigurationRequest.destination),
                "destination must be greater than or equal to 0 when supplied."));
        }

        if (payload.configuration == TwoFactorAuthConfiguration.AUTHENTICATOR_APP && payload.destination.HasValue && payload.destination.Value != 0)
        {
            errors.Add(ValidationError(
                nameof(SelectTwoFactorConfigurationRequest.destination),
                "destination must be omitted or 0 for authenticator-app challenges."));
        }

        if (!string.IsNullOrWhiteSpace(payload.twoFactorAccessToken) && payload.twoFactorAccessToken.Length > SelectTwoFactorConfigurationRequest.MaxTwoFactorAccessTokenLength)
        {
            errors.Add(ValidationError(
                nameof(SelectTwoFactorConfigurationRequest.twoFactorAccessToken),
                $"twoFactorAccessToken must be no longer than {SelectTwoFactorConfigurationRequest.MaxTwoFactorAccessTokenLength} characters."));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }


    protected static ApiOutcome<LayeredAuthenticateResponse>? ValidateTwoFactorAuthenticateRequest(LayeredAuthenticateRequest? payload)
    {
        var body = new LayeredAuthenticateResponse(TwoFactorAuthOutcome.FAILURE);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        var errors = new List<ApiValidationError>();
        if (!IsSupportedTwoFactorMethod(payload.method))
        {
            errors.Add(SupportedTwoFactorMethodRequired(nameof(LayeredAuthenticateRequest.method)));
        }

        if (string.IsNullOrWhiteSpace(payload.codeKey))
        {
            errors.Add(RequiredField(nameof(LayeredAuthenticateRequest.codeKey)));
        }
        else if (payload.codeKey.Length > LayeredAuthenticateRequest.MaxCodeLength)
        {
            errors.Add(ValidationError(
                nameof(LayeredAuthenticateRequest.codeKey),
                $"codeKey must be no longer than {LayeredAuthenticateRequest.MaxCodeLength} characters."));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    protected static ApiOutcome<AccountEditResponse>? ValidateModifyAccountRequest(AccountEditRequest? payload)
    {
        var body = new AccountEditResponse(HttpMessage.ACCOUNT_ADJUST_FAILED);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        payload.emailAddress = TrimOptionalAdjustmentField(payload.emailAddress);
        payload.username = TrimOptionalAdjustmentField(payload.username);

        var errors = new List<ApiValidationError>();
        bool emailSupplied = payload.emailAddress is not null;
        bool usernameSupplied = payload.username is not null;

        if (!emailSupplied && !usernameSupplied)
        {
            errors.Add(ValidationError(
                string.Empty,
                "At least one account adjustment field is required."));
        }

        if (emailSupplied && usernameSupplied)
        {
            errors.Add(ValidationError(
                string.Empty,
                "Only one account adjustment field may be supplied per request."));
        }

        if (emailSupplied)
        {
            if (payload.emailAddress!.Length == 0)
            {
                errors.Add(ValidationError(
                    nameof(AccountEditRequest.emailAddress),
                    "emailAddress must not be empty when supplied."));
            }
            else if (!HasValidEmailShape(payload.emailAddress, AccountEditRequest.MaxEmailAddressLength))
            {
                errors.Add(ValidationError(
                    nameof(AccountEditRequest.emailAddress),
                    $"emailAddress must be a valid email address no longer than {AccountEditRequest.MaxEmailAddressLength} characters when supplied."));
            }
        }

        if (usernameSupplied)
        {
            if (payload.username!.Length == 0)
            {
                errors.Add(ValidationError(
                    nameof(AccountEditRequest.username),
                    "username must not be empty when supplied."));
            }
            else if (payload.username.Length > AccountEditRequest.MaxUsernameLength)
            {
                errors.Add(ValidationError(
                    nameof(AccountEditRequest.username),
                    $"username must be no longer than {AccountEditRequest.MaxUsernameLength} characters when supplied."));
            }
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    protected static int AccountAdjustFailureStatus(string? code)
    {
        return code switch
        {
            "SENSITIVE_ACTION_GRANT_REQUIRED" => 401,
            "ACCOUNT_ADJUST_AUTHORITY_CHANGED" or "ACCOUNT_ADJUST_CONFLICT" or "ACCOUNT_ADJUST_DELIVERY_PENDING" or "DELIVERY_CANDIDATE_CONFLICT" or AccountAdjustEmailVerificationPendingCode => 409,
            AccountAdjustDuplicateEmailCode
                or AccountAdjustDuplicateUsernameCode
                or AccountAdjustTokenExpiredCode
                or AccountAdjustTokenMismatchCode
                => StatusCodes.Status400BadRequest,
            AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded => StatusCodes.Status429TooManyRequests,
            AbuseReasonCodes.CounterStoreUnavailable
                or AbuseReasonCodes.CounterStoreTimeout => StatusCodes.Status503ServiceUnavailable,
            AccountSecurityStampMismatchCode => StatusCodes.Status401Unauthorized,
            AccountNotFoundCode => StatusCodes.Status404NotFound,
            _ => StatusCodes.Status500InternalServerError
        };
    }

    protected static HttpMessage AccountAdjustMessage(string? code)
    {
        return code switch
        {
            AccountAdjustSucceededCode => HttpMessage.ACCOUNT_ADJUST_SUCCEEDED,
            AccountAdjustDuplicateEmailCode => HttpMessage.ACCOUNT_ADJUST_DUPLICATE_EMAIL,
            AccountAdjustDuplicateUsernameCode => HttpMessage.ACCOUNT_ADJUST_DUPLICATE_USERNAME,
            AccountSecurityStampMismatchCode => HttpMessage.ACCOUNT_SECURITY_STAMP_MISMATCH,
            AccountNotFoundCode => HttpMessage.ACCOUNT_NOT_FOUND,
            AccountAdjustEmailVerificationPendingCode => HttpMessage.ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING,
            AccountAdjustEmailDeliveryFailedCode => HttpMessage.ACCOUNT_ADJUST_EMAIL_DELIVERY_FAILED,
            AccountAdjustEmailChangeCleanupFailedCode => HttpMessage.ACCOUNT_ADJUST_EMAIL_CHANGE_CLEANUP_FAILED,
            AccountAdjustTokenExpiredCode => HttpMessage.ACCOUNT_ADJUST_TOKEN_EXPIRED,
            AccountAdjustTokenMismatchCode => HttpMessage.ACCOUNT_ADJUST_TOKEN_MISMATCH,
            _ => HttpMessage.ACCOUNT_ADJUST_FAILED
        };
    }

    protected static int AccountViewFailureStatus(string? code)
    {
        return code switch
        {
            AccountSecurityStampMismatchCode => StatusCodes.Status401Unauthorized,
            AccountNotFoundCode => StatusCodes.Status404NotFound,
            _ => StatusCodes.Status500InternalServerError
        };
    }

    protected static HttpMessage AccountViewFailureMessage(string? code)
    {
        return code switch
        {
            AccountSecurityStampMismatchCode => HttpMessage.ACCOUNT_SECURITY_STAMP_MISMATCH,
            AccountNotFoundCode => HttpMessage.ACCOUNT_NOT_FOUND,
            _ => HttpMessage.ACCOUNT_VIEW_FAILED
        };
    }

    protected static ApiOutcome<AccountDeleteResponse>? ValidateDeleteAccountRequest(AccountDeleteRequest? payload)
    {
        var body = new AccountDeleteResponse(HttpMessage.ACCOUNT_DELETE_FAILED);
        if (payload == null)
        {
            return null;
        }

        payload.passPhrase = TrimOptionalAdjustmentField(payload.passPhrase);

        var errors = new List<ApiValidationError>();
        if (payload.passPhrase is not null)
        {
            if (payload.passPhrase.Length == 0)
            {
                errors.Add(ValidationError(
                    nameof(AccountDeleteRequest.passPhrase),
                    "passPhrase must not be empty when supplied."));
            }
            else if (payload.passPhrase.Length > AccountDeleteRequest.MaxPassPhraseLength)
            {
                errors.Add(ValidationError(
                    nameof(AccountDeleteRequest.passPhrase),
                    $"passPhrase must be no longer than {AccountDeleteRequest.MaxPassPhraseLength} characters when supplied."));
            }
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }


    protected static ApiOutcome<AccountEditResponse>? ValidateEmailChangeVerifyPayload(string? payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return ApiResponses.InvalidPayload(
                new AccountEditResponse(HttpMessage.ACCOUNT_ADJUST_FAILED),
                "payload",
                "payload is required.");
        }

        if (payload.Length > AccountEmailChangeVerifyRequest.MaxEmailChangeTokenLength)
        {
            return ApiResponses.InvalidPayload(
                new AccountEditResponse(HttpMessage.ACCOUNT_ADJUST_FAILED),
                "payload",
                $"payload must be no longer than {AccountEmailChangeVerifyRequest.MaxEmailChangeTokenLength} characters.");
        }

        return null;
    }

    protected static ApiOutcome<AccountDeleteResponse>? ValidateDeleteVerifyPayload(string? payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return ApiResponses.InvalidPayload(
                new AccountDeleteResponse(HttpMessage.ACCOUNT_DELETE_FAILED),
                "payload",
                "payload is required.");
        }

        if (payload.Length > AccountDeleteVerifyRequest.MaxDeleteTokenLength)
        {
            return ApiResponses.InvalidPayload(
                new AccountDeleteResponse(HttpMessage.ACCOUNT_DELETE_FAILED),
                "payload",
                $"payload must be no longer than {AccountDeleteVerifyRequest.MaxDeleteTokenLength} characters.");
        }

        return null;
    }

    protected static ApiOutcome<AccountDeleteResponse>? ValidateFinalizeDeleteRequest(AccountDeleteFinalizeRequest? payload)
    {
        var body = new AccountDeleteResponse(HttpMessage.ACCOUNT_DELETE_FAILED);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        payload.deleteToken = payload.deleteToken?.Trim() ?? string.Empty;
        payload.passPhrase = TrimOptionalAdjustmentField(payload.passPhrase);

        var errors = new List<ApiValidationError>();
        if (string.IsNullOrWhiteSpace(payload.deleteToken))
        {
            errors.Add(ValidationError(nameof(AccountDeleteFinalizeRequest.deleteToken), "deleteToken is required."));
        }
        else if (payload.deleteToken.Length > AccountDeleteFinalizeRequest.MaxDeleteTokenLength)
        {
            errors.Add(ValidationError(
                nameof(AccountDeleteFinalizeRequest.deleteToken),
                $"deleteToken must be no longer than {AccountDeleteFinalizeRequest.MaxDeleteTokenLength} characters."));
        }

        if (payload.passPhrase is not null)
        {
            if (payload.passPhrase.Length == 0)
            {
                errors.Add(ValidationError(
                    nameof(AccountDeleteFinalizeRequest.passPhrase),
                    "passPhrase must not be empty when supplied."));
            }
            else if (payload.passPhrase.Length > AccountDeleteFinalizeRequest.MaxPassPhraseLength)
            {
                errors.Add(ValidationError(
                    nameof(AccountDeleteFinalizeRequest.passPhrase),
                    $"passPhrase must be no longer than {AccountDeleteFinalizeRequest.MaxPassPhraseLength} characters when supplied."));
            }
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    protected static int AccountDeleteFailureStatus(string? code)
    {
        return code switch
        {
            AccountDeleteTokenExpiredCode
                or AccountDeleteTokenMismatchCode
                or AccountDeleteVerifyRequiredCode
                => StatusCodes.Status400BadRequest,
            AccountDeleteRateLimitedCode
                or AccountDeleteAttemptLimitedCode
                or AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded
                or AbuseReasonCodes.AccountDeleteFinalizeAttemptsExceeded
                => StatusCodes.Status429TooManyRequests,
            AbuseReasonCodes.CounterStoreUnavailable
                or AbuseReasonCodes.CounterStoreTimeout => StatusCodes.Status503ServiceUnavailable,
            "SENSITIVE_ACTION_GRANT_REQUIRED" => StatusCodes.Status401Unauthorized,
            "ACCOUNT_DELETE_AUTHORITY_CHANGED" or "ACCOUNT_DELETE_CONFLICT" or "DELIVERY_CANDIDATE_CONFLICT" or AccountDeletePendingCode => StatusCodes.Status409Conflict,
            AccountSecurityStampMismatchCode => StatusCodes.Status401Unauthorized,
            AccountNotFoundCode => StatusCodes.Status404NotFound,
            _ => StatusCodes.Status500InternalServerError
        };
    }

    protected static HttpMessage AccountDeleteMessage(string? code)
    {
        return code switch
        {
            AccountDeletePendingCode => HttpMessage.ACCOUNT_DELETE_PENDING,
            AccountDeleteVerifiedCode => HttpMessage.ACCOUNT_DELETE_VERIFIED,
            AccountDeleteSucceededCode => HttpMessage.ACCOUNT_DELETE_SUCCEEDED,
            AccountDeleteTokenExpiredCode => HttpMessage.ACCOUNT_DELETE_TOKEN_EXPIRED,
            AccountDeleteTokenMismatchCode => HttpMessage.ACCOUNT_DELETE_TOKEN_MISMATCH,
            AccountDeleteRateLimitedCode => HttpMessage.ACCOUNT_DELETE_RATE_LIMITED,
            AccountDeleteAttemptLimitedCode
                or AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded
                or AbuseReasonCodes.AccountDeleteFinalizeAttemptsExceeded => HttpMessage.ACCOUNT_DELETE_ATTEMPT_LIMITED,
            AccountDeleteVerifyRequiredCode => HttpMessage.ACCOUNT_DELETE_VERIFY_REQUIRED,
            AccountDeleteEmailDeliveryFailedCode => HttpMessage.ACCOUNT_DELETE_EMAIL_DELIVERY_FAILED,
            AccountDeleteRequestCleanupFailedCode => HttpMessage.ACCOUNT_DELETE_REQUEST_CLEANUP_FAILED,
            AccountSecurityStampMismatchCode => HttpMessage.ACCOUNT_SECURITY_STAMP_MISMATCH,
            AccountNotFoundCode => HttpMessage.ACCOUNT_NOT_FOUND,
            _ => HttpMessage.ACCOUNT_DELETE_FAILED
        };
    }


    protected static ApiOutcome<ReauthenticateResponse>? ValidateReauthenticateRequest(ReauthenticateRequest? payload)
    {
        var body = new ReauthenticateResponse(HttpMessage.SENSITIVE_ACTION_REAUTHENTICATION_FAILED);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        var errors = new List<ApiValidationError>();
        if (string.IsNullOrWhiteSpace(payload.password))
        {
            errors.Add(RequiredField(nameof(ReauthenticateRequest.password)));
        }
        else if (payload.password.Length > ReauthenticateRequest.MaxPasswordLength)
        {
            errors.Add(ValidationError(
                nameof(ReauthenticateRequest.password),
                $"password must be no longer than {ReauthenticateRequest.MaxPasswordLength} characters."));
        }

        if (!SensitiveActionTargets.Supported(payload.purpose))
        {
            errors.Add(ValidationError(
                nameof(ReauthenticateRequest.purpose),
                "purpose must be a supported sensitive action."));
        }

        if ((payload.target is null && payload.purpose != SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP)
            || payload.target is { Length: < 1 or > 1024 })
            errors.Add(ValidationError(nameof(ReauthenticateRequest.target), "target must be the bounded canonical action target."));
        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    protected static ApiOutcome<AuthenticateLogoffResponse>? ValidateLogoffAccountRequest(AuthenticateLogoffRequest? payload)
    {
        // Logout is bearer-token driven. A missing body is treated the same as an empty object.
        return null;
    }

    protected static ApiOutcome<AuthenticateLogoffAllResponse>? ValidateLogoffAllAccountRequest(AuthenticateLogoffAllRequest? payload)
    {
        if (payload?.includeCurrentSession == false)
        {
            var body = new AuthenticateLogoffAllResponse(HttpMessage.AUTHENTICATION_LOGOFF_FAILED);
            return ApiResponses.InvalidPayload(
                body,
                nameof(AuthenticateLogoffAllRequest.includeCurrentSession),
                "includeCurrentSession must be true because logout-all rotates the account security stamp and invalidates the current session.");
        }

        // A missing body is accepted and behaves like the default request: includeCurrentSession = true.
        return null;
    }

    protected static int AuthStateConflictStatus(string? code)
    {
        return string.Equals(code, AccountSecurityStampMismatchCode, StringComparison.Ordinal)
            ? StatusCodes.Status401Unauthorized
            : StatusCodes.Status500InternalServerError;
    }

    protected static HttpMessage LogoffReplayMessage(string? code)
    {
        return code is LogoffSucceededCode or LogoffCacheRevokeFailedCode
            ? HttpMessage.AUTHENTICATION_LOGOFF_SUCCEEDED
            : HttpMessage.AUTHENTICATION_LOGOFF_FAILED;
    }

    protected static HttpMessage LogoffAllReplayMessage(string? code)
    {
        return string.Equals(code, LogoffAllSucceededCode, StringComparison.Ordinal)
            ? HttpMessage.AUTHENTICATION_LOGOFF_ALL_SUCCEEDED
            : HttpMessage.AUTHENTICATION_LOGOFF_FAILED;
    }

    protected static HttpMessage SessionRevokeReplayMessage(string? code)
    {
        return code is SessionRevokeSucceededCode or CurrentSessionRevokeSucceededCode or SessionRevokeCacheRevokeFailedCode
            ? HttpMessage.AUTHENTICATION_SESSION_REVOKED
            : HttpMessage.AUTHENTICATION_SESSION_REVOKE_FAILED;
    }

    protected static ApiOutcome<AccountSessionRevokeResponse>? ValidateRevokeSessionRequest(AccountSessionRevokeRequest? payload)
    {
        var body = new AccountSessionRevokeResponse(HttpMessage.AUTHENTICATION_SESSION_REVOKE_FAILED);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        if (payload.sessionId == Guid.Empty)
        {
            return ApiResponses.InvalidPayload(body, nameof(AccountSessionRevokeRequest.sessionId), "sessionId is required.");
        }

        return null;
    }

}
