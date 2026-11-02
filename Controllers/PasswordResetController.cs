using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

using treehammock.Models.Api;
using treehammock.Models.PasswordReset;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Controllers;

[ApiController]
[AllowAnonymous]
[Route("account/password-reset")]
[Produces("application/json")]
public sealed class PasswordResetController : ControllerBase
{
    private const string RequestBodyRequiredMessage = "The request body is required.";
    private readonly IPasswordResetService _passwordResetService;

    public PasswordResetController(IPasswordResetService passwordResetService)
    {
        _passwordResetService = passwordResetService;
    }

    [HttpPost("request")]
    [ProducesResponseType(typeof(ApiResponse<PasswordResetRequestResponse>), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ApiResponse<PasswordResetRequestResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<PasswordResetRequestResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<PasswordResetRequestResponse>>> RequestReset(
        [FromBody] RequestPasswordResetRequest? payload,
        CancellationToken cancellationToken)
    {
        var validation = ValidateRequestReset(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        PasswordResetRequestResult result = await _passwordResetService.RequestReset(
            new RequestPasswordResetCommand(
                payload!.identifier,
                payload.deliveryChannel,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers["User-Agent"].ToString(), payload.captchaToken, payload.captchaContinuation),
            cancellationToken);

        return ToActionResult(new ApiOutcome<PasswordResetRequestResponse>(
            new PasswordResetRequestResponse("accepted", result.ResetId, PasswordResetRequestResponse.GenericAcceptedMessage) { captchaChallenge = result.CaptchaChallenge },
            StatusCodes.Status202Accepted,
            result.Code));
    }

    [HttpPost("verify")]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTokenResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTokenResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTokenResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTokenResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTokenResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTokenResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTokenResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<VerifyPasswordResetTokenResponse>>> VerifyResetToken(
        [FromBody] VerifyPasswordResetTokenRequest? payload,
        CancellationToken cancellationToken)
    {
        var validation = ValidateVerify(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        PasswordResetVerifyResult result = await _passwordResetService.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(
                payload!.resetId,
                payload.keyCode,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers["User-Agent"].ToString()),
            cancellationToken);

        return ToActionResult(new ApiOutcome<VerifyPasswordResetTokenResponse>(
            new VerifyPasswordResetTokenResponse(
                result.Status,
                result.ResetAccessToken,
                result.RequiresTwoFactor,
                result.AvailableTwoFactorAuthConfigurations,
                result.ExpiresAt),
            result.StatusCode,
            result.Code));
    }

    [HttpPost("twofactor/select")]
    [ProducesResponseType(typeof(ApiResponse<SelectPasswordResetTwoFactorConfigurationResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<SelectPasswordResetTwoFactorConfigurationResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<SelectPasswordResetTwoFactorConfigurationResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<SelectPasswordResetTwoFactorConfigurationResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<SelectPasswordResetTwoFactorConfigurationResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<SelectPasswordResetTwoFactorConfigurationResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<SelectPasswordResetTwoFactorConfigurationResponse>), StatusCodes.Status501NotImplemented)]
    [ProducesResponseType(typeof(ApiResponse<SelectPasswordResetTwoFactorConfigurationResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<SelectPasswordResetTwoFactorConfigurationResponse>>> SelectTwoFactorConfiguration(
        [FromBody] SelectPasswordResetTwoFactorConfigurationRequest? payload,
        CancellationToken cancellationToken)
    {
        var validation = ValidateSelectTwoFactorConfiguration(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        PasswordResetTwoFactorSelectResult result = await _passwordResetService.SelectTwoFactorConfiguration(
            new SelectPasswordResetTwoFactorConfigurationCommand(
                payload!.resetAccessToken,
                payload.configuration,
                payload.destination,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers["User-Agent"].ToString()),
            cancellationToken);

        return ToActionResult(new ApiOutcome<SelectPasswordResetTwoFactorConfigurationResponse>(
            new SelectPasswordResetTwoFactorConfigurationResponse(
                result.Status,
                result.ResetAccessToken,
                result.SelectedConfiguration,
                result.CurrentRequiredMethod,
                result.ChallengeExpiration,
                result.CompletedTwoFactorAuthMethods,
                result.RemainingTwoFactorAuthMethods,
                result.AvailableTwoFactorAuthConfigurations,
                result.ExpiresAt,
                result.CanChangePassword),
            result.StatusCode,
            result.Code));
    }


    [HttpPost("twofactor/verify")]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTwoFactorResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTwoFactorResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTwoFactorResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTwoFactorResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTwoFactorResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTwoFactorResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<VerifyPasswordResetTwoFactorResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<VerifyPasswordResetTwoFactorResponse>>> VerifyTwoFactorProof(
        [FromBody] VerifyPasswordResetTwoFactorRequest? payload,
        CancellationToken cancellationToken)
    {
        var validation = ValidateVerifyTwoFactorProof(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        PasswordResetTwoFactorVerifyResult result = await _passwordResetService.VerifyTwoFactorProof(
            new VerifyPasswordResetTwoFactorCommand(
                payload!.resetAccessToken,
                payload.method,
                payload.code,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers["User-Agent"].ToString()),
            cancellationToken);

        return ToActionResult(new ApiOutcome<VerifyPasswordResetTwoFactorResponse>(
            new VerifyPasswordResetTwoFactorResponse(
                result.Status,
                result.ResetAccessToken,
                result.SelectedConfiguration,
                result.CurrentRequiredMethod,
                result.CompletedTwoFactorAuthMethods,
                result.RemainingTwoFactorAuthMethods,
                result.ExpiresAt,
                result.CanChangePassword),
            result.StatusCode,
            result.Code));
    }

    [HttpPost("finalize")]
    [ProducesResponseType(typeof(ApiResponse<FinalizePasswordResetResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<FinalizePasswordResetResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<FinalizePasswordResetResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<FinalizePasswordResetResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<FinalizePasswordResetResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<FinalizePasswordResetResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<FinalizePasswordResetResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<FinalizePasswordResetResponse>>> FinalizeReset(
        [FromBody] FinalizePasswordResetRequest? payload,
        CancellationToken cancellationToken)
    {
        var validation = ValidateFinalize(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        PasswordResetFinalizeResult result = await _passwordResetService.FinalizeReset(
            new FinalizePasswordResetCommand(
                payload!.resetId,
                payload.keyCode,
                payload.totpCode,
                payload.password,
                payload.verifyPassword,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers["User-Agent"].ToString(),
                payload.resetAccessToken),
            cancellationToken);

        return ToActionResult(new ApiOutcome<FinalizePasswordResetResponse>(
            new FinalizePasswordResetResponse(StatusFromCode(result.Code)),
            result.StatusCode,
            result.Code));
    }

    private static ApiOutcome<PasswordResetRequestResponse>? ValidateRequestReset(RequestPasswordResetRequest? payload)
    {
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(AcceptedResponse(Guid.Empty), string.Empty, RequestBodyRequiredMessage);
        }

        payload.identifier = payload.identifier?.Trim() ?? string.Empty;
        payload.deliveryChannel = PasswordResetDeliveryChannels.Normalize(payload.deliveryChannel);

        var errors = new List<ApiValidationError>();
        if (payload.captchaToken?.Length > 2048 || payload.captchaContinuation?.Length > 256)
            errors.Add(ApiResponses.ValidationError("captcha", "CAPTCHA proof exceeds its allowed length."));

        if (string.IsNullOrWhiteSpace(payload.identifier))
        {
            errors.Add(ApiResponses.ValidationError(nameof(RequestPasswordResetRequest.identifier), "identifier is required."));
        }
        else if (payload.identifier.Length > RequestPasswordResetRequest.MaxIdentifierLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(RequestPasswordResetRequest.identifier),
                $"identifier must be no longer than {RequestPasswordResetRequest.MaxIdentifierLength} characters."));
        }

        if (string.IsNullOrWhiteSpace(payload.deliveryChannel))
        {
            errors.Add(ApiResponses.ValidationError(nameof(RequestPasswordResetRequest.deliveryChannel), "deliveryChannel is required."));
        }
        else if (payload.deliveryChannel.Length > RequestPasswordResetRequest.MaxDeliveryChannelLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(RequestPasswordResetRequest.deliveryChannel),
                $"deliveryChannel must be no longer than {RequestPasswordResetRequest.MaxDeliveryChannelLength} characters."));
        }
        else if (!PasswordResetDeliveryChannels.IsSupported(payload.deliveryChannel))
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(RequestPasswordResetRequest.deliveryChannel),
                $"deliveryChannel must be {PasswordResetDeliveryChannels.SupportedDeliveryChannelsDescription}."));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(AcceptedResponse(Guid.Empty), errors);
    }

    private static ApiOutcome<VerifyPasswordResetTokenResponse>? ValidateVerify(VerifyPasswordResetTokenRequest? payload)
    {
        var body = FailedVerifyResponse();
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        payload.keyCode = payload.keyCode?.Trim() ?? string.Empty;

        var errors = new List<ApiValidationError>();
        if (payload.resetId == Guid.Empty)
        {
            errors.Add(ApiResponses.ValidationError(nameof(VerifyPasswordResetTokenRequest.resetId), "resetId is required."));
        }

        if (string.IsNullOrWhiteSpace(payload.keyCode))
        {
            errors.Add(ApiResponses.ValidationError(nameof(VerifyPasswordResetTokenRequest.keyCode), "keyCode is required."));
        }
        else if (payload.keyCode.Length > VerifyPasswordResetTokenRequest.MaxKeyCodeLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(VerifyPasswordResetTokenRequest.keyCode),
                $"keyCode must be no longer than {VerifyPasswordResetTokenRequest.MaxKeyCodeLength} characters."));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    private static ApiOutcome<SelectPasswordResetTwoFactorConfigurationResponse>? ValidateSelectTwoFactorConfiguration(SelectPasswordResetTwoFactorConfigurationRequest? payload)
    {
        var body = FailedSelectResponse();
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        payload.resetAccessToken = payload.resetAccessToken?.Trim() ?? string.Empty;

        var errors = new List<ApiValidationError>();
        if (string.IsNullOrWhiteSpace(payload.resetAccessToken))
        {
            errors.Add(ApiResponses.ValidationError(nameof(SelectPasswordResetTwoFactorConfigurationRequest.resetAccessToken), "resetAccessToken is required."));
        }
        else if (payload.resetAccessToken.Length > SelectPasswordResetTwoFactorConfigurationRequest.MaxResetAccessTokenLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(SelectPasswordResetTwoFactorConfigurationRequest.resetAccessToken),
                $"resetAccessToken must be no longer than {SelectPasswordResetTwoFactorConfigurationRequest.MaxResetAccessTokenLength} characters."));
        }

        if (payload.configuration is TwoFactorAuthConfiguration.NONE or TwoFactorAuthConfiguration.CUSTOM)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(SelectPasswordResetTwoFactorConfigurationRequest.configuration),
                "A selectable two-factor configuration is required."));
        }

        if (payload.destination.HasValue && payload.destination.Value < 0)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(SelectPasswordResetTwoFactorConfigurationRequest.destination),
                "destination must be zero or greater when provided."));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }


    private static ApiOutcome<VerifyPasswordResetTwoFactorResponse>? ValidateVerifyTwoFactorProof(VerifyPasswordResetTwoFactorRequest? payload)
    {
        var body = FailedVerifyTwoFactorResponse();
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        payload.resetAccessToken = payload.resetAccessToken?.Trim() ?? string.Empty;
        payload.code = payload.code?.Trim() ?? string.Empty;

        var errors = new List<ApiValidationError>();
        if (string.IsNullOrWhiteSpace(payload.resetAccessToken))
        {
            errors.Add(ApiResponses.ValidationError(nameof(VerifyPasswordResetTwoFactorRequest.resetAccessToken), "resetAccessToken is required."));
        }
        else if (payload.resetAccessToken.Length > VerifyPasswordResetTwoFactorRequest.MaxResetAccessTokenLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(VerifyPasswordResetTwoFactorRequest.resetAccessToken),
                $"resetAccessToken must be no longer than {VerifyPasswordResetTwoFactorRequest.MaxResetAccessTokenLength} characters."));
        }

        if (payload.method == TwoFactorAuthMethod.NONE)
        {
            errors.Add(ApiResponses.ValidationError(nameof(VerifyPasswordResetTwoFactorRequest.method), "method is required."));
        }

        if (string.IsNullOrWhiteSpace(payload.code))
        {
            errors.Add(ApiResponses.ValidationError(nameof(VerifyPasswordResetTwoFactorRequest.code), "code is required."));
        }
        else if (payload.code.Length > VerifyPasswordResetTwoFactorRequest.MaxCodeLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(VerifyPasswordResetTwoFactorRequest.code),
                $"code must be no longer than {VerifyPasswordResetTwoFactorRequest.MaxCodeLength} characters."));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    private static ApiOutcome<FinalizePasswordResetResponse>? ValidateFinalize(FinalizePasswordResetRequest? payload)
    {
        var body = new FinalizePasswordResetResponse("failed");
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        payload.keyCode = string.IsNullOrWhiteSpace(payload.keyCode) ? null : payload.keyCode.Trim();
        payload.totpCode = string.IsNullOrWhiteSpace(payload.totpCode) ? null : payload.totpCode.Trim();
        payload.resetAccessToken = string.IsNullOrWhiteSpace(payload.resetAccessToken) ? null : payload.resetAccessToken.Trim();
        payload.password ??= string.Empty;
        payload.verifyPassword ??= string.Empty;

        bool hasResetAccessToken = payload.resetAccessToken is not null;

        var errors = new List<ApiValidationError>();
        if (!hasResetAccessToken && payload.resetId == Guid.Empty)
        {
            errors.Add(ApiResponses.ValidationError(nameof(FinalizePasswordResetRequest.resetId), "resetId is required when resetAccessToken is not provided."));
        }

        if (!hasResetAccessToken && payload.keyCode is null && payload.totpCode is null)
        {
            errors.Add(ApiResponses.ValidationError(
                string.Empty,
                "resetAccessToken, keyCode, or totpCode is required."));
        }

        if (payload.keyCode?.Length > FinalizePasswordResetRequest.MaxKeyCodeLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(FinalizePasswordResetRequest.keyCode),
                $"keyCode must be no longer than {FinalizePasswordResetRequest.MaxKeyCodeLength} characters."));
        }

        if (payload.totpCode?.Length > FinalizePasswordResetRequest.MaxTotpCodeLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(FinalizePasswordResetRequest.totpCode),
                $"totpCode must be no longer than {FinalizePasswordResetRequest.MaxTotpCodeLength} characters."));
        }

        if (payload.resetAccessToken?.Length > FinalizePasswordResetRequest.MaxResetAccessTokenLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(FinalizePasswordResetRequest.resetAccessToken),
                $"resetAccessToken must be no longer than {FinalizePasswordResetRequest.MaxResetAccessTokenLength} characters."));
        }

        if (string.IsNullOrWhiteSpace(payload.password))
        {
            errors.Add(ApiResponses.ValidationError(nameof(FinalizePasswordResetRequest.password), "password is required."));
        }
        else if (payload.password.Length > FinalizePasswordResetRequest.MaxPasswordLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(FinalizePasswordResetRequest.password),
                $"password must be no longer than {FinalizePasswordResetRequest.MaxPasswordLength} characters."));
        }

        if (string.IsNullOrWhiteSpace(payload.verifyPassword))
        {
            errors.Add(ApiResponses.ValidationError(nameof(FinalizePasswordResetRequest.verifyPassword), "verifyPassword is required."));
        }
        else if (payload.verifyPassword.Length > FinalizePasswordResetRequest.MaxPasswordLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(FinalizePasswordResetRequest.verifyPassword),
                $"verifyPassword must be no longer than {FinalizePasswordResetRequest.MaxPasswordLength} characters."));
        }

        if (!string.IsNullOrWhiteSpace(payload.password)
            && !string.IsNullOrWhiteSpace(payload.verifyPassword)
            && !string.Equals(payload.password, payload.verifyPassword, StringComparison.Ordinal))
        {
            errors.Add(ApiResponses.ValidationError(nameof(FinalizePasswordResetRequest.verifyPassword), "verifyPassword must match password."));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    private static VerifyPasswordResetTokenResponse FailedVerifyResponse()
    {
        return new VerifyPasswordResetTokenResponse("failed", null, false, [], null);
    }

    private static SelectPasswordResetTwoFactorConfigurationResponse FailedSelectResponse()
    {
        return new SelectPasswordResetTwoFactorConfigurationResponse("failed", null, null, null, null, [], [], [], null, false);
    }

    private static VerifyPasswordResetTwoFactorResponse FailedVerifyTwoFactorResponse()
    {
        return new VerifyPasswordResetTwoFactorResponse("failed", null, null, null, [], [], null, false);
    }

    private static PasswordResetRequestResponse AcceptedResponse(Guid resetId)
    {
        return new PasswordResetRequestResponse("accepted", resetId, PasswordResetRequestResponse.GenericAcceptedMessage);
    }

    private static string StatusFromCode(string code)
    {
        return code switch
        {
            PasswordResetService.CompletedCode => "completed",
            PasswordResetService.TwoFactorRequiredCode => "two_factor_required",
            PasswordResetService.TwoFactorNotCompleteCode => "two_factor_not_complete",
            PasswordResetService.SessionExpiredCode => "expired",
            _ => "failed"
        };
    }

    private ActionResult<ApiResponse<T>> ToActionResult<T>(ApiOutcome<T> outcome)
    {
        return ApiResponses.FromOutcome(this, outcome);
    }
}
