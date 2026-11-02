using System.ComponentModel.DataAnnotations;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NodaTime;

using treehammock.DataLayer.Cache;
using treehammock.Models.Activation;
using treehammock.Models.Api;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Replay;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;

namespace treehammock.Controllers;

[Authenticate]
[ApiController]
[Route("activations")]
[Produces("application/json")]
public class ActivationsController : ControllerBase
{
    private const string RequestBodyRequiredMessage = "The request body is required.";
    private const string AuthenticationFailedCode = "AUTHENTICATION_FAILED";

    private readonly IActivationService _activationService;
    private readonly IAuthenticatedMutationIdempotencyService _authenticatedMutationIdempotencyService;
    private readonly EmailAddressAttribute _emailValidator = new();

    public ActivationsController(
        IActivationService activationService,
        IAuthenticatedMutationIdempotencyService? authenticatedMutationIdempotencyService = null)
    {
        _activationService = activationService;
        _authenticatedMutationIdempotencyService = authenticatedMutationIdempotencyService ?? NoOpAuthenticatedMutationIdempotencyService.Instance;
    }

    [HttpPost("place")]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<ActivationCreationResponse>>> PlaceActivation([FromBody] ActivationCreationRequest? payload)
    {
        var validation = ValidateCreationRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<ActivationCreationResponse>(
                new ActivationCreationResponse(Pass.UNAUTHORIZED),
                StatusCodes.Status401Unauthorized,
                AuthenticationFailedCode));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "activations/place", requireKey: true, payload: payload);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new ActivationCreationResponse(Pass.FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome<ActivationCreationResponse>(idempotency);
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        ActivationCreateResult result = await _activationService.PlaceActivation(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload!,
            SystemClock.Instance.GetCurrentInstant(), cancellationToken: HttpContext.RequestAborted);

        int? retrySeconds = result.RetryAfter is { } retry ? (int)Math.Clamp(Math.Ceiling(retry.TotalSeconds), 1, 86400) : null;
        if (retrySeconds is int seconds) Response.Headers["Retry-After"] = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var outcome = new ApiOutcome<ActivationCreationResponse>(
            new ActivationCreationResponse(result.Result ? Pass.SUCCESSFUL : ActivationPass(result.Code)) { grantId=payload!.grantId,grantVersion=payload.grantVersion,requestId=result.RequestId,retryAfterSeconds=retrySeconds,lifecycle=result.Result ? "queued" : "denied" },
            ActivationStatusCode(result.Code, successStatusCode: StatusCodes.Status202Accepted),
            result.Code);
        await CompleteAuthenticatedMutationIdempotency(idempotency, outcome);

        return ToActionResult(outcome);
    }

    [HttpPost("verify")]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status410Gone)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status503ServiceUnavailable)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<ActivationDetailsResponse>>> VerifyActivation([FromBody] ActivationDetailsRequest? payload)
    {
        var validation = ValidateDetailsRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<ActivationDetailsResponse>(
                EmptyDetails(Pass.UNAUTHORIZED),
                StatusCodes.Status401Unauthorized,
                AuthenticationFailedCode));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "activations/verify", requireKey: true, payload: payload);
        var blocked = IdempotencyBlockingOutcome(idempotency, EmptyDetails(Pass.FAILED));
        if (blocked != null) return ToActionResult(blocked);
        var replay = IdempotencyReplayOutcome<ActivationDetailsResponse>(idempotency);
        if (replay != null) return ToActionResult(replay);

        ActivationVerifyResult result = await _activationService.VerifyActivation(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload!,
            SystemClock.Instance.GetCurrentInstant(), cancellationToken: HttpContext.RequestAborted);

        ActivationDetailsResponse response = result.Result && result.Activation is not null
            ? new ActivationDetailsResponse(
                Pass.SUCCESSFUL,
                result.Activation.expiration.ToString(),
                (uint)result.Activation.duration,
                (uint)result.Activation.featureSet)
            : EmptyDetails(result.Result ? Pass.SUCCESSFUL : ActivationPass(result.Code));

        if (result.Result && result.Entitlement is { } entitlement)
        {
            response.startsAt = entitlement.StartsAt;
            response.eligibilityUntil = entitlement.EligibilityUntil;
            response.off = entitlement.EligibilityUntil?.ToString() ?? string.Empty;
            response.term = (uint)(entitlement.Term ?? 0);
            response.featureSet = (uint)(entitlement.Tier ?? 0);
            response.entitlements = entitlement.Entitlements;
            response.rightsEnabled = entitlement.Entitlements?.RightsEnabled ?? false;
        }
        response.grantId=payload!.grantId; response.grantVersion=result.Result ? payload.grantVersion+1 : payload.grantVersion;
        response.lifecycle=result.Result ? "active" : "denied";
        var outcome = new ApiOutcome<ActivationDetailsResponse>(
            response,
            ActivationStatusCode(result.Code, successStatusCode: StatusCodes.Status200OK),
            result.Code);
        await CompleteAuthenticatedMutationIdempotency(idempotency, outcome);
        return ToActionResult(outcome);
    }

    [HttpPost("disable")]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status410Gone)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<ActivationUnSubscribeResponse>>> DisableActivation([FromBody] ActivationUnSubscribeRequest? payload)
    {
        var validation = ValidateUnSubscribeRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<ActivationUnSubscribeResponse>(
                new ActivationUnSubscribeResponse(Pass.UNAUTHORIZED),
                StatusCodes.Status401Unauthorized,
                AuthenticationFailedCode));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "activations/disable", requireKey: true, payload: payload);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new ActivationUnSubscribeResponse(Pass.FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome<ActivationUnSubscribeResponse>(idempotency);
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        ActivationDisableResult result = await _activationService.DisableActivation(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload!,
            SystemClock.Instance.GetCurrentInstant(), cancellationToken: HttpContext.RequestAborted);

        var outcome = new ApiOutcome<ActivationUnSubscribeResponse>(
            new ActivationUnSubscribeResponse(result.Result ? Pass.SUCCESSFUL : ActivationPass(result.Code)) { grantId=payload!.grantId,grantVersion=result.Result ? payload.grantVersion+1 : payload.grantVersion,lifecycle=result.Result ? "revoked" : "denied" },
            ActivationStatusCode(result.Code, successStatusCode: StatusCodes.Status200OK),
            result.Code);
        await CompleteAuthenticatedMutationIdempotency(idempotency, outcome);

        return ToActionResult(outcome);
    }

    [HttpPost("cancel")]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status410Gone)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<ActivationUnSubscribeResponse>>> CancelActivation([FromBody] ActivationUnSubscribeRequest? payload)
    {
        if (payload is not null && payload.requestId == Guid.Empty)
            return ToActionResult(ApiResponses.InvalidPayload(new ActivationUnSubscribeResponse(Pass.INVALID),"requestId","The pending request ID is required."));
        var validation = ValidateUnSubscribeRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<ActivationUnSubscribeResponse>(
                new ActivationUnSubscribeResponse(Pass.UNAUTHORIZED),
                StatusCodes.Status401Unauthorized,
                AuthenticationFailedCode));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "activations/cancel", requireKey: true, payload: payload);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new ActivationUnSubscribeResponse(Pass.FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome<ActivationUnSubscribeResponse>(idempotency);
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        ActivationDisableResult result = await _activationService.CancelActivation(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload!,
            SystemClock.Instance.GetCurrentInstant(), cancellationToken: HttpContext.RequestAborted);

        var outcome = new ApiOutcome<ActivationUnSubscribeResponse>(
            new ActivationUnSubscribeResponse(result.Result ? Pass.SUCCESSFUL : ActivationPass(result.Code)) { grantId=payload!.grantId,grantVersion=result.Result ? payload.grantVersion+1 : payload.grantVersion,lifecycle=result.Result ? "revoked" : "denied" },
            ActivationStatusCode(result.Code, successStatusCode: StatusCodes.Status200OK),
            result.Code);
        await CompleteAuthenticatedMutationIdempotency(idempotency, outcome);

        return ToActionResult(outcome);
    }

    private ApiOutcome<ActivationCreationResponse>? ValidateCreationRequest(ActivationCreationRequest? payload)
    {
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(
                new ActivationCreationResponse(Pass.INVALID),
                string.Empty,
                RequestBodyRequiredMessage);
        }

        payload.emailAddress = payload.emailAddress?.Trim() ?? string.Empty;

        var errors = new List<ApiValidationError>();
        if (payload.version != 2 || payload.grantId == Guid.Empty || payload.grantVersion < 1)
            errors.Add(ApiResponses.ValidationError("grantId", "Version 2 requires a trusted grant ID and expected version."));

        AddEmailValidation(
            errors,
            payload.emailAddress,
            nameof(ActivationCreationRequest.emailAddress),
            ActivationCreationRequest.MaxEmailAddressLength);

        if (!Enum.IsDefined(typeof(FeatureSet), (int)payload.featureSet))
        {
            errors.Add(ApiResponses.ValidationError(nameof(ActivationCreationRequest.featureSet), "A supported featureSet is required."));
        }

        if (!Enum.IsDefined(typeof(DayDuration), payload.term))
        {
            errors.Add(ApiResponses.ValidationError(nameof(ActivationCreationRequest.term), "A supported term is required."));
        }

        if (!Enum.IsDefined(typeof(DurationRepeat), payload.recycle))
        {
            errors.Add(ApiResponses.ValidationError(nameof(ActivationCreationRequest.recycle), "A supported recycle value is required."));
        }

        return errors.Count == 0
            ? null
            : ApiResponses.InvalidPayload(new ActivationCreationResponse(Pass.INVALID), errors);
    }

    private ApiOutcome<ActivationDetailsResponse>? ValidateDetailsRequest(ActivationDetailsRequest? payload)
    {
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(
                EmptyDetails(Pass.INVALID),
                string.Empty,
                RequestBodyRequiredMessage);
        }

        payload.emailAddress = payload.emailAddress?.Trim() ?? string.Empty;
        payload.code = payload.code?.Trim() ?? string.Empty;

        var errors = new List<ApiValidationError>();
        AddEmailValidation(
            errors,
            payload.emailAddress,
            nameof(ActivationDetailsRequest.emailAddress),
            ActivationDetailsRequest.MaxEmailAddressLength);

        if (string.IsNullOrWhiteSpace(payload.code))
        {
            errors.Add(ApiResponses.ValidationError(nameof(ActivationDetailsRequest.code), "code is required."));
        }
        else if (payload.code.Length > ActivationDetailsRequest.MaxCodeLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(ActivationDetailsRequest.code),
                $"code must be no longer than {ActivationDetailsRequest.MaxCodeLength} characters."));
        }

        return errors.Count == 0
            ? null
            : ApiResponses.InvalidPayload(EmptyDetails(Pass.INVALID), errors);
    }

    private ApiOutcome<ActivationUnSubscribeResponse>? ValidateUnSubscribeRequest(ActivationUnSubscribeRequest? payload)
    {
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(
                new ActivationUnSubscribeResponse(Pass.INVALID),
                string.Empty,
                RequestBodyRequiredMessage);
        }

        payload.emailAddress = payload.emailAddress?.Trim() ?? string.Empty;

        var errors = new List<ApiValidationError>();
        AddEmailValidation(
            errors,
            payload.emailAddress,
            nameof(ActivationUnSubscribeRequest.emailAddress),
            ActivationUnSubscribeRequest.MaxEmailAddressLength);

        return errors.Count == 0
            ? null
            : ApiResponses.InvalidPayload(new ActivationUnSubscribeResponse(Pass.INVALID), errors);
    }

    private void AddEmailValidation(List<ApiValidationError> errors, string? emailAddress, string fieldName, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(emailAddress))
        {
            errors.Add(ApiResponses.ValidationError(fieldName, "emailAddress is required."));
        }
        else if (emailAddress.Length > maxLength)
        {
            errors.Add(ApiResponses.ValidationError(fieldName, $"emailAddress must be no longer than {maxLength} characters."));
        }
        else if (!_emailValidator.IsValid(emailAddress))
        {
            errors.Add(ApiResponses.ValidationError(fieldName, "emailAddress must be a valid email address."));
        }
    }

    private bool TryGetAuthenticatedSession(out ActiveSession activeSession)
    {
        if (HttpContext.Items[AuthContextItems.ActiveSession] is ActiveSession session)
        {
            activeSession = session;
            return true;
        }

        activeSession = default!;
        return false;
    }

    private ActionResult<ApiResponse<T>> ToActionResult<T>(ApiOutcome<T> outcome)
    {
        return ApiResponses.FromOutcome(this, outcome);
    }

    private async Task<AuthenticatedMutationIdempotencyBeginResult> BeginAuthenticatedMutationIdempotency(
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

    private async Task CompleteAuthenticatedMutationIdempotency<T>(
        AuthenticatedMutationIdempotencyBeginResult idempotency, ApiOutcome<T> outcome)
    {
        if (idempotency.Reservation is null) return;
        await _authenticatedMutationIdempotencyService.CompleteStoredAsync(idempotency.Reservation,
            AuthenticatedMutationSafeResult.Capture(outcome, Response.Headers["AppStatus"].FirstOrDefault()),
            HttpContext.RequestAborted);
    }

    private static ApiOutcome<T>? IdempotencyBlockingOutcome<T>(
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

    private ApiOutcome<T>? IdempotencyReplayOutcome<T>(AuthenticatedMutationIdempotencyBeginResult idempotency)
    {
        if (idempotency.Status != AuthenticatedMutationIdempotencyStatus.ReplayCompleted || idempotency.StoredResult is null) return null;
        return AuthenticatedMutationSafeResult.Restore<T>(idempotency.StoredResult, Response);
    }

    private static ActivationDetailsResponse EmptyDetails(Pass result)
    {
        return new ActivationDetailsResponse(result, string.Empty, 0, 0);
    }

    private static Pass ActivationPass(string code)
    {
        return code switch
        {
            ActivationService.NotFoundCode => Pass.NOT_FOUND,
            ActivationService.SecurityStampMismatchCode => Pass.UNAUTHORIZED,
            ActivationService.InvalidCode or ActivationService.InvalidTermCode or ActivationService.InvalidRecycleCode or
                ActivationService.CodeMismatchCode or ActivationService.EmailMismatchCode => Pass.INVALID,
            ActivationService.ExpiredCode => Pass.INVALID,
            ActivationService.ConflictCode => Pass.FAILED,
            AbuseReasonCodes.ActivationVerifyAttemptsExceeded or AbuseReasonCodes.CounterStoreUnavailable or AbuseReasonCodes.CounterStoreTimeout => Pass.FAILED,
            ActivationService.FailedCode or ActivationService.EmailDeliveryFailedCode or ActivationService.CleanupFailedCode => Pass.FAILED,
            _ => Pass.FAILED
        };
    }

    private static int ActivationStatusCode(string code, int successStatusCode)
    {
        return code switch
        {
            ActivationService.CreatedCode or ActivationService.VerifiedCode or ActivationService.DisabledCode => successStatusCode,
            ActivationService.SecurityStampMismatchCode => StatusCodes.Status401Unauthorized,
            ActivationService.TrustedGrantRequiredCode or ActivationService.ApprovalMismatchCode => StatusCodes.Status403Forbidden,
            ActivationService.EmailMismatchCode or ActivationService.CodeMismatchCode or ActivationService.InvalidCode or
                ActivationService.InvalidTermCode or ActivationService.InvalidRecycleCode => StatusCodes.Status400BadRequest,
            ActivationService.NotFoundCode => StatusCodes.Status404NotFound,
            ActivationService.ExpiredCode => StatusCodes.Status410Gone,
            ActivationService.ConflictCode => StatusCodes.Status409Conflict,
            AbuseReasonCodes.ActivationVerifyAttemptsExceeded or ActivationService.CreationThrottledCode or
                ActivationService.PendingCode or AbuseReasonCodes.DeliveryThrottleExceeded or AbuseReasonCodes.FailureCooldownActive => StatusCodes.Status429TooManyRequests,
            ActivationService.AdmissionRequiredCode => StatusCodes.Status409Conflict,
            AbuseReasonCodes.CounterStoreUnavailable or AbuseReasonCodes.CounterStoreTimeout => StatusCodes.Status503ServiceUnavailable,
            ActivationService.EmailDeliveryFailedCode or ActivationService.CleanupFailedCode or ActivationService.FailedCode => StatusCodes.Status500InternalServerError,
            _ => StatusCodes.Status500InternalServerError
        };
    }
}
