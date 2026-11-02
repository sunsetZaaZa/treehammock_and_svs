using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NodaTime;

using treehammock.Models.Api;
using treehammock.Models.Recovery;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Rigging.Abuse;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;

namespace treehammock.Controllers;

[ApiController]
[AllowAnonymous]
[Route("account/unlock")]
[Produces("application/json")]
public class AccountRecoveryController : ControllerBase
{
    private const string RequestBodyRequiredMessage = "The request body is required.";

    private readonly IAccountRecoveryService _accountRecoveryService;

    public AccountRecoveryController(IAccountRecoveryService accountRecoveryService)
    {
        _accountRecoveryService = accountRecoveryService;
    }

    [HttpPost("start")]
    [ProducesResponseType(typeof(ApiResponse<AccountRecoveryResponse>), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ApiResponse<AccountRecoveryResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountRecoveryResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<AccountRecoveryResponse>>> StartRecovery([FromBody] AccountRecoveryRequest? payload)
    {
        var validation = ValidateStartRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        AccountRecoveryStartResult result = await _accountRecoveryService.StartRecovery(
            payload!,
            SystemClock.Instance.GetCurrentInstant(), cancellationToken: HttpContext.RequestAborted);

        return ToActionResult(new ApiOutcome<AccountRecoveryResponse>(
            new AccountRecoveryResponse(RecoveryMessage(result.Code)),
            RecoveryStatusCode(result.Code, successStatusCode: StatusCodes.Status202Accepted),
            result.Code));
    }

    [HttpPost("verify")]
    [ProducesResponseType(typeof(ApiResponse<AccountRecoveryResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AccountRecoveryResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountRecoveryResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<AccountRecoveryResponse>), StatusCodes.Status503ServiceUnavailable)]
    [ProducesResponseType(typeof(ApiResponse<AccountRecoveryResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<AccountRecoveryResponse>>> VerifyRecovery([FromBody] AccountRecoveryVerifyRequest? payload)
    {
        var validation = ValidateVerifyRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        AccountRecoveryVerifyResult result = await _accountRecoveryService.VerifyRecovery(payload!, cancellationToken: HttpContext.RequestAborted);

        return ToActionResult(new ApiOutcome<AccountRecoveryResponse>(
            new AccountRecoveryResponse(RecoveryMessage(result.Code)),
            RecoveryStatusCode(result.Code, successStatusCode: StatusCodes.Status200OK),
            result.Code));
    }

    private static ApiOutcome<AccountRecoveryResponse>? ValidateStartRequest(AccountRecoveryRequest? payload)
    {
        var body = new AccountRecoveryResponse(HttpMessage.ACCOUNT_UNLOCK_FAILED);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        payload.identifier = payload.identifier?.Trim() ?? string.Empty;

        var errors = new List<ApiValidationError>();
        if (string.IsNullOrWhiteSpace(payload.identifier))
        {
            errors.Add(ApiResponses.ValidationError(nameof(AccountRecoveryRequest.identifier), "identifier is required."));
        }
        else if (payload.identifier.Length > AccountRecoveryRequest.MaxIdentifierLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(AccountRecoveryRequest.identifier),
                $"identifier must be no longer than {AccountRecoveryRequest.MaxIdentifierLength} characters."));
        }

        if (!Enum.IsDefined(typeof(AccountUnlockDeliveryMethod), payload.deliveryMethod))
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(AccountRecoveryRequest.deliveryMethod),
                "deliveryMethod must be EMAIL or SMS."));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    private static ApiOutcome<AccountRecoveryResponse>? ValidateVerifyRequest(AccountRecoveryVerifyRequest? payload)
    {
        var body = new AccountRecoveryResponse(HttpMessage.ACCOUNT_UNLOCK_FAILED);
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(body, string.Empty, RequestBodyRequiredMessage);
        }

        payload.token = payload.token?.Trim() ?? string.Empty;

        var errors = new List<ApiValidationError>();
        if (string.IsNullOrWhiteSpace(payload.token))
        {
            errors.Add(ApiResponses.ValidationError(nameof(AccountRecoveryVerifyRequest.token), "token is required."));
        }
        else if (payload.token.Length > AccountRecoveryVerifyRequest.MaxTokenLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(AccountRecoveryVerifyRequest.token),
                $"token must be no longer than {AccountRecoveryVerifyRequest.MaxTokenLength} characters."));
        }

        return errors.Count == 0 ? null : ApiResponses.InvalidPayload(body, errors);
    }

    private ActionResult<ApiResponse<T>> ToActionResult<T>(ApiOutcome<T> outcome)
    {
        return ApiResponses.FromOutcome(this, outcome);
    }

    private static int RecoveryStatusCode(string code, int successStatusCode)
    {
        return code switch
        {
            AccountRecoveryService.PendingCode => StatusCodes.Status202Accepted,
            AccountRecoveryService.VerifiedCode => successStatusCode,
            AccountRecoveryService.TokenExpiredCode
                or AccountRecoveryService.TokenMismatchCode
                or AccountRecoveryService.NotLockedCode => StatusCodes.Status400BadRequest,
            AbuseReasonCodes.AccountUnlockVerifyAttemptsExceeded => StatusCodes.Status429TooManyRequests,
            AbuseReasonCodes.CounterStoreUnavailable
                or AbuseReasonCodes.CounterStoreTimeout => StatusCodes.Status503ServiceUnavailable,
            _ => StatusCodes.Status500InternalServerError
        };
    }

    private static HttpMessage RecoveryMessage(string code)
    {
        return code switch
        {
            AccountRecoveryService.PendingCode => HttpMessage.ACCOUNT_UNLOCK_PENDING,
            AccountRecoveryService.VerifiedCode => HttpMessage.ACCOUNT_UNLOCK_VERIFIED,
            AccountRecoveryService.TokenExpiredCode => HttpMessage.ACCOUNT_UNLOCK_TOKEN_EXPIRED,
            AccountRecoveryService.TokenMismatchCode => HttpMessage.ACCOUNT_UNLOCK_TOKEN_MISMATCH,
            AccountRecoveryService.NotLockedCode => HttpMessage.ACCOUNT_UNLOCK_NOT_LOCKED,
            _ => HttpMessage.ACCOUNT_UNLOCK_FAILED
        };
    }
}
