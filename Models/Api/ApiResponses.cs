using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace treehammock.Models.Api;

public sealed record ApiOutcome<T>(T Body, int StatusCode, string Code, IReadOnlyList<ApiValidationError>? Errors = null);

public static class ApiResponses
{
    public const string ValidationFailedCode = "VALIDATION_FAILED";
    private const string InvalidPayloadMessage = "The request payload is invalid.";

    public static ActionResult<ApiResponse<T>> FromOutcome<T>(ControllerBase controller, ApiOutcome<T> outcome)
    {
        ArgumentNullException.ThrowIfNull(controller);
        ArgumentNullException.ThrowIfNull(outcome);

        var envelope = Build(outcome.StatusCode, outcome.Code, outcome.Body, outcome.Errors);
        return controller.StatusCode(outcome.StatusCode, envelope);
    }

    public static ApiOutcome<T> InvalidPayload<T>(T body, string field, string message)
    {
        return InvalidPayload(body, new[] { ValidationError(field, message) });
    }

    public static ApiOutcome<T> InvalidPayload<T>(T body, IReadOnlyList<ApiValidationError>? errors)
    {
        return new ApiOutcome<T>(
            body,
            StatusCodes.Status400BadRequest,
            ValidationFailedCode,
            NormalizeValidationErrors(errors));
    }

    public static ApiOutcome<T> InvalidPayload<T>(T body)
    {
        return new ApiOutcome<T>(
            body,
            StatusCodes.Status400BadRequest,
            ValidationFailedCode,
            DefaultValidationErrors());
    }

    public static ApiValidationError ValidationError(string field, string message)
    {
        return new ApiValidationError(
            field,
            new[] { string.IsNullOrWhiteSpace(message) ? InvalidPayloadMessage : message });
    }

    public static JsonResult Unauthorized(string code, object? data = null)
    {
        return JsonFailure(StatusCodes.Status401Unauthorized, code, data);
    }

    public static JsonResult JsonFailure<T>(int statusCode, string code, T? data = default, IReadOnlyList<ApiValidationError>? errors = null)
    {
        return new JsonResult(ApiResponse<T>.Failure(
            statusCode,
            code,
            data,
            NormalizeErrorsForFailure(statusCode, code, errors)))
        {
            StatusCode = statusCode
        };
    }

    public static BadRequestObjectResult InvalidModelState(ModelStateDictionary modelState)
    {
        ArgumentNullException.ThrowIfNull(modelState);

        var envelope = ApiResponse<object>.Failure(
            StatusCodes.Status400BadRequest,
            ValidationFailedCode,
            errors: ValidationErrorsFrom(modelState));

        return new BadRequestObjectResult(envelope);
    }

    public static IReadOnlyList<ApiValidationError> ValidationErrorsFrom(ModelStateDictionary modelState)
    {
        ArgumentNullException.ThrowIfNull(modelState);

        var errors = modelState
            .Where(entry => entry.Value?.Errors.Count > 0)
            .Select(entry => new ApiValidationError(
                NormalizeModelStateFieldName(entry.Key),
                entry.Value!.Errors
                    .Select(error => string.IsNullOrWhiteSpace(error.ErrorMessage)
                        ? InvalidPayloadMessage
                        : error.ErrorMessage)
                    .ToList()))
            .ToList();

        return NormalizeValidationErrors(errors);
    }

    private static string NormalizeModelStateFieldName(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return string.Empty;
        }

        string normalized = key.Trim();
        if (normalized.StartsWith("$.", StringComparison.Ordinal))
        {
            normalized = normalized[2..];
        }

        int lastDot = normalized.LastIndexOf('.');
        if (lastDot >= 0 && lastDot < normalized.Length - 1)
        {
            normalized = normalized[(lastDot + 1)..];
        }

        return normalized.TrimStart('$');
    }

    private static IReadOnlyList<ApiValidationError> NormalizeValidationErrors(IReadOnlyList<ApiValidationError>? errors)
    {
        if (errors is null || errors.Count == 0)
        {
            return DefaultValidationErrors();
        }

        return errors;
    }

    private static IReadOnlyList<ApiValidationError> DefaultValidationErrors()
    {
        return new[] { ValidationError(string.Empty, InvalidPayloadMessage) };
    }

    private static ApiResponse<T> Build<T>(int statusCode, string code, T? data = default, IReadOnlyList<ApiValidationError>? errors = null)
    {
        return IsSuccess(statusCode)
            ? ApiResponse<T>.Success(statusCode, code, data!)
            : ApiResponse<T>.Failure(statusCode, code, data, NormalizeErrorsForFailure(statusCode, code, errors));
    }

    private static IReadOnlyList<ApiValidationError>? NormalizeErrorsForFailure(
        int statusCode,
        string code,
        IReadOnlyList<ApiValidationError>? errors)
    {
        return statusCode == StatusCodes.Status400BadRequest
            && string.Equals(code, ValidationFailedCode, StringComparison.Ordinal)
            ? NormalizeValidationErrors(errors)
            : errors;
    }

    private static bool IsSuccess(int statusCode)
    {
        return statusCode >= StatusCodes.Status200OK && statusCode < StatusCodes.Status300MultipleChoices;
    }
}
