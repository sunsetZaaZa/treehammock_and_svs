using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Shouldly;

using treehammock.Models.Api;

namespace treehammock.Tests.Unit;

public class ApiResponsesTests
{
    [Fact]
    public void FromOutcome_wraps_success_response()
    {
        var controller = new TestController();
        var body = new TestBody("ready");
        var outcome = new ApiOutcome<TestBody>(body, StatusCodes.Status200OK, "OK");

        var actionResult = ApiResponses.FromOutcome(controller, outcome);

        var objectResult = actionResult.Result.ShouldBeOfType<ObjectResult>();
        objectResult.StatusCode.ShouldBe(StatusCodes.Status200OK);
        var envelope = objectResult.Value.ShouldBeOfType<ApiResponse<TestBody>>();
        envelope.success.ShouldBeTrue();
        envelope.statusCode.ShouldBe(StatusCodes.Status200OK);
        envelope.code.ShouldBe("OK");
        envelope.data.ShouldBe(body);
        envelope.errors.ShouldBeNull();
    }

    [Fact]
    public void FromOutcome_wraps_failure_response()
    {
        var controller = new TestController();
        var body = new TestBody("failed");
        var outcome = new ApiOutcome<TestBody>(body, StatusCodes.Status500InternalServerError, "SERVER_FAILURE");

        var actionResult = ApiResponses.FromOutcome(controller, outcome);

        var objectResult = actionResult.Result.ShouldBeOfType<ObjectResult>();
        objectResult.StatusCode.ShouldBe(StatusCodes.Status500InternalServerError);
        var envelope = objectResult.Value.ShouldBeOfType<ApiResponse<TestBody>>();
        envelope.success.ShouldBeFalse();
        envelope.statusCode.ShouldBe(StatusCodes.Status500InternalServerError);
        envelope.code.ShouldBe("SERVER_FAILURE");
        envelope.data.ShouldBe(body);
    }


    [Fact]
    public void InvalidPayload_with_field_message_returns_validation_failed_outcome_with_error()
    {
        var body = new TestBody("invalid");

        var outcome = ApiResponses.InvalidPayload(body, "password", "password is invalid.");

        outcome.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        outcome.Code.ShouldBe(ApiResponses.ValidationFailedCode);
        outcome.Body.ShouldBe(body);
        outcome.Errors.ShouldNotBeNull();
        outcome.Errors!.Single().field.ShouldBe("password");
        outcome.Errors!.Single().messages.ShouldContain("password is invalid.");
    }

    [Fact]
    public void InvalidPayload_with_null_errors_returns_default_validation_error()
    {
        var body = new TestBody("invalid");

        var outcome = ApiResponses.InvalidPayload(body, (IReadOnlyList<ApiValidationError>?)null);

        outcome.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        outcome.Code.ShouldBe(ApiResponses.ValidationFailedCode);
        outcome.Errors.ShouldNotBeNull();
        outcome.Errors!.Count.ShouldBe(1);
        outcome.Errors.Single().field.ShouldBe(string.Empty);
        outcome.Errors.Single().messages.ShouldContain("The request payload is invalid.");
    }

    [Fact]
    public void InvalidPayload_with_empty_errors_returns_default_validation_error()
    {
        var body = new TestBody("invalid");

        var outcome = ApiResponses.InvalidPayload(body, Array.Empty<ApiValidationError>());

        outcome.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        outcome.Code.ShouldBe(ApiResponses.ValidationFailedCode);
        outcome.Errors.ShouldNotBeNull();
        outcome.Errors!.Count.ShouldBe(1);
        outcome.Errors.Single().field.ShouldBe(string.Empty);
        outcome.Errors.Single().messages.ShouldContain("The request payload is invalid.");
    }

    [Fact]
    public void InvalidPayload_with_populated_errors_preserves_errors()
    {
        var body = new TestBody("invalid");
        var errors = new[]
        {
            ApiResponses.ValidationError("username", "username is invalid."),
            ApiResponses.ValidationError("password", "password is invalid.")
        };

        var outcome = ApiResponses.InvalidPayload(body, errors);

        outcome.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        outcome.Code.ShouldBe(ApiResponses.ValidationFailedCode);
        outcome.Errors.ShouldNotBeNull();
        outcome.Errors.ShouldBe(errors);
        outcome.Errors!.Count.ShouldBe(2);
    }

    [Fact]
    public void FromOutcome_preserves_validation_errors_on_failure_envelope()
    {
        var controller = new TestController();
        var body = new TestBody("invalid");
        var errors = new[] { ApiResponses.ValidationError("emailAddress", "emailAddress is invalid.") };
        var outcome = ApiResponses.InvalidPayload(body, errors);

        var actionResult = ApiResponses.FromOutcome(controller, outcome);

        var objectResult = actionResult.Result.ShouldBeOfType<ObjectResult>();
        objectResult.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        var envelope = objectResult.Value.ShouldBeOfType<ApiResponse<TestBody>>();
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.Single().field.ShouldBe("emailAddress");
    }

    [Fact]
    public void FromOutcome_with_validation_failed_and_no_errors_returns_default_validation_error()
    {
        var controller = new TestController();
        var body = new TestBody("invalid");
        var outcome = new ApiOutcome<TestBody>(
            body,
            StatusCodes.Status400BadRequest,
            ApiResponses.ValidationFailedCode);

        var actionResult = ApiResponses.FromOutcome(controller, outcome);

        var objectResult = actionResult.Result.ShouldBeOfType<ObjectResult>();
        objectResult.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        var envelope = objectResult.Value.ShouldBeOfType<ApiResponse<TestBody>>();
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.Count.ShouldBe(1);
        envelope.errors.Single().field.ShouldBe(string.Empty);
        envelope.errors.Single().messages.ShouldContain("The request payload is invalid.");
    }

    [Fact]
    public void JsonFailure_with_validation_failed_and_empty_errors_returns_default_validation_error()
    {
        var body = new TestBody("invalid");

        var result = ApiResponses.JsonFailure(
            StatusCodes.Status400BadRequest,
            ApiResponses.ValidationFailedCode,
            body,
            Array.Empty<ApiValidationError>());

        result.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        var envelope = result.Value.ShouldBeOfType<ApiResponse<TestBody>>();
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.Count.ShouldBe(1);
        envelope.errors.Single().field.ShouldBe(string.Empty);
        envelope.errors.Single().messages.ShouldContain("The request payload is invalid.");
    }

    [Fact]
    public void Unauthorized_wraps_custom_auth_failure_response()
    {
        var result = ApiResponses.Unauthorized("AUTHENTICATION_FAILED", new { result = "AUTHENTICATION_FAILED" });

        result.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        var envelope = result.Value.ShouldBeOfType<ApiResponse<object>>();
        envelope.success.ShouldBeFalse();
        envelope.statusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        envelope.code.ShouldBe("AUTHENTICATION_FAILED");
        envelope.data.ShouldNotBeNull();
    }

    [Fact]
    public void InvalidModelState_wraps_validation_errors_in_standard_envelope()
    {
        var modelState = new ModelStateDictionary();
        modelState.AddModelError("emailAddress", "The emailAddress field is required.");
        modelState.AddModelError("password", string.Empty);

        var result = ApiResponses.InvalidModelState(modelState);

        result.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        var envelope = result.Value.ShouldBeOfType<ApiResponse<object>>();
        envelope.success.ShouldBeFalse();
        envelope.statusCode.ShouldBe(StatusCodes.Status400BadRequest);
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.Count.ShouldBe(2);
        envelope.errors.ShouldContain(error => error.field == "emailAddress" && error.messages.Contains("The emailAddress field is required."));
        envelope.errors.ShouldContain(error => error.field == "password" && error.messages.Contains("The request payload is invalid."));
    }

    [Fact]
    public void InvalidModelState_with_no_errors_returns_default_validation_error()
    {
        var modelState = new ModelStateDictionary();

        var result = ApiResponses.InvalidModelState(modelState);

        result.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        var envelope = result.Value.ShouldBeOfType<ApiResponse<object>>();
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.Count.ShouldBe(1);
        envelope.errors.Single().field.ShouldBe(string.Empty);
        envelope.errors.Single().messages.ShouldContain("The request payload is invalid.");
    }

    private sealed record TestBody(string Value);

    private sealed class TestController : ControllerBase
    {
    }
}
