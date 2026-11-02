using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Shouldly;

using treehammock.Models.Api;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

public class ApiValidationEnvelopeTests
{
    [Fact]
    public async Task Missing_body_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/requestaccess",
            new StringContent(string.Empty, Encoding.UTF8, "application/json"));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode, dataField: "result", dataValue: HttpMessage.AUTHENTICATION_FAILED.ToString());
        AccountFailureAssertions.ValidationField(document, string.Empty);
    }

    [Fact]
    public async Task Malformed_json_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/requestaccess",
            new StringContent("{", Encoding.UTF8, "application/json"));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AccountFailureAssertions.ValidationErrors(document);
    }

    [Fact]
    public async Task Invalid_model_data_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/setupaccount",
            JsonContent("""
            {
              "emailAddress": "not-an-email",
              "password": "ValidPassword1!",
              "country": "USA"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AccountFailureAssertions.ValidationField(document, "emailAddress");
    }

    [Fact]
    public async Task None_two_factor_configuration_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/twofactor/select",
            JsonContent("""
            {
              "configuration": "NONE"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AccountFailureAssertions.ValidationField(document, "configuration");
    }


    [Fact]
    public async Task Negative_two_factor_destination_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/twofactor/select",
            JsonContent("""
            {
              "configuration": "EMAIL",
              "destination": -1
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AccountFailureAssertions.ValidationField(document, "destination");
    }

    [Fact]
    public async Task Empty_two_factor_code_key_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent("""
            {
              "method": "SMS_KEY",
              "codeKey": ""
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AccountFailureAssertions.ValidationField(document, "codeKey");
    }

    [Fact]
    public async Task Runtime_config_validation_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/requestaccess",
            JsonContent("""
            {
              "emailAddress": "reader@example.com",
              "password": "short"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode, dataField: "result", dataValue: HttpMessage.AUTHENTICATION_FAILED.ToString());
        AccountFailureAssertions.ValidationField(document, "password");
    }

    [Fact]
    public async Task Runtime_login_validation_rejects_supplied_short_username()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/requestaccess",
            JsonContent("""
            {
              "emailAddress": "reader@example.com",
              "username": "ab",
              "password": "ValidPassword1!"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode, dataField: "result", dataValue: HttpMessage.AUTHENTICATION_FAILED.ToString());
        AccountFailureAssertions.ValidationField(document, "username");
    }

    [Fact]
    public async Task Runtime_login_validation_rejects_supplied_invalid_email_even_with_valid_username()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/requestaccess",
            JsonContent("""
            {
              "emailAddress": "not-an-email",
              "username": "reader",
              "password": "ValidPassword1!"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AccountFailureAssertions.ValidationField(document, "emailAddress");
    }

    [Fact]
    public async Task Runtime_setup_validation_rejects_supplied_short_username()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/setupaccount",
            JsonContent("""
            {
              "emailAddress": "reader@example.com",
              "username": "ab",
              "password": "ValidPassword1!",
              "country": "USA"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode, dataField: "status", dataValue: HttpMessage.ACCOUNT_CREATION_FAILED.ToString());
        AccountFailureAssertions.ValidationField(document, "username");
    }

    [Fact]
    public async Task Runtime_setup_validation_rejects_country_none()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/setupaccount",
            JsonContent("""
            {
              "emailAddress": "reader@example.com",
              "password": "ValidPassword1!",
              "country": "NONE"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AccountFailureAssertions.ValidationField(document, "country");
    }

    [Fact]
    public async Task Runtime_setup_validation_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/setupaccount",
            JsonContent("""
            {
              "emailAddress": "reader@example.com",
              "password": "short",
              "country": "USA"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode, dataField: "status", dataValue: HttpMessage.ACCOUNT_CREATION_PASSWORD_REQUIREMENT.ToString());
        AccountFailureAssertions.ValidationField(document, "password");
    }

    [Fact]
    public async Task Custom_anonymous_requestaccess_reaches_model_validation_without_active_token()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/requestaccess",
            JsonContent("""
            {
              "password": "ValidPassword1!"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AccountFailureAssertions.ValidationErrors(document);
    }

    [Fact]
    public async Task Custom_anonymous_setupaccount_reaches_model_validation_without_active_token()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/setupaccount",
            JsonContent("""
            {
              "emailAddress": "not-an-email",
              "password": "ValidPassword1!",
              "country": "USA"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AccountFailureAssertions.ValidationField(document, "emailAddress");
    }

    [Fact]
    public async Task Unauthorized_protected_endpoint_returns_standard_auth_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.GetAsync("/account/view");

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status401Unauthorized, HttpMessage.AUTHENTICATION_FAILED.ToString(), dataField: "result", dataValue: HttpMessage.AUTHENTICATION_FAILED.ToString());
        document.RootElement.GetProperty("data").GetProperty("result").GetString().ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
    }

    [Fact]
    public async Task Unauthenticated_protected_placeholder_with_missing_body_returns_auth_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/logoff",
            new StringContent(string.Empty, Encoding.UTF8, "application/json"));

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        AccountFailureAssertions.Failure(response, document, StatusCodes.Status401Unauthorized, HttpMessage.AUTHENTICATION_FAILED.ToString(), dataField: "result", dataValue: HttpMessage.AUTHENTICATION_FAILED.ToString());
        document.RootElement.GetProperty("data").GetProperty("result").GetString().ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
    }

    private static HttpClient CreateHttpsClient(TreehammockWebApplicationFactory factory)
    {
        return factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
    }

    private static StringContent JsonContent(string json)
    {
        return new StringContent(json, Encoding.UTF8, "application/json");
    }

}
