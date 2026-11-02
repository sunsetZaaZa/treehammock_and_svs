using System.ComponentModel.DataAnnotations;
using Shouldly;

using treehammock.Models.Account;
using treehammock.Models.Authentication;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Tests.Unit;

public class ModelValidationConsistencyTests
{
    [Fact]
    public void Account_creation_model_does_not_hard_code_configured_minimum_lengths()
    {
        var request = new AccountCreationRequest("new-user@example.test", "short")
        {
            username = "ab",
            country = Country.USA
        };

        IReadOnlyList<ValidationResult> errors = Validate(request);

        errors.ShouldBeEmpty();
    }

    [Fact]
    public void Account_creation_model_rejects_country_none_sentinel()
    {
        var request = new AccountCreationRequest("new-user@example.test", "ValidPassword1!")
        {
            username = null,
            country = Country.NONE
        };

        IReadOnlyList<ValidationResult> errors = Validate(request);

        errors.ShouldContain(error => error.MemberNames.Contains(nameof(AccountCreationRequest.country)));
    }

    [Fact]
    public void Authenticate_login_model_keeps_minimum_length_rules_in_runtime_validation()
    {
        var request = new AuthenticateLogin("user@example.test", "short");

        IReadOnlyList<ValidationResult> errors = Validate(request);

        errors.ShouldBeEmpty();
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("", "")]
    public void Authenticate_login_model_requires_email_or_username_shape(string? emailAddress, string? username)
    {
        var request = new AuthenticateLogin(emailAddress!, username!, "ValidPassword1!");

        IReadOnlyList<ValidationResult> errors = Validate(request);

        errors.ShouldContain(error =>
            error.MemberNames.Contains(nameof(AuthenticateLogin.emailAddress)) ||
            error.MemberNames.Contains(nameof(AuthenticateLogin.username)));
    }

    [Fact]
    public void Two_factor_method_model_rejects_none_sentinel()
    {
        var request = new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.NONE);

        IReadOnlyList<ValidationResult> errors = Validate(request);

        errors.ShouldContain(error => error.MemberNames.Contains(nameof(LayeredAuthenticateMethodsRequest.method)));
    }

    [Fact]
    public void Two_factor_auth_model_rejects_none_sentinel()
    {
        var request = new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.NONE);

        IReadOnlyList<ValidationResult> errors = Validate(request);

        errors.ShouldContain(error => error.MemberNames.Contains(nameof(LayeredAuthenticateRequest.method)));
    }

    [Fact]
    public void Authenticate_logoff_all_request_defaults_to_include_current_session()
    {
        var request = new AuthenticateLogoffAllRequest();
        var response = new AuthenticateLogoffAllResponse(HttpMessage.AUTHENTICATION_LOGOFF_ALL_SUCCEEDED);

        request.includeCurrentSession.ShouldBeTrue();
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_LOGOFF_ALL_SUCCEEDED);
    }

    [Fact]
    public void Account_session_management_models_preserve_session_identity_without_token_hashes()
    {
        Guid sessionId = Guid.NewGuid();
        var request = new AccountSessionRevokeRequest(sessionId);
        var response = new AccountSessionRevokeResponse(HttpMessage.AUTHENTICATION_SESSION_REVOKED);
        var sessionsResponse = new AccountSessionsResponse(HttpMessage.AUTHENTICATION_SESSIONS_LISTED);

        request.sessionId.ShouldBe(sessionId);
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_SESSION_REVOKED);
        sessionsResponse.result.ShouldBe(HttpMessage.AUTHENTICATION_SESSIONS_LISTED);
        sessionsResponse.sessions.ShouldBeEmpty();
    }

    private static IReadOnlyList<ValidationResult> Validate(object value)
    {
        var results = new List<ValidationResult>();
        var context = new ValidationContext(value);
        Validator.TryValidateObject(value, context, results, validateAllProperties: true);
        return results;
    }
}
