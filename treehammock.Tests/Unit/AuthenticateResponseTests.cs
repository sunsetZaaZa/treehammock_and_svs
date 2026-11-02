using Newtonsoft.Json;
using Shouldly;

using treehammock.Models.Authentication;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Tests.Unit;

public class AuthenticateResponseTests
{
    [Fact]
    public void AuthenticateResponse_serializes_access_token_as_explicit_response_field()
    {
        var response = new AuthenticateResponse(
            HttpMessage.AUTHENTICATION_PASSED,
            accessToken: "issued-access-token");

        string json = JsonConvert.SerializeObject(response);

        json.ShouldContain("accessToken");
        var parsed = JsonConvert.DeserializeObject<AuthenticateResponse>(json);
        parsed.ShouldNotBeNull();
        parsed.result.ShouldBe(HttpMessage.AUTHENTICATION_PASSED);
        parsed.accessToken.ShouldBe("issued-access-token");
    }

    [Fact]
    public void AuthenticateResponse_keeps_two_factor_methods_and_token_together()
    {
        var methods = new List<TwoFactorAuthMethod> { TwoFactorAuthMethod.SMS_KEY };
        var response = new AuthenticateResponse(
            HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED,
            twoFactorAccessToken: "pending-two-factor-token",
            twoFactorAuthMethods: methods,
            availableTwoFactorAuthConfigurations: [TwoFactorAuthConfiguration.SMS]);

        response.accessToken.ShouldBeNull();
        response.twoFactorAccessToken.ShouldBe("pending-two-factor-token");
        response.twoFactorAuthMethods.ShouldBe(methods);
        response.availableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.SMS]);
    }
}
