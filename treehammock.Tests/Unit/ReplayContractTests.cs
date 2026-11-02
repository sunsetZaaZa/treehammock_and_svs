using System.Text;
using Microsoft.AspNetCore.Http;
using Shouldly;
using treehammock.Models.Account;
using treehammock.Models.Activation;
using treehammock.Models.Api;
using treehammock.Models.Authentication;
using treehammock.Rigging.Operations;
using treehammock.Rigging.Replay;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Tests.Unit;

public class Cor06ReplayContractTests
{
    private static byte[] Canonical(string json, object payload, string? proof = null)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, true))
        { writer.Write("application/json"); writer.Write(""); var bytes = Encoding.UTF8.GetBytes(json); writer.Write(bytes.Length); writer.Write(bytes); }
        using var ambient = SecurityOperationRequestContext.Push(new() { Purpose = "POST:/test", CanonicalBody = stream.ToArray() });
        var http = new DefaultHttpContext();
        if (proof is not null) http.Request.Headers[SensitiveActionTokenConstants.HeaderName] = proof;
        return AuthenticatedMutationCanonicalRequest.FromHttp(http, payload);
    }

    [Fact]
    public void Canonical_request_orders_fields_but_preserves_omitted_null_and_default()
    {
        var payload = new StartAuthenticatorAppSetupRequest { label = "office", required = true };
        Canonical("{\"label\":\"office\",\"required\":true}", payload)
            .ShouldBe(Canonical("{\"REQUIRED\":true,\"LABEL\":\"office\"}", payload));
        Canonical("{\"label\":\"office\"}", payload)
            .ShouldNotBe(Canonical("{\"label\":\"office\",\"required\":true}", payload));
        Canonical("{}", new StartAuthenticatorAppSetupRequest())
            .ShouldNotBe(Canonical("{\"label\":null}", new StartAuthenticatorAppSetupRequest()));
    }

    [Fact]
    public void Proof_password_and_unknown_fields_are_content_bound_without_plaintext_persistence()
    {
        var payload = new AccountDeleteRequest("secret-one");
        Canonical("{\"passPhrase\":\"secret-one\"}", payload, "proof-one")
            .ShouldNotBe(Canonical("{\"passPhrase\":\"secret-one\"}", payload, "proof-two"));
        Canonical("{\"passPhrase\":\"secret-one\"}", payload)
            .ShouldNotBe(Canonical("{\"passPhrase\":\"secret-two\"}", new AccountDeleteRequest("secret-two")));
        Canonical("{\"futureTier\":1}", payload).ShouldNotBe(Canonical("{\"futureTier\":2}", payload));
        Should.Throw<treehammock.DataLayer.Operations.SecurityOperationException>(() =>
            Canonical("{\"passPhrase\":\"a\",\"PassPhrase\":\"b\"}", payload));
    }

    [Fact]
    public void Typed_session_factor_destination_and_activation_tier_changes_are_bound()
    {
        Guid first = Guid.NewGuid(), second = Guid.NewGuid();
        Canonical($"{{\"sessionId\":\"{first}\"}}", new AccountSessionRevokeRequest(first))
            .ShouldNotBe(Canonical($"{{\"sessionId\":\"{second}\"}}", new AccountSessionRevokeRequest(second)));
        Canonical("{\"method\":1}", new RemoveTwoFactorMethodRequest(TwoFactorAuthMethod.EMAIL))
            .ShouldNotBe(Canonical("{\"method\":2}", new RemoveTwoFactorMethodRequest(TwoFactorAuthMethod.SMS_KEY)));
        Canonical("{\"method\":1,\"contact\":\"first@example.invalid\"}", new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "first@example.invalid", null, true))
            .ShouldNotBe(Canonical("{\"method\":1,\"contact\":\"other@example.invalid\"}", new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "other@example.invalid", null, true)));
        Canonical("{\"featureSet\":1}", new ActivationCreationRequest("a@example.invalid", 1, DayDuration.DAILY, DurationRepeat.NONE))
            .ShouldNotBe(Canonical("{\"featureSet\":2}", new ActivationCreationRequest("a@example.invalid", 2, DayDuration.DAILY, DurationRepeat.NONE)));
        Canonical("{\"emailAddress\":\"  NAME@EXAMPLE.INVALID  \"}", new AccountEditRequest("  NAME@EXAMPLE.INVALID  ", null))
            .ShouldBe(Canonical("{\"emailAddress\":\"name@example.invalid\"}", new AccountEditRequest("name@example.invalid", null)));
    }

    [Fact]
    public void Replay_restores_original_factor_lists_status_code_errors_and_client_header()
    {
        var body = new RemoveTwoFactorMethodResponse(true, HttpMessage.TWO_FACTOR_METHOD_REMOVED, TwoFactorAuthMethod.EMAIL,
            [TwoFactorAuthMethod.SMS_KEY], []);
        var original = new ApiOutcome<RemoveTwoFactorMethodResponse>(body, 200, "ORIGINAL_RESULT",
            [new ApiValidationError("originalField", ["original message"])]);
        var stored = AuthenticatedMutationSafeResult.Capture(original, "CLIENT_CLEAR_ACCESS_TOKEN");
        body.twoFactorAuthMethods!.Clear(); // Later mutable state cannot rewrite the stored response.
        var http = new DefaultHttpContext();
        var replay = AuthenticatedMutationSafeResult.Restore<RemoveTwoFactorMethodResponse>(stored, http.Response);
        replay.StatusCode.ShouldBe(200); replay.Code.ShouldBe("ORIGINAL_RESULT");
        replay.Body!.twoFactorAuthMethods!.Single().ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        replay.Errors!.Single().field.ShouldBe("originalField");
        http.Response.Headers["AppStatus"].ToString().ShouldBe("CLIENT_CLEAR_ACCESS_TOKEN");
    }

    [Fact]
    public void Authenticator_seeds_and_access_tokens_require_recovery_and_are_never_saved()
    {
        var seed = AuthenticatedMutationSafeResult.Capture(new ApiOutcome<StartAuthenticatorAppSetupResponse>(
            new(HttpMessage.TWO_FACTOR_METHOD_REMOVED, true) { manualEntryKey = "secret-seed", otpauthUri = "secret-uri" }, 200, "STARTED"));
        seed.SafeResponse.ShouldBeNull();
        var token = AuthenticatedMutationSafeResult.Capture(new ApiOutcome<VerifyAuthenticatorAppSetupResponse>(
            new(HttpMessage.TWO_FACTOR_METHOD_REMOVED, true, "secret-access-token"), 200, "VERIFIED"));
        token.SafeResponse.ShouldBeNull();
        Should.Throw<treehammock.DataLayer.Operations.SecurityOperationException>(() =>
            AuthenticatedMutationSafeResult.Restore<VerifyAuthenticatorAppSetupResponse>(token));
    }
}
