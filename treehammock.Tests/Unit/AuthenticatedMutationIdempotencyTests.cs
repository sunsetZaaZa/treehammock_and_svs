using NSubstitute;
using Microsoft.Extensions.Options;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Rigging.Replay;

namespace treehammock.Tests.Unit;

public class AuthenticatedMutationIdempotencyTests
{
    [Fact]
    public void Header_name_and_result_codes_are_stable()
    {
        AuthenticatedMutationIdempotencyConstants.HeaderName.ShouldBe("Idempotency-Key");
        AuthenticatedMutationIdempotencyConstants.MissingRequiredKeyCode.ShouldBe("IDEMPOTENCY_KEY_REQUIRED");
        AuthenticatedMutationIdempotencyConstants.InvalidKeyCode.ShouldBe("IDEMPOTENCY_KEY_INVALID");
        AuthenticatedMutationIdempotencyConstants.ReplayInProgressCode.ShouldBe("IDEMPOTENCY_REPLAY_IN_PROGRESS");
        AuthenticatedMutationIdempotencyConstants.StoreUnavailableCode.ShouldBe("IDEMPOTENCY_STORE_UNAVAILABLE");
    }

    [Fact]
    public void Cache_key_uses_account_route_method_and_fingerprinted_client_key()
    {
        Guid accountId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        string rawClientKey = "client-generated-key-123";

        string cacheKey = DragonflyAuthenticatedMutationIdempotencyService.BuildCacheKey(
            accountId,
            "POST",
            "account/wipeout/finalize",
            rawClientKey);

        cacheKey.StartsWith("idempotency:authmutation:v2:{", StringComparison.Ordinal).ShouldBeTrue();
        cacheKey.ShouldNotContain(rawClientKey);
        cacheKey.ShouldNotContain("/");
        cacheKey.ShouldNotBe(DragonflyAuthenticatedMutationIdempotencyService.BuildCacheKey(accountId, "POST", "account-wipeout/finalize", rawClientKey));
    }

    [Theory]
    [InlineData("client-key-123456")]
    [InlineData("03F701CC-AD33-444A-BEBE-90CDAE4AC3D9")]
    [InlineData("reader_key-123.456:789")]
    public void Client_key_normalization_accepts_safe_tokens(string value)
    {
        DragonflyAuthenticatedMutationIdempotencyService.NormalizeClientKey(value, 16, 128).ShouldBe(value);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("too-short")]
    [InlineData("contains whitespace")]
    [InlineData("line\nbreak")]
    [InlineData("unsafe/character-123")]
    [InlineData("unsafe@email-key-123")]
    public void Client_key_normalization_rejects_missing_or_unsafe_values(string? value)
    {
        DragonflyAuthenticatedMutationIdempotencyService.NormalizeClientKey(value, 16, 128).ShouldBeNull();
    }


    [Theory]
    [InlineData(15, false)] [InlineData(16, true)]
    [InlineData(128, true)] [InlineData(129, false)]
    public void Client_key_length_boundaries_apply_after_trimming(int length, bool accepted)
    {
        string normalized = new('a', length);
        var actual = DragonflyAuthenticatedMutationIdempotencyService.NormalizeClientKey("  " + normalized + "  ", 16, 128);
        actual.ShouldBe(accepted ? normalized : null);
    }

    [Fact]
    public void Missing_required_key_result_uses_precondition_required_reason_code()
    {
        AuthenticatedMutationIdempotencyBeginResult result = AuthenticatedMutationIdempotencyBeginResult.MissingRequiredKeyResult();

        result.Status.ShouldBe(AuthenticatedMutationIdempotencyStatus.MissingRequiredKey);
        result.ReasonCode.ShouldBe(AuthenticatedMutationIdempotencyConstants.MissingRequiredKeyCode);
    }


    [Fact]
    public async Task Dragonfly_service_returns_required_key_result_before_touching_cache_when_key_is_missing()
    {
        await using var service = new DragonflyAuthenticatedMutationIdempotencyService(
            Options.Create(new AbuseCounterCacheSettings
            {
                servers = "localhost",
                port = 6379,
                clientName = "idempotency-tests"
            }),
            Options.Create(new AbuseControlSettings()), Substitute.For<StackExchange.Redis.IConnectionMultiplexer>());

        AuthenticatedMutationIdempotencyBeginResult result = await service.BeginAsync(
            new AuthenticatedMutationIdempotencyRequest(
                Guid.NewGuid(),
                "POST",
                "account/adjust",
                null,
                RequireKey: true));

        result.Status.ShouldBe(AuthenticatedMutationIdempotencyStatus.MissingRequiredKey);
        result.ReasonCode.ShouldBe(AuthenticatedMutationIdempotencyConstants.MissingRequiredKeyCode);
    }

    [Fact]
    public async Task Noop_idempotency_service_never_blocks_requests()
    {
        AuthenticatedMutationIdempotencyBeginResult result = await NoOpAuthenticatedMutationIdempotencyService.Instance.BeginAsync(
            new AuthenticatedMutationIdempotencyRequest(
                Guid.NewGuid(),
                "POST",
                "account/adjust",
                "client-key-12345"));

        result.Status.ShouldBe(AuthenticatedMutationIdempotencyStatus.NotApplied);
    }
    [Theory]
    [InlineData("Controllers/AccountTwoFactorController.cs", "account/twofactor/authenticator/setup")]
    [InlineData("Controllers/AccountTwoFactorController.cs", "account/twofactor/authenticator/verify")]
    [InlineData("Controllers/AccountTwoFactorController.cs", "account/twofactor/authenticator/cancel")]
    [InlineData("Controllers/AccountTwoFactorController.cs", "account/setuptwofactormethod")]
    [InlineData("Controllers/AccountTwoFactorController.cs", "account/twofactor/method/remove")]
    [InlineData("Controllers/AccountProfileController.cs", "account/adjust")]
    [InlineData("Controllers/AccountDeleteController.cs", "account/wipeout")]
    [InlineData("Controllers/AccountDeleteController.cs", "account/wipeout/finalize")]
    [InlineData("Controllers/AccountSessionController.cs", "account/logoff/all")]
    [InlineData("Controllers/AccountSessionController.cs", "account/sessions/revoke")]
    [InlineData("Controllers/ActivationsController.cs", "activations/place")]
    [InlineData("Controllers/ActivationsController.cs", "activations/disable")]
    public void Required_authenticated_mutation_endpoints_pass_required_key_to_idempotency_service(string controllerPath, string route)
    {
        string source = File.ReadAllText(ProjectFile(controllerPath));

        source.ShouldContain($"BeginAuthenticatedMutationIdempotency(activeSession, \"{route}\", requireKey: true, payload: payload)");
    }

    [Fact]
    public void Current_session_logout_keeps_idempotency_key_optional()
    {
        string source = File.ReadAllText(ProjectFile("Controllers/AccountSessionController.cs"));

        source.ShouldContain("BeginAuthenticatedMutationIdempotency(activeSession, \"account/logoff\", payload: payload)");
        source.ShouldNotContain("BeginAuthenticatedMutationIdempotency(activeSession, \"account/logoff\", requireKey: true, payload: payload)");
    }
    private static string ProjectFile(string relativePath)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return Path.Combine(directory.FullName, relativePath.Replace('/', Path.DirectorySeparatorChar));
    }

}
