using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Shouldly;
using treehammock.DataLayer.Operations;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Operations;

namespace treehammock.Tests.Unit;

public class Cor04SecurityOperationContractTests
{
    [Fact]
    public void Expired_keys_cannot_become_new_admission_after_receipt_cleanup()
    {
        string id = $"{DateTimeOffset.UtcNow.AddDays(-2).ToUnixTimeSeconds()}.{Guid.NewGuid():N}";
        Should.Throw<SecurityOperationException>(() => SecurityOperationKey.Parse(id, 86400)).Code.ShouldBe("SECURITY_OPERATION_EXPIRED");
    }
    [Theory]
    [InlineData("not-a-key")]
    [InlineData("0.00000000000000000000000000000000")]
    [InlineData("9223372036854775807.11111111111111111111111111111111")]
    public void Malformed_keys_fail_before_database_access(string key)
        => Should.Throw<SecurityOperationException>(() => SecurityOperationKey.Parse(key, 86400)).HttpStatus.ShouldBe(400);
    [Fact]
    public void Recovery_capability_requires_256_bits_and_is_not_an_operation_UUID()
    {
        Should.Throw<SecurityOperationException>(() => SecurityOperationKey.ParseRecoveryKey(Guid.NewGuid().ToString()));
        SecurityOperationKey.ParseRecoveryKey(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))).Length.ShouldBe(32);
    }
    [Fact]
    public void Generic_outcome_allowlist_cannot_serialize_secret_fields()
    {
        var output = SecurityOperationOutcome.From(new { Result = true, Code = "SETUP_COMPLETE", AccessToken = "secret-token", Seed = "setup-seed" });
        string json = JsonSerializer.Serialize(output);
        json.ShouldContain("SETUP_COMPLETE"); json.ShouldNotContain("secret-token"); json.ShouldNotContain("setup-seed");
        Should.Throw<InvalidOperationException>(() => SecurityOperationOutcome.From(new { AccessToken = "secret-token" }));
        Should.Throw<InvalidOperationException>(() => SecurityOperationOutcome.From(new { Result = true, Code = "secret-token" }));
    }
    [Fact]
    public async Task Body_normalization_is_stable_without_consuming_MVC_input()
    {
        static DefaultHttpContext Http(string body)
        {
            var http = new DefaultHttpContext(); http.Request.ContentType = "application/json";
            http.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body)); return http;
        }
        var first = Http("{\"z\":2, \"a\":{\"b\":1}}");
        var second = Http("{\"a\":{\"b\":1},\"z\":2}");
        (await SecurityOperationMiddleware.CanonicalBodyAsync(first)).ShouldBe(await SecurityOperationMiddleware.CanonicalBodyAsync(second));
        first.Request.Body.Position.ShouldBe(0);
        var changed = Http("{\"a\":{\"b\":3},\"z\":2}");
        (await SecurityOperationMiddleware.CanonicalBodyAsync(first)).SequenceEqual(await SecurityOperationMiddleware.CanonicalBodyAsync(changed)).ShouldBeFalse();
    }
    [Fact]
    public async Task Oversized_decoded_body_is_rejected_before_domain_execution()
    {
        var http = new DefaultHttpContext(); http.Request.Body = new MemoryStream(new byte[1024 * 1024 + 1]);
        (await Should.ThrowAsync<SecurityOperationException>(() => SecurityOperationMiddleware.CanonicalBodyAsync(http))).HttpStatus.ShouldBe(413);
    }
    [Fact]
    public async Task Missing_identity_returns_428_before_opening_a_database_connection()
    {
        await using var storage = new StorageContext(Options.Create(new DatabaseSettings { servers="localhost", database="unused", userId="unused", password="unused" }));
        var http = new DefaultHttpContext(); http.Response.Body = new MemoryStream();
        http.Request.Method = "POST"; http.Request.Path = "/account/test";
        var middleware = new SecurityOperationMiddleware(async _ =>
        {
            await using var operation = await storage.SecurityOperations.BeginAsync("test.mutation", new { value=1 }, null, null, null, default);
            await operation.CommitAsync(true);
        });
        await middleware.InvokeAsync(http, storage.SecurityOperations);
        http.Response.StatusCode.ShouldBe(428);
        http.Response.Headers["AppStatus"].ToString().ShouldBeEmpty();
        http.Response.Headers["AccessToken"].ToString().ShouldBeEmpty();
    }
    [Fact]
    public async Task Async_requests_and_nested_scopes_do_not_share_operation_identity()
    {
        var outer = SecurityOperationRequestContext.Isolated("outer");
        using (SecurityOperationRequestContext.Push(outer))
        {
            await Task.WhenAll(Enumerable.Range(0, 8).Select(async n =>
            {
                var own = SecurityOperationRequestContext.Isolated(n.ToString());
                using (SecurityOperationRequestContext.Push(own))
                { await Task.Yield(); SecurityOperationRequestContext.Current.ShouldBeSameAs(own); }
                SecurityOperationRequestContext.Current.ShouldBeSameAs(outer);
            }));
            SecurityOperationRequestContext.Current.ShouldBeSameAs(outer);
        }
        SecurityOperationRequestContext.Current.ShouldBeNull();
    }
    [Fact]
    public void Invalid_keyrings_and_unbounded_budgets_fail_startup_validation()
    {
        var settings = new SecurityOperationSettings { HmacKeys = new() { [1] = Convert.ToBase64String(new byte[16]) } };
        Validator.TryValidateObject(settings, new ValidationContext(settings), new List<ValidationResult>(), true).ShouldBeFalse();
        settings.HmacKeys[1] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)); settings.ExecutionSeconds = 121;
        Validator.TryValidateObject(settings, new ValidationContext(settings), new List<ValidationResult>(), true).ShouldBeFalse();
    }
}
