using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Shouldly;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public sealed class Cor23ACAccountFailureAssertionTests
{
    private const string Validation = """
        {"success":false,"statusCode":400,"code":"VALIDATION_FAILED","errors":[{"field":"emailAddress","messages":["Invalid email."]}]}
        """;
    private const string RequiredKey = """
        {"success":false,"statusCode":428,"code":"IDEMPOTENCY_KEY_REQUIRED","data":{"result":"ACCOUNT_ADJUST_FAILED"}}
        """;

    public static IEnumerable<object[]> InvalidEnvelopes()
    {
        yield return new object[] { "[]" };
        yield return new object[] { "null" };
        yield return new object[] { "\"text\"" };
        yield return new object[] { "{\"status\":400,\"errors\":{\"emailAddress\":[\"Invalid\"]}}" };
        foreach (string property in new[] { "success", "statusCode", "code", "errors" })
        {
            JsonObject body = JsonNode.Parse(Validation)!.AsObject();
            body.Remove(property);
            yield return new object[] { body.ToJsonString() };
        }
        foreach ((string property, string value) in new[]
        {
            ("success", "true"), ("success", "\"false\""), ("success", "0"), ("success", "null"),
            ("statusCode", "\"400\""), ("statusCode", "401"), ("statusCode", "400.5"), ("statusCode", "null"),
            ("code", "\"OTHER\""), ("code", "400"), ("code", "null"), ("code", "\"validation_failed\""),
            ("errors", "{}"), ("errors", "null"), ("errors", "[]"), ("errors", "\"invalid\"")
        })
        {
            JsonObject body = JsonNode.Parse(Validation)!.AsObject();
            body[property] = JsonNode.Parse(value);
            yield return new object[] { body.ToJsonString() };
        }
        foreach (string errors in new[]
        {
            "[null]", "[\"invalid\"]", "[{}]", "[{\"field\":null,\"messages\":[\"Invalid\"]}]",
            "[{\"field\":42,\"messages\":[\"Invalid\"]}]", "[{\"field\":\"emailAddress\"}]",
            "[{\"field\":\"emailAddress\",\"messages\":\"Invalid\"}]",
            "[{\"field\":\"emailAddress\",\"messages\":[]}]",
            "[{\"field\":\"emailAddress\",\"messages\":[null]}]",
            "[{\"field\":\"emailAddress\",\"messages\":[42]}]",
            "[{\"field\":\"emailAddress\",\"messages\":[\" \" ]}]",
            "[{\"field\":\"emailAddress\",\"messages\":[\"Invalid\"]},{\"field\":\"password\",\"messages\":[]}]",
            "[{\"field\":\"emailAddress\",\"messages\":[\"Invalid\"],\"other\":true}]"
        })
        {
            JsonObject body = JsonNode.Parse(Validation)!.AsObject();
            body["errors"] = JsonNode.Parse(errors);
            yield return new object[] { body.ToJsonString() };
        }
        yield return new object[] { Validation.Replace("\"success\":false", "\"success\":true,\"success\":false", StringComparison.Ordinal) };
        yield return new object[] { Validation.Replace("\"field\":\"emailAddress\"", "\"field\":\"wrong\",\"field\":\"emailAddress\"", StringComparison.Ordinal) };
        yield return new object[] { Validation.Replace("\"success\":false", "\"success\":false,\"data\":null", StringComparison.Ordinal) };
    }

    [Theory]
    [MemberData(nameof(InvalidEnvelopes))]
    public void Status_only_missing_wrongly_typed_and_malformed_validation_shapes_are_rejected(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        Should.Throw<ShouldAssertException>(() => AccountFailureAssertions.Failure(HttpStatusCode.BadRequest, document, 400, "VALIDATION_FAILED"));
    }

    [Fact]
    public void Exact_validation_error_array_and_case_sensitive_field_pass()
    {
        using JsonDocument document = JsonDocument.Parse(Validation);
        AccountFailureAssertions.Failure(HttpStatusCode.BadRequest, document, 400, "VALIDATION_FAILED");
        AccountFailureAssertions.ValidationField(document, "emailAddress");
        Should.Throw<ShouldAssertException>(() => AccountFailureAssertions.ValidationField(document, "EmailAddress"));
    }

    [Fact]
    public void Envelope_status_cannot_replace_transport_status()
    {
        using JsonDocument document = JsonDocument.Parse(Validation);
        Should.Throw<ShouldAssertException>(() => AccountFailureAssertions.Failure(HttpStatusCode.OK, document, 400, "VALIDATION_FAILED"));
    }

    [Fact]
    public void Required_key_exact_code_and_result_pass_while_same_428_wrong_or_missing_code_fails()
    {
        using JsonDocument good = JsonDocument.Parse(RequiredKey);
        AccountFailureAssertions.Failure(HttpStatusCode.PreconditionRequired, good, 428, "IDEMPOTENCY_KEY_REQUIRED", "result", "ACCOUNT_ADJUST_FAILED");
        foreach (string property in new[] { "code", "data" })
        {
            JsonObject body = JsonNode.Parse(RequiredKey)!.AsObject();
            body.Remove(property);
            using JsonDocument bad = JsonDocument.Parse(body.ToJsonString());
            Should.Throw<ShouldAssertException>(() => AccountFailureAssertions.Failure(HttpStatusCode.PreconditionRequired, bad, 428, "IDEMPOTENCY_KEY_REQUIRED", "result", "ACCOUNT_ADJUST_FAILED"));
        }
        foreach (string json in new[]
        {
            RequiredKey.Replace("IDEMPOTENCY_KEY_REQUIRED", "OTHER", StringComparison.Ordinal),
            RequiredKey.Replace("ACCOUNT_ADJUST_FAILED", "OTHER", StringComparison.Ordinal),
            RequiredKey.Replace("\"data\":{\"result\":\"ACCOUNT_ADJUST_FAILED\"}", "\"data\":null", StringComparison.Ordinal),
            RequiredKey.Replace("\"success\":false", "\"errors\":{},\"success\":false", StringComparison.Ordinal),
            RequiredKey.Replace("\"success\":false", "\"errors\":null,\"success\":false", StringComparison.Ordinal)
        })
        {
            using JsonDocument bad = JsonDocument.Parse(json);
            Should.Throw<ShouldAssertException>(() => AccountFailureAssertions.Failure(HttpStatusCode.PreconditionRequired, bad, 428, "IDEMPOTENCY_KEY_REQUIRED", "result", "ACCOUNT_ADJUST_FAILED"));
        }
    }

    [Fact]
    public async Task Missing_json_content_type_is_rejected()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(Validation))
        };
        using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
        Should.Throw<ShouldAssertException>(() => AccountFailureAssertions.Failure(response, document, 400, "VALIDATION_FAILED"));
    }

    [Theory]
    [InlineData("", "application/json", false)]
    [InlineData("{", "application/json", true)]
    [InlineData(Validation, "application/problem+json", false)]
    public async Task Empty_malformed_or_wrong_media_type_body_is_rejected(string body, string mediaType, bool malformed)
    {
        using var response = new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent(body, Encoding.UTF8, mediaType) };
        if (malformed) await Should.ThrowAsync<JsonException>(() => AccountFailureAssertions.ReadJson(response));
        else await Should.ThrowAsync<ShouldAssertException>(async () =>
        {
            using JsonDocument document = await AccountFailureAssertions.ReadJson(response);
            AccountFailureAssertions.Failure(response, document, 400, "VALIDATION_FAILED");
        });
    }
}
