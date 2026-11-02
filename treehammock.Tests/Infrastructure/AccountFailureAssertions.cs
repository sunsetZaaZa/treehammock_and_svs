using System.Net;
using System.Text.Json;
using Shouldly;
using treehammock.Models.Api;

namespace treehammock.Tests.Infrastructure;

// Account wire contract only. Null data/errors are omitted by the current HTTP serializer.
public static class AccountFailureAssertions
{
    public static async Task<JsonDocument> ReadJson(HttpResponseMessage response)
    {
        string json = await response.Content.ReadAsStringAsync();
        json.ShouldNotBeNullOrWhiteSpace();
        return JsonDocument.Parse(json);
    }

    public static void Failure(HttpResponseMessage response, JsonDocument document, int statusCode, string code,
        string? dataField = null, string? dataValue = null)
    {
        // Assert the wire body before media type, so framework-body mutations fail on schema/code.
        Failure(response.StatusCode, document, statusCode, code, dataField, dataValue);
        (response.Content.Headers.ContentType?.MediaType).ShouldBe("application/json");
    }

    public static void Failure(HttpStatusCode httpStatus, JsonDocument document, int statusCode, string code,
        string? dataField = null, string? dataValue = null)
    {
        ((int)httpStatus).ShouldBe(statusCode);
        JsonElement root = document.RootElement;
        ObjectProperties(root, "success", "statusCode", "code", "data", "errors");
        Required(root, "success", JsonValueKind.False);
        JsonElement status = Required(root, "statusCode", JsonValueKind.Number);
        status.TryGetInt32(out int envelopeStatus).ShouldBeTrue();
        envelopeStatus.ShouldBe(statusCode);
        Required(root, "code", JsonValueKind.String).GetString().ShouldBe(code);

        if (dataField is null)
        {
            root.TryGetProperty("data", out _).ShouldBeFalse("This account response omits null data.");
            dataValue.ShouldBeNull();
        }
        else
        {
            dataValue.ShouldNotBeNullOrWhiteSpace();
            JsonElement data = Required(root, "data", JsonValueKind.Object);
            ObjectProperties(data, dataField);
            Required(data, dataField, JsonValueKind.String).GetString().ShouldBe(dataValue);
        }

        if (code == ApiResponses.ValidationFailedCode)
            ValidationErrors(document);
        else
            root.TryGetProperty("errors", out _).ShouldBeFalse("These account failures omit null errors.");
    }

    public static void ValidationErrors(JsonDocument document)
    {
        JsonElement errors = Required(document.RootElement, "errors", JsonValueKind.Array);
        errors.GetArrayLength().ShouldBeGreaterThan(0);
        foreach (JsonElement error in errors.EnumerateArray())
        {
            ObjectProperties(error, "field", "messages");
            string field = Required(error, "field", JsonValueKind.String).GetString()!;
            (field.Length == 0 || !string.IsNullOrWhiteSpace(field)).ShouldBeTrue();
            JsonElement messages = Required(error, "messages", JsonValueKind.Array);
            messages.GetArrayLength().ShouldBeGreaterThan(0);
            foreach (JsonElement message in messages.EnumerateArray())
            {
                message.ValueKind.ShouldBe(JsonValueKind.String);
                message.GetString().ShouldNotBeNullOrWhiteSpace();
            }
        }
    }

    public static void ValidationField(JsonDocument document, string field)
    {
        ValidationErrors(document);
        document.RootElement.GetProperty("errors").EnumerateArray()
            .Any(error => string.Equals(error.GetProperty("field").GetString(), field, StringComparison.Ordinal))
            .ShouldBeTrue($"Expected exact validation field '{field}'.");
    }

    private static JsonElement Required(JsonElement parent, string name, JsonValueKind kind)
    {
        parent.ValueKind.ShouldBe(JsonValueKind.Object);
        parent.TryGetProperty(name, out JsonElement value).ShouldBeTrue($"Required account property '{name}'.");
        value.ValueKind.ShouldBe(kind);
        return value;
    }

    private static void ObjectProperties(JsonElement value, params string[] allowed)
    {
        value.ValueKind.ShouldBe(JsonValueKind.Object);
        string[] names = value.EnumerateObject().Select(property => property.Name).ToArray();
        names.Distinct(StringComparer.Ordinal).Count().ShouldBe(names.Length, "Duplicate account properties are invalid.");
        names.All(name => allowed.Contains(name, StringComparer.Ordinal)).ShouldBeTrue("Unexpected account properties.");
    }
}
