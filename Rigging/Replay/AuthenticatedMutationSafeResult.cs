using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using treehammock.DataLayer.Operations;
using treehammock.Models.Account;
using treehammock.Models.Activation;
using treehammock.Models.Api;
using treehammock.Models.Authentication;

namespace treehammock.Rigging.Replay;

public static class AuthenticatedMutationSafeResult
{
    // Explicit fields, not arbitrary DTO serialization: future secret properties cannot leak.
    private static readonly Dictionary<Type, string[]> Fields = new()
    {
        [typeof(AccountEditResponse)] = ["result"],
        [typeof(AccountDeleteResponse)] = ["result", "workflow"],
        [typeof(AuthenticateLogoffResponse)] = ["result"],
        [typeof(AuthenticateLogoffAllResponse)] = ["result"],
        [typeof(AccountSessionRevokeResponse)] = ["result"],
        [typeof(CancelAuthenticatorAppSetupResponse)] = ["result", "status"],
        [typeof(SetupLayeredAuthenticateMethodResponse)] = ["status"],
        [typeof(RemoveTwoFactorMethodResponse)] = ["outcome", "result", "removedMethod", "twoFactorAuthMethods", "availableTwoFactorAuthConfigurations"],
        [typeof(ActivationCreationResponse)] = ["result", "version", "grantId", "grantVersion", "requestId", "lifecycle", "rightsEnabled", "retryAfterSeconds"],
        [typeof(ActivationUnSubscribeResponse)] = ["result"]
    };
    public static AuthenticatedMutationIdempotencyStoredResult Capture<T>(ApiOutcome<T> outcome, string? appStatus = null)
    {
        if (outcome.Body is null || outcome.Body.GetType() != typeof(T) || !Fields.TryGetValue(typeof(T), out var fields))
            return new(outcome.StatusCode, outcome.Code); // Seed/access-token responses require explicit recovery.
        var body = new JObject();
        foreach (string field in fields)
        {
            object? value = typeof(T).GetProperty(field)!.GetValue(outcome.Body);
            body[field] = value is null ? JValue.CreateNull() : JToken.FromObject(value);
        }
        var envelope = new JObject { ["bodyType"] = typeof(T).FullName, ["body"] = body,
            ["errors"] = outcome.Errors is null ? JValue.CreateNull() : JToken.FromObject(outcome.Errors),
            ["appStatus"] = appStatus == "CLIENT_CLEAR_ACCESS_TOKEN" ? appStatus : null };
        string json = envelope.ToString(Formatting.None);
        return Encoding.UTF8.GetByteCount(json) <= 16384
            ? new(outcome.StatusCode, outcome.Code, json) : new(outcome.StatusCode, outcome.Code);
    }
    public static ApiOutcome<T> Restore<T>(AuthenticatedMutationIdempotencyStoredResult stored, HttpResponse? response = null)
    {
        if (stored.SafeResponse is null || !Fields.ContainsKey(typeof(T)))
            throw new SecurityOperationException(AuthenticatedMutationIdempotencyConstants.RecoveryRequiredCode, 409);
        var envelope = JObject.Parse(stored.SafeResponse);
        if (envelope["bodyType"]?.Value<string>() != typeof(T).FullName)
            throw new SecurityOperationException(AuthenticatedMutationIdempotencyConstants.RecoveryRequiredCode, 409);
        T? body = envelope["body"]!.ToObject<T>();
        if (body is null) throw new SecurityOperationException(AuthenticatedMutationIdempotencyConstants.RecoveryRequiredCode, 409);
        if (response is not null && envelope["appStatus"]?.Value<string>() == "CLIENT_CLEAR_ACCESS_TOKEN")
            response.Headers["AppStatus"] = "CLIENT_CLEAR_ACCESS_TOKEN";
        if (response is not null && body is ActivationCreationResponse { retryAfterSeconds: int seconds } && seconds > 0)
            response.Headers["Retry-After"] = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var errors = envelope["errors"]?.Type == JTokenType.Array ? envelope["errors"]!.ToObject<List<ApiValidationError>>() : null;
        return new(body, stored.StatusCode, stored.Code, errors);
    }
}
