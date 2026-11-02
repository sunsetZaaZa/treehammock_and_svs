using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using treehammock.DataLayer.Operations;
using treehammock.Models.Activation;
using treehammock.Models.Account;
using treehammock.Models.Authentication;
using treehammock.Rigging.Operations;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Rigging.Replay;

public static class AuthenticatedMutationCanonicalRequest
{
    public static byte[] Identity(Guid accountId, string method, string route, string key)
        => SHA256.HashData(Frame(accountId.ToString("N"), method.Trim().ToUpperInvariant(), route.Trim().Trim('/').ToLowerInvariant(), key));
    internal static byte[] Frame(params string[] values)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.UTF8, true);
        foreach (string value in values) writer.Write(value);
        writer.Flush(); return stream.ToArray();
    }
    public static byte[] FromHttp(HttpContext http, object? payload)
    {
        // Bind effective typed values, but retain presence: omitted and explicit null/default
        // stay distinct. Only fields normalized by the actual domain path are normalized here.
        JObject typed = payload is null ? new() : JObject.FromObject(payload);
        Normalize(typed, payload);
        JObject supplied = typed;
        var context = SecurityOperationRequestContext.Current;
        if (context is not null)
        {
            using var framing = new BinaryReader(new MemoryStream(context.CanonicalBody), Encoding.UTF8);
            framing.ReadString(); framing.ReadString();
            int length = framing.ReadInt32();
            if (length < 0 || length > 1024 * 1024) throw new SecurityOperationException("IDEMPOTENCY_BODY_INVALID", 400);
            byte[] bytes = framing.ReadBytes(length);
            if (bytes.Length != length) throw new SecurityOperationException("IDEMPOTENCY_BODY_INVALID", 400);
            try
            {
                if (bytes.Length == 0) supplied = new();
                else
                {
                    supplied = JObject.Parse(Encoding.UTF8.GetString(bytes), new JsonLoadSettings
                        { DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error });
                    if (supplied.Properties().GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase).Any(g => g.Count() > 1))
                        throw new SecurityOperationException("IDEMPOTENCY_BODY_INVALID", 400);
                    var normalized = new JObject();
                    foreach (var property in supplied.Properties())
                    {
                        string name = property.Name.ToLowerInvariant();
                        var effective = typed.Properties().FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
                        // Unknown fields conservatively remain content-bound; explicit null stays null.
                        normalized[name] = property.Value.Type == JTokenType.Null ? JValue.CreateNull()
                            : effective?.Value.DeepClone() ?? property.Value.DeepClone();
                    }
                    supplied = normalized;
                }
            }
            catch (JsonException) { throw new SecurityOperationException("IDEMPOTENCY_BODY_INVALID", 400); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        var headers = http.Request.Headers[SensitiveActionTokenConstants.HeaderName];
        if (headers.Count > 1 || (headers.Count == 1 && headers[0]!.Length > 4096))
            throw new SecurityOperationException("IDEMPOTENCY_PROOF_HEADER_INVALID", 400);
        var root = new JObject { ["body"] = Sort(supplied), ["query"] = http.Request.QueryString.Value ?? "",
            ["sensitiveProof"] = headers.Count == 1 ? headers[0] : null };
        byte[] result = Encoding.UTF8.GetBytes(root.ToString(Formatting.None));
        if (result.Length > 1024 * 1024 + 8192) throw new SecurityOperationException("IDEMPOTENCY_BODY_TOO_LARGE", 413);
        return result;
    }
    private static JToken Sort(JToken value)
    {
        if (value is JObject obj) return new JObject(obj.Properties().OrderBy(p => p.Name, StringComparer.Ordinal)
            .Select(p => new JProperty(p.Name, Sort(p.Value))));
        if (value is JArray array) return new JArray(array.Select(Sort));
        return value.DeepClone();
    }
    private static void Normalize(JObject value, object? payload)
    {
        if (payload is ActivationCreationRequest or ActivationUnSubscribeRequest or AccountEditRequest)
            value["emailAddress"] = value["emailAddress"]?.Value<string>()?.Trim().ToLowerInvariant();
        if (payload is SetupLayeredAuthenticateMethodRequest setup)
            value["contact"] = setup.method == TwoFactorAuthMethod.EMAIL
                ? setup.contact.Trim().ToLowerInvariant() : setup.contact.Trim();
        if (payload is StartAuthenticatorAppSetupRequest start)
            value["label"] = string.IsNullOrWhiteSpace(start.label) ? null : start.label.Trim();
        // Passwords, proof codes, setup IDs, username, delete tokens: retain the
        // effective validated DTO value; add no further normalization here.
        // Conservative conflicts are safe when a future domain path adds normalization.
    }
}
