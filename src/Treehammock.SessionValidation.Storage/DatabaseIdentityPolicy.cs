using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace Treehammock.SessionValidation.Storage;

public enum DatabaseIdentityAuditStatus { Unspecified, Verified, Unavailable, Rejected, Quarantined }
public sealed record DatabaseIdentityAuditResult(DatabaseIdentityAuditStatus Status)
{
    public override string ToString() => $"DatabaseIdentityAuditResult({Status})";
}

// No public caller-supplied privilege assertion: these documents are obtained by the catalog executor.
internal static class DatabaseIdentityPolicy
{
    internal const string Login = "treehammock_svs";
    internal const string Group = "treehammock_svs_read";
    private static readonly JsonDocument Spec = JsonDocument.Parse(Resource("SVS05_ROLE_SPEC.json"));
    internal static string InspectionSql => Resource("svs05-inspect-identity.sql");
    internal static string Resource(string name)
    {
        using var stream = typeof(DatabaseIdentityPolicy).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException("Identity resource unavailable.");
        using var reader = new StreamReader(stream); return reader.ReadToEnd();
    }
    internal static bool Accept(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 });
            var root = document.RootElement;
            if (root.GetProperty("sessionUser").GetString() != Login || root.GetProperty("currentUser").GetString() != Login ||
                !root.GetProperty("requiredConnect").GetBoolean() || !root.GetProperty("requiredUsage").GetBoolean() ||
                root.GetProperty("unsafe").GetArrayLength() != 0) return false;
            var roles = root.GetProperty("roles").EnumerateArray().ToArray();
            if (roles.Length != 2 || roles.Count(r => r.GetProperty("name").GetString() == Login) != 1 ||
                roles.Count(r => r.GetProperty("name").GetString() == Group) != 1) return false;
            foreach (var role in roles)
            {
                bool login = role.GetProperty("name").GetString() == Login;
                if (role.GetProperty("login").GetBoolean() != login || role.GetProperty("inherit").GetBoolean() != login ||
                    (login && role.GetProperty("connectionLimit").GetInt32() != 16)) return false;
                foreach (string attribute in new[] { "superuser", "createDb", "createRole", "replication", "bypassRls" })
                    if (role.GetProperty(attribute).GetBoolean()) return false;
            }
            var memberships = root.GetProperty("memberships").EnumerateArray().ToArray();
            if (memberships.Length != 1 || memberships[0].GetProperty("member").GetString() != Login ||
                memberships[0].GetProperty("role").GetString() != Group || memberships[0].GetProperty("admin").GetBoolean()) return false;
            var columns = root.GetProperty("columns").EnumerateArray().Select(x => x.GetString()!).ToArray();
            var expected = Spec.RootElement.GetProperty("columns").EnumerateObject()
                .SelectMany(t => t.Value.EnumerateArray().Select(c => t.Name + "." + c.GetString())).ToHashSet(StringComparer.Ordinal);
            if (columns.Length != expected.Count || !expected.SetEquals(columns)) return false;
            var functions = root.GetProperty("functions").EnumerateArray().ToArray();
            var allowed = Spec.RootElement.GetProperty("functions").EnumerateArray().ToDictionary(f => f.GetProperty("signature").GetString()!, StringComparer.Ordinal);
            if (functions.Length != allowed.Count) return false;
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var function in functions)
            {
                string signature = function.GetProperty("signature").GetString()!;
                if (!seen.Add(signature) || !allowed.TryGetValue(signature, out var contract) ||
                    function.GetProperty("definer").GetBoolean() || function.GetProperty("kind").GetString() != "f" ||
                    function.GetProperty("volatility").GetString() != contract.GetProperty("volatility").GetString() ||
                    function.GetProperty("language").GetString() != contract.GetProperty("language").GetString()) return false;
                var config = function.GetProperty("config").EnumerateArray().Select(x => x.GetString()).ToArray();
                if (config.Length != 1 || config[0] != Spec.RootElement.GetProperty("function_search_path").GetString()) return false;
                var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(function.GetProperty("source").GetString()!))).ToLowerInvariant();
                if (hash != contract.GetProperty("source_sha256").GetString()) return false;
            }
            return true;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or ArgumentException or FormatException or OverflowException)
        { return false; }
    }
}
