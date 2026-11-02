using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
namespace Treehammock.SessionValidation.Storage;

// Trusted deployment binding. It contains role names, never writer/owner credentials.
public sealed record TreehammockRoleMap(string App, string Coordinator, string Validator, string Maintenance, string Owner, string ValidatorRead, string Refiller = "svs_refiller")
{
    public void Validate()
    {
        string[] names = [App, Coordinator, Validator, Maintenance, Owner, ValidatorRead, Refiller];
        if (names.Any(n => n is null || !System.Text.RegularExpressions.Regex.IsMatch(n, "^[a-z][a-z0-9_]{0,62}$") || n.StartsWith("pg_", StringComparison.Ordinal) || n.StartsWith("yb_", StringComparison.Ordinal)) || names.Distinct(StringComparer.Ordinal).Count() != 7)
            throw new ArgumentException("Seven distinct trusted role names required.");
        if (ValidatorRead != "treehammock_svs_read") throw new ArgumentException("The reviewed TreeHammock read group is required.");
    }
    public override string ToString() => nameof(TreehammockRoleMap);
}

internal static class TreehammockIdentityPolicy
{
    internal static string Policy => DatabaseIdentityPolicy.Resource("SVS07_THS_POLICY.json");
    internal static string RolesJson(TreehammockRoleMap r) => JsonSerializer.Serialize(r);
    internal static bool Preflight(JsonElement root, TreehammockRoleMap roles)
    {
        if (root.GetProperty("sessionUser").GetString() != roles.Validator || root.GetProperty("currentUser").GetString() != roles.Validator ||
            !root.GetProperty("rolesMatch").GetBoolean() || !root.GetProperty("policyMatch").GetBoolean() || root.GetProperty("groupOwnsObjects").GetBoolean()) return false;
        foreach (var (field, login) in new[] { ("login", true), ("readGroup", false) })
        {
            var role = root.GetProperty(field);
            if (role.GetProperty("login").GetBoolean() != login) return false;
            // THS10 creates NOINHERIT runtime logins with the server default limit;
            // an adopted SVS05 login has INHERIT/16. Effective rights are closed by
            // the pinned helper in both profiles; the owned client pool is bounded.
            bool inherit = role.GetProperty("inherit").GetBoolean();
            int limit = role.GetProperty("connectionLimit").GetInt32();
            if (!login && inherit || login && (inherit ? limit != 16 : limit is not (-1 or 16))) return false;
            foreach (string attr in new[] { "superuser", "createDb", "createRole", "replication", "bypassRls" }) if (role.GetProperty(attr).GetBoolean()) return false;
        }
        var membership = root.GetProperty("membership");
        if (membership.GetProperty("count").GetInt32() != 1 || membership.GetProperty("member").GetString() != roles.Validator || membership.GetProperty("role").GetString() != roles.ValidatorRead || membership.GetProperty("admin").GetBoolean()) return false;
        var helper = root.GetProperty("helper");
        using var spec = JsonDocument.Parse(DatabaseIdentityPolicy.Resource("SVS07_THS_AUDIT_SPEC.json"));
        if (helper.GetProperty("owner").GetString() != roles.Owner || helper.GetProperty("definer").GetBoolean() || helper.GetProperty("kind").GetString() != "f" || helper.GetProperty("language").GetString() != "plpgsql" || helper.GetProperty("volatility").GetString() != "s") return false;
        var config = helper.GetProperty("config").EnumerateArray().Select(x => x.GetString()).ToArray();
        if (config.Length != 1 || config[0] != "search_path=public, pg_catalog, pg_temp") return false;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(helper.GetProperty("source").GetString()!))).ToLowerInvariant() == spec.RootElement.GetProperty("helper_source_sha256").GetString();
    }
    internal static bool Accept(string json, TreehammockRoleMap roles)
    {
        try
        {
            if (Encoding.UTF8.GetByteCount(json) > 65536) return false;
            using var d = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 12 });
            return Preflight(d.RootElement, roles) && d.RootElement.GetProperty("helperSafe").GetBoolean();
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or ArgumentException or FormatException or OverflowException) { return false; }
    }
}
