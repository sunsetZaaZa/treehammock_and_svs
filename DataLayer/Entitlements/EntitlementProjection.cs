using System.Globalization;
using System.Text.Json;
using Newtonsoft.Json;
using NodaTime;
using treehammock.RiggingSupport.Enum;
namespace treehammock.DataLayer.Entitlements;

public sealed record EntitlementGrantProjection(Guid GrantId, long GrantVersion, string State, short Tier,
    short Term, short Cadence, string Anchor, Instant? StartsAt, Instant? EligibilityUntil,
    int Cycle, int MaxCycles, int MaterializedCycle, bool IssuerTrusted);

public sealed record EntitlementProjection(
    [property: JsonProperty("accountId", Required = Required.Always)] Guid AccountId,
    [property: JsonProperty("version", Required = Required.Always)] long Version,
    [property: JsonProperty("features", Required = Required.Always)] FeatureSet Features,
    [property: JsonProperty("capabilities", Required = Required.Always)] string[] Capabilities,
    [property: JsonProperty("rightsEnabled", Required = Required.Always)] bool RightsEnabled,
    [property: JsonProperty("evaluatedAt", Required = Required.Always)] Instant EvaluatedAt,
    [property: JsonProperty("nextBoundary", Required = Required.AllowNull)] Instant? NextBoundary,
    [property: JsonProperty("eligibilityUntil", Required = Required.AllowNull)] Instant? EligibilityUntil,
    [property: JsonProperty("grants", Required = Required.Always)] EntitlementGrantProjection[] Grants)
{
    public bool IsCurrent(Guid account, Instant now) =>
        Treehammock.SessionValidation.Core.EntitlementRules.IsCurrent(account, AccountId, Version,
            (int)Features, Capabilities, Grants is not null, RightsEnabled, EvaluatedAt, NextBoundary, now);
    public bool Allows(string capability) => Capabilities.Contains(capability, StringComparer.Ordinal);

    // Database JSON is decoded explicitly: absent/malformed authority never becomes a basic fallback.
    public static EntitlementProjection Parse(string json, Guid? account = null)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        static Instant ReadInstant(JsonElement value) => Instant.FromDateTimeOffset(
            DateTimeOffset.Parse(value.GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.None));
        static Instant? Optional(JsonElement value) => value.ValueKind == JsonValueKind.Null ? null : ReadInstant(value);
        var grants = root.GetProperty("grants").EnumerateArray().Select(g => new EntitlementGrantProjection(
            g.GetProperty("grantId").GetGuid(), g.GetProperty("grantVersion").GetInt64(), g.GetProperty("state").GetString()!,
            g.GetProperty("tier").GetInt16(), g.GetProperty("term").GetInt16(), g.GetProperty("cadence").GetInt16(),
            g.GetProperty("anchor").GetString()!, Optional(g.GetProperty("startsAt")), Optional(g.GetProperty("eligibilityUntil")),
            g.GetProperty("cycle").GetInt32(), g.GetProperty("maxCycles").GetInt32(), g.GetProperty("materializedCycle").GetInt32(),
            g.GetProperty("issuerTrusted").GetBoolean())).ToArray();
        var result = new EntitlementProjection(root.GetProperty("accountId").GetGuid(), root.GetProperty("version").GetInt64(),
            (FeatureSet)root.GetProperty("features").GetInt16(), root.GetProperty("capabilities").EnumerateArray().Select(c => c.GetString()!).ToArray(),
            root.GetProperty("rightsEnabled").GetBoolean(), ReadInstant(root.GetProperty("evaluatedAt")),
            Optional(root.GetProperty("nextBoundary")), Optional(root.GetProperty("eligibilityUntil")), grants);
        if (!result.IsCurrent(account ?? result.AccountId, result.EvaluatedAt)) throw new ArgumentException("Invalid entitlement projection.");
        return result;
    }
}
