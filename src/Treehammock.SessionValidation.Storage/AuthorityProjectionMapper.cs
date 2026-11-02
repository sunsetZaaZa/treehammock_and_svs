using System.Security.Cryptography;
using System.Text.Json;
using NodaTime;
using NodaTime.Text;
using Treehammock.SessionValidation.Core;
namespace Treehammock.SessionValidation.Storage;

internal sealed record CurrentSessionRow(string Binding, SessionIdentity Identity, Guid AccountStamp, byte[] Key,
    SessionLifetime Lifetime, short VerificationStatus, Instant? UnlockWhen, Instant ReadAt, string EntitlementJson) : IDisposable
{
    public void Dispose() => CryptographicOperations.ZeroMemory(Key);
    public override string ToString() => nameof(CurrentSessionRow);
}
internal static class AuthorityProjectionMapper
{
    internal static AuthorityReadResult Map(CurrentSessionRow row, string binding, Instant now)
    {
        if (row.Binding != binding || !row.Identity.IsWellFormed || row.AccountStamp == Guid.Empty ||
            row.Key.Length < 32 || row.ReadAt > now || row.ReadAt < Instant.FromUtc(1,1,1,0,0))
            return new(AuthorityReadStatus.Unavailable);
        if (row.AccountStamp != row.Identity.AccountStamp || row.VerificationStatus is >= 0 and <= 6 && row.VerificationStatus != 1 ||
            row.UnlockWhen > row.ReadAt || row.Lifetime.AccessExpiration <= now || row.Lifetime.EffectiveHardExpiration <= now)
            return new(AuthorityReadStatus.Unauthenticated);
        if (row.VerificationStatus != 1) return new(AuthorityReadStatus.Unavailable);
        var entitlements = ParseEntitlements(row.EntitlementJson);
        if (!EntitlementRules.IsCurrent(row.Identity.AccountId, entitlements.AccountId, entitlements.Version,
            entitlements.FeatureTier, entitlements.Capabilities, entitlements.GrantsPresent, entitlements.RightsEnabled,
            entitlements.EvaluatedAt, entitlements.NextBoundary, now) || entitlements.EvaluatedAt != row.ReadAt)
            return new(AuthorityReadStatus.Unavailable);
        return new(AuthorityReadStatus.Found, new(binding, row.Key, row.Identity, row.Lifetime, entitlements, row.ReadAt));
    }
    internal static EntitlementPolicyInputs ParseEntitlements(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var e = doc.RootElement;
        if (e.GetProperty("grants").ValueKind != JsonValueKind.Array) throw new FormatException();
        var capabilities = e.GetProperty("capabilities").EnumerateArray().Select(v => v.GetString() ?? throw new FormatException()).ToArray();
        return new(e.GetProperty("accountId").GetGuid(), e.GetProperty("version").GetInt64(), e.GetProperty("features").GetInt32(),
            capabilities, e.GetProperty("rightsEnabled").GetBoolean(), Parse(e.GetProperty("evaluatedAt")),
            Optional(e.GetProperty("nextBoundary")), Optional(e.GetProperty("eligibilityUntil")), true);
    }
    // PostgreSQL JSON timestamptz values include an explicit numeric offset.
    private static Instant Parse(JsonElement e) => OffsetDateTimePattern.Rfc3339.Parse(e.GetString() ?? "").GetValueOrThrow().ToInstant();
    private static Instant? Optional(JsonElement e) => e.ValueKind == JsonValueKind.Null ? null : Parse(e);
}
