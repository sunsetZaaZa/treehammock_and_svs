using NodaTime;
namespace treehammock.Models.Activation;

// Only the restricted operator issuer may authorize these values.
public sealed record EntitlementGrantApproval(Guid GrantId, Guid AccountId, Guid AccountStamp,
    string Catalog, short Tier, short Term, short Cadence, Instant? ApprovedStart,
    Instant? AuthorizedEnd, int MaxCycles, Instant RedeemBefore, string IssuerReference, string StartAnchor, string[] DeniedCapabilities);
public sealed record ActivationLifecycleResult(bool Result, string Code, long? GrantVersion = null, Instant? StartsAt = null, Instant? EligibilityUntil = null,
    treehammock.DataLayer.Entitlements.EntitlementProjection? Entitlements = null, short? Term = null, short? Tier = null, short? Cadence = null);
