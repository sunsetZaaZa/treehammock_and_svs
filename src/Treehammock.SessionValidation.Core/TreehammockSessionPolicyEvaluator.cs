using NodaTime;

namespace Treehammock.SessionValidation.Core;

public static class EntitlementRules
{
    // Exact existing projection-currentness predicate. EligibilityUntil alone was NOT a
    // currentness check: NextBoundary governs reevaluation. Empty capabilities can be
    // structurally current and still cannot authorize an action (SVS00-F02).
    public static bool IsCurrent(Guid account, Guid projectionAccount, long version, int featureTier,
        IReadOnlyList<string>? capabilities, bool grantsPresent, bool rightsEnabled,
        Instant evaluatedAt, Instant? nextBoundary, Instant now)
    {
        if (projectionAccount != account || account == Guid.Empty || version is < 1 or > SessionIdentity.MaximumGeneration ||
            featureTier is not (1 or 2) || capabilities is null || !grantsPresent || evaluatedAt > now ||
            (nextBoundary is { } boundary && boundary <= now) || (!rightsEnabled && featureTier != 1)) return false;
        foreach (string capability in capabilities)
            if (capability is not ("account.read" or "account.manage")) return false;
        return true;
    }
}

public interface ITreehammockSessionPolicyEvaluator
{
    bool IsLifetimeCurrent(SessionLifetime lifetime, Instant now);
    bool MatchesAuthority(SessionIdentity observed, SessionIdentity current);
    PolicyEvaluation EvaluateState(SessionValidationInputs inputs);
    Task<SessionDecision> EvaluateAccessAsync(SessionValidationInputs inputs, string accessCredential,
        byte[] signingKey, string issuer);
}

// This class evaluates evidence already admitted by the storage coordinator. It does not
// prove freshness or credential-to-record binding. No storage/trusted flag or I/O callback.
public sealed record VerifiedSessionAccess(SessionDecision Decision,string? WebKey=null)
{ public override string ToString()=>$"VerifiedSessionAccess({Decision})"; }
public interface IVerifiedSessionPolicyEvaluator : ITreehammockSessionPolicyEvaluator
{
    Task<VerifiedSessionAccess> EvaluateVerifiedAccessAsync(SessionValidationInputs inputs,string credential,byte[] key,string issuer);
}
public sealed class TreehammockSessionPolicyEvaluator : IVerifiedSessionPolicyEvaluator
{
    private readonly ITreehammockTokenVerifier _tokens;
    public TreehammockSessionPolicyEvaluator(ITreehammockTokenVerifier? tokens = null) =>
        _tokens = tokens ?? new TreehammockTokenVerifier();

    public bool IsLifetimeCurrent(SessionLifetime lifetime, Instant now) =>
        lifetime.AccessExpiration > now && lifetime.EffectiveHardExpiration > now;

    // Equality preserves the existing middleware refresh-reload comparison. Validity is
    // evaluated separately so extraction cannot silently change legacy orchestration.
    public bool MatchesAuthority(SessionIdentity observed, SessionIdentity current) => observed == current;

    public PolicyEvaluation EvaluateState(SessionValidationInputs inputs)
    {
        if (inputs.Deadline <= inputs.Now) return new(PolicyOutcome.Unavailable, PolicyReason.Deadline);
        if (inputs.AccountState == AccountEligibility.Unknown || !Enum.IsDefined(inputs.AccountState))
            return new(PolicyOutcome.Unavailable, PolicyReason.MissingAuthority);
        if (inputs.AccountState != AccountEligibility.Eligible)
            return new(PolicyOutcome.Unauthenticated, PolicyReason.AccountIneligible);
        if (!inputs.Identity.IsWellFormed) return new(PolicyOutcome.Unauthenticated, PolicyReason.InvalidIdentity);
        if (inputs.CurrentAuthorityIdentity is not { } authority)
            return new(PolicyOutcome.Unavailable, PolicyReason.MissingAuthority);
        if (!authority.IsWellFormed || !MatchesAuthority(inputs.Identity, authority))
            return new(PolicyOutcome.Unauthenticated, PolicyReason.AuthorityMismatch);
        if (!IsLifetimeCurrent(inputs.Lifetime, inputs.Now))
            return new(PolicyOutcome.Unauthenticated, PolicyReason.LifetimeExpired);
        var e = inputs.Entitlements;
        if (e is null || !EntitlementRules.IsCurrent(inputs.Identity.AccountId, e.AccountId, e.Version, e.FeatureTier,
            e.Capabilities.IsDefault ? null : e.Capabilities, e.GrantsPresent, e.RightsEnabled,
            e.EvaluatedAt, e.NextBoundary, inputs.Now))
            return new(PolicyOutcome.Unavailable, PolicyReason.StaleEntitlements);
        if (string.IsNullOrWhiteSpace(inputs.RequiredCapability))
            return new(PolicyOutcome.Unavailable, PolicyReason.MissingActionPolicy);
        if (!e.Capabilities.Contains(inputs.RequiredCapability, StringComparer.Ordinal))
            return new(PolicyOutcome.Forbidden, PolicyReason.CapabilityDenied);
        return new(PolicyOutcome.Eligible, PolicyReason.None);
    }

    public async Task<SessionDecision> EvaluateAccessAsync(SessionValidationInputs inputs,string accessCredential,byte[] signingKey,string issuer)
        => (await EvaluateVerifiedAccessAsync(inputs,accessCredential,signingKey,issuer)).Decision;
    public async Task<VerifiedSessionAccess> EvaluateVerifiedAccessAsync(SessionValidationInputs inputs, string accessCredential,
        byte[] signingKey, string issuer)
    {
        var state = EvaluateState(inputs);
        if (state.Outcome is not (PolicyOutcome.Eligible or PolicyOutcome.Forbidden))
            return new(state.Outcome switch
            {
                PolicyOutcome.Unauthenticated => SessionDecision.Unauthenticated,
                _ => SessionDecision.Unavailable
            });
        // Active validation never admits a pre-auth purpose or an opaque refresh credential.
        var token = await _tokens.ValidateAsync(accessCredential, signingKey, issuer, inputs.Now,
            inputs.Lifetime.AccessExpiration, TreehammockTokenPurpose.Active, Duration.Zero);
        // Coordinator must recheck current time/deadline/boundaries before publishing a reply.
        if (token.Status != TokenStatus.Passed || string.IsNullOrWhiteSpace(token.WebKey))
            return new(token.Status is TokenStatus.UnexpectedException or TokenStatus.Unspecified
                ? SessionDecision.Unavailable : SessionDecision.Unauthenticated);
        // A permission refusal still requires a verified credential before reporting Forbidden.
        return state.Outcome == PolicyOutcome.Forbidden ? new(SessionDecision.Forbidden,token.WebKey) : new(SessionDecision.Active,token.WebKey);
    }
}
