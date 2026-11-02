using NodaTime;
using Treehammock.SessionValidation.Core;
using Xunit;
using Legacy = Svs02.FrozenBaseline;

namespace Treehammock.SessionValidation.UnitTests;

public sealed class PredicateParityTests
{
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    [InlineData(5)] [InlineData(6)] [InlineData(7)] [InlineData(8)]
    public void Entitlement_currentness_matches_original_including_empty_capabilities(int feature)
    {
        var account = TestSessions.Identity.AccountId; var now = TestSessions.Now;
        foreach (long version in new[] { 0L, 1L, SessionIdentity.MaximumGeneration, SessionIdentity.MaximumGeneration + 1 })
        foreach (bool rights in new[] { false, true })
        foreach (bool grants in new[] { false, true })
        foreach (bool match in new[] { false, true })
        foreach (Instant evaluated in new[] { now, now + Duration.FromTicks(1) })
        foreach (Instant? boundary in new Instant?[] { null, now, now + Duration.FromTicks(1) })
        foreach (string[]? caps in new string[]?[] { null, Array.Empty<string>(), new[] { "account.read" }, new[] { "ACCOUNT.READ" }, new[] { "account.read", "account.manage" } })
        {
            var p = new Legacy.LegacyEntitlementProjection(match ? account : Guid.Empty, version,
                (Legacy.FeatureSet)feature, caps!, rights, evaluated, boundary, now - Duration.FromDays(1), grants ? Array.Empty<object>() : null!);
            bool expected = p.IsCurrent(account, now);
            Assert.Equal(expected, EntitlementRules.IsCurrent(account, p.AccountId, version, feature, caps,
                grants, rights, evaluated, boundary, now));
        }
    }

    [Fact]
    public void Lifetime_predicate_matches_original_on_each_cutoff_boundary()
    {
        var now = TestSessions.Now; var evaluator = new TreehammockSessionPolicyEvaluator();
        foreach (int accessOffset in new[] { -1, 0, 1 })
        foreach (int hardOffset in new[] { -1, 0, 1 })
        foreach (int? cutoffOffset in new int?[] { null, -2, 0, 2 })
        {
            var lifetime = new SessionLifetime(now + Duration.FromTicks(accessOffset), now + Duration.FromTicks(hardOffset),
                cutoffOffset is { } c ? now + Duration.FromTicks(c) : null);
            var effective = lifetime.Cutoff is { } cutoff && cutoff < lifetime.HardExpiration ? cutoff : lifetime.HardExpiration;
            bool legacy = !(effective <= now || lifetime.AccessExpiration <= now);
            Assert.Equal(legacy, evaluator.IsLifetimeCurrent(lifetime, now));
        }
    }

    [Fact]
    public void Identity_reload_comparison_matches_all_original_fields()
    {
        var a = TestSessions.Identity;
        var variants = new[] { a, a with { AccountId = Guid.NewGuid() }, a with { FamilyId = Guid.NewGuid() },
            a with { Generation = 6 }, a with { ProtocolVersion = 1 }, a with { SessionStamp = Guid.NewGuid() }, a with { AccountStamp = Guid.NewGuid() } };
        foreach (var b in variants)
        {
            bool legacy = !(a.AccountId != b.AccountId || a.ProtocolVersion != b.ProtocolVersion || a.SessionStamp != b.SessionStamp ||
                a.AccountStamp != b.AccountStamp || a.FamilyId != b.FamilyId || a.Generation != b.Generation);
            Assert.Equal(legacy, new TreehammockSessionPolicyEvaluator().MatchesAuthority(a,b));
        }
    }

    [Fact]
    public void F02_is_not_hidden_by_treating_empty_entitlements_as_account_eligibility()
    {
        var i = TestSessions.Inputs() with { Entitlements = TestSessions.Entitlements(capabilities: Array.Empty<string>()) };
        Assert.Equal(PolicyOutcome.Forbidden, new TreehammockSessionPolicyEvaluator().EvaluateState(i).Outcome);
        Assert.Equal(PolicyOutcome.Unavailable, new TreehammockSessionPolicyEvaluator().EvaluateState(i with { AccountState = AccountEligibility.Unknown }).Outcome);
    }
}
