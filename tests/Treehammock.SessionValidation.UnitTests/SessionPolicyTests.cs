using NodaTime;
using Treehammock.SessionValidation.Core;
using Xunit;

namespace Treehammock.SessionValidation.UnitTests;

public sealed class SessionPolicyTests
{
    public static IEnumerable<object[]> Cases()
    {
        foreach (string name in new[] { "valid", "unknown-account", "unknown-enum", "locked", "unverified", "disabled", "deleted",
            "missing-authority", "other-account", "other-family", "old-generation", "old-protocol", "old-session-stamp", "old-account-stamp",
            "empty-account", "empty-family", "empty-session-stamp", "empty-account-stamp", "generation-zero", "generation-too-large", "protocol-one",
            "access-equality", "hard-equality", "cutoff-equality", "cutoff-later-than-hard", "deadline-equality", "no-entitlements", "stale-boundary",
            "future-evaluation", "wrong-entitlement-account", "version-zero", "version-too-large", "future-tier", "premium-no-rights", "basic-no-rights",
            "missing-capabilities", "missing-grants", "unknown-capability", "empty-capabilities", "action-denied", "missing-action-policy", "case-sensitive-action" })
            yield return new object[] { name };
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Complete_state_requires_current_identity_eligibility_lifetime_and_action(string name)
    {
        var i = TestSessions.Inputs(); var now = i.Now; var identity = i.Identity;
        var expected = PolicyOutcome.Eligible;
        i = name switch
        {
            "unknown-account" => i with { AccountState = AccountEligibility.Unknown },
            "unknown-enum" => i with { AccountState = (AccountEligibility)999 },
            "locked" => i with { AccountState = AccountEligibility.Locked },
            "unverified" => i with { AccountState = AccountEligibility.Unverified },
            "disabled" => i with { AccountState = AccountEligibility.Disabled },
            "deleted" => i with { AccountState = AccountEligibility.Deleted },
            "missing-authority" => i with { CurrentAuthorityIdentity = null },
            "other-account" => i with { CurrentAuthorityIdentity = identity with { AccountId = Guid.NewGuid() } },
            "other-family" => i with { CurrentAuthorityIdentity = identity with { FamilyId = Guid.NewGuid() } },
            "old-generation" => i with { CurrentAuthorityIdentity = identity with { Generation = 6 } },
            "old-protocol" => i with { CurrentAuthorityIdentity = identity with { ProtocolVersion = 3 } },
            "old-session-stamp" => i with { CurrentAuthorityIdentity = identity with { SessionStamp = Guid.NewGuid() } },
            "old-account-stamp" => i with { CurrentAuthorityIdentity = identity with { AccountStamp = Guid.NewGuid() } },
            "empty-account" => i with { Identity = identity with { AccountId = Guid.Empty } },
            "empty-family" => i with { Identity = identity with { FamilyId = Guid.Empty } },
            "empty-session-stamp" => i with { Identity = identity with { SessionStamp = Guid.Empty } },
            "empty-account-stamp" => i with { Identity = identity with { AccountStamp = Guid.Empty } },
            "generation-zero" => i with { Identity = identity with { Generation = 0 } },
            "generation-too-large" => i with { Identity = identity with { Generation = SessionIdentity.MaximumGeneration + 1 } },
            "protocol-one" => i with { Identity = identity with { ProtocolVersion = 1 } },
            "access-equality" => i with { Lifetime = i.Lifetime with { AccessExpiration = now } },
            "hard-equality" => i with { Lifetime = i.Lifetime with { HardExpiration = now } },
            "cutoff-equality" => i with { Lifetime = i.Lifetime with { Cutoff = now } },
            "cutoff-later-than-hard" => i with { Lifetime = i.Lifetime with { HardExpiration = now, Cutoff = now + Duration.FromHours(2) } },
            "deadline-equality" => i with { Deadline = now },
            "no-entitlements" => i with { Entitlements = null },
            "stale-boundary" => i with { Entitlements = TestSessions.Entitlements(boundary: now) },
            "future-evaluation" => i with { Entitlements = TestSessions.Entitlements(evaluated: now + Duration.FromTicks(1)) },
            "wrong-entitlement-account" => i with { Entitlements = new(Guid.NewGuid(), 1, 1, new[] { "account.read" }, true, now, null, null, true) },
            "version-zero" => i with { Entitlements = TestSessions.Entitlements(version: 0) },
            "version-too-large" => i with { Entitlements = TestSessions.Entitlements(version: SessionIdentity.MaximumGeneration + 1) },
            "future-tier" => i with { Entitlements = TestSessions.Entitlements(tier: 3) },
            "premium-no-rights" => i with { Entitlements = TestSessions.Entitlements(tier: 2, rights: false) },
            "basic-no-rights" => i with { Entitlements = TestSessions.Entitlements(tier: 1, rights: false) },
            "missing-capabilities" => i with { Entitlements = new(identity.AccountId, 1, 1, null, true, now, null, null, true) },
            "missing-grants" => i with { Entitlements = TestSessions.Entitlements(grants: false) },
            "unknown-capability" => i with { Entitlements = TestSessions.Entitlements(capabilities: new[] { "backup.read" }) },
            "empty-capabilities" => i with { Entitlements = TestSessions.Entitlements(capabilities: Array.Empty<string>()) },
            "action-denied" => i with { Entitlements = TestSessions.Entitlements(capabilities: new[] { "account.read" }), RequiredCapability = "account.manage" },
            "missing-action-policy" => i with { RequiredCapability = "" },
            "case-sensitive-action" => i with { RequiredCapability = "Account.Read" },
            _ => i
        };
        if (name is "unknown-account" or "unknown-enum" or "missing-authority" or "deadline-equality" or "no-entitlements" or "stale-boundary" or "future-evaluation" or
            "wrong-entitlement-account" or "version-zero" or "version-too-large" or "future-tier" or "premium-no-rights" or "missing-capabilities" or "missing-grants" or "unknown-capability" or "missing-action-policy")
            expected = PolicyOutcome.Unavailable;
        else if (name is "empty-capabilities" or "action-denied" or "case-sensitive-action") expected = PolicyOutcome.Forbidden;
        else if (name is not ("valid" or "basic-no-rights")) expected = PolicyOutcome.Unauthenticated;
        Assert.Equal(expected, new TreehammockSessionPolicyEvaluator().EvaluateState(i).Outcome);
    }

    [Theory]
    [InlineData("valid", SessionDecision.Active)]
    [InlineData("preauth", SessionDecision.Unauthenticated)]
    [InlineData("wrong-key", SessionDecision.Unauthenticated)]
    [InlineData("wrong-purpose", SessionDecision.Unauthenticated)]
    [InlineData("missing-jti", SessionDecision.Unauthenticated)]
    public async Task Aggregate_access_evaluation_requires_actual_signature_and_active_purpose(string kind, SessionDecision expected)
    {
        var result = await new TreehammockSessionPolicyEvaluator().EvaluateAccessAsync(TestSessions.Inputs(),
            TestSessions.Mint(kind), TestSessions.Key(), TestSessions.Issuer);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(TokenStatus.AtExpiration, SessionDecision.Unauthenticated)]
    [InlineData(TokenStatus.UnexpectedException, SessionDecision.Unavailable)]
    [InlineData(TokenStatus.Passed, SessionDecision.Unauthenticated)]
    [InlineData(TokenStatus.Unspecified, SessionDecision.Unavailable)]
    public async Task Nondefinitive_token_results_never_grant_active(TokenStatus status, SessionDecision expected)
    {
        var result = await new TreehammockSessionPolicyEvaluator(new TokenStub(new(status, null)))
            .EvaluateAccessAsync(TestSessions.Inputs(), "unread", TestSessions.Key(), TestSessions.Issuer);
        Assert.Equal(expected, result);
    }

    [Fact]
    public async Task State_refusal_does_not_invoke_verifier_or_need_IO()
    {
        var tokens = new TokenStub(new(TokenStatus.Passed, "web"));
        var evaluator = new TreehammockSessionPolicyEvaluator(tokens);
        var result = await evaluator.EvaluateAccessAsync(TestSessions.Inputs() with { AccountState = AccountEligibility.Unknown },
            "not-processed", TestSessions.Key(), TestSessions.Issuer);
        Assert.Equal(SessionDecision.Unavailable, result); Assert.Equal(0, tokens.Calls);
    }

    [Theory]
    [InlineData("valid", SessionDecision.Forbidden)]
    [InlineData("wrong-key", SessionDecision.Unauthenticated)]
    public async Task Permission_refusal_requires_valid_signature(string kind, SessionDecision expected)
    {
        var inputs = TestSessions.Inputs() with { RequiredCapability = "ungranted.action" };
        Assert.Equal(expected, await new TreehammockSessionPolicyEvaluator().EvaluateAccessAsync(inputs,
            TestSessions.Mint(kind), TestSessions.Key(), TestSessions.Issuer));
    }

    [Fact]
    public void Default_results_never_mean_authorized()
    {
        Assert.NotEqual(SessionDecision.Active, default(SessionDecision));
        Assert.NotEqual(PolicyOutcome.Eligible, default(PolicyOutcome));
        Assert.NotEqual(TokenStatus.Passed, default(TokenStatus));
    }

    [Fact]
    public void Immutable_inputs_snapshot_capabilities_and_do_not_print_auth_material()
    {
        string[] caps = { "account.read" };
        var e = TestSessions.Entitlements(capabilities: caps); caps[0] = "account.manage";
        Assert.Equal("account.read", Assert.Single(e.Capabilities));
        Assert.DoesNotContain("web-canary", new TokenVerificationResult(TokenStatus.Passed, "web-canary").ToString());
        Assert.Equal(nameof(SessionValidationInputs), TestSessions.Inputs().ToString());
        Assert.Equal(nameof(SessionIdentity), TestSessions.Identity.ToString());
    }

    [Fact]
    public void Core_has_no_HTTP_storage_messaging_or_application_reference()
    {
        var names = typeof(TreehammockSessionPolicyEvaluator).Assembly.GetReferencedAssemblies().Select(a => a.Name!).ToArray();
        Assert.DoesNotContain(names, n => n.Contains("AspNetCore") || n.Contains("Npgsql") || n.Contains("Redis") || n.Contains("RabbitMQ") || n == "treehammock");
    }

    private sealed class TokenStub(TokenVerificationResult result) : ITreehammockTokenVerifier
    {
        public int Calls { get; private set; }
        public Task<TokenVerificationResult> ValidateAsync(string token, byte[] signingKey, string issuer, Instant now,
            Instant accessExpiration, string expectedPurpose = TreehammockTokenPurpose.Active, Duration? refreshWindow = null)
        { Calls++; return Task.FromResult(result); }
    }
}
