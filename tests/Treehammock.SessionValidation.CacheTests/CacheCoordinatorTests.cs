using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NodaTime;
using Treehammock.SessionValidation.Core;
using Treehammock.SessionValidation.Storage;
using Treehammock.SessionValidation.UnitTests;
using Xunit;
namespace Treehammock.SessionValidation.CacheTests;

public sealed class CacheCoordinatorTests
{
    [Fact] public async Task Usable_hit_has_two_gets_one_atomic_record_zero_database_and_zero_refill()
    {
        using var h=new CacheHarness();h.Db.Down=true;var r=await h.Validate(token:TestContext.Current.CancellationToken);
        Assert.Equal(SessionDecision.Active,r.Decision);Assert.Equal(TestSessions.Identity.AccountId,r.Subject!.AccountId);Assert.NotNull(r.ValidUntil);
        Assert.Equal(2,h.Cache.Keys.Count);Assert.Single(h.Cache.Keys,k=>k.Contains(":account:",StringComparison.Ordinal));Assert.Equal(0,h.Db.Calls);Assert.Empty(h.Refill.Requests);
        Assert.All(h.Cache.Returned,b=>Assert.All(b,v=>Assert.Equal(0,v)));Assert.DoesNotContain(h.Hash,r.ToString());
    }
    [Fact] public async Task Production_gate_cannot_be_enabled_by_configuration_or_cached_state()
    {
        using var h=new CacheHarness(false);h.Gate=JsonSerializer.Deserialize<SessionCacheAdmission>("{\"CacheReady\":true,\"Enabled\":true}")!;h.Db.Down=true;
        var result=await h.Validate(token:TestContext.Current.CancellationToken);Assert.False(h.Gate.CacheReady);Assert.Equal(SessionDecision.Unavailable,result.Decision);Assert.Empty(h.Cache.Keys);Assert.Equal(1,h.Db.Calls);
    }
    [Theory][InlineData("wrong-key")][InlineData("preauth")][InlineData("wrong-issuer")][InlineData("missing-jti")][InlineData("hs384")]
    public async Task Bad_signature_purpose_issuer_or_claim_is_not_a_cache_miss(string kind)
    {using var h=new CacheHarness();h.Token=TestSessions.Mint(kind);h.SetReady();var result=await h.Validate(token:TestContext.Current.CancellationToken);Assert.Equal(SessionDecision.Unauthenticated,result.Decision);Assert.Null(result.Subject);Assert.Equal(0,h.Db.Calls);Assert.Empty(h.Refill.Requests);}
    [Fact] public async Task Eligible_empty_capabilities_is_forbidden_after_real_signature_without_fallback()
    {
        using var h=new CacheHarness();var j=JsonNode.Parse(h.Cache.Payload!)!;j["entitlements"]!["capabilities"]=new JsonArray();h.Cache.Payload=Encoding.UTF8.GetBytes(j.ToJsonString());
        var result=await h.Validate(token:TestContext.Current.CancellationToken);Assert.Equal(SessionDecision.Forbidden,result.Decision);Assert.Null(result.Subject);Assert.Equal(0,h.Db.Calls);Assert.Empty(h.Refill.Requests);
    }
    [Theory][InlineData("missing-index")][InlineData("bad-index")][InlineData("stale-index")][InlineData("missing-record")][InlineData("blocked")][InlineData("malformed")]
    [InlineData("epoch")][InlineData("policy")][InlineData("environment")][InlineData("account")][InlineData("binding")]
    [InlineData("future-produced")][InlineData("not-after-equal")][InlineData("age-bound")][InlineData("access-bound")][InlineData("hard-bound")][InlineData("cutoff-bound")]
    [InlineData("entitlement-bound")][InlineData("eligibility-bound")][InlineData("unverified")][InlineData("locked")][InlineData("deleted")][InlineData("revoked")]
    [InlineData("stamp")][InlineData("protocol")][InlineData("family")][InlineData("generation")][InlineData("entitlements")][InlineData("unqualified-rights")][InlineData("outage")]
    public async Task Unusable_cache_uses_current_database_and_one_guarded_refill(string kind)
    {
        using var h=new CacheHarness();var j=JsonNode.Parse(h.Cache.Payload!)!.AsObject();
        switch(kind)
        {
            case "missing-index":h.Cache.Index=null;break;case "bad-index":h.Cache.Index=Encoding.UTF8.GetBytes("arbitrary-account-assertion");break;
            case "stale-index":h.Cache.Index=Encoding.UTF8.GetBytes(Guid.NewGuid().ToString("N"));break;
            case "missing-record":h.Cache.Payload=null;break;
            case "blocked":using(var ready=h.Record())using(var r=new CachedAccountAuthority(ready.Header with{State=CachedAuthorityState.Blocked}))h.Cache.Payload=CoherentCacheCodec.Encode(r);break;
            case "malformed":h.Cache.Payload=Encoding.UTF8.GetBytes("legacy");break;
            case "epoch":j["epoch"]=Guid.NewGuid().ToString("N");break;case "policy":j["policy"]="old.v0";break;case "environment":j["environment"]="other";break;
            case "account":j["identity"]!["accountId"]=Guid.NewGuid().ToString("N");break;case "binding":j["credentialHash"]=new string('A',64);break;
            case "future-produced":j["producedAt"]="2026-10-17T01:00:01Z";break;case "not-after-equal":j["notAfter"]="2026-10-17T01:00:00Z";break;
            case "age-bound":j["notAfter"]="2026-10-17T01:01:00Z";break;case "access-bound":j["lifetime"]!["accessExpiration"]="2026-10-17T01:00:10Z";break;
            case "hard-bound":j["lifetime"]!["hardExpiration"]="2026-10-17T01:00:10Z";break;case "cutoff-bound":j["lifetime"]!["cutoff"]="2026-10-17T01:00:10Z";break;
            case "entitlement-bound":j["entitlements"]!["nextBoundary"]="2026-10-17T01:00:10Z";break;case "eligibility-bound":j["entitlements"]!["eligibilityUntil"]="2026-10-17T01:00:10Z";break;
            case "unverified":j["account"]!["verificationStatus"]=0;break;case "locked":j["account"]!["unlockWhen"]="2026-10-17T01:00:01Z";break;
            case "deleted":j["account"]!["exists"]=false;break;case "revoked":j["account"]!["sessionCurrent"]=false;break;
            case "stamp":j["account"]!["currentStamp"]=Guid.NewGuid().ToString("N");break;
            case "protocol":j["identity"]!["protocol"]=1;break;case "family":j["identity"]!["familyId"]=new string('0',32);break;case "generation":j["identity"]!["generation"]="0";break;
            case "entitlements":j["entitlements"]!["capabilities"]=new JsonArray("admin");break;case "outage":h.Cache.Down=true;break;
            case "unqualified-rights":j["entitlements"]!["rightsEnabled"]=true;break;
        }
        if(kind is not ("missing-index" or "bad-index" or "stale-index" or "missing-record" or "blocked" or "malformed" or "outage"))h.Cache.Payload=Encoding.UTF8.GetBytes(j.ToJsonString());
        var result=await h.Validate(token:TestContext.Current.CancellationToken);Assert.Equal(SessionDecision.Active,result.Decision);Assert.Equal(1,h.Db.Calls);Assert.Single(h.Refill.Requests);Assert.Equal((h.Hash,h.Space.Epoch),h.Refill.Requests[0]);
    }
    [Theory][InlineData(AuthorityReadStatus.Unavailable,SessionDecision.Unavailable)][InlineData(AuthorityReadStatus.NotFound,SessionDecision.Unauthenticated)][InlineData(AuthorityReadStatus.Unauthenticated,SessionDecision.Unauthenticated)]
    public async Task No_usable_cache_and_no_valid_database_never_grants(AuthorityReadStatus status,SessionDecision expected)
    {using var h=new CacheHarness();h.Cache.Index=null;h.Db.Status=status;var r=await h.Validate(token:TestContext.Current.CancellationToken);Assert.Equal(expected,r.Decision);Assert.Null(r.Subject);Assert.Empty(h.Refill.Requests);}
    [Fact] public async Task No_positive_identity_is_reused_between_requests()
    {using var h=new CacheHarness();Assert.Equal(SessionDecision.Active,(await h.Validate(token:TestContext.Current.CancellationToken)).Decision);h.Cache.Payload=null;h.Db.Status=AuthorityReadStatus.NotFound;var r=await h.Validate(token:TestContext.Current.CancellationToken);Assert.Equal(SessionDecision.Unauthenticated,r.Decision);Assert.Null(r.Subject);Assert.Equal(4,h.Cache.Keys.Count);Assert.Equal(1,h.Db.Calls);}
    [Fact] public async Task Admission_change_during_index_read_discards_cache_and_suppresses_refill()
    {
        using var h=new CacheHarness();h.Cache.Read=(_,_)=>{h.Gate.Quarantine();return Task.FromResult<byte[]?>((byte[])h.Cache.Index!.Clone());};
        var r=await h.Validate(token:TestContext.Current.CancellationToken);Assert.Equal(SessionDecision.Active,r.Decision);Assert.Single(h.Cache.Keys);Assert.Equal(1,h.Db.Calls);Assert.Empty(h.Refill.Requests);
    }
    [Theory][InlineData(-1)][InlineData(1)] public async Task Clock_rollback_or_deadline_jump_is_unavailable(int direction)
    {
        using var h=new CacheHarness();h.Cache.Read=(_,_)=>{h.Clock.Now+=Duration.FromSeconds(direction);return Task.FromResult<byte[]?>((byte[])h.Cache.Index!.Clone());};
        Assert.Equal(SessionDecision.Unavailable,(await h.Validate(token:TestContext.Current.CancellationToken)).Decision);Assert.Equal(0,h.Db.Calls);
    }
    [Fact] public async Task Cache_timeout_leaves_an_independent_fallback_budget_and_erases_late_payload()
    {
        using var h=new CacheHarness();var completion=new TaskCompletionSource<byte[]?>();h.Cache.Read=(_,_)=>completion.Task;
        var r=await h.Coordinator(cacheMilliseconds:20).ValidateAsync(h.Token,"account.read",h.Clock.Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);
        Assert.Equal(SessionDecision.Active,r.Decision);Assert.Equal(1,h.Db.Calls);var late=(byte[])h.Cache.Payload!.Clone();completion.SetResult(late);Assert.All(late,b=>Assert.Equal(0,b));
    }
    [Fact] public async Task Caller_cancellation_observes_and_erases_late_database_evidence()
    {
        using var h=new CacheHarness(false);using var cancelled=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);var completion=new TaskCompletionSource<AuthorityReadResult>();h.Db.Read=(_,_,_)=>completion.Task;
        var pending=h.Validate(token:cancelled.Token);cancelled.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>pending);
        using var projection=CacheHarness.Authority.Projection(h.Hash);completion.SetResult(new(AuthorityReadStatus.Found,projection));
        Assert.Equal(SessionDecision.Unavailable,await projection.EvaluateAccessAsync(new TreehammockSessionPolicyEvaluator(),h.Token,TestSessions.Issuer,"account.read",h.Clock.Now+Duration.FromSeconds(1),h.Clock,TestContext.Current.CancellationToken));
    }
    [Fact] public async Task Refill_exception_or_crossed_boundary_cannot_create_a_late_active()
    {
        using var h=new CacheHarness();h.Cache.Index=null;h.Refill.OnRequest=()=>throw new InvalidOperationException("private-queue-canary");
        Assert.Equal(SessionDecision.Active,(await h.Validate(token:TestContext.Current.CancellationToken)).Decision);
        h.Refill.OnRequest=()=>h.Clock.Now+=Duration.FromSeconds(2);Assert.Equal(SessionDecision.Unavailable,(await h.Validate(token:TestContext.Current.CancellationToken)).Decision);
    }
    [Fact] public void Refill_queue_is_bounded_deduplicated_and_payload_free()
    {
        var q=new BoundedSessionRefillQueue(1);var epoch=Guid.NewGuid();var hash=new string('A',64);
        Assert.True(q.TryRequest(hash,epoch));Assert.True(q.TryRequest(hash,epoch));Assert.False(q.TryRequest(new string('B',64),epoch));Assert.False(q.TryRequest("bad",epoch));
        Assert.True(q.TryTake(out var request));Assert.Equal(hash,request!.CredentialHash);Assert.DoesNotContain(hash,request.ToString());Assert.False(q.TryTake(out _));
        Assert.True(q.TryRequest(new string('B',64),epoch));
    }
    [Theory][InlineData("oversized")][InlineData("utf8")][InlineData("missing")][InlineData("deadline")]
    public async Task Invalid_request_is_rejected_before_cache_or_database(string kind)
    {
        using var h=new CacheHarness();string token=kind switch{"oversized"=>new string('x',8193),"utf8"=>new string('ü',4097),"missing"=>"",_=>h.Token};
        var r=await h.Coordinator().ValidateAsync(token,"account.read",kind=="deadline"?h.Clock.Now:h.Clock.Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);
        Assert.Equal(SessionDecision.Unavailable,r.Decision);Assert.Null(r.Subject);Assert.Empty(h.Cache.Keys);Assert.Equal(0,h.Db.Calls);
    }
}
