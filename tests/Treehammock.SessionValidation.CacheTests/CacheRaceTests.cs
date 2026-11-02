using NodaTime;
using NSubstitute;
using StackExchange.Redis;
using Treehammock.SessionValidation.Core;
using Treehammock.SessionValidation.Storage;
using Treehammock.SessionValidation.UnitTests;
using Xunit;
namespace Treehammock.SessionValidation.CacheTests;

public sealed class CacheRaceTests
{
    private sealed class Verifier(Action action) : ITreehammockTokenVerifier
    {
        public async Task<TokenVerificationResult> ValidateAsync(string token,byte[] key,string issuer,Instant now,Instant expires,string purpose=TreehammockTokenPurpose.Active,Duration? skew=null)
        {var result=await new TreehammockTokenVerifier().ValidateAsync(token,key,issuer,now,expires,purpose,skew);action();return result;}
    }
    [Fact] public async Task Not_after_crossed_during_signature_work_uses_fresh_fallback()
    {
        using var h=new CacheHarness();int calls=0;
        var json=System.Text.Json.Nodes.JsonNode.Parse(h.Cache.Payload!)!;json["notAfter"]="2026-10-17T01:00:00.01Z";h.Cache.Payload=System.Text.Encoding.UTF8.GetBytes(json.ToJsonString());
        var policy=new TreehammockSessionPolicyEvaluator(new Verifier(()=>{if(++calls==1)h.Clock.Now+=Duration.FromMilliseconds(10);}));
        var result=await h.Coordinator(policy,requestMilliseconds:1000).ValidateAsync(h.Token,"account.read",h.Clock.Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);
        Assert.Equal(SessionDecision.Active,result.Decision);Assert.NotNull(result.Subject);Assert.Equal(1,h.Db.Calls);Assert.Single(h.Refill.Requests);
    }
    [Fact] public async Task Quarantine_during_signature_prevents_returning_the_cached_identity()
    {
        using var h=new CacheHarness();h.Db.Status=AuthorityReadStatus.NotFound;
        var policy=new TreehammockSessionPolicyEvaluator(new Verifier(h.Gate.Quarantine));
        var result=await h.Coordinator(policy).ValidateAsync(h.Token,"account.read",h.Clock.Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);
        Assert.Equal(SessionDecision.Unauthenticated,result.Decision);Assert.Equal(1,h.Db.Calls);Assert.Empty(h.Refill.Requests);
    }
    private sealed class HangingVerifier : ITreehammockTokenVerifier
    {
        internal readonly TaskCompletionSource<TokenVerificationResult> Completion=new();internal byte[]? Key;
        public Task<TokenVerificationResult> ValidateAsync(string token,byte[] key,string issuer,Instant now,Instant expires,string purpose=TreehammockTokenPurpose.Active,Duration? skew=null)
        {Key=key;return Completion.Task;}
    }
    [Fact] public async Task Timed_out_signature_is_observed_and_its_key_erased_after_completion()
    {
        using var h=new CacheHarness();var verifier=new HangingVerifier();
        var result=await h.Coordinator(new TreehammockSessionPolicyEvaluator(verifier),cacheMilliseconds:10,requestMilliseconds:30).ValidateAsync(h.Token,"account.read",h.Clock.Now+Duration.FromSeconds(1),TestContext.Current.CancellationToken);
        Assert.Equal(SessionDecision.Unavailable,result.Decision);Assert.NotNull(verifier.Key);
        verifier.Completion.SetResult(new(TokenStatus.Passed,"synthetic-web-key"));
        Assert.All(verifier.Key,b=>Assert.Equal(0,b));Assert.Equal(0,h.Db.Calls);
    }
    [Fact] public async Task Redis_adapter_issues_only_a_primary_get_and_returns_owned_bytes()
    {
        var connection=Substitute.For<IConnectionMultiplexer>();var database=Substitute.For<IDatabase>();connection.GetDatabase(0,null).Returns(database);
        database.StringGetAsync("owned-key",CommandFlags.DemandMaster|CommandFlags.NoRedirect).Returns(Task.FromResult<RedisValue>(new byte[]{1,2,3}));
        using var adapter=new DragonflyGetStore(connection,new SessionCacheAdmission());
        Assert.Equal(new byte[]{1,2,3},await adapter.GetAsync("owned-key",TestContext.Current.CancellationToken));
        await database.Received(1).StringGetAsync("owned-key",CommandFlags.DemandMaster|CommandFlags.NoRedirect);
        Assert.Single(database.ReceivedCalls());
    }
    [Theory][InlineData("failed")][InlineData("restored")][InlineData("configuration")][InlineData("broadcast")]
    public void Connection_or_topology_changes_quarantine_the_admitted_incarnation(string kind)
    {
        using var h=new CacheHarness();var connection=Substitute.For<IConnectionMultiplexer>();connection.GetDatabase(0,null).Returns(Substitute.For<IDatabase>());
        using var adapter=new DragonflyGetStore(connection,h.Gate);Assert.True(h.Gate.CacheReady);
        var failed=new ConnectionFailedEventArgs(connection,new System.Net.IPEndPoint(System.Net.IPAddress.Loopback,6379),ConnectionType.Interactive,ConnectionFailureType.SocketFailure,new InvalidOperationException("synthetic"),"fixture");
        var changed=new EndPointEventArgs(connection,new System.Net.IPEndPoint(System.Net.IPAddress.Loopback,6379));
        switch(kind)
        {
            case "failed":connection.ConnectionFailed+=Raise.EventWith(connection,failed);break;
            case "restored":connection.ConnectionRestored+=Raise.EventWith(connection,failed);break;
            case "configuration":connection.ConfigurationChanged+=Raise.EventWith(connection,changed);break;
            default:connection.ConfigurationChangedBroadcast+=Raise.EventWith(connection,changed);break;
        }
        Assert.False(h.Gate.CacheReady);
    }
    [Fact] public async Task Redis_permission_error_quarantines_instead_of_remaining_admitted()
    {
        using var h=new CacheHarness();var connection=Substitute.For<IConnectionMultiplexer>();var db=Substitute.For<IDatabase>();connection.GetDatabase(0,null).Returns(db);
        db.StringGetAsync("owned-key",CommandFlags.DemandMaster|CommandFlags.NoRedirect).Returns(Task.FromException<RedisValue>(new RedisServerException("NOPERM synthetic")));
        using var adapter=new DragonflyGetStore(connection,h.Gate);
        await Assert.ThrowsAsync<RedisServerException>(()=>adapter.GetAsync("owned-key",TestContext.Current.CancellationToken));Assert.False(h.Gate.CacheReady);
    }
    [Fact] public async Task Clock_rollback_between_cache_gets_is_sticky_even_above_request_start()
    {
        using var h=new CacheHarness();int calls=0;
        h.Cache.Read=(_,_)=>
        {
            calls++;h.Clock.Now=TestSessions.Now+Duration.FromMilliseconds(calls==1?600:500);
            return Task.FromResult<byte[]?>((byte[])(calls==1?h.Cache.Index!:h.Cache.Payload!).Clone());
        };
        var result=await h.Validate(token:TestContext.Current.CancellationToken);
        Assert.Equal(SessionDecision.Unavailable,result.Decision);Assert.Null(result.Subject);Assert.Equal(0,h.Db.Calls);
    }

    // Model of the REQUIRED writer primitive, not a deployed Redis script or TreeHammock writer.
    private sealed class Cell
    {
        internal sealed record Value(Guid Epoch,string Nonce,CachedAuthorityState State,long Revision);
        internal Value? Current;
        private readonly HashSet<string> _used=[];
        internal bool InitializeBlocked(Guid epoch,string nonce)
        {if(Current is not null||!_used.Add(nonce))return false;Current=new(epoch,nonce,CachedAuthorityState.Blocked,0);return true;}
        internal bool Cas(Guid epoch,string expected,string next,CachedAuthorityState state,long revision)
        {if(Current is not {} c||c.Epoch!=epoch||c.Nonce!=expected||!_used.Add(next))return false;Current=new(epoch,next,state,revision);return true;}
    }
    [Theory][InlineData("later-fence")][InlineData("evicted")][InlineData("new-epoch")]
    public void Delayed_ready_cannot_replace_a_later_fence_missing_cell_or_new_epoch(string schedule)
    {
        var c=new Cell();var epoch=Guid.NewGuid();var first=CoherentCacheKeySpace.NewTransitionNonce();Assert.True(c.InitializeBlocked(epoch,first));
        if(schedule=="later-fence")Assert.True(c.Cas(epoch,first,CoherentCacheKeySpace.NewTransitionNonce(),CachedAuthorityState.Blocked,2));
        else {c.Current=null;if(schedule=="new-epoch")Assert.True(c.InitializeBlocked(Guid.NewGuid(),CoherentCacheKeySpace.NewTransitionNonce()));}
        Assert.False(c.Cas(epoch,first,CoherentCacheKeySpace.NewTransitionNonce(),CachedAuthorityState.Ready,1));
        Assert.True(c.Current is null||c.Current.State==CachedAuthorityState.Blocked);
    }
    [Fact] public void Every_transition_rotates_nonce_and_late_nx_can_only_create_blocked()
    {
        var c=new Cell();var epoch=Guid.NewGuid();var a=CoherentCacheKeySpace.NewTransitionNonce();var b=CoherentCacheKeySpace.NewTransitionNonce();
        Assert.True(c.InitializeBlocked(epoch,a));Assert.True(c.Cas(epoch,a,b,CachedAuthorityState.Ready,1));Assert.False(c.Cas(epoch,b,a,CachedAuthorityState.Blocked,2));
        c.Current=null;Assert.True(c.InitializeBlocked(epoch,CoherentCacheKeySpace.NewTransitionNonce()));Assert.Equal(CachedAuthorityState.Blocked,c.Current!.State);
    }
}
