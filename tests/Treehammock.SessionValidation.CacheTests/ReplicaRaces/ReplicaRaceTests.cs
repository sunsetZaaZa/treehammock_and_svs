using NodaTime;
using Svs13.Harness;
using Treehammock.SessionValidation.Core;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.CacheTests;
public sealed class ReplicaRaceTests
{
    [Fact] public async Task Two_usable_readers_during_SQL_outage_make_no_fallback_or_hint_calls()
    {using var w=new RaceWorld();w.Db.Down=true;Assert.All(await w.ReadBoth(),x=>Assert.Equal(SessionDecision.Active,x.Decision));Assert.Equal(0,w.Db.Calls);Assert.All(w.Cache.Returned.SelectMany(b=>b),b=>Assert.Equal(0,b));}
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Restart_replay_cannot_reenable_quarantined_incarnation_and_fresh_epoch_refuses_old_bytes(bool fresh)
    {
        using var w=new RaceWorld();foreach(var a in w.Admissions)a.Quarantine();
        var space=fresh?new CoherentCacheKeySpace("svs12",Guid.NewGuid(),"auth.v1"):w.Golden.Space;
        foreach(var a in w.Admissions)Assert.Throws<InvalidOperationException>(()=>a.Admit(space,w.Cache,()=>true));
        if(fresh)w.Admissions=[SessionCacheAdmission.ForQualification(space,w.Cache),SessionCacheAdmission.ForQualification(space,w.Cache)];
        w.Db.Down=true;Assert.All(await w.ReadBoth(),x=>{Assert.Equal(SessionDecision.Unavailable,x.Decision);Assert.Null(x.Subject);});Assert.Equal(2,w.Db.Calls);
    }
    [Theory][InlineData("logout-current")][InlineData("logout-all")][InlineData("revocation")][InlineData("lock")][InlineData("verification")][InlineData("deletion")][InlineData("account-stamp")][InlineData("capability")][InlineData("calendar")]
    public async Task Committed_change_before_ready_GET_or_fallback_snapshot_cannot_return_Active(string mutation)
    {
        using var w=new RaceWorld();w.Mutate(mutation);
        // Emulate the acknowledged precommit Blocked transport result. Actual owner
        // ordering is covered by the exact-peer overlay, not this storage fixture.
        using var blocked=new CachedAccountAuthority(new(w.Golden.Space.Environment,w.Golden.Space.Epoch,w.Golden.Space.Policy,CoherentCacheKeySpace.NewTransitionNonce(),w.Version.Revision.Value,CachedAuthorityState.Blocked,w.Version.AccountId));
        w.Cache.Seed(w.Golden.Space.AccountKey(w.Version.AccountId),CoherentCacheCodec.Encode(blocked));
        Assert.All(await w.ReadBoth(),x=>Assert.NotEqual(SessionDecision.Active,x.Decision));Assert.Equal(2,w.Db.Calls);
        await w.Publisher().ReconcileAsync(w.Version.AccountId,w.Golden.Hash,w.Golden.Now+Duration.FromSeconds(2),TestContext.Current.CancellationToken);
        Assert.All(await w.ReadBoth(),x=>Assert.NotEqual(SessionDecision.Active,x.Decision));
    }
}
