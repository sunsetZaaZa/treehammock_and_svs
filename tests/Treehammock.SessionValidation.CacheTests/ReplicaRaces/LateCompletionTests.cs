using NodaTime;
using Svs13.Harness;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.CacheTests;
public sealed class LateCompletionTests
{
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Late_raw_ready_CAS_cannot_replace_later_fence_or_an_evicted_cell(bool evicted)
    {
        using var w=new RaceWorld();var gate=new Rendezvous();
        w.Cache.Raw=async c=>{await gate.Arrive();return w.Cache.Apply(c);};
        var pending=w.Publisher().ReconcileAsync(w.Version.AccountId,w.Golden.Hash,w.Golden.Now+Duration.FromSeconds(2),TestContext.Current.CancellationToken);
        await gate.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5),TestContext.Current.CancellationToken);
        // Transport stale injection, outside the legitimate serialized owner.
        using var blocked=new CachedAccountAuthority(new(w.Golden.Space.Environment,w.Golden.Space.Epoch,w.Golden.Space.Policy,CoherentCacheKeySpace.NewTransitionNonce(),w.Version.Revision.Value+1,CachedAuthorityState.Blocked,w.Version.AccountId));
        if(evicted)w.Cache.Remove(w.Golden.Space.AccountKey(w.Version.AccountId));else w.Cache.Seed(w.Golden.Space.AccountKey(w.Version.AccountId),CoherentCacheCodec.Encode(blocked));
        gate.Release.SetResult();Assert.Equal(ProjectionPublication.Conflict,await pending);
        if(!evicted)Assert.Equal(CachedAuthorityState.Blocked,w.State());
    }
    [Fact] public async Task Cancelled_reader_observes_and_erases_late_raw_GET_buffer()
    {
        using var h=new CacheHarness();var raw=new TaskCompletionSource<byte[]?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        h.Cache.Read=(_,_)=>{entered.SetResult();return raw.Task;};
        using var cancel=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var read=h.Validate(token:cancel.Token);await entered.Task.WaitAsync(TestContext.Current.CancellationToken);cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>read);Assert.Equal(0,h.Db.Calls);
        var secret=new byte[]{1,2,3,4};raw.SetResult(secret);
        await Task.WhenAll(raw.Task.ContinueWith(_=>{},TaskScheduler.Default));
        // Cleanup continuation may race this continuation; bounded cooperative polling.
        using var limit=new CancellationTokenSource(TimeSpan.FromSeconds(2));
        while(secret.Any(b=>b!=0)){limit.Token.ThrowIfCancellationRequested();await Task.Yield();}
        Assert.All(secret,b=>Assert.Equal(0,b));
    }
}
