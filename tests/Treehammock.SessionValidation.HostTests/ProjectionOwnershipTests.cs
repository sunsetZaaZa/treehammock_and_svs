using NodaTime;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.HostTests;
public sealed class ProjectionOwnershipTests
{
    private static readonly string Hash=new('A',64);
    [Fact] public async Task Cancelled_CAS_retains_guard_until_actual_native_completion()
    {
        var space=new CoherentCacheKeySpace("local",Guid.NewGuid(),"auth.v1");var lease=new Lease();var store=new Store();var publisher=new ConditionalProjectionPublisher(new(new Factory(lease),space,TimeSpan.FromSeconds(30),TimeSpan.FromSeconds(2)),store,space,TimeSpan.FromSeconds(2));
        using var cancel=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);var work=publisher.ReconcileAsync(lease.Authority!.AccountId,Hash,SystemClock.Instance.GetCurrentInstant()+Duration.FromSeconds(2),cancel.Token);
        await store.Entered.Task.WaitAsync(TestContext.Current.CancellationToken);cancel.Cancel();await Task.Delay(25,TestContext.Current.CancellationToken);
        Assert.False(work.IsCompleted);Assert.False(lease.Disposed);Assert.Equal(1,lease.Reads);
        store.Release.SetResult(true);await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>work);Assert.True(lease.Disposed);
    }
    [Fact] public async Task Timed_out_post_lock_read_keeps_guard_and_fleet_slot_until_raw_read_cleanup()
    {
        var lease=new Lease{Pending=new(TaskCreationOptions.RunContinuationsAsynchronously)};var requests=new RequestLifetime(1);var factory=new OwnedProjectionLeases(new Factory(lease),()=>requests.TryEnter()!);
        var space=new CoherentCacheKeySpace("local",Guid.NewGuid(),"auth.v1");var builder=new AuthorityProjectionBuilder(factory,space,TimeSpan.FromSeconds(30),TimeSpan.FromSeconds(2));
        using var cancel=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);var work=builder.PrepareAsync(lease.Authority!.AccountId,Hash,SystemClock.Instance.GetCurrentInstant()+Duration.FromSeconds(2),cancel.Token);
        await TestWait.Until(()=>lease.Reads==1);cancel.Cancel();await Task.Delay(20,TestContext.Current.CancellationToken);Assert.False(work.IsCompleted);Assert.False(lease.Disposed);Assert.Equal(1,requests.Active);
        lease.Pending.SetResult(new(Hash,null));await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>work);Assert.True(lease.Disposed);Assert.Equal(0,requests.Active);
    }
    [Fact] public async Task Cancelled_acquisition_is_owned_until_late_lease_is_disposed()
    {
        var lease=new Lease();var pending=new TaskCompletionSource<IAuthorityProjectionLease>(TaskCreationOptions.RunContinuationsAsynchronously);var requests=new RequestLifetime(1);var factory=new OwnedProjectionLeases(new Factory(lease,pending.Task),()=>requests.TryEnter()!);
        var builder=new AuthorityProjectionBuilder(factory,new("local",Guid.NewGuid(),"auth.v1"),TimeSpan.FromSeconds(30),TimeSpan.FromSeconds(2));
        using var cancel=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);var work=builder.PrepareAsync(lease.Authority!.AccountId,Hash,SystemClock.Instance.GetCurrentInstant()+Duration.FromSeconds(2),cancel.Token);cancel.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>work);
        Assert.Equal(1,requests.Active);pending.SetResult(lease);await TestWait.Until(()=>lease.Disposed);Assert.Equal(0,requests.Active);
    }
    private sealed class Factory(Lease lease,Task<IAuthorityProjectionLease>? pending=null):IAuthorityProjectionLeaseFactory
    {public Task<IAuthorityProjectionLease> AcquireAsync(Guid account,TimeSpan budget,CancellationToken token)=>pending??Task.FromResult<IAuthorityProjectionLease>(lease);}
    private sealed class Lease:IAuthorityProjectionLease
    {
        public AuthorityVersion? Authority{get;}=new(Guid.NewGuid(),new(7),"Live");internal bool Disposed;internal int Reads;internal TaskCompletionSource<ProjectionCandidate>? Pending;
        public Task<ProjectionCandidate> ReadCurrentAsync(string hash,CancellationToken token){Reads++;return Pending?.Task??Task.FromResult(new ProjectionCandidate(hash,null));}
        public ValueTask DisposeAsync(){Disposed=true;return ValueTask.CompletedTask;}
    }
    private sealed class Store:IAuthorityConditionalStore
    {
        public bool Available=>true;internal readonly TaskCompletionSource Entered=new(TaskCreationOptions.RunContinuationsAsynchronously);internal readonly TaskCompletionSource<bool> Release=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<byte[]?> GetAsync(string key,CancellationToken token)=>Task.FromResult<byte[]?>(null);
        public Task<bool> ExchangeAsync(CacheTransition transition,CancellationToken token){Entered.SetResult();return Release.Task;}
    }
}
