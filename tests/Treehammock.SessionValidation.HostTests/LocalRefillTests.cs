using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.HostTests;

public sealed class LocalRefillTests
{
    private static string Hash(int n)=>n.ToString("X64");
    private static readonly Guid Epoch=Guid.NewGuid();
    [Fact] public async Task Saturation_deduplicates_queued_and_inflight_and_owns_ignored_cancellation()
    {
        var p=new Publisher();var w=new LocalRefillWorker(new(){QueueCapacity=4,Workers=2,OperationTimeoutMilliseconds=100},p,e=>e==Epoch);
        Assert.True(w.TryRequest(Hash(1),Epoch));Assert.True(w.TryRequest(Hash(2),Epoch));await TestWait.Until(()=>p.Calls==2);
        for(int n=0;n<10000;n++)Assert.True(w.TryRequest(Hash(1),Epoch));
        Assert.True(w.TryRequest(Hash(3),Epoch));Assert.True(w.TryRequest(Hash(4),Epoch));Assert.False(w.TryRequest(Hash(5),Epoch));Assert.Equal(4,w.OwnedCount);
        await TestWait.Until(()=>p.Cancelled==2);Assert.Equal(2,p.Calls);
        var stop=w.StopAsync();Assert.False(stop.IsCompleted);Assert.False(w.TryRequest(Hash(6),Epoch));Assert.Equal(2,w.OwnedCount);Assert.False(p.Disposed);
        p.Release.TrySetResult();await stop.WaitAsync(TimeSpan.FromSeconds(2),TestContext.Current.CancellationToken);Assert.Equal(0,w.OwnedCount);Assert.True(p.Disposed);Assert.Equal(2,p.Calls);
    }
    [Fact] public async Task Completed_cooldown_is_bounded_and_prevents_repeated_dispatch()
    {
        var p=new Publisher();p.Release.SetResult();await using var w=new LocalRefillWorker(new(){QueueCapacity=4,Workers=1,PublicationsPerSecond=1000,CompletedCooldownMilliseconds=30000},p,_=>true);
        for(int n=1;n<=30;n++){Assert.True(w.TryRequest(Hash(n),Epoch));await TestWait.Until(()=>w.OwnedCount==0);}
        Assert.Equal(30,p.Calls);Assert.Equal(4,w.RecentCount);
        for(int n=0;n<10000;n++)Assert.True(w.TryRequest(Hash(30),Epoch));Assert.Equal(30,p.Calls);
    }
    [Fact] public async Task Expired_queue_items_and_foreign_epochs_never_publish()
    {
        var p=new Publisher();await using var w=new LocalRefillWorker(new(){QueueCapacity=4,Workers=1,MaximumQueueAgeMilliseconds=100,OperationTimeoutMilliseconds=1000},p,e=>e==Epoch);
        w.TryRequest(Hash(1),Epoch);await TestWait.Until(()=>p.Calls==1);w.TryRequest(Hash(2),Epoch);w.TryRequest(Hash(3),Guid.NewGuid());
        await Task.Delay(160,TestContext.Current.CancellationToken);p.Release.SetResult();await TestWait.Until(()=>w.OwnedCount==0);Assert.Equal(1,p.Calls);
    }
    [Fact] public async Task Rate_limit_bounds_dispatch()
    {
        var p=new Publisher();p.Release.SetResult();await using var w=new LocalRefillWorker(new(){QueueCapacity=8,Workers=2,PublicationsPerSecond=1},p,_=>true);
        for(int n=1;n<=8;n++)w.TryRequest(Hash(n),Epoch);await TestWait.Until(()=>p.Calls==1);
        await Task.Delay(150,TestContext.Current.CancellationToken);Assert.Equal(1,p.Calls);Assert.Equal(7,w.OwnedCount);
    }
    [Fact] public async Task Warmup_owns_one_late_scan_and_stop_waits_for_actual_completion()
    {
        var p=new Publisher{ScanPending=new(TaskCreationOptions.RunContinuationsAsynchronously)};
        var w=new LocalRefillWorker(new(){Epoch=Epoch,WarmupIntervalMilliseconds=1000,OperationTimeoutMilliseconds=100},p,e=>e==Epoch);
        await TestWait.Until(()=>p.Scans==1);await Task.Delay(200,TestContext.Current.CancellationToken);var stop=w.StopAsync();Assert.False(stop.IsCompleted);Assert.False(p.Disposed);Assert.Equal(1,p.Scans);
        p.ScanPending.SetResult([]);await stop.WaitAsync(TimeSpan.FromSeconds(2),TestContext.Current.CancellationToken);Assert.True(p.Disposed);Assert.Equal(1,p.Scans);
    }
    [Fact] public async Task Invalid_hints_and_closed_publisher_do_not_create_work()
    {
        var p=new Publisher{Ready=false};await using var w=new LocalRefillWorker(new(),p,_=>true);
        Assert.False(w.TryRequest("secret",Epoch));Assert.False(w.TryRequest(Hash(1),Guid.Empty));w.TryRequest(Hash(1),Epoch);await TestWait.Until(()=>w.OwnedCount==0);Assert.Equal(0,p.Calls);
    }
    private sealed class Publisher:ILocalPublication
    {
        public bool Ready{get;set;}=true;
        internal int Calls,Cancelled;internal bool Disposed;
        internal readonly TaskCompletionSource Release=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Scans;internal TaskCompletionSource<IReadOnlyList<string>>? ScanPending;
        public async Task PublishAsync(GuardedSessionRefillRequest work,CancellationToken token){Interlocked.Increment(ref Calls);using var observe=token.Register(()=>Interlocked.Increment(ref Cancelled));await Release.Task;}
        public Task<IReadOnlyList<string>> ScanAsync(string? after,int limit,CancellationToken token){Interlocked.Increment(ref Scans);return ScanPending?.Task??Task.FromResult<IReadOnlyList<string>>([]);}
        public ValueTask DisposeAsync(){Disposed=true;return ValueTask.CompletedTask;}
    }
}
