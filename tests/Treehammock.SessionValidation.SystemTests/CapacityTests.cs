using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using NodaTime;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.Storage;
using Treehammock.SessionValidation.HostTests;
using Xunit;
namespace Treehammock.SessionValidation.SystemTests;
public sealed class CapacityTests(HostFixture fixture):IClassFixture<HostFixture>
{
    [Fact] public async Task Concurrent_arrivals_never_queue_or_exceed_capacity_and_drain_owns_leases()
    {
        var limiter=new ServiceConcurrencyLimiter(2);using var a=limiter.TryEnter();using var b=limiter.TryEnter();Assert.NotNull(a);Assert.NotNull(b);
        await Task.WhenAll(Enumerable.Range(0,500).Select(_=>Task.Run(()=>Assert.Null(limiter.TryEnter()),TestContext.Current.CancellationToken)));
        var snapshot=limiter.Snapshot;Assert.Equal(2,snapshot.Active);Assert.Equal(2,snapshot.Peak);Assert.Equal(0,snapshot.Queued);Assert.Equal(500,snapshot.Rejected);
        var drain=limiter.DrainAsync(TestContext.Current.CancellationToken);Assert.False(drain.IsCompleted);Assert.Null(limiter.TryEnter());a.Dispose();a.Dispose();Assert.False(drain.IsCompleted);b.Dispose();await drain;Assert.Equal(0,limiter.Snapshot.Active);Assert.False(limiter.Open);
    }
    [Theory][InlineData(0)][InlineData(-1)][InlineData(2049)]
    public void Invalid_or_unbounded_limiter_is_rejected(int value)=>Assert.Throws<ArgumentException>(()=>new ServiceConcurrencyLimiter(value));
    [Theory][InlineData("sql")][InlineData("raw-cache")][InlineData("replicas")][InlineData("reserve")]
    public void Pool_audit_reserve_and_aggregate_budget_must_fit(string fault)
    {
        var settings=fixture.Settings(j=>{
            var capacity=JsonNode.Parse("""{"foregroundSqlOperations":1,"cacheReadOperations":32,"rawCacheOperations":256,"replicaCount":2,"writerConnectionReserve":16,"totalSqlConnectionBudget":64}""")!;
            switch(fault){case "sql":capacity["foregroundSqlOperations"]=8;break;case "raw-cache":capacity["rawCacheOperations"]=32;break;case "replicas":capacity["replicaCount"]=64;break;default:capacity["writerConnectionReserve"]=64;break;}
            j["capacity"]=capacity;
        });Assert.Throws<ArgumentException>(()=>settings.Validate());
    }
    [Fact] public void Owner_creation_failure_releases_capacity()
    {
        var limiter=new ServiceConcurrencyLimiter(1,"foreground-sql");Assert.Throws<InvalidOperationException>(()=>limiter.EnterWith(()=>throw new InvalidOperationException()));Assert.Equal(0,limiter.Snapshot.Active);using var lease=limiter.TryEnter();Assert.NotNull(lease);
    }
    [Fact] public async Task Timed_out_YSQL_retains_budget_through_actual_executor_cleanup()
    {
        var limiter=new ServiceConcurrencyLimiter(1,"foreground-sql");var executor=new PendingExecutor();var now=SystemClock.Instance.GetCurrentInstant();
        var reader=new YsqlSessionAuthority(executor,TimeSpan.FromMilliseconds(30),SystemClock.Instance,ownOperation:()=>limiter.TryEnter()??throw new InvalidOperationException("Busy"));
        using var first=await reader.ReadAsync(new('A',64),now+Duration.FromSeconds(2),TestContext.Current.CancellationToken);Assert.Equal(AuthorityReadStatus.Unavailable,first.Status);Assert.Equal(1,limiter.Snapshot.Active);
        using var blocked=await reader.ReadAsync(new('B',64),SystemClock.Instance.GetCurrentInstant()+Duration.FromSeconds(2),TestContext.Current.CancellationToken);Assert.Equal(AuthorityReadStatus.Unavailable,blocked.Status);Assert.Equal(1,executor.Calls);
        var draining=limiter.DrainAsync(TestContext.Current.CancellationToken);Assert.False(draining.IsCompleted);executor.Completion.SetResult(null);await draining;Assert.Equal(0,limiter.Snapshot.Active);
    }
    [Fact] public async Task Real_listener_overload_returns_503_while_health_remains_available()
    {
        var settings=fixture.Settings(j=>j["maximumConcurrentRequests"]=1);await using var app=SvsHost.Build(settings,_=>new FakeResources());var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var done=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        app.MapGet("/capacity-work",async()=>{entered.TrySetResult();await done.Task;return Results.NoContent();});await app.StartAsync(TestContext.Current.CancellationToken);
        using var client=fixture.Http(settings,fixture.Client);var first=client.GetAsync("/capacity-work",TestContext.Current.CancellationToken);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(3),TestContext.Current.CancellationToken);using var blocked=await client.GetAsync("/capacity-work",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.ServiceUnavailable,blocked.StatusCode);
            using var health=await client.GetAsync("/health/live",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,health.StatusCode);var limiter=app.Services.GetRequiredService<RequestLifetime>();Assert.Equal(1,limiter.Snapshot.Active);Assert.Equal(0,limiter.Snapshot.Queued);Assert.True(limiter.Snapshot.Rejected>=1);
        }
        finally{done.TrySetResult();using var reply=await first;Assert.Equal(HttpStatusCode.NoContent,reply.StatusCode);}
    }
    [Fact] public void Telemetry_exporter_failure_cannot_leak_capacity_or_change_admission()
    {
        using var listener=new MeterListener();listener.InstrumentPublished=(instrument,l)=>{if(instrument.Meter.Name=="Treehammock.SessionValidation.Capacity")l.EnableMeasurementEvents(instrument);};listener.SetMeasurementEventCallback<long>((_,_,_,_)=>throw new InvalidOperationException("Exporter failure"));listener.Start();
        var limiter=new ServiceConcurrencyLimiter(1);var lease=limiter.TryEnter();Assert.NotNull(lease);Assert.ThrowsAny<Exception>(()=>listener.RecordObservableInstruments());Assert.Null(limiter.TryEnter());lease.Dispose();Assert.Equal(0,limiter.Snapshot.Active);
    }
    [Fact] public void Admission_hot_path_has_bounded_exploratory_allocation()
    {
        var limiter=new ServiceConcurrencyLimiter(1);for(int i=0;i<200;i++)limiter.TryEnter()!.Dispose();long start=GC.GetAllocatedBytesForCurrentThread();var timer=Stopwatch.StartNew();
        for(int i=0;i<10000;i++)limiter.TryEnter()!.Dispose();timer.Stop();long bytes=GC.GetAllocatedBytesForCurrentThread()-start;
        Assert.InRange(bytes,1,10000L*1024);Assert.Equal(10000+200,limiter.Snapshot.Accepted);Assert.Equal(0,limiter.Snapshot.Active);
        // Informational local bound only; no elapsed-time/throughput SLO assertion.
    }
    private sealed class PendingExecutor:IYsqlSnapshotExecutor
    {internal int Calls;internal readonly TaskCompletionSource<CurrentSessionRow?> Completion=new(TaskCreationOptions.RunContinuationsAsynchronously);public Task<CurrentSessionRow?> ReadAsync(string binding,TimeSpan budget,CancellationToken token){Calls++;return Completion.Task;}}
}
