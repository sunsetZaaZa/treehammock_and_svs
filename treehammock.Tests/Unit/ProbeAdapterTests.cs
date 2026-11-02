using Microsoft.Extensions.Options;
using NSubstitute;
using StackExchange.Redis;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Health;
namespace treehammock.Tests.Unit;
public sealed class Cor23OProbeAdapterTests
{
    private sealed class CacheOnly(HealthProbeClient adapter) : IHealthProbeClient
    {
        public Task<bool> ProbeAsync(HealthDependency dependency, CancellationToken token) => dependency == HealthDependency.PostgreSql
            ? Task.FromResult(true) : adapter.ProbeAsync(dependency, token);
    }
    private static StorageContext Storage() => new(Options.Create(new DatabaseSettings { servers = "localhost", database = "fixture", userId = "fixture" }));
    private static IConnectionMultiplexer Client(IDatabase database)
    {
        var client = Substitute.For<IConnectionMultiplexer>(); client.IsConnected.Returns(true);
        client.GetDatabase(Arg.Any<int>(), Arg.Any<object>()).Returns(database); return client;
    }
    private static CacheConnectionOwner Owner(Func<ConfigurationOptions, Task<IConnectionMultiplexer>> connect) => new(
        Options.Create(new UserCacheSettings { servers = "localhost", port = 6379 }),
        Options.Create(new TwoFactorSessionCacheSettings { servers = "localhost", port = 6379 }),
        Options.Create(new AbuseCounterCacheSettings { servers = "localhost", port = 6379 }), connect);
    private static async Task Until(Func<bool> condition)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!condition()) await Task.Delay(5, deadline.Token);
    }
    [Fact]
    public async Task Real_cache_adapter_keeps_raw_PINGs_owned_after_its_application_wait_expires()
    {
        var ping = new TaskCompletionSource<TimeSpan>(TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0; var database = Substitute.For<IDatabase>();
        database.PingAsync(Arg.Any<CommandFlags>()).Returns(_ => { Interlocked.Increment(ref calls); return ping.Task; });
        var clients = new List<IConnectionMultiplexer>();
        await using var owner = Owner(_ => { var c = Client(database); lock (clients) clients.Add(c); return Task.FromResult(c); });
        await using var storage = Storage(); await owner.StartAsync(CancellationToken.None);
        await Until(() => owner.GetDiagnostics().Values.All(d => d.Connected));
        await using var service = new HealthDependencyService(new CacheOnly(new HealthProbeClient(storage, owner)),
            new HealthProbeSettings { TotalTimeoutMilliseconds = 200, DependencyTimeoutMilliseconds = 50, SampleMaxAgeMilliseconds = 10 });
        try
        {
            Assert.False((await service.CheckAsync()).Ready); Assert.Equal(3, calls);
            for (int i = 0; i < 6; i++)
            {
                await Task.Delay(15); Assert.False((await service.CheckAsync()).Ready);
                Assert.Equal(3, calls); Assert.Equal(3, service.GetDiagnostics().PendingOperations.Values.Sum());
            }
            ping.SetResult(TimeSpan.Zero);
            await Until(() => service.GetDiagnostics().PendingOperations.Values.Sum() == 0);
            await Task.Delay(15); Assert.True((await service.CheckAsync()).Ready);
            Assert.Equal(6, calls); await service.DisposeAsync();
            foreach (var client in clients) client.DidNotReceive().Dispose(); // Sampler borrows cache roles.
        }
        finally { ping.TrySetResult(TimeSpan.Zero); }
    }
    [Fact]
    public async Task Cold_initialization_is_unhealthy_without_waiting_on_or_restarting_the_owner()
    {
        var pending = new List<TaskCompletionSource<IConnectionMultiplexer>>();
        int connections = 0;
        await using var owner = Owner(_ =>
        {
            var work = new TaskCompletionSource<IConnectionMultiplexer>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (pending) pending.Add(work); Interlocked.Increment(ref connections); return work.Task;
        });
        await using var storage = Storage(); await owner.StartAsync(CancellationToken.None);
        await Until(() => connections == 3);
        await using var service = new HealthDependencyService(new CacheOnly(new HealthProbeClient(storage, owner)), new HealthProbeSettings());
        try
        {
            var report = await service.CheckAsync(); Assert.False(report.Ready); Assert.Equal(3, connections);
            Assert.All(report.dependencies.Where(d => d.name != "postgresql"), d => Assert.Equal("cache_unavailable", d.reasonCode));
            Assert.All(owner.GetDiagnostics().Values, d => Assert.Equal(1, d.PendingInitializations));
        }
        finally { lock (pending) foreach (var work in pending) work.TrySetResult(Client(Substitute.For<IDatabase>())); }
    }
    [Fact]
    public async Task Pre_canceled_adapter_never_acquires_database_or_sends_PING()
    {
        int connects = 0; await using var owner = Owner(_ => { connects++; return Task.FromResult(Client(Substitute.For<IDatabase>())); });
        await using var storage = Storage(); var adapter = new HealthProbeClient(storage, owner);
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        foreach (HealthDependency dependency in Enum.GetValues<HealthDependency>())
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => adapter.ProbeAsync(dependency, canceled.Token));
        Assert.Equal(0, connects); // Owner was not started. PostgreSQL sees cancellation before pool acquisition.
    }
}
