using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NSubstitute;
using StackExchange.Redis;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Dependencies;
using treehammock.Rigging.Replay;

namespace treehammock.Tests.Unit;
public sealed class Cor23NCacheLifecycleTests
{
    private static UserCacheSettings Settings() => new() { servers = "localhost", port = 6379,
        database = 0, clientName = "fixture", reconnectRetryPolicy = 10, asyncTimeoutMilliseconds = 100 };
    private static IConnectionMultiplexer Client(bool connected = true)
    {
        var client = Substitute.For<IConnectionMultiplexer>();
        client.IsConnected.Returns(connected);
        client.GetDatabase(Arg.Any<int>(), Arg.Any<object>()).Returns(Substitute.For<IDatabase>());
        return client;
    }
    private static async Task Wait(Func<bool> condition)
    {
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!condition()) await Task.Delay(5, limit.Token);
    }
    [Fact]
    public async Task Concurrent_starts_and_first_requests_keep_one_pending_initializer()
    {
        int calls = 0;
        var pending = new TaskCompletionSource<IConnectionMultiplexer>(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = Client();
        await using var slot = new CacheConnectionSlot(Settings(), _ => { Interlocked.Increment(ref calls); return pending.Task; });
        try
        {
            await Task.WhenAll(Enumerable.Range(0, 128).Select(_ => Task.Run(slot.Start)));
            await Wait(() => Volatile.Read(ref calls) == 1);
            await Task.WhenAll(Enumerable.Range(0, 64).Select(_ =>
                Assert.ThrowsAsync<DependencyUnavailableException>(() => slot.ExecuteAsync(db => db.PingAsync()))));
            Assert.Equal(1, calls);
            Assert.Equal(1, slot.GetDiagnostics().PendingInitializations);
            Assert.False(slot.GetDiagnostics().HasClient);
        }
        finally { pending.TrySetResult(client); }
        await Wait(() => slot.Ready);
        Assert.Same(client, slot.Connection);
        Assert.Equal(1, slot.GetDiagnostics().InitializationAttempts);
    }
    [Fact]
    public async Task Retry_recovers_without_requests_allocating_another_client()
    {
        int calls = 0; var client = Client();
        await using var slot = new CacheConnectionSlot(Settings(), _ =>
        {
            if (Interlocked.Increment(ref calls) < 3) throw new RedisConnectionException(ConnectionFailureType.UnableToConnect, "fixture");
            return Task.FromResult(client);
        });
        slot.Start(); await Wait(() => slot.Ready);
        for (int i = 0; i < 64; i++) { slot.Start(); Assert.Same(client, slot.Connection); }
        var report = slot.GetDiagnostics();
        Assert.Equal(3, report.InitializationAttempts); Assert.Equal(2, report.InitializationFailures);
        Assert.Equal(0, report.PendingInitializations); Assert.Equal(0, report.RetryDelayMilliseconds);
    }
    [Theory]
    [InlineData(1, 10)][InlineData(2, 20)][InlineData(3, 40)][InlineData(14, 60000)][InlineData(long.MaxValue, 60000)]
    public void Exponential_retry_is_bounded_without_overflow(long failures, int expected)
    {
        using var slot = new CacheConnectionSlot(Settings(), _ => throw new Exception());
        Assert.Equal(expected, slot.RetryDelayForFailure(failures));
    }
    [Fact]
    public void Unvalidated_retry_input_is_clamped_to_an_explicit_ceiling()
    {
        var settings = Settings(); settings.reconnectRetryPolicy = uint.MaxValue;
        using var slot = new CacheConnectionSlot(settings, _ => throw new Exception());
        Assert.Equal(60000, slot.RetryDelayForFailure(1));
    }
    [Fact]
    public async Task Retry_and_commands_use_the_original_options_snapshot()
    {
        var settings = Settings(); settings.database = 3;
        var first = new TaskCompletionSource<IConnectionMultiplexer>(TaskCreationOptions.RunContinuationsAsynchronously);
        var captured = new List<ConfigurationOptions>(); var client = Client();
        await using var slot = new CacheConnectionSlot(settings, configuration =>
        {
            lock (captured) { captured.Add(configuration); return captured.Count == 1 ? first.Task : Task.FromResult(client); }
        });
        slot.Start(); await Wait(() => slot.GetDiagnostics().PendingInitializations == 1 && slot.GetDiagnostics().InitializationAttempts == 1);
        await Wait(() => { lock (captured) return captured.Count == 1; });
        settings.servers = "changed.invalid"; settings.port = 1; settings.database = 9;
        settings.password = "changed"; settings.clientName = "changed"; settings.reconnectRetryPolicy = uint.MaxValue;
        first.SetException(new InvalidOperationException("fixture"));
        await Wait(() => slot.Ready);
        lock (captured)
        {
            Assert.Equal(2, captured.Count);
            foreach (var c in captured)
            {
                Assert.Equal("fixture", c.ClientName); Assert.Equal("", c.Password);
                Assert.Equal(3, c.DefaultDatabase); Assert.Equal(0, c.ConnectRetry); Assert.False(c.AbortOnConnectFail);
                Assert.Contains("localhost:6379", c.EndPoints.Single().ToString());
            }
        }
        _ = slot.Database; client.Received(1).GetDatabase(3, Arg.Any<object>());
    }
    [Fact]
    public async Task Shutdown_during_backoff_prevents_further_initialization()
    {
        var settings = Settings(); settings.reconnectRetryPolicy = 60000;
        await using var slot = new CacheConnectionSlot(settings, _ => throw new InvalidOperationException("fixture"));
        slot.Start(); await Wait(() => slot.GetDiagnostics().Lifecycle == CacheClientLifecycle.RetryWaiting);
        await slot.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(1, slot.GetDiagnostics().InitializationAttempts);
        Assert.Equal(CacheClientLifecycle.Disposed, slot.GetDiagnostics().Lifecycle);
        Assert.Throws<ObjectDisposedException>(slot.Start);
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Concurrent_disposal_of_a_late_client_has_one_cleanup_owner(bool lateFailure)
    {
        var pending = new TaskCompletionSource<IConnectionMultiplexer>(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = Client(); var slot = new CacheConnectionSlot(Settings(), _ => { started.TrySetResult(); return pending.Task; });
        slot.Start(); await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Task drain = slot.DisposeAsync().AsTask();
        Task[] waits = Enumerable.Range(0, 64).Select(_ => slot.DisposeAsync().AsTask()).ToArray();
        Assert.All(waits, task => Assert.Same(drain, task));
        Assert.False(slot.Ready); Assert.Throws<ObjectDisposedException>(() => slot.Connection);
        if (lateFailure) pending.SetException(new InvalidOperationException("late fixture")); else pending.SetResult(client);
        await Task.WhenAll(waits).WaitAsync(TimeSpan.FromSeconds(2)); slot.Dispose();
        if (lateFailure) client.DidNotReceive().Dispose(); else client.Received(1).Dispose();
        Assert.Equal(0, slot.GetDiagnostics().PendingInitializations);
        Assert.Equal(CacheClientLifecycle.Disposed, slot.GetDiagnostics().Lifecycle);
    }
    [Fact]
    public async Task Client_disposal_can_read_diagnostics_from_another_thread_without_a_lock_deadlock()
    {
        var client = Client(); CacheConnectionSlot? slot = null;
        client.When(c => c.Dispose()).Do(_ =>
            Task.Run(() => Assert.False(slot!.GetDiagnostics().Connected)).GetAwaiter().GetResult());
        slot = new CacheConnectionSlot(Settings(), _ => Task.FromResult(client));
        slot.Start(); await Wait(() => slot.Ready);
        await slot.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(2));
        client.Received(1).Dispose();
    }
    [Fact]
    public async Task Borrowed_client_survives_slot_disposal_but_the_slot_cannot_be_reused()
    {
        var client = Client(); var slot = new CacheConnectionSlot(Settings(), client);
        slot.Start(); await slot.DisposeAsync(); slot.Dispose();
        Assert.False(slot.Ready); Assert.False(slot.GetDiagnostics().HasClient); Assert.False(slot.GetDiagnostics().OwnsClient);
        Assert.Throws<ObjectDisposedException>(() => slot.Database); Assert.Throws<ObjectDisposedException>(slot.Start);
        int commands = 0;
        await Assert.ThrowsAsync<DependencyUnavailableException>(() => slot.ExecuteAsync(_ => { commands++; return Task.FromResult(1); }));
        Assert.Equal(0, commands); client.DidNotReceive().Dispose();
    }
    [Fact]
    public async Task Shared_consumers_do_not_dispose_or_restart_the_host_slot()
    {
        var client = Client(); int calls = 0;
        await using var slot = new CacheConnectionSlot(Settings(), _ => { calls++; return Task.FromResult(client); });
        slot.Start(); await Wait(() => slot.Ready);
        var active = new ActiveUserCacheService(Options.Create(Settings()), slot);
        var factor = new TwoFactorSessionService(Options.Create(new TwoFactorSessionCacheSettings()), slot);
        var counter = new DragonflyAbuseCounterStore(Options.Create(new AbuseCounterCacheSettings()), Options.Create(new AbuseControlSettings()), slot);
        var replay = new DragonflyAuthenticatedMutationIdempotencyService(Options.Create(new AbuseCounterCacheSettings()), Options.Create(new AbuseControlSettings()), slot);
        await active.DisposeAsync(); active.Dispose(); await factor.DisposeAsync(); factor.Dispose();
        await counter.DisposeAsync(); counter.Dispose(); await replay.DisposeAsync(); replay.Dispose();
        Assert.True(slot.Ready); Assert.Same(client, slot.Connection); Assert.Equal(1, calls); client.DidNotReceive().Dispose();
        await slot.DisposeAsync(); client.Received(1).Dispose();
    }
    [Fact]
    public async Task Multiplexer_disconnect_and_reconnect_never_create_a_second_initializer()
    {
        var client = Client(); int calls = 0;
        await using var slot = new CacheConnectionSlot(Settings(), _ => { calls++; return Task.FromResult(client); });
        slot.Start(); await Wait(() => slot.Ready); client.IsConnected.Returns(false);
        Assert.Equal(CacheClientLifecycle.Disconnected, slot.GetDiagnostics().Lifecycle);
        Assert.Throws<DependencyUnavailableException>(() => slot.Database);
        slot.Start(); client.IsConnected.Returns(true); Assert.True(slot.Ready); Assert.Equal(1, calls);
    }
    [Fact]
    public async Task Canceled_request_does_not_stop_shared_initialization()
    {
        var pending = new TaskCompletionSource<IConnectionMultiplexer>(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = Client(); await using var slot = new CacheConnectionSlot(Settings(), _ => pending.Task);
        slot.Start(); using var canceled = new CancellationTokenSource(); canceled.Cancel(); int commands = 0;
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => slot.ExecuteAsync(_ => { commands++; return Task.FromResult(1); }, canceled.Token));
            Assert.Equal(0, commands);
        }
        finally { pending.TrySetResult(client); }
        await Wait(() => slot.Ready);
    }
    private static CacheConnectionOwner Owner(Func<ConfigurationOptions, Task<IConnectionMultiplexer>> connect) => new(
        Options.Create(Settings()), Options.Create(new TwoFactorSessionCacheSettings { servers = "localhost", port = 6379, database = 1, clientName = "factor", reconnectRetryPolicy = 10 }),
        Options.Create(new AbuseCounterCacheSettings { servers = "localhost", port = 6379, database = 2, clientName = "abuse", reconnectRetryPolicy = 10 }), connect);
    [Fact]
    public async Task Repeated_host_lifetimes_and_startup_bursts_release_each_role_exactly_once()
    {
        var names = new HashSet<string>();
        for (int generation = 0; generation < 4; generation++)
        {
            var clients = new List<IConnectionMultiplexer>();
            var owner = Owner(configuration =>
            {
                var client = Client();
                lock (clients) { clients.Add(client); Assert.True(names.Add(configuration.ClientName!)); }
                return Task.FromResult(client);
            });
            using (IHost host = new HostBuilder().ConfigureServices(services =>
            {
                services.AddSingleton(owner);
                services.AddHostedService(provider => provider.GetRequiredService<CacheConnectionOwner>());
            }).Build())
            {
                await host.StartAsync();
                await Task.WhenAll(Enumerable.Range(0, 64).Select(_ => owner.StartAsync(CancellationToken.None)));
                await Wait(() => owner.GetDiagnostics().Values.All(d => d.Connected));
                Assert.All(owner.GetDiagnostics().Values, d => Assert.Equal(1, d.InitializationAttempts));
                lock (clients) Assert.Equal(3, clients.Count);
                await host.StopAsync();
                Assert.All(owner.GetDiagnostics().Values, d => Assert.Equal(CacheClientLifecycle.Disposed, d.Lifecycle));
            }
            foreach (var client in clients) client.Received(1).Dispose();
            await owner.DisposeAsync();
            Assert.Throws<ObjectDisposedException>(() => { _ = owner.StartAsync(CancellationToken.None); });
        }
        Assert.Equal(12, names.Count);
    }
    [Fact]
    public async Task Host_shutdown_cancellation_bounds_the_wait_but_retains_all_late_clients()
    {
        int starts = 0;
        // Separate clients in production; give each attempt its own late result here too.
        var attempts = new List<TaskCompletionSource<IConnectionMultiplexer>>();
        var owner = Owner(_ =>
        {
            var work = new TaskCompletionSource<IConnectionMultiplexer>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (attempts) attempts.Add(work); Interlocked.Increment(ref starts); return work.Task;
        });
        await owner.StartAsync(CancellationToken.None); await Wait(() => Volatile.Read(ref starts) == 3);
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        var clients = new List<IConnectionMultiplexer>();
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => owner.StopAsync(canceled.Token));
            Assert.Throws<ObjectDisposedException>(() => { _ = owner.StartAsync(CancellationToken.None); });
            await Wait(() => owner.GetDiagnostics().Values.All(d => d.Lifecycle == CacheClientLifecycle.Stopping));
            Assert.All(owner.GetDiagnostics().Values, d => Assert.Equal(1, d.PendingInitializations));
        }
        finally
        {
            lock (attempts) foreach (var attempt in attempts) { var late = Client(); clients.Add(late); attempt.TrySetResult(late); }
            await owner.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(2));
        }
        foreach (var late in clients) late.Received(1).Dispose();
        Assert.All(owner.GetDiagnostics().Values, d => { Assert.False(d.HasClient); Assert.Equal(0, d.PendingInitializations); });
    }
    [Fact]
    public async Task Disposal_failure_is_observed_and_does_not_skip_other_roles_or_repeat_cleanup()
    {
        int index = 0; var clients = new List<IConnectionMultiplexer>();
        var owner = Owner(configuration =>
        {
            var client = Client();
            if (Interlocked.Increment(ref index) == 1) client.When(c => c.Dispose()).Do(_ => throw new InvalidOperationException("fixture cleanup"));
            lock (clients) clients.Add(client);
            return Task.FromResult(client);
        });
        await owner.StartAsync(CancellationToken.None); await Wait(() => owner.GetDiagnostics().Values.All(d => d.Connected));
        await Assert.ThrowsAsync<InvalidOperationException>(() => owner.DisposeAsync().AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(() => owner.DisposeAsync().AsTask());
        foreach (var client in clients) client.Received(1).Dispose();
        Assert.Single(owner.GetDiagnostics().Values.Where(d => d.DisposalFailed));
        Assert.All(owner.GetDiagnostics().Values, d => Assert.Equal(CacheClientLifecycle.Disposed, d.Lifecycle));
    }
    [Fact]
    public async Task Pre_canceled_start_and_dispose_before_start_never_call_the_connector()
    {
        int calls = 0; var owner = Owner(_ => { calls++; return Task.FromResult(Client()); });
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => { _ = owner.StartAsync(canceled.Token); });
        Assert.Equal(0, calls); await owner.DisposeAsync(); Assert.Equal(0, calls);
        Assert.All(owner.GetDiagnostics().Values, d => Assert.Equal(CacheClientLifecycle.Disposed, d.Lifecycle));
    }

}
