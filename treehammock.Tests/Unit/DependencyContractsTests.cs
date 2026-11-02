using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Npgsql;
using NSubstitute;
using Shouldly;
using StackExchange.Redis;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Dependencies;

namespace treehammock.Tests.Unit;

public class Cor03DependencyContractsTests
{
    [Theory]
    [InlineData("db;name", "user;name", "password;Ssl Mode=Disable;Host=evil")]
    [InlineData("db\"name", "user=name", "a'b\"c; d=1")]
    [InlineData("日本語", " user ", "  secret  ")]
    public void Database_settings_roundtrip_without_parameter_injection(string database, string user, string password)
    {
        var settings = new DatabaseSettings { servers = "localhost", database = database, userId = user, password = password, profile = "Production" };
        var parsed = new NpgsqlConnectionStringBuilder(StorageContext.BuildConnectionString(settings));
        parsed.Host.ShouldBe("localhost");
        parsed.Database.ShouldBe(database);
        parsed.Username.ShouldBe(user);
        parsed.Password.ShouldBe(password);
        parsed.SslMode.ShouldBe(SslMode.VerifyFull);
        parsed.Timeout.ShouldBe(5);
        parsed.CommandTimeout.ShouldBe(30);
        parsed.CancellationTimeout.ShouldBe(2000);
        parsed.Pooling.ShouldBeTrue();
        parsed.MaxPoolSize.ShouldBe(100);
    }

    [Fact]
    public void Invalid_database_profile_and_pool_bounds_are_rejected()
    {
        Should.Throw<ArgumentException>(() => StorageContext.BuildConnectionString(new DatabaseSettings { profile = "guess" }));
        Should.Throw<ArgumentException>(() => StorageContext.BuildConnectionString(new DatabaseSettings { minimumPoolSize = 5, maximumPoolSize = 2 }));
    }

    [Fact]
    public async Task Startup_failure_retries_and_readiness_recovers_without_request_connecting()
    {
        int attempts = 0;
        var recovered = Substitute.For<IConnectionMultiplexer>();
        recovered.IsConnected.Returns(true);
        var connected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var slot = new CacheConnectionSlot(Settings(), _ =>
        {
            if (Interlocked.Increment(ref attempts) == 1) throw new RedisConnectionException(ConnectionFailureType.UnableToConnect, "injected unavailable startup");
            connected.TrySetResult();
            return Task.FromResult(recovered);
        });
        Should.Throw<DependencyUnavailableException>(() => slot.Database);
        attempts.ShouldBe(0); // Hot-path access cannot initialize a connection.
        slot.Start();
        await connected.Task.WaitAsync(TimeSpan.FromSeconds(2));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        while (!slot.Ready) await Task.Delay(10, deadline.Token);
        slot.Ready.ShouldBeTrue();
        await slot.DisposeAsync();
        attempts.ShouldBe(2);
        recovered.Received(1).Dispose();
    }

    [Fact]
    public async Task Late_connection_is_disposed_once_when_shutdown_wins()
    {
        var pending = new TaskCompletionSource<IConnectionMultiplexer>(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var connection = Substitute.For<IConnectionMultiplexer>();
        var slot = new CacheConnectionSlot(Settings(), _ => { started.SetResult(); return pending.Task; });
        slot.Start();
        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Task disposal = slot.DisposeAsync().AsTask();
        pending.SetResult(connection);
        await disposal.WaitAsync(TimeSpan.FromSeconds(2));
        await slot.DisposeAsync();
        connection.Received(1).Dispose();
    }

    [Fact]
    public async Task Borrowed_connection_is_never_disposed_by_a_service()
    {
        var connection = Substitute.For<IConnectionMultiplexer>();
        await using (var service = new ActiveUserCacheService(Options.Create(Settings()), connection)) { }
        connection.DidNotReceive().Dispose();
    }

    [Fact]
    public async Task Repeated_host_lifetimes_dispose_each_owned_role_once()
    {
        for (int generation = 0; generation < 3; generation++)
        {
            var connections = new List<IConnectionMultiplexer>();
            var allStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using IHost host = new HostBuilder().ConfigureServices(services =>
            {
                services.AddSingleton(new CacheConnectionOwner(Options.Create(Settings()),
                    Options.Create(new TwoFactorSessionCacheSettings { servers = "localhost", port = 6379, database = 1 }),
                    Options.Create(new AbuseCounterCacheSettings { servers = "localhost", port = 6379, database = 2 }), _ =>
                    {
                        var connection = Substitute.For<IConnectionMultiplexer>();
                        connection.IsConnected.Returns(true);
                        lock (connections)
                        {
                            connections.Add(connection);
                            if (connections.Count == 3) allStarted.TrySetResult();
                        }
                        return Task.FromResult(connection);
                    }));
                services.AddHostedService(provider => provider.GetRequiredService<CacheConnectionOwner>());
            }).Build();
            await host.StartAsync();
            await allStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
            await host.StopAsync();
            foreach (var connection in connections) connection.Received(1).Dispose();
        }
    }

    [Fact]
    public async Task Cancellation_and_deadline_have_distinct_outcomes()
    {
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        int starts = 0;
        await Should.ThrowAsync<OperationCanceledException>(() => DependencyDeadline.RunAsync(_ => { starts++; return Task.FromResult(1); }, TimeSpan.FromSeconds(1), canceled.Token));
        starts.ShouldBe(0);
        var work = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        await Should.ThrowAsync<TimeoutException>(() => DependencyDeadline.RunAsync(_ => work.Task, TimeSpan.FromMilliseconds(20)));
        work.SetException(new InvalidOperationException("late fault")); // The boundary observes this abandoned command.
    }

    private static UserCacheSettings Settings() => new() { servers = "localhost", port = 6379, reconnectRetryPolicy = 10, asyncTimeoutMilliseconds = 100 };
}
