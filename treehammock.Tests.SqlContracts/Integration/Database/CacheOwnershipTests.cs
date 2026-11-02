using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Npgsql;
using StackExchange.Redis;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Health;
using treehammock.Tests.SqlContracts.Support;
namespace treehammock.Tests.Integration.Database;
[Trait("Suite", "SqlContracts")]
public sealed class Cor23NCacheOwnershipTests
{
    private static DatabaseSettings Database()
    {
        var c = new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);
        return new() { servers = c.Host, port = c.Port, database = c.Database, userId = c.Username!, password = c.Password!, maximumPoolSize = 32, connectionTimeoutSeconds = 3 };
    }
    private static UserCacheSettings Cache(string name, int database = 0)
    {
        string? endpoint = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT");
        string? password = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_PASSWORD");
        if (string.IsNullOrWhiteSpace(endpoint) || string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException("Use the owned correction SQL/cache fixture.");
        var address = ConfigurationOptions.Parse(endpoint).EndPoints.Single();
        var (host, port) = address switch
        {
            System.Net.DnsEndPoint dns => (dns.Host, dns.Port),
            System.Net.IPEndPoint ip => (ip.Address.ToString(), ip.Port),
            _ => throw new InvalidOperationException("Fixture must expose one TCP cache endpoint.")
        };
        return new() { servers = host, port = port, password = password, clientName = name,
            database = database, connectTimeoutMilliseconds = 1000, asyncTimeoutMilliseconds = 5000, reconnectRetryPolicy = 10 };
    }
    private static async Task Wait(Func<Task<bool>> condition, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(TimeSpan.FromSeconds(15));
        while (!await condition()) await Task.Delay(20, deadline.Token);
    }
    private static async Task<int> Clients(IDatabase observer, string prefix)
    {
        string list = (await observer.ExecuteAsync("CLIENT", "LIST")).ToString();
        return list.Split('\n').Count(line => line.Split(' ').Any(field => field.StartsWith("name=" + prefix, StringComparison.Ordinal)));
    }
    [Fact]
    public async Task Real_cache_and_PostgreSQL_health_bursts_across_repeated_hosts_have_bounded_clients_and_no_leaks()
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            string scope = "cor23n-" + Guid.NewGuid().ToString("N");
            var observerSettings = Cache(scope + "-observer");
            var configuration = ActiveUserCacheService.BuildConfiguration(observerSettings); configuration.AbortOnConnectFail = true; configuration.AllowAdmin = true;
            using var observer = await ConnectionMultiplexer.ConnectAsync(configuration);
            await using var storage = new StorageContext(Options.Create(Database()), Options.Create(new SecurityOperationSettings
                { HmacKeys = new() { [1] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } }));
            for (int generation = 0; generation < 3; generation++)
            {
                string prefix = scope + "-host-" + generation;
                var active = Cache(prefix + "-active"); var factor = Cache(prefix + "-factor", 1); var abuse = Cache(prefix + "-abuse", 2);
                var owner = new CacheConnectionOwner(Options.Create(active),
                    Options.Create(new TwoFactorSessionCacheSettings { servers = factor.servers, port = factor.port, password = factor.password, database = 1, clientName = factor.clientName, connectTimeoutMilliseconds = 1000, asyncTimeoutMilliseconds = 5000, reconnectRetryPolicy = 10 }),
                    Options.Create(new AbuseCounterCacheSettings { servers = abuse.servers, port = abuse.port, password = abuse.password, database = 2, clientName = abuse.clientName, connectTimeoutMilliseconds = 1000, asyncTimeoutMilliseconds = 5000, reconnectRetryPolicy = 10 }));
                using (IHost host = new HostBuilder().ConfigureServices(services =>
                {
                    services.AddSingleton(owner); services.AddHostedService(provider => provider.GetRequiredService<CacheConnectionOwner>());
                }).Build())
                {
                    await host.StartAsync(token);
                    await Task.WhenAll(Enumerable.Range(0, 64).Select(_ => owner.StartAsync(token)));
                    await Wait(() => Task.FromResult(owner.GetDiagnostics().Values.All(d => d.Connected)), token);
                    await using var health = new HealthDependencyService(storage, owner);
                    var before = await Clients(observer.GetDatabase(), prefix);
                    Assert.InRange(before, 3, 12); // Multiplexers may have separate interactive/subscription sockets.
                    var reports = await Task.WhenAll(Enumerable.Range(0, 64).Select(_ => health.CheckAsync(token)));
                    Assert.All(reports, report => Assert.True(report.Ready));
                    Assert.All(owner.GetDiagnostics().Values, d => { Assert.Equal(1, d.InitializationAttempts); Assert.Equal(0, d.PendingInitializations); });
                    Assert.InRange(await Clients(observer.GetDatabase(), prefix), 3, 12);
                    foreach (CacheProfile role in Enum.GetValues<CacheProfile>())
                        Assert.True(await owner.Get(role).ExecuteAsync(db => db.PingAsync(), token) >= TimeSpan.Zero);
                    await host.StopAsync(token);
                }
                await Wait(async () => await Clients(observer.GetDatabase(), prefix) == 0, token);
                Assert.All(owner.GetDiagnostics().Values, d => { Assert.Equal(CacheClientLifecycle.Disposed, d.Lifecycle); Assert.False(d.HasClient); });
                await owner.DisposeAsync();
            }
            Assert.Equal(0, await Clients(observer.GetDatabase(), scope + "-host-"));
        });
    }
    [Fact]
    public async Task Borrowed_real_cache_client_survives_wrapper_and_service_disposal()
    {
        var settings = Cache("cor23n-borrowed-" + Guid.NewGuid().ToString("N"));
        var config = ActiveUserCacheService.BuildConfiguration(settings); config.AbortOnConnectFail = true;
        using var client = await ConnectionMultiplexer.ConnectAsync(config);
        var slot = new CacheConnectionSlot(settings, client);
        await using (var service = new ActiveUserCacheService(Options.Create(settings), slot)) { }
        Assert.True(await slot.ExecuteAsync(db => db.PingAsync(), TestContext.Current.CancellationToken) >= TimeSpan.Zero);
        await slot.DisposeAsync();
        Assert.True(await client.GetDatabase().PingAsync() >= TimeSpan.Zero);
        Assert.False(slot.GetDiagnostics().HasClient);
    }
    [Fact]
    public async Task Shutdown_during_real_connection_initialization_disposes_the_late_candidate()
    {
        string prefix = "cor23n-late-" + Guid.NewGuid().ToString("N");
        var settings = Cache(prefix);
        var config = ActiveUserCacheService.BuildConfiguration(Cache("cor23n-observer-" + Guid.NewGuid().ToString("N")));
        config.AbortOnConnectFail = true; config.AllowAdmin = true;
        using var observer = await ConnectionMultiplexer.ConnectAsync(config);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var connected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var slot = new CacheConnectionSlot(settings, async configuration =>
        {
            var candidate = await ConnectionMultiplexer.ConnectAsync(configuration);
            connected.TrySetResult();
            await release.Task;
            return candidate;
        });
        slot.Start();
        try
        {
            await connected.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            Assert.InRange(await Clients(observer.GetDatabase(), prefix), 1, 4);
            Task drain = slot.DisposeAsync().AsTask();
            Assert.False(drain.IsCompleted); Assert.False(slot.GetDiagnostics().HasClient);
            Assert.Equal(1, slot.GetDiagnostics().PendingInitializations);
        }
        finally
        {
            release.TrySetResult();
            await slot.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        }
        await Wait(async () => await Clients(observer.GetDatabase(), prefix) == 0, TestContext.Current.CancellationToken);
        Assert.Equal(CacheClientLifecycle.Disposed, slot.GetDiagnostics().Lifecycle);
        Assert.Equal(1, slot.GetDiagnostics().InitializationAttempts);
    }

}
