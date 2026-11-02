using System.Diagnostics;
using System.Security.Cryptography;
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
public sealed class Cor23OReadinessBudgetTests
{
    private static DatabaseSettings Database(int pool = 1)
    {
        var c = new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);
        return new() { servers = c.Host, port = c.Port, database = c.Database, userId = c.Username!, password = c.Password!, maximumPoolSize = pool, connectionTimeoutSeconds = 3 };
    }
    private static SecurityOperationSettings Security() => new() { HmacKeys = new() { [1] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } };
    private static CacheConnectionOwner Owner(Func<ConfigurationOptions, Task<IConnectionMultiplexer>>? connect = null)
    {
        string? endpoint = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT");
        string? password = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_PASSWORD");
        if (string.IsNullOrWhiteSpace(endpoint) || string.IsNullOrWhiteSpace(password)) throw new InvalidOperationException("Use the owned SQL/cache fixture.");
        var (host, port) = ConfigurationOptions.Parse(endpoint).EndPoints.Single() switch
        {
            System.Net.DnsEndPoint dns => (dns.Host, dns.Port), System.Net.IPEndPoint ip => (ip.Address.ToString(), ip.Port),
            _ => throw new InvalidOperationException("Fixture endpoint must be TCP.")
        };
        string name = "cor23o-" + Guid.NewGuid().ToString("N");
        return new(Options.Create(new UserCacheSettings { servers = host, port = port, password = password, clientName = name + "-active", connectTimeoutMilliseconds = 500, asyncTimeoutMilliseconds = 1000 }),
            Options.Create(new TwoFactorSessionCacheSettings { servers = host, port = port, password = password, clientName = name + "-factor", database = 1, connectTimeoutMilliseconds = 500, asyncTimeoutMilliseconds = 1000 }),
            Options.Create(new AbuseCounterCacheSettings { servers = host, port = port, password = password, clientName = name + "-abuse", database = 2, connectTimeoutMilliseconds = 500, asyncTimeoutMilliseconds = 1000 }), connect);
    }
    private static async Task Until(Func<bool> condition, CancellationToken token)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(token); limit.CancelAfter(TimeSpan.FromSeconds(5));
        while (!condition()) await Task.Delay(10, limit.Token);
    }
    [Fact]
    public async Task Real_one_slot_PostgreSQL_pool_pressure_is_bounded_and_recovers_after_release()
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            await using var owner = Owner(); await owner.StartAsync(token); await Until(() => owner.GetDiagnostics().Values.All(d => d.Connected), token);
            await using var storage = new StorageContext(Options.Create(Database()), Options.Create(Security()));
            await using var held = await storage.CreateConnection(token);
            await using var service = new HealthDependencyService(storage, owner, Options.Create(new HealthProbeSettings
                { TotalTimeoutMilliseconds = 300, DependencyTimeoutMilliseconds = 100, SampleMaxAgeMilliseconds = 10 }));
            var timer = Stopwatch.StartNew(); var reports = await Task.WhenAll(Enumerable.Range(0, 64).Select(i => service.CheckAsync(token)));
            Assert.All(reports, r => Assert.False(r.Ready)); Assert.True(timer.Elapsed < TimeSpan.FromMilliseconds(650));
            Assert.All(service.GetDiagnostics().PendingOperations.Values, n => Assert.InRange(n, 0, 1));
            await held.DisposeAsync(); await Task.Delay(20, token);
            Assert.True((await service.CheckAsync(token)).Ready);
            Assert.All(owner.GetDiagnostics().Values, d => Assert.Equal(1, d.InitializationAttempts));
            await service.DisposeAsync(); Assert.All(owner.GetDiagnostics().Values, d => Assert.True(d.Connected));
        });
    }
    private sealed class DelayedStorage : StorageContext
    {
        internal readonly TaskCompletionSource<NpgsqlConnection> Acquired = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Delay = true;
        public DelayedStorage() : base(Options.Create(Database()), Options.Create(Security())) { }
        public override async Task<NpgsqlConnection> CreateConnection(CancellationToken token = default)
        {
            var connection = await base.CreateConnection(token);
            if (Delay) { Acquired.TrySetResult(connection); await Release.Task; } // Private late-acquisition fault barrier ignores cancellation.
            return connection;
        }
    }
    [Fact]
    public async Task Late_real_PostgreSQL_acquisition_is_disposed_without_poisoning_the_one_slot_pool()
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            await using var owner = Owner(); await owner.StartAsync(token); await Until(() => owner.GetDiagnostics().Values.All(d => d.Connected), token);
            await using var storage = new DelayedStorage { Delay = false };
            await using (var warm = await storage.CreateConnection(token)) { }
            storage.Delay = true;
            await using var service = new HealthDependencyService(storage, owner, Options.Create(new HealthProbeSettings
                { TotalTimeoutMilliseconds = 300, DependencyTimeoutMilliseconds = 100, SampleMaxAgeMilliseconds = 10 }));
            try
            {
                var check = service.CheckAsync(token); var acquired = await storage.Acquired.Task.WaitAsync(token);
                Assert.False((await check).Ready); Assert.Equal(1, service.GetDiagnostics().PendingOperations[HealthDependency.PostgreSql]);
                storage.Delay = false; storage.Release.TrySetResult();
                await Until(() => service.GetDiagnostics().PendingOperations[HealthDependency.PostgreSql] == 0, token);
                Assert.Equal(System.Data.ConnectionState.Closed, acquired.State);
                await Task.Delay(20, token); Assert.True((await service.CheckAsync(token)).Ready);
            }
            finally { storage.Release.TrySetResult(); }
        });
    }
    private sealed class SlowSql(StorageContext storage, HealthProbeClient normal) : IHealthProbeClient
    {
        internal bool Slow = true;
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<bool> ProbeAsync(HealthDependency dependency, CancellationToken token)
        {
            if (dependency != HealthDependency.PostgreSql || !Slow) return await normal.ProbeAsync(dependency, token);
            await using var connection = await storage.CreateConnection(token);
            await using var command = new NpgsqlCommand("select pg_sleep(10)", connection); Entered.TrySetResult();
            _ = await command.ExecuteScalarAsync(token); return true;
        }
    }
    [Fact]
    public async Task Real_delayed_SQL_command_receives_budget_cancellation_and_releases_resources_for_recovery()
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            await using var owner = Owner(); await owner.StartAsync(token); await Until(() => owner.GetDiagnostics().Values.All(d => d.Connected), token);
            await using var storage = new StorageContext(Options.Create(Database()), Options.Create(Security()));
            await using (var warm = await storage.CreateConnection(token)) { }
            var backend = new SlowSql(storage, new HealthProbeClient(storage, owner));
            await using var service = new HealthDependencyService(backend, new HealthProbeSettings
                { TotalTimeoutMilliseconds = 300, DependencyTimeoutMilliseconds = 100, SampleMaxAgeMilliseconds = 10 });
            var check = service.CheckAsync(token); await backend.Entered.Task.WaitAsync(token); Assert.False((await check).Ready);
            await Until(() => service.GetDiagnostics().PendingOperations[HealthDependency.PostgreSql] == 0, token);
            backend.Slow = false; await Task.Delay(20, token); Assert.True((await service.CheckAsync(token)).Ready);
        });
    }
    [Fact]
    public async Task Health_does_not_wait_on_real_cache_initialization_or_add_clients_and_recovers_on_its_shared_owner()
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); int attempts = 0;
            await using var owner = Owner(async configuration =>
            {
                Interlocked.Increment(ref attempts); await release.Task; return await ConnectionMultiplexer.ConnectAsync(configuration);
            });
            await using var storage = new StorageContext(Options.Create(Database()), Options.Create(Security()));
            await using var service = new HealthDependencyService(storage, owner, Options.Create(new HealthProbeSettings
                { TotalTimeoutMilliseconds = 500, DependencyTimeoutMilliseconds = 250, SampleMaxAgeMilliseconds = 10 }));
            await owner.StartAsync(token); await Until(() => Volatile.Read(ref attempts) == 3, token);
            try
            {
                Assert.False((await service.CheckAsync(token)).Ready); Assert.Equal(3, attempts);
                release.TrySetResult(); await Until(() => owner.GetDiagnostics().Values.All(d => d.Connected), token);
                await Task.Delay(20, token); Assert.True((await service.CheckAsync(token)).Ready); Assert.Equal(3, attempts);
            }
            finally { release.TrySetResult(); }
        });
    }
}
