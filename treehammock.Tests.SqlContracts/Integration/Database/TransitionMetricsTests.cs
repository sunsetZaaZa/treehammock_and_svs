using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Npgsql;
using StackExchange.Redis;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Observability;
using treehammock.Tests.Infrastructure;
using treehammock.Tests.SqlContracts.Support;
namespace treehammock.Tests.Integration.Database;
[Trait("Suite", "SqlContracts")]
public sealed class Cor23PTransitionMetricsTests
{
    private sealed class OwnedStorage : StorageContext
    {
        private readonly string _schema;
        internal OwnedStorage(string schema) : base(Options.Create(Database()), Options.Create(new SecurityOperationSettings
            { HmacKeys = new() { [1] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } })) { _schema = schema; }
        private static DatabaseSettings Database()
        {
            var c = new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);
            return new() { servers = c.Host, port = c.Port, database = c.Database, userId = c.Username!, password = c.Password!, maximumPoolSize = 32, connectionTimeoutSeconds = 3 };
        }
        public override async Task<NpgsqlConnection> CreateConnection(CancellationToken token = default)
        {
            var c = await base.CreateConnection(token);
            try { await using var command = new NpgsqlCommand($"set search_path to {_schema},public", c); await command.ExecuteNonQueryAsync(token); return c; }
            catch { await c.DisposeAsync(); throw; }
        }
    }
    private static async Task<ConnectionMultiplexer> Cache()
    {
        string? endpoint = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT"), password = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_PASSWORD");
        if (string.IsNullOrWhiteSpace(endpoint) || string.IsNullOrWhiteSpace(password)) throw new InvalidOperationException("Use the owned SQL/cache fixture.");
        var options = new ConfigurationOptions { Password = password, AbortOnConnectFail = true, ConnectTimeout = 1000, AsyncTimeout = 5000 };
        options.EndPoints.Add(endpoint); return await ConnectionMultiplexer.ConnectAsync(options);
    }
    [Fact]
    public async Task Real_cache_concurrent_contenders_and_repeat_denials_count_only_the_SET_NX_winner()
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            using var capture = new Cor23PMetricCapture(); using var c1 = await Cache(); using var c2 = await Cache();
            var settings = Options.Create(new AbuseControlSettings { DragonflyTimeoutMilliseconds = 5000 }); var cacheSettings = Options.Create(new AbuseCounterCacheSettings { database = 0 });
            using var one = new DragonflyAbuseCounterStore(cacheSettings, settings, c1); using var two = new DragonflyAbuseCounterStore(cacheSettings, settings, c2);
            var key = new AbuseCounterKey(AbuseFeature.Login, AbuseCounterDimension.Account, Guid.NewGuid().ToString("N"));
            var limit = new AbuseCounterLimit(3, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30)); var db = c1.GetDatabase(0);
            try
            {
                var decisions = await fixture.Observe(Task.WhenAll(Enumerable.Range(0, 64).Select(i => (i % 2 == 0 ? one : two).IncrementAsync(key, limit, token))));
                Assert.Equal(3, decisions.Count(d => d.CanAdmit)); Assert.Equal(1, decisions.Count(d => d.CooldownCreated));
                Assert.Equal(64, capture.Sum(AbuseMetricNames.CounterAdmissionsTotal)); Assert.Equal(61, capture.Sum(AbuseMetricNames.CounterAdmissionsTotal, "denied"));
                Assert.Equal(1, capture.Sum(AbuseMetricNames.CooldownsStartedTotal, dependency: "dragonfly")); Assert.Equal(60, capture.Sum(AbuseMetricNames.CooldownBlockedAttemptsTotal));
                long ttl = (long)await db.ExecuteAsync("PTTL", key.CooldownValue);
                for (int i = 0; i < 8; i++) { Assert.True((await one.GetCooldownAsync(key, token)).Active); Assert.False((await two.IncrementAsync(key, limit, token)).CooldownCreated); }
                Assert.True((long)await db.ExecuteAsync("PTTL", key.CooldownValue) <= ttl);
                Assert.Equal(1, capture.Sum(AbuseMetricNames.CooldownsStartedTotal)); Assert.Equal(68, capture.Sum(AbuseMetricNames.CooldownBlockedAttemptsTotal));
                await one.ResetAsync(key, token); await one.IncrementAsync(key, limit, token); await one.IncrementAsync(key, limit, token); await one.IncrementAsync(key, limit, token);
                Assert.True((await one.IncrementAsync(key, limit, token)).CooldownCreated); Assert.Equal(2, capture.Sum(AbuseMetricNames.CooldownsStartedTotal));
                Assert.All(capture.Values, m => Assert.DoesNotContain(key.SafeId, string.Join(" ", m.Tags.Values)));
            }
            finally { await db.KeyDeleteAsync(new RedisKey[] { key.Value, key.CooldownValue }); }
        });
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Real_durable_transition_counts_after_commit_and_wrapper_counts_one_outcome(bool breakCache)
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            using var capture = new Cor23PMetricCapture(); await using var storage = new OwnedStorage(fixture.Schema); using var connection = await Cache();
            var settings = new AbuseControlSettings { CounterFailureMode = AbuseCounterFailureMode.RequirePostgreSqlBudgetV1, PostgreSqlFallbackPolicies = [AbuseFeature.Login], PostgreSqlBudgetTimeoutMilliseconds = 5000, DragonflyTimeoutMilliseconds = 5000 };
            var budget = new PostgreSqlAbuseBudgetStore(storage, Options.Create(settings));
            using var store = new DragonflyAbuseCounterStore(Options.Create(new AbuseCounterCacheSettings { database = 0 }), Options.Create(settings), connection, budget);
            var key = new AbuseCounterKey(AbuseFeature.Login, AbuseCounterDimension.Account, Guid.NewGuid().ToString("N")); var limit = new AbuseCounterLimit(1, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30)); var db = connection.GetDatabase(0);
            try
            {
                if (breakCache) await db.ListLeftPushAsync(key.Value, "private-wrong-type");
                var decisions = await fixture.Observe(Task.WhenAll(Enumerable.Range(0, 16).Select(i => store.IncrementAsync(key, limit, token))));
                Assert.Equal(1, decisions.Count(d => d.CanAdmit)); Assert.Equal(1, decisions.Count(d => d.CooldownCreated));
                Assert.Equal(16, capture.Sum(AbuseMetricNames.CounterAdmissionsTotal)); Assert.Equal(15, capture.Sum(AbuseMetricNames.CounterAdmissionsTotal, "denied"));
                Assert.Equal(1, capture.Sum(AbuseMetricNames.CooldownsStartedTotal, dependency: "postgresql")); Assert.Equal(0, capture.Sum(AbuseMetricNames.CooldownsStartedTotal, dependency: "dragonfly"));
                Assert.Equal(14, capture.Sum(AbuseMetricNames.CooldownBlockedAttemptsTotal));
                await using var observer = await storage.CreateConnection(token);
                await using var command = new NpgsqlCommand("select count(*) from abuse_admission_budgets_v1 where budget_hash=@hash and cooldown_until>clock_timestamp()", observer);
                command.Parameters.AddWithValue("hash", PostgreSqlAbuseBudgetStore.BudgetHash(key)); Assert.Equal(1L, (long)(await command.ExecuteScalarAsync(token))!);
                for (int i = 0; i < 8; i++) Assert.True((await store.GetCooldownAsync(key, token)).Active);
                Assert.Equal(1, capture.Sum(AbuseMetricNames.CooldownsStartedTotal)); Assert.Equal(16, capture.Sum(AbuseMetricNames.CounterAdmissionsTotal));
            }
            finally { await db.KeyDeleteAsync(new RedisKey[] { key.Value, key.CooldownValue }); }
        });
    }
    [Fact]
    public async Task Real_zero_cooldown_limit_denials_never_count_creations_or_existing_cooldown_blocks()
    {
        await SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            using var capture = new Cor23PMetricCapture(); using var connection = await Cache();
            using var store = new DragonflyAbuseCounterStore(Options.Create(new AbuseCounterCacheSettings { database = 0 }), Options.Create(new AbuseControlSettings { DragonflyTimeoutMilliseconds = 5000 }), connection);
            var key = new AbuseCounterKey(AbuseFeature.Signup, AbuseCounterDimension.IpFingerprint, Guid.NewGuid().ToString("N")); var limit = new AbuseCounterLimit(1, TimeSpan.FromSeconds(30), TimeSpan.Zero);
            try
            {
                var decisions = await fixture.Observe(Task.WhenAll(Enumerable.Range(0, 16).Select(i => store.IncrementAsync(key, limit, token))));
                Assert.Equal(1, decisions.Count(d => d.CanAdmit)); Assert.Equal(15, capture.Sum(AbuseMetricNames.CounterAdmissionsTotal, "denied"));
                Assert.Equal(0, capture.Sum(AbuseMetricNames.CooldownsStartedTotal)); Assert.Equal(0, capture.Sum(AbuseMetricNames.CooldownBlockedAttemptsTotal));
            }
            finally { await connection.GetDatabase(0).KeyDeleteAsync(new RedisKey[] { key.Value, key.CooldownValue }); }
        });
    }
}
