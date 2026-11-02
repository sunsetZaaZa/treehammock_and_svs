using Microsoft.Extensions.Options;
using Shouldly;
using StackExchange.Redis;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class Cor05AtomicCounterTests
{
    [Fact]
    public async Task Real_adapter_repairs_immortal_counter_and_rollover_restores_admission()
    {
        using var connection = await Connect();
        var database = connection.GetDatabase(0);
        using var store = Store(connection);
        var key = Key();
        var limit = new AbuseCounterLimit(5, TimeSpan.FromMilliseconds(300), TimeSpan.Zero);
        try
        {
            await database.StringSetAsync(key.Value, 9); // TTL-less legacy counter greater than one.
            var denied = await store.IncrementAsync(key, limit);
            denied.Allowed.ShouldBeFalse();
            denied.CurrentCount.ShouldBe(10);
            denied.ReasonCode.ShouldBe(AbuseReasonCodes.CounterLimitExceeded);
            var ttl = await database.KeyTimeToLiveAsync(key.Value);
            ttl.ShouldNotBeNull();
            ttl.Value.ShouldBeLessThanOrEqualTo(limit.Window);
            await WaitForExpiry(database, key.Value);
            var admitted = await store.IncrementAsync(key, limit);
            admitted.Allowed.ShouldBeTrue();
            admitted.CurrentCount.ShouldBe(1);
        }
        finally { await store.ResetAsync(key); }
    }

    [Fact]
    public async Task Concurrent_real_admission_obeys_exact_limit_and_cooldown_does_not_increment()
    {
        using var connection = await Connect();
        var database = connection.GetDatabase(0);
        using var store = Store(connection);
        var key = Key();
        try
        {
            var limit = new AbuseCounterLimit(8, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5));
            var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => store.IncrementAsync(key, limit)));
            results.Count(result => result.Allowed).ShouldBe(8);
            (await database.StringGetAsync(key.Value)).ToString().ShouldBe("9");
            var active = await store.IncrementAsync(key, limit);
            active.ReasonCode.ShouldBe(AbuseReasonCodes.FailureCooldownActive);
            active.CurrentCount.ShouldBe(9);
            active.RetryAfter.ShouldNotBeNull();
            (await database.KeyTimeToLiveAsync(key.Value)).ShouldNotBeNull();
            (await database.KeyTimeToLiveAsync(key.CooldownValue)).ShouldNotBeNull();
        }
        finally { await store.ResetAsync(key); }
    }

    [Fact]
    public async Task Cooldown_lookup_repairs_legacy_immortal_key_and_reset_is_scoped()
    {
        using var connection = await Connect();
        var database = connection.GetDatabase(0);
        using var store = Store(connection, new AbuseControlSettings
            { FailureCooldown = new FailureCooldownSettings { CooldownSeconds = 1 } });
        var key = Key();
        string sentinel = "cor05:unrelated:" + Guid.NewGuid().ToString("N");
        try
        {
            await database.StringSetAsync(sentinel, "keep", TimeSpan.FromSeconds(10));
            await database.StringSetAsync(key.CooldownValue, "legacy");
            (await store.GetCooldownAsync(key)).Active.ShouldBeTrue();
            (await database.KeyTimeToLiveAsync(key.CooldownValue)).ShouldNotBeNull();
            await WaitForExpiry(database, key.CooldownValue);
            (await store.GetCooldownAsync(key)).Active.ShouldBeFalse();
            await store.ResetAsync(key);
            (await database.StringGetAsync(sentinel)).ToString().ShouldBe("keep");
        }
        finally { await database.KeyDeleteAsync(sentinel); await store.ResetAsync(key); }
    }

    private static async Task WaitForExpiry(IDatabase database, RedisKey key)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (await database.KeyExistsAsync(key)) await Task.Delay(10, deadline.Token);
    }
    private static AbuseCounterKey Key() => new(AbuseFeature.TwoFactorChallenge, AbuseCounterDimension.Challenge, Guid.NewGuid().ToString("N"));
    private static DragonflyAbuseCounterStore Store(IConnectionMultiplexer connection, AbuseControlSettings? settings = null)
        => new(Options.Create(new AbuseCounterCacheSettings { database = 0 }),
            Options.Create(settings ?? new AbuseControlSettings { DragonflyTimeoutMilliseconds = 1000 }), connection);
    private static async Task<ConnectionMultiplexer> Connect()
    {
        string? endpoint = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT");
        string? password = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_PASSWORD");
        if (string.IsNullOrWhiteSpace(endpoint) || string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException("Run eng/correction-counter-fixture.py for pinned Redis and Dragonfly qualification.");
        var options = new ConfigurationOptions { Password = password, AbortOnConnectFail = true,
            ConnectTimeout = 1000, AsyncTimeout = 1000, SyncTimeout = 1000 };
        options.EndPoints.Add(endpoint);
        return await ConnectionMultiplexer.ConnectAsync(options);
    }
}
