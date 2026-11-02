using Microsoft.Extensions.Options;
using Shouldly;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Services;
namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public sealed class Cor14CaptchaNonceContractTests
{
    [Fact]
    public async Task Real_store_has_one_consumer_and_preserves_deadline()
    {
        await using var owner = await Owner(); var store = Store(owner); string nonce = Guid.NewGuid().ToString("N");
        var db = owner.Get(CacheProfile.AbuseCounters).Database; string key = "reset-captcha:" + nonce;
        try
        {
            (await store.CreateAsync(nonce, TimeSpan.FromSeconds(3), default)).ShouldBeTrue();
            (await store.CreateAsync(nonce, TimeSpan.FromSeconds(30), default)).ShouldBeFalse();
            var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => store.ConsumeAsync(nonce, default)));
            results.Count(x => x).ShouldBe(1);
            (await db.StringGetAsync(key)).ToString().ShouldBe("consumed");
            var ttl = await db.KeyTimeToLiveAsync(key); ttl.ShouldNotBeNull(); ttl.Value.ShouldBeLessThanOrEqualTo(TimeSpan.FromSeconds(3));
            (await store.ConsumeAsync(nonce, default)).ShouldBeFalse();
        }
        finally { await db.KeyDeleteAsync(key); }
    }
    [Fact]
    public async Task Real_store_missing_or_evicted_nonce_cannot_resume()
    {
        await using var owner = await Owner(); var store = Store(owner); string nonce = Guid.NewGuid().ToString("N");
        (await store.ConsumeAsync(nonce, default)).ShouldBeFalse();
        (await store.CreateAsync(nonce, TimeSpan.FromSeconds(3), default)).ShouldBeTrue();
        await owner.Get(CacheProfile.AbuseCounters).Database.KeyDeleteAsync("reset-captcha:" + nonce);
        (await store.ConsumeAsync(nonce, default)).ShouldBeFalse();
    }
    [Fact]
    public async Task Real_store_expired_or_corrupt_immortal_nonce_is_denied()
    {
        await using var owner = await Owner(); var store = Store(owner); string nonce = Guid.NewGuid().ToString("N");
        var db = owner.Get(CacheProfile.AbuseCounters).Database; string key = "reset-captcha:" + nonce;
        try
        {
            (await store.CreateAsync(nonce, TimeSpan.FromMilliseconds(20), default)).ShouldBeTrue();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            while (await db.KeyExistsAsync(key)) await Task.Delay(10, timeout.Token);
            (await store.ConsumeAsync(nonce, default)).ShouldBeFalse();
            await db.StringSetAsync(key, "issued");
            (await store.ConsumeAsync(nonce, default)).ShouldBeFalse();
            (await db.KeyExistsAsync(key)).ShouldBeFalse();
        }
        finally { await db.KeyDeleteAsync(key); }
    }
    private static DragonflyCaptchaContinuationStore Store(CacheConnectionOwner owner) => new(owner, Options.Create(new AbuseCounterCacheSettings { asyncTimeoutMilliseconds = 1000 }));
    private static async Task<CacheConnectionOwner> Owner()
    {
        string endpoint = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT") ?? throw new InvalidOperationException("Run eng/correction-counter-fixture.py --captcha");
        string password = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_PASSWORD") ?? throw new InvalidOperationException("Owned cache password required");
        string[] parts = endpoint.Split(':'); if (parts.Length != 2 || parts[0] != "127.0.0.1") throw new InvalidOperationException("Owned loopback fixture required");
        int port = int.Parse(parts[1]);
        var owner = new CacheConnectionOwner(
            Options.Create(new UserCacheSettings { servers = parts[0], port = port, password = password, clientName = "cor14-active" }),
            Options.Create(new TwoFactorSessionCacheSettings { servers = parts[0], port = port, password = password, clientName = "cor14-factor" }),
            Options.Create(new AbuseCounterCacheSettings { servers = parts[0], port = port, password = password, clientName = "cor14-abuse" }));
        try
        {
            await owner.StartAsync(default); using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (!owner.Get(CacheProfile.AbuseCounters).Ready) await Task.Delay(10, timeout.Token);
            return owner;
        }
        catch { await owner.DisposeAsync(); throw; }
    }
}
