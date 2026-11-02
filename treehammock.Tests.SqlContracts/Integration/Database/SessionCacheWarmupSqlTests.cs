using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using treehammock.Repos;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Services;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

// Actual owned PostgreSQL + Redis/Dragonfly fixture. Yugabyte requires its own deployment qualification.
[Trait("Suite", "SqlContracts")]
public sealed class SessionCacheWarmupSqlTests
{
    [Fact]
    public Task Candidate_scan_excludes_inactive_accounts_and_sessions_and_honors_keyset_limits()
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var connection = await fixture.OpenConnectionAsync();
            var seeds = new List<Cor09SessionFamilyTests.SeededSession>();
            for (int i = 0; i < 10; i++) seeds.Add(await Cor09SessionFamilyTests.Seed(fixture, connection, token));
            await fixture.ExecuteAsync(connection, $"""
                update sessions set access_expiration=clock_timestamp()-interval '1 second' where access_token_hash='{seeds[2].Hash}';
                update sessions set access_expiration=clock_timestamp()-interval '1 second',session_expiration=clock_timestamp()-interval '1 second' where access_token_hash='{seeds[3].Hash}';
                update sessions set cut_off=clock_timestamp()-interval '1 second' where access_token_hash='{seeds[4].Hash}';
                update accounts set cut_off=clock_timestamp()-interval '1 second' where account_id='{seeds[5].Account}';
                update accounts set security_stamp=gen_random_uuid() where account_id='{seeds[6].Account}';
                update accounts set verify_status=0 where account_id='{seeds[7].Account}';
                update accounts set unlock_when=clock_timestamp()+interval '1 day' where account_id='{seeds[8].Account}';
                update sessions set session_lifespan=null where access_token_hash='{seeds[9].Hash}';
                """, cancellation: token);
            await using var storage = new Cor09RefreshHttpTests.FixtureStorage(fixture, SecurityOperationSettings.Isolated());
            var repo = new SessionCacheWarmupRepo(storage);
            var all = await repo.ReadCandidateHashesAsync(null, 100, token);
            Assert.Equal(2, all.Count); Assert.Contains(seeds[0].Hash, all); Assert.Contains(seeds[1].Hash, all);
            var first = await repo.ReadCandidateHashesAsync(null, 1, token);
            var second = await repo.ReadCandidateHashesAsync(first.Single(), 1, token);
            Assert.Equal(all[0], first.Single()); Assert.Equal(all[1], second.Single());
            Assert.Empty(await repo.ReadCandidateHashesAsync(second.Single(), 1, token));
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => repo.ReadCandidateHashesAsync(null, 1001, token));
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Real_cache_warmup_restores_authoritative_payload_preserves_existing_entries_and_cannot_authorize_revocation()
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var connection = await fixture.OpenConnectionAsync();
            var seed = await Cor09SessionFamilyTests.Seed(fixture, connection, token);
            await using var storage = new Cor09RefreshHttpTests.FixtureStorage(fixture, SecurityOperationSettings.Isolated());
            var candidates = new SessionCacheWarmupRepo(storage);
            var sessions = new SessionRepo(storage, Options.Create(Cor09SessionFamilyTests.Settings()), NullLogger<SessionRepo>.Instance);
            string endpoint = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT")
                ?? throw new InvalidOperationException("Use the owned SQL/cache fixture.");
            string password = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_PASSWORD")
                ?? throw new InvalidOperationException("Use the owned SQL/cache fixture.");
            var config = ConfigurationOptions.Parse(endpoint); config.Password = password;
            config.AbortOnConnectFail = true; config.ClientName = "warmup-" + fixture.Schema;
            using var client = await ConnectionMultiplexer.ConnectAsync(config);
            var settings = Options.Create(new UserCacheSettings { database = 0, asyncTimeoutMilliseconds = 1000 });
            await using var cache = new ActiveUserCacheService(settings, client);
            using var worker = new SessionCacheWarmupWorker(candidates, sessions, cache,
                Options.Create(new SessionCacheWarmupSettings { BatchSize = 10, CacheTtlSeconds = 60 }),
                Options.Create(Cor09SessionFamilyTests.Settings()), NullLogger<SessionCacheWarmupWorker>.Instance);
            var database = client.GetDatabase(0);
            try
            {
                Assert.Equal(1, await worker.WarmBatchAsync(token));
                var hydrated = await cache.GetSession(seed.Hash, token); Assert.NotNull(hydrated);
                Assert.Equal(seed.Account, hydrated.accountId); Assert.Equal(seed.Stamp, hydrated.accountSecurityStamp);
                Assert.Equal(seed.Family, hydrated.familyId); Assert.Equal(1, hydrated.generation);
                Assert.Equal(seed.Key, hydrated.refreshToken); Assert.NotNull(hydrated.entitlements);
                var ttl = await database.KeyTimeToLiveAsync(seed.Hash);
                Assert.NotNull(ttl); Assert.InRange(ttl.Value.TotalSeconds, 0.01, 60);
                var before = await database.StringGetAsync(seed.Hash);
                Assert.Equal(0, await worker.WarmBatchAsync(token)); // NX never replaces even the same payload/TTL.
                Assert.Equal(before, await database.StringGetAsync(seed.Hash));
                await fixture.ExecuteAsync(connection, $"select * from logout_current_session('{seed.Account}','{seed.Hash}','{seed.Stamp}')", cancellation: token);
                var trust = await sessions.ValidateCachedSessionTrust(seed.Hash, hydrated.accountId, hydrated.securityStamp, hydrated.accountSecurityStamp, token);
                Assert.NotNull(trust); Assert.False(trust.Succeeded);
                // The cached snapshot is harmless: middleware checks this same trust result on every hit.
                await cache.RevokeSession(seed.Hash, token);
                Assert.Equal(0, await worker.WarmBatchAsync(token)); Assert.Null(await cache.GetSession(seed.Hash, token));
            }
            finally { await database.KeyDeleteAsync(seed.Hash); }
        }, TestContext.Current.CancellationToken);
}
