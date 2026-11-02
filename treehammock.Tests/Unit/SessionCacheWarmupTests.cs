using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using StackExchange.Redis;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Repos;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Services;
using treehammock.Tests.Support;

namespace treehammock.Tests.Unit;

public sealed class SessionCacheWarmupTests
{
    private static ActiveSession BuildSession(Instant? at = null)
    {
        var now = at ?? SystemClock.Instance.GetCurrentInstant();
        var session = new ActiveSession(Guid.NewGuid(), new byte[64], 0, now,
            Period.FromHours(1), now + Duration.FromMinutes(10), now + Duration.FromHours(1), null, treehammock.RiggingSupport.Enum.FeatureSet.basic,
            accountSecurityStamp: Guid.NewGuid());
        session.entitlements = EntitlementTestData.ForAccount(session.accountId, evaluated: now);
        return session;
    }
    private sealed class Fixture : IDisposable
    {
        public readonly ISessionCacheWarmupRepo Candidates = Substitute.For<ISessionCacheWarmupRepo>();
        public readonly ISessionRepo Sessions = Substitute.For<ISessionRepo>();
        public readonly IActiveUserCacheService Cache = Substitute.For<IActiveUserCacheService>();
        public SessionCacheWarmupWorker Worker { get; }
        public Fixture(SessionCacheWarmupSettings? settings = null)
        {
            Worker = new(Candidates, Sessions, Cache, Options.Create(settings ?? new() { BatchSize = 2 }),
                Options.Create(new JWTSettings { RefreshTokenAliveMinutes = 10 }), NullLogger<SessionCacheWarmupWorker>.Instance);
        }
        public void Dispose() => Worker.Dispose();
    }

    [Theory]
    [InlineData("cache", 30)] [InlineData("configured", 60)] [InlineData("access", 40)]
    [InlineData("hard", 50)] [InlineData("cutoff", 20)] [InlineData("boundary", 10)]
    public void Ttl_never_exceeds_any_authority_or_configured_lifetime(string cap, int expected)
    {
        var now = SystemClock.Instance.GetCurrentInstant(); var session = BuildSession(now);
        var jwt = new JWTSettings { RefreshTokenAliveMinutes = cap == "configured" ? 1 : 10 };
        if (cap == "access") session.accessExpiration = now + Duration.FromSeconds(40);
        if (cap == "hard") session.sessionExpiration = now + Duration.FromSeconds(50);
        if (cap == "cutoff") session.cutOff = now + Duration.FromSeconds(20);
        if (cap == "boundary") session.entitlements = session.entitlements! with { NextBoundary = now + Duration.FromSeconds(10) };
        Assert.Equal(TimeSpan.FromSeconds(expected), SessionCacheWarmupWorker.CalculateTtl(session, jwt, cap == "cache" ? 30 : 300, now));
    }

    [Theory]
    [InlineData("expired")] [InlineData("cutoff")] [InlineData("boundary")] [InlineData("missing")]
    [InlineData("wrong_account")] [InlineData("future_projection")] [InlineData("zero_configured")]
    public void Expired_or_untrusted_projection_is_never_warmed(string fault)
    {
        var now = SystemClock.Instance.GetCurrentInstant(); var session = BuildSession(now);
        if (fault == "expired") session.accessExpiration = now;
        if (fault == "cutoff") session.cutOff = now;
        if (fault == "boundary") session.entitlements = session.entitlements! with { NextBoundary = now };
        if (fault == "missing") session.entitlements = null;
        if (fault == "wrong_account") session.entitlements = session.entitlements! with { AccountId = Guid.NewGuid() };
        if (fault == "future_projection") session.entitlements = session.entitlements! with { EvaluatedAt = now + Duration.FromSeconds(1) };
        var jwt = new JWTSettings { RefreshTokenAliveMinutes = fault == "zero_configured" ? 0 : 10 };
        Assert.Equal(TimeSpan.Zero, SessionCacheWarmupWorker.CalculateTtl(session, jwt, 300, now));
    }

    [Fact]
    public async Task Pages_are_bounded_and_wrap_only_after_the_end_of_the_scan()
    {
        using var f = new Fixture();
        f.Candidates.ReadCandidateHashesAsync(null, 2, Arg.Any<CancellationToken>()).Returns(new[] { "a", "b" });
        f.Candidates.ReadCandidateHashesAsync("b", 2, Arg.Any<CancellationToken>()).Returns(new[] { "c" });
        f.Sessions.GetSession(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(_ => BuildSession().toSession());
        f.Cache.WarmSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>()).Returns(true);
        Assert.Equal(2, await f.Worker.WarmBatchAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, await f.Worker.WarmBatchAsync(TestContext.Current.CancellationToken));
        Assert.Equal(2, await f.Worker.WarmBatchAsync(TestContext.Current.CancellationToken));
        await f.Candidates.Received(2).ReadCandidateHashesAsync(null, 2, Arg.Any<CancellationToken>());
        await f.Candidates.Received(1).ReadCandidateHashesAsync("b", 2, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Failed_entry_is_retried_without_replaying_completed_entries()
    {
        using var f = new Fixture();
        f.Candidates.ReadCandidateHashesAsync(null, 2, Arg.Any<CancellationToken>()).Returns(new[] { "a", "b" });
        f.Candidates.ReadCandidateHashesAsync("a", 2, Arg.Any<CancellationToken>()).Returns(new[] { "b" });
        f.Sessions.GetSession(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(_ => BuildSession().toSession());
        f.Cache.WarmSession("a", Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>()).Returns(true);
        int attempts = 0;
        f.Cache.WarmSession("b", Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(_ => Interlocked.Increment(ref attempts) == 1 ? Task.FromException<bool>(new InvalidOperationException()) : Task.FromResult(true));
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Worker.WarmBatchAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, await f.Worker.WarmBatchAsync(TestContext.Current.CancellationToken));
        await f.Cache.Received(1).WarmSession("a", Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
        await f.Cache.Received(2).WarmSession("b", Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Deleted_expired_and_incomplete_sessions_are_skipped_after_enumeration()
    {
        using var f = new Fixture(new() { BatchSize = 3 }); var expired = BuildSession().toSession();
        expired.accessExpiration = SystemClock.Instance.GetCurrentInstant() - Duration.FromSeconds(1);
        var incomplete = BuildSession().toSession(); incomplete.sessionLifespan = null;
        f.Candidates.ReadCandidateHashesAsync(null, 3, Arg.Any<CancellationToken>()).Returns(new[] { "deleted", "expired", "incomplete" });
        f.Sessions.GetSession("deleted", Arg.Any<CancellationToken>()).Returns((Session?)null);
        f.Sessions.GetSession("expired", Arg.Any<CancellationToken>()).Returns(expired);
        f.Sessions.GetSession("incomplete", Arg.Any<CancellationToken>()).Returns(incomplete);
        Assert.Equal(0, await f.Worker.WarmBatchAsync(TestContext.Current.CancellationToken));
        await f.Cache.DidNotReceiveWithAnyArgs().WarmSession(default!, default!, default, default);
    }

    [Fact]
    public async Task Oversized_candidate_page_is_rejected_before_any_session_lookup()
    {
        using var f = new Fixture();
        f.Candidates.ReadCandidateHashesAsync(null, 2, Arg.Any<CancellationToken>()).Returns(new[] { "a", "b", "c" });
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Worker.WarmBatchAsync(TestContext.Current.CancellationToken));
        await f.Sessions.DidNotReceiveWithAnyArgs().GetSession(default!, default);
    }

    [Fact]
    public async Task Disabled_worker_does_not_query_dependencies()
    {
        using var f = new Fixture(new() { Enabled = false });
        await f.Worker.StartAsync(TestContext.Current.CancellationToken);
        await f.Worker.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);
        await f.Candidates.DidNotReceiveWithAnyArgs().ReadCandidateHashesAsync(default, default, default);
    }

    [Fact]
    public async Task Duration_cancels_inflight_batch_and_startup_is_nonblocking()
    {
        using var f = new Fixture(new() { Enabled = true, DurationSeconds = 1, BatchTimeoutMilliseconds = 5000 });
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Candidates.ReadCandidateHashesAsync(Arg.Any<string?>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(async call => { entered.TrySetResult(); await Task.Delay(Timeout.Infinite, call.ArgAt<CancellationToken>(2)); return (IReadOnlyList<string>)Array.Empty<string>(); });
        try
        {
            await f.Worker.StartAsync(TestContext.Current.CancellationToken).WaitAsync(TimeSpan.FromSeconds(2));
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);
            await f.Worker.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
            await f.Candidates.Received(1).ReadCandidateHashesAsync(null, 100, Arg.Any<CancellationToken>());
        }
        finally { await f.Worker.StopAsync(CancellationToken.None); }
    }

    [Fact]
    public async Task Failed_batches_wait_for_interval_instead_of_spinning_and_shutdown_cancels_delay()
    {
        using var f = new Fixture(new() { Enabled = true, DurationSeconds = 0, IntervalSeconds = 3600 });
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Candidates.ReadCandidateHashesAsync(Arg.Any<string?>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(_ => { entered.TrySetResult(); return Task.FromException<IReadOnlyList<string>>(new InvalidOperationException()); });
        try
        {
            await f.Worker.StartAsync(TestContext.Current.CancellationToken);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);
        }
        finally { await f.Worker.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2)); }
        await f.Candidates.Received(1).ReadCandidateHashesAsync(null, 100, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Batch_deadline_cancels_a_stalled_dependency_without_starting_another_batch()
    {
        using var f = new Fixture(new() { Enabled = true, DurationSeconds = 0, BatchTimeoutMilliseconds = 100, IntervalSeconds = 3600 });
        var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Candidates.ReadCandidateHashesAsync(Arg.Any<string?>(), Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(async call =>
            {
                try { await Task.Delay(Timeout.Infinite, call.ArgAt<CancellationToken>(2)); }
                finally { canceled.TrySetResult(); }
                return (IReadOnlyList<string>)Array.Empty<string>();
            });
        try
        {
            await f.Worker.StartAsync(TestContext.Current.CancellationToken);
            await canceled.Task.WaitAsync(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);
        }
        finally { await f.Worker.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2)); }
        await f.Candidates.Received(1).ReadCandidateHashesAsync(null, 100, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Shutdown_cancels_session_reload_before_any_cache_insert()
    {
        using var f = new Fixture(new() { Enabled = true, DurationSeconds = 0 });
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Candidates.ReadCandidateHashesAsync(null, 100, Arg.Any<CancellationToken>()).Returns(new[] { "a" });
        f.Sessions.GetSession("a", Arg.Any<CancellationToken>()).Returns(async call =>
        {
            entered.TrySetResult(); await Task.Delay(Timeout.Infinite, call.ArgAt<CancellationToken>(1)); return (Session?)null;
        });
        try
        {
            await f.Worker.StartAsync(TestContext.Current.CancellationToken);
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);
        }
        finally { await f.Worker.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2)); }
        await f.Cache.DidNotReceiveWithAnyArgs().WarmSession(default!, default!, default, default);
    }

    [Fact]
    public async Task Cache_warmup_uses_atomic_insert_only_and_never_writes_zero_ttl()
    {
        var database = Substitute.For<IDatabase>(); var connection = Substitute.For<IConnectionMultiplexer>();
        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object>()).Returns(database);
        await using var cache = new ActiveUserCacheService(Options.Create(new UserCacheSettings()), connection);
        database.StringSetAsync(Arg.Any<RedisKey>(), Arg.Any<RedisValue>(), Arg.Any<TimeSpan?>(), When.NotExists, CommandFlags.PreferMaster).Returns(false);
        Assert.False(await cache.WarmSession("hash", BuildSession(), TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken));
        Assert.False(await cache.WarmSession("expired", BuildSession(), TimeSpan.Zero, TestContext.Current.CancellationToken));
        await database.Received(1).StringSetAsync("hash", Arg.Any<RedisValue>(), TimeSpan.FromSeconds(30), When.NotExists, CommandFlags.PreferMaster);
        await database.DidNotReceive().StringSetAsync("expired", Arg.Any<RedisValue>(), Arg.Any<TimeSpan?>(), Arg.Any<When>(), Arg.Any<CommandFlags>());
    }

    [Theory]
    [InlineData("BatchSize", "0")] [InlineData("BatchSize", "1001")]
    [InlineData("IntervalSeconds", "0")] [InlineData("DurationSeconds", "-1")]
    [InlineData("CacheTtlSeconds", "0")] [InlineData("BatchTimeoutMilliseconds", "30001")]
    public void Invalid_environment_bound_values_are_rejected(string property, string value)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { [property] = value }).Build();
        var settings = config.Get<SessionCacheWarmupSettings>()!;
        Assert.False(Validator.TryValidateObject(settings, new ValidationContext(settings), new List<ValidationResult>(), true));
    }

    [Fact]
    public void Double_underscore_environment_variables_bind_all_six_knobs()
    {
        string prefix = "TREEHAMMOCK_WARMUP_TEST_" + Guid.NewGuid().ToString("N") + "_";
        var values = new Dictionary<string, string> { ["Enabled"] = "true", ["BatchSize"] = "17",
            ["IntervalSeconds"] = "9", ["DurationSeconds"] = "0", ["CacheTtlSeconds"] = "80", ["BatchTimeoutMilliseconds"] = "450" };
        try
        {
            foreach (var value in values) Environment.SetEnvironmentVariable(prefix + "SessionCacheWarmupSettings__" + value.Key, value.Value);
            var config = new ConfigurationBuilder().AddEnvironmentVariables(prefix).Build();
            var settings = config.GetSection("SessionCacheWarmupSettings").Get<SessionCacheWarmupSettings>()!;
            Assert.True(settings.Enabled); Assert.Equal(17, settings.BatchSize); Assert.Equal(9, settings.IntervalSeconds);
            Assert.Equal(0, settings.DurationSeconds); Assert.Equal(80, settings.CacheTtlSeconds); Assert.Equal(450, settings.BatchTimeoutMilliseconds);
        }
        finally { foreach (string key in values.Keys) Environment.SetEnvironmentVariable(prefix + "SessionCacheWarmupSettings__" + key, null); }
    }

    [Fact]
    public void All_warmup_knobs_bind_from_configuration_including_continuous_duration()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["SessionCacheWarmupSettings:Enabled"] = "true", ["SessionCacheWarmupSettings:BatchSize"] = "17",
            ["SessionCacheWarmupSettings:IntervalSeconds"] = "9", ["SessionCacheWarmupSettings:DurationSeconds"] = "0",
            ["SessionCacheWarmupSettings:CacheTtlSeconds"] = "80", ["SessionCacheWarmupSettings:BatchTimeoutMilliseconds"] = "450" }).Build();
        var s = config.GetSection("SessionCacheWarmupSettings").Get<SessionCacheWarmupSettings>()!;
        Assert.True(s.Enabled); Assert.Equal(17, s.BatchSize); Assert.Equal(9, s.IntervalSeconds);
        Assert.Equal(0, s.DurationSeconds); Assert.Equal(80, s.CacheTtlSeconds); Assert.Equal(450, s.BatchTimeoutMilliseconds);
        Assert.True(Validator.TryValidateObject(s, new ValidationContext(s), new List<ValidationResult>(), true));
    }
}
