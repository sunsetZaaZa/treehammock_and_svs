using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using StackExchange.Redis;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;
using treehammock.Services;
using treehammock.Repos;
using treehammock.Models.Recovery;
using treehammock.Tests.Infrastructure;
namespace treehammock.Tests.Unit;

[CollectionDefinition("COR23P telemetry", DisableParallelization = true)]
public sealed class Cor23PTelemetryCollection { }
[Collection("COR23P telemetry")]
public sealed class Cor23PTransitionTelemetryTests
{
    private static readonly AbuseCounterKey Key = new(AbuseFeature.Login, AbuseCounterDimension.Account, "private-test-key");
    private static readonly AbuseCounterLimit Limit = new(1, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    private static RedisResult Reply(params int[] values) => RedisResult.Create(values.Select(v => (RedisValue)v).ToArray());
    private static DragonflyAbuseCounterStore Store(IDatabase db, AbuseControlSettings? settings = null, IPostgreSqlAbuseBudgetStore? durable = null)
    {
        var connection = Substitute.For<IConnectionMultiplexer>(); connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(db);
        return new(Options.Create(new AbuseCounterCacheSettings { database = 0 }), Options.Create(settings ?? new AbuseControlSettings()), connection, durable);
    }
    private static void SetReply(IDatabase db, Task<RedisResult> reply) => db.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>()).Returns(reply);
    [Fact]
    public async Task One_atomic_transition_then_repeat_denials_produce_one_creation_and_distinct_blocked_attempts()
    {
        using var capture = new Cor23PMetricCapture(); var db = Substitute.For<IDatabase>(); using var store = Store(db);
        SetReply(db, Task.FromResult(Reply(1, 1, 0, 0, 0))); Assert.True((await store.IncrementAsync(Key, Limit)).CanAdmit);
        SetReply(db, Task.FromResult(Reply(0, 2, 30000, 2, 1))); Assert.True((await store.IncrementAsync(Key, Limit)).CooldownCreated);
        SetReply(db, Task.FromResult(Reply(0, 2, 20000, 1, 0)));
        for (int i = 0; i < 12; i++) Assert.False((await store.IncrementAsync(Key, Limit)).CooldownCreated);
        Assert.Equal(1, capture.Sum(AbuseMetricNames.CooldownsStartedTotal)); Assert.Equal(12, capture.Sum(AbuseMetricNames.CooldownBlockedAttemptsTotal));
        Assert.Equal(14, capture.Sum(AbuseMetricNames.CounterAdmissionsTotal)); Assert.Equal(13, capture.Sum(AbuseMetricNames.CounterAdmissionsTotal, "denied"));
        SetReply(db, Task.FromResult(RedisResult.Create((RedisValue)10000)));
        for (int i = 0; i < 12; i++) Assert.True((await store.GetCooldownAsync(Key)).Active);
        Assert.Equal(1, capture.Sum(AbuseMetricNames.CooldownsStartedTotal)); Assert.Equal(14, capture.Sum(AbuseMetricNames.CounterAdmissionsTotal));
    }
    [Theory]
    [InlineData(1, 1, 0, 0, 1)][InlineData(0, 2, 100, 1, 1)][InlineData(0, 2, 0, 2, 1)]
    [InlineData(0, 2, 100, 2, 2)][InlineData(0, -1, 100, 2, 1)][InlineData(2, 1, 0, 0, 0)]
    public async Task Malformed_transition_reply_does_not_invent_a_cooldown(int allowed, int count, int retry, int reason, int created)
    {
        using var capture = new Cor23PMetricCapture(); var db = Substitute.For<IDatabase>(); using var store = Store(db);
        SetReply(db, Task.FromResult(Reply(allowed, count, retry, reason, created)));
        Assert.True((await store.IncrementAsync(Key, Limit)).Unavailable);
        Assert.Equal(0, capture.Sum(AbuseMetricNames.CooldownsStartedTotal)); Assert.Equal(1, capture.Sum(AbuseMetricNames.CounterAdmissionsTotal, "denied"));
    }
    [Fact]
    public async Task Late_raw_creation_counts_once_without_rewriting_the_returned_timeout_outcome()
    {
        using var capture = new Cor23PMetricCapture(); var db = Substitute.For<IDatabase>();
        using var store = Store(db, new AbuseControlSettings { DragonflyTimeoutMilliseconds = 10 });
        var raw = new TaskCompletionSource<RedisResult>(TaskCreationOptions.RunContinuationsAsynchronously); SetReply(db, raw.Task);
        var decision = await store.IncrementAsync(Key, Limit); Assert.True(decision.Unavailable); Assert.False(decision.CooldownCreated);
        raw.SetResult(Reply(0, 2, 30000, 2, 1));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (capture.Sum(AbuseMetricNames.CooldownsStartedTotal) == 0) await Task.Delay(5, timeout.Token);
        Assert.Equal(1, capture.Sum(AbuseMetricNames.CooldownsStartedTotal)); Assert.Equal(1, capture.Sum(AbuseMetricNames.CounterAdmissionsTotal, "denied"));
        Assert.Equal(0, capture.Sum(AbuseMetricNames.CooldownBlockedAttemptsTotal));
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Durable_and_cache_resolution_emits_one_terminal_admission(bool cacheFails)
    {
        using var capture = new Cor23PMetricCapture(); var db = Substitute.For<IDatabase>(); var durable = Substitute.For<IPostgreSqlAbuseBudgetStore>();
        durable.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>()).Returns(new CounterDecision(true, 1, 1, Limit.Window, null, null));
        SetReply(db, cacheFails ? Task.FromException<RedisResult>(new RedisServerException("private-fault")) : Task.FromResult(Reply(1, 1, 0, 0, 0)));
        using var store = Store(db, new AbuseControlSettings { CounterFailureMode = AbuseCounterFailureMode.RequirePostgreSqlBudgetV1, PostgreSqlFallbackPolicies = [AbuseFeature.Login] }, durable);
        Assert.True((await store.IncrementAsync(Key, Limit)).CanAdmit); Assert.Equal(1, capture.Sum(AbuseMetricNames.CounterAdmissionsTotal, "allowed"));
        Assert.Equal(0, capture.Sum(AbuseMetricNames.CooldownsStartedTotal));
    }
    [Fact]
    public async Task Real_unlock_policy_denial_does_not_double_count_the_store_or_invoke_proof_work()
    {
        using var capture = new Cor23PMetricCapture(); var db = Substitute.For<IDatabase>(); using var store = Store(db);
        // A valid counter denial without a new cooldown; applies to the first token dimension.
        SetReply(db, Task.FromResult(Reply(0, 100, 30000, 2, 0)));
        var repo = Substitute.For<IAccountRecoveryRepo>();
        var service = new AccountRecoveryService(new CapturingDurableDelivery(), repo, Options.Create(new EmailSubjectSettings()),
            NullLogger<AccountRecoveryService>.Instance, new AccountUnlockAbuseCounterKeyFactory(), store, Options.Create(new AbuseControlSettings()));
        var result = await service.VerifyRecovery(new AccountRecoveryVerifyRequest("private-token"));
        Assert.False(result.Result); Assert.Equal(AbuseReasonCodes.AccountUnlockVerifyAttemptsExceeded, result.Code);
        Assert.Equal(1, capture.Sum(AbuseMetricNames.CounterAdmissionsTotal, "denied")); Assert.Equal(0, capture.Sum(AbuseMetricNames.CooldownsStartedTotal));
        Assert.Empty(repo.ReceivedCalls());
    }
    [Fact]
    public async Task Pre_canceled_admission_emits_no_outcome_or_transition()
    {
        using var capture = new Cor23PMetricCapture(); var db = Substitute.For<IDatabase>(); using var store = Store(db);
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.IncrementAsync(Key, Limit, canceled.Token));
        Assert.Empty(capture.Values); Assert.Empty(db.ReceivedCalls());
    }
    [Fact]
    public void Unknown_tag_values_and_undefined_enums_collapse_to_a_finite_catalog()
    {
        using var capture = new Cor23PMetricCapture();
        for (int i = 0; i < 100; i++)
        {
            string secret = "person" + i + "@example.test token=" + Guid.NewGuid();
            AbuseOperationalTelemetry.RecordCounterAdmission((AbuseFeature)(1000 + i), (AbuseCounterDimension)(1000 + i), new(false, 0, 1, Limit.Window, null, secret));
            AbuseOperationalTelemetry.RecordCounterStoreFailure(secret, secret, secret);
            AbuseOperationalTelemetry.RecordDeliveryThrottled(secret, secret);
            AbuseOperationalTelemetry.RecordEdgeAbuseEvent(secret, secret);
        }
        Assert.All(capture.Values, m => Assert.All(m.Tags, t => { Assert.Contains(t.Key, AbuseMetricLabels.Allowed); Assert.Contains(t.Value, new[] { "unknown", "denied", "dragonfly" }); }));
        Assert.Equal(1, capture.Values.Where(m => m.Name == AbuseMetricNames.CounterAdmissionsTotal).Select(m => string.Join("|", m.Tags.Values)).Distinct().Count());
    }
}
