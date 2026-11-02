using Microsoft.Extensions.Options;
using NSubstitute;
using Shouldly;
using StackExchange.Redis;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;

namespace treehammock.Tests.Unit;

public class DragonflyAbuseCounterStoreTests
{
    [Theory]
    [InlineData(1, 1, 0, 0, 0)]
    [InlineData(0, 6, 900000, 2, 1)]
    [InlineData(0, 6, 45000, 1, 0)]
    public async Task Increment_maps_one_atomic_reply_and_never_issues_split_writes(
        int allowed, int count, int retry, int reason, int started)
    {
        var database = Substitute.For<IDatabase>();
        using var store = CreateStore(database);
        var key = Key();
        var limit = new AbuseCounterLimit(5, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(15));
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult(Reply(allowed, count, retry, reason, started)));
        CounterDecision decision = await store.IncrementAsync(key, limit);
        decision.Allowed.ShouldBe(allowed == 1);
        decision.CurrentCount.ShouldBe(count);
        decision.RetryAfter.ShouldBe(retry > 0 ? TimeSpan.FromMilliseconds(retry) : null);
        decision.ReasonCode.ShouldBe(reason == 0 ? null : reason == 1
            ? AbuseReasonCodes.FailureCooldownActive : AbuseReasonCodes.CounterLimitExceeded);
        await database.Received(1).ScriptEvaluateAsync(AbuseCounterScripts.Increment,
            Arg.Is<RedisKey[]>(keys => keys.Length == 2 && keys[0] == key.Value && keys[1] == key.CooldownValue),
            Arg.Is<RedisValue[]>(args => args.Length == 4 && (long)args[0] == 5 && (long)args[1] == 600000 && (long)args[2] == 900000),
            CommandFlags.None);
        database.ReceivedCalls().Count().ShouldBe(1);
    }

    [Fact]
    public async Task Cooldown_uses_repair_script_and_reset_deletes_both_keys_in_one_call()
    {
        var database = Substitute.For<IDatabase>();
        using var store = CreateStore(database);
        var key = Key();
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult(RedisResult.Create((RedisValue)45000)));
        var decision = await store.GetCooldownAsync(key);
        decision.Active.ShouldBeTrue();
        decision.RetryAfter.ShouldBe(TimeSpan.FromSeconds(45));
        await database.Received(1).ScriptEvaluateAsync(AbuseCounterScripts.Cooldown,
            Arg.Is<RedisKey[]>(keys => keys.Length == 1 && keys[0] == key.CooldownValue),
            Arg.Any<RedisValue[]>(), CommandFlags.None);
        await store.ResetAsync(key);
        await database.Received(1).KeyDeleteAsync(
            Arg.Is<RedisKey[]>(keys => keys.Length == 2 && keys[0] == key.Value && keys[1] == key.CooldownValue), CommandFlags.None);
    }

    [Theory]
    [InlineData(AbuseCounterFailureMode.FailClosed, false)]
    [InlineData(AbuseCounterFailureMode.RequirePostgreSqlBudgetV1, false)]
    public async Task Script_error_returns_explicit_configured_outage_policy(AbuseCounterFailureMode mode, bool allowed)
    {
        var database = Substitute.For<IDatabase>();
        using var store = CreateStore(database, new AbuseControlSettings { CounterFailureMode = mode });
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>())
            .Returns(_ => Task.FromException<RedisResult>(new RedisServerException("CROSSSLOT or invalid cache value")));
        var decision = await store.IncrementAsync(Key(), new AbuseCounterLimit(5, TimeSpan.FromSeconds(10)));
        decision.Allowed.ShouldBe(allowed);
        decision.ReasonCode.ShouldBe(AbuseReasonCodes.CounterStoreUnavailable);
    }

    [Fact]
    public async Task Deadline_does_not_fabricate_success_and_caller_cancellation_propagates()
    {
        var database = Substitute.For<IDatabase>();
        using var store = CreateStore(database, new AbuseControlSettings { DragonflyTimeoutMilliseconds = 0 });
        var pending = new TaskCompletionSource<RedisResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>())
            .Returns(pending.Task);
        var limit = new AbuseCounterLimit(5, TimeSpan.FromSeconds(10));
        var decision = await store.IncrementAsync(Key(), limit);
        decision.Allowed.ShouldBeFalse();
        decision.ReasonCode.ShouldBe(AbuseReasonCodes.CounterStoreTimeout);
        pending.SetResult(Reply(1, 1, 0, 0, 0)); // Late completion must not change returned outage result.
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Should.ThrowAsync<OperationCanceledException>(() => store.IncrementAsync(Key(), limit, canceled.Token));
    }

    [Fact]
    public void Durations_round_up_to_milliseconds_and_upper_bounds_are_clamped()
    {
        var tiny = new AbuseCounterLimit(5, TimeSpan.FromTicks(1), TimeSpan.FromTicks(1));
        tiny.Window.ShouldBe(TimeSpan.FromMilliseconds(1));
        tiny.Cooldown.ShouldBe(TimeSpan.FromMilliseconds(1));
        var huge = new AbuseCounterLimit(int.MaxValue, TimeSpan.MaxValue, TimeSpan.MaxValue);
        huge.MaxAttempts.ShouldBe(1_000_000);
        huge.Window.ShouldBe(TimeSpan.FromDays(1));
        huge.Cooldown.ShouldBe(TimeSpan.FromDays(1));
        new AbuseCounterLimit(5, TimeSpan.FromSeconds(1), TimeSpan.Zero).Cooldown.ShouldBe(TimeSpan.Zero);
        Should.Throw<ArgumentOutOfRangeException>(() => new AbuseCounterLimit(0, TimeSpan.FromSeconds(1)));
        Should.Throw<ArgumentOutOfRangeException>(() => new AbuseCounterLimit(1, TimeSpan.Zero));
    }

    [Fact]
    public void Abuse_counter_cache_settings_builds_isolated_dragonfly_configuration()
    {
        var settings = new AbuseCounterCacheSettings { servers = "localhost", port = 6379, database = 2, clientName = "treehammock-tests-abuse-counters", connectTimeoutMilliseconds = 1000, asyncTimeoutMilliseconds = 1000, syncTimeoutMilliseconds = 1000, connectRetry = 1 };

        ConfigurationOptions configuration = treehammock.Rigging.Cache.ActiveUserCacheService.BuildConfiguration(settings);

        configuration.DefaultDatabase.ShouldBe(2);
        configuration.ClientName.ShouldBe("treehammock-tests-abuse-counters");
        configuration.ConnectTimeout.ShouldBe(1000);
        configuration.AsyncTimeout.ShouldBe(1000);
        configuration.SyncTimeout.ShouldBe(1000);
        configuration.ConnectRetry.ShouldBe(1);
    }

    private static RedisResult Reply(params int[] values) => RedisResult.Create(values.Select(value => (RedisValue)value).ToArray());
    private static AbuseCounterKey Key() => new(AbuseFeature.TwoFactorChallenge, AbuseCounterDimension.Challenge, "challenge-123");
    private static DragonflyAbuseCounterStore CreateStore(IDatabase database, AbuseControlSettings? settings = null)
    {
        var connection = Substitute.For<IConnectionMultiplexer>();
        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(database);
        return new DragonflyAbuseCounterStore(Options.Create(new AbuseCounterCacheSettings
            { servers = "localhost", port = 6379, database = 2, connectTimeoutMilliseconds = 1000,
                asyncTimeoutMilliseconds = 1000, syncTimeoutMilliseconds = 1000 }),
            Options.Create(settings ?? new AbuseControlSettings()), connection);
    }
}
