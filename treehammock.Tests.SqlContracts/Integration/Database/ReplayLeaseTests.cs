using Shouldly;
using StackExchange.Redis;
using treehammock.Rigging.Replay;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class Cor06ReplayLeaseTests
{
    [Fact]
    public async Task Expired_owner_cannot_complete_or_renew_replacement_generation()
    {
        using var connection = await Connect(); var db = connection.GetDatabase(0); string key = Key();
        RedisValue[] a = ["owner-a", "generation-a", "request", "operation", 40];
        RedisValue[] b = ["owner-b", "generation-b", "request", "operation", 3000];
        try
        {
            (await Run(db, AuthenticatedMutationReplayScripts.Reserve, key, a)).ShouldBe(1);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (await db.KeyExistsAsync(key)) await Task.Delay(5, deadline.Token);
            (await Run(db, AuthenticatedMutationReplayScripts.Reserve, key, b)).ShouldBe(1);
            (await Run(db, AuthenticatedMutationReplayScripts.Complete, key, [.. a, "late-a"])).ShouldBe(0);
            (await Run(db, AuthenticatedMutationReplayScripts.Renew, key, a)).ShouldBe(0);
            (await db.HashGetAsync(key, "owner")).ToString().ShouldBe("owner-b");
            (await Run(db, AuthenticatedMutationReplayScripts.Renew, key, b)).ShouldBe(1);
            (await Run(db, AuthenticatedMutationReplayScripts.Complete, key, [.. b, "original-b"])).ShouldBe(1);
            (await db.HashGetAsync(key, "result")).ToString().ShouldBe("original-b");
        }
        finally { await db.KeyDeleteAsync(key); }
    }

    [Fact]
    public async Task Changed_request_or_operation_conflicts_and_completed_result_is_immutable()
    {
        using var connection = await Connect(); var db = connection.GetDatabase(0); string key = Key();
        RedisValue[] a = ["owner-a", "generation-a", "request", "operation", 3000];
        try
        {
            (await Run(db, AuthenticatedMutationReplayScripts.Reserve, key, a)).ShouldBe(1);
            (await Run(db, AuthenticatedMutationReplayScripts.Reserve, key, ["b", "b", "changed", "operation", 3000])).ShouldBe(-1);
            (await Run(db, AuthenticatedMutationReplayScripts.Reserve, key, ["b", "b", "request", "changed", 3000])).ShouldBe(-1);
            (await Run(db, AuthenticatedMutationReplayScripts.Complete, key, [.. a, "original"])).ShouldBe(1);
            (await Run(db, AuthenticatedMutationReplayScripts.Complete, key, [.. a, "overwrite"])).ShouldBe(0);
            (await db.HashGetAsync(key, "result")).ToString().ShouldBe("original");
            (await db.KeyTimeToLiveAsync(key)).ShouldNotBeNull();
        }
        finally { await db.KeyDeleteAsync(key); }
    }

    [Fact]
    public async Task Invalid_duration_and_wrong_type_fail_before_mutation()
    {
        using var connection = await Connect(); var db = connection.GetDatabase(0); string key = Key();
        try
        {
            await Should.ThrowAsync<RedisServerException>(() => Run(db, AuthenticatedMutationReplayScripts.Reserve, key, ["a", "a", "r", "o", 0]));
            (await db.KeyExistsAsync(key)).ShouldBeFalse();
            await db.StringSetAsync(key, "sentinel", TimeSpan.FromSeconds(5));
            await Should.ThrowAsync<RedisServerException>(() => Run(db, AuthenticatedMutationReplayScripts.Reserve, key, ["a", "a", "r", "o", 3000]));
            (await db.StringGetAsync(key)).ToString().ShouldBe("sentinel");
        }
        finally { await db.KeyDeleteAsync(key); }
    }
    private static string Key() => "cor06:test:{" + Guid.NewGuid().ToString("N") + "}";
    private static async Task<long> Run(IDatabase db, string script, string key, RedisValue[] values)
        => (long)await db.ScriptEvaluateAsync(script, [key], values);
    internal static async Task<ConnectionMultiplexer> Connect()
    {
        string? endpoint = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT");
        string? password = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_PASSWORD");
        if (string.IsNullOrWhiteSpace(endpoint) || string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException("Run eng/correction-counter-fixture.py --replay or the owned SQL fixture.");
        var options = new ConfigurationOptions { Password = password, AbortOnConnectFail = true,
            ConnectTimeout = 1000, AsyncTimeout = 1000, SyncTimeout = 1000 };
        options.EndPoints.Add(endpoint); return await ConnectionMultiplexer.ConnectAsync(options);
    }
}
