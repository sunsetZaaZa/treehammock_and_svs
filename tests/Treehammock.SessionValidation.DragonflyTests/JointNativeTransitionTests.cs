using System.Globalization;
using System.Text.RegularExpressions;
using StackExchange.Redis;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.DragonflyTests;

// Explicit owned-target runner only. Never run by the local conformance suite.
public sealed class JointNativeTransitionTests
{
    private static string Required(string key) => Environment.GetEnvironmentVariable(key) ?? throw new InvalidOperationException("Missing joint native fixture: " + key);
    private static async Task<ConnectionMultiplexer> Connect(string key)
    {
        if (Required("SVS06_DISPOSABLE_DRAGONFLY") != "true") throw new InvalidOperationException("Owned disposable Dragonfly acknowledgment required.");
        var options = ConfigurationOptions.Parse(Required(key));
        if (options.EndPoints.Count != 1 || !options.Ssl || string.IsNullOrWhiteSpace(options.User)) throw new InvalidOperationException("Dedicated identity, verified TLS, single endpoint required.");
        options.ConnectRetry = 0; options.AbortOnConnectFail = true; options.ConnectTimeout = 2000; options.AsyncTimeout = 2000;
        return await ConnectionMultiplexer.ConnectAsync(options);
    }
    [Theory][InlineData("stale-nonce")][InlineData("revision")][InlineData("epoch")][InlineData("nx-collision")]
    public async Task Exact_TH12B_Lua_rejects_stale_or_foreign_transitions_on_actual_pinned_Dragonfly(string fault)
    {
        string prefix = Required("SVS06_OWNED_NAMESPACE");
        if (!Regex.IsMatch(prefix, "^svs:authority:v1:[a-z0-9.-]{1,32}:[a-f0-9]{32}$", RegexOptions.CultureInvariant)) throw new InvalidOperationException("Owned namespace required.");
        var parts = prefix.Split(':'); var space = new CoherentCacheKeySpace(parts[3], Guid.ParseExact(parts[4], "N"), Required("SVS10_POLICY"));
        using var owner = await Connect("SVS06_OWNER_CONNECTION"); using var writer = await Connect("SVS10_WRITER_CONNECTION");
        var db = writer.GetDatabase(); var admin = owner.GetDatabase(); string version = (await admin.ExecuteAsync("INFO", "server")).ToString();
        Assert.Contains("dragonfly_version:" + Required("SVS10_DRAGONFLY_VERSION"), version, StringComparison.Ordinal);
        Guid account = Guid.NewGuid(); string key = space.AccountKey(account); long revision = 9007199254740993;
        var first = new CacheAuthorityHeader(space.Environment, space.Epoch, space.Policy, CoherentCacheKeySpace.NewTransitionNonce(), revision, CachedAuthorityState.Blocked, account);
        byte[] Encode(CacheAuthorityHeader header) { using var record = new CachedAccountAuthority(header); return CoherentCacheCodec.Encode(record); }
        string script = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "authority-transition.lua"), TestContext.Current.CancellationToken);
        async Task<int> Exchange(byte[]? prior, CacheAuthorityHeader? old, CacheAuthorityHeader next)
        {
            RedisValue[] args = [prior is null ? "0" : "1", prior is null ? RedisValue.EmptyString : prior, Encode(next), space.Environment,
                space.Epoch.ToString("N"), space.Policy, account.ToString("N"), next.Nonce, next.Revision.ToString(CultureInfo.InvariantCulture), "Blocked", "0", old?.Nonce ?? "", old?.Revision.ToString(CultureInfo.InvariantCulture) ?? "", ""];
            return (int)await db.ScriptEvaluateAsync(script, [(RedisKey)key], args, CommandFlags.DemandMaster | CommandFlags.NoRedirect);
        }
        try
        {
            Assert.Equal(1, await Exchange(null, null, first)); byte[] before = Encode(first);
            var second = first with { Nonce = CoherentCacheKeySpace.NewTransitionNonce() }; Assert.Equal(1, await Exchange(before, first, second));
            var next = second with { Nonce = CoherentCacheKeySpace.NewTransitionNonce() };
            int outcome = fault switch
            {
                "stale-nonce" => await Exchange(before, first, next),
                "revision" => await Exchange(Encode(second), second, next with { Revision = revision - 1 }),
                "epoch" => await Exchange(Encode(second), second, next with { Epoch = Guid.NewGuid() }),
                _ => await Exchange(null, null, next)
            };
            Assert.Equal(fault is "stale-nonce" or "nx-collision" ? 0 : -1, outcome);
            Assert.Equal(Encode(second), (byte[]?)await admin.StringGetAsync(key)); Assert.Null(await admin.KeyTimeToLiveAsync(key));
        }
        finally { await admin.KeyDeleteAsync(key); }
    }
}
