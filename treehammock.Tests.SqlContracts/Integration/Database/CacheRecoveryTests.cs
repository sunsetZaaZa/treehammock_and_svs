using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using Shouldly;
using StackExchange.Redis;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Dependencies;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class Cor03CacheRecoveryTests
{
    [Fact]
    public async Task Real_cache_connect_failure_recovers_and_commands_work_without_recreating_the_owner()
    {
        string? endpoint = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_ENDPOINT");
        string? password = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_CACHE_PASSWORD");
        if (string.IsNullOrWhiteSpace(endpoint) || string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException("Run eng/correction-sql-fixture.sh for the owned PostgreSQL/cache fixture.");
        var address = endpoint.Split(':');
        var settings = new UserCacheSettings { servers = address[0], port = int.Parse(address[1]), password = password,
            database = 0, reconnectRetryPolicy = 10, connectTimeoutMilliseconds = 500, asyncTimeoutMilliseconds = 500, connectRetry = 0 };
        var blockedHandshake = new TcpListener(IPAddress.Loopback, 0);
        blockedHandshake.Start(); // Accepting TCP without speaking Redis makes the first provider handshake unavailable.
        int attempts = 0;
        using var lifetime = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            await using var slot = new CacheConnectionSlot(settings, async configuration =>
            {
                if (Interlocked.Increment(ref attempts) == 1)
                {
                    configuration.EndPoints.Clear();
                    configuration.EndPoints.Add((IPEndPoint)blockedHandshake.LocalEndpoint);
                    configuration.AbortOnConnectFail = true;
                    configuration.ConnectTimeout = 100;
                }
                return await ConnectionMultiplexer.ConnectAsync(configuration);
            });
            await Should.ThrowAsync<DependencyUnavailableException>(() => slot.ExecuteAsync(db => db.PingAsync(), lifetime.Token));
            attempts.ShouldBe(0);
            slot.Start();
            while (!slot.Ready) await Task.Delay(10, lifetime.Token);
            attempts.ShouldBeGreaterThanOrEqualTo(2);
            string key = "cor03:" + Guid.NewGuid().ToString("N");
            (await slot.ExecuteAsync(db => db.StringSetAsync(key, "recovered", TimeSpan.FromSeconds(10)), lifetime.Token)).ShouldBeTrue();
            (await slot.ExecuteAsync(db => db.StringGetAsync(key), lifetime.Token)).ToString().ShouldBe("recovered");
            await slot.ExecuteAsync(db => db.KeyDeleteAsync(key), lifetime.Token);
        }
        finally { blockedHandshake.Stop(); }
    }
}
