using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using NSubstitute;
using StackExchange.Redis;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Health;
using treehammock.Rigging.Replay;
using treehammock.Tests.Infrastructure;
namespace treehammock.Tests.Integration;
public sealed class Cor23NCacheHostTests
{
    [Fact]
    public async Task Real_application_composition_shares_roles_with_health_and_releases_host_clients()
    {
        var clients = new List<IConnectionMultiplexer>(); CacheConnectionOwner? owner = null;
        using (var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings(), services =>
        {
            // Keep production consumer registrations. Isolate unrelated database/provider workers.
            services.RemoveAll<IHostedService>(); services.RemoveAll<CacheConnectionOwner>();
            services.AddSingleton(provider => owner = new CacheConnectionOwner(
                provider.GetRequiredService<IOptions<UserCacheSettings>>(),
                provider.GetRequiredService<IOptions<TwoFactorSessionCacheSettings>>(),
                provider.GetRequiredService<IOptions<AbuseCounterCacheSettings>>(), _ =>
                {
                    var client = Substitute.For<IConnectionMultiplexer>(); client.IsConnected.Returns(true);
                    lock (clients) clients.Add(client); return Task.FromResult(client);
                }));
            services.AddHostedService(provider => provider.GetRequiredService<CacheConnectionOwner>());
        }))
        {
            using var http = factory.CreateClient(); Assert.NotNull(owner);
            using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (!owner!.GetDiagnostics().Values.All(d => d.Connected)) await Task.Delay(5, limit.Token);
            await Task.WhenAll(Enumerable.Range(0, 64).Select(_ => Task.Run(() =>
            {
                Assert.Same(owner.Get(CacheProfile.ActiveSessions).Connection,
                    ((ActiveUserCacheService)factory.Services.GetRequiredService<IActiveUserCacheService>())._connection);
                Assert.Same(owner.Get(CacheProfile.TwoFactorSessions).Connection,
                    ((TwoFactorSessionService)factory.Services.GetRequiredService<ITwoFactorSessionService>())._connection);
                Assert.Same(owner.Get(CacheProfile.AbuseCounters).Connection,
                    ((DragonflyAbuseCounterStore)factory.Services.GetRequiredService<IAbuseCounterStore>()).Connection);
                Assert.Same(owner.Get(CacheProfile.AbuseCounters).Connection,
                    ((DragonflyAuthenticatedMutationIdempotencyService)factory.Services.GetRequiredService<IAuthenticatedMutationIdempotencyService>()).Connection);
            })));
            var health = factory.Services.GetRequiredService<IHealthDependencyService>();
            // Resolving health and canceling its request cannot start or stop a connection.
            using var canceled = new CancellationTokenSource(); canceled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => health.CheckAsync(canceled.Token));
            Assert.All(owner.GetDiagnostics().Values, d => Assert.Equal(1, d.InitializationAttempts));
            lock (clients) Assert.Equal(3, clients.Count);
        }
        Assert.NotNull(owner);
        foreach (var client in clients) client.Received(1).Dispose();
        Assert.All(owner!.GetDiagnostics().Values, d => Assert.Equal(CacheClientLifecycle.Disposed, d.Lifecycle));
    }
}
