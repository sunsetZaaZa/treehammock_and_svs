using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using Npgsql;
using NSubstitute;
using Shouldly;
using treehammock.DataLayer.Cache;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Dependencies;
using treehammock.RiggingSupport.Enum;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class Cor03DependencySqlTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task Real_sql_failure_returns_503_without_token_clear_and_recovers_on_same_repository(bool warm)
        => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            await using var storage = new FixtureStorage(fixture);
            var repo = new SessionRepo(storage, Options.Create(new JWTSettings()), NullLogger<SessionRepo>.Instance);
            await using var admin = await fixture.OpenConnectionAsync();
            string signature = warm ? "validate_cached_session_trust(text,uuid,uuid,uuid)" : "get_session(text)";
            string name = warm ? "validate_cached_session_trust" : "get_session";
            await fixture.ExecuteAsync(admin, $"alter function {fixture.Schema}.{signature} rename to cor03_saved_{name}");
            var now = SystemClock.Instance.GetCurrentInstant();
            var session = new ActiveSession(Guid.NewGuid(), new byte[32], 0, now, Period.FromHours(1),
                now.Plus(Duration.FromMinutes(10)), now.Plus(Duration.FromHours(1)), cutOff: null, features: FeatureSet.basic,
                accountSecurityStamp: Guid.NewGuid());
            var cache = Substitute.For<IActiveUserCacheService>();
            cache.GetSession(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(warm ? session : null));
            var jwt = Substitute.For<IJsonWebTokenUtility>();
            int next = 0;
            var middleware = new JsonWebTokenMiddleware(_ => { next++; return Task.CompletedTask; });
            var context = new DefaultHttpContext(); context.Request.Headers["AccessToken"] = "still-valid-token";
            await new DependencyExceptionMiddleware(_ => middleware.InvokeAsync(context, cache, jwt, repo, Options.Create(new JWTSettings())),
                NullLogger<DependencyExceptionMiddleware>.Instance).InvokeAsync(context);
            context.Response.StatusCode.ShouldBe(503);
            context.Response.Headers["AppStatus"].ToString().ShouldBeEmpty();
            context.Response.Headers["AccessToken"].ToString().ShouldBeEmpty();
            next.ShouldBe(0);
            await cache.DidNotReceiveWithAnyArgs().RevokeSession(default!, default);
            await fixture.ExecuteAsync(admin, $"alter function {fixture.Schema}.cor03_saved_{signature} rename to {name}");
            if (warm)
            {
                var result = await repo.ValidateCachedSessionTrust("still-valid-token", session.accountId, session.securityStamp, session.accountSecurityStamp, fixture.Token);
                result.ShouldNotBeNull(); result!.Status.ShouldBe(CachedSessionTrustStatus.AccountNotFound);
            }
            else (await repo.GetSession("still-valid-token", fixture.Token)).ShouldBeNull();
        });

    [Fact]
    public Task Native_command_cancellation_releases_connection_and_the_owner_remains_usable()
        => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            await using var storage = new FixtureStorage(fixture);
            await using (var connection = await storage.CreateConnection(fixture.Token))
            {
                await using var command = new NpgsqlCommand("select pg_sleep(10)", connection);
                using var commandCancellation = CancellationTokenSource.CreateLinkedTokenSource(fixture.Token);
                commandCancellation.CancelAfter(TimeSpan.FromMilliseconds(50));
                await Should.ThrowAsync<OperationCanceledException>(() => command.ExecuteScalarAsync(commandCancellation.Token));
            }
            await using var recovered = await storage.CreateConnection(fixture.Token);
            await using var probe = new NpgsqlCommand("select 1", recovered);
            Convert.ToInt32(await probe.ExecuteScalarAsync(fixture.Token)).ShouldBe(1);
        });

    [Fact]
    public Task Native_pool_acquisition_cancellation_is_distinct_from_missing_session_and_recovers()
        => SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            await using var storage = new FixtureStorage(fixture);
            var held = await storage.CreateConnection(fixture.Token);
            try
            {
                using var acquisitionCancellation = CancellationTokenSource.CreateLinkedTokenSource(fixture.Token);
                acquisitionCancellation.CancelAfter(TimeSpan.FromMilliseconds(50));
                await Should.ThrowAsync<OperationCanceledException>(async () =>
                {
                    await using var unexpected = await storage.CreateConnection(acquisitionCancellation.Token);
                });
            }
            finally { await held.DisposeAsync(); }
            await using var recovered = await storage.CreateConnection(fixture.Token);
            await using var command = new NpgsqlCommand("select 1", recovered);
            Convert.ToInt32(await command.ExecuteScalarAsync(fixture.Token)).ShouldBe(1);
        });

    private sealed class FixtureStorage : StorageContext
    {
        private readonly SqlContractFixture _fixture;
        public FixtureStorage(SqlContractFixture fixture) : base(Options.Create(Settings())) => _fixture = fixture;
        private static DatabaseSettings Settings()
        {
            var parsed = new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);
            return new() { servers = parsed.Host, port = parsed.Port, database = parsed.Database,
                userId = parsed.Username!, password = parsed.Password!, maximumPoolSize = 1 };
        }
        public override async Task<NpgsqlConnection> CreateConnection(CancellationToken cancellationToken = default)
        {
            var connection = await base.CreateConnection(cancellationToken);
            try
            {
                await using var command = new NpgsqlCommand($"set search_path to {_fixture.Schema}", connection);
                await command.ExecuteNonQueryAsync(cancellationToken);
                return connection;
            }
            catch { await connection.DisposeAsync(); throw; }
        }
    }
}
