using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Npgsql;
using Shouldly;
using treehammock.DataLayer.Operations;
using treehammock.Models.Account;
using treehammock.Models.Api;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Operations;
using treehammock.Rigging.Replay;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class Cor06DurableReplayTests
{
    private const string ClientKey = "cor06-client-key-12345";
    private static SecurityOperationSettings Settings() => new()
    { HmacKeys = new() { [1] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } };
    private static AuthenticatedMutationIdempotencyRequest Request(Guid account, Guid stamp, string body = "{\"value\":1}")
        => new(account, "POST", "account/adjust", ClientKey, true, stamp, Encoding.UTF8.GetBytes(body));
    private static SecurityOperationRequestContext Context(AuthenticatedMutationIdempotencyRequest request) => new()
    { ClientKey = SecurityOperationKey.Create(), RecoveryKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        Purpose = "POST:/account/adjust", CanonicalBody = request.CanonicalRequest! };
    private static AuthenticatedMutationIdempotencyStoredResult Safe()
        => AuthenticatedMutationSafeResult.Capture(new ApiOutcome<AccountEditResponse>(new(HttpMessage.ACCOUNT_ADJUST_SUCCEEDED), 200, "ORIGINAL_RESULT"));

    [Fact]
    public Task Concurrent_instances_reserve_one_SQL_owner_and_rollback_the_losing_root()
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var settings = Settings(); await using var a = new FixtureStorage(fixture, settings);
            await using var b = new FixtureStorage(fixture, settings);
            var (account, stamp, admin) = await Seed(fixture); var request = Request(account, stamp);
            var contexts = new[] { Context(request), Context(request) };
            var stores = new[] { a, b }; var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var tasks = stores.Select((store, index) => Task.Run(async () =>
            {
                using var ambient = SecurityOperationRequestContext.Push(contexts[index]);
                await gate.Task.WaitAsync(token);
                return await new AuthenticatedMutationReplayRepo(store, new()).BeginAsync(request, ClientKey, token);
            }, token)).ToArray();
            foreach (var task in tasks) fixture.Observe(task);
            gate.SetResult(); var results = await Task.WhenAll(tasks);
            results.Count(result => result.Started).ShouldBe(1);
            results.Count(result => result.Status == AuthenticatedMutationIdempotencyStatus.RecoveryRequired).ShouldBe(1);
            int winner = Array.FindIndex(results, result => result.Started);
            using (SecurityOperationRequestContext.Push(contexts[winner]))
            {
                await Effect(stores[winner], fixture, account, stamp, token);
                (await new AuthenticatedMutationReplayRepo(stores[winner], new()).CompleteAsync(results[winner].Reservation!, Safe(), token)).ShouldBeTrue();
            }
            (await Scalar<long>(admin, "select count(*) from security_operations", token)).ShouldBe(1);
            (await Scalar<long>(admin, "select count(*) from cor06_effects", token)).ShouldBe(1);
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Real_cache_eviction_and_another_instance_replay_original_response_without_another_effect()
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var settings = Settings(); await using var first = new FixtureStorage(fixture, settings);
            await using var second = new FixtureStorage(fixture, settings);
            var (account, stamp, admin) = await Seed(fixture);
            using var cache = await Cor06ReplayLeaseTests.Connect();
            var abuse = Options.Create(new AbuseControlSettings { AuthenticatedMutationIdempotency = new() { TimeoutMilliseconds = 60 } });
            await using var serviceA = new DragonflyAuthenticatedMutationIdempotencyService(Options.Create(new AbuseCounterCacheSettings { database = 0 }), abuse, cache, first);
            await using var serviceB = new DragonflyAuthenticatedMutationIdempotencyService(Options.Create(new AbuseCounterCacheSettings { database = 0 }), abuse, cache, second);
            var request = Request(account, stamp); var context = Context(request);
            using (SecurityOperationRequestContext.Push(context))
            {
                var started = await serviceA.BeginAsync(request, token); started.Started.ShouldBeTrue();
                await Effect(first, fixture, account, stamp, token);
                await serviceA.CompleteStoredAsync(started.Reservation, Safe(), token);
                await cache.GetDatabase(0).KeyDeleteAsync(started.Reservation!.CacheKey);
            }
            using (SecurityOperationRequestContext.Push(Context(request)))
            {
                var duplicate = await serviceB.BeginAsync(request, token);
                duplicate.Status.ShouldBe(AuthenticatedMutationIdempotencyStatus.ReplayCompleted);
                duplicate.StoredResult.ShouldBe(Safe());
            }
            (await Scalar<long>(admin, "select count(*) from cor06_effects", token)).ShouldBe(1);
            (await Scalar<long>(admin, "select count(*) from security_operations", token)).ShouldBe(1);
        }, TestContext.Current.CancellationToken);

    [Theory]
    [InlineData("{\"sessionId\":\"first\"}", "{\"sessionId\":\"other\"}")]
    [InlineData("{\"method\":1}", "{\"method\":2}")]
    [InlineData("{\"contact\":\"first@example.invalid\"}", "{\"contact\":\"other@example.invalid\"}")]
    [InlineData("{\"featureSet\":1}", "{\"featureSet\":2}")]
    [InlineData("{\"passPhrase\":\"first-secret\"}", "{\"passPhrase\":\"changed-secret\"}")]
    public Task Same_identity_with_changed_input_conflicts_before_domain_work(string original, string body)
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            await using var storage = new FixtureStorage(fixture, Settings()); var repo = new AuthenticatedMutationReplayRepo(storage, new());
            var (account, stamp, admin) = await Seed(fixture); var request = Request(account, stamp, original);
            using (SecurityOperationRequestContext.Push(Context(request)))
            {
                (await repo.BeginAsync(request, ClientKey, token)).Started.ShouldBeTrue();
                await Effect(storage, fixture, account, stamp, token);
            }
            var changed = Request(account, stamp, body);
            using (SecurityOperationRequestContext.Push(Context(changed)))
                (await repo.BeginAsync(changed, ClientKey, token)).Status.ShouldBe(AuthenticatedMutationIdempotencyStatus.ContentConflict);
            (await Scalar<long>(admin, "select count(*) from cor06_effects", token)).ShouldBe(1);
            string row = await Scalar<string>(admin, "select to_jsonb(r)::text from authenticated_mutation_replays r", token);
            row.ShouldNotContain("changed-secret"); row.ShouldNotContain("sessionId");
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Pending_or_expired_replay_window_requires_recovery_and_fake_owner_cannot_complete()
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            await using var storage = new FixtureStorage(fixture, Settings()); var repo = new AuthenticatedMutationReplayRepo(storage, new());
            var (account, stamp, admin) = await Seed(fixture); var request = Request(account, stamp);
            AuthenticatedMutationIdempotencyReservation owner;
            using (SecurityOperationRequestContext.Push(Context(request)))
            {
                owner = (await repo.BeginAsync(request, ClientKey, token)).Reservation!;
                await Effect(storage, fixture, account, stamp, token);
                (await repo.CompleteAsync(owner with { ReservationToken = Guid.NewGuid().ToString("N") }, Safe(), token)).ShouldBeFalse();
            }
            using (SecurityOperationRequestContext.Push(Context(request)))
                (await repo.BeginAsync(request, ClientKey, token)).Status.ShouldBe(AuthenticatedMutationIdempotencyStatus.RecoveryRequired);
            (await repo.CompleteAsync(owner, Safe(), token)).ShouldBeTrue();
            await fixture.ExecuteAsync(admin, "update authenticated_mutation_replays set replay_until=clock_timestamp()-interval '1 second'");
            using (SecurityOperationRequestContext.Push(Context(request)))
                (await repo.BeginAsync(request, ClientKey, token)).Status.ShouldBe(AuthenticatedMutationIdempotencyStatus.RecoveryRequired);
            (await Scalar<long>(admin, "select count(*) from cor06_effects", token)).ShouldBe(1);
            (await Scalar<long>(admin, "select count(*) from security_operations", token)).ShouldBe(1);
            using (SecurityOperationRequestContext.Push(Context(request)))
            {
                // Even the old executor's admitted context cannot acquire another terminal gate.
                (await Should.ThrowAsync<PostgresException>(() => fixture.ExecuteAsync(admin, $"select lock_security_operation('{owner.OperationId}',null)"))).SqlState.ShouldBe("P0404");
            }
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Retained_HMAC_key_allows_replay_but_changed_account_epoch_denies_historical_response()
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var old = Settings(); await using var first = new FixtureStorage(fixture, old);
            var (account, stamp, admin) = await Seed(fixture); var request = Request(account, stamp);
            var repo = new AuthenticatedMutationReplayRepo(first, new());
            using (SecurityOperationRequestContext.Push(Context(request)))
            {
                var owner = (await repo.BeginAsync(request, ClientKey, token)).Reservation!;
                (await repo.CompleteAsync(owner, Safe(), token)).ShouldBeTrue();
            }
            var rollover = Settings(); rollover.ActiveKeyVersion = 2;
            rollover.HmacKeys = new() { [1] = old.HmacKeys[1], [2] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) };
            await using var second = new FixtureStorage(fixture, rollover); var other = new AuthenticatedMutationReplayRepo(second, new());
            using (SecurityOperationRequestContext.Push(Context(request)))
                (await other.BeginAsync(request, ClientKey, token)).Status.ShouldBe(AuthenticatedMutationIdempotencyStatus.ReplayCompleted);
            Guid changed = Guid.NewGuid(); await fixture.ExecuteAsync(admin, $"update accounts set security_stamp='{changed}' where account_id='{account}'");
            using (SecurityOperationRequestContext.Push(Context(request)))
                (await other.BeginAsync(request, ClientKey, token)).Status.ShouldBe(AuthenticatedMutationIdempotencyStatus.AuthorityChanged);
            var current = Request(account, changed);
            using (SecurityOperationRequestContext.Push(Context(current)))
                (await other.BeginAsync(current, ClientKey, token)).Status.ShouldBe(AuthenticatedMutationIdempotencyStatus.AuthorityChanged);
        }, TestContext.Current.CancellationToken);

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public Task Lost_admission_or_completion_commit_ack_is_recovered_without_readmission(bool completion)
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            var settings = Settings(); var parsed = new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);
            await using var proxy = new Cor04CommitAckLossProxy(parsed.Host, parsed.Port);
            await using var first = new FixtureStorage(fixture, settings, proxy.Port);
            await using var second = new FixtureStorage(fixture, settings);
            var (account, stamp, admin) = await Seed(fixture); var request = Request(account, stamp);
            var repo = new AuthenticatedMutationReplayRepo(first, new());
            using (SecurityOperationRequestContext.Push(Context(request)))
            {
                if (completion)
                {
                    var owner = (await repo.BeginAsync(request, ClientKey, token)).Reservation!;
                    await Effect(first, fixture, account, stamp, token); proxy.Arm();
                    await Should.ThrowAsync<SecurityOperationException>(() => repo.CompleteAsync(owner, Safe(), token));
                }
                else
                {
                    proxy.Arm(); await Should.ThrowAsync<SecurityOperationException>(() => repo.BeginAsync(request, ClientKey, token));
                }
                await proxy.Dropped.WaitAsync(TimeSpan.FromSeconds(5), token);
            }
            using (SecurityOperationRequestContext.Push(Context(request)))
                (await new AuthenticatedMutationReplayRepo(second, new()).BeginAsync(request, ClientKey, token)).Status
                    .ShouldBe(completion ? AuthenticatedMutationIdempotencyStatus.ReplayCompleted : AuthenticatedMutationIdempotencyStatus.RecoveryRequired);
            (await Scalar<long>(admin, "select count(*) from cor06_effects", token)).ShouldBe(completion ? 1L : 0L);
            (await Scalar<long>(admin, "select count(*) from security_operations", token)).ShouldBe(1);
        }, TestContext.Current.CancellationToken);

    private static async Task<(Guid, Guid, NpgsqlConnection)> Seed(SqlContractFixture fixture)
    {
        var admin = await fixture.OpenConnectionAsync(); var account = Guid.NewGuid(); var stamp = Guid.NewGuid();
        await fixture.ExecuteAsync(admin, $"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{account}','cor06@example.invalid',1,'{stamp}'); create table cor06_effects(value integer not null)");
        return (account, stamp, admin);
    }
    private static async Task Effect(StorageContext storage, SqlContractFixture fixture, Guid account, Guid stamp, CancellationToken token)
    {
        await using var scope = await storage.SecurityOperations.BeginAsync("test.cor06.effect", new { value = 1 }, account, stamp, null, token);
        await fixture.ExecuteAsync(scope.Connection, "insert into cor06_effects values(1)", scope.Transaction, token);
        await scope.CommitAsync(true);
    }
    private static async Task<T> Scalar<T>(NpgsqlConnection connection, string sql, CancellationToken token)
    { await using var command = new NpgsqlCommand(sql, connection); return (T)(await command.ExecuteScalarAsync(token))!; }
    private sealed class FixtureStorage : StorageContext
    {
        private readonly SqlContractFixture _fixture;
        public FixtureStorage(SqlContractFixture fixture, SecurityOperationSettings settings, int? proxyPort = null)
            : base(Options.Create(Database(proxyPort)), Options.Create(settings)) => _fixture = fixture;
        private static DatabaseSettings Database(int? port)
        {
            var parsed = new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);
            return new() { servers = port.HasValue ? "127.0.0.1" : parsed.Host, port = port ?? parsed.Port,
                database = parsed.Database, userId = parsed.Username!, password = parsed.Password!, maximumPoolSize = 1 };
        }
        public override async Task<NpgsqlConnection> CreateConnection(CancellationToken token = default)
        {
            var connection = await base.CreateConnection(token);
            try { await using var command = new NpgsqlCommand($"set search_path to {_fixture.Schema},public", connection); await command.ExecuteNonQueryAsync(token); return connection; }
            catch { await connection.DisposeAsync(); throw; }
        }
    }
}
