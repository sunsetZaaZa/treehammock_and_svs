using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using Npgsql;
using Shouldly;
using treehammock.DataLayer.Operations;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Operations;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

// Production repository/provider and real owned PostgreSQL. Issuer membership and
// delivery publication are private schema fixtures; no HTTP/provider/role-ACL claim.
[Trait("Suite", "SqlContracts")]
public sealed class Cor23AActivationReaderTests
{
    private sealed record Subject(Guid Account, Guid Stamp, Guid Family, Guid Grant, Guid Request, string Session)
    {
        public string Email => $"{Account:N}@example.test";
        public string Hash => new('a', 64);
    }

    // A single-slot production pool exposes leaks on error cleanup and next-operation reuse.
    private sealed class OwnedStorage : StorageContext
    {
        private readonly SqlContractFixture _fixture;
        public OwnedStorage(SqlContractFixture fixture)
            : base(Options.Create(Settings()), Options.Create(new SecurityOperationSettings
                { HmacKeys = new() { [1] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } }))
            => _fixture = fixture;
        private static DatabaseSettings Settings()
        {
            var c = new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);
            return new() { servers = c.Host, port = c.Port, database = c.Database, userId = c.Username!,
                password = c.Password!, maximumPoolSize = 1, connectionTimeoutSeconds = 3 };
        }
        public override async Task<NpgsqlConnection> CreateConnection(CancellationToken token = default)
        {
            var connection = await base.CreateConnection(token);
            try
            {
                await using var command = new NpgsqlCommand($"set search_path to {_fixture.Schema},public", connection);
                await command.ExecuteNonQueryAsync(token);
                return connection;
            }
            catch { await connection.DisposeAsync(); throw; }
        }
    }

    private static ActivationRepo Repo(StorageContext storage) => new(storage, NullLogger<ActivationRepo>.Instance);
    private static async Task Exec(NpgsqlConnection c, string sql, CancellationToken ct)
    { await using var command = new NpgsqlCommand(sql, c); await command.ExecuteNonQueryAsync(ct); }
    private static async Task<T> Scalar<T>(NpgsqlConnection c, string sql, CancellationToken ct)
    { await using var command = new NpgsqlCommand(sql, c); return (T)(await command.ExecuteScalarAsync(ct))!; }
    private static async Task<(T Result, Guid Operation)> Invoke<T>(string purpose, Func<Task<T>> call)
    {
        var context = SecurityOperationRequestContext.Isolated(purpose);
        var id = SecurityOperationKey.Parse(context.ClientKey!, 900).Id;
        using var ambient = SecurityOperationRequestContext.Push(context);
        return (await call(), id);
    }
    private static Task Receipt(NpgsqlConnection observer, Guid operation, string code, bool succeeded, CancellationToken ct)
        => ReceiptCore(observer, operation, code, succeeded, ct);
    private static async Task ReceiptCore(NpgsqlConnection observer, Guid operation, string code, bool succeeded, CancellationToken ct)
    {
        (await Scalar<long>(observer, $"select count(*) from security_operation_steps where operation_id='{operation}' and outcome_code='{code}' and succeeded={(succeeded ? "true" : "false")}", ct)).ShouldBe(1);
    }
    private static async Task<Subject> Seed(NpgsqlConnection c, CancellationToken ct)
    {
        var a = new Subject(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid().ToString("N"));
        await Exec(c, $"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{a.Account}','{a.Email}',1,'{a.Stamp}'); insert into sessions(access_token_hash,account_id,session_id,account_security_stamp,created_on,access_expiration,session_expiration) values('{a.Session}','{a.Account}','{a.Family}','{a.Stamp}',clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours')", ct);
        // Same explicitly isolated issuer substitute as COR19/21. No global role is created.
        await Exec(c, "create or replace function cor19_is_issuer(p_actor name) returns boolean language plpgsql stable as $$ begin return p_actor=current_user::name; end $$", ct);
        (await Scalar<bool>(c, $"select result from cor19_issue_grant('{a.Grant}','{a.Account}','{a.Stamp}','treehammock-v1',2::smallint,1::smallint,0::smallint,null,clock_timestamp()+interval '2 days',1,clock_timestamp()+interval '1 hour','reviewed reader fixture','redemption',array[]::text[])", ct)).ShouldBeTrue();
        return a;
    }
    private static Task<ActivationCreationAdmission> Admit(ActivationRepo repo, Subject a, CancellationToken ct)
        => repo.AdmitCreationAsync(a.Account, a.Stamp, a.Session, a.Family, a.Grant, 1, a.Hash, a.Email,
            2, 1, 0, new string('b', 32), new ActivationAbusePolicySettings(), ct);
    private static Task<treehammock.Models.Activation.ActivationLifecycleResult> Transition(ActivationRepo repo, Subject a, string action, CancellationToken ct, string? hash = null)
        => repo.TransitionAsync(a.Account, a.Stamp, a.Session, a.Family, a.Grant, 1, a.Request, hash ?? a.Hash, action, ct);
    private static async Task StagePublished(NpgsqlConnection c, ActivationRepo repo, Subject a, CancellationToken ct)
    {
        var admitted = await Invoke("fixture-admit", () => Admit(repo, a, ct));
        admitted.Result.Result.ShouldBeTrue();
        (await Scalar<bool>(c, $"select result from cor19_stage_activation('{a.Request}','{a.Account}','{a.Stamp}','{a.Session}','{a.Family}','{a.Grant}',1,'{a.Hash}',clock_timestamp()+interval '10 minutes','{a.Email}',2::smallint,1::smallint,0::smallint,'{admitted.Result.AdmissionId}')", ct)).ShouldBeTrue();
        await Exec(c, $"insert into delivery_candidates(delivery_id,account_id,account_stamp,purpose,proof_hash,expires_at,metadata_json,predecessor,state,terminal_at) values('{a.Request}','{a.Account}','{a.Stamp}','activation','{a.Hash}',clock_timestamp()+interval '10 minutes','{{}}','fixture','published',clock_timestamp()); select cor19_publish_activation('{a.Request}','{a.Stamp}','{a.Hash}')", ct);
    }
    private static async Task<(bool Result, string Code)> Legacy(ActivationRepo repo, Subject a, string method, CancellationToken ct)
    {
        var now = SystemClock.Instance.GetCurrentInstant();
        if (method == "verify")
        {
            var r = (await repo.VerifyActivation(a.Account, a.Stamp, a.Email, a.Hash, now, 0, 10, ct)).ShouldNotBeNull();
            r.Activation.ShouldBeNull(); return (r.Result, r.Code);
        }
        var result = method switch
        {
            "place" => await repo.PlaceActivation(a.Account, a.Stamp, a.Email, a.Hash, now, DayDuration.DAILY, DurationRepeat.NONE,
                now + Duration.FromDays(1), FeatureSet.premium, PlatformBacker.Intra, "fixture", ActivationStatus.REQUEST, null, ct),
            "cancel" => await repo.CancelActivationRequest(a.Account, a.Stamp, a.Hash, now, ct),
            "disable" => await repo.DisableActivation(a.Account, a.Stamp, a.Email, now, now + Duration.FromDays(1), ActivationStatus.DISRUPTED, ct),
            _ => throw new ArgumentException(nameof(method))
        };
        result.ShouldNotBeNull(); result.Status.ShouldBeNull(); return (result.Result, result.Code);
    }

    [Theory]
    [InlineData("place")]
    [InlineData("cancel")]
    [InlineData("disable")]
    [InlineData("verify")]
    public Task Legacy_denial_materializes_then_commits_receipt_without_restoring_paid_authority(string method)
        => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var observer = await f.OpenConnectionAsync(); var a = await Seed(observer, ct);
        await using var storage = new OwnedStorage(f); var repo = Repo(storage);
        var returned = await Invoke("legacy-" + method, () => Legacy(repo, a, method, ct));
        returned.Result.Result.ShouldBeFalse(); returned.Result.Code.ShouldBe("ACTIVATION_TRUSTED_GRANT_REQUIRED");
        await Receipt(observer, returned.Operation, returned.Result.Code, false, ct);
        (await Scalar<string>(observer, "select state from entitlement_grants", ct)).ShouldBe("approved");
        (await Scalar<long>(observer, "select count(*) from grant_activation_requests", ct)).ShouldBe(0);
        // Run again to establish the connection was released, not merely that a DTO returned.
        (await Invoke("legacy-repeat", () => Legacy(repo, a, method, ct))).Result.Result.ShouldBeFalse();
    });

    [Fact]
    public Task Actual_admission_commits_budget_and_ticket_then_throttle_materializes_false()
        => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var observer = await f.OpenConnectionAsync(); var a = await Seed(observer, ct);
        await using var storage = new OwnedStorage(f); var repo = Repo(storage);
        var admitted = await Invoke("admit", () => Admit(repo, a, ct));
        admitted.Result.Result.ShouldBeTrue(); admitted.Result.AdmissionId.ShouldNotBeNull();
        await Receipt(observer, admitted.Operation, admitted.Result.Code, true, ct);
        (await Scalar<long>(observer, $"select count(*) from activation_creation_admissions where admission_id='{admitted.Result.AdmissionId}'", ct)).ShouldBe(1);
        (await Scalar<int>(observer, $"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'", ct)).ShouldBe(1);
        (await Scalar<string>(observer, $"select expected_version from security_operation_steps where operation_id='{admitted.Operation}'", ct)).ShouldBe("1");
        var denied = await Invoke("throttled", () => Admit(repo, a, ct));
        denied.Result.Result.ShouldBeFalse(); denied.Result.RetryAfterSeconds.ShouldNotBeNull();
        await Receipt(observer, denied.Operation, denied.Result.Code, false, ct);
        (await Scalar<int>(observer, $"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'", ct)).ShouldBe(1);
    });

    [Theory]
    [InlineData("verify")]
    [InlineData("cancel")]
    [InlineData("disable")]
    public Task Actual_lifecycle_decodes_full_result_and_independent_observer_sees_committed_state(string action)
        => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var observer = await f.OpenConnectionAsync(); var a = await Seed(observer, ct);
        await using var storage = new OwnedStorage(f); var repo = Repo(storage);
        await StagePublished(observer, repo, a, ct);
        var returned = await Invoke("transition-" + action, () => Transition(repo, a, action, ct));
        returned.Result.Result.ShouldBeTrue(); returned.Result.GrantVersion.ShouldBe(2);
        returned.Result.Tier.ShouldBe((short)2); returned.Result.Term.ShouldBe((short)1); returned.Result.Cadence.ShouldBe((short)0);
        if (action == "verify") { returned.Result.StartsAt.ShouldNotBeNull(); returned.Result.EligibilityUntil.ShouldNotBeNull(); }
        await Receipt(observer, returned.Operation, returned.Result.Code, true, ct);
        (await Scalar<string>(observer, "select state from entitlement_grants", ct)).ShouldBe(action == "verify" ? "active" : "revoked");
        (await Scalar<string>(observer, "select state from grant_activation_requests", ct)).ShouldBe(action == "verify" ? "active" : "revoked");
        // A stale version is a controlled denial after the successful connection is returned.
        var denied = await Invoke("stale-version", () => Transition(repo, a, action, ct));
        denied.Result.Result.ShouldBeFalse(); denied.Result.Code.ShouldBe("ACTIVATION_CONFLICT");
        await Receipt(observer, denied.Operation, denied.Result.Code, false, ct);
    });

    // Failures modify function bodies only inside this fixture's disposable schema.
    // They are result/rollback fault injection, never a production legacy-success path.
    private static async Task Inject(NpgsqlConnection observer, string method, string fault, CancellationToken ct)
    {
        string name = method switch { "place" => "place_activation", "cancel" => "cancel_activation_request", "disable" => "disable_activation",
            "verify" => "verify_activation", "admit" => "cor21_admit_creation", _ => "cor19_transition_activation" };
        var definition = await Scalar<string>(observer, $"select pg_get_functiondef(p.oid) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname=current_schema() and p.proname='{name}'", ct);
        int start = definition.IndexOf("AS $", StringComparison.OrdinalIgnoreCase);
        int tagEnd = definition.IndexOf('$', start + 4); // pg_get_functiondef uses AS $function$.
        var tag = definition.Substring(start + 3, tagEnd - (start + 3) + 1);
        var write = "insert into cor23a_probe values (1);";
        var columns = method == "verify" ? "false,null::text,null::smallint,null::timestamptz,null::smallint,null::smallint" :
            method == "admit" ? "false,null::text,null::uuid,null::integer" :
            method == "transition" ? "false,null::text,null::bigint,null::timestamptz,null::timestamptz,null::text,null::smallint,null::smallint,null::smallint" :
            "false,null::text,null::smallint";
        var body = fault switch { "no-row" => "return;", "decode" => "return query select " + columns + ";", _ => "raise exception 'owned failure' using errcode='P2301';" };
        await Exec(observer, definition[..(start + 3)] + tag + " begin " + write + body + " end; " + tag + ";", ct);
    }

    [Theory]
    [InlineData("place", "no-row"), InlineData("place", "decode"), InlineData("place", "sql-error")]
    [InlineData("cancel", "no-row"), InlineData("cancel", "decode"), InlineData("cancel", "sql-error")]
    [InlineData("disable", "no-row"), InlineData("disable", "decode"), InlineData("disable", "sql-error")]
    [InlineData("verify", "no-row"), InlineData("verify", "decode"), InlineData("verify", "sql-error")]
    [InlineData("admit", "no-row"), InlineData("admit", "decode"), InlineData("admit", "sql-error")]
    [InlineData("transition", "no-row"), InlineData("transition", "decode"), InlineData("transition", "sql-error")]
    public Task Missing_row_decode_and_sql_errors_roll_back_writes_and_release_the_single_pool_slot(string method, string fault)
        => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var observer = await f.OpenConnectionAsync(); var a = await Seed(observer, ct);
        await Exec(observer, "create table cor23a_probe(value integer)", ct);
        await Inject(observer, method, fault, ct);
        await using var storage = new OwnedStorage(f); var repo = Repo(storage);
        var context = SecurityOperationRequestContext.Isolated("fault-" + method);
        var id = SecurityOperationKey.Parse(context.ClientKey!, 900).Id;
        using (SecurityOperationRequestContext.Push(context))
        {
            var error = await Should.ThrowAsync<SecurityOperationException>(async () =>
            {
                if (method == "admit") await Admit(repo, a, ct);
                else if (method == "transition") await Transition(repo, a, "verify", ct);
                else await Legacy(repo, a, method, ct);
            });
            error.Status.ShouldNotBeNull(); error.Status.State.ShouldBe(SecurityOperationState.RolledBack);
        }
        (await Scalar<long>(observer, "select count(*) from cor23a_probe", ct)).ShouldBe(0);
        (await Scalar<long>(observer, $"select count(*) from security_operation_steps where operation_id='{id}'", ct)).ShouldBe(0);
        (await Scalar<string>(observer, "select state from entitlement_grants", ct)).ShouldBe("approved");
        await using var reused = await storage.CreateConnection(ct);
        (await Scalar<int>(reused, "select 1", ct)).ShouldBe(1);
    });

    [Fact]
    public Task Pinned_provider_rejects_receipt_command_inside_live_reader_then_commits_after_disposal()
        => SqlContractFixture.RunAsync(async (f, ct) =>
    {
        var observer = await f.OpenConnectionAsync(); await using var storage = new OwnedStorage(f);
        var context = SecurityOperationRequestContext.Isolated("provider-oracle");
        var id = SecurityOperationKey.Parse(context.ClientKey!, 900).Id;
        using var ambient = SecurityOperationRequestContext.Push(context);
        await using (var op = await storage.SecurityOperations.BeginAsync("reader-oracle", new { }, null, null, null, ct))
        {
            await using var command = new NpgsqlCommand("select 1", op.Connection, op.Transaction);
            await using (var reader = await command.ExecuteReaderAsync(op.CancellationToken))
            {
                (await reader.ReadAsync(op.CancellationToken)).ShouldBeTrue();
                await Should.ThrowAsync<NpgsqlOperationInProgressException>(() => op.CommitAsync(true));
            }
            await op.CommitAsync(true);
        }
        await Receipt(observer, id, "SUCCEEDED", true, ct);
    });
}
