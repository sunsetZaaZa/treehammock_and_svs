using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Shouldly;
using treehammock.Rigging.Database.Migrations;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class Cor02MigrationTests
{
    private static string Connection => DeferredSqlProcedureContractSettings.ConnectionString!;

    [Fact]
    public async Task Fresh_and_legacy_upgrade_have_identical_catalogs_and_preserve_legacy_rows()
    {
        await using var fresh = await SqlContractFixture.CreateAsync(TestContext.Current.CancellationToken, installBaseline: false);
        await using var legacy = await SqlContractFixture.CreateAsync(TestContext.Current.CancellationToken, installBaseline: false);
        await using var canonical = await SqlContractFixture.CreateAsync(TestContext.Current.CancellationToken);
        var legacyConnection = await legacy.OpenConnectionAsync();
        await legacy.ExecuteAsync(legacyConnection, DatabaseMigrationRunner.LoadMigrations()[0].Sql);
        await legacy.ExecuteAsync(legacyConnection, """
            insert into accounts(account_id,email_address,verify_status,security_stamp)
            values('00000000-0000-0000-0000-000000000101','legacy@example.invalid',1,'00000000-0000-0000-0000-000000000201');
            insert into account_verifications(account_id,verify_key_hash,verify_status,sent_when,expiration,account_security_stamp)
            select account_id,'legacy-proof',2,clock_timestamp(),interval '1 day',security_stamp from accounts;
            insert into two_factor_authentications(two_factor_index,account_id,method,verified,email_address)
            select 0,account_id,1,true,email_address from accounts;
            insert into sessions(access_token_hash,account_id,access_expiration,session_expiration,account_security_stamp)
            select 'legacy-session',account_id,clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 day',security_stamp from accounts;
            """);
        string dataBefore = await Data(legacyConnection, legacy.Token);
        var freshResult = await DatabaseMigrationRunner.ApplyAsync(Connection, fresh.Schema, cancellation: fresh.Token);
        var legacyResult = await DatabaseMigrationRunner.ApplyAsync(Connection, legacy.Schema, adoptLegacy: true, cancellation: legacy.Token);
        freshResult.Applied.ShouldBe(DatabaseMigrationRunner.LoadMigrations().Count);
        freshResult.AdoptedLegacy.ShouldBeFalse();
        legacyResult.Applied.ShouldBe(DatabaseMigrationRunner.LoadMigrations().Count);
        legacyResult.AdoptedLegacy.ShouldBeTrue();
        (await Data(legacyConnection, legacy.Token)).ShouldBe(dataBefore);
        var freshConnection = await fresh.OpenConnectionAsync();
        await using var freshTransaction = await fresh.BeginTransactionAsync(freshConnection);
        await using var legacyTransaction = await legacy.BeginTransactionAsync(legacyConnection);
        string actual = await DatabaseMigrationRunner.FingerprintAsync(freshConnection, freshTransaction, fresh.Schema, fresh.Token);
        string upgraded = await DatabaseMigrationRunner.FingerprintAsync(legacyConnection, legacyTransaction, legacy.Schema, legacy.Token);
        actual.ShouldBe(upgraded);
        var canonicalConnection = await canonical.OpenConnectionAsync();
        await using var canonicalTransaction = await canonical.BeginTransactionAsync(canonicalConnection);
        (await DatabaseMigrationRunner.FingerprintAsync(canonicalConnection, canonicalTransaction, canonical.Schema, canonical.Token)).ShouldBe(actual);
        await canonicalTransaction.RollbackAsync(canonical.Token);
        await freshTransaction.RollbackAsync(fresh.Token);
        await legacyTransaction.RollbackAsync(legacy.Token);
        (await DatabaseMigrationRunner.ApplyAsync(Connection, legacy.Schema, cancellation: legacy.Token)).Applied.ShouldBe(0);
    }

    [Fact]
    public async Task Existing_schema_requires_explicit_adoption_and_drift_is_refused_without_history()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var connection = await fixture.OpenConnectionAsync();
            await fixture.ExecuteAsync(connection, DatabaseMigrationRunner.LoadMigrations()[0].Sql, cancellation: cancellation);
            await Should.ThrowAsync<InvalidOperationException>(() => DatabaseMigrationRunner.ApplyAsync(Connection, fixture.Schema, cancellation: cancellation));
            await fixture.ExecuteAsync(connection, "alter table accounts add column unexpected_contract text", cancellation: cancellation);
            await Should.ThrowAsync<InvalidOperationException>(() => DatabaseMigrationRunner.ApplyAsync(Connection, fixture.Schema, true, cancellation));
            (await Scalar<bool>(connection, "select to_regclass('treehammock_schema_history') is null", cancellation)).ShouldBeTrue();
            (await Scalar<long>(connection, "select count(*) from pg_namespace where nspname like 'cor02_adopt_%'", cancellation)).ShouldBe(0);
        }, TestContext.Current.CancellationToken, installBaseline: false);
    }

    [Theory]
    [InlineData("checksum")]
    [InlineData("gap")]
    [InlineData("unknown")]
    public async Task Inconsistent_history_refuses_the_run(string fault)
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            await DatabaseMigrationRunner.ApplyAsync(Connection, fixture.Schema, cancellation: cancellation);
            var connection = await fixture.OpenConnectionAsync();
            string mutation = fault switch
            {
                "checksum" => "update treehammock_schema_history set sha256=repeat('0',64) where version=1",
                "gap" => "delete from treehammock_schema_history where version=1",
                _ => "insert into treehammock_schema_history(version,name,sha256) values(7,'007_unknown.sql',repeat('0',64))"
            };
            await fixture.ExecuteAsync(connection, mutation, cancellation: cancellation);
            await Should.ThrowAsync<InvalidOperationException>(() => DatabaseMigrationRunner.ApplyAsync(Connection, fixture.Schema, cancellation: cancellation));
            (await Scalar<long>(connection, "select count(*) from accounts", cancellation)).ShouldBe(0);
        }, TestContext.Current.CancellationToken, installBaseline: false);
    }

    [Fact]
    public async Task Failed_second_migration_rolls_back_first_schema_history_and_lease()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var migrations = DatabaseMigrationRunner.LoadMigrations().ToArray();
            string broken = migrations[1].Sql + "\nselect 1/0;\n";
            migrations[1] = migrations[1] with { Sql = broken, Sha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(broken))).ToLowerInvariant() };
            await Should.ThrowAsync<PostgresException>(() => DatabaseMigrationRunner.ApplyAsync(Connection, fixture.Schema, cancellation: cancellation, migrations: migrations));
            var connection = await fixture.OpenConnectionAsync();
            (await Scalar<bool>(connection, "select to_regclass('accounts') is null and to_regclass('treehammock_schema_history') is null", cancellation)).ShouldBeTrue();
            (await DatabaseMigrationRunner.ApplyAsync(Connection, fixture.Schema, cancellation: cancellation)).Applied.ShouldBe(DatabaseMigrationRunner.LoadMigrations().Count);
        }, TestContext.Current.CancellationToken, installBaseline: false);
    }

    [Fact]
    public async Task Concurrent_deployer_lease_is_exclusive_and_cancellation_releases_it()
    {
        await SqlContractFixture.RunAsync(async (fixture, cancellation) =>
        {
            var blocker = await fixture.OpenConnectionAsync();
            var transaction = await fixture.BeginTransactionAsync(blocker);
            await fixture.ExecuteAsync(blocker, $"select pg_advisory_xact_lock(hashtextextended(current_database()||':{fixture.Schema}',0))", transaction, cancellation);
            using var contenderCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            var task = fixture.Observe(DatabaseMigrationRunner.ApplyAsync(Connection, fixture.Schema, cancellation: contenderCancellation.Token));
            var observer = await fixture.OpenConnectionAsync();
            // Observe the contender's granted bootstrap lease while its schema
            // try-lease is denied. Time alone never establishes serialization.
            while (!await Scalar<bool>(observer, $"""
                select exists(select 1 from pg_stat_activity a join pg_locks l on l.pid=a.pid
                 where a.application_name='treehammock-migrations:{fixture.Schema}'
                   and l.locktype='advisory' and l.granted and l.objid=548013001);
                """, cancellation))
            {
                if (task.IsCompleted) { await task; throw new InvalidOperationException("Deployer bypassed the held lease."); }
                await Task.Delay(20, cancellation);
            }
            task.IsCompleted.ShouldBeFalse();
            contenderCancellation.Cancel();
            try { await task; throw new InvalidOperationException("Cancelled migration completed."); }
            catch (OperationCanceledException) { }
            (await Scalar<bool>(observer, "select to_regclass('treehammock_schema_history') is null", cancellation)).ShouldBeTrue();
            await transaction.RollbackAsync(cancellation);
            (await DatabaseMigrationRunner.ApplyAsync(Connection, fixture.Schema, cancellation: cancellation)).Applied.ShouldBe(DatabaseMigrationRunner.LoadMigrations().Count);
        }, TestContext.Current.CancellationToken, installBaseline: false);
    }

    [Fact]
    public async Task Published_bundle_rejects_modified_SQL_before_opening_a_connection()
    {
        var migrations = DatabaseMigrationRunner.LoadMigrations().ToArray();
        migrations[0] = migrations[0] with { Sql = migrations[0].Sql + "-- drift" };
        await Should.ThrowAsync<InvalidOperationException>(() => DatabaseMigrationRunner.ApplyAsync("", migrations: migrations));
    }

    [Fact]
    public async Task Routine_fingerprint_normalizes_only_owned_search_path_and_retains_body_order_and_security()
    {
        await using var first = await SqlContractFixture.CreateAsync(TestContext.Current.CancellationToken, installBaseline: false);
        await using var second = await SqlContractFixture.CreateAsync(TestContext.Current.CancellationToken, installBaseline: false);
        var a = await first.OpenConnectionAsync(); var b = await second.OpenConnectionAsync();
        string Definition(string schema) => $"create or replace function fingerprint_probe() returns integer language sql set search_path=pg_catalog,{schema},public,pg_temp as 'select 1'";
        await first.ExecuteAsync(a,Definition(first.Schema),cancellation:first.Token);
        await second.ExecuteAsync(b,Definition(second.Schema),cancellation:second.Token);
        await using var ta = await first.BeginTransactionAsync(a);
        await using var tb = await second.BeginTransactionAsync(b);
        string expected = await DatabaseMigrationRunner.FingerprintAsync(a,ta,first.Schema,first.Token);
        (await DatabaseMigrationRunner.FingerprintAsync(b,tb,second.Schema,second.Token)).ShouldBe(expected);
        foreach(string mutation in new[] {
            $"alter function fingerprint_probe() set search_path={second.Schema},pg_catalog,public,pg_temp",
            $"alter function fingerprint_probe() set search_path=pg_catalog,{second.Schema},foreign_schema,pg_temp",
            $"alter function fingerprint_probe() set search_path=pg_catalog,\"prefix, {second.Schema}, suffix\",public,pg_temp",
            "alter function fingerprint_probe() security definer",
            "revoke execute on function fingerprint_probe() from public",
            "create or replace function fingerprint_probe() returns integer language sql as 'select 2'"
        }) {
            await second.ExecuteAsync(b,"savepoint fingerprint_control",tb,second.Token);
            await second.ExecuteAsync(b,mutation,tb,second.Token);
            (await DatabaseMigrationRunner.FingerprintAsync(b,tb,second.Schema,second.Token)).ShouldNotBe(expected);
            await second.ExecuteAsync(b,"rollback to savepoint fingerprint_control",tb,second.Token);
        }
        // Explicit schema text inside a function body is never rewritten as a schema placeholder.
        await first.ExecuteAsync(a,$"create function body_probe() returns text language sql as 'select ''{first.Schema}.object''::text'",ta,first.Token);
        await second.ExecuteAsync(b,$"create function body_probe() returns text language sql as 'select ''{second.Schema}.object''::text'",tb,second.Token);
        (await DatabaseMigrationRunner.FingerprintAsync(a,ta,first.Schema,first.Token))
            .ShouldNotBe(await DatabaseMigrationRunner.FingerprintAsync(b,tb,second.Schema,second.Token));
    }

    private static Task<string> Data(NpgsqlConnection connection, CancellationToken cancellation) => Scalar<string>(connection, """
        select jsonb_build_array(
            (select jsonb_agg(to_jsonb(a) order by account_id) from accounts a),
            (select jsonb_agg(to_jsonb(v) order by verification_index) from account_verifications v),
            (select jsonb_agg(to_jsonb(t) order by account_id,two_factor_index) from two_factor_authentications t),
            (select jsonb_agg(to_jsonb(s) order by access_token_hash) from sessions s))::text;
        """, cancellation);
    private static async Task<T> Scalar<T>(NpgsqlConnection connection, string sql, CancellationToken cancellation)
    {
        await using var command = new NpgsqlCommand(sql, connection) { CommandTimeout = 10 };
        return (T)(await command.ExecuteScalarAsync(cancellation))!;
    }
}
