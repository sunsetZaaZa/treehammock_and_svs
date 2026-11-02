using Npgsql;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.YsqlTests;

// Compiled independently; missing native prerequisites fail explicitly, never skip or masquerade as a pass.
public sealed class ReadOnlyPrivilegesTests
{
    private static string Required(string key) => Environment.GetEnvironmentVariable(key) ?? throw new InvalidOperationException("Native configuration missing: "+key);
    private static async Task<NpgsqlConnection> Open(NpgsqlDataSource source,CancellationToken ct)
    {
        if(Required("SVS05_DISPOSABLE_DATABASE")!="true")throw new InvalidOperationException("Explicit disposable database ownership required.");
        var c=await source.OpenConnectionAsync(ct);
        try
        {
            await using var cmd=new NpgsqlCommand("select version()",c);
            Assert.Contains("YB",(string)(await cmd.ExecuteScalarAsync(ct))!,StringComparison.OrdinalIgnoreCase);return c;
        }
        catch { await c.DisposeAsync();throw; }
    }
    [Fact] public async Task Actual_login_passes_complete_catalog_inspection()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var raw=YsqlAuthorityDataSource.Create(Required("SVS05_READER_CONNECTION"));
        await using var c=await Open(raw,ct);
        await using var identity=YsqlAuthorityDataSource.CreateValidator(Required("SVS05_READER_CONNECTION"));
        Assert.False(identity.DatabaseFallbackReady);
        Assert.Equal(DatabaseIdentityAuditStatus.Verified,(await identity.RefreshIdentityAsync(ct)).Status);
        Assert.True(identity.DatabaseFallbackReady);
    }
    [Theory]
    [InlineData("insert into public.accounts(account_id) values(gen_random_uuid())")]
    [InlineData("update public.accounts set unlock_when=null where false")]
    [InlineData("delete from public.accounts where false")]
    [InlineData("truncate public.sessions")]
    [InlineData("update public.sessions set refresh_token=refresh_token where false")]
    [InlineData("select * from public.accounts limit 0")]
    [InlineData("select * from public.sessions limit 0")]
    [InlineData("select * from public.two_factor_authentications limit 0")]
    [InlineData("select * from pg_catalog.pg_authid limit 0")]
    [InlineData("select * from pg_catalog.pg_shadow limit 0")]
    [InlineData("create schema svs05_forbidden")]
    [InlineData("create temporary table svs05_forbidden_temp(x integer)")]
    [InlineData("create table public.svs05_forbidden_table(x integer)")]
    [InlineData("select public.cor20_resolve_account('00000000-0000-0000-0000-000000000001'::uuid)")]
    [InlineData("select public.cor02_lock_account_authority('00000000-0000-0000-0000-000000000001'::uuid,'activation')")]
    [InlineData("select * from public.get_session(repeat('A',64))")]
    [InlineData("select * from public.validate_cached_session_trust(repeat('A',64),'00000000-0000-0000-0000-000000000001'::uuid,'00000000-0000-0000-0000-000000000001'::uuid,'00000000-0000-0000-0000-000000000001'::uuid)")]
    [InlineData("select pg_catalog.lo_create(0::oid)")]
    [InlineData("set role treehammock_entitlement_issuer")]
    [InlineData("grant treehammock_svs_read to treehammock_svs with admin option")]
    public async Task Real_privileges_deny_writes_secrets_shadowing_and_legacy_functions(string sql)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var source=YsqlAuthorityDataSource.Create(Required("SVS05_READER_CONNECTION"));
        await using var c=await Open(source,ct);
        // Disable the convenience GUC: only ACL denial SQLSTATE 42501 is accepted.
        await using(var setup=new NpgsqlCommand("set default_transaction_read_only=off",c))await setup.ExecuteNonQueryAsync(ct);
        await using var tx=await c.BeginTransactionAsync(ct);
        try
        {
            await using(var mode=new NpgsqlCommand("set transaction read write; set local statement_timeout='2s';set local lock_timeout='200ms'",c,tx))await mode.ExecuteNonQueryAsync(ct);
            var ex=await Assert.ThrowsAsync<PostgresException>(async()=>{await using var cmd=new NpgsqlCommand(sql,c,tx);await cmd.ExecuteNonQueryAsync(ct);});
            Assert.Equal("42501",ex.SqlState);
        }
        finally { using var cleanup=new CancellationTokenSource(TimeSpan.FromSeconds(3));await tx.RollbackAsync(cleanup.Token); }
    }
    [Fact] public async Task Preserved_nonowner_writer_can_read_and_call_existing_function()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var source=YsqlAuthorityDataSource.Create(Required("SVS05_WRITER_CONNECTION"));await using var c=await Open(source,ct);
        await using var check=new NpgsqlCommand("select not r.rolsuper and r.rolname<>'treehammock_svs' and p.proowner<>r.oid from pg_roles r cross join pg_proc p where r.rolname=current_user and p.oid='public.get_session(text)'::regprocedure",c);
        Assert.Equal(true,await check.ExecuteScalarAsync(ct));
        await using var read=new NpgsqlCommand("select count(*) from public.accounts where false;select public.cor20_capabilities(1::smallint);select * from public.get_session(repeat('A',64))",c);
        await using var rows=await read.ExecuteReaderAsync(ct);while(await rows.NextResultAsync(ct)) { }
    }
    [Fact] public async Task New_owner_objects_do_not_leak_through_future_public_defaults()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var admin=YsqlAuthorityDataSource.Create(Required("SVS05_OWNER_CONNECTION"));await using var owner=await Open(admin,ct);
        await using var source=YsqlAuthorityDataSource.Create(Required("SVS05_READER_CONNECTION"));await using var c=await Open(source,ct);
        string suffix=Guid.NewGuid().ToString("N"),table="public.svs05_table_"+suffix,function="public.svs05_function_"+suffix;
        try
        {
            await using(var create=new NpgsqlCommand($"create table {table}(x integer);create function {function}() returns integer language sql stable security invoker as 'select 1'",owner))await create.ExecuteNonQueryAsync(ct);
            foreach(string statement in new[]{"select * from "+table,"select "+function+"()"})
            {
                var ex=await Assert.ThrowsAsync<PostgresException>(async()=>{await using var cmd=new NpgsqlCommand(statement,c);await cmd.ExecuteNonQueryAsync(ct);});Assert.Equal("42501",ex.SqlState);
            }
        }
        finally { using var cleanup=new CancellationTokenSource(TimeSpan.FromSeconds(5));await using var drop=new NpgsqlCommand($"drop function if exists {function}();drop table if exists {table}",owner);await drop.ExecuteNonQueryAsync(cleanup.Token); }
    }
    [Fact] public async Task Pool_reuse_resets_role_search_path_and_readonly_context_after_cancellation()
    {
        var ct=TestContext.Current.CancellationToken;
        var config=new NpgsqlConnectionStringBuilder(Required("SVS05_READER_CONNECTION")){MaxPoolSize=1,MinPoolSize=0};
        await using var source=YsqlAuthorityDataSource.Create(config.ConnectionString);
        await using(var c=await Open(source,ct))
        {
            await using(var settings=new NpgsqlCommand("set role treehammock_svs_read;set search_path=pg_catalog;set default_transaction_read_only=off",c))await settings.ExecuteNonQueryAsync(ct);
            using var cancelled=CancellationTokenSource.CreateLinkedTokenSource(ct);cancelled.CancelAfter(TimeSpan.FromMilliseconds(100));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>{await using var sleep=new NpgsqlCommand("select pg_sleep(2)",c);await sleep.ExecuteNonQueryAsync(cancelled.Token);});
        }
        await using var fresh=await Open(source,ct);
        await using var probe=new NpgsqlCommand("select session_user=current_user and current_user='treehammock_svs' and current_setting('default_transaction_read_only')='on' and current_setting('search_path')='pg_catalog, public, pg_temp'",fresh);
        Assert.Equal(true,await probe.ExecuteScalarAsync(ct));
    }
}
