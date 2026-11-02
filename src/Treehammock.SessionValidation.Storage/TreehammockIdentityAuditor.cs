using System.Data;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
namespace Treehammock.SessionValidation.Storage;

internal static class TreehammockIdentityAuditor
{
    // Bootstrap inspects the helper before executing it. All data is bound; public is
    // the exact schema used by the current SVS read query and reviewed THS policy.
    internal const string PreflightSql = """
        select jsonb_build_object(
         'sessionUser',session_user,'currentUser',current_user,
         'rolesMatch',(select roles=@roles from public.ths_database_role_configuration where singleton),
         'policyMatch',(select policy=@policy from public.ths_database_role_configuration where singleton),
         'groupOwnsObjects',exists(select 1 from pg_shdepend d join pg_roles r on r.oid=d.refobjid where d.refclassid='pg_authid'::regclass and r.rolname=@readgroup and d.deptype in ('o','i')),
         'login',(select jsonb_build_object('login',rolcanlogin,'inherit',rolinherit,'connectionLimit',rolconnlimit,'superuser',rolsuper,'createDb',rolcreatedb,'createRole',rolcreaterole,'replication',rolreplication,'bypassRls',rolbypassrls) from pg_roles where rolname=@validator),
         'readGroup',(select jsonb_build_object('login',rolcanlogin,'inherit',rolinherit,'connectionLimit',rolconnlimit,'superuser',rolsuper,'createDb',rolcreatedb,'createRole',rolcreaterole,'replication',rolreplication,'bypassRls',rolbypassrls) from pg_roles where rolname=@readgroup),
         'membership',(select jsonb_build_object('count',count(*),'member',min(m.rolname),'role',min(r.rolname),'admin',bool_or(a.admin_option)) from pg_auth_members a join pg_roles m on m.oid=a.member join pg_roles r on r.oid=a.roleid where m.rolname=@validator),
         'helper',(select jsonb_build_object('source',p.prosrc,'owner',r.rolname,'definer',p.prosecdef,'kind',p.prokind::text,'language',l.lanname,'volatility',p.provolatile::text,'config',p.proconfig) from pg_proc p join pg_roles r on r.oid=p.proowner join pg_language l on l.oid=p.prolang where p.oid='public.ths_database_role_safe(text,jsonb)'::regprocedure))::text
        """;
    internal static async Task<string> InspectAsync(NpgsqlDataSource source, TreehammockRoleMap roles, CancellationToken token)
    {
        if (System.Transactions.Transaction.Current is not null) throw new InvalidOperationException("Ambient identity transaction forbidden.");
        await using var connection = await source.OpenConnectionAsync(token);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, token);
        await using (var setup = new NpgsqlCommand("set transaction read only; set local search_path=pg_catalog; set local yb_read_from_followers=off; set local statement_timeout='2s'; set local lock_timeout='500ms'", connection, transaction) { CommandTimeout = 3 }) await setup.ExecuteNonQueryAsync(token);
        JsonObject result;
        await using (var command = new NpgsqlCommand(PreflightSql, connection, transaction) { CommandTimeout = 3 })
        {
            command.Parameters.AddWithValue("roles", NpgsqlDbType.Jsonb, TreehammockIdentityPolicy.RolesJson(roles));
            command.Parameters.AddWithValue("policy", NpgsqlDbType.Jsonb, TreehammockIdentityPolicy.Policy);
            command.Parameters.AddWithValue("validator", roles.Validator); command.Parameters.AddWithValue("readgroup", roles.ValidatorRead);
            string json = (string)(await command.ExecuteScalarAsync(token) ?? throw new InvalidOperationException("No identity result."));
            using var parsed = JsonDocument.Parse(json);
            if (!TreehammockIdentityPolicy.Preflight(parsed.RootElement, roles)) return "{}";
            result = JsonNode.Parse(json)!.AsObject();
        }
        await using (var command = new NpgsqlCommand("select public.ths_database_role_safe('Validator',@policy)", connection, transaction) { CommandTimeout = 3 })
        {
            command.Parameters.AddWithValue("policy", NpgsqlDbType.Jsonb, TreehammockIdentityPolicy.Policy);
            result["helperSafe"] = await command.ExecuteScalarAsync(token) is true;
        }
        await transaction.CommitAsync(token); return result.ToJsonString();
    }
}
