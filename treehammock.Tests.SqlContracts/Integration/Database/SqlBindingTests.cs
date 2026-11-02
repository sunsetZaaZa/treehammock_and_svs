using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Npgsql;
using NpgsqlTypes;
using Shouldly;
using treehammock.Rigging.Config;
using treehammock.Services;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

// Actual current SQL, default conflict setting, real v2 encryption and independent observers.
// Proof attestation and issuer membership are private-schema fixtures. This bypasses the
// repository target-check defect tracked as R23B-01/COR23AF; it cannot qualify that layer.
[Trait("Suite", "SqlContracts")]
public sealed class Cor23BSqlBindingTests
{
    private sealed record Subject(Guid Account, Guid Stamp)
    { public string Email => $"{Account:N}@example.test"; }
    private sealed record Material(byte[] Plain, ProtectedTotpSecret Protected, TotpSecretProtector Protector)
    {
        public static Material Create(Guid account)
        {
            var protector = new TotpSecretProtector(Options.Create(new TotpSettings
            { ActiveProtectionKeyId = "binding-test", ProtectionKeys = new() { ["binding-test"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } }));
            byte[] plain = RandomNumberGenerator.GetBytes(32);
            return new(plain, protector.Protect(plain, new(account, Guid.NewGuid(), new("SHA256", 6, 30, 1))), protector);
        }
    }
    private sealed record Outcome(bool Result, string Code, long? Index, DateTime? Expiration);
    private static async Task Exec(NpgsqlConnection c, string sql, CancellationToken ct)
    { await using var cmd = new NpgsqlCommand(sql, c); await cmd.ExecuteNonQueryAsync(ct); }
    private static async Task<T> Scalar<T>(NpgsqlConnection c, string sql, CancellationToken ct)
    { await using var cmd = new NpgsqlCommand(sql, c); return (T)(await cmd.ExecuteScalarAsync(ct))!; }
    private static async Task<Subject> Seed(NpgsqlConnection c, CancellationToken ct)
    {
        // Assert the server/session default rather than setting a preference that hides ambiguity.
        (await Scalar<string>(c, "show plpgsql.variable_conflict", ct)).ShouldBe("error");
        var a = new Subject(Guid.NewGuid(), Guid.NewGuid());
        await Exec(c, $"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{a.Account}','{a.Email}',1,'{a.Stamp}')", ct);
        return a;
    }
    private static Task<string> Snapshot(NpgsqlConnection c, Subject a, CancellationToken ct)
        => Scalar<string>(c, $"select coalesce(jsonb_agg(to_jsonb(t) order by t.two_factor_index),'[]'::jsonb)::text from two_factor_authentications t where t.account_id='{a.Account}'", ct);
    private static void Parameter(NpgsqlCommand cmd, string name, NpgsqlDbType type, object? value)
        => cmd.Parameters.Add(name, type).Value = value ?? DBNull.Value;
    private static async Task<Outcome> Begin(NpgsqlConnection c, Subject a, Cor16EnrollmentSql.Grant g, Material material,
        CancellationToken ct, Guid? expected = null, long? version = null, string invalid = "", bool legacy = false)
    {
        string function = legacy ? "begin_authenticator_app_setup" : "cor08_authorized_begin_authenticator_app_setup";
        await using var cmd = new NpgsqlCommand($"""
            select result,code,two_factor_index,expiration from {function}(
              @account,@stamp,@token,@created,@expires,@label,@required,@provider,@cipher,@nonce,@tag,
              @secretVersion,@key,@enrollment,@algorithm,@digits,@period,@skew,@expected,@version
              {(legacy ? "" : ",@session,@grant,@target")})
            """, c);
        var p = material.Protected;
        var now = DateTime.UtcNow;
        Parameter(cmd,"account",NpgsqlDbType.Uuid,a.Account);
        Parameter(cmd,"stamp",NpgsqlDbType.Uuid,invalid == "stamp" ? Guid.NewGuid() : a.Stamp);
        Parameter(cmd,"token",NpgsqlDbType.Text,invalid == "token" ? " " : p.Context.EnrollmentId.ToString("N"));
        Parameter(cmd,"created",NpgsqlDbType.TimestampTz,now);
        Parameter(cmd,"expires",NpgsqlDbType.TimestampTz,invalid == "expiry" ? now.AddMinutes(-1) : now.AddMinutes(20));
        Parameter(cmd,"label",NpgsqlDbType.Text,"replacement");Parameter(cmd,"required",NpgsqlDbType.Boolean,true);
        Parameter(cmd,"provider",NpgsqlDbType.Smallint,(short)(invalid == "provider" ? 2 : 1));
        Parameter(cmd,"cipher",NpgsqlDbType.Bytea,invalid == "secret" ? null : p.Ciphertext);
        Parameter(cmd,"nonce",NpgsqlDbType.Bytea,p.Nonce);Parameter(cmd,"tag",NpgsqlDbType.Bytea,p.Tag);
        Parameter(cmd,"secretVersion",NpgsqlDbType.Integer,p.Version);Parameter(cmd,"key",NpgsqlDbType.Text,p.KeyId);
        Parameter(cmd,"enrollment",NpgsqlDbType.Uuid,p.Context.EnrollmentId);
        Parameter(cmd,"algorithm",NpgsqlDbType.Text,p.Context.Parameters.HashAlgorithm);
        Parameter(cmd,"digits",NpgsqlDbType.Integer,p.Context.Parameters.Digits);
        Parameter(cmd,"period",NpgsqlDbType.Integer,p.Context.Parameters.PeriodSeconds);
        Parameter(cmd,"skew",NpgsqlDbType.Integer,p.Context.Parameters.AllowedClockSkewSteps);
        Parameter(cmd,"expected",NpgsqlDbType.Uuid,invalid == "predecessor" ? Guid.NewGuid() : expected);
        Parameter(cmd,"version",NpgsqlDbType.Bigint,invalid == "version" ? 99L : version);
        if (!legacy)
        {
            Parameter(cmd,"session",NpgsqlDbType.Text,g.Session);Parameter(cmd,"grant",NpgsqlDbType.Text,g.Token);
            Parameter(cmd,"target",NpgsqlDbType.Text,invalid == "target" ? new string('b',64) : g.Target);
        }
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        (await reader.ReadAsync(ct)).ShouldBeTrue();
        var result = new Outcome(reader.GetBoolean(0),reader.GetString(1),reader.IsDBNull(2) ? null : reader.GetInt64(2),reader.IsDBNull(3) ? null : reader.GetDateTime(3));
        (await reader.ReadAsync(ct)).ShouldBeFalse();
        return result;
    }
    private static async Task AssertMaterial(NpgsqlConnection observer, Subject a, Material material, long version, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand($"select totp_secret_ciphertext,totp_secret_nonce,totp_secret_tag,totp_secret_version,totp_key_id,totp_enrollment_id,setup_request_id,setup_version,token,method,verified,email_address,phone_number from two_factor_authentications where account_id='{a.Account}'",observer);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        (await reader.ReadAsync(ct)).ShouldBeTrue();
        var persisted = new ProtectedTotpSecret(reader.GetFieldValue<byte[]>(0),reader.GetFieldValue<byte[]>(1),reader.GetFieldValue<byte[]>(2),reader.GetInt32(3),reader.GetString(4),material.Protected.Context);
        material.Protector.Unprotect(persisted).ShouldBe(material.Plain);
        persisted.Ciphertext.ShouldBe(material.Protected.Ciphertext);
        reader.GetGuid(5).ShouldBe(material.Protected.Context.EnrollmentId);
        reader.GetGuid(6).ShouldBe(material.Protected.Context.EnrollmentId);reader.GetInt64(7).ShouldBe(version);
        reader.GetString(8).ShouldBe(material.Protected.Context.EnrollmentId.ToString("N"));reader.GetInt16(9).ShouldBe((short)3);
        reader.GetBoolean(10).ShouldBeFalse();reader.IsDBNull(11).ShouldBeTrue();reader.IsDBNull(12).ShouldBeTrue();
        (await reader.ReadAsync(ct)).ShouldBeFalse();
    }
    private static async Task<(Guid Request, long Index)> Pending(NpgsqlConnection c, Subject a, int method, CancellationToken ct)
    {
        Guid request = Guid.NewGuid();
        var g = await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,method == 3 ? 1 : method == 1 ? 3 : 4,ct);
        if (method == 3)
        {
            var material = Material.Create(a.Account);
            var result = await Begin(c,a,g,material,ct);result.Code.ShouldBe("AUTHENTICATOR_SETUP_PENDING");result.Result.ShouldBeTrue();
            request = material.Protected.Context.EnrollmentId;
        }
        else
            (await Scalar<bool>(c,Cor16EnrollmentSql.Begin(a.Account,a.Stamp,method,"old-proof",request,g),ct)).ShouldBeTrue();
        long index = await Scalar<long>(c,$"select two_factor_index from two_factor_authentications where account_id='{a.Account}'",ct);
        return (request,index);
    }

    [Fact]
    public Task Fresh_insert_returns_exact_pending_result_and_committed_v2_material()
        => SqlContractFixture.RunAsync(async (f,ct) =>
    {
        var c=await f.OpenConnectionAsync();var observer=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,1,ct);var material=Material.Create(a.Account);
        var result=await Begin(c,a,g,material,ct);
        result.Result.ShouldBeTrue();result.Code.ShouldBe("AUTHENTICATOR_SETUP_PENDING");result.Index.ShouldBe(0L);result.Expiration.ShouldNotBeNull();
        await AssertMaterial(observer,a,material,1,ct);
        (await Scalar<bool>(observer,$"select consumed_on is not null from sensitive_action_grants where token_hash='{g.Token}'",ct)).ShouldBeTrue();
    });

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public Task Pending_email_sms_and_authenticator_replacement_keeps_index_and_changes_secret(int method)
        => SqlContractFixture.RunAsync(async (f,ct) =>
    {
        var c=await f.OpenConnectionAsync();var observer=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        var prior=await Pending(c,a,method,ct);string old=await Snapshot(observer,a,ct);
        var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,1,ct);var material=Material.Create(a.Account);
        var result=await Begin(c,a,g,material,ct,prior.Request,1);
        result.Result.ShouldBeTrue();result.Code.ShouldBe("AUTHENTICATOR_SETUP_PENDING");result.Index.ShouldBe(prior.Index);result.Expiration.ShouldNotBeNull();
        await AssertMaterial(observer,a,material,2,ct);(await Snapshot(observer,a,ct)).ShouldNotBe(old);
        (await Scalar<long>(observer,$"select count(*) from two_factor_authentications where account_id='{a.Account}' and setup_request_id='{prior.Request}'",ct)).ShouldBe(0);
        (await Scalar<bool>(observer,$"select consumed_on is not null from sensitive_action_grants where token_hash='{g.Token}'",ct)).ShouldBeTrue();
    });

    [Theory]
    [InlineData("provider","AUTHENTICATOR_SETUP_UNSUPPORTED_PROVIDER")]
    [InlineData("token","AUTHENTICATOR_SETUP_INVALID_TOKEN")]
    [InlineData("expiry","AUTHENTICATOR_SETUP_INVALID_EXPIRATION")]
    [InlineData("secret","AUTHENTICATOR_SETUP_INVALID_SECRET")]
    [InlineData("predecessor","AUTHENTICATOR_SETUP_CONFLICT")]
    [InlineData("version","AUTHENTICATOR_SETUP_CONFLICT")]
    [InlineData("stamp","SENSITIVE_ACTION_GRANT_REQUIRED")]
    [InlineData("target","SENSITIVE_ACTION_GRANT_REQUIRED")]
    [InlineData("purpose","SENSITIVE_ACTION_GRANT_REQUIRED")]
    [InlineData("missing","SENSITIVE_ACTION_GRANT_REQUIRED")]
    public Task Failed_replacement_returns_exact_denial_and_retains_original_setup(string invalid,string code)
        => SqlContractFixture.RunAsync(async (f,ct) =>
    {
        var c=await f.OpenConnectionAsync();var observer=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        var prior=await Pending(c,a,3,ct);string old=await Snapshot(observer,a,ct);
        var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,invalid == "purpose" ? 3 : 1,ct);
        if (invalid == "missing") g=g with { Token=new string('f',64) };
        var result=await Begin(c,a,g,Material.Create(a.Account),ct,prior.Request,1,invalid);
        result.Result.ShouldBeFalse();result.Code.ShouldBe(code);result.Index.ShouldBeNull();result.Expiration.ShouldBeNull();
        (await Snapshot(observer,a,ct)).ShouldBe(old);
        if (invalid is "predecessor" or "version")
            (await Scalar<bool>(observer,$"select consumed_on is null from sensitive_action_grants where token_hash='{g.Token}'",ct)).ShouldBeTrue();
    });

    [Fact]
    public Task Verified_authenticator_is_retained_and_cannot_be_replaced()
        => SqlContractFixture.RunAsync(async (f,ct) =>
    {
        var c=await f.OpenConnectionAsync();var observer=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        var prior=await Pending(c,a,3,ct);
        await Exec(c,$"update two_factor_authentications set verified=true where account_id='{a.Account}'",ct);
        string old=await Snapshot(observer,a,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,1,ct);
        var result=await Begin(c,a,g,Material.Create(a.Account),ct,prior.Request,1);
        result.Result.ShouldBeFalse();result.Code.ShouldBe("TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED");
        (await Snapshot(observer,a,ct)).ShouldBe(old);
    });

    [Theory]
    [InlineData("zero-write","AUTHENTICATOR_SETUP_CONFLICT")]
    [InlineData("bare-output","AUTHENTICATOR_SETUP_FAILED")]
    public Task Native_write_and_original_ambiguity_oracles_preserve_state_and_allow_retry(string fault,string code)
        => SqlContractFixture.RunAsync(async (f,ct) =>
    {
        var c=await f.OpenConnectionAsync();var observer=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        var prior=await Pending(c,a,3,ct);string old=await Snapshot(observer,a,ct);
        var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,1,ct);var material=Material.Create(a.Account);
        string definition=await Scalar<string>(c,"select pg_get_functiondef(p.oid) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname=current_schema() and p.proname='cor08_authorized_begin_authenticator_app_setup'",ct);
        if (fault == "bare-output")
        {
            definition.ShouldContain("t.two_factor_index = target_index");
            await Exec(c,definition.Replace("t.two_factor_index = target_index","two_factor_index = target_index",StringComparison.Ordinal),ct);
        }
        else
            await Exec(c,"create function cor23b_skip_write() returns trigger language plpgsql as $$ begin return null; end $$; create trigger cor23b_skip_write before update on two_factor_authentications for each row execute function cor23b_skip_write()",ct);
        var denied=await Begin(c,a,g,material,ct,prior.Request,1);
        denied.Result.ShouldBeFalse();denied.Code.ShouldBe(code);(await Snapshot(observer,a,ct)).ShouldBe(old);
        (await Scalar<bool>(observer,$"select consumed_on is null from sensitive_action_grants where token_hash='{g.Token}'",ct)).ShouldBeTrue();
        if (fault == "bare-output") await Exec(c,definition,ct);
        else await Exec(c,"drop trigger cor23b_skip_write on two_factor_authentications",ct);
        var retry=await Begin(c,a,g,material,ct,prior.Request,1);
        retry.Result.ShouldBeTrue();retry.Code.ShouldBe("AUTHENTICATOR_SETUP_PENDING");await AssertMaterial(observer,a,material,2,ct);
    });

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public Task Legacy_setup_and_disable_always_deny_without_mutating_pending_state(int method)
        => SqlContractFixture.RunAsync(async (f,ct) =>
    {
        var c=await f.OpenConnectionAsync();var observer=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        if (method != 0) await Pending(c,a,method,ct);
        string old=await Snapshot(observer,a,ct);
        var g=new Cor16EnrollmentSql.Grant("unused","unused","unused");
        var denied=await Begin(c,a,g,Material.Create(a.Account),ct,legacy:true);
        denied.Result.ShouldBeFalse();denied.Code.ShouldBe("SENSITIVE_ACTION_GRANT_REQUIRED");
        await using (var cmd=new NpgsqlCommand($"select result,code,status from disable_activation('{a.Account}','{a.Stamp}','{a.Email}',clock_timestamp(),clock_timestamp()+interval '1 day',1::smallint)",c))
        await using (var reader=await cmd.ExecuteReaderAsync(ct))
        {
            (await reader.ReadAsync(ct)).ShouldBeTrue();reader.GetBoolean(0).ShouldBeFalse();
            reader.GetString(1).ShouldBe("ACTIVATION_TRUSTED_GRANT_REQUIRED");reader.IsDBNull(2).ShouldBeTrue();
            (await reader.ReadAsync(ct)).ShouldBeFalse();
        }
        (await Snapshot(observer,a,ct)).ShouldBe(old);
        (await Scalar<long>(observer,"select count(*) from activations",ct)).ShouldBe(0);
    });

    [Theory]
    [InlineData("absent","ACTIVATION_DISABLED")]
    [InlineData("pending","ACTIVATION_DISABLED")]
    [InlineData("expired-request","ACTIVATION_DISABLED")]
    [InlineData("stale-version","ACTIVATION_CONFLICT")]
    [InlineData("wrong-stamp","ACCOUNT_SECURITY_STAMP_MISMATCH")]
    [InlineData("revoked","ACTIVATION_CONFLICT")]
    public Task Current_disable_handles_request_branches_and_denials_with_committed_state(string branch,string code)
        => SqlContractFixture.RunAsync(async (f,ct) =>
    {
        var c=await f.OpenConnectionAsync();var observer=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        var session=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,1,ct);
        Guid family=await Scalar<Guid>(c,$"select session_id from sessions where access_token_hash='{session.Session}'",ct);
        Guid grant=Guid.NewGuid(),request=Guid.NewGuid();
        // Explicit local issuer substitute; no deployment/global role authority claim.
        await Exec(c,"create or replace function cor19_is_issuer(p_actor name) returns boolean language plpgsql stable as $$ begin return p_actor=current_user::name; end $$",ct);
        (await Scalar<bool>(c,$"select result from cor19_issue_grant('{grant}','{a.Account}','{a.Stamp}','treehammock-v1',2::smallint,1::smallint,0::smallint,null,clock_timestamp()+interval '2 days',1,clock_timestamp()+interval '1 hour','binding fixture','redemption',array[]::text[])",ct)).ShouldBeTrue();
        // Only the transition branch is under test. Admission/publication are separate suites.
        if (branch is "pending" or "expired-request")
            await Exec(c,$"insert into grant_activation_requests(request_id,grant_id,account_id,grant_version,origin_stamp,family_id,proof_hash,expires_at,state) values('{request}','{grant}','{a.Account}',1,'{a.Stamp}','{family}','{new string('a',64)}',clock_timestamp()+interval '{(branch == "pending" ? "10 minutes" : "-1 minute")}','pending')",ct);
        if (branch == "revoked") await Exec(c,$"update entitlement_grants set state='revoked',revoked_at=clock_timestamp() where grant_id='{grant}'",ct);
        string before=await Scalar<string>(observer,$"select to_jsonb(g)::text from entitlement_grants g where grant_id='{grant}'",ct);
        Guid stamp=branch == "wrong-stamp" ? Guid.NewGuid() : a.Stamp;
        await using (var cmd=new NpgsqlCommand($"select result,code,grant_version from cor19_transition_activation('{a.Account}','{stamp}','{session.Session}','{family}','{grant}',{(branch == "stale-version" ? 99 : 1)}::bigint,'{request}','{new string('a',64)}','disable')",c))
        await using (var reader=await cmd.ExecuteReaderAsync(ct))
        {
            (await reader.ReadAsync(ct)).ShouldBeTrue();reader.GetBoolean(0).ShouldBe(code == "ACTIVATION_DISABLED");reader.GetString(1).ShouldBe(code);
            if (code == "ACTIVATION_DISABLED") reader.GetInt64(2).ShouldBe(2L);else reader.IsDBNull(2).ShouldBeTrue();
            (await reader.ReadAsync(ct)).ShouldBeFalse();
        }
        if (code == "ACTIVATION_DISABLED")
        {
            (await Scalar<string>(observer,$"select state from entitlement_grants where grant_id='{grant}'",ct)).ShouldBe("revoked");
            (await Scalar<long>(observer,$"select version from entitlement_grants where grant_id='{grant}'",ct)).ShouldBe(2L);
            if (branch != "absent") (await Scalar<string>(observer,$"select state from grant_activation_requests where request_id='{request}'",ct)).ShouldBe("revoked");
        }
        else (await Scalar<string>(observer,$"select to_jsonb(g)::text from entitlement_grants g where grant_id='{grant}'",ct)).ShouldBe(before);
    });
}
