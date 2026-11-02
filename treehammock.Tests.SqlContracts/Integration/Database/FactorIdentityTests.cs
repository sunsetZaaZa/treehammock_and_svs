using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using Npgsql;
using Shouldly;
using treehammock.DataLayer.Operations;
using treehammock.DataLayer.Security;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Operations;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

// Owned native PostgreSQL and actual repositories. Proof attestation is the explicit
// COR16 fixture substitute. No HTTP, provider delivery or repository replacement claim.
[Trait("Suite", "SqlContracts")]
public sealed class Cor23CFactorIdentityTests
{
    private sealed record Subject(Guid Account, Guid Stamp)
    { public string Email => $"{Account:N}@example.test"; }
    private sealed record Envelope(byte[] Plain, ProtectedTotpSecret Secret, TotpSecretProtector Protector)
    {
        public static Envelope Create(Guid account)
        {
            var protector=new TotpSecretProtector(Options.Create(new TotpSettings { ActiveProtectionKeyId="identity-test",
                ProtectionKeys=new() { ["identity-test"]=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } }));
            byte[] plain=RandomNumberGenerator.GetBytes(32);
            return new(plain,protector.Protect(plain,new(account,Guid.NewGuid(),new("SHA256",6,30,1))),protector);
        }
    }
    private sealed record Result(bool Succeeded,string Code,long? Index);
    private static Cor09RefreshHttpTests.FixtureStorage Storage(SqlContractFixture f)
        => new(f,new SecurityOperationSettings { HmacKeys=new() { [1]=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } });
    private static async Task<T> Invoke<T>(Func<Task<T>> call)
    { using var context=SecurityOperationRequestContext.Push(SecurityOperationRequestContext.Isolated("cor23c"));return await call(); }
    private static async Task Exec(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null)
    { await using var cmd=new NpgsqlCommand(sql,c,tx);await cmd.ExecuteNonQueryAsync(ct); }
    private static async Task<T> Scalar<T>(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null)
    { await using var cmd=new NpgsqlCommand(sql,c,tx);return (T)(await cmd.ExecuteScalarAsync(ct))!; }
    private static async Task<Subject> Seed(NpgsqlConnection c,CancellationToken ct)
    {
        (await Scalar<string>(c,"show plpgsql.variable_conflict",ct)).ShouldBe("error");
        var a=new Subject(Guid.NewGuid(),Guid.NewGuid());
        await Exec(c,$"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{a.Account}','{a.Email}',1,'{a.Stamp}')",ct);return a;
    }
    private static SensitiveActionGrant Grant(Cor16EnrollmentSql.Grant g,string? label="identity")
        => new(g.Session,g.Token,g.Target,SensitiveActionTargets.AuthenticatorSetup(label,true,TotpProviderType.LOCAL_RFC6238));
    private static BeginAuthenticatorAppSetupCommand Command(Subject a,Cor16EnrollmentSql.Grant g,Envelope e)
    {
        var now=SystemClock.Instance.GetCurrentInstant();var p=e.Secret;
        return new(a.Account,a.Stamp,p.Context.EnrollmentId.ToString("N"),now,now+Duration.FromMinutes(20),"identity",true,
            TotpProviderType.LOCAL_RFC6238,p.Ciphertext,p.Nonce,p.Tag,p.Version,Grant(g),p.KeyId,p.Context);
    }
    private static string Hex(byte[] bytes)=>"decode('"+Convert.ToHexString(bytes)+"','hex')";
    private static string Uuid(Guid? id)=>id is null ? "null::uuid" : $"'{id}'::uuid";
    private static async Task<Result> Begin(NpgsqlConnection c,Subject a,Cor16EnrollmentSql.Grant g,int method,Guid request,
        CancellationToken ct,Envelope? e=null,Guid? expected=null,long? version=null,NpgsqlTransaction? tx=null)
    {
        string sql;
        if(method!=3) sql=Cor16EnrollmentSql.Begin(a.Account,a.Stamp,method,request.ToString("N"),request,g,expected,version);
        else
        {
            e.ShouldNotBeNull();var p=e.Secret;
            sql=$"select result,code,two_factor_index from cor08_authorized_begin_authenticator_app_setup('{a.Account}','{a.Stamp}','{request:N}',clock_timestamp(),clock_timestamp()+interval '20 minutes','identity',true,1::smallint,{Hex(p.Ciphertext)},{Hex(p.Nonce)},{Hex(p.Tag)},2,'{p.KeyId}','{p.Context.EnrollmentId}','SHA256',6,30,1,{Uuid(expected)},{(version is null ? "null::bigint" : version+"::bigint")},'{g.Session}','{g.Token}','{g.Target}')";
        }
        // The existing email/SMS helper selects only result/code, so append its output projection here.
        if(method!=3) sql=sql.Replace("select result,code from","select result,code,two_factor_index from",StringComparison.Ordinal);
        await using var cmd=new NpgsqlCommand(sql,c,tx);await using var reader=await cmd.ExecuteReaderAsync(ct);
        (await reader.ReadAsync(ct)).ShouldBeTrue();var result=new Result(reader.GetBoolean(0),reader.GetString(1),reader.IsDBNull(2)?null:reader.GetInt64(2));
        (await reader.ReadAsync(ct)).ShouldBeFalse();return result;
    }
    private static async Task AssertSecret(NpgsqlConnection c,Subject a,Envelope e,CancellationToken ct)
    {
        await using var cmd=new NpgsqlCommand($"select totp_secret_ciphertext,totp_secret_nonce,totp_secret_tag,totp_secret_version,totp_key_id,totp_enrollment_id from two_factor_authentications where account_id='{a.Account}' and revoked_at is null and method=3",c);
        await using var reader=await cmd.ExecuteReaderAsync(ct);(await reader.ReadAsync(ct)).ShouldBeTrue();
        reader.GetGuid(5).ShouldBe(e.Secret.Context.EnrollmentId);
        var stored=new ProtectedTotpSecret(reader.GetFieldValue<byte[]>(0),reader.GetFieldValue<byte[]>(1),reader.GetFieldValue<byte[]>(2),reader.GetInt32(3),reader.GetString(4),e.Secret.Context);
        e.Protector.Unprotect(stored).ShouldBe(e.Plain);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public Task Retained_revoked_history_past_smallint_does_not_block_current_enrollment(int method)
        => SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var observer=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        // Real generated identities, not manual keys or a mock allocator: 0 through 32767.
        int retiredMethod=method==3?3:2;
        await Exec(c,$"insert into two_factor_authentications(account_id,method,verified,revoked_at,revoked_reason,phone_number,phone_country_code) select '{a.Account}',{retiredMethod}::smallint,false,clock_timestamp(),'retained fixture',case when {retiredMethod}=2 then '5555550101' end,case when {retiredMethod}=2 then '1' end from generate_series(1,32768)",ct);
        (await Scalar<long>(observer,$"select max(two_factor_index) from two_factor_authentications where account_id='{a.Account}'",ct)).ShouldBe(32767L);
        var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,method==3?1:method==1?3:4,ct);
        var envelope=Envelope.Create(a.Account);Guid request=method==3?envelope.Secret.Context.EnrollmentId:Guid.NewGuid();
        var result=await Begin(c,a,g,method,request,ct,envelope);
        result.Succeeded.ShouldBeTrue();result.Code.ShouldBe(method==3?"AUTHENTICATOR_SETUP_PENDING":"TWO_FACTOR_SETUP_PENDING");result.Index.ShouldBe(32768L);
        (await Scalar<long>(observer,$"select count(*) from two_factor_authentications where account_id='{a.Account}' and revoked_at is not null",ct)).ShouldBe(32768L);
        (await Scalar<Guid>(observer,$"select setup_request_id from two_factor_authentications where account_id='{a.Account}' and revoked_at is null",ct)).ShouldBe(request);
        if(method==3)await AssertSecret(observer,a,envelope,ct);
    });

    [Theory]
    [InlineData(32768L)]
    [InlineData(4294967296L)]
    public Task Actual_authenticator_and_reset_repositories_decode_and_mark_wide_identity(long identity)
        => SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var observer=await f.OpenConnectionAsync();var a=await Seed(observer,ct);
        // Private boundary fixture, never a deployment backfill or sequence reset policy.
        await Exec(observer,$"select setval(pg_get_serial_sequence('two_factor_authentications','two_factor_index'),{identity-1},true)",ct);
        var g=await Cor16EnrollmentSql.SeedGrant(observer,a.Account,a.Stamp,1,ct);var e=Envelope.Create(a.Account);var command=Command(a,g,e);
        await using var storage=Storage(f);var repo=new AuthenticatorAppEnrollmentRepo(storage,NullLogger<AuthenticatorAppEnrollmentRepo>.Instance);
        var begun=(await Invoke(()=>repo.BeginAuthenticatorAppSetupAsync(command,ct))).ShouldNotBeNull();
        begun.Result.ShouldBeTrue();begun.Code.ShouldBe("AUTHENTICATOR_SETUP_PENDING");begun.TwoFactorIndex.ShouldBe(identity);
        var pending=(await repo.GetPendingAuthenticatorAppSetupAsync(new(a.Account,a.Stamp,command.SetupTokenHash,SystemClock.Instance.GetCurrentInstant()),ct)).ShouldNotBeNull();
        pending.Result.ShouldBeTrue();pending.TwoFactorIndex.ShouldBe(identity);pending.Context.ShouldBe(e.Secret.Context);
        e.Protector.Unprotect(new(pending.TotpSecretCiphertext!,pending.TotpSecretNonce!,pending.TotpSecretTag!,pending.TotpSecretVersion!.Value,pending.TotpKeyId!,pending.Context!)).ShouldBe(e.Plain);
        var now=SystemClock.Instance.GetCurrentInstant();
        var completed=(await Invoke(()=>repo.CompleteAuthenticatorAppSetupAndRotateSessionAsync(new(a.Account,a.Stamp,command.SetupTokenHash,100,g.Session,Guid.NewGuid().ToString("N"),RandomNumberGenerator.GetBytes(32),0,10,now,Duration.FromHours(2),now+Duration.FromHours(1),now+Duration.FromHours(2),null,FeatureSet.basic,Guid.NewGuid()),ct))).ShouldNotBeNull();
        completed.Result.ShouldBeTrue();completed.TwoFactorIndex.ShouldBe(identity);
        var verified=(await repo.GetVerifiedTotpEnrollmentForAccountAsync(a.Account,SystemClock.Instance.GetCurrentInstant(),ct)).ShouldNotBeNull();verified.TwoFactorIndex.ShouldBe(identity);
        var reset=new PasswordResetTotpRepo(storage,NullLogger<PasswordResetTotpRepo>.Instance);
        var resetEnrollment=(await reset.GetPasswordResetTotpEnrollmentAsync(a.Account,SystemClock.Instance.GetCurrentInstant(),ct)).ShouldNotBeNull();resetEnrollment.TwoFactorIndex.ShouldBe(identity);
        (await Invoke(()=>repo.MarkTotpStepUsedAsync(a.Account,identity,101,e.Secret.Context.EnrollmentId,ct))).ShouldNotBeNull().Code.ShouldBe("TOTP_STEP_ACCEPTED");
        (await Invoke(()=>reset.MarkPasswordResetTotpStepUsedAsync(a.Account,identity,101,e.Secret.Context.EnrollmentId,ct))).ShouldNotBeNull().Code.ShouldBe("TOTP_REPLAY_DETECTED");
        (await Invoke(()=>reset.MarkPasswordResetTotpStepUsedAsync(a.Account,identity,102,e.Secret.Context.EnrollmentId,ct))).ShouldNotBeNull().Code.ShouldBe("TOTP_STEP_ACCEPTED");
        (await Scalar<long>(observer,$"select totp_last_used_step from two_factor_authentications where account_id='{a.Account}' and two_factor_index={identity}",ct)).ShouldBe(102L);
        await AssertSecret(observer,a,e,ct);
    });

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public Task Replacement_changes_enrollment_uuid_and_preserves_row_slot_after_boundary(int method)
        => SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var observer=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        await Exec(c,"select setval(pg_get_serial_sequence('two_factor_authentications','two_factor_index'),32767,true)",ct);
        var old=Envelope.Create(a.Account);Guid request=method==3?old.Secret.Context.EnrollmentId:Guid.NewGuid();
        var first=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,method==3?1:method==1?3:4,ct);
        (await Begin(c,a,first,method,request,ct,old)).Index.ShouldBe(32768L);
        var replacement=Envelope.Create(a.Account);var grant=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,1,ct);
        var result=await Begin(c,a,grant,3,replacement.Secret.Context.EnrollmentId,ct,replacement,request,1);
        result.Succeeded.ShouldBeTrue();result.Index.ShouldBe(32768L);result.Code.ShouldBe("AUTHENTICATOR_SETUP_PENDING");
        (await Scalar<long>(observer,$"select setup_version from two_factor_authentications where account_id='{a.Account}'",ct)).ShouldBe(2L);
        await AssertSecret(observer,a,replacement,ct);
        replacement.Secret.Context.EnrollmentId.ShouldNotBe(request);
        old.Protector.Unprotect(old.Secret).ShouldBe(old.Plain); // Row widening did not alter v2 associated data.
        Should.Throw<CryptographicException>(()=>replacement.Protector.Unprotect(replacement.Secret with { Context=replacement.Secret.Context with { EnrollmentId=request } }));
    });

    [Fact]
    public Task Rollback_and_deleted_history_do_not_reuse_generated_factor_identity()
        => SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var observer=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        var grant=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,4,ct);long burned;
        await using(var tx=await f.BeginTransactionAsync(c))
        {
            var result=await Begin(c,a,grant,2,Guid.NewGuid(),ct,tx:tx);result.Succeeded.ShouldBeTrue();burned=result.Index!.Value;
            await tx.RollbackAsync(ct);
        }
        (await Scalar<long>(observer,"select count(*) from two_factor_authentications",ct)).ShouldBe(0L);
        var committed=await Begin(c,a,grant,2,Guid.NewGuid(),ct);committed.Succeeded.ShouldBeTrue();committed.Index!.Value.ShouldBeGreaterThan(burned);
        await Exec(c,$"delete from two_factor_authentications where account_id='{a.Account}'",ct); // Owned retention/discard boundary.
        var nextGrant=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,4,ct);
        var next=await Begin(c,a,nextGrant,2,Guid.NewGuid(),ct);next.Succeeded.ShouldBeTrue();next.Index!.Value.ShouldBeGreaterThan(committed.Index.Value);
    });

    [Fact]
    public Task Concurrent_same_account_creation_serializes_and_leaves_one_pending_enrollment()
        => SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var observer=await f.OpenConnectionAsync();var a=await Seed(observer,ct);
        var first=await Cor16EnrollmentSql.SeedGrant(observer,a.Account,a.Stamp,4,ct);var second=await Cor16EnrollmentSql.SeedGrant(observer,a.Account,a.Stamp,4,ct);
        var owner=await f.OpenConnectionAsync();var waiter=await f.OpenConnectionAsync();
        await using var hold=await f.BeginTransactionAsync(owner);await using var waiting=await f.BeginTransactionAsync(waiter);
        await Exec(owner,$"select cor02_lock_account_authority('{a.Account}','factor')",ct,hold);
        var task=f.Observe(Begin(waiter,a,second,2,Guid.NewGuid(),ct,tx:waiting));
        await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waiter.ProcessID,owner.ProcessID,task,ct);
        (await Begin(owner,a,first,2,Guid.NewGuid(),ct,tx:hold)).Succeeded.ShouldBeTrue();await hold.CommitAsync(ct);
        var loser=await task;loser.Succeeded.ShouldBeFalse();loser.Code.ShouldBe("TWO_FACTOR_SETUP_CONFLICT");await waiting.CommitAsync(ct);
        (await Scalar<long>(observer,$"select count(*) from two_factor_authentications where account_id='{a.Account}' and revoked_at is null",ct)).ShouldBe(1L);
    });

    [Fact]
    public Task Concurrent_different_accounts_get_distinct_database_owned_identities()
        => SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var observer=await f.OpenConnectionAsync();var a=await Seed(observer,ct);var b=await Seed(observer,ct);
        var ga=await Cor16EnrollmentSql.SeedGrant(observer,a.Account,a.Stamp,4,ct);var gb=await Cor16EnrollmentSql.SeedGrant(observer,b.Account,b.Stamp,4,ct);
        var ca=await f.OpenConnectionAsync();var cb=await f.OpenConnectionAsync();
        var one=f.Observe(Begin(ca,a,ga,2,Guid.NewGuid(),ct));var two=f.Observe(Begin(cb,b,gb,2,Guid.NewGuid(),ct));
        var results=await Task.WhenAll(one,two);results.All(x=>x.Succeeded).ShouldBeTrue();results[0].Index.ShouldNotBe(results[1].Index);
        (await Scalar<long>(observer,"select count(distinct two_factor_index) from two_factor_authentications",ct)).ShouldBe(2L);
    });

    [Fact]
    public Task Removed_authenticator_cannot_regain_authority_or_share_replay_with_reenrollment()
        => SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var observer=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        var old=Envelope.Create(a.Account);var oldGrant=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,1,ct);
        var created=await Begin(c,a,oldGrant,3,old.Secret.Context.EnrollmentId,ct,old);created.Succeeded.ShouldBeTrue();long oldIndex=created.Index!.Value;
        // Verification mechanics have an actual repository case above; this fixture focuses removal/replay.
        await Exec(c,$"update two_factor_authentications set verified=true,totp_last_used_step=500 where account_id='{a.Account}'",ct);
        var remove=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,2,ct);
        (await Scalar<bool>(c,$"select result from cor08_authorized_remove_twofactor_method('{a.Account}','{a.Stamp}',3::smallint,clock_timestamp(),'{remove.Session}','{remove.Token}','{remove.Target}')",ct)).ShouldBeTrue();
        (await Scalar<bool>(observer,$"select revoked_at is not null and totp_secret_ciphertext is null from two_factor_authentications where account_id='{a.Account}' and two_factor_index={oldIndex}",ct)).ShouldBeTrue();
        var fresh=Envelope.Create(a.Account);var grant=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,1,ct);
        var replacement=await Begin(c,a,grant,3,fresh.Secret.Context.EnrollmentId,ct,fresh);replacement.Succeeded.ShouldBeTrue();long newIndex=replacement.Index!.Value;newIndex.ShouldBeGreaterThan(oldIndex);
        await Exec(c,$"update two_factor_authentications set verified=true where account_id='{a.Account}' and two_factor_index={newIndex}",ct);
        foreach(var pair in new[]{(oldIndex,old.Secret.Context.EnrollmentId),(newIndex,old.Secret.Context.EnrollmentId)})
            (await Scalar<string>(c,$"select code from mark_totp_step_used('{a.Account}',{pair.Item1}::bigint,501::bigint,'{pair.Item2}')",ct)).ShouldBe("TOTP_ENROLLMENT_NOT_FOUND");
        (await Scalar<string>(c,$"select code from mark_password_reset_totp_step_used('{a.Account}',{newIndex}::bigint,1::bigint,'{fresh.Secret.Context.EnrollmentId}')",ct)).ShouldBe("TOTP_STEP_ACCEPTED");
        (await Scalar<string>(c,$"select code from mark_totp_step_used('{a.Account}',{newIndex}::bigint,1::bigint,'{fresh.Secret.Context.EnrollmentId}')",ct)).ShouldBe("TOTP_REPLAY_DETECTED");
        await AssertSecret(observer,a,fresh,ct);old.Protector.Unprotect(old.Secret).ShouldBe(old.Plain);
    });

    [Fact]
    public Task Account_setup_reader_materializes_bigint_index_from_current_delivery_function()
        => SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);await Exec(c,"select setval(pg_get_serial_sequence('two_factor_authentications','two_factor_index'),4294967295,true)",ct);
        var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,3,ct);Guid request=Guid.NewGuid();
        string sql=Cor16EnrollmentSql.Begin(a.Account,a.Stamp,1,"proof",request,g).Replace("select result,code from","select result,code,two_factor_index,expiration from",StringComparison.Ordinal);
        // Production reader and actual SQL result; fixture connection has no NodaTime plugin.
        // Give this reader the production StorageContext connection (which has UseNodaTime).
        await using var storage=Storage(f);await using var production=await storage.CreateConnection(ct);
        await using var cmd=new NpgsqlCommand(sql,production);await using var reader=await cmd.ExecuteReaderAsync(ct);
        var result=await AccountRepo.ReadTwoFactorSetupCommandResultAsync(reader,ct);result.Result.ShouldBeTrue();result.TwoFactorIndex.ShouldBe(4294967296L);
    });
}
