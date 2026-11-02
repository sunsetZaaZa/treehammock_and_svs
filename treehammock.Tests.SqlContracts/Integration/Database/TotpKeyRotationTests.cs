using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Npgsql;
using Shouldly;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Services;
using treehammock.Tests.SqlContracts.Support;
namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class Cor15TotpKeyRotationTests
{
    private static TotpSettings Settings()=>new(){ActiveProtectionKeyId="new",ProtectionKeys=new(){["old"]=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),["new"]=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}};
    private static async Task<ProtectedTotpSecret> Seed(NpgsqlConnection c,TotpSettings settings,CancellationToken ct,bool verified=true)
    {
        Guid account=Guid.NewGuid(),enrollment=Guid.NewGuid();
        settings.ActiveProtectionKeyId="old";
        var envelope=new TotpSecretProtector(Options.Create(settings)).Protect("12345678901234567890"u8.ToArray(),new(account,enrollment,new("SHA256",8,60,0)));
        settings.ActiveProtectionKeyId="new";
        await using var cmd=new NpgsqlCommand("""
            insert into accounts(account_id,email_address,verify_status,security_stamp) values(@account,'cor15@example.test',1,gen_random_uuid());
            insert into two_factor_authentications(account_id,two_factor_index,method,verified,required,token,expiration,
                totp_provider_type,totp_secret_version,totp_secret_ciphertext,totp_secret_nonce,totp_secret_tag,totp_key_id,
                totp_enrollment_id,totp_algorithm,totp_digits,totp_period_seconds,totp_clock_skew_steps,totp_last_used_step)
            values(@account,1,3,@verified,true,'pending',case when @verified then null else clock_timestamp()+interval '1 hour' end,
                1,2,@cipher,@nonce,@tag,'old',@enrollment,'SHA256',8,60,0,12345);
            """,c);
        cmd.Parameters.AddWithValue("account",account);cmd.Parameters.AddWithValue("enrollment",enrollment);cmd.Parameters.AddWithValue("verified",verified);
        cmd.Parameters.AddWithValue("cipher",envelope.Ciphertext);cmd.Parameters.AddWithValue("nonce",envelope.Nonce);cmd.Parameters.AddWithValue("tag",envelope.Tag);
        await cmd.ExecuteNonQueryAsync(ct);return envelope;
    }
    private static async Task<T> Scalar<T>(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null)
    {await using var cmd=new NpgsqlCommand(sql,c,tx);return (T)(await cmd.ExecuteScalarAsync(ct))!;}
    private static Cor09RefreshHttpTests.FixtureStorage Storage(SqlContractFixture f)=>new(f,new SecurityOperationSettings {HmacKeys=new(){{1,Convert.ToBase64String(new byte[32])}}});
    private static ServiceProvider Provider(TotpSettings settings,TotpReencryptionRepo repo)=>new ServiceCollection()
        .AddSingleton<IOptions<TotpSettings>>(Options.Create(settings)).AddSingleton<ITotpSecretProtector,TotpSecretProtector>().AddSingleton(repo).BuildServiceProvider();
    // Seed an already-attested grant to exercise the production removal transaction;
    // password/factor proof verification is covered by COR08's separate native suite.
    private static async Task SeedRemovalGrant(NpgsqlConnection c,Guid account,CancellationToken ct)
    {
        await using var cmd=new NpgsqlCommand("""
            insert into sessions(access_token_hash,account_id,created_on,access_expiration,session_expiration,account_security_stamp)
            select 'cor15-removal-session',account_id,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours',security_stamp from accounts where account_id=@account;
            insert into sensitive_action_proof_sessions(proof_id,handle_hash,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,factor_required,factor_complete,expiration,state)
            select gen_random_uuid(),repeat('b',64),a.account_id,a.security_stamp,s.access_token_hash,s.session_id,2,repeat('a',64),cor08_factor_policy(a.account_id),true,true,clock_timestamp()+interval '10 minutes','Granted'
            from accounts a join sessions s using(account_id) where a.account_id=@account;
            insert into sensitive_action_grants(token_hash,proof_id,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,policy_version,expiration)
            select repeat('c',64),proof_id,account_id,credential_stamp,session_hash,family_id,purpose,target_hash,factor_policy,1,expiration from sensitive_action_proof_sessions where account_id=@account;
            """,c);cmd.Parameters.AddWithValue("account",account);await cmd.ExecuteNonQueryAsync(ct);
    }
    private static string Checkpoint()=>Path.Combine(Path.GetTempPath(),"cor15-"+Guid.NewGuid().ToString("N")+".json");
    private static void Cleanup(string path){File.Delete(path);File.Delete(path+".lock");}

    [Fact]
    public async Task Production_command_resumes_partial_rotation_and_preserves_parameters_and_replay()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var settings=Settings();var first=await Seed(c,settings,ct);var second=await Seed(c,settings,ct,verified:false);
            await using var storage=Storage(f);var repo=new TotpReencryptionRepo(storage);using var services=Provider(settings,repo);string path=Checkpoint();
            try {
                (await TotpReencryptionCommand.RunAsync(services,["--checkpoint",path,"--batch-size","1","--max-batches","1"],ct)).ShouldBe(3);
                var partial=JsonSerializer.Deserialize<TotpRotationCheckpoint>(await File.ReadAllTextAsync(path,ct))!;partial.Reencrypted.ShouldBe(1);partial.Completed.ShouldBeFalse();
                (await TotpReencryptionCommand.RunAsync(services,["--checkpoint",path,"--batch-size","1"],ct)).ShouldBe(0);
                (await repo.RemainingAsync("new",ct)).ShouldBe(0);
                foreach(var original in new[]{first,second}) {
                    var row=(await repo.ReadEnrollmentAsync(original.Context.EnrollmentId,ct))!;row.RowVersion.ShouldBe(2);row.Envelope.Context.ShouldBe(original.Context);
                    new TotpSecretProtector(Options.Create(settings)).Unprotect(row.Envelope).ShouldBe("12345678901234567890"u8.ToArray());
                    (await Scalar<long>(c,$"select totp_last_used_step from two_factor_authentications where totp_enrollment_id='{original.Context.EnrollmentId}'",ct)).ShouldBe(12345);
                }
                (await TotpReencryptionCommand.RunAsync(services,["--checkpoint",path],ct)).ShouldBe(0); // Completed checkpoint is safe to repeat.
            } finally {Cleanup(path);}
        });
    }
    [Fact]
    public async Task Stale_CAS_and_transaction_rollback_leave_the_observed_enrollment_intact()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var settings=Settings();var original=await Seed(c,settings,ct);
            await using var storage=Storage(f);var repo=new TotpReencryptionRepo(storage);var observed=(await repo.ReadEnrollmentAsync(original.Context.EnrollmentId,ct))!;
            var protector=new TotpSecretProtector(Options.Create(settings));var replacement=protector.Protect(protector.Unprotect(original),original.Context);
            await using(var tx=await c.BeginTransactionAsync(ct)) {
                await using var cmd=new NpgsqlCommand("select cor15_reencrypt_totp(@account,@enrollment,1::bigint,'old','new',@cipher,@nonce,@tag)",c,tx);
                cmd.Parameters.AddWithValue("account",original.Context.AccountId);cmd.Parameters.AddWithValue("enrollment",original.Context.EnrollmentId);
                cmd.Parameters.AddWithValue("cipher",replacement.Ciphertext);cmd.Parameters.AddWithValue("nonce",replacement.Nonce);cmd.Parameters.AddWithValue("tag",replacement.Tag);
                ((bool)(await cmd.ExecuteScalarAsync(ct))!).ShouldBeTrue();await tx.RollbackAsync(ct);
            }
            (await repo.ReadEnrollmentAsync(original.Context.EnrollmentId,ct))!.RowVersion.ShouldBe(1);
            (await repo.CompareExchangeAsync(observed,replacement,ct)).ShouldBeTrue();
            (await repo.CompareExchangeAsync(observed,replacement,ct)).ShouldBeFalse();
            (await repo.ReadEnrollmentAsync(original.Context.EnrollmentId,ct))!.RowVersion.ShouldBe(2);
            (await Scalar<bool>(c,$"select result from mark_totp_step_used('{original.Context.AccountId}',1::smallint,12346::bigint,'{Guid.NewGuid()}')",ct)).ShouldBeFalse();
            (await Scalar<long>(c,$"select totp_last_used_step from two_factor_authentications where totp_enrollment_id='{original.Context.EnrollmentId}'",ct)).ShouldBe(12345);
        });
    }
    [Theory,InlineData("missing-key"),InlineData("tampered-old"),InlineData("tampered-current")]
    public async Task Missing_key_and_tampering_stop_before_a_completed_checkpoint(string fault)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var settings=Settings();var original=await Seed(c,settings,ct);
            await using var storage=Storage(f);var repo=new TotpReencryptionRepo(storage);using var services=Provider(settings,repo);string path=Checkpoint();
            try {
                if(fault=="tampered-current") {
                    var row=(await repo.ReadEnrollmentAsync(original.Context.EnrollmentId,ct))!;var protector=new TotpSecretProtector(Options.Create(settings));
                    (await repo.CompareExchangeAsync(row,protector.Protect(protector.Unprotect(row.Envelope),row.Envelope.Context),ct)).ShouldBeTrue();
                }
                if(fault=="missing-key") settings.ProtectionKeys.Remove("old");
                else await Scalar<int>(c,$"with changed as (update two_factor_authentications set totp_secret_tag=decode(repeat('ff',16),'hex') where totp_enrollment_id='{original.Context.EnrollmentId}' returning 1) select count(*)::integer from changed",ct);
                if(fault=="missing-key") await Should.ThrowAsync<InvalidOperationException>(()=>TotpReencryptionCommand.RunAsync(services,["--checkpoint",path],ct));
                else await Should.ThrowAsync<CryptographicException>(()=>TotpReencryptionCommand.RunAsync(services,["--checkpoint",path],ct));
                File.Exists(path).ShouldBeFalse(); // Includes final verification of rows already using the target key.
            } finally {Cleanup(path);}
        });
    }
    [Theory,InlineData(1),InlineData(2)]
    public async Task Replacing_pending_authenticator_with_email_or_SMS_clears_all_TOTP_material(int method)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var settings=Settings();var original=await Seed(c,settings,ct,verified:false);Guid account=original.Context.AccountId;
            Guid stamp=await Scalar<Guid>(c,$"select security_stamp from accounts where account_id='{account}'",ct);
            var origin=await Cor16EnrollmentSql.SeedGrant(c,account,stamp,1,ct);
            (await Scalar<bool>(c,$"select cor08_validate_sensitive_grant('{account}','{stamp}','{origin.Session}','{origin.Token}',1::smallint,'{origin.Target}',true)",ct)).ShouldBeTrue();
            await using(var bind=new NpgsqlCommand($"select cor16_bind_setup('{account}',1::smallint,'{original.Context.EnrollmentId}',1::bigint,'{origin.Token}')",c)) await bind.ExecuteNonQueryAsync(ct);
            var grant=await Cor16EnrollmentSql.SeedGrant(c,account,stamp,method==1?3:4,ct);
            (await Scalar<bool>(c,Cor16EnrollmentSql.Begin(account,stamp,method,"email-sms-proof",Guid.NewGuid(),grant,original.Context.EnrollmentId,1),ct)).ShouldBeTrue();
            string columns="totp_secret_ciphertext,totp_secret_nonce,totp_secret_tag,totp_secret_version,totp_key_id,totp_enrollment_id,totp_algorithm,totp_digits,totp_period_seconds,totp_clock_skew_steps,totp_row_version,totp_last_used_step,totp_provider_type,totp_provider_enrollment_id,totp_provider_account_binding_hash";
            string checks=string.Join(" and ",columns.Split(',').Select(column=>column+" is null"));
            (await Scalar<bool>(c,$"select {checks} from two_factor_authentications where account_id='{account}' and two_factor_index=1",ct)).ShouldBeTrue();
        });
    }
    [Fact]
    public async Task Unrelated_factor_removal_preserves_the_authenticator_envelope_and_replay_guard()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var settings=Settings();var original=await Seed(c,settings,ct);Guid account=original.Context.AccountId;
            await Scalar<int>(c,$"with inserted as (insert into two_factor_authentications(account_id,two_factor_index,method,verified,phone_number,phone_country_code) values('{account}',2,2,true,'5555550101','1') returning 1) select count(*)::integer from inserted",ct);
            await SeedRemovalGrant(c,account,ct);
            (await Scalar<bool>(c,$"select result from cor08_authorized_remove_twofactor_method('{account}',(select security_stamp from accounts where account_id='{account}'),2::smallint,clock_timestamp(),'cor15-removal-session',repeat('c',64),repeat('a',64))",ct)).ShouldBeTrue();
            await using var storage=Storage(f);var row=(await new TotpReencryptionRepo(storage).ReadEnrollmentAsync(original.Context.EnrollmentId,ct))!;
            row.Envelope.Context.ShouldBe(original.Context);row.Envelope.Ciphertext.ShouldBe(original.Ciphertext);row.RowVersion.ShouldBe(1);
            (await Scalar<bool>(c,$"select result from mark_totp_step_used('{account}',1::smallint,12345::bigint,'{original.Context.EnrollmentId}')",ct)).ShouldBeFalse();
            (await Scalar<bool>(c,$"select result from mark_totp_step_used('{account}',1::smallint,12346::bigint,'{original.Context.EnrollmentId}')",ct)).ShouldBeTrue();
        });
    }
    [Fact]
    public async Task Enrollment_parameters_cannot_be_changed_without_reprovisioning()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var original=await Seed(c,Settings(),ct);
            var error=await Should.ThrowAsync<PostgresException>(()=>Scalar<int>(c,$"with changed as (update two_factor_authentications set totp_period_seconds=30 where totp_enrollment_id='{original.Context.EnrollmentId}' returning 1) select count(*)::integer from changed",ct));
            error.SqlState.ShouldBe("23514");
        });
    }
}
