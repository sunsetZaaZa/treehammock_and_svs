using Microsoft.Extensions.Logging.Abstractions;
using NodaTime;
using Npgsql;
using Shouldly;
using treehammock.DataLayer.Cache;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite","SqlContracts")]
public class Cor13ResetAuthorizationTests
{
    [Theory]
    [InlineData("email",null)]
    [InlineData("email"," ")]
    [InlineData("email","sms")]
    [InlineData("sms",null)]
    [InlineData("sms"," ")]
    [InlineData("sms","email")]
    public async Task Invalid_delivery_channel_preserves_prior_request_and_events(string method,string? channel)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>
        {
            var c=await f.OpenConnectionAsync(t);await Seed(c,t,factor:1,bootstrap:false);
            long events=await Read<long>(c,"select count(*) from password_reset_events",t);
            await using var command=new NpgsqlCommand($"select result,code from create_password_reset_request(@id,'{Account}',@method,@channel,'next-proof',1,'fp','masked',true,false,clock_timestamp()+interval '1 hour',5,null,null,'{Stamp}')",c);
            command.Parameters.AddWithValue("id",Guid.NewGuid());command.Parameters.AddWithValue("method",method);
            command.Parameters.Add("channel",NpgsqlTypes.NpgsqlDbType.Text).Value=(object?)channel??DBNull.Value;
            await using(var reader=await command.ExecuteReaderAsync(t))
            {
                (await reader.ReadAsync(t)).ShouldBeTrue();reader.GetBoolean(0).ShouldBeFalse();
                reader.GetString(1).ShouldBe("PASSWORD_RESET_DELIVERY_CHANNEL_INELIGIBLE");
            }
            (await Read<long>(c,"select count(*) from password_reset_requests",t)).ShouldBe(1);
            (await Read<bool>(c,$"select cancelled_at is null from password_reset_requests where password_reset_request_id='{Parent}'",t)).ShouldBeTrue();
            (await Read<long>(c,"select count(*) from password_reset_events",t)).ShouldBe(events);
            var error=await Should.ThrowAsync<PostgresException>(()=>Exec(c,$"update password_reset_requests set delivery_channel=null where password_reset_request_id='{Parent}'",t));
            error.SqlState.ShouldBe("23514");
            (await Read<string>(c,$"select delivery_channel from password_reset_requests where password_reset_request_id='{Parent}'",t)).ShouldBe("email");
        });
    }

    [Theory]
    [InlineData("email")]
    [InlineData("sms")]
    public async Task Matching_delivery_channels_still_replace_the_prior_request(string method)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>
        {
            var c=await f.OpenConnectionAsync(t);await Seed(c,t,factor:1,bootstrap:false);
            (await Read<bool>(c,$"select result from create_password_reset_request('{Guid.NewGuid()}','{Account}','{method}','{method}','next-proof',1,'fp','masked',true,false,clock_timestamp()+interval '1 hour',5,null,null,'{Stamp}')",t)).ShouldBeTrue();
            (await Read<bool>(c,$"select cancelled_at is not null from password_reset_requests where password_reset_request_id='{Parent}'",t)).ShouldBeTrue();
            (await Read<long>(c,$"select count(*) from password_reset_requests where cancelled_at is null and delivery_channel='{method}'",t)).ShouldBe(1);
        });
    }

    private const string Account="00000000-0000-0000-0000-000000001301";
    private const string Stamp="00000000-0000-0000-0000-000000001302";
    private const string Parent="00000000-0000-0000-0000-000000001303";
    private const string Hash="reset-authorization";
    private static async Task<T> Read<T>(NpgsqlConnection c,string sql,CancellationToken token,NpgsqlTransaction? tx=null)
    { await using var cmd=new NpgsqlCommand(sql,c,tx) {CommandTimeout=10};return (T)(await cmd.ExecuteScalarAsync(token))!; }
    private static async Task Exec(NpgsqlConnection c,string sql,CancellationToken token,NpgsqlTransaction? tx=null)
    {await using var cmd=new NpgsqlCommand(sql,c,tx) {CommandTimeout=10};await cmd.ExecuteNonQueryAsync(token);}
    private static async Task Seed(NpgsqlConnection c,CancellationToken token,int factor=0,bool bootstrap=true)
    {
        await Exec(c,$"insert into accounts(account_id,email_address,security_stamp,verify_status,hashed_password) values('{Account}','reader@example.test','{Stamp}',1,decode(repeat('01',128),'hex'))",token);
        if(factor is 1 or 4) await Exec(c,$"insert into two_factor_authentications(two_factor_index,account_id,method,verified,phone_number,phone_country_code) values(1,'{Account}',2,true,'5555550101','1')",token);
        if(factor is 3 or 4) await Exec(c,$"insert into two_factor_authentications(two_factor_index,account_id,method,verified,totp_secret_ciphertext,totp_secret_nonce,totp_secret_tag,totp_provider_type,totp_secret_version,totp_key_id,totp_enrollment_id,totp_algorithm,totp_digits,totp_period_seconds,totp_clock_skew_steps) values(2,'{Account}',3,true,decode(repeat('01',20),'hex'),decode(repeat('01',12),'hex'),decode(repeat('01',16),'hex'),1,2,'fixture',gen_random_uuid(),'SHA1',6,30,1)",token);
        (await Read<bool>(c,$"select result from create_password_reset_request('{Parent}','{Account}','email','email','bootstrap-hash',1,'fp','masked',true,false,clock_timestamp()+interval '1 hour',5,null,null,'{Stamp}')",token)).ShouldBeTrue();
        if(bootstrap)(await Read<bool>(c,Cor13ResetSql.Bootstrap(Account,Parent),token)).ShouldBeTrue();
    }
    private static string Snapshot => $"select jsonb_build_array(a.hashed_password,a.security_stamp,r.consumed_at,(select count(*) from password_reset_events where code='PASSWORD_RESET_COMPLETED'))::text from accounts a join password_reset_requests r using(account_id) where r.password_reset_request_id='{Parent}'";
    private static async Task Select(NpgsqlConnection c,CancellationToken token,int factor=3)
    {(await Read<bool>(c,Cor13ResetSql.Transition(Hash,2,1,0,Cor13ResetSql.Select(factor)),token)).ShouldBeTrue();}

    [Fact]
    public async Task Production_repository_creates_and_consumes_no_additional_factor_authorization()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,t,bootstrap:false);
            await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,new SecurityOperationSettings {HmacKeys=new() {{1,Convert.ToBase64String(new byte[32])}}});
            var repo=new PasswordResetRepo(storage,NullLogger<PasswordResetRepo>.Instance);
            var reset=(await repo.GetPasswordResetRequestForFinalizeAsync(Guid.Parse(Parent),t)).ShouldNotBeNull();
            var now=SystemClock.Instance.GetCurrentInstant();
            var session=new PasswordResetSession(Guid.Parse(Account),Hash,PasswordResetBootstrapProof.EmailResetToken,Array.Empty<TwoFactorAuthConfiguration>(),now,reset.ExpiresAt!.Value,passwordResetRequestId:Guid.Parse(Parent)) {bootstrapCodeHash="bootstrap-hash"};
            (await repo.TransitionPendingPasswordResetSessionAsync(session,t))!.Result.ShouldBeTrue();session.sessionVersion.ShouldBe(1);session.challengeVersion.ShouldBe(0);
            var read=(await repo.GetPendingPasswordResetSessionAsync(Hash,t)).ShouldNotBeNull();read.canChangePassword.ShouldBeTrue();read.factorPolicyVersion.ShouldNotBeNullOrWhiteSpace();
            var promotion=new PromotePasswordResetDbCommand(Guid.Parse(Parent),Guid.Parse(Account),new byte[128],new byte[64],new byte[32],new byte[16],Guid.NewGuid(),now,Hash,read.sessionVersion,read.challengeVersion);
            (await repo.PromotePasswordResetAsync(promotion,t))!.Result.ShouldBeTrue();
            (await repo.PromotePasswordResetAsync(promotion,t))!.Result.ShouldBeFalse();
            (await Read<long>(c,"select count(*) from password_reset_events where code='PASSWORD_RESET_COMPLETED'",t)).ShouldBe(1);
        });
    }

    [Theory][InlineData("missing")][InlineData("incomplete")][InlineData("wrong-token")][InlineData("stale-version")][InlineData("stale-challenge")][InlineData("revoked")][InlineData("expired")][InlineData("policy-changed")]
    public async Task Promotion_denies_invalid_authorization_without_password_stamp_or_success_audit_mutation(string kind)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,t,kind=="incomplete"?3:0,kind!="missing");
            if(kind=="revoked") await Exec(c,$"select result from revoke_pending_password_reset_session('{Hash}',clock_timestamp(),'test',1::bigint,0::bigint)",t);
            if(kind=="expired") await Exec(c,$"update pending_password_reset_sessions set created_on=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour'",t);
            if(kind=="policy-changed")await Exec(c,$"update accounts set email_address='changed@example.test' where account_id='{Account}'",t);
            string before=await Read<string>(c,Snapshot,t);
            (await Read<bool>(c,Cor13ResetSql.Promote(Parent,Account,kind=="stale-version"?2:1,kind=="stale-challenge"?1:0,kind=="wrong-token"?"different-token":Hash),t)).ShouldBeFalse();
            (await Read<string>(c,Snapshot,t)).ShouldBe(before);
        });
    }

    [Theory][InlineData(4)][InlineData(5)]
    public async Task Stale_failure_or_success_cannot_change_a_replacement_challenge(int operation)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,t,1);await Select(c,t,1);
            var resend=Cor13ResetSql.Select(1,"replacement");resend["selected_at"]="t.selected_at";
            (await Read<bool>(c,Cor13ResetSql.Transition(Hash,3,2,1,resend),t)).ShouldBeTrue();
            string before=await Read<string>(c,$"select to_jsonb(t)::text from pending_password_reset_sessions t where reset_access_token_hash='{Hash}'",t);
            var fields=operation==4?new Dictionary<string,string>{{"challenge_attempts","t.challenge_attempts+1"}}:Cor13ResetSql.Valid();
            (await Read<bool>(c,Cor13ResetSql.Transition(Hash,operation,2,1,fields),t)).ShouldBeFalse();
            (await Read<string>(c,$"select to_jsonb(t)::text from pending_password_reset_sessions t where reset_access_token_hash='{Hash}'",t)).ShouldBe(before);
            (await Read<int>(c,"select attempt_count from password_reset_requests",t)).ShouldBe(0);
        });
    }

    [Theory][InlineData(1)][InlineData(3)][InlineData(4)]
    public async Task Completed_exact_factor_path_promotes_once_and_preserves_order(int factor)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,t,factor);await Select(c,t,factor);
            (await Read<bool>(c,Cor13ResetSql.Promote(Parent,Account,2,1),t)).ShouldBeFalse();
            (await Read<bool>(c,Cor13ResetSql.Transition(Hash,5,2,1,Cor13ResetSql.Valid(factor==4)),t)).ShouldBeTrue();
            long version=3,challenge=2;
            if(factor==4){(await Read<bool>(c,Cor13ResetSql.Transition(Hash,5,version,challenge,Cor13ResetSql.Valid()),t)).ShouldBeTrue();version++;challenge++;}
            (await Read<bool>(c,Cor13ResetSql.Promote(Parent,Account,version,challenge),t)).ShouldBeTrue();
            (await Read<bool>(c,Cor13ResetSql.Promote(Parent,Account,version,challenge),t)).ShouldBeFalse();
            (await Read<long>(c,"select count(*) from password_reset_events where code='PASSWORD_RESET_COMPLETED'",t)).ShouldBe(1);
        });
    }

    [Fact]
    public async Task Stale_revocation_cannot_cancel_a_replacement_challenge()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,t,1);await Select(c,t,1);
            var resend=Cor13ResetSql.Select(1,"replacement");resend["selected_at"]="t.selected_at";
            (await Read<bool>(c,Cor13ResetSql.Transition(Hash,3,2,1,resend),t)).ShouldBeTrue();
            (await Read<bool>(c,$"select result from revoke_pending_password_reset_session('{Hash}',clock_timestamp(),'stale',2::bigint,1::bigint)",t)).ShouldBeFalse();
            (await Read<bool>(c,"select cancelled_at is null from password_reset_requests",t)).ShouldBeTrue();
            (await Read<bool>(c,"select revoked_at is null from pending_password_reset_sessions",t)).ShouldBeTrue();
        });
    }

    [Fact]
    public async Task Selection_preserves_attempts_and_resends_and_cooldown_cannot_be_cleared()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,t,4);await Select(c,t,1);
            (await Read<bool>(c,Cor13ResetSql.Transition(Hash,4,2,1,new(){{"challenge_attempts","t.challenge_attempts+1"}}),t)).ShouldBeTrue();
            (await Read<bool>(c,Cor13ResetSql.Transition(Hash,2,3,1,Cor13ResetSql.Select(3)),t)).ShouldBeTrue();
            (await Read<int>(c,"select challenge_attempts from pending_password_reset_sessions",t)).ShouldBe(1);
            (await Read<int>(c,"select challenge_resends from pending_password_reset_sessions",t)).ShouldBe(1);
            await Exec(c,"update pending_password_reset_sessions set next_challenge_allowed_at=clock_timestamp()+interval '1 hour'",t);
            (await Read<bool>(c,Cor13ResetSql.Transition(Hash,2,4,2,Cor13ResetSql.Select(1)),t)).ShouldBeFalse();
        });
    }

    [Fact]
    public async Task Invalid_proofs_charge_parent_atomically_and_terminal_rows_cannot_be_recreated()
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,t,3);await Select(c,t);
            for(int i=0;i<5;i++)(await Read<bool>(c,Cor13ResetSql.Transition(Hash,4,2+i,1,new(){{"challenge_attempts","t.challenge_attempts+1"}}),t)).ShouldBeTrue();
            (await Read<bool>(c,"select cancelled_at is not null from password_reset_requests",t)).ShouldBeTrue();
            (await Read<bool>(c,Cor13ResetSql.Bootstrap(Account,Parent),t)).ShouldBeFalse();
            (await Read<bool>(c,Cor13ResetSql.Bootstrap(Account,Parent,"different-token"),t)).ShouldBeFalse();
            (await Read<bool>(c,Cor13ResetSql.Transition(Hash,5,7,1,Cor13ResetSql.Valid()),t)).ShouldBeFalse();
        });
    }

    [Theory][InlineData(1)][InlineData(3)]
    public async Task Actual_last_factor_removal_cancels_parent_and_denies_old_finalize_and_rebootstrap(int factor)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var c=await f.OpenConnectionAsync();await Seed(c,t,factor);await Select(c,t,factor);
            (await Read<bool>(c,Cor13ResetSql.Transition(Hash,5,2,1,Cor13ResetSql.Valid()),t)).ShouldBeTrue();
            await Exec(c,$"insert into sessions(access_token_hash,account_id,created_on,access_expiration,session_expiration,account_security_stamp) values('grant-session','{Account}',clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','{Stamp}')",t);
            var attempt=Guid.NewGuid();
            (await Read<bool>(c,$"select result from cor08_begin_password_proof('{Account}','{Stamp}','grant-session','{attempt}',2::smallint,repeat('a',64),5,900,30)",t)).ShouldBeTrue();
            (await Read<bool>(c,$"select result from cor08_finish_password_proof('{Account}','{Stamp}','grant-session','{attempt}',true,repeat('b',64),repeat('c',64),10)",t)).ShouldBeTrue();
            (await Read<bool>(c,$"select result from cor08_authorized_remove_twofactor_method('{Account}','{Stamp}',{(factor==1?2:3)}::smallint,clock_timestamp(),'grant-session',repeat('c',64),repeat('a',64))",t)).ShouldBeTrue();
            (await Read<bool>(c,"select cancelled_at is not null from password_reset_requests",t)).ShouldBeTrue();
            string before=await Read<string>(c,Snapshot,t);
            (await Read<bool>(c,Cor13ResetSql.Promote(Parent,Account,3,2),t)).ShouldBeFalse();
            (await Read<bool>(c,Cor13ResetSql.Bootstrap(Account,Parent),t)).ShouldBeFalse();
            (await Read<bool>(c,Cor13ResetSql.Bootstrap(Account,Parent,"new-token"),t)).ShouldBeFalse();
            (await Read<string>(c,Snapshot,t)).ShouldBe(before);
        });
    }

    [Theory][InlineData("revoke")][InlineData("expire")][InlineData("competing-finalizer")]
    public async Task Promotion_rechecks_authorization_after_observed_account_lock_wait(string mutation)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var observer=await f.OpenConnectionAsync();await Seed(observer,t);
            var owner=await f.OpenConnectionAsync();var worker=await f.OpenConnectionAsync();
            var tx=await f.BeginTransactionAsync(owner);
            await Exec(owner,$"select 1 from accounts where account_id='{Account}' for update",t,tx);
            var pending=f.Observe(Read<bool>(worker,Cor13ResetSql.Promote(Parent,Account,1,0),t));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,worker.ProcessID,owner.ProcessID,pending,t);
            if(mutation=="revoke")await Exec(owner,$"select result from revoke_pending_password_reset_session('{Hash}',clock_timestamp(),'test',1::bigint,0::bigint)",t,tx);
            else if(mutation=="expire")await Exec(owner,"update pending_password_reset_sessions set created_on=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour'",t,tx);
            else (await Read<bool>(owner,Cor13ResetSql.Promote(Parent,Account,1,0),t,tx)).ShouldBeTrue();
            await tx.CommitAsync(t);(await pending).ShouldBeFalse();
            (await Read<long>(observer,"select count(*) from password_reset_events where code='PASSWORD_RESET_COMPLETED'",t)).ShouldBe(mutation=="competing-finalizer"?1:0);
            if(mutation!="competing-finalizer") (await Read<bool>(observer,$"select hashed_password=decode(repeat('01',128),'hex') and security_stamp='{Stamp}' from accounts",t)).ShouldBeTrue();
        });
    }

    [Theory][InlineData(4)][InlineData(5)]
    public async Task Proof_transition_rechecks_versions_after_observed_account_lock_wait(int operation)
    {
        await SqlContractFixture.RunAsync(async(f,t)=>{
            var observer=await f.OpenConnectionAsync();await Seed(observer,t,1);await Select(observer,t,1);
            var owner=await f.OpenConnectionAsync();var worker=await f.OpenConnectionAsync();var tx=await f.BeginTransactionAsync(owner);
            await Exec(owner,$"select 1 from accounts where account_id='{Account}' for update",t,tx);
            var fields=operation==4?new Dictionary<string,string>{{"challenge_attempts","t.challenge_attempts+1"}}:Cor13ResetSql.Valid();
            var pending=f.Observe(Read<bool>(worker,Cor13ResetSql.Transition(Hash,operation,2,1,fields),t));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,worker.ProcessID,owner.ProcessID,pending,t);
            var resend=Cor13ResetSql.Select(1,"replacement");resend["selected_at"]="t.selected_at";
            (await Read<bool>(owner,Cor13ResetSql.Transition(Hash,3,2,1,resend),t,tx)).ShouldBeTrue();
            await tx.CommitAsync(t);(await pending).ShouldBeFalse();
            (await Read<string>(observer,"select challenge_code_hash from pending_password_reset_sessions",t)).ShouldBe("replacement");
            (await Read<int>(observer,"select attempt_count from password_reset_requests",t)).ShouldBe(0);
        });
    }
}
