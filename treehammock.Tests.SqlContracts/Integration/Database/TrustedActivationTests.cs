using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging.Abstractions;
using NodaTime;
using Npgsql;
using Shouldly;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Operations;
using treehammock.Tests.SqlContracts.Support;
namespace treehammock.Tests.Integration.Database;

[Trait("Suite","SqlContracts")]
public class Cor19TrustedActivationTests
{
    private sealed record Subject(Guid Account,Guid Stamp,Guid Family,Guid Grant,Guid Request,string Session)
    {
        public string Email => Account.ToString("N")+"@example.test";
        public string Hash => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("plaintext-secret"))).ToLowerInvariant();
    }
    private static async Task Exec(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null)
    {await using var cmd=new NpgsqlCommand(sql,c,tx);await cmd.ExecuteNonQueryAsync(ct);}
    private static async Task<T> Scalar<T>(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null)
    {await using var cmd=new NpgsqlCommand(sql,c,tx);return (T)(await cmd.ExecuteScalarAsync(ct))!;}
    // Explicit authority substitute: local schema only; never creates a global database role.
    // Separate deployment qualification must use actual ordinary/issuer logins and ACLs.
    private static Task Issuer(NpgsqlConnection c,bool allowed,CancellationToken ct)=>Exec(c,$"create or replace function cor19_is_issuer(p_actor name) returns boolean language plpgsql stable as $$ begin return {(allowed?"p_actor=current_user::name":"false")};end $$",ct);
    private static string Issue(Subject a)=>$"select result from cor19_issue_grant('{a.Grant}','{a.Account}','{a.Stamp}','treehammock-v1',2::smallint,1::smallint,0::smallint,null,clock_timestamp()+interval '1 day',1,clock_timestamp()+interval '2 hours','reviewed approval','redemption',array[]::text[])";
    private static string Stage(Subject a)=>$"select result from cor19_stage_activation('{a.Request}','{a.Account}','{a.Stamp}','{a.Session}','{a.Family}','{a.Grant}',1,'{a.Hash}',clock_timestamp()+interval '10 minutes','{a.Email}',2::smallint,1::smallint,0::smallint,{Cor21CreationSql.Admit(a.Account,a.Stamp,a.Session,a.Family,a.Grant,a.Hash,a.Email)})";
    private static string Transition(Subject a,string action,long version=1)=>$"select result from cor19_transition_activation('{a.Account}','{a.Stamp}','{a.Session}','{a.Family}','{a.Grant}',{version},'{a.Request}','{a.Hash}','{action}')";
    private static async Task<Subject> Seed(NpgsqlConnection c,CancellationToken ct,bool approved=true,bool pending=true)
    {
        var a=new Subject(Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid().ToString("N"));
        await Exec(c,$"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{a.Account}','{a.Email}',1,'{a.Stamp}');insert into sessions(access_token_hash,account_id,session_id,account_security_stamp,created_on,access_expiration,session_expiration) values('{a.Session}','{a.Account}','{a.Family}','{a.Stamp}',clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours')",ct);
        if(approved){await Issuer(c,true,ct);(await Scalar<bool>(c,Issue(a),ct)).ShouldBeTrue();}
        if(pending){(await Scalar<bool>(c,Stage(a),ct)).ShouldBeTrue();
            // Domain fixture substitutes publication; encrypted outbox case below uses production worker transitions.
            await Exec(c,$"insert into delivery_candidates(delivery_id,account_id,account_stamp,purpose,proof_hash,expires_at,metadata_json,predecessor,state,terminal_at) values('{a.Request}','{a.Account}','{a.Stamp}','activation','{a.Hash}',clock_timestamp()+interval '10 minutes','{{}}','fixture','published',clock_timestamp());select cor19_publish_activation('{a.Request}','{a.Stamp}','{a.Hash}')",ct);
        }return a;
    }
    [Fact]
    public async Task Ordinary_database_identity_cannot_issue_premium()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct,false,false);await Issuer(c,false,ct);
            (await Scalar<bool>(c,Issue(a),ct)).ShouldBeFalse();(await Scalar<long>(c,"select count(*) from entitlement_grants",ct)).ShouldBe(0);(await Scalar<long>(c,"select count(*) from entitlement_grant_audit",ct)).ShouldBe(0);});
    }
    [Theory,InlineData("account"),InlineData("stamp"),InlineData("grant"),InlineData("version"),InlineData("email"),InlineData("tier"),InlineData("term"),InlineData("cadence"),InlineData("family"),InlineData("issuer")]
    public async Task Placement_requires_matching_server_approval_and_current_authority(string bad)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct,true,false);string sql=Stage(a);
            if(bad=="account")sql=sql.Replace(a.Account.ToString(),Guid.NewGuid().ToString());if(bad=="stamp")sql=sql.Replace(a.Stamp.ToString(),Guid.NewGuid().ToString());
            if(bad=="grant")sql=sql.Replace(a.Grant.ToString(),Guid.NewGuid().ToString());if(bad=="version")sql=sql.Replace($"'{a.Grant}',1",$"'{a.Grant}',2");
            if(bad=="email")sql=sql.Replace(a.Email,"other@example.test");if(bad=="tier")sql=sql.Replace("2::smallint","1::smallint");
            if(bad=="term")sql=sql.Replace("1::smallint","2::smallint");if(bad=="cadence")sql=sql.Replace("0::smallint","1::smallint");
            if(bad=="family")sql=sql.Replace(a.Family.ToString(),Guid.NewGuid().ToString());if(bad=="issuer")await Issuer(c,false,ct);
            (await Scalar<bool>(c,sql,ct)).ShouldBeFalse();(await Scalar<long>(c,"select count(*) from grant_activation_requests",ct)).ShouldBe(0);
        });
    }
    [Theory,InlineData("verify","verify"),InlineData("verify","disable"),InlineData("disable","verify"),InlineData("verify","cancel"),InlineData("cancel","verify")]
    public async Task Concurrent_lifecycle_mutations_have_one_version_winner(string first,string second)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var observer=await f.OpenConnectionAsync();var a=await Seed(observer,ct);var owner=await f.OpenConnectionAsync();var waiter=await f.OpenConnectionAsync();
            await using var tx=await owner.BeginTransactionAsync(ct);(await Scalar<bool>(owner,Transition(a,first),ct,tx)).ShouldBeTrue();
            var pending=f.Observe(Scalar<bool>(waiter,Transition(a,second),ct));await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waiter.ProcessID,owner.ProcessID,pending,ct);
            await tx.CommitAsync(ct);(await pending).ShouldBeFalse();
            (await Scalar<string>(observer,"select state from entitlement_grants",ct)).ShouldBe(first=="verify"?"active":"revoked");
            (await Scalar<bool>(observer,"select proof_hash is null from grant_activation_requests",ct)).ShouldBeTrue();
            (await Scalar<long>(observer,"select count(*) from entitlement_grant_audit where action in ('redeemed','revoked')",ct)).ShouldBe(1);
        });
    }
    [Fact]
    public async Task Sequential_place_verify_disable_revokes_active_and_never_resurrects_code()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);
            (await Scalar<bool>(c,Transition(a,"verify"),ct)).ShouldBeTrue();(await Scalar<bool>(c,Transition(a,"verify"),ct)).ShouldBeFalse();
            (await Scalar<bool>(c,Transition(a,"disable",2),ct)).ShouldBeTrue();(await Scalar<string>(c,"select state from entitlement_grants",ct)).ShouldBe("revoked");
            (await Scalar<bool>(c,Transition(a,"verify",3),ct)).ShouldBeFalse();(await Scalar<bool>(c,Stage(a),ct)).ShouldBeFalse();
            (await Scalar<long>(c,"select count(*) from entitlement_grant_audit where action='revoked'",ct)).ShouldBe(1);
        });
    }
    [Theory,InlineData("account"),InlineData("family"),InlineData("stamp"),InlineData("version"),InlineData("request"),InlineData("hash"),InlineData("publication"),InlineData("expired"),InlineData("issuer")]
    public async Task Redemption_denials_leave_code_unconsumed(string bad)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);string sql=Transition(a,"verify");
            if(bad=="account")sql=sql.Replace(a.Account.ToString(),Guid.NewGuid().ToString());if(bad=="family")sql=sql.Replace(a.Family.ToString(),Guid.NewGuid().ToString());if(bad=="stamp")sql=sql.Replace(a.Stamp.ToString(),Guid.NewGuid().ToString());
            if(bad=="version")sql=sql.Replace($"'{a.Grant}',1",$"'{a.Grant}',2");if(bad=="request")sql=sql.Replace(a.Request.ToString(),Guid.NewGuid().ToString());if(bad=="hash")sql=sql.Replace(a.Hash,new string('b',64));
            if(bad=="publication")await Exec(c,"update delivery_candidates set state='rejected'",ct);if(bad=="expired")await Exec(c,"update grant_activation_requests set expires_at=clock_timestamp()",ct);if(bad=="issuer")await Issuer(c,false,ct);
            (await Scalar<bool>(c,sql,ct)).ShouldBeFalse();(await Scalar<string>(c,"select state from entitlement_grants",ct)).ShouldBe("approved");(await Scalar<bool>(c,"select consumed_at is null from grant_activation_requests",ct)).ShouldBeTrue();
        });
    }
    [Fact]
    public async Task Stamp_rotation_while_verification_waits_cannot_cross_mutation()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var observer=await f.OpenConnectionAsync();var a=await Seed(observer,ct);var owner=await f.OpenConnectionAsync();var waiter=await f.OpenConnectionAsync();
            await using var tx=await owner.BeginTransactionAsync(ct);await Exec(owner,$"update accounts set security_stamp=gen_random_uuid() where account_id='{a.Account}'",ct,tx);
            var pending=f.Observe(Scalar<bool>(waiter,Transition(a,"verify"),ct));await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waiter.ProcessID,owner.ProcessID,pending,ct);await tx.CommitAsync(ct);
            (await pending).ShouldBeFalse();(await Scalar<string>(observer,"select state from entitlement_grants",ct)).ShouldBe("approved");
        });
    }
    [Fact]
    public async Task Historical_client_selected_activation_rows_are_not_authoritative()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct,false,false);
            await Exec(c,$"insert into activations(account_id,term,off_at,feature_set,code,status) values('{a.Account}',interval '1 year',clock_timestamp()+interval '1 year',8,'historical-code',4)",ct);
            (await Scalar<bool>(c,$"select result from verify_activation('{a.Account}','{a.Stamp}','{a.Email}','historical-code',clock_timestamp(),0::smallint,1::smallint)",ct)).ShouldBeFalse();
            (await Scalar<bool>(c,Stage(a),ct)).ShouldBeFalse();(await Scalar<long>(c,"select count(*) from entitlement_grants",ct)).ShouldBe(0);
        });
    }
    [Theory,InlineData("request"),InlineData("grant"),InlineData("audit")]
    public async Task Missing_domain_or_audit_write_rolls_back_consumption(string skip)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);string table=skip switch {"request"=>"grant_activation_requests","grant"=>"entitlement_grants",_=>"entitlement_grant_audit"};string verb=skip=="audit"?"insert":"update";
            await Exec(c,$"create function cor19_skip_effect() returns trigger language plpgsql as $$ begin return null;end $$;create trigger cor19_skip_effect before {verb} on {table} for each row execute function cor19_skip_effect()",ct);
            await Should.ThrowAsync<PostgresException>(()=>Scalar<bool>(c,Transition(a,"verify"),ct));
            (await Scalar<string>(c,"select state from entitlement_grants",ct)).ShouldBe("approved");(await Scalar<string>(c,"select state from grant_activation_requests",ct)).ShouldBe("pending");(await Scalar<bool>(c,"select consumed_at is null from grant_activation_requests",ct)).ShouldBeTrue();
        });
    }
    [Fact]
    public async Task Encrypted_outbox_and_atomic_receipt_preserve_lifecycle_on_another_instance()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct,true,false);
            var settings=Options.Create(new DeliveryOutboxSettings {EncryptionKeys=new(){{1,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}});
            var ops=new SecurityOperationSettings{HmacKeys=new(){{1,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}};
            await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,ops);var outbox=new DeliveryOutboxRepo(storage,settings);
            var admission=(await Scalar<Guid>(c,"select " + Cor21CreationSql.Admit(a.Account,a.Stamp,a.Session,a.Family,a.Grant,a.Hash,a.Email),ct));
            var payload=new DeliveryPayloadProtector(settings).Protect(new(a.Account,a.Stamp,"activation",a.Hash,SystemClock.Instance.GetCurrentInstant()+Duration.FromMinutes(10),new {admissionId=admission,grantId=a.Grant,grantVersion=1,sessionHash=a.Session,familyId=a.Family,emailAddress=a.Email,tier=2,term=1,cadence=0},new("activation-code","email",a.Email,"activation","plaintext-secret")));
            (await outbox.StageAsync(payload,ct)).Result.ShouldBeTrue();a=a with{Request=payload.Id};
            (await Scalar<string>(c,"select metadata_json from delivery_candidates",ct)).ShouldNotContain("plaintext-secret");
            var job=(await outbox.ClaimAsync(ct)).ShouldNotBeNull();await outbox.RecordAsync(job,new(DeliverySendState.Accepted,"accepted"),ct);(await outbox.PublishAsync(payload.Id,ct)).ShouldBeTrue();
            var repo=new ActivationRepo(storage,NullLogger<ActivationRepo>.Instance);var context=SecurityOperationRequestContext.Isolated("activation-response-loss");
            using(SecurityOperationRequestContext.Push(context)){
                (await repo.TransitionAsync(a.Account,a.Stamp,a.Session,a.Family,a.Grant,1,a.Request,a.Hash,"verify",ct)).Result.ShouldBeTrue();
                await storage.SecurityOperations.FinishAsync(context,200,false);
            }
            await using var second=new Cor09RefreshHttpTests.FixtureStorage(f,ops);var receipt=await second.SecurityOperations.ReconcileAuthorizedAsync(context.ClientKey!,context.RecoveryKey!,ct);
            receipt.State.ShouldBe(treehammock.DataLayer.Operations.SecurityOperationState.Committed);receipt.Steps.Single().Code.ShouldBe("ACTIVATION_VERIFIED");
            (await Scalar<string>(c,"select string_agg(to_jsonb(s)::text,',') from security_operation_steps s",ct)).ShouldNotContain("plaintext-secret");
            (await Scalar<bool>(c,Transition(a,"disable",2),ct)).ShouldBeTrue();
        });
    }
    [Fact]
    public async Task Deadline_passing_during_audit_wait_rolls_back_every_redemption_write()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var observer=await f.OpenConnectionAsync();var a=await Seed(observer,ct);
            await Exec(observer,"update grant_activation_requests set expires_at=clock_timestamp()+interval '700 milliseconds'",ct);
            var owner=await f.OpenConnectionAsync();var waiter=await f.OpenConnectionAsync();await using var tx=await owner.BeginTransactionAsync(ct);
            await Exec(owner,"lock table entitlement_grant_audit in share mode",ct,tx);
            var pending=f.Observe(Scalar<bool>(waiter,Transition(a,"verify"),ct));await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waiter.ProcessID,owner.ProcessID,pending,ct);
            while(!await Scalar<bool>(observer,"select clock_timestamp()>=expires_at from grant_activation_requests",ct))await Task.Delay(20,ct);
            await tx.CommitAsync(ct);(await pending).ShouldBeFalse();
            (await Scalar<string>(observer,"select state from entitlement_grants",ct)).ShouldBe("approved");(await Scalar<bool>(observer,"select proof_hash is not null and consumed_at is null from grant_activation_requests",ct)).ShouldBeTrue();
            (await Scalar<long>(observer,"select count(*) from entitlement_grant_audit where action='redeemed'",ct)).ShouldBe(0);
        });
    }
    [Fact]
    public async Task Refreshed_generation_in_same_live_family_can_redeem_once()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);
            string fresh=Guid.NewGuid().ToString("N");await Exec(c,$"update sessions set access_token_hash='{fresh}',generation=generation+1 where session_id='{a.Family}'",ct);
            (await Scalar<bool>(c,Transition(a,"verify"),ct)).ShouldBeFalse();a=a with{Session=fresh};(await Scalar<bool>(c,Transition(a,"verify"),ct)).ShouldBeTrue();
        });
    }
    [Fact]
    public async Task Unaudited_grant_row_is_not_an_approval_and_audit_history_is_immutable()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct,false,false);await Issuer(c,true,ct);
            await Exec(c,$"insert into entitlement_grants(grant_id,account_id,origin_stamp,catalog,tier,term,cadence,authorized_end,max_cycles,redeem_before,issuer,issuer_reference,start_anchor) values('{a.Grant}','{a.Account}','{a.Stamp}','treehammock-v1',2,1,0,clock_timestamp()+interval '1 day',1,clock_timestamp()+interval '2 hours',current_user,'unaudited','redemption')",ct);
            (await Scalar<bool>(c,Stage(a),ct)).ShouldBeFalse();
            var trusted=a with{Grant=Guid.NewGuid()};(await Scalar<bool>(c,Issue(trusted),ct)).ShouldBeTrue();
            await Should.ThrowAsync<PostgresException>(()=>Exec(c,"update entitlement_grant_audit set actor='forged'",ct));await Should.ThrowAsync<PostgresException>(()=>Exec(c,"delete from entitlement_grant_audit",ct));
        });
    }
    [Theory,InlineData("queued"),InlineData("accepted"),InlineData("family-revoked")]
    public async Task Pending_cancel_or_lost_family_prevents_outbox_publication(string state)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct,true,false);
            (await Scalar<bool>(c,Stage(a),ct)).ShouldBeTrue();await Exec(c,$"insert into delivery_candidates(delivery_id,account_id,account_stamp,purpose,proof_hash,expires_at,metadata_json,predecessor,state) values('{a.Request}','{a.Account}','{a.Stamp}','activation','{a.Hash}',clock_timestamp()+interval '10 minutes','{{}}',cor12_delivery_predecessor('{a.Account}','activation'),'staged');insert into delivery_outbox(delivery_id,state,key_version,nonce,ciphertext,tag) values('{a.Request}','{(state=="queued"?"queued":"accepted")}',1,null,null,null)",ct);
            if(state=="family-revoked")await Exec(c,"update sessions set cut_off=clock_timestamp()",ct);else(await Scalar<bool>(c,Transition(a,"cancel"),ct)).ShouldBeTrue();
            (await Scalar<bool>(c,$"select cor12_publish_delivery('{a.Request}')",ct)).ShouldBeFalse();
            (await Scalar<long>(c,"select count(*) from entitlement_grants where state='active'",ct)).ShouldBe(0);
        });
    }

    [Theory,InlineData("request"),InlineData("grant"),InlineData("audit")]
    public async Task Revocation_missing_write_cannot_report_success_or_leave_partial_state(string skip)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);(await Scalar<bool>(c,Transition(a,"verify"),ct)).ShouldBeTrue();
            string table=skip switch {"request"=>"grant_activation_requests","grant"=>"entitlement_grants",_=>"entitlement_grant_audit"};
            await Exec(c,$"create function skip_revoke() returns trigger language plpgsql as $$ begin return null;end $$;create trigger skip_revoke before {(skip=="audit"?"insert":"update")} on {table} for each row execute function skip_revoke()",ct);
            await Should.ThrowAsync<PostgresException>(()=>Scalar<bool>(c,Transition(a,"disable",2),ct));
            (await Scalar<string>(c,"select state from entitlement_grants",ct)).ShouldBe("active");(await Scalar<string>(c,"select state from grant_activation_requests",ct)).ShouldBe("active");(await Scalar<long>(c,"select count(*) from entitlement_grant_audit where action='revoked'",ct)).ShouldBe(0);
        });
    }
    [Fact]
    public async Task Active_grant_can_be_revoked_after_stamp_rotation_from_a_new_live_family()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);(await Scalar<bool>(c,Transition(a,"verify"),ct)).ShouldBeTrue();
            var fresh=a with{Stamp=Guid.NewGuid(),Family=Guid.NewGuid(),Session=Guid.NewGuid().ToString("N")};
            await Exec(c,$"update accounts set security_stamp='{fresh.Stamp}';insert into sessions(access_token_hash,account_id,session_id,account_security_stamp,created_on,access_expiration,session_expiration) values('{fresh.Session}','{fresh.Account}','{fresh.Family}','{fresh.Stamp}',clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours')",ct);
            (await Scalar<bool>(c,Transition(a,"disable",2),ct)).ShouldBeFalse();(await Scalar<bool>(c,Transition(fresh,"disable",2),ct)).ShouldBeTrue();
            (await Scalar<string>(c,"select state from entitlement_grants",ct)).ShouldBe("revoked");
        });
    }

}
