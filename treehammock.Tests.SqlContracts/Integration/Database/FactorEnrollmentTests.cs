using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using NodaTime;
using Npgsql;
using Shouldly;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Tests.SqlContracts.Support;
namespace treehammock.Tests.Integration.Database;

[Trait("Suite","SqlContracts")]
public class Cor16FactorEnrollmentTests
{
    private static IOptions<DeliveryOutboxSettings> Settings()=>Options.Create(new DeliveryOutboxSettings {EncryptionKeys=new(){{1,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}});
    private static Cor09RefreshHttpTests.FixtureStorage Storage(SqlContractFixture f)=>new(f,new SecurityOperationSettings {HmacKeys=new(){{1,Convert.ToBase64String(new byte[32])}}});
    private static async Task<(Guid Account,Guid Stamp)> Account(NpgsqlConnection c,CancellationToken ct)
    {
        Guid account=Guid.NewGuid(),stamp=Guid.NewGuid();await Exec(c,$"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{account}','cor16@example.test',1,'{stamp}')",ct);return(account,stamp);
    }
    private static async Task Exec(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null)
    {await using var cmd=new NpgsqlCommand(sql,c,tx);await cmd.ExecuteNonQueryAsync(ct);}
    private static async Task<T> Scalar<T>(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null)
    {await using var cmd=new NpgsqlCommand(sql,c,tx);return (T)(await cmd.ExecuteScalarAsync(ct))!;}
    private static ProtectedDelivery Candidate(Guid account,Guid stamp,int method,Cor16EnrollmentSql.Grant g,string hash="proof",Guid? expected=null,long? version=null)
    {
        var intent=new DeliveryIntent(account,stamp,"factor-"+method,hash,SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(20)),
            new{emailAddress=method==1?"cor16@example.test":null,phoneNumber=method==2?"5555550101":null,phoneCountryCode=method==2?"1":null,required=true,
                expectedEnrollmentId=expected,expectedVersion=version,grantSession=g.Session,grantToken=g.Token,grantTarget=g.Target},new("factor",method==1?"email":"sms","fixture","test","123456"));
        return new DeliveryPayloadProtector(Settings()).Protect(intent);
    }
    private static async Task Publish(DeliveryOutboxRepo repo,Guid id,CancellationToken ct)
    {
        var job=(await repo.ClaimAsync(ct)).ShouldNotBeNull();job.Delivery.Id.ShouldBe(id);job.State.ShouldBe("claimed");
        await repo.RecordAsync(job,new(DeliverySendState.Accepted,"fixture-provider-acknowledgment"),ct);
        (await repo.PublishAsync(id,ct)).ShouldBeTrue();
    }
    [Theory,InlineData(1),InlineData(2)]
    public async Task Fresh_grant_reserves_a_bound_request_and_published_destination_proof_promotes_once(int method)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,method==1?3:4,ct);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a.Account,a.Stamp,method,g);
            var staged=await repo.StageAsync(d,ct);staged.Result.ShouldBeTrue();staged.EnrollmentId.ShouldBe(d.Id);staged.SetupVersion.ShouldBe(1);
            (await Scalar<bool>(c,Cor16EnrollmentSql.Verify(a.Account,a.Stamp,method,"proof",d.Id),ct)).ShouldBeFalse(); // No published destination proof yet.
            await Publish(repo,d.Id,ct);
            (await Scalar<bool>(c,Cor16EnrollmentSql.Verify(a.Account,a.Stamp,method,"proof",d.Id),ct)).ShouldBeTrue();
            (await Scalar<bool>(c,Cor16EnrollmentSql.Verify(a.Account,a.Stamp,method,"proof",d.Id),ct)).ShouldBeFalse();
            (await Scalar<long>(c,"select count(*) from two_factor_authentications where verified",ct)).ShouldBe(1);
            (await Scalar<int>(c,"select two_factor_auth_method::integer from accounts",ct)).ShouldBe(method);
            (await Scalar<bool>(c,"select setup_request_id is null and setup_origin_stamp is null from two_factor_authentications where verified",ct)).ShouldBeTrue();
        });
    }
    [Theory,InlineData("missing"),InlineData("wrong-purpose"),InlineData("wrong-target"),InlineData("incomplete-factor"),InlineData("stale-stamp")]
    public async Task Unapproved_setup_creates_no_new_factor_or_delivery_job(string fault)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);
            if(fault=="incomplete-factor") await Exec(c,$"insert into two_factor_authentications(account_id,two_factor_index,method,verified,email_address) values('{a.Account}',1,1,true,'cor16@example.test')",ct);
            var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,fault=="wrong-purpose"?3:4,ct,factorComplete:fault!="incomplete-factor");
            if(fault=="missing")g=g with{Token=new string('f',64)};if(fault=="wrong-target")g=g with{Target=new string('b',64)};
            if(fault=="stale-stamp")await Exec(c,"update accounts set security_stamp=gen_random_uuid()",ct);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());
            (await repo.StageAsync(Candidate(a.Account,a.Stamp,2,g),ct)).Result.ShouldBeFalse();
            (await Scalar<long>(c,"select count(*) from two_factor_authentications where not verified",ct)).ShouldBe(0);
            (await Scalar<long>(c,"select count(*) from delivery_outbox",ct)).ShouldBe(0);
        });
    }
    [Theory,InlineData("stamp"),InlineData("family"),InlineData("policy"),InlineData("expiry"),InlineData("version")]
    public async Task Verification_rejects_changed_origin_and_preserves_summary_and_attempt_budget(string changed)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,4,ct);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a.Account,a.Stamp,2,g);(await repo.StageAsync(d,ct)).Result.ShouldBeTrue();await Publish(repo,d.Id,ct);
            Guid current=a.Stamp;string? family=null;long version=1;
            if(changed=="stamp"){current=Guid.NewGuid();await Exec(c,$"update accounts set security_stamp='{current}'",ct);}
            if(changed=="family")family=$"'{Guid.NewGuid()}'::uuid";
            if(changed=="policy")await Exec(c,$"insert into two_factor_authentications(account_id,two_factor_index,method,verified,email_address) values('{a.Account}',2,1,true,'cor16@example.test')",ct);
            if(changed=="expiry")await Exec(c,"update two_factor_authentications set setup_authorized_until=clock_timestamp()-interval '1 second' where not verified",ct);
            if(changed=="version")version=2;
            (await Scalar<bool>(c,Cor16EnrollmentSql.Verify(a.Account,current,2,"proof",d.Id,version,family),ct)).ShouldBeFalse();
            (await Scalar<long>(c,"select count(*) from two_factor_authentications where method=2 and verified",ct)).ShouldBe(0);
            (await Scalar<short>(c,"select setup_attempts from two_factor_authentications where method=2",ct)).ShouldBe((short)0);
            (await Scalar<short>(c,"select two_factor_auth_method from accounts",ct)).ShouldBe((short)0);
        });
    }
    [Theory,InlineData("factor"),InlineData("summary")]
    public async Task Zero_row_effect_rolls_back_both_promotion_and_summary(string skipped)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,4,ct);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a.Account,a.Stamp,2,g);(await repo.StageAsync(d,ct)).Result.ShouldBeTrue();await Publish(repo,d.Id,ct);
            string table=skipped=="factor"?"two_factor_authentications":"accounts";
            await Exec(c,$"create function cor16_skip_write() returns trigger language plpgsql as $$ begin return null;end;$$; create trigger a_cor16_skip_write before update on {table} for each row execute function cor16_skip_write()",ct);
            (await Scalar<bool>(c,Cor16EnrollmentSql.Verify(a.Account,a.Stamp,2,"proof",d.Id),ct)).ShouldBeFalse();
            (await Scalar<bool>(c,"select not verified and token='proof' and setup_request_id is not null from two_factor_authentications",ct)).ShouldBeTrue();
            (await Scalar<short>(c,"select two_factor_auth_method from accounts",ct)).ShouldBe((short)0);
        });
    }
    [Theory,InlineData(false),InlineData(true)]
    public async Task Replacement_and_verification_observe_one_account_locked_winner(bool verificationWins)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var observer=await f.OpenConnectionAsync();var a=await Account(observer,ct);var first=await Cor16EnrollmentSql.SeedGrant(observer,a.Account,a.Stamp,4,ct);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var old=Candidate(a.Account,a.Stamp,2,first);(await repo.StageAsync(old,ct)).Result.ShouldBeTrue();await Publish(repo,old.Id,ct);
            var second=await Cor16EnrollmentSql.SeedGrant(observer,a.Account,a.Stamp,4,ct);var next=Candidate(a.Account,a.Stamp,2,second,"replacement",old.Id,1);
            var holdingConnection=await f.OpenConnectionAsync();var waitingConnection=await f.OpenConnectionAsync();await using var holding=await holdingConnection.BeginTransactionAsync(ct);await using var waiting=await waitingConnection.BeginTransactionAsync(ct);
            await Exec(holdingConnection,$"select 1 from accounts where account_id='{a.Account}' for update",ct,holding);
            Task<bool> contender=verificationWins?StageResult(waitingConnection,waiting,next,ct):Scalar<bool>(waitingConnection,Cor16EnrollmentSql.Verify(a.Account,a.Stamp,2,"proof",old.Id),ct,waiting);
            f.Observe(contender);await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waitingConnection.ProcessID,holdingConnection.ProcessID,contender,ct);
            bool winner=verificationWins?await Scalar<bool>(holdingConnection,Cor16EnrollmentSql.Verify(a.Account,a.Stamp,2,"proof",old.Id),ct,holding):await StageResult(holdingConnection,holding,next,ct);
            winner.ShouldBeTrue();await holding.CommitAsync(ct);(await contender).ShouldBeFalse();await waiting.CommitAsync(ct);
            (await Scalar<long>(observer,$"select count(*) from delivery_outbox where delivery_id='{next.Id}'",ct)).ShouldBe(verificationWins?0:1);
            (await Scalar<long>(observer,"select count(*) from two_factor_authentications where verified",ct)).ShouldBe(verificationWins?1:0);
        });
    }
    private static async Task<bool> StageResult(NpgsqlConnection c,NpgsqlTransaction tx,ProtectedDelivery d,CancellationToken ct)=>(await DeliveryOutboxRepo.StageInAsync(c,tx,d,ct)).Result;
    [Theory,InlineData(false),InlineData(true)]
    public async Task Zero_row_pending_write_rolls_back_grant_domain_and_delivery(bool replacement)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);
            var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,4,ct);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());
            Guid? previous=null;long? version=null;
            if(replacement) {var old=Candidate(a.Account,a.Stamp,2,g);(await repo.StageAsync(old,ct)).Result.ShouldBeTrue();previous=old.Id;version=1;g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,4,ct);}
            await Exec(c,"create function skip_setup_write() returns trigger language plpgsql as $$ begin return null; end $$; create trigger skip_setup before insert or update on two_factor_authentications for each row execute function skip_setup_write()",ct);
            var d=Candidate(a.Account,a.Stamp,2,g,"new-proof",previous,version);
            (await repo.StageAsync(d,ct)).Result.ShouldBeFalse();
            (await Scalar<long>(c,$"select count(*) from delivery_outbox where delivery_id='{d.Id}'",ct)).ShouldBe(0);
            (await Scalar<bool>(c,$"select consumed_on is null from sensitive_action_grants where token_hash='{g.Token}'",ct)).ShouldBeTrue();
            (await Scalar<long>(c,"select count(*) from two_factor_authentications",ct)).ShouldBe(replacement?1:0);
            if(replacement) (await Scalar<string>(c,"select token from two_factor_authentications",ct)).ShouldBe("proof");
        });
    }
    [Theory,InlineData("email"),InlineData("reset"),InlineData("remove")]
    public async Task Verification_waiting_for_authoritative_change_cannot_promote_stale_setup(string transition)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var observer=await f.OpenConnectionAsync();var a=await Account(observer,ct);
            var grant=await Cor16EnrollmentSql.SeedGrant(observer,a.Account,a.Stamp,4,ct);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a.Account,a.Stamp,2,grant);
            (await repo.StageAsync(d,ct)).Result.ShouldBeTrue();await Publish(repo,d.Id,ct);
            string mutation;
            if(transition=="email") {
                await Cor17EmailSql.Install(observer,ct);
                (await Scalar<bool>(observer,$"select result from cor17_fixture_request_email('{a.Account}','{a.Stamp}','changed@example.test','email-proof',clock_timestamp()+interval '1 hour')",ct)).ShouldBeTrue();
                mutation="select result from complete_account_email_change('email-proof')";
            } else if(transition=="remove") {
                var remove=await Cor16EnrollmentSql.SeedGrant(observer,a.Account,a.Stamp,2,ct);
                mutation=$"select code='TWO_FACTOR_METHOD_NOT_CONFIGURED' from cor08_authorized_remove_twofactor_method('{a.Account}','{a.Stamp}',2::smallint,clock_timestamp(),'{remove.Session}','{remove.Token}','{remove.Target}')";
            } else {
                var reset=Guid.NewGuid();
                (await Scalar<bool>(observer,$"select result from create_password_reset_request('{reset}','{a.Account}','email','email','reset-proof',1,'fingerprint','masked',true,false,clock_timestamp()+interval '1 hour',5,null,null,'{a.Stamp}')",ct)).ShouldBeTrue();
                await Exec(observer,Cor13ResetSql.Bootstrap(a.Account.ToString(),reset.ToString()),ct);
                mutation=$"select result from promote_password_reset('{reset}','{a.Account}',decode(repeat('01',128),'hex'),decode(repeat('02',64),'hex'),decode(repeat('03',32),'hex'),decode(repeat('04',16),'hex'),'{Guid.NewGuid()}',clock_timestamp(),'reset-authorization',1::bigint,0::bigint)";
            }
            var owner=await f.OpenConnectionAsync();var waiter=await f.OpenConnectionAsync();await using var hold=await owner.BeginTransactionAsync(ct);
            await Exec(owner,$"select 1 from accounts where account_id='{a.Account}' for update",ct,hold);
            var verify=f.Observe(Scalar<bool>(waiter,Cor16EnrollmentSql.Verify(a.Account,a.Stamp,2,"proof",d.Id),ct));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waiter.ProcessID,owner.ProcessID,verify,ct);
            (await Scalar<bool>(owner,mutation,ct,hold)).ShouldBeTrue();await hold.CommitAsync(ct);
            (await verify).ShouldBeFalse();(await Scalar<long>(observer,"select count(*) from two_factor_authentications where method=2 and verified",ct)).ShouldBe(0);
        });
    }
    [Fact]
    public async Task Stable_family_refresh_preserves_pending_authority()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,4,ct);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a.Account,a.Stamp,2,g);
            (await repo.StageAsync(d,ct)).Result.ShouldBeTrue();await Publish(repo,d.Id,ct);
            await Exec(c,$"update sessions set access_token_hash='rotated-access' where access_token_hash='{g.Session}'",ct);
            (await Scalar<bool>(c,Cor16EnrollmentSql.Verify(a.Account,a.Stamp,2,"proof",d.Id),ct)).ShouldBeTrue();
        });
    }
    [Fact]
    public async Task Stale_queued_approval_is_rejected_before_provider_claim()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,4,ct);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a.Account,a.Stamp,2,g);(await repo.StageAsync(d,ct)).Result.ShouldBeTrue();
            await Exec(c,"update sessions set cut_off=clock_timestamp()-interval '1 second'",ct);
            (await repo.ClaimAsync(ct)).ShouldBeNull();
            (await Scalar<bool>(c,"select ciphertext is null and tag is null and state='expired' from delivery_outbox",ct)).ShouldBeTrue();
        });
    }
    [Fact]
    public async Task A_claimed_delivery_blocks_cross_method_replacement_without_a_second_job()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,4,ct);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a.Account,a.Stamp,2,g);(await repo.StageAsync(d,ct)).Result.ShouldBeTrue();(await repo.ClaimAsync(ct)).ShouldNotBeNull();
            var emailGrant=await Cor16EnrollmentSql.SeedGrant(c,a.Account,a.Stamp,3,ct);var attempted=await repo.StageAsync(Candidate(a.Account,a.Stamp,1,emailGrant,"other",d.Id,1),ct);
            attempted.Result.ShouldBeFalse();attempted.Code.ShouldBe("TWO_FACTOR_SETUP_DELIVERY_PENDING");
            (await Scalar<long>(c,"select count(*) from delivery_outbox",ct)).ShouldBe(1);
            (await Scalar<int>(c,"select method::integer from two_factor_authentications",ct)).ShouldBe(2);
        });
    }
}
