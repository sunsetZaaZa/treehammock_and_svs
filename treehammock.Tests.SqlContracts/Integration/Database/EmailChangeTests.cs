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
public class Cor17EmailChangeTests
{
    private static IOptions<DeliveryOutboxSettings> Settings()=>Options.Create(new DeliveryOutboxSettings {EncryptionKeys=new(){{1,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}});
    private static Cor09RefreshHttpTests.FixtureStorage Storage(SqlContractFixture f)=>new(f,new SecurityOperationSettings {HmacKeys=new(){{1,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}});
    private static async Task Exec(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null) {await using var cmd=new NpgsqlCommand(sql,c,tx);await cmd.ExecuteNonQueryAsync(ct);}
    private static async Task<T> Scalar<T>(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null) {await using var cmd=new NpgsqlCommand(sql,c,tx);return(T)(await cmd.ExecuteScalarAsync(ct))!;}
    private static async Task<(Guid Id,Guid Stamp,string Email)> Account(NpgsqlConnection c,CancellationToken ct)
    {Guid id=Guid.NewGuid(),stamp=Guid.NewGuid();string email=id.ToString("N")+"@example.test";await Exec(c,$"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{id}','{email}',1,'{stamp}')",ct);return(id,stamp,email);}
    private static ProtectedDelivery Candidate((Guid Id,Guid Stamp,string Email) a,Cor16EnrollmentSql.Grant grant,DeliveryPayloadProtector protector,string target="new@example.test",string hash="email-proof",string payload="new-mailbox-proof",Instant? requestedExpiry=null)
    {
        Instant expiry=requestedExpiry??SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(20));
        var notice=new DeliveryIntent(a.Id,a.Stamp,"email-notice",hash,expiry,new{originEmail=a.Email,requestProofHash=hash},new("email-change-notice","email",a.Email,"test","Owner notification"));
        return protector.Protect(new(a.Id,a.Stamp,"email",hash,expiry,new{newEmailAddress=target,originEmail=a.Email,grantSession=grant.Session,grantToken=grant.Token,grantTarget=grant.Target},new("email","email",target,"test",payload),notice));
    }
    private static async Task Publish(DeliveryOutboxRepo repo,Guid main,CancellationToken ct)
    {
        var job=(await repo.ClaimAsync(ct)).ShouldNotBeNull();job.Delivery.Id.ShouldBe(main);await repo.RecordAsync(job,new(DeliverySendState.Accepted,"accepted"),ct);(await repo.PublishAsync(main,ct)).ShouldBeTrue();
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Clipped_and_unclipped_companions_stage_atomically_with_exact_deadline_binding(bool clipped)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>
        {
            var c=await f.OpenConnectionAsync(ct);var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,5,ct);
            var settings=Settings();settings.Value.PayloadRetentionHours=1;var protector=new DeliveryPayloadProtector(settings);
            var requested=SystemClock.Instance.GetCurrentInstant().Plus(clipped?Duration.FromDays(2):Duration.FromMinutes(20));
            var d=Candidate(a,g,protector,requestedExpiry:requested);var notice=d.Companion.ShouldNotBeNull();
            d.ExpiresAt.ShouldBe(notice.ExpiresAt);d.Id.ShouldNotBe(notice.Id);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,settings);(await repo.StageAsync(d,ct)).Result.ShouldBeTrue();
            await using var check=new NpgsqlCommand("select count(*) from delivery_candidates where account_id=@account and expires_at=@expires",c);
            check.Parameters.AddWithValue("account",a.Id);check.Parameters.Add("expires",NpgsqlTypes.NpgsqlDbType.TimestampTz).Value=d.ExpiresAt.ToDateTimeUtc();
            ((long)(await check.ExecuteScalarAsync(ct))!).ShouldBe(2);
            (await Scalar<long>(c,"select count(*) from delivery_outbox",ct)).ShouldBe(2);
            (await Scalar<long>(c,"select count(*) from account_email_change_requests",ct)).ShouldBe(1);
            var tx=await f.BeginTransactionAsync(c);
            await Should.ThrowAsync<InvalidOperationException>(()=>DeliveryOutboxRepo.StageInAsync(c,tx,d with {Companion=notice with {ExpiresAt=notice.ExpiresAt.Plus(Duration.FromTicks(10))}},ct));
            await tx.RollbackAsync(ct);
        });
    }
    [Fact]
    public async Task Request_grant_reservation_and_two_encrypted_jobs_commit_together_then_POST_revokes_old_sessions()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,5,ct);
            var settings=Settings();var protector=new DeliveryPayloadProtector(settings);var d=Candidate(a,g,protector);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,settings);
            (await repo.StageAsync(d,ct)).Result.ShouldBeTrue();(await Scalar<long>(c,"select count(*) from delivery_outbox",ct)).ShouldBe(2);
            (await Scalar<bool>(c,$"select consumed_on is not null from sensitive_action_grants where token_hash='{g.Token}'",ct)).ShouldBeTrue();
            (await Scalar<bool>(c,"select result from complete_account_email_change('email-proof')",ct)).ShouldBeFalse();
            (await Scalar<string>(c,"select email_address from accounts",ct)).ShouldBe(a.Email);
            await Publish(repo,d.Id,ct);
            (await Scalar<bool>(c,"select result from complete_account_email_change('email-proof')",ct)).ShouldBeTrue();
            (await Scalar<bool>(c,"select result from complete_account_email_change('email-proof')",ct)).ShouldBeFalse();
            (await Scalar<string>(c,"select email_address from accounts",ct)).ShouldBe("new@example.test");
            (await Scalar<Guid>(c,"select security_stamp from accounts",ct)).ShouldNotBe(a.Stamp);
            (await Scalar<long>(c,"select count(*) from sessions where access_expiration>clock_timestamp() or session_expiration>clock_timestamp()",ct)).ShouldBe(0);
            // Old trusted destination notice survives credential rotation and is authenticated with its original envelope.
            var notice=(await repo.ClaimAsync(ct)).ShouldNotBeNull();notice.Delivery.Purpose.ShouldBe("email-notice");protector.Open(notice.Delivery).Destination.ShouldBe(a.Email);
            await repo.RecordAsync(notice,new(DeliverySendState.Accepted,"accepted"),ct);(await repo.PublishAsync(notice.Delivery.Id,ct)).ShouldBeTrue();
            (await Scalar<long>(c,"select count(*) from sensitive_action_grants",ct)).ShouldBe(0);
            (await Scalar<long>(c,"select count(*) from account_email_change_requests",ct)).ShouldBe(0);
        });
    }
    [Theory,InlineData("missing"),InlineData("purpose"),InlineData("target"),InlineData("incomplete"),InlineData("expired")]
    public async Task Invalid_approval_has_no_reservation_or_delivery(string fault)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);
            if(fault=="incomplete")await Exec(c,$"insert into two_factor_authentications(account_id,two_factor_index,method,verified,email_address) values('{a.Id}',1,1,true,'{a.Email}')",ct);
            var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,fault=="purpose"?4:5,ct,factorComplete:fault!="incomplete");
            if(fault=="expired")await Exec(c,"update sensitive_action_grants set expiration=clock_timestamp()-interval '1 second'",ct);
            if(fault=="target")g=g with{Target=new string('b',64)};if(fault=="missing")g=g with{Token=new string('x',64)};
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a,g,new(Settings()));
            (await repo.StageAsync(d,ct)).Result.ShouldBeFalse();(await Scalar<long>(c,"select count(*) from account_email_change_requests",ct)).ShouldBe(0);(await Scalar<long>(c,"select count(*) from delivery_outbox",ct)).ShouldBe(0);
        });
    }
    [Theory,InlineData("stamp"),InlineData("family"),InlineData("policy"),InlineData("deadline")]
    public async Task Origin_change_prevents_identity_mutation_even_with_new_mailbox_proof(string changed)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,5,ct);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a,g,new(Settings()));(await repo.StageAsync(d,ct)).Result.ShouldBeTrue();await Publish(repo,d.Id,ct);
            string mutation=changed switch {
                "stamp"=>"update accounts set security_stamp=gen_random_uuid()",
                "family"=>"update sessions set access_expiration=clock_timestamp()",
                "deadline"=>"update account_email_change_requests set authorized_until=clock_timestamp()",
                _=>$"insert into two_factor_authentications(account_id,two_factor_index,method,verified,email_address) values('{a.Id}',1,1,true,'{a.Email}')"};
            await Exec(c,mutation,ct);(await Scalar<bool>(c,"select result from complete_account_email_change('email-proof')",ct)).ShouldBeFalse();(await Scalar<string>(c,"select email_address from accounts",ct)).ShouldBe(a.Email);
        });
    }
    [Theory,InlineData("expired"),InlineData("stamp"),InlineData("cancelled")]
    public async Task Admission_retires_stale_reservations_and_preserves_live_unique_claims(string stale)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var first=await Account(c,ct);var second=await Account(c,ct);
            var g=await Cor16EnrollmentSql.SeedGrant(c,first.Id,first.Stamp,5,ct);await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());
            var old=Candidate(first,g,new(Settings()));(await repo.StageAsync(old,ct)).Result.ShouldBeTrue();
            g=await Cor16EnrollmentSql.SeedGrant(c,second.Id,second.Stamp,5,ct);var next=Candidate(second,g,new(Settings()),hash:"next-proof");
            (await repo.StageAsync(next,ct)).Code.ShouldBe("ACCOUNT_ADJUST_DUPLICATE_EMAIL");
            if(stale=="expired")await Exec(c,$"update account_email_change_requests set authorized_until=clock_timestamp() where account_id='{first.Id}'",ct);
            else if(stale=="stamp")await Exec(c,$"update accounts set security_stamp=gen_random_uuid() where account_id='{first.Id}'",ct);
            else (await Scalar<bool>(c,$"select result from cancel_account_email_change_request('{first.Id}','{first.Stamp}','email-proof')",ct)).ShouldBeTrue();
            (await repo.StageAsync(next,ct)).Result.ShouldBeTrue();
            (await Scalar<Guid>(c,"select account_id from account_email_change_requests",ct)).ShouldBe(second.Id);
            (await Scalar<bool>(c,$"select state='expired' and ciphertext is null from delivery_outbox where delivery_id='{old.Id}'",ct)).ShouldBeTrue();
        });
    }
    [Theory,InlineData("reservation"),InlineData("notice")]
    public async Task Zero_row_or_notification_failure_rolls_back_grant_reservation_and_both_jobs(string fail)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,5,ct);
            if(fail=="reservation")await Exec(c,"create function skip_reservation() returns trigger language plpgsql as $$ begin return null;end $$;create trigger skip_reservation before insert or update on account_email_change_requests for each row execute function skip_reservation()",ct);
            var d=Candidate(a,g,new(Settings()));if(fail=="notice")d=d with{Companion=d.Companion! with{MetadataJson="{}"}};
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());(await repo.StageAsync(d,ct)).Result.ShouldBeFalse();
            (await Scalar<long>(c,"select count(*) from account_email_change_requests",ct)).ShouldBe(0);(await Scalar<long>(c,"select count(*) from delivery_outbox",ct)).ShouldBe(0);
            (await Scalar<bool>(c,$"select consumed_on is null from sensitive_action_grants where token_hash='{g.Token}'",ct)).ShouldBeTrue();
        });
    }
    [Theory,InlineData("account"),InlineData("summary")]
    public async Task Zero_row_account_or_summary_write_rolls_back_identity_factor_and_sessions(string skip)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,5,ct);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a,g,new(Settings()));(await repo.StageAsync(d,ct)).Result.ShouldBeTrue();await Publish(repo,d.Id,ct);
            string predicate=skip=="account"?"new.email_address is distinct from old.email_address":"new.email_address=old.email_address";
            await Exec(c,$"create function skip_email_effect() returns trigger language plpgsql as $$ begin if {predicate} then return null;end if;return new;end $$;create trigger skip_email_effect before update on accounts for each row execute function skip_email_effect()",ct);
            (await Scalar<bool>(c,"select result from complete_account_email_change('email-proof')",ct)).ShouldBeFalse();
            (await Scalar<Guid>(c,"select security_stamp from accounts",ct)).ShouldBe(a.Stamp);(await Scalar<string>(c,"select email_address from accounts",ct)).ShouldBe(a.Email);
            (await Scalar<long>(c,"select count(*) from sessions where access_expiration>clock_timestamp()",ct)).ShouldBe(1);(await Scalar<long>(c,"select count(*) from account_email_change_requests",ct)).ShouldBe(1);
        });
    }
    [Theory,InlineData(1),InlineData(2)]
    public async Task Email_or_SMS_only_accounts_do_not_downgrade_owner_approval(int method)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,5,ct);
            await Exec(c,$"insert into two_factor_authentications(account_id,two_factor_index,method,verified,email_address,phone_number,phone_country_code) values('{a.Id}',1,{method},true,'{a.Email}','5555550101','1')",ct);
            (await Scalar<string>(c,$"select code from cor08_begin_password_proof('{a.Id}','{a.Stamp}','{g.Session}','{Guid.NewGuid()}',5::smallint,repeat('a',64),5,900,30)",ct)).ShouldBe("SENSITIVE_ACTION_FACTOR_UNAVAILABLE");
            (await Scalar<long>(c,"select count(*) from account_email_change_requests",ct)).ShouldBe(0);
        });
    }
    [Fact]
    public async Task Email_change_removes_email_and_pending_factors_but_retains_authenticator_material()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);
            var settings=new TotpSettings {ActiveProtectionKeyId="fixture",ProtectionKeys=new(){{"fixture",Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}};
            var protector=new treehammock.Services.TotpSecretProtector(Options.Create(settings));
            var envelope=protector.Protect("12345678901234567890"u8.ToArray(),new(a.Id,Guid.NewGuid(),new("SHA256",8,60,0)));
            await using(var insert=new NpgsqlCommand("""
                insert into two_factor_authentications(account_id,two_factor_index,method,verified,email_address) values(@account,1,1,true,@email);
                insert into two_factor_authentications(account_id,two_factor_index,method,verified,totp_provider_type,totp_secret_version,totp_secret_ciphertext,totp_secret_nonce,totp_secret_tag,totp_key_id,totp_enrollment_id,totp_algorithm,totp_digits,totp_period_seconds,totp_clock_skew_steps,totp_last_used_step)
                values(@account,2,3,true,1,2,@cipher,@nonce,@tag,'fixture',@enrollment,'SHA256',8,60,0,12345);
                insert into two_factor_authentications(account_id,two_factor_index,method,verified,token,expiration,phone_number,phone_country_code) values(@account,3,2,false,'pending',clock_timestamp()+interval '1 hour','5555550101','1');
                """,c)) {
                insert.Parameters.AddWithValue("account",a.Id);insert.Parameters.AddWithValue("email",a.Email);insert.Parameters.AddWithValue("cipher",envelope.Ciphertext);insert.Parameters.AddWithValue("nonce",envelope.Nonce);insert.Parameters.AddWithValue("tag",envelope.Tag);insert.Parameters.AddWithValue("enrollment",envelope.Context.EnrollmentId);await insert.ExecuteNonQueryAsync(ct);
            }
            // Grant represents already-completed password and retained authenticator attestation.
            var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,5,ct);await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a,g,new(Settings()));(await repo.StageAsync(d,ct)).Result.ShouldBeTrue();await Publish(repo,d.Id,ct);
            (await Scalar<bool>(c,"select result from complete_account_email_change('email-proof')",ct)).ShouldBeTrue();
            (await Scalar<long>(c,"select count(*) from two_factor_authentications",ct)).ShouldBe(1);(await Scalar<short>(c,"select two_factor_auth_method from accounts",ct)).ShouldBe((short)3);
            (await Scalar<byte[]>(c,"select totp_secret_ciphertext from two_factor_authentications",ct)).ShouldBe(envelope.Ciphertext);
            (await Scalar<long>(c,"select totp_last_used_step from two_factor_authentications",ct)).ShouldBe(12345);
        });
    }
    [Fact]
    public async Task Lost_confirmation_response_is_resolved_from_committed_receipt_on_another_instance()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,5,ct);
            var options=Options.Create(new SecurityOperationSettings {HmacKeys=new(){{1,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}});
            await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,options.Value);
            var delivery=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a,g,new(Settings()));(await delivery.StageAsync(d,ct)).Result.ShouldBeTrue();await Publish(delivery,d.Id,ct);
            var context=treehammock.Rigging.Operations.SecurityOperationRequestContext.Isolated("cor17-confirmation");
            using(treehammock.Rigging.Operations.SecurityOperationRequestContext.Push(context)) {
                var accountRepo=new AccountRepo(new(Settings()),storage,Options.Create(new JWTSettings()),Microsoft.Extensions.Logging.Abstractions.NullLogger<AccountRepo>.Instance,NSubstitute.Substitute.For<treehammock.Rigging.Security.IUserSecretHasher>());
                (await accountRepo.CompleteEmailChange("email-proof",ct)).ShouldNotBeNull().Result.ShouldBeTrue();
                await storage.SecurityOperations.FinishAsync(context,200,false);
            }
            // Simulate loss after commit, before any response reaches the caller.
            await using var second=new Cor09RefreshHttpTests.FixtureStorage(f,options.Value);
            var receipt=await second.SecurityOperations.ReconcileAuthorizedAsync(context.ClientKey!,context.RecoveryKey!,ct);
            receipt.State.ShouldBe(treehammock.DataLayer.Operations.SecurityOperationState.Committed);
            (await Scalar<string>(c,"select email_address from accounts",ct)).ShouldBe("new@example.test");
            (await Scalar<bool>(c,"select result from complete_account_email_change('email-proof')",ct)).ShouldBeFalse();
        });
    }
    [Fact]
    public async Task Concurrent_claims_wait_on_namespace_gate_and_leave_one_live_owner()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var observer=await f.OpenConnectionAsync();var a=await Account(observer,ct);var b=await Account(observer,ct);
            var ga=await Cor16EnrollmentSql.SeedGrant(observer,a.Id,a.Stamp,5,ct);var gb=await Cor16EnrollmentSql.SeedGrant(observer,b.Id,b.Stamp,5,ct);
            var first=Candidate(a,ga,new(Settings()));var next=Candidate(b,gb,new(Settings()),hash:"competing-proof");
            var owner=await f.OpenConnectionAsync();var waiter=await f.OpenConnectionAsync();await using var hold=await owner.BeginTransactionAsync(ct);await using var waiting=await waiter.BeginTransactionAsync(ct);
            await Exec(owner,"select cor17_email_gate()",ct,hold);
            var task=f.Observe(DeliveryOutboxRepo.StageInAsync(waiter,waiting,next,ct));await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waiter.ProcessID,owner.ProcessID,task,ct);
            (await DeliveryOutboxRepo.StageInAsync(owner,hold,first,ct)).Result.ShouldBeTrue();await hold.CommitAsync(ct);(await task).Code.ShouldBe("ACCOUNT_ADJUST_DUPLICATE_EMAIL");await waiting.CommitAsync(ct);
            (await Scalar<long>(observer,"select count(*) from account_email_change_requests",ct)).ShouldBe(1);(await Scalar<long>(observer,"select count(*) from delivery_outbox",ct)).ShouldBe(2);
        });
    }
    [Theory,InlineData(false),InlineData(true)]
    public async Task Purge_and_admission_share_gate_and_never_remove_the_live_replacement(bool admissionWins)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var observer=await f.OpenConnectionAsync();var a=await Account(observer,ct);var b=await Account(observer,ct);
            var firstGrant=await Cor16EnrollmentSql.SeedGrant(observer,a.Id,a.Stamp,5,ct);await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var old=Candidate(a,firstGrant,new(Settings()));(await repo.StageAsync(old,ct)).Result.ShouldBeTrue();
            await Exec(observer,"update account_email_change_requests set authorized_until=clock_timestamp()",ct);
            var nextGrant=await Cor16EnrollmentSql.SeedGrant(observer,b.Id,b.Stamp,5,ct);var next=Candidate(b,nextGrant,new(Settings()),hash:"replacement-proof");
            var owner=await f.OpenConnectionAsync();var waiter=await f.OpenConnectionAsync();await using var hold=await owner.BeginTransactionAsync(ct);await using var waiting=await waiter.BeginTransactionAsync(ct);
            await Exec(owner,"select cor17_email_gate()",ct,hold);
            async Task<bool> Stage(NpgsqlConnection c,NpgsqlTransaction tx)=>(await DeliveryOutboxRepo.StageInAsync(c,tx,next,ct)).Result;
            var task=f.Observe(admissionWins?Scalar<bool>(waiter,"select result from purge_expired_account_email_change_requests()",ct,waiting):Stage(waiter,waiting));
            await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waiter.ProcessID,owner.ProcessID,task,ct);
            (admissionWins?await Stage(owner,hold):await Scalar<bool>(owner,"select result from purge_expired_account_email_change_requests()",ct,hold)).ShouldBeTrue();await hold.CommitAsync(ct);(await task).ShouldBeTrue();await waiting.CommitAsync(ct);
            (await Scalar<Guid>(observer,"select account_id from account_email_change_requests",ct)).ShouldBe(b.Id);
            (await Scalar<bool>(observer,$"select state='expired' and ciphertext is null from delivery_outbox where delivery_id='{old.Id}'",ct)).ShouldBeTrue();
            (await Scalar<bool>(observer,$"select state='queued' and ciphertext is not null from delivery_outbox where delivery_id='{next.Id}'",ct)).ShouldBeTrue();
        });
    }
    [Theory,InlineData(false),InlineData(true)]
    public async Task Signup_cannot_claim_a_live_reserved_address_but_can_claim_an_expired_one(bool expired)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,5,ct);await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a,g,new(Settings()));(await repo.StageAsync(d,ct)).Result.ShouldBeTrue();
            if(expired)await Exec(c,"update account_email_change_requests set authorized_until=clock_timestamp()",ct);
            (await Scalar<short>(c,$"select outcome from setup_account_email('{Guid.NewGuid()}','new@example.test','signup-web-key',decode(repeat('01',128),'hex'),decode(repeat('02',64),'hex'),decode(repeat('03',32),'hex'),decode(repeat('04',16),'hex'),0::smallint,'signup-proof',clock_timestamp(),interval '1 day')",ct)).ShouldBe(expired?(short)8000:(short)8040);
            (await Scalar<long>(c,"select count(*) from accounts",ct)).ShouldBe(expired?2:1);
        });
    }
    [Fact]
    public async Task Direct_unique_race_maps_only_registered_email_constraint_to_duplicate()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,5,ct);
            await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a,g,new(Settings()));(await repo.StageAsync(d,ct)).Result.ShouldBeTrue();await Publish(repo,d.Id,ct);
            // A competing writer wins after the function's precheck. The named unique index remains the authority.
            await Exec(c,$"create function claim_email_during_update() returns trigger language plpgsql as $$ begin if new.account_id='{a.Id}' and new.email_address<>old.email_address then insert into accounts(account_id,email_address) values(gen_random_uuid(),new.email_address);end if;return new;end $$;create trigger claim_email_during_update before update on accounts for each row execute function claim_email_during_update()",ct);
            (await Scalar<string>(c,"select code from complete_account_email_change('email-proof')",ct)).ShouldBe("ACCOUNT_ADJUST_DUPLICATE_EMAIL");
            (await Scalar<string>(c,"select email_address from accounts",ct)).ShouldBe(a.Email);(await Scalar<long>(c,"select count(*) from sessions where access_expiration>clock_timestamp()",ct)).ShouldBe(1);
        });
    }    [Fact]
    public async Task Unrelated_unique_violation_remains_dependency_error_and_rolls_back()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,5,ct);await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,Settings());var d=Candidate(a,g,new(Settings()));(await repo.StageAsync(d,ct)).Result.ShouldBeTrue();await Publish(repo,d.Id,ct);
            await Exec(c,"create function unrelated_unique_failure() returns trigger language plpgsql as $$ begin raise exception 'unrelated uniqueness failure' using errcode='23505',constraint='unexpected_email_constraint';end $$;create trigger unrelated_unique_failure before update on accounts for each row execute function unrelated_unique_failure()",ct);
            (await Should.ThrowAsync<PostgresException>(()=>Scalar<bool>(c,"select result from complete_account_email_change('email-proof')",ct))).ConstraintName.ShouldBe("unexpected_email_constraint");
            (await Scalar<string>(c,"select email_address from accounts",ct)).ShouldBe(a.Email);(await Scalar<long>(c,"select count(*) from account_email_change_requests",ct)).ShouldBe(1);
        });
    }

    [Theory]
    [InlineData("https://localhost:5001")] [InlineData("http://localhost:5001")]
    [InlineData("http://localhost:8080")] [InlineData("https://api.example.test")]
    public Task Cor23G_encrypted_email_change_URL_round_trips_and_publication_precedes_actual_proof_consumption(string origin)
        => SqlContractFixture.RunAsync(async(f,ct)=>
        {
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var grant=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,5,ct);
            var settings=Settings();var protector=new DeliveryPayloadProtector(settings);await using var storage=Storage(f);var repo=new DeliveryOutboxRepo(storage,settings);
            string proof=treehammock.Rigging.Security.AccountVerificationTokenUtility.GenerateToken();
            string url=new treehammock.Rigging.Hosting.VerificationLinkBuilder(origin).EmailChange(proof);
            string payload=Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri(url).Query)["payload"].ToString();payload.ShouldBe(proof);
            string hash=treehammock.Rigging.Security.AccountVerificationTokenUtility.HashToken(payload);
            var delivery=Candidate(a,grant,protector,hash:hash,payload:url);(await repo.StageAsync(delivery,ct)).Result.ShouldBeTrue();
            (await Scalar<bool>(c,$"select result from complete_account_email_change('{hash}')",ct)).ShouldBeFalse();
            var job=(await repo.ClaimAsync(ct)).ShouldNotBeNull();job.Delivery.Id.ShouldBe(delivery.Id);protector.Open(job.Delivery).Value.ShouldBe(url);
            await repo.RecordAsync(job,new(DeliverySendState.Accepted,"accepted"),ct);(await repo.PublishAsync(delivery.Id,ct)).ShouldBeTrue();
            (await Scalar<string>(c,"select email_address from accounts",ct)).ShouldBe(a.Email);
            (await Scalar<bool>(c,$"select result from complete_account_email_change('{hash}')",ct)).ShouldBeTrue();
            (await Scalar<string>(c,"select email_address from accounts",ct)).ShouldBe("new@example.test");
        },TestContext.Current.CancellationToken);

}
