using System.Security.Cryptography;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using treehammock.Controllers;
using treehammock.Services;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging.Abstractions;
using NodaTime;
using Npgsql;
using NSubstitute;
using Shouldly;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Security;
using treehammock.Rigging.Operations;
using treehammock.Tests.SqlContracts.Support;
namespace treehammock.Tests.Integration.Database;

[Trait("Suite","SqlContracts")]
public class Cor18DeleteAuthorityTests
{
    private static IOptions<DeliveryOutboxSettings> Settings()=>Options.Create(new DeliveryOutboxSettings{EncryptionKeys=new(){{1,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}});
    private static SecurityOperationSettings Operations()=>new(){HmacKeys=new(){{1,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}};
    private static async Task Exec(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null){await using var cmd=new NpgsqlCommand(sql,c,tx);await cmd.ExecuteNonQueryAsync(ct);}
    private static async Task<T> Scalar<T>(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null){await using var cmd=new NpgsqlCommand(sql,c,tx);return(T)(await cmd.ExecuteScalarAsync(ct))!;}
    private static async Task<(Guid Id,Guid Stamp)> Account(NpgsqlConnection c,CancellationToken ct)
    {Guid id=Guid.NewGuid(),stamp=Guid.NewGuid();await Exec(c,$"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{id}','{id:N}@example.test',1,'{stamp}')",ct);return(id,stamp);}
    private static string Admit((Guid Id,Guid Stamp) a,Guid request,Cor16EnrollmentSql.Grant g,string hash="delete-proof")
        =>$"select result,code from cor18_admit_delete('{a.Id}','{a.Stamp}','{request}','{hash}',clock_timestamp()+interval '20 minutes',interval '15 minutes',interval '1 day',8::smallint,'{g.Session}','{g.Token}','{g.Target}')";
    private static string Complete((Guid Id,Guid Stamp) a,Guid request,Cor16EnrollmentSql.Grant g,string? phrase=null,bool satisfied=true)
        =>$"select result from commit_account_delete_finalize('{a.Id}','{a.Stamp}','delete-proof',{(satisfied?"true":"false")},5::smallint,interval '30 minutes','{request}',{(phrase is null?"null::text":"'"+phrase+"'")},'{g.Session}')";
    private static async Task<(Guid Request,Cor16EnrollmentSql.Grant Grant,ProtectedDelivery Job)> Stage(NpgsqlConnection c,(Guid Id,Guid Stamp) a,DeliveryOutboxRepo repo,CancellationToken ct,string? phrase=null,string hash="delete-proof",string payload="opaque-proof",DeliveryPayloadProtector? protector=null)
    {
        var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,6,ct);Guid id=Guid.NewGuid();
        (await Scalar<bool>(c,Admit(a,id,g,hash),ct)).ShouldBeTrue();
        DateTime expires=await Scalar<DateTime>(c,"select expires_at from account_delete_admissions",ct);
        var d=(protector??new DeliveryPayloadProtector(Settings())).Protect(new(a.Id,a.Stamp,"delete",hash,Instant.FromDateTimeUtc(expires),new{admissionId=id,passPhraseHash=phrase},new("delete","email",a.Id.ToString("N")+"@example.test","test",payload)));
        (await repo.StageAsync(d,ct)).Result.ShouldBeTrue();return(id,g,d);
    }
    private static async Task Publish(DeliveryOutboxRepo repo,Guid id,CancellationToken ct)
    {var job=(await repo.ClaimAsync(ct)).ShouldNotBeNull();job.Delivery.Id.ShouldBe(id);await repo.RecordAsync(job,new(DeliverySendState.Accepted,"accepted"),ct);(await repo.PublishAsync(id,ct)).ShouldBeTrue();}
    private static AccountRepo Repo(Cor09RefreshHttpTests.FixtureStorage s,IUserSecretHasher hasher)=>new(new(Settings()),s,Options.Create(new JWTSettings()),NullLogger<AccountRepo>.Instance,hasher);

    private static TestServer BrowserHost(Cor09RefreshHttpTests.FixtureStorage storage, DeliveryOutboxRepo outbox)
        => new(new WebHostBuilder().ConfigureServices(services => {
            services.AddLogging();services.AddRouting();services.AddControllers().AddApplicationPart(typeof(AccountDeleteController).Assembly);
            services.AddSingleton(storage.SecurityOperations);
            services.AddSingleton<IOptions<treehammock.Rigging.Config.RequestBodySettings>>(Options.Create(new RequestBodySettings()));
            services.AddSingleton<treehammock.Rigging.Hosting.RequestBodyPolicy>();
            var repo = Repo(storage, Substitute.For<IUserSecretHasher>());
            services.AddSingleton<IAccountRepo>(repo);
            services.AddSingleton<IAccountService>(new AccountService(
                new DurableDeliveryService(outbox, new DeliveryPayloadProtector(Settings()), Substitute.For<IDeliveryAbuseThrottleService>()),
                repo,Options.Create(new LoginSettings()),Options.Create(new RegistrationSettings {PublicOrigin="http://localhost.test"}),
                Options.Create(new EmailSubjectSettings()),Substitute.For<IUserSecretHasher>(),
                abuseControlSettings:Options.Create(new AbuseControlSettings {Enabled=false})));
            services.AddSingleton(Substitute.For<ISessionRepo>());services.AddSingleton(Substitute.For<IActiveUserCacheService>());
            services.AddSingleton(Substitute.For<ITwoFactorSessionService>());services.AddSingleton(Substitute.For<IJsonWebTokenUtility>());
            services.AddSingleton(Substitute.For<ITwoFactorAuthenticateService>());services.AddSingleton(Substitute.For<IAbuseCounterStore>());
            services.AddSingleton(Substitute.For<ILoginAbuseCounterKeyFactory>());
            services.AddSingleton<IOptions<RegistrationSettings>>(Options.Create(new RegistrationSettings()));
            services.AddSingleton<IOptions<JWTSettings>>(Options.Create(new JWTSettings()));
            services.AddSingleton<IOptions<LoginSettings>>(Options.Create(new LoginSettings()));
            services.AddSingleton<IOptions<AbuseControlSettings>>(Options.Create(new AbuseControlSettings()));
        }).Configure(app => {
            app.UseRouting();app.UseMiddleware<treehammock.Rigging.Hosting.RequestBodyMiddleware>();
            app.UseMiddleware<SecurityOperationMiddleware>();app.UseEndpoints(e=>e.MapControllers());
        }));

    [Theory]
    [InlineData("live")][InlineData("unpublished")][InlineData("stale")]
    public Task Browser_confirmation_requires_retained_keys_and_current_published_proof_and_never_deletes(string state)
        => SqlContractFixture.RunAsync(async(f,ct) => {
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);
            await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());
            var outbox=new DeliveryOutboxRepo(storage,Settings());const string proof="cor25-mailbox-proof";
            var pending=await Stage(c,a,outbox,ct,hash:SecretHashUtility.HashLookupToken(proof),payload:proof);
            if(state!="unpublished")await Publish(outbox,pending.Job.Id,ct);
            if(state=="stale")await Exec(c,"update delete_standby set authorized_until=clock_timestamp()",ct);
            using var host=BrowserHost(storage,outbox);using var client=host.CreateClient();
            string path="/account/wipeout/verify?payload="+Uri.EscapeDataString(proof);
            using var page=await client.GetAsync(path,ct);page.StatusCode.ShouldBe(HttpStatusCode.OK);
            string html=await page.Content.ReadAsStringAsync(ct);
            page.Headers.CacheControl!.NoStore.ShouldBeTrue();page.Headers.GetValues("Referrer-Policy").Single().ShouldBe("no-referrer");
            page.Headers.GetValues("Content-Security-Policy").Single().ShouldContain("form-action 'self'");
            (await Scalar<bool>(c,"select verified from delete_standby",ct)).ShouldBeFalse();
            var fields=Regex.Matches(html,"name=\"([^\"]+)\" value=\"([^\"]*)\"")
                .ToDictionary(m=>m.Groups[1].Value,m=>WebUtility.HtmlDecode(m.Groups[2].Value));
            using(var noKeys=new FormUrlEncodedContent(new Dictionary<string,string>{{"deleteToken",proof}}))
            using(var denied=await client.PostAsync("/account/wipeout/verify",noKeys,ct)) {
                denied.StatusCode.ShouldBe(state=="unpublished"?HttpStatusCode.Conflict:HttpStatusCode.PreconditionRequired);
            }
            for(int i=0;i<2;i++) {
                using var form=new FormUrlEncodedContent(fields);using var response=await client.PostAsync("/account/wipeout/verify",form,ct);
                if(state=="live")response.StatusCode.ShouldBe(i==0?HttpStatusCode.OK:HttpStatusCode.Conflict);
                else ((int)response.StatusCode).ShouldBeInRange(400,499);
            }
            (await Scalar<bool>(c,"select verified from delete_standby",ct)).ShouldBe(state=="live");
            (await Scalar<long>(c,"select count(*) from accounts",ct)).ShouldBe(1);
            (await Scalar<long>(c,"select count(*) from account_delete_events where event_type='COMPLETED'",ct)).ShouldBe(0);
            if(state=="live") {
                var receipt=await storage.SecurityOperations.ReconcileAuthorizedAsync(fields["operationKey"],fields["operationRecovery"],ct);
                receipt.State.ShouldBe(treehammock.DataLayer.Operations.SecurityOperationState.Committed);
            }
        });

    [Theory,InlineData("missing"),InlineData("purpose"),InlineData("target"),InlineData("expired"),InlineData("factor")]
    public async Task Unapproved_requests_create_no_budget_or_destructive_authority(string bad)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);
            if(bad=="factor")await Exec(c,$"insert into two_factor_authentications(account_id,two_factor_index,method,verified,email_address) values('{a.Id}',1,1,true,'{a.Id:N}@example.test')",ct);
            var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,bad=="purpose"?5:6,ct,factorComplete:bad!="factor");
            if(bad=="missing")g=g with{Token=new string('x',64)};if(bad=="target")g=g with{Target=new string('b',64)};
            if(bad=="expired")await Exec(c,"update sensitive_action_grants set expiration=clock_timestamp()",ct);
            (await Scalar<bool>(c,Admit(a,Guid.NewGuid(),g),ct)).ShouldBeFalse();
            (await Scalar<long>(c,"select count(*) from account_delete_budgets",ct)).ShouldBe(0);(await Scalar<long>(c,"select count(*) from account_delete_admissions",ct)).ShouldBe(0);(await Scalar<long>(c,"select count(*) from delete_standby",ct)).ShouldBe(0);
        });
    }
    [Theory,InlineData("cancel"),InlineData("purge"),InlineData("rejected"),InlineData("new-key")]
    public async Task Proof_cleanup_or_provider_failure_cannot_reset_admission_budget(string action)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());var repo=new DeliveryOutboxRepo(storage,Settings());var pending=await Stage(c,a,repo,ct);
            if(action=="cancel")(await Scalar<bool>(c,$"select result from cancel_account_delete_request('{a.Id}','{a.Stamp}','delete-proof')",ct)).ShouldBeTrue();
            if(action=="purge"){await Exec(c,"update delete_standby set authorized_until=clock_timestamp()",ct);await Exec(c,"select * from purge_expired_delete_standby()",ct);}
            if(action=="rejected"){var job=(await repo.ClaimAsync(ct)).ShouldNotBeNull();await repo.RecordAsync(job,new(DeliverySendState.Rejected,"provider-denied"),ct);(await repo.PublishAsync(pending.Job.Id,ct)).ShouldBeFalse();}
            var next=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,6,ct);
            (await Scalar<bool>(c,Admit(a,Guid.NewGuid(),next,"replacement"),ct)).ShouldBeFalse();
            (await Scalar<int>(c,"select requested_count from account_delete_budgets",ct)).ShouldBe(1);
            (await Scalar<bool>(c,$"select consumed_on is null from sensitive_action_grants where token_hash='{next.Token}'",ct)).ShouldBeTrue();
        });
    }
    [Fact]
    public async Task Fixed_window_is_anchored_and_expiry_releases_count_without_cancelling_cooldown()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,6,ct);(await Scalar<bool>(c,Admit(a,Guid.NewGuid(),g),ct)).ShouldBeTrue();
            var start=await Scalar<DateTime>(c,"select window_start from account_delete_budgets",ct);await Exec(c,"update account_delete_budgets set next_request_allowed_at=clock_timestamp()-interval '1 second'",ct);
            g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,6,ct);(await Scalar<bool>(c,Admit(a,Guid.NewGuid(),g,"second"),ct)).ShouldBeTrue();(await Scalar<DateTime>(c,"select window_start from account_delete_budgets",ct)).ShouldBe(start);(await Scalar<int>(c,"select requested_count from account_delete_budgets",ct)).ShouldBe(2);
            await Exec(c,"update account_delete_budgets set window_start=clock_timestamp()-interval '2 days',requested_count=8",ct);g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,6,ct);(await Scalar<bool>(c,Admit(a,Guid.NewGuid(),g,"third"),ct)).ShouldBeFalse();
            await Exec(c,"update account_delete_budgets set next_request_allowed_at=clock_timestamp()-interval '1 second'",ct);(await Scalar<bool>(c,Admit(a,Guid.NewGuid(),g,"third"),ct)).ShouldBeTrue();(await Scalar<int>(c,"select requested_count from account_delete_budgets",ct)).ShouldBe(1);
        });
    }
    [Fact]
    public async Task Concurrent_initial_requests_have_one_admission_and_one_budget_charge()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var observer=await f.OpenConnectionAsync();var a=await Account(observer,ct);var g1=await Cor16EnrollmentSql.SeedGrant(observer,a.Id,a.Stamp,6,ct);var g2=await Cor16EnrollmentSql.SeedGrant(observer,a.Id,a.Stamp,6,ct);
            var owner=await f.OpenConnectionAsync();var waiter=await f.OpenConnectionAsync();await using var hold=await owner.BeginTransactionAsync(ct);await using var waiting=await waiter.BeginTransactionAsync(ct);
            await Exec(owner,$"select cor12_lock_delivery('{a.Id}')",ct,hold);
            var task=f.Observe(Scalar<bool>(waiter,Admit(a,Guid.NewGuid(),g2,"second"),ct,waiting));await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waiter.ProcessID,owner.ProcessID,task,ct);
            (await Scalar<bool>(owner,Admit(a,Guid.NewGuid(),g1),ct,hold)).ShouldBeTrue();await hold.CommitAsync(ct);(await task).ShouldBeFalse();await waiting.CommitAsync(ct);
            (await Scalar<int>(observer,"select requested_count from account_delete_budgets",ct)).ShouldBe(1);(await Scalar<long>(observer,"select count(*) from account_delete_admissions",ct)).ShouldBe(1);
        });
    }
    [Theory,InlineData("stamp"),InlineData("reset"),InlineData("logout-all"),InlineData("email"),InlineData("factor"),InlineData("deadline")]
    public async Task Security_event_denies_old_verified_token_even_under_a_fresh_session(string change)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());var repo=new DeliveryOutboxRepo(storage,Settings());var pending=await Stage(c,a,repo,ct);await Publish(repo,pending.Job.Id,ct);(await Scalar<bool>(c,"select result from verify_account_delete_token('delete-proof')",ct)).ShouldBeTrue();
            if(change=="reset") {
                Guid reset=Guid.NewGuid();await Exec(c,$"select * from create_password_reset_request('{reset}','{a.Id}','email','email','reset-proof',1,'fingerprint','masked',true,false,clock_timestamp()+interval '1 hour',5,null,null,'{a.Stamp}')",ct);
                await Exec(c,Cor13ResetSql.Bootstrap(a.Id.ToString(),reset.ToString()),ct);
                (await Scalar<bool>(c,$"select result from promote_password_reset('{reset}','{a.Id}',decode(repeat('01',128),'hex'),decode(repeat('02',64),'hex'),decode(repeat('03',32),'hex'),decode(repeat('04',16),'hex'),'{Guid.NewGuid()}',clock_timestamp(),'reset-authorization',1::bigint,0::bigint)",ct)).ShouldBeTrue();
            }
            string sql=change switch {"stamp"=>"update accounts set security_stamp=gen_random_uuid()","reset"=>"select true","logout-all"=>$"select * from logout_all_sessions('{a.Id}','{a.Stamp}')","email"=>"update accounts set email_address='rotated@example.test'","factor"=>$"insert into two_factor_authentications(account_id,two_factor_index,method,verified,email_address) values('{a.Id}',1,1,true,'{a.Id:N}@example.test')",_=>"update delete_standby set authorized_until=clock_timestamp()"};await Exec(c,sql,ct);
            Guid stamp=await Scalar<Guid>(c,"select security_stamp from accounts",ct);var fresh=await Cor16EnrollmentSql.SeedGrant(c,a.Id,stamp,6,ct,session:"fresh-family");
            (await Scalar<bool>(c,Complete((a.Id,stamp),pending.Request,fresh),ct)).ShouldBeFalse();(await Scalar<long>(c,"select count(*) from accounts",ct)).ShouldBe(1);(await Scalar<long>(c,"select count(*) from account_delete_events where event_type='COMPLETED'",ct)).ShouldBe(0);(await Scalar<int>(c,"select requested_count from account_delete_budgets",ct)).ShouldBe(1);
        });
    }
    [Theory,InlineData("request"),InlineData("hash")]
    public async Task Snapshot_replacement_fails_CAS_without_deleting_or_charging_wrong_secret(string changed)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());var repo=new DeliveryOutboxRepo(storage,Settings());var pending=await Stage(c,a,repo,ct,"old-hash");await Publish(repo,pending.Job.Id,ct);await Exec(c,"select * from verify_account_delete_token('delete-proof')",ct);
            await Exec(c,changed=="request"?"update delete_standby set request_id=gen_random_uuid()":"update delete_standby set pass_phrase_hash='changed-hash'",ct);
            (await Scalar<bool>(c,Complete(a,pending.Request,pending.Grant,"old-hash"),ct)).ShouldBeFalse();(await Scalar<long>(c,"select count(*) from accounts",ct)).ShouldBe(1);(await Scalar<int>(c,"select failed_finalize_attempts from account_delete_budgets",ct)).ShouldBe(0);
        });
    }
    [Theory,InlineData("account"),InlineData("audit")]
    public async Task Zero_row_delete_or_audit_rolls_back_cascades_and_success(string skip)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());var repo=new DeliveryOutboxRepo(storage,Settings());var pending=await Stage(c,a,repo,ct);await Publish(repo,pending.Job.Id,ct);await Exec(c,"select * from verify_account_delete_token('delete-proof')",ct);
            await Exec(c,skip=="account"?"create function skip_delete() returns trigger language plpgsql as $$ begin return null;end $$;create trigger skip_delete before delete on accounts for each row execute function skip_delete()":"create function skip_delete_audit() returns trigger language plpgsql as $$ begin if new.event_type='COMPLETED' then return null;end if;return new;end $$;create trigger skip_delete_audit before insert on account_delete_events for each row execute function skip_delete_audit()",ct);
            (await Scalar<bool>(c,Complete(a,pending.Request,pending.Grant),ct)).ShouldBeFalse();(await Scalar<long>(c,"select count(*) from accounts",ct)).ShouldBe(1);(await Scalar<long>(c,"select count(*) from sessions",ct)).ShouldBe(1);(await Scalar<long>(c,"select count(*) from delete_standby",ct)).ShouldBe(1);(await Scalar<long>(c,"select count(*) from account_delete_events where event_type='COMPLETED'",ct)).ShouldBe(0);
        });
    }
    [Fact]
    public async Task Wrong_passphrase_lockout_survives_proof_cancel_and_blocks_new_admission()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());var repo=new DeliveryOutboxRepo(storage,Settings());var pending=await Stage(c,a,repo,ct,"argon-hash");await Publish(repo,pending.Job.Id,ct);await Exec(c,"select * from verify_account_delete_token('delete-proof')",ct);
            for(int i=0;i<5;i++)(await Scalar<bool>(c,Complete(a,pending.Request,pending.Grant,"argon-hash",false),ct)).ShouldBeFalse();
            await Exec(c,$"select * from cancel_account_delete_request('{a.Id}','{a.Stamp}','delete-proof');update account_delete_budgets set next_request_allowed_at=clock_timestamp()-interval '1 second'",ct);
            var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,6,ct);(await Scalar<bool>(c,Admit(a,Guid.NewGuid(),g),ct)).ShouldBeFalse();(await Scalar<int>(c,"select failed_finalize_attempts from account_delete_budgets",ct)).ShouldBe(5);(await Scalar<long>(c,"select count(*) from accounts",ct)).ShouldBe(1);
        });
    }
    [Fact]
    public async Task Repository_releases_prepare_connection_before_hash_and_rechecks_stamp_at_commit()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());var delivery=new DeliveryOutboxRepo(storage,Settings());var pending=await Stage(c,a,delivery,ct,"stored-hash");await Publish(delivery,pending.Job.Id,ct);await Exec(c,"select * from verify_account_delete_token('delete-proof')",ct);
            var hasher=Substitute.For<IUserSecretHasher>();hasher.VerifyUserSecretAsync("phrase","stored-hash",Arg.Any<CancellationToken>()).Returns(async _=>{await Exec(c,"update accounts set security_stamp=gen_random_uuid()",ct);return true;});
            var result=(await Repo(storage,hasher).FinalizeAccountDelete(a.Id,a.Stamp,"delete-proof","phrase",5,Period.FromMinutes(30),ct,pending.Grant.Session)).ShouldNotBeNull();result.Result.ShouldBeFalse();(await Scalar<long>(c,"select count(*) from accounts",ct)).ShouldBe(1);(await Scalar<long>(c,"select count(*) from account_delete_events where event_type='COMPLETED'",ct)).ShouldBe(0);
        });
    }
    [Fact]
    public async Task Real_Argon2id_passphrase_verification_deletes_once_and_lost_response_recovers_minimal_receipt()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var ops=Operations();await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,ops);var delivery=new DeliveryOutboxRepo(storage,Settings());var hasher=new Argon2idUserSecretHasher(Options.Create(new LoginSettings()));string encoded=await hasher.HashUserSecretAsync("chosen deletion phrase",ct);
            var pending=await Stage(c,a,delivery,ct,encoded);await Publish(delivery,pending.Job.Id,ct);await Exec(c,"select * from verify_account_delete_token('delete-proof')",ct);
            var context=SecurityOperationRequestContext.Isolated("cor18-finalize");using(SecurityOperationRequestContext.Push(context)) {
                var result=(await Repo(storage,hasher).FinalizeAccountDelete(a.Id,a.Stamp,"delete-proof","chosen deletion phrase",5,Period.FromMinutes(30),ct,pending.Grant.Session)).ShouldNotBeNull();result.Result.ShouldBeTrue();await storage.SecurityOperations.FinishAsync(context,200,false);
            }
            (await Scalar<long>(c,"select count(*) from accounts",ct)).ShouldBe(0);(await Scalar<long>(c,"select count(*) from sessions",ct)).ShouldBe(0);(await Scalar<long>(c,"select count(*) from delete_standby",ct)).ShouldBe(0);(await Scalar<long>(c,"select count(*) from account_delete_budgets",ct)).ShouldBe(0);(await Scalar<long>(c,"select count(*) from delivery_candidates",ct)).ShouldBe(0);
            (await Scalar<long>(c,$"select count(*) from account_delete_events where event_type='COMPLETED' and request_id='{pending.Request}' and credential_stamp='{a.Stamp}'",ct)).ShouldBe(1);
            // Simulated response loss after commit/final receipt; status needs recovery keys, not a deleted login.
            await using var second=new Cor09RefreshHttpTests.FixtureStorage(f,ops);var receipt=await second.SecurityOperations.ReconcileAuthorizedAsync(context.ClientKey!,context.RecoveryKey!,ct);receipt.State.ShouldBe(treehammock.DataLayer.Operations.SecurityOperationState.Committed);receipt.Steps.Single().Code.ShouldBe("ACCOUNT_DELETE_SUCCEEDED");
            await Should.ThrowAsync<treehammock.DataLayer.Operations.SecurityOperationException>(()=>second.SecurityOperations.ReconcileAuthorizedAsync(context.ClientKey!,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),ct));
            (await Scalar<string>(c,"select string_agg(to_jsonb(s)::text,',') from security_operation_steps s",ct)).ShouldNotContain("chosen deletion phrase");
        });
    }
    [Theory,InlineData("budget"),InlineData("admission"),InlineData("standby"),InlineData("grant")]
    public async Task Zero_row_admission_or_staging_has_no_false_success_and_preserves_committed_budget(string skip)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,6,ct);Guid id=Guid.NewGuid();
            string table=skip switch {"budget"=>"account_delete_budgets","admission"=>"account_delete_admissions","grant"=>"sensitive_action_grants",_=>"delete_standby"};
            await Exec(c,$"create function skip_effect() returns trigger language plpgsql as $$ begin return null;end $$;create trigger skip_effect before insert or update on {table} for each row execute function skip_effect()",ct);
            bool admitted=await Scalar<bool>(c,Admit(a,id,g),ct);admitted.ShouldBe(skip=="standby");
            if(admitted){
                DateTime expires=await Scalar<DateTime>(c,"select expires_at from account_delete_admissions",ct);
                var d=new DeliveryPayloadProtector(Settings()).Protect(new(a.Id,a.Stamp,"delete","delete-proof",Instant.FromDateTimeUtc(expires),new{admissionId=id,passPhraseHash=(string?)null},new("delete","email","owner@example.test","test","opaque-proof")));
                await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());(await new DeliveryOutboxRepo(storage,Settings()).StageAsync(d,ct)).Result.ShouldBeFalse();
            }
            (await Scalar<long>(c,"select count(*) from account_delete_budgets",ct)).ShouldBe(skip=="standby"?1:0);(await Scalar<long>(c,"select count(*) from delete_standby",ct)).ShouldBe(0);(await Scalar<long>(c,"select count(*) from delivery_outbox",ct)).ShouldBe(0);
            (await Scalar<bool>(c,$"select consumed_on is not null from sensitive_action_grants where token_hash='{g.Token}'",ct)).ShouldBe(skip=="standby");
        });
    }
    [Fact]
    public async Task Audit_wait_crossing_hard_authority_deadline_rolls_back_account_and_cascades()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var observer=await f.OpenConnectionAsync();var a=await Account(observer,ct);await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());var delivery=new DeliveryOutboxRepo(storage,Settings());var pending=await Stage(observer,a,delivery,ct);await Publish(delivery,pending.Job.Id,ct);await Exec(observer,"select * from verify_account_delete_token('delete-proof')",ct);
            await Exec(observer,"update delete_standby set authorized_until=clock_timestamp()+interval '2 seconds';create function hold_delete_audit() returns trigger language plpgsql as $$ begin if new.event_type='COMPLETED' then perform pg_advisory_xact_lock(548180001);end if;return new;end $$;create trigger hold_delete_audit before insert on account_delete_events for each row execute function hold_delete_audit()",ct);
            var owner=await f.OpenConnectionAsync();var waiter=await f.OpenConnectionAsync();await using var hold=await owner.BeginTransactionAsync(ct);await Exec(owner,"select pg_advisory_xact_lock(548180001)",ct,hold);
            var task=f.Observe(Scalar<bool>(waiter,Complete(a,pending.Request,pending.Grant),ct));await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waiter.ProcessID,owner.ProcessID,task,ct);
            while(!await Scalar<bool>(observer,"select authorized_until<=clock_timestamp() from delete_standby",ct))await Task.Delay(10,ct);
            await hold.CommitAsync(ct);(await task).ShouldBeFalse();(await Scalar<long>(observer,"select count(*) from accounts",ct)).ShouldBe(1);(await Scalar<long>(observer,"select count(*) from sessions",ct)).ShouldBe(1);(await Scalar<long>(observer,"select count(*) from delete_standby",ct)).ShouldBe(1);(await Scalar<long>(observer,"select count(*) from account_delete_events where event_type='COMPLETED'",ct)).ShouldBe(0);
        });
    }
    [Theory,InlineData(false),InlineData(true)]
    public async Task Purge_and_new_staging_serialize_and_keep_the_live_request(bool stageWins)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var observer=await f.OpenConnectionAsync();var a=await Account(observer,ct);await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());var repo=new DeliveryOutboxRepo(storage,Settings());await Stage(observer,a,repo,ct);
            await Exec(observer,"update delete_standby set authorized_until=clock_timestamp();update account_delete_budgets set next_request_allowed_at=clock_timestamp()-interval '1 second'",ct);
            var g=await Cor16EnrollmentSql.SeedGrant(observer,a.Id,a.Stamp,6,ct);Guid request=Guid.NewGuid();(await Scalar<bool>(observer,Admit(a,request,g,"new-proof"),ct)).ShouldBeTrue();
            DateTime expires=await Scalar<DateTime>(observer,"select expires_at from account_delete_admissions",ct);
            var job=new DeliveryPayloadProtector(Settings()).Protect(new(a.Id,a.Stamp,"delete","new-proof",Instant.FromDateTimeUtc(expires),new{admissionId=request,passPhraseHash=(string?)null},new("delete","email","owner@example.test","test","new-proof")));
            var owner=await f.OpenConnectionAsync();var waiter=await f.OpenConnectionAsync();await using var hold=await owner.BeginTransactionAsync(ct);await using var waiting=await waiter.BeginTransactionAsync(ct);await Exec(owner,$"select cor12_lock_delivery('{a.Id}')",ct,hold);
            async Task Run(NpgsqlConnection c,NpgsqlTransaction tx,bool stage){if(stage)(await DeliveryOutboxRepo.StageInAsync(c,tx,job,ct)).Result.ShouldBeTrue();else await Exec(c,"select * from purge_expired_delete_standby()",ct,tx);}
            var task=f.Observe(Run(waiter,waiting,!stageWins));await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waiter.ProcessID,owner.ProcessID,task,ct);await Run(owner,hold,stageWins);await hold.CommitAsync(ct);await task;await waiting.CommitAsync(ct);
            (await Scalar<Guid>(observer,"select request_id from delete_standby",ct)).ShouldBe(request);(await Scalar<int>(observer,"select requested_count from account_delete_budgets",ct)).ShouldBe(2);(await Scalar<bool>(observer,$"select state='queued' and ciphertext is not null from delivery_outbox where delivery_id='{job.Id}'",ct)).ShouldBeTrue();
        });
    }

    [Theory,InlineData(false),InlineData(true)]
    public async Task Production_service_delivery_denial_or_send_rejection_keeps_budget_across_new_operation_keys(bool sendRejected)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());var deliveryRepo=new DeliveryOutboxRepo(storage,Settings());
            var producer=NSubstitute.Substitute.For<IDurableDeliveryService>();
            producer.AdmitAsync(Arg.Any<treehammock.Rigging.Abuse.AbuseFeature>(),"email",a.Id,Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(sendRejected);
            producer.EnqueueAsync(Arg.Any<DeliveryIntent>(),Arg.Any<CancellationToken>()).Returns(call=>deliveryRepo.StageAsync(new DeliveryPayloadProtector(Settings()).Protect(call.ArgAt<DeliveryIntent>(0)),ct));
            var hasher=Substitute.For<IUserSecretHasher>();var service=new treehammock.Services.AccountService(producer,Repo(storage,hasher),Options.Create(new LoginSettings()),Options.Create(new RegistrationSettings { PublicOrigin = "http://localhost.test" }),Options.Create(new EmailSubjectSettings()),hasher);
            for(int i=0;i<2;i++) {
                var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,6,ct);var ctx=SecurityOperationRequestContext.Isolated("cor18-denied-"+i);
                using(SecurityOperationRequestContext.Push(ctx)) {
                    var result=(await service.RequestAccountDelete(a.Id,a.Stamp,null,ct,new(g.Session,g.Token,g.Target,SensitiveActionTargets.AccountDelete(null)))).ShouldNotBeNull();result.Result.ShouldBe(i==0 && sendRejected);await storage.SecurityOperations.FinishAsync(ctx,result.Result?202:429,false);
                }
                if(i==0 && sendRejected){var job=(await deliveryRepo.ClaimAsync(ct)).ShouldNotBeNull();await deliveryRepo.RecordAsync(job,new(DeliverySendState.Rejected,"provider-rejection"),ct);(await deliveryRepo.PublishAsync(job.Delivery.Id,ct)).ShouldBeFalse();}
            }
            (await Scalar<int>(c,"select requested_count from account_delete_budgets",ct)).ShouldBe(1);(await Scalar<long>(c,"select count(*) from accounts",ct)).ShouldBe(1);await hasher.DidNotReceiveWithAnyArgs().HashUserSecretAsync(default!,default);
        });
    }
    [Theory,InlineData(1),InlineData(2)]
    public async Task Email_or_SMS_only_factors_cannot_downgrade_destructive_owner_proof(int method)
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var g=await Cor16EnrollmentSql.SeedGrant(c,a.Id,a.Stamp,6,ct);
            await Exec(c,$"insert into two_factor_authentications(account_id,two_factor_index,method,verified,email_address,phone_number,phone_country_code) values('{a.Id}',1,{method},true,'{a.Id:N}@example.test','5555550101','1')",ct);
            (await Scalar<string>(c,$"select code from cor08_begin_password_proof('{a.Id}','{a.Stamp}','{g.Session}','{Guid.NewGuid()}',6::smallint,repeat('a',64),5,900,30)",ct)).ShouldBe("SENSITIVE_ACTION_FACTOR_UNAVAILABLE");(await Scalar<long>(c,"select count(*) from account_delete_budgets",ct)).ShouldBe(0);
        });
    }

    [Theory]
    [InlineData("https://localhost:5001")] [InlineData("http://localhost:5001")]
    [InlineData("http://localhost:8080")] [InlineData("https://api.example.test")]
    public Task Cor23G_encrypted_delete_URL_verifies_published_proof_without_finalizing_deletion(string origin)
        => SqlContractFixture.RunAsync(async(f,ct)=>
        {
            var c=await f.OpenConnectionAsync();var a=await Account(c,ct);var settings=Settings();var protector=new DeliveryPayloadProtector(settings);
            await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());var repo=new DeliveryOutboxRepo(storage,settings);
            string proof=treehammock.Rigging.Security.AccountVerificationTokenUtility.GenerateToken();
            string url=new treehammock.Rigging.Hosting.VerificationLinkBuilder(origin).Delete(proof);
            string payload=Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri(url).Query)["payload"].ToString();payload.ShouldBe(proof);
            string hash=treehammock.Rigging.Security.SecretHashUtility.HashLookupToken(payload);
            var staged=await Stage(c,a,repo,ct,hash:hash,payload:url,protector:protector);
            var job=(await repo.ClaimAsync(ct)).ShouldNotBeNull();job.Delivery.Id.ShouldBe(staged.Job.Id);protector.Open(job.Delivery).Value.ShouldBe(url);
            await repo.RecordAsync(job,new(DeliverySendState.Accepted,"accepted"),ct);(await repo.PublishAsync(staged.Job.Id,ct)).ShouldBeTrue();
            (await Scalar<bool>(c,$"select result from verify_account_delete_token('{hash}')",ct)).ShouldBeTrue();
            (await Scalar<long>(c,$"select count(*) from accounts where account_id='{a.Id}'",ct)).ShouldBe(1);
            (await Scalar<long>(c,"select count(*) from account_delete_events where event_type='COMPLETED'",ct)).ShouldBe(0);
        },TestContext.Current.CancellationToken);

}
