using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NodaTime.Serialization.JsonNet;
using Npgsql;
using NSubstitute;
using Shouldly;
using treehammock.Controllers;
using treehammock.DataLayer.Cache;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Replay;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;
using treehammock.Tests.SqlContracts.Support;
namespace treehammock.Tests.Integration.Database;

// Real SQL budgets/authority/staging and routed MVC/service/outbox. Issuer membership and
// authenticated context are owned fixture substitutes; cache/provider/transport qualification is separate.
[Trait("Suite","SqlContracts")]
public class Cor21ActivationCreationTests
{
    private sealed record Subject(Guid Account,Guid Stamp,Guid Family,Guid Grant,string Session)
    { public string Email=>$"{Account:N}@example.test";public string Hash=>new string('a',64); }
    private static async Task Exec(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null)
    {await using var command=new NpgsqlCommand(sql,c,tx);await command.ExecuteNonQueryAsync(ct);}
    private static async Task<T> Scalar<T>(NpgsqlConnection c,string sql,CancellationToken ct,NpgsqlTransaction? tx=null)
    {await using var command=new NpgsqlCommand(sql,c,tx);return (T)(await command.ExecuteScalarAsync(ct))!;}
    private static string Issue(Subject a)=>$"select result from cor19_issue_grant('{a.Grant}','{a.Account}','{a.Stamp}','treehammock-v1',2::smallint,1::smallint,0::smallint,null,clock_timestamp()+interval '2 days',1,clock_timestamp()+interval '1 hour','reviewed','redemption',array[]::text[])";
    private static async Task<Subject> Seed(NpgsqlConnection c,CancellationToken ct)
    {
        var a=new Subject(Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid().ToString("N"));
        await Exec(c,"create or replace function cor19_is_issuer(p_actor name) returns boolean language plpgsql stable as $$ begin return p_actor=current_user::name;end $$",ct);
        await Exec(c,$"insert into accounts(account_id,email_address,verify_status,security_stamp) values('{a.Account}','{a.Email}',1,'{a.Stamp}');insert into sessions(access_token_hash,account_id,session_id,account_security_stamp,created_on,access_expiration,session_expiration) values('{a.Session}','{a.Account}','{a.Family}','{a.Stamp}',clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours')",ct);
        (await Scalar<bool>(c,Issue(a),ct)).ShouldBeTrue();return a;
    }
    private static string Admit(Subject a,string column="result",string? ip=null,int accountMax=5,int ipMax=50)=>
        $"select {column} from cor21_admit_creation('{a.Account}','{a.Stamp}','{a.Session}','{a.Family}','{a.Grant}',1,'{a.Hash}','{a.Email}',2::smallint,1::smallint,0::smallint,'{ip??new string('a',32)}',{accountMax},5,{ipMax},900,60)";
    private static string Stage(Subject a,Guid ticket,Guid request)=>$"select result from cor19_stage_activation('{request}','{a.Account}','{a.Stamp}','{a.Session}','{a.Family}','{a.Grant}',1,'{a.Hash}',clock_timestamp()+interval '10 minutes','{a.Email}',2::smallint,1::smallint,0::smallint,'{ticket}')";
    private static Task Cooldown(NpgsqlConnection c,Subject a,CancellationToken ct)=>Exec(c,$"update activation_creation_budgets set next_request_at=clock_timestamp() where budget_key='a:{a.Account}'",ct);
    [Fact]
    public Task Denied_delivery_attempts_and_varied_ip_cannot_create_unbounded_history()=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        for(int i=0;i<5;i++) { (await Scalar<bool>(c,Admit(a),ct)).ShouldBeTrue();await Cooldown(c,a,ct); }
        for(int i=0;i<20;i++) { (await Scalar<string>(c,Admit(a,"code",i.ToString("x32")),ct)).ShouldBe(ActivationService.CreationThrottledCode); }
        (await Scalar<long>(c,"select count(*) from activation_creation_admissions",ct)).ShouldBe(1);
        (await Scalar<long>(c,"select count(*) from activation_creation_budgets",ct)).ShouldBe(3);
        (await Scalar<int>(c,$"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'",ct)).ShouldBe(5);
        (await Scalar<long>(c,"select count(*) from grant_activation_requests",ct)).ShouldBe(0);
        (await Scalar<long>(c,"select count(*) from delivery_candidates",ct)).ShouldBe(0);
        (await Scalar<long>(c,"select count(*) from delivery_outbox",ct)).ShouldBe(0);
        (await Scalar<string>(c,"select state from entitlement_grants",ct)).ShouldBe("approved");
        (await Scalar<int>(c,Admit(a,"retry_after_seconds"),ct)).ShouldBeGreaterThan(0);
    });
    [Fact]
    public Task Concurrent_first_requests_on_independent_connections_charge_once()=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var observer=await f.OpenConnectionAsync();var a=await Seed(observer,ct);var owner=await f.OpenConnectionAsync();var waiter=await f.OpenConnectionAsync();
        await using var tx=await owner.BeginTransactionAsync(ct);(await Scalar<bool>(owner,Admit(a),ct,tx)).ShouldBeTrue();
        var pending=f.Observe(Scalar<string>(waiter,Admit(a,"code"),ct));await SqlInterleavingBarrier.WaitForBlockedAsync(observer,waiter.ProcessID,owner.ProcessID,pending,ct);
        await tx.CommitAsync(ct);(await pending).ShouldBe(ActivationService.CreationThrottledCode);
        (await Scalar<int>(observer,$"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'",ct)).ShouldBe(1);
        (await Scalar<long>(observer,"select count(*) from activation_creation_admissions",ct)).ShouldBe(1);
    });
    [Fact]
    public Task Shared_ip_budget_limits_multiple_accounts_without_resetting_on_success()=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);var b=await Seed(c,ct);
        (await Scalar<bool>(c,Admit(a,ipMax:1),ct)).ShouldBeTrue();(await Scalar<string>(c,Admit(b,"code",ipMax:1),ct)).ShouldBe(ActivationService.CreationThrottledCode);
        (await Scalar<long>(c,"select count(*) from activation_creation_admissions",ct)).ShouldBe(1);
        (await Scalar<int>(c,$"select request_count from activation_creation_budgets where budget_key='a:{b.Account}'",ct)).ShouldBe(0);
    });
    [Fact]
    public Task Identifier_limit_uses_registered_email_and_different_destination_is_not_a_bypass()=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        await Exec(c,$"insert into activation_creation_budgets values('i:'||encode(public.digest('{a.Email}','sha256'),'hex'),clock_timestamp()+interval '15 minutes',5,clock_timestamp())",ct);
        (await Scalar<string>(c,Admit(a,"code"),ct)).ShouldBe(ActivationService.CreationThrottledCode);
        (await Scalar<string>(c,Admit(a,"code").Replace(a.Email,"different@example.test"),ct)).ShouldBe(ActivationService.ApprovalMismatchCode);
        (await Scalar<long>(c,"select count(*) from activation_creation_admissions",ct)).ShouldBe(0);
    });
    [Theory,InlineData("stamp"),InlineData("family"),InlineData("grant"),InlineData("version"),InlineData("email"),InlineData("ip"),InlineData("policy")]
    public Task Invalid_creation_does_not_charge_or_insert(string bad)=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);var sql=Admit(a);
        sql=bad switch {"stamp"=>sql.Replace(a.Stamp.ToString(),Guid.NewGuid().ToString()),"family"=>sql.Replace(a.Family.ToString(),Guid.NewGuid().ToString()),
            "grant"=>sql.Replace(a.Grant.ToString(),Guid.NewGuid().ToString()),"version"=>sql.Replace($"'{a.Grant}',1",$"'{a.Grant}',2"),
            "email"=>sql.Replace(a.Email,"other@example.test"),"ip"=>sql.Replace(new string('a',32),"unhashed-ip"),"policy"=>Admit(a,accountMax:6),_=>sql};
        (await Scalar<bool>(c,sql,ct)).ShouldBeFalse();(await Scalar<long>(c,"select count(*) from activation_creation_budgets",ct)).ShouldBe(0);
        (await Scalar<long>(c,"select count(*) from activation_creation_admissions",ct)).ShouldBe(0);
    });
    [Theory,InlineData("ticket"),InlineData("hash"),InlineData("expired")]
    public Task Staging_requires_exact_live_ticket_and_failed_stage_retains_charge(string bad)=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);var ticket=await Scalar<Guid>(c,Admit(a,"admission_id"),ct);
        var sql=Stage(a,ticket,Guid.NewGuid());if(bad=="ticket")sql=sql.Replace(ticket.ToString(),Guid.NewGuid().ToString());
        if(bad=="hash")sql=sql.Replace(a.Hash,new string('b',64));if(bad=="expired")await Exec(c,"update activation_creation_admissions set expires_at=clock_timestamp()",ct);
        (await Scalar<bool>(c,sql,ct)).ShouldBeFalse();(await Scalar<long>(c,"select count(*) from grant_activation_requests",ct)).ShouldBe(0);
        (await Scalar<bool>(c,"select consumed_at is null from activation_creation_admissions",ct)).ShouldBeTrue();
        (await Scalar<int>(c,$"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'",ct)).ShouldBe(1);
    });
    [Fact]
    public Task Pending_cap_and_unique_grant_reservation_reject_fresh_keys_then_cancel_preserves_budget()=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);var request=Guid.NewGuid();var ticket=await Scalar<Guid>(c,Admit(a,"admission_id"),ct);
        (await Scalar<bool>(c,Stage(a,ticket,request),ct)).ShouldBeTrue();await Cooldown(c,a,ct);
        (await Scalar<string>(c,Admit(a,"code"),ct)).ShouldBe(ActivationService.ConflictCode);
        var second=a with {Grant=Guid.NewGuid()};(await Scalar<bool>(c,Issue(second),ct)).ShouldBeTrue();
        (await Scalar<string>(c,Admit(second,"code"),ct)).ShouldBe(ActivationService.PendingCode);
        (await Scalar<bool>(c,$"select result from cor19_transition_activation('{a.Account}','{a.Stamp}','{a.Session}','{a.Family}','{a.Grant}',1,'{request}',null,'cancel')",ct)).ShouldBeTrue();
        (await Scalar<int>(c,$"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'",ct)).ShouldBe(1);
        (await Scalar<bool>(c,Admit(second),ct)).ShouldBeTrue();
        (await Scalar<long>(c,"select count(*) from activation_creation_admissions",ct)).ShouldBe(1);
    });
    [Theory,InlineData("activation_creation_budgets"),InlineData("activation_creation_admissions")]
    public Task Zero_row_admission_effect_rolls_back_all_charges(string table)=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);
        await Exec(c,$"create function suppress_creation() returns trigger language plpgsql as $$ begin return null;end $$;create trigger suppress_creation before insert on {table} for each row execute function suppress_creation()",ct);
        var error=await Should.ThrowAsync<PostgresException>(async()=>{await Scalar<bool>(c,Admit(a),ct);});error.SqlState.ShouldBe("P2101");
        (await Scalar<long>(c,"select count(*) from activation_creation_budgets",ct)).ShouldBe(0);
        (await Scalar<long>(c,"select count(*) from activation_creation_admissions",ct)).ShouldBe(0);
    });
    [Fact]
    public Task Expired_ticket_purge_does_not_reset_budget_and_exact_window_end_allows_new_charge()=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);(await Scalar<bool>(c,Admit(a),ct)).ShouldBeTrue();
        await Exec(c,"update activation_creation_admissions set expires_at=clock_timestamp();delete from activation_creation_admissions where expires_at<=clock_timestamp()",ct);
        (await Scalar<string>(c,Admit(a,"code"),ct)).ShouldBe(ActivationService.CreationThrottledCode);
        await Exec(c,"update activation_creation_budgets set window_end=clock_timestamp(),next_request_at=clock_timestamp()",ct);
        (await Scalar<bool>(c,Admit(a),ct)).ShouldBeTrue();
        (await Scalar<int>(c,$"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'",ct)).ShouldBe(1);
    });
    private static SecurityOperationSettings Operations()=>new() {HmacKeys=new(){{1,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}};
    private static IOptions<DeliveryOutboxSettings> DeliveryOptions()=>Options.Create(new DeliveryOutboxSettings {EncryptionKeys=new(){{1,Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))}}});
    private static async Task<ProtectedDelivery> Payload(NpgsqlConnection c,Subject a,IOptions<DeliveryOutboxSettings> settings,CancellationToken ct)
    {
        var ticket=await Scalar<Guid>(c,Admit(a,"admission_id"),ct);
        return new DeliveryPayloadProtector(settings).Protect(new(a.Account,a.Stamp,"activation",a.Hash,SystemClock.Instance.GetCurrentInstant()+Duration.FromMinutes(10),
            new {admissionId=ticket,grantId=a.Grant,grantVersion=1,sessionHash=a.Session,familyId=a.Family,emailAddress=a.Email,tier=2,term=1,cadence=0},
            new("activation-code","email",a.Email,"activation","provider-fixture-value")));
    }
    [Theory,InlineData(DeliverySendState.Accepted),InlineData(DeliverySendState.Rejected),InlineData(DeliverySendState.Unknown),InlineData(DeliverySendState.NotSubmitted)]
    public Task Provider_outcomes_do_not_refund_or_multiply_queued_activations(DeliverySendState state)=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);var options=DeliveryOptions();await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());
        var repo=new DeliveryOutboxRepo(storage,options);var payload=await Payload(c,a,options,ct);(await repo.StageAsync(payload,ct)).Result.ShouldBeTrue();
        var job=(await repo.ClaimAsync(ct)).ShouldNotBeNull();await repo.RecordAsync(job,new(state,"fixture"),ct);
        (await repo.PublishAsync(payload.Id,ct)).ShouldBe(state==DeliverySendState.Accepted);
        (await Scalar<long>(c,"select count(*) from grant_activation_requests",ct)).ShouldBe(1);
        (await Scalar<long>(c,"select count(*) from delivery_outbox",ct)).ShouldBe(1);
        (await Scalar<int>(c,$"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'",ct)).ShouldBe(1);
        (await Scalar<bool>(c,Admit(a),ct)).ShouldBeFalse();(await repo.StageAsync(payload,ct)).Result.ShouldBeFalse();
    });

    [Theory][InlineData(false)][InlineData(true)]
    public Task Cor23I_unknown_activation_receipt_preserves_request_budget_and_explicit_cancel_or_expiry_authority(bool expire)=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);var options=DeliveryOptions();await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());
        var repo=new DeliveryOutboxRepo(storage,options);var payload=await Payload(c,a,options,ct);(await repo.StageAsync(payload,ct)).Result.ShouldBeTrue();
        var job=(await repo.ClaimAsync(ct)).ShouldNotBeNull();await repo.RecordAsync(job,new(DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN",Provider:"smtp"),ct);
        (await repo.ClaimAsync(ct)).ShouldBeNull();(await repo.PublishAsync(payload.Id,ct)).ShouldBeFalse();
        (await Scalar<long>(c,"select count(*) from grant_activation_requests",ct)).ShouldBe(1);
        (await Scalar<int>(c,$"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'",ct)).ShouldBe(1);
        (await Scalar<string>(c,$"select state from delivery_attempts where attempt_id='{job.LeaseId}'",ct)).ShouldBe("unknown");
        (await Scalar<bool>(c,$"select ciphertext is not null from delivery_outbox where delivery_id='{payload.Id}'",ct)).ShouldBeTrue();
        if(expire)await Exec(c,$"update delivery_candidates set expires_at=clock_timestamp()-interval '1 second' where delivery_id='{payload.Id}'",ct);
        else (await Scalar<bool>(c,$"select result from cor19_transition_activation('{a.Account}','{a.Stamp}','{a.Session}','{a.Family}','{a.Grant}',1,'{payload.Id}',null,'cancel')",ct)).ShouldBeTrue();
        (await repo.RecordAsync(job,new(DeliverySendState.Accepted,"DELIVERY_ACCEPTED"),ct)).ShouldBeFalse();(await repo.PublishAsync(payload.Id,ct)).ShouldBeFalse();
        (await Scalar<bool>(c,$"select ciphertext is null from delivery_outbox where delivery_id='{payload.Id}'",ct)).ShouldBeTrue();
        (await Scalar<int>(c,$"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'",ct)).ShouldBe(1);
    });
    [Fact]
    public Task Staging_write_conflict_rolls_back_ticket_consumption_without_refunding_prior_charge()=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);var options=DeliveryOptions();var payload=await Payload(c,a,options,ct);
        await Exec(c,"create function suppress_candidate() returns trigger language plpgsql as $$ begin return null;end $$;create trigger suppress_candidate before insert on delivery_candidates for each row execute function suppress_candidate()",ct);
        await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());var repo=new DeliveryOutboxRepo(storage,options);
        await Should.ThrowAsync<Exception>(async()=>{await repo.StageAsync(payload,ct);});
        (await Scalar<long>(c,"select count(*) from grant_activation_requests",ct)).ShouldBe(0);
        (await Scalar<long>(c,"select count(*) from delivery_outbox",ct)).ShouldBe(0);
        (await Scalar<bool>(c,"select consumed_at is null from activation_creation_admissions",ct)).ShouldBeTrue();
        (await Scalar<int>(c,$"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'",ct)).ShouldBe(1);
    });
    private static TestServer Host(Cor09RefreshHttpTests.FixtureStorage storage,Subject a,IDeliveryAbuseThrottleService throttle)
        =>new(new WebHostBuilder().ConfigureServices(services=>
        {
            services.AddLogging();services.AddRouting();services.AddHttpContextAccessor();
            services.AddControllers().AddApplicationPart(typeof(ActivationsController).Assembly).AddNewtonsoftJson(o=>o.SerializerSettings.ConfigureForNodaTime(DateTimeZoneProviders.Tzdb));
            var settings=DeliveryOptions();var delivery=new DurableDeliveryService(new DeliveryOutboxRepo(storage,settings),new DeliveryPayloadProtector(settings),throttle);
            services.AddSingleton<IActivationService>(sp=>new ActivationService(new ActivationRepo(storage,NullLogger<ActivationRepo>.Instance),Substitute.For<ISMTPService>(),
                Options.Create(new EmailSubjectSettings()),NullLogger<ActivationService>.Instance,httpContextAccessor:sp.GetRequiredService<Microsoft.AspNetCore.Http.IHttpContextAccessor>(),durableDelivery:delivery));
            services.AddSingleton<IAuthenticatedMutationIdempotencyService>(NoOpAuthenticatedMutationIdempotencyService.Instance);
        }).Configure(app=>
        {
            app.UseRouting();app.Use(async(context,next)=>
            {
                // Substituted authentication transport; SQL independently validates the seeded current session.
                var now=SystemClock.Instance.GetCurrentInstant();context.Connection.RemoteIpAddress=IPAddress.Parse("192.0.2.1");
                context.Items[AuthContextItems.ActiveSession]=new ActiveSession(a.Account,new byte[32],0,now,Period.FromHours(2),now+Duration.FromHours(1),now+Duration.FromHours(2),null,FeatureSet.basic,accountSecurityStamp:a.Stamp,familyId:a.Family);
                context.Items[AuthContextItems.HashedAccessToken]=a.Session;context.Items[AuthContextItems.WebKey]="fixture";await next();
            });
            app.UseEndpoints(endpoints=>endpoints.MapControllers());
        }));
    private static HttpRequestMessage Request(Subject a)=>new(HttpMethod.Post,"/activations/place")
    {Content=JsonContent.Create(new {version=2,grantId=a.Grant,grantVersion=1,emailAddress=a.Email,featureSet=2,term=1,recycle=0}),Headers={{"Idempotency-Key",Guid.NewGuid().ToString("N")}}};
    [Theory,InlineData(AbuseReasonCodes.DeliveryThrottleExceeded,429),InlineData(AbuseReasonCodes.FailureCooldownActive,429),
        InlineData(AbuseReasonCodes.CounterStoreUnavailable,503),InlineData(AbuseReasonCodes.CounterStoreTimeout,503)]
    public Task Routed_denial_carries_reason_retry_and_second_instance_observes_durable_charge(string reason,int status)=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);var operations=Operations();
        await using var first=new Cor09RefreshHttpTests.FixtureStorage(f,operations);await using var second=new Cor09RefreshHttpTests.FixtureStorage(f,operations);
        var throttle=Substitute.For<IDeliveryAbuseThrottleService>();throttle.ShouldAllowDeliveryAsync(Arg.Any<DeliveryAbuseThrottleRequest>(),Arg.Any<CancellationToken>()).Returns(AbuseDecision.Deny(reason,TimeSpan.FromSeconds(27)));
        using var one=Host(first,a,throttle);using var client=one.CreateClient();using var request=Request(a);using var denied=await client.SendAsync(request,ct);
        ((int)denied.StatusCode).ShouldBe(status);denied.Headers.RetryAfter!.Delta.ShouldBe(TimeSpan.FromSeconds(27));
        using var json=JsonDocument.Parse(await denied.Content.ReadAsStringAsync(ct));json.RootElement.GetProperty("code").GetString().ShouldBe(reason);
        // A cache recovery and a new idempotency key cannot reset the committed account cooldown.
        throttle.ShouldAllowDeliveryAsync(Arg.Any<DeliveryAbuseThrottleRequest>(),Arg.Any<CancellationToken>()).Returns(AbuseDecision.Allow());
        using var two=Host(second,a,throttle);using var other=two.CreateClient();using var retry=Request(a);using var blocked=await other.SendAsync(retry,ct);
        blocked.StatusCode.ShouldBe(HttpStatusCode.TooManyRequests);await throttle.Received(1).ShouldAllowDeliveryAsync(Arg.Any<DeliveryAbuseThrottleRequest>(),Arg.Any<CancellationToken>());
        (await Scalar<long>(c,"select count(*) from delivery_outbox",ct)).ShouldBe(0);(await Scalar<long>(c,"select count(*) from grant_activation_requests",ct)).ShouldBe(0);
        (await Scalar<int>(c,$"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'",ct)).ShouldBe(1);
    });
    [Fact]
    public Task Routed_success_queues_one_job_and_fresh_key_cannot_replace_its_grant()=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);await using var storage=new Cor09RefreshHttpTests.FixtureStorage(f,Operations());
        var throttle=Substitute.For<IDeliveryAbuseThrottleService>();throttle.ShouldAllowDeliveryAsync(Arg.Any<DeliveryAbuseThrottleRequest>(),Arg.Any<CancellationToken>()).Returns(AbuseDecision.Allow());
        using var server=Host(storage,a,throttle);using var client=server.CreateClient();using var request=Request(a);using var accepted=await client.SendAsync(request,ct);
        accepted.StatusCode.ShouldBe(HttpStatusCode.Accepted);using var json=JsonDocument.Parse(await accepted.Content.ReadAsStringAsync(ct));
        var id=json.RootElement.GetProperty("data").GetProperty("requestId").GetGuid();
        (await Scalar<Guid>(c,"select request_id from grant_activation_requests",ct)).ShouldBe(id);
        using var retry=Request(a);using var rejected=await client.SendAsync(retry,ct);rejected.StatusCode.ShouldBe(HttpStatusCode.Conflict);
        (await Scalar<long>(c,"select count(*) from delivery_outbox",ct)).ShouldBe(1);
    });
    [Fact]
    public Task Lost_admission_response_reconciles_on_another_instance_without_a_second_charge()=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);var operations=Operations();
        await using var first=new Cor09RefreshHttpTests.FixtureStorage(f,operations);var repo=new ActivationRepo(first,NullLogger<ActivationRepo>.Instance);
        var context=treehammock.Rigging.Operations.SecurityOperationRequestContext.Isolated("cor21-admission-response-loss");
        using(treehammock.Rigging.Operations.SecurityOperationRequestContext.Push(context))
        {
            (await repo.AdmitCreationAsync(a.Account,a.Stamp,a.Session,a.Family,a.Grant,1,a.Hash,a.Email,2,1,0,new string('a',32),new ActivationAbusePolicySettings(),ct)).Result.ShouldBeTrue();
            await first.SecurityOperations.FinishAsync(context,503,true);
        }
        await using var second=new Cor09RefreshHttpTests.FixtureStorage(f,operations);
        var receipt=await second.SecurityOperations.ReconcileAuthorizedAsync(context.ClientKey!,context.RecoveryKey!,ct);
        receipt.State.ShouldBe(treehammock.DataLayer.Operations.SecurityOperationState.PartiallyCommitted);
        receipt.Steps.Single().Code.ShouldBe("ACTIVATION_CREATION_ADMITTED");
        (await Scalar<string>(c,Admit(a,"code"),ct)).ShouldBe(ActivationService.CreationThrottledCode);
        (await Scalar<int>(c,$"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'",ct)).ShouldBe(1);
        (await Scalar<long>(c,"select count(*) from delivery_outbox",ct)).ShouldBe(0);
    });

    [Fact]
    public Task Expired_pending_request_stops_counting_against_cap_without_erasing_history_or_budget()=>SqlContractFixture.RunAsync(async(f,ct)=>
    {
        var c=await f.OpenConnectionAsync();var a=await Seed(c,ct);var ticket=await Scalar<Guid>(c,Admit(a,"admission_id"),ct);
        (await Scalar<bool>(c,Stage(a,ticket,Guid.NewGuid()),ct)).ShouldBeTrue();await Cooldown(c,a,ct);
        await Exec(c,"update grant_activation_requests set expires_at=clock_timestamp()",ct);
        var second=a with {Grant=Guid.NewGuid()};(await Scalar<bool>(c,Issue(second),ct)).ShouldBeTrue();
        (await Scalar<bool>(c,Admit(second),ct)).ShouldBeTrue();
        (await Scalar<int>(c,$"select request_count from activation_creation_budgets where budget_key='a:{a.Account}'",ct)).ShouldBe(2);
        (await Scalar<long>(c,"select count(*) from grant_activation_requests",ct)).ShouldBe(1);
        (await Scalar<bool>(c,Stage(second,await Scalar<Guid>(c,$"select admission_id from activation_creation_admissions where account_id='{a.Account}'",ct),Guid.NewGuid()),ct)).ShouldBeTrue();
    });

}
