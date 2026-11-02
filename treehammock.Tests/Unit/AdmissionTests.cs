using Microsoft.Extensions.DependencyInjection;
using treehammock.Rigging.Dependencies;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;
using treehammock.Controllers;
using treehammock.Entities;
using treehammock.Models.Account;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;
public class Cor12AdmissionTests
{
    [Fact]
    public async Task Signup_delivery_denial_precedes_password_work_and_account_mutation()
    {
        var delivery=new CapturingDurableDelivery {Allowed=false};var repo=Substitute.For<IAccountRepo>();var work=Substitute.For<IPasswordWorkService>();
        var admission=Substitute.For<ISignupAdmissionPolicy>();var service=new AccountService(delivery,repo,Options.Create(new LoginSettings()),Options.Create(new RegistrationSettings { PublicOrigin = "http://localhost.test" }),Options.Create(new EmailSubjectSettings()),Substitute.For<IUserSecretHasher>(),passwordWork:work,signupAdmission:admission);
        (await service.SetupUserAccount("reader@example.test",null,"password",Country.USA,SystemClock.Instance.GetCurrentInstant(),AccountSetupAction.EMAIL)).ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING);
        await work.DidNotReceiveWithAnyArgs().HashBytesAsync(default!);await repo.DidNotReceiveWithAnyArgs().SetupAccount(default!,default!,default!,default,default!);delivery.Intents.ShouldBeEmpty();delivery.Admissions.Single().Account.ShouldNotBe(Guid.Empty);
    }
    [Fact]
    public async Task Sms_setup_admission_keeps_the_account_budget_when_destination_and_ip_change()
    {
        var store=Substitute.For<IAbuseCounterStore>();var counts=new Dictionary<string,int>();var accounts=new List<AbuseCounterKey>();
        store.IncrementAsync(Arg.Any<AbuseCounterKey>(),Arg.Any<AbuseCounterLimit>(),Arg.Any<CancellationToken>()).Returns(call=>{
            var key=call.ArgAt<AbuseCounterKey>(0);var limit=call.ArgAt<AbuseCounterLimit>(1);int count=counts.GetValueOrDefault(key.Value)+1;counts[key.Value]=count;
            if(key.Dimension==AbuseCounterDimension.Account)accounts.Add(key);
            return Task.FromResult(new CounterDecision(count<=limit.MaxAttempts,count,limit.MaxAttempts,limit.Window,null,null));
        });
        var context=new DefaultHttpContext();var policy=new DeliveryAbuseThrottleService(store,Options.Create(new AbuseControlSettings {FailureCooldown=new() {Enabled=false},Delivery=new() {MaxSmsDeliveriesPerAccountPerHour=2,MaxSmsDeliveriesPerIpPerHour=100}}),new HttpContextAccessor {HttpContext=context});
        using var storage=new StorageContext(Options.Create(new DatabaseSettings {servers="localhost",database="test",userId="test",password="test"}));
        var durable=new DurableDeliveryService(new DeliveryOutboxRepo(storage,Options.Create(new DeliveryOutboxSettings())),CapturingDurableDelivery.Protector(),policy);
        Guid account=Guid.NewGuid();
        for(int i=0;i<3;i++){context.Connection.RemoteIpAddress=IPAddress.Parse($"192.0.2.{i+1}");(await durable.AdmitAsync(AbuseFeature.Delivery,"sms",account,$"+1555555010{i}",CancellationToken.None)).ShouldBe(i<2);}
        accounts.Count.ShouldBe(3);accounts.Select(x=>x.Value).Distinct().Count().ShouldBe(1);
    }
    [Fact]
    public async Task Setup_delivery_counter_outage_does_not_create_a_candidate()
    {
        var harness=new AccountControllerHarness();var controller=harness.CreateTwoFactorController();harness.SetAuthenticatedSession();
        var store=Substitute.For<IAbuseCounterStore>();store.IncrementAsync(Arg.Any<AbuseCounterKey>(),Arg.Any<AbuseCounterLimit>(),Arg.Any<CancellationToken>()).Returns(new CounterDecision(false,0,2,TimeSpan.FromHours(1),null,AbuseReasonCodes.CounterStoreUnavailable));
        var policy=new DeliveryAbuseThrottleService(store,Options.Create(new AbuseControlSettings {FailureCooldown=new() {Enabled=false}}),new HttpContextAccessor {HttpContext=harness.HttpContext});
        using var storage=new StorageContext(Options.Create(new DatabaseSettings {servers="localhost",database="test",userId="test",password="test"}));
        var durable=new DurableDeliveryService(new DeliveryOutboxRepo(storage,Options.Create(new DeliveryOutboxSettings())),CapturingDurableDelivery.Protector(),policy);
        harness.HttpContext.RequestServices=new ServiceCollection().AddSingleton<IDurableDeliveryService>(durable).AddSingleton(harness.SensitiveActionService).AddSingleton(harness.LoginProofs).BuildServiceProvider();
        await Should.ThrowAsync<DependencyUnavailableException>(()=>controller.SetupTwoFactorMethod(new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.SMS_KEY,"5555550101",1,true)));
        harness.Delivery.Intents.ShouldBeEmpty();
    }
    [Fact]
    public async Task Pending_setup_code_is_bound_to_the_authenticated_account_and_does_not_charge_sql_proof_attempts()
    {
        var harness=new AccountControllerHarness();var controller=harness.CreateTwoFactorController();harness.SetAuthenticatedSession();harness.Delivery.Pending=true;
        var result=await controller.VerifyTwoFactorMethod(new VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.SMS_KEY,"123456") {enrollmentId=Guid.NewGuid(),setupVersion=1});
        AccountControllerHarness.ExtractEnvelope(result,StatusCodes.Status202Accepted);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().VerifyTwoFactorSetup(default,default,default,default!,default,default,default,default,default);
    }
}
