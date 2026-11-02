using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;
using treehammock.DataLayer.Cache;
using treehammock.Models.Activation;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;
namespace treehammock.Tests.Unit;

public class ActivationServiceTests
{
    public sealed class Harness
    {
        public Guid Account = Guid.NewGuid(), Stamp = Guid.NewGuid(), Family = Guid.NewGuid(), Grant = Guid.NewGuid(), Request = Guid.NewGuid();
        public IActivationRepo Repo = Substitute.For<IActivationRepo>();
        public ISMTPService Smtp = Substitute.For<ISMTPService>();
        public IDurableDeliveryService Delivery = Substitute.For<IDurableDeliveryService>();
        public HttpContextAccessor Context = new() { HttpContext = new DefaultHttpContext() };
        public ActivationService Service;
        public Harness()
        {
            var now = SystemClock.Instance.GetCurrentInstant();
            Context.HttpContext!.Items[AuthContextItems.ActiveSession] = treehammock.Tests.Support.EntitlementTestData.Attach(new ActiveSession(Account,new byte[32],0,now,Period.FromHours(2),now+Duration.FromHours(1),now+Duration.FromHours(2),null,FeatureSet.basic,accountSecurityStamp:Stamp,familyId:Family));
            Context.HttpContext.Items[AuthContextItems.HashedAccessToken] = "server-session-hash";
            Delivery.AdmitWithReasonAsync(Arg.Any<treehammock.Rigging.Abuse.AbuseFeature>(),Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(treehammock.Rigging.Abuse.AbuseDecision.Allow());
            Delivery.EnqueueAsync(Arg.Any<DeliveryIntent>(),Arg.Any<CancellationToken>()).Returns(new DeliveryStageResult(true,"DELIVERY_PENDING",Request));
            Repo.TransitionAsync(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<long>(),Arg.Any<Guid>(),Arg.Any<string?>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(new ActivationLifecycleResult(true,ActivationService.VerifiedCode));
            Repo.AdmitCreationAsync(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<long>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<short>(),Arg.Any<short>(),Arg.Any<short>(),Arg.Any<string>(),Arg.Any<treehammock.Rigging.Config.ActivationAbusePolicySettings>(),Arg.Any<CancellationToken>()).Returns(new ActivationCreationAdmission(true,"ACTIVATION_CREATION_ADMITTED",Guid.NewGuid()));
            Service = new(Repo,Smtp,Options.Create(new EmailSubjectSettings()),NullLogger<ActivationService>.Instance,httpContextAccessor:Context,durableDelivery:Delivery);
        }
        public ActivationCreationRequest Creation() => new("owner@example.test",2,DayDuration.MONTHLY,DurationRepeat.NONE) {grantId=Grant,grantVersion=1};
        public ActivationDetailsRequest Verification() => new("owner@example.test","secret-code") {grantId=Grant,grantVersion=1,requestId=Request};
        public ActivationUnSubscribeRequest Revocation() => new("owner@example.test") {grantId=Grant,grantVersion=2,requestId=Request};
    }
    [Theory,InlineData("missing"),InlineData("version"),InlineData("protocol")]
    public async Task Client_descriptors_without_trusted_grant_create_no_job(string bad)
    {
        var h=new Harness();var request=h.Creation();if(bad=="missing")request.grantId=Guid.Empty;if(bad=="version")request.grantVersion=0;if(bad=="protocol")request.version=1;
        var result=await h.Service.PlaceActivation(h.Account,h.Stamp,request,SystemClock.Instance.GetCurrentInstant());
        result.Result.ShouldBeFalse();result.Code.ShouldBe(ActivationService.TrustedGrantRequiredCode);
        await h.Delivery.DidNotReceiveWithAnyArgs().EnqueueAsync(default!,default);
    }
    [Theory,InlineData("family"),InlineData("stamp"),InlineData("account"),InlineData("token")]
    public async Task Placement_requires_current_server_session_lineage(string bad)
    {
        var h=new Harness();if(bad=="family")((ActiveSession)h.Context.HttpContext!.Items[AuthContextItems.ActiveSession]!).familyId=Guid.Empty;
        if(bad=="stamp")h.Stamp=Guid.NewGuid();if(bad=="account")h.Account=Guid.NewGuid();if(bad=="token")h.Context.HttpContext!.Items[AuthContextItems.HashedAccessToken]=null;
        (await h.Service.PlaceActivation(h.Account,h.Stamp,h.Creation(),SystemClock.Instance.GetCurrentInstant())).Code.ShouldBe(ActivationService.SecurityStampMismatchCode);
        await h.Delivery.DidNotReceiveWithAnyArgs().EnqueueAsync(default!,default);
    }
    [Fact]
    public async Task Placement_queues_only_hashed_verifier_and_encrypted_payload_intent()
    {
        var h=new Harness();DeliveryIntent? intent=null;h.Delivery.EnqueueAsync(Arg.Do<DeliveryIntent>(x=>intent=x),Arg.Any<CancellationToken>()).Returns(new DeliveryStageResult(true,"DELIVERY_PENDING",h.Request));
        var result=await h.Service.PlaceActivation(h.Account,h.Stamp,h.Creation(),SystemClock.Instance.GetCurrentInstant());
        result.Result.ShouldBeTrue();result.RequestId.ShouldBe(h.Request);intent.ShouldNotBeNull();intent.Purpose.ShouldBe("activation");intent.ProofHash.ShouldBe(ActivationService.HashCode(intent.Payload.Value));
        System.Text.Json.JsonSerializer.Serialize(intent.Metadata).ShouldNotContain(intent.Payload.Value);
        await h.Smtp.DidNotReceiveWithAnyArgs().Send(default!,default!,default!, token: Arg.Any<CancellationToken>());
    }
    [Fact]
    public async Task Delivery_denial_leaves_no_activation_or_provider_send()
    {
        var h=new Harness();h.Delivery.AdmitWithReasonAsync(Arg.Any<treehammock.Rigging.Abuse.AbuseFeature>(),Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(treehammock.Rigging.Abuse.AbuseDecision.Deny(treehammock.Rigging.Abuse.AbuseReasonCodes.DeliveryThrottleExceeded));
        (await h.Service.PlaceActivation(h.Account,h.Stamp,h.Creation(),SystemClock.Instance.GetCurrentInstant())).Result.ShouldBeFalse();
        await h.Delivery.DidNotReceiveWithAnyArgs().EnqueueAsync(default!,default);await h.Smtp.DidNotReceiveWithAnyArgs().Send(default!,default!,default!, token: Arg.Any<CancellationToken>());
    }
    [Fact]
    public async Task Verification_binds_hash_and_exact_target_to_server_family()
    {
        var h=new Harness();var result=await h.Service.VerifyActivation(h.Account,h.Stamp,h.Verification(),SystemClock.Instance.GetCurrentInstant());
        result.Result.ShouldBeTrue();result.Activation.ShouldBeNull();
        await h.Repo.Received(1).TransitionAsync(h.Account,h.Stamp,"server-session-hash",h.Family,h.Grant,1,h.Request,ActivationService.HashCode("secret-code"),"verify",Arg.Any<CancellationToken>());
    }
    [Fact]
    public async Task Disable_targets_the_active_grant_expected_version()
    {
        var h=new Harness();await h.Service.DisableActivation(h.Account,h.Stamp,h.Revocation(),SystemClock.Instance.GetCurrentInstant());
        await h.Repo.Received(1).TransitionAsync(h.Account,h.Stamp,"server-session-hash",h.Family,h.Grant,2,h.Request,null,"disable",Arg.Any<CancellationToken>());
    }
    [Theory,InlineData(FeatureSet.offsite),InlineData(FeatureSet.solokong),InlineData(FeatureSet.solorawrzilla),InlineData(FeatureSet.bigbrain)]
    public void Capability_catalog_has_no_numeric_tier_inheritance(FeatureSet tier)
    {
        CapabilityCatalog.ForTier(tier).ShouldBeEmpty();new EntitlementResolver().GrantsCapability("premium").ShouldBeFalse();
        EntitlementResolver.GrantRightsEnabled.ShouldBeFalse();
    }
    [Theory,InlineData("verify"),InlineData("disable")]
    public async Task Missing_target_cannot_reach_atomic_mutation(string action)
    {
        var h=new Harness();if(action=="verify"){var q=h.Verification();q.requestId=Guid.Empty;(await h.Service.VerifyActivation(h.Account,h.Stamp,q,SystemClock.Instance.GetCurrentInstant())).Result.ShouldBeFalse();}
        else{var q=h.Revocation();q.grantId=Guid.Empty;(await h.Service.DisableActivation(h.Account,h.Stamp,q,SystemClock.Instance.GetCurrentInstant())).Result.ShouldBeFalse();}
        await h.Repo.DidNotReceiveWithAnyArgs().TransitionAsync(default,default,default!,default,default,default,default,default,default!,default);
    }
    [Fact]
    public async Task Exhausted_verify_budget_denies_before_atomic_transition()
    {
        var h=new Harness();var counters=Substitute.For<treehammock.Rigging.Abuse.IAbuseCounterStore>();
        counters.IncrementAsync(Arg.Any<treehammock.Rigging.Abuse.AbuseCounterKey>(),Arg.Any<treehammock.Rigging.Abuse.AbuseCounterLimit>(),Arg.Any<CancellationToken>()).Returns(new treehammock.Rigging.Abuse.CounterDecision(false,6,5,TimeSpan.FromMinutes(15),TimeSpan.FromMinutes(15),treehammock.Rigging.Abuse.AbuseReasonCodes.CounterLimitExceeded));
        var settings=new AbuseControlSettings{Enabled=true};settings.Activation.Enabled=true;
        var service=new ActivationService(h.Repo,h.Smtp,Options.Create(new EmailSubjectSettings()),NullLogger<ActivationService>.Instance,abuseCounterStore:counters,abuseControlSettings:Options.Create(settings),httpContextAccessor:h.Context,durableDelivery:h.Delivery);
        (await service.VerifyActivation(h.Account,h.Stamp,h.Verification(),SystemClock.Instance.GetCurrentInstant())).Code.ShouldBe(treehammock.Rigging.Abuse.AbuseReasonCodes.ActivationVerifyAttemptsExceeded);
        await h.Repo.DidNotReceiveWithAnyArgs().TransitionAsync(default,default,default!,default,default,default,default,default,default!,default);
    }

}
