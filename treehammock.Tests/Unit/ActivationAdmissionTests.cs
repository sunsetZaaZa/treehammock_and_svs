using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NodaTime;
using NSubstitute;
using Shouldly;
using treehammock.Controllers;
using treehammock.Models.Activation;
using treehammock.Models.Api;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Replay;
using treehammock.RiggingSupport.Status;
using treehammock.Services;
namespace treehammock.Tests.Unit;

public class Cor21ActivationAdmissionTests
{
    [Theory,InlineData(AbuseReasonCodes.DeliveryThrottleExceeded),InlineData(AbuseReasonCodes.FailureCooldownActive),
        InlineData(AbuseReasonCodes.CounterStoreUnavailable),InlineData(AbuseReasonCodes.CounterStoreTimeout)]
    public async Task Delivery_denial_preserves_reason_retry_and_never_stages(string code)
    {
        var h=new ActivationServiceTests.Harness();
        h.Delivery.AdmitWithReasonAsync(Arg.Any<AbuseFeature>(),Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<CancellationToken>())
            .Returns(AbuseDecision.Deny(code,TimeSpan.FromSeconds(37)));
        var result=await h.Service.PlaceActivation(h.Account,h.Stamp,h.Creation(),SystemClock.Instance.GetCurrentInstant());
        result.Result.ShouldBeFalse();result.Code.ShouldBe(code);result.RetryAfter.ShouldBe(TimeSpan.FromSeconds(37));
        await h.Repo.ReceivedWithAnyArgs(1).AdmitCreationAsync(default,default,default!,default,default,default,default!,default!,default,default,default,default!,default!,default);
        await h.Delivery.DidNotReceiveWithAnyArgs().EnqueueAsync(default!,default);
        await h.Smtp.DidNotReceiveWithAnyArgs().Send(default!,default!,default!);
    }
    [Fact]
    public async Task Durable_budget_denial_stops_before_delivery_cache_even_when_cache_brakes_are_disabled()
    {
        var h=new ActivationServiceTests.Harness();
        h.Repo.AdmitCreationAsync(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<long>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<short>(),Arg.Any<short>(),Arg.Any<short>(),Arg.Any<string>(),Arg.Any<ActivationAbusePolicySettings>(),Arg.Any<CancellationToken>())
            .Returns(new ActivationCreationAdmission(false,ActivationService.CreationThrottledCode,RetryAfterSeconds:900));
        var settings=new AbuseControlSettings {Enabled=false};settings.Activation.Enabled=false;
        var service=new ActivationService(h.Repo,h.Smtp,null,Microsoft.Extensions.Logging.Abstractions.NullLogger<ActivationService>.Instance,
            abuseControlSettings:Microsoft.Extensions.Options.Options.Create(settings),httpContextAccessor:h.Context,durableDelivery:h.Delivery);
        var result=await service.PlaceActivation(h.Account,h.Stamp,h.Creation(),SystemClock.Instance.GetCurrentInstant());
        result.Code.ShouldBe(ActivationService.CreationThrottledCode);result.RetryAfter.ShouldBe(TimeSpan.FromMinutes(15));
        await h.Delivery.DidNotReceiveWithAnyArgs().AdmitWithReasonAsync(default,default!,default,default!,default);
        await h.Delivery.DidNotReceiveWithAnyArgs().EnqueueAsync(default!,default);
    }
    [Theory,InlineData(ActivationService.CreationThrottledCode,429),InlineData(ActivationService.PendingCode,429),
        InlineData(AbuseReasonCodes.DeliveryThrottleExceeded,429),InlineData(AbuseReasonCodes.FailureCooldownActive,429),
        InlineData(AbuseReasonCodes.CounterStoreUnavailable,503),InlineData(AbuseReasonCodes.CounterStoreTimeout,503),
        InlineData(ActivationService.EmailDeliveryFailedCode,500),InlineData(ActivationService.CleanupFailedCode,500)]
    public async Task Controller_returns_typed_status_and_retry_without_a_creation_request_id(string code,int status)
    {
        var h=new ActivationServiceTests.Harness();var service=Substitute.For<IActivationService>();
        service.PlaceActivation(h.Account,h.Stamp,Arg.Any<ActivationCreationRequest>(),Arg.Any<Instant>(),Arg.Any<CancellationToken>())
            .Returns(new ActivationCreateResult(false,code,RetryAfter:TimeSpan.FromSeconds(8.2)));
        var controller=new ActivationsController(service) {ControllerContext=new() {HttpContext=h.Context.HttpContext!}};
        var action=await controller.PlaceActivation(h.Creation());
        var response=action.Result.ShouldBeOfType<ObjectResult>();response.StatusCode.ShouldBe(status);
        var envelope=response.Value.ShouldBeOfType<ApiResponse<ActivationCreationResponse>>();envelope.code.ShouldBe(code);
        envelope.data!.retryAfterSeconds.ShouldBe(9);controller.Response.Headers["Retry-After"].ToString().ShouldBe("9");
    }
    [Theory,InlineData(true),InlineData(false)]
    public void Safe_response_recovery_retains_request_identity_and_retry_but_no_proof(bool success)
    {
        var request=Guid.NewGuid();var grant=Guid.NewGuid();
        var body=new ActivationCreationResponse(success?Pass.SUCCESSFUL:Pass.FAILED) {requestId=success?request:null,grantId=grant,grantVersion=1,
            lifecycle=success?"queued":"denied",retryAfterSeconds=success?null:42};
        var stored=AuthenticatedMutationSafeResult.Capture(new ApiOutcome<ActivationCreationResponse>(body,success?202:429,success?ActivationService.CreatedCode:ActivationService.CreationThrottledCode));
        var http=new DefaultHttpContext();var restored=AuthenticatedMutationSafeResult.Restore<ActivationCreationResponse>(stored,http.Response);
        restored.Body.grantId.ShouldBe(grant);restored.Body.requestId.ShouldBe(body.requestId);restored.Body.lifecycle.ShouldBe(body.lifecycle);
        if(!success)http.Response.Headers["Retry-After"].ToString().ShouldBe("42");
        stored.SafeResponse!.ShouldNotContain("proofHash");stored.SafeResponse.ShouldNotContain("admissionId");
    }
    [Fact]
    public void Creation_ip_keys_canonicalize_mapped_ipv4_and_hide_the_address()
    {
        ActivationAbuseCounterKeyFactory.CreationIpFingerprint("::ffff:192.0.2.1").ShouldBe(ActivationAbuseCounterKeyFactory.CreationIpFingerprint("192.0.2.1"));
        ActivationAbuseCounterKeyFactory.CreationIpFingerprint("192.0.2.1").ShouldNotContain("192.0.2.1");
    }
}
