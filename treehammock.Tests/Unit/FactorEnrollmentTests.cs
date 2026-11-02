using System.Text.Json;
using Microsoft.AspNetCore.Http;
using NodaTime;
using NSubstitute;
using Shouldly;
using treehammock.Models.Authentication;
using treehammock.Models.Account;
using treehammock.Models.Api;
using treehammock.Repos;
using treehammock.Services;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;
namespace treehammock.Tests.Unit;

public class Cor16FactorEnrollmentTests
{
    private static AccountViewResult AccountEmail()=>new(true,"ACCOUNT_VIEW_FOUND",new AccountProfile {emailAddress="reader@example.test",username="reader",createdOn=SystemClock.Instance.GetCurrentInstant(),verifyStatus=VerificationStatus.SUCCESSFUL,country=Country.NONE,features=FeatureSet.basic,twoFactorEnabled=false});
    [Theory,InlineData(TwoFactorAuthMethod.EMAIL),InlineData(TwoFactorAuthMethod.SMS_KEY)]
    public async Task Active_session_alone_cannot_stage_destination_enrollment(TwoFactorAuthMethod method)
    {
        var h=new AccountControllerHarness();var controller=h.CreateTwoFactorController();h.SetAuthenticatedSession();
        var result=await controller.SetupTwoFactorMethod(new(method,method==TwoFactorAuthMethod.EMAIL?"reader@example.test":"5555550101",method==TwoFactorAuthMethod.EMAIL?null:(short)1,true));
        AccountControllerHarness.ExtractEnvelope(result,428).success.ShouldBeFalse();
        h.Delivery.Intents.ShouldBeEmpty();h.Delivery.Admissions.ShouldBeEmpty();
        await h.SensitiveActionService.DidNotReceiveWithAnyArgs().ValidateAsync(default!,default);
    }
    [Theory,InlineData(TwoFactorAuthMethod.EMAIL),InlineData(TwoFactorAuthMethod.SMS_KEY)]
    public async Task Fresh_grant_is_bound_to_method_destination_and_pending_predecessor(TwoFactorAuthMethod method)
    {
        var h=new AccountControllerHarness();var controller=h.CreateTwoFactorController();var session=h.SetAuthenticatedSession();
        h.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        h.AccountRepo.ViewAccount(session.accountId,session.accountSecurityStamp,Arg.Any<CancellationToken>()).Returns(AccountEmail());
        Guid expected=Guid.NewGuid();var request=new SetupLayeredAuthenticateMethodRequest(method,method==TwoFactorAuthMethod.EMAIL?"READER@example.test":"5555550101",method==TwoFactorAuthMethod.EMAIL?null:(short)1,true){expectedEnrollmentId=expected,expectedVersion=7};
        var result=await controller.SetupTwoFactorMethod(request);var response=AccountControllerHarness.ExtractEnvelope(result,202);
        response.data!.enrollmentId.ShouldNotBeNull();response.data.setupVersion.ShouldNotBeNull();
        var purpose=method==TwoFactorAuthMethod.EMAIL?SensitiveActionPurpose.TWO_FACTOR_EMAIL_ENROLL:SensitiveActionPurpose.TWO_FACTOR_SMS_ENROLL;
        await h.SensitiveActionService.Received(1).ValidateAsync(Arg.Is<SensitiveActionValidationCommand>(c=>!c.Consume && c.Purpose==purpose && c.Target==SensitiveActionTargets.DeliverySetup(method,request.contact,request.countryCode,true,expected,7)),Arg.Any<CancellationToken>());
        var metadata=JsonSerializer.SerializeToElement(h.Delivery.Intents.Single().Metadata);
        metadata.GetProperty("expectedEnrollmentId").GetGuid().ShouldBe(expected);metadata.GetProperty("expectedVersion").GetInt64().ShouldBe(7);
        metadata.GetProperty("grantToken").GetString().ShouldBe("test-token-hash");
        h.Delivery.Intents.Single().AccountStamp.ShouldBe(session.accountSecurityStamp);
    }
    [Theory,InlineData("wrong-purpose"),InlineData("wrong-target"),InlineData("expired"),InlineData("stale-stamp")]
    public async Task Rejected_fresh_proof_has_no_delivery_side_effects(string denial)
    {
        var h=new AccountControllerHarness();var controller=h.CreateTwoFactorController();h.SetAuthenticatedSession();
        h.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="rejected-proof";
        h.SensitiveActionService.ValidateAsync(Arg.Any<SensitiveActionValidationCommand>(),Arg.Any<CancellationToken>())
            .Returns(new SensitiveActionValidationResult(false,HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATION_FAILED,denial));
        AccountControllerHarness.ExtractEnvelope(await controller.SetupTwoFactorMethod(new(TwoFactorAuthMethod.SMS_KEY,"5555550101",1,true)),401).success.ShouldBeFalse();
        h.Delivery.Intents.ShouldBeEmpty();h.Delivery.Admissions.ShouldBeEmpty();
    }
    [Theory,InlineData("TWO_FACTOR_SETUP_CONFLICT"),InlineData("TWO_FACTOR_SETUP_DELIVERY_PENDING"),InlineData("TWO_FACTOR_SETUP_DUPLICATE")]
    public async Task Domain_conflict_cannot_return_a_successful_pending_response(string code)
    {
        var h=new AccountControllerHarness();var controller=h.CreateTwoFactorController();h.SetAuthenticatedSession();h.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        h.Delivery.Result=new(false,code);
        var response=AccountControllerHarness.ExtractEnvelope(await controller.SetupTwoFactorMethod(new(TwoFactorAuthMethod.SMS_KEY,"5555550101",1,true)),409);
        response.data!.status.ShouldBeFalse();response.data.enrollmentId.ShouldBeNull();response.data.setupVersion.ShouldBeNull();
    }
    [Fact]
    public async Task Verification_passes_exact_request_version_and_current_family_to_authority()
    {
        var h=new AccountControllerHarness();var controller=h.CreateTwoFactorController();var session=h.SetAuthenticatedSession();Guid id=Guid.NewGuid();
        h.AccountRepo.VerifyTwoFactorSetup(session.accountId,session.accountSecurityStamp,TwoFactorAuthMethod.SMS_KEY,Arg.Any<string>(),Arg.Any<short>(),Arg.Any<Instant>(),id,9,session.familyId,Arg.Any<CancellationToken>())
            .Returns(new TwoFactorSetupVerificationCommandResult(true,"TWO_FACTOR_SETUP_VERIFIED",0,null));
        AccountControllerHarness.ExtractEnvelope(await controller.VerifyTwoFactorMethod(new(TwoFactorAuthMethod.SMS_KEY,"123456"){enrollmentId=id,setupVersion=9}),200).success.ShouldBeTrue();
        await h.AccountRepo.Received(1).VerifyTwoFactorSetup(session.accountId,session.accountSecurityStamp,TwoFactorAuthMethod.SMS_KEY,Arg.Any<string>(),Arg.Any<short>(),Arg.Any<Instant>(),id,9,session.familyId,Arg.Any<CancellationToken>());
    }
    [Theory,InlineData("TWO_FACTOR_SETUP_AUTHORITY_CHANGED"),InlineData("TWO_FACTOR_SETUP_CONFLICT"),InlineData("TWO_FACTOR_SETUP_DELIVERY_PENDING")]
    public async Task Changed_or_unpublished_authority_cannot_report_verified(string code)
    {
        var h=new AccountControllerHarness();var controller=h.CreateTwoFactorController();var session=h.SetAuthenticatedSession();Guid id=Guid.NewGuid();
        h.AccountRepo.VerifyTwoFactorSetup(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<TwoFactorAuthMethod>(),Arg.Any<string>(),Arg.Any<short>(),Arg.Any<Instant>(),Arg.Any<Guid>(),Arg.Any<long>(),Arg.Any<Guid>(),Arg.Any<CancellationToken>())
            .Returns(new TwoFactorSetupVerificationCommandResult(false,code,0,null));
        AccountControllerHarness.ExtractEnvelope(await controller.VerifyTwoFactorMethod(new(TwoFactorAuthMethod.SMS_KEY,"123456"){enrollmentId=id,setupVersion=1}),409).success.ShouldBeFalse();
    }
    [Theory,InlineData(0),InlineData(-1),InlineData(9007199254740992L)]
    public async Task Verification_rejects_missing_or_out_of_range_versions_before_SQL(long version)
    {
        var h=new AccountControllerHarness();var controller=h.CreateTwoFactorController();h.SetAuthenticatedSession();
        AccountControllerHarness.ExtractEnvelope(await controller.VerifyTwoFactorMethod(new(TwoFactorAuthMethod.SMS_KEY,"123456"){enrollmentId=Guid.NewGuid(),setupVersion=version}),400).success.ShouldBeFalse();
        await h.AccountRepo.DidNotReceiveWithAnyArgs().VerifyTwoFactorSetup(default,default,default,default!,default,default,default,default,default,default);
    }
    [Fact]
    public void Enrollment_target_changes_with_destination_method_required_flag_and_predecessor()
    {
        var method=TwoFactorAuthMethod.SMS_KEY;string baseline=SensitiveActionTargets.DeliverySetup(method,"5555550101",1,true);
        SensitiveActionTargets.DeliverySetup(method,"5555550102",1,true).ShouldNotBe(baseline);
        SensitiveActionTargets.DeliverySetup(method,"5555550101",44,true).ShouldNotBe(baseline);
        SensitiveActionTargets.DeliverySetup(method,"5555550101",1,false).ShouldNotBe(baseline);
        SensitiveActionTargets.DeliverySetup(method,"5555550101",1,true,Guid.NewGuid(),1).ShouldNotBe(baseline);
    }
}
