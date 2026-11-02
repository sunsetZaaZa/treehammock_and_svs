using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Shouldly;
using treehammock.Models.Account;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Status;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;
using treehammock.Tests.Infrastructure;
namespace treehammock.Tests.Unit;

public class Cor17EmailChangeTests
{
    [Fact]
    public async Task Active_session_without_fresh_approval_cannot_request_identity_change()
    {
        var h=new AccountControllerHarness();var controller=h.CreateProfileController();h.SetAuthenticatedSession();
        AccountControllerHarness.ExtractEnvelope(await controller.ModifyAccount(new("new@example.test",null)),428).success.ShouldBeFalse();
        await h.AccountService.DidNotReceiveWithAnyArgs().RequestEmailChange(default,default,default!,default);
        await h.SensitiveActionService.DidNotReceiveWithAnyArgs().ValidateAsync(default!,default);
    }
    [Theory,InlineData("wrong-purpose"),InlineData("wrong-target"),InlineData("expired"),InlineData("stale-stamp")]
    public async Task Invalid_fresh_approval_never_reaches_email_delivery(string reason)
    {
        var h=new AccountControllerHarness();var controller=h.CreateProfileController();h.SetAuthenticatedSession();h.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="invalid-proof";
        h.SensitiveActionService.ValidateAsync(Arg.Any<SensitiveActionValidationCommand>(),Arg.Any<CancellationToken>()).Returns(new SensitiveActionValidationResult(false,HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATION_FAILED,reason));
        AccountControllerHarness.ExtractEnvelope(await controller.ModifyAccount(new("new@example.test",null)),401).success.ShouldBeFalse();
        await h.AccountService.DidNotReceiveWithAnyArgs().RequestEmailChange(default,default,default!,default);
    }
    [Fact]
    public async Task Approval_is_bound_to_normalized_registered_email_target()
    {
        var h=new AccountControllerHarness();var controller=h.CreateProfileController();var session=h.SetAuthenticatedSession();h.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        h.AccountService.RequestEmailChange(session.accountId,session.accountSecurityStamp,"new@example.test",Arg.Any<CancellationToken>(),Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>()).Returns(new AccountAdjustResult(true,"ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING"));
        AccountControllerHarness.ExtractEnvelope(await controller.ModifyAccount(new(" NEW@example.test ",null)),202).success.ShouldBeTrue();
        await h.SensitiveActionService.Received(1).ValidateAsync(Arg.Is<SensitiveActionValidationCommand>(c=>c.Purpose==SensitiveActionPurpose.ACCOUNT_EMAIL_CHANGE && c.Target=="email:new@example.test" && !c.Consume),Arg.Any<CancellationToken>());
        await h.AccountService.Received(1).RequestEmailChange(session.accountId,session.accountSecurityStamp,"new@example.test",Arg.Any<CancellationToken>(),Arg.Is<treehammock.DataLayer.Security.SensitiveActionGrant>(g=>g.CanonicalTarget=="email:new@example.test"));
    }
    [Theory,InlineData("ACCOUNT_ADJUST_CONFLICT"),InlineData("ACCOUNT_ADJUST_AUTHORITY_CHANGED"),InlineData("ACCOUNT_ADJUST_DELIVERY_PENDING")]
    public async Task Explicit_confirmation_reports_authority_conflict_without_success(string code)
    {
        var h=new AccountControllerHarness();var controller=h.CreateProfileController();
        h.AccountService.CompleteEmailChange("proof",Arg.Any<CancellationToken>()).Returns(new AccountAdjustResult(false,code));
        AccountControllerHarness.ExtractEnvelope(await controller.ConfirmEmailChange(new("proof")),409).success.ShouldBeFalse();
        h.HttpContext.Response.Headers["Cache-Control"].ToString().ShouldBe("no-store");h.HttpContext.Response.Headers["Referrer-Policy"].ToString().ShouldBe("no-referrer");
    }
    [Theory,InlineData("scanner-token"),InlineData("\"><script>alert(1)</script>")]
    public async Task Repeated_GET_only_renders_an_encoded_manual_confirmation_form(string token)
    {
        var h=new AccountControllerHarness();var controller=h.CreateProfileController();
        for(int i=0;i<3;i++) {
            var page=controller.VerifyEmailChange(token);page.StatusCode.ShouldBe(200);page.ContentType.ShouldBe("text/html; charset=utf-8");
            page.Content!.ShouldContain("method=\"post\"");page.Content.ShouldContain("name=\"verifyToken\"");page.Content.ShouldContain("operationKey");page.Content.ShouldNotContain("<script>");page.Content.ShouldNotContain("onload=");
        }
        h.HttpContext.Response.Headers["Cache-Control"].ToString().ShouldBe("no-store");h.HttpContext.Response.Headers["Referrer-Policy"].ToString().ShouldBe("no-referrer");
        await h.AccountService.DidNotReceiveWithAnyArgs().CompleteEmailChange(default!,default);
        h.AccountRepo.ReceivedCalls().ShouldBeEmpty();h.SensitiveActionService.ReceivedCalls().ShouldBeEmpty();h.Delivery.Intents.ShouldBeEmpty();
    }
    [Theory,InlineData(null),InlineData("")]
    public void Invalid_GET_is_read_only(string? token)
    {
        var h=new AccountControllerHarness();var controller=h.CreateProfileController();controller.VerifyEmailChange(token).StatusCode.ShouldBe(400);
        h.AccountService.ReceivedCalls().ShouldBeEmpty();h.AccountRepo.ReceivedCalls().ShouldBeEmpty();
    }
    [Fact]
    public void GET_and_POST_have_distinct_HTTP_and_payload_contracts()
    {
        var get=typeof(treehammock.Controllers.AccountProfileController).GetMethod("VerifyEmailChange")!;
        var post=typeof(treehammock.Controllers.AccountProfileController).GetMethod("ConfirmEmailChange")!;
        get.GetCustomAttributes(typeof(HttpGetAttribute),true).ShouldNotBeEmpty();post.GetCustomAttributes(typeof(HttpPostAttribute),true).ShouldNotBeEmpty();
        post.GetParameters().Single().ParameterType.ShouldBe(typeof(AccountEmailChangeVerifyRequest));
    }
}
