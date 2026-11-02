using NSubstitute;
using Shouldly;
using treehammock.Models.Account;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;
using treehammock.Tests.Infrastructure;
namespace treehammock.Tests.Unit;

public class Cor18DeleteAuthorityTests
{
    [Fact]
    public async Task Stolen_session_alone_cannot_admit_destructive_authority()
    {
        var h=new AccountControllerHarness();var c=h.CreateDeleteController();h.SetAuthenticatedSession();
        AccountControllerHarness.ExtractEnvelope(await c.DeleteAccount(null),428).success.ShouldBeFalse();
        await h.AccountService.DidNotReceiveWithAnyArgs().RequestAccountDelete(default,default,null);
        await h.SensitiveActionService.DidNotReceiveWithAnyArgs().ValidateAsync(default!,default);
    }
    [Theory,InlineData("purpose"),InlineData("target"),InlineData("expired"),InlineData("stamp")]
    public async Task Invalid_fresh_delete_approval_never_reaches_admission(string reason)
    {
        var h=new AccountControllerHarness();var c=h.CreateDeleteController();h.SetAuthenticatedSession();h.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="bad-proof";
        h.SensitiveActionService.ValidateAsync(Arg.Any<SensitiveActionValidationCommand>(),Arg.Any<CancellationToken>()).Returns(new SensitiveActionValidationResult(false,HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATION_FAILED,reason));
        AccountControllerHarness.ExtractEnvelope(await c.DeleteAccount(null),401).success.ShouldBeFalse();
        await h.AccountService.DidNotReceiveWithAnyArgs().RequestAccountDelete(default,default,null);
    }
    [Theory,InlineData(null,"delete:one-time"),InlineData("new deletion secret","delete:passphrase")]
    public async Task Delete_approval_is_bound_to_purpose_and_selected_workflow(string? phrase,string target)
    {
        var h=new AccountControllerHarness();var c=h.CreateDeleteController();var session=h.SetAuthenticatedSession();h.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        h.AccountService.RequestAccountDelete(session.accountId,session.accountSecurityStamp,phrase,Arg.Any<CancellationToken>(),Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>()).Returns(new AccountDeleteCommandResult(true,"ACCOUNT_DELETE_PENDING"));
        AccountControllerHarness.ExtractEnvelope(await c.DeleteAccount(phrase is null?null:new(phrase)),202).success.ShouldBeTrue();
        await h.SensitiveActionService.Received(1).ValidateAsync(Arg.Is<SensitiveActionValidationCommand>(x=>x.Purpose==SensitiveActionPurpose.ACCOUNT_DELETE && x.Target==target && !x.Consume),Arg.Any<CancellationToken>());
    }
    [Theory,InlineData("ACCOUNT_DELETE_AUTHORITY_CHANGED"),InlineData("ACCOUNT_DELETE_CONFLICT")]
    public async Task Invalidated_finalization_has_no_clear_token_instruction(string code)
    {
        var h=new AccountControllerHarness();var c=h.CreateDeleteController();h.SetAuthenticatedSession();
        h.AccountService.FinalizeAccountDelete(Arg.Any<Guid>(),Arg.Any<Guid>(),"proof",Arg.Is<string?>(value=>value==null),Arg.Any<CancellationToken>(),Arg.Any<string>()).Returns(new AccountDeleteCommandResult(false,code));
        AccountControllerHarness.ExtractEnvelope(await c.FinalizeDeleteAccount(new("proof")),409).success.ShouldBeFalse();
        h.HttpContext.Response.Headers.ContainsKey("AppStatus").ShouldBeFalse();
        await h.ActiveUserCacheService.DidNotReceiveWithAnyArgs().RevokeSession(default!,default);
    }
    [Fact]
    public async Task Clear_token_result_identifies_only_the_completed_credential_generation()
    {
        var h=new AccountControllerHarness();var c=h.CreateDeleteController();var session=h.SetAuthenticatedSession();
        h.AccountService.FinalizeAccountDelete(session.accountId,session.accountSecurityStamp,"proof",Arg.Is<string?>(value=>value==null),Arg.Any<CancellationToken>(),Arg.Any<string>()).Returns(new AccountDeleteCommandResult(true,"ACCOUNT_DELETE_SUCCEEDED"));
        var response=AccountControllerHarness.ExtractEnvelope(await c.FinalizeDeleteAccount(new("proof")),200);
        response.data!.completedCredentialStamp.ShouldBe(session.accountSecurityStamp);h.HttpContext.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        await h.AccountService.Received(1).FinalizeAccountDelete(session.accountId,session.accountSecurityStamp,"proof",Arg.Is<string?>(value=>value==null),Arg.Any<CancellationToken>(),Arg.Any<string>());
    }
}
