using NSubstitute;
using Shouldly;
using treehammock.Rigging.Delivery;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;
using treehammock.Tests.Infrastructure;
namespace treehammock.Tests.Unit;
public sealed class Cor23JLoginCancellationTests
{
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Actual_login_selection_passes_request_abort_to_real_delivery_service_and_keeps_unknown_challenge(bool sms)
    {
        var configuration=sms?TwoFactorAuthConfiguration.SMS:TwoFactorAuthConfiguration.EMAIL;
        var(h,proof,hash)=TwoFactorAuthenticationPromotionTests.Prepare(configuration);proof.ResetToSelectionRequired();proof.progressVersion=1;proof.challengeId=null;h.ProofState.Stored[hash]=proof;
        var controller=h.CreateTwoFactorController();h.HttpContext.Request.Headers["AccessToken"]=TwoFactorAuthenticationPromotionTests.Token;
        using var cancel=new CancellationTokenSource();h.HttpContext.RequestAborted=cancel.Token;
        var mail=Substitute.For<ISMTPService>();var text=Substitute.For<ISmsSender>();CancellationToken seen=default;
        mail.TwoFactorKeyOutboundLetter(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(call=>{seen=call.ArgAt<CancellationToken>(3);cancel.Cancel();return Task.FromResult<bool?>(null);});
        text.SendCode(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(call=>{seen=call.ArgAt<CancellationToken>(2);cancel.Cancel();return Task.FromException<bool>(new DeliveryAcceptanceUnknownException());});
        var service=new TwoFactorAuthenticateService(mail,text,execution:Cor23JDeliveryBudgetTests.Policy());
        h.TwoFactorService.Email(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<Guid?>(),Arg.Any<CancellationToken>()).Returns(call=>service.Email(call.ArgAt<string>(0),call.ArgAt<string>(1),call.ArgAt<Guid?>(2),call.ArgAt<CancellationToken>(3)));
        h.TwoFactorService.SMS(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<Guid?>(),Arg.Any<CancellationToken>()).Returns(call=>service.SMS(call.ArgAt<string>(0),call.ArgAt<string>(1),call.ArgAt<Guid?>(2),call.ArgAt<CancellationToken>(3)));
        var envelope=AccountControllerHarness.ExtractEnvelope(await controller.SelectTwoFactorConfiguration(new(configuration)),503);
        envelope.code.ShouldBe("DELIVERY_ACCEPTANCE_UNKNOWN");seen.CanBeCanceled.ShouldBeTrue();seen.IsCancellationRequested.ShouldBeTrue();
        var current=h.ProofState.Stored[hash];current.challengeId.ShouldNotBeNull();current.challengeCodeHash.ShouldNotBeNull();current.progressVersion.ShouldBe(2);current.challengeResends.ShouldBe((short)1);
        _=h.LoginProofs.DidNotReceiveWithAnyArgs().CancelAsync(default!,default!,default);
    }
}
