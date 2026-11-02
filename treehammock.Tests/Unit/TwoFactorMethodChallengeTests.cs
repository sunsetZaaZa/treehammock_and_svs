using NSubstitute;
using NodaTime;
using Shouldly;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.DataLayer.Cache;
using treehammock.Rigging.Authorization;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

// Public selection/delivery contract replacing tests of the unrouted legacy method.
public class TwoFactorMethodChallengeTests
{
    private static (AccountControllerHarness Harness,treehammock.Controllers.AccountTwoFactorController Controller,string Hash) Prepare(TwoFactorAuthConfiguration configuration=TwoFactorAuthConfiguration.EMAIL)
    {
        var(h,p,hash)=TwoFactorAuthenticationPromotionTests.Prepare(configuration);p.ResetToSelectionRequired();p.progressVersion=1;p.challengeId=null;
        h.ProofState.Stored[hash]=p;var c=h.CreateTwoFactorController();h.HttpContext.Request.Headers["AccessToken"]=TwoFactorAuthenticationPromotionTests.Token;
        return(h,c,hash);
    }
    [Theory]
    [InlineData(TwoFactorAuthConfiguration.EMAIL,TwoFactorAuthMethod.EMAIL)]
    [InlineData(TwoFactorAuthConfiguration.SMS,TwoFactorAuthMethod.SMS_KEY)]
    [InlineData(TwoFactorAuthConfiguration.AUTHENTICATOR_APP,TwoFactorAuthMethod.AUTHENTICATOR_APP)]
    [InlineData(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP,TwoFactorAuthMethod.EMAIL)]
    [InlineData(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP,TwoFactorAuthMethod.SMS_KEY)]
    public async Task Selection_issues_current_challenge_and_exposes_only_safe_lineage(TwoFactorAuthConfiguration configuration,TwoFactorAuthMethod method)
    {
        var(h,c,hash)=Prepare(configuration);string? raw=null;
        h.TwoFactorService.Email(Arg.Any<string>(),Arg.Any<string>(), token: Arg.Any<CancellationToken>()).Returns(x=>{raw=x.ArgAt<string>(1);return Task.FromResult(true);});
        h.TwoFactorService.SMS(Arg.Any<string>(),Arg.Any<string>(), token: Arg.Any<CancellationToken>()).Returns(x=>{raw=x.ArgAt<string>(1);return Task.FromResult<bool?>(true);});
        var data=AccountControllerHarness.ExtractData(await c.SelectTwoFactorConfiguration(new(configuration)),200);
        data.method.ShouldBe(method);data.progressVersion.ShouldBe(2);data.challengeId.ShouldNotBeNull();
        var current=h.ProofState.Stored[hash];current.intraCodeKey.ShouldBeNull();current.requiredMethods.ShouldBe(LoginProofTestDouble.Required(configuration));
        if(raw is not null) {current.challengeCodeHash.ShouldBe(TwoFactorChallengeCodeUtility.Hash(raw,h.LoginSettings.TwoFactorChallengePepper));
            Newtonsoft.Json.JsonConvert.SerializeObject(data).ShouldNotContain(raw);}
        Newtonsoft.Json.JsonConvert.SerializeObject(data).ShouldNotContain("preAuthRefreshToken");
        if(method==TwoFactorAuthMethod.AUTHENTICATOR_APP)
        { _=h.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!,default!, token: Arg.Any<CancellationToken>());_=h.TwoFactorService.DidNotReceiveWithAnyArgs().SMS(default!,default!, token: Arg.Any<CancellationToken>()); }
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Provider_failure_cancels_current_version_and_preserves_durable_resend_cooldown(bool throws)
    {
        var(h,c,hash)=Prepare();h.TwoFactorService.Email(Arg.Any<string>(),Arg.Any<string>(), token: Arg.Any<CancellationToken>())
            .Returns(_=>throws?Task.FromException<bool>(new InvalidOperationException("provider")):Task.FromResult(false));
        if(throws)
        {
            AccountControllerHarness.ExtractEnvelope(await c.SelectTwoFactorConfiguration(new(TwoFactorAuthConfiguration.EMAIL)),503).code.ShouldBe("DELIVERY_ACCEPTANCE_UNKNOWN");
            h.ProofState.Stored[hash].challengeId.ShouldNotBeNull();h.ProofState.Stored[hash].progressVersion.ShouldBe(2);
            _=h.LoginProofs.DidNotReceiveWithAnyArgs().CancelAsync(default!,default!,default);return;
        }
        AccountControllerHarness.ExtractEnvelope(await c.SelectTwoFactorConfiguration(new(TwoFactorAuthConfiguration.EMAIL)),500).code.ShouldBe("TWO_FACTOR_PROVIDER_FAILED");
        var p=h.ProofState.Stored[hash];p.challengeId.ShouldBeNull();p.challengeCodeHash.ShouldBeNull();p.progressVersion.ShouldBe(3);
        p.challengeResends.ShouldBe((short)1);p.nextChallengeAllowedAt.ShouldNotBeNull();
        await h.LoginProofs.Received(1).CancelAsync(hash,Arg.Any<TwoFactorSession>(),Arg.Any<CancellationToken>());
    }
    [Fact]
    public async Task Provider_cleanup_stale_denial_cannot_clear_newer_challenge()
    {
        var(h,c,_)=Prepare();h.TwoFactorService.Email(Arg.Any<string>(),Arg.Any<string>(), token: Arg.Any<CancellationToken>()).Returns(Task.FromResult(false));
        h.LoginProofs.CancelAsync(Arg.Any<string>(),Arg.Any<TwoFactorSession>(),Arg.Any<CancellationToken>()).Returns(Task.FromResult(new LoginProofTransition(false,"LOGIN_PROOF_STALE")));
        AccountControllerHarness.ExtractEnvelope(await c.SelectTwoFactorConfiguration(new(TwoFactorAuthConfiguration.EMAIL)),500).code.ShouldBe("TWO_FACTOR_CHALLENGE_CLEANUP_FAILED");
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Cache_projection_failure_after_delivery_keeps_durable_challenge(bool throws)
    {
        var(h,c,hash)=Prepare();h.TwoFactorService.Email(Arg.Any<string>(),Arg.Any<string>(), token: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        h.TwoFactorSessionService.SetSession(hash,Arg.Any<TwoFactorSession>(),Arg.Any<TimeSpan>(),cancellationToken:Arg.Any<CancellationToken>())
            .Returns(_=>throws?Task.FromException<bool?>(new InvalidOperationException("cache")):Task.FromResult<bool?>(false));
        AccountControllerHarness.ExtractEnvelope(await c.SelectTwoFactorConfiguration(new(TwoFactorAuthConfiguration.EMAIL)),200).success.ShouldBeTrue();
        h.ProofState.Stored[hash].challengeCodeHash.ShouldNotBeNull();
        _=h.LoginProofs.DidNotReceiveWithAnyArgs().CancelAsync(default!,default!,default);
        _=h.TwoFactorSessionService.DidNotReceiveWithAnyArgs().RevokeSession(default!,cancellationToken:Arg.Any<CancellationToken>());
    }
    [Fact]
    public async Task Durable_cooldown_prevents_reselection_and_second_delivery()
    {
        var(h,c,_)=Prepare();h.TwoFactorService.Email(Arg.Any<string>(),Arg.Any<string>(), token: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        _=await c.SelectTwoFactorConfiguration(new(TwoFactorAuthConfiguration.EMAIL));
        AccountControllerHarness.ExtractEnvelope(await c.SelectTwoFactorConfiguration(new(TwoFactorAuthConfiguration.EMAIL)),400).success.ShouldBeFalse();
        await h.TwoFactorService.Received(1).Email(Arg.Any<string>(),Arg.Any<string>(), token: Arg.Any<CancellationToken>());
    }
    [Theory]
    [InlineData(-1)] [InlineData(4)]
    public async Task Invalid_destination_cannot_issue_or_deliver(short destination)
    {
        var(h,c,_)=Prepare();AccountControllerHarness.ExtractEnvelope(await c.SelectTwoFactorConfiguration(new(TwoFactorAuthConfiguration.EMAIL,destination:destination)),400).success.ShouldBeFalse();
        _=h.LoginProofs.DidNotReceiveWithAnyArgs().IssueAsync(default!,default!,default,default,default);
        _=h.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!,default!, token: Arg.Any<CancellationToken>());
    }
    [Fact]
    public async Task Expired_or_invalidated_SQL_authority_does_not_read_restored_cache_or_deliver()
    {
        var(h,c,hash)=Prepare();h.ProofState.AuthorityCurrent=()=>false;
        AccountControllerHarness.ExtractEnvelope(await c.SelectTwoFactorConfiguration(new(TwoFactorAuthConfiguration.EMAIL)),401).success.ShouldBeFalse();
        _=h.TwoFactorSessionService.DidNotReceiveWithAnyArgs().GetSession(default!,cancellationToken:Arg.Any<CancellationToken>());
        _=h.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!,default!, token: Arg.Any<CancellationToken>());
    }
}
