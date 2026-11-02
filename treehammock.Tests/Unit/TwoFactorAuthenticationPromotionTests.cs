using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using NodaTime;
using Shouldly;
using treehammock.DataLayer.Cache;
using treehammock.Models.Api;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Abuse;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class TwoFactorAuthenticationPromotionTests
{
    internal const string Token="pending-token",Final="final-token";
    internal static (AccountControllerHarness Harness,TwoFactorSession Session,string Hash) Prepare(
        TwoFactorAuthConfiguration configuration=TwoFactorAuthConfiguration.EMAIL,string? prior=null)
    {
        var h=new AccountControllerHarness();var now=SystemClock.Instance.GetCurrentInstant();
        var methods=LoginProofTestDouble.Required(configuration);
        var p=new TwoFactorSession(Guid.NewGuid(),"web-key",Enumerable.Repeat((byte)7,64).ToArray(),methods,
            null,["5555550101"],["1"],["reader@example.com"],0,null,1,0,1,now,
            now.Plus(Duration.FromMinutes(5)),FeatureSet.basic,accountSecurityStamp:Guid.NewGuid(),priorActiveAccessTokenHash:prior)
        { selectedConfiguration=configuration,requiredMethods=methods,currentExpectedMethod=methods[0],challengedMethod=methods[0],
            state=TwoFactorSession.StateForMethod(methods[0]),challengeId=Guid.NewGuid(),progressVersion=2,
            challengeCodeHash=TwoFactorChallengeCodeUtility.Hash("123456",h.LoginSettings.TwoFactorChallengePepper),
            challengeExpiration=now.Plus(Duration.FromMinutes(2)) };
        string hash=AccessTokenHashUtility.Hash(Token);h.ProofState.Stored[hash]=LoginProofTestDouble.Clone(p);
        h.JwtUtility.ValidateAccessToken(Token,Arg.Any<byte[]>(),Arg.Any<Instant>(),Arg.Any<Instant>(),JsonWebTokenPurpose.PreAuthTwoFactor)
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION,(string?)p.webKey)));
        h.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(),p.webKey).Returns(Final);
        h.TwoFactorSessionService.SetSession(hash,Arg.Any<TwoFactorSession>(),Arg.Any<TimeSpan>(),cancellationToken:Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        h.TwoFactorSessionService.RevokeSession(hash,cancellationToken:Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        return(h,p,hash);
    }
    private static treehammock.Controllers.AccountTwoFactorController Controller(AccountControllerHarness h,IAuthenticatorAppLoginVerifier? verifier=null)
    {
        var controller=h.CreateTwoFactorController();h.HttpContext.Request.Headers["AccessToken"]=Token;
        if(verifier is not null) h.HttpContext.RequestServices=new ServiceCollection().AddSingleton(h.LoginProofs).AddSingleton(verifier).BuildServiceProvider();
        return controller;
    }
    [Fact]
    public async Task Empty_code_is_rejected_before_SQL_load()
    {
        var h=new AccountControllerHarness();var c=h.CreateTwoFactorController();
        var result=await c.TwoFactorAuthenticate(new LayeredAuthenticateRequest("",TwoFactorAuthMethod.EMAIL));
        AccountControllerHarness.ExtractEnvelope(result,400).code.ShouldBe(ApiResponses.ValidationFailedCode);
        _=h.LoginProofs.DidNotReceiveWithAnyArgs().LoadAsync(default!,default);
    }
    [Fact]
    public async Task No_pre_auth_token_does_not_load_or_promote()
    {
        var h=new AccountControllerHarness();var c=h.CreateTwoFactorController();
        AccountControllerHarness.ExtractEnvelope(await c.TwoFactorAuthenticate(new("123456",TwoFactorAuthMethod.EMAIL)),401).success.ShouldBeFalse();
        _=h.LoginProofs.DidNotReceiveWithAnyArgs().LoadAsync(default!,default);
        _=h.LoginProofs.DidNotReceiveWithAnyArgs().PromoteAsync(default!,default!,default!,default!,default);
    }
    [Theory]
    [InlineData(null)] [InlineData("prior-active-hash")]
    public async Task Final_durable_proof_promotes_a_new_family_and_cache_failure_preserves_committed_output(string? prior)
    {
        var(h,p,hash)=Prepare(prior:prior);var c=Controller(h);
        h.ActiveUserCacheService.SetSession(Arg.Any<string>(),Arg.Any<ActiveSession>(),Arg.Any<TimeSpan>(),cancellationToken:Arg.Any<CancellationToken>()).Returns(Task.FromResult(false));
        var data=AccountControllerHarness.ExtractData(await c.TwoFactorAuthenticate(new("123456",TwoFactorAuthMethod.EMAIL)),200);
        data.result.ShouldBe(TwoFactorAuthOutcome.SUCCESS);data.accessToken.ShouldBe(Final);
        await h.LoginProofs.Received(1).CompleteAsync(hash,Arg.Any<TwoFactorSession>(),p.challengeCodeHash,false,3,Arg.Any<CancellationToken>());
        await h.LoginProofs.Received(1).PromoteAsync(hash,Arg.Is<TwoFactorSession>(s=>s.isComplete&&s.progressVersion==3),AccessTokenHashUtility.Hash(Final),
            Arg.Is<ActiveSession>(s=>s.accountId==p.accountId&&s.generation==1),Arg.Any<CancellationToken>());
        await h.TwoFactorSessionService.Received(1).RevokeSession(hash,cancellationToken:Arg.Any<CancellationToken>());
        if(prior is not null) await h.ActiveUserCacheService.Received(1).RevokeSession(prior,cancellationToken:Arg.Any<CancellationToken>());
        _=h.SessionRepo.DidNotReceiveWithAnyArgs().ExpireSession(default!,default,cancellationToken:Arg.Any<CancellationToken>());
    }
    [Fact]
    public async Task Incorrect_proof_records_versioned_failure_without_promotion()
    {
        var(h,_,hash)=Prepare();var c=Controller(h);
        var data=AccountControllerHarness.ExtractData(await c.TwoFactorAuthenticate(new("654321",TwoFactorAuthMethod.EMAIL)),401);
        data.accessToken.ShouldBeNull();h.ProofState.Stored[hash].challengeAttempts.ShouldBe((short)1);
        h.ProofState.Stored[hash].progressVersion.ShouldBe(3);
        await h.AbuseCounterStore.Received(1).IncrementAsync(Arg.Is<AbuseCounterKey>(k=>k.Feature==AbuseFeature.TwoFactorChallenge),Arg.Any<AbuseCounterLimit>(),Arg.Any<CancellationToken>());
        _=h.LoginProofs.DidNotReceiveWithAnyArgs().PromoteAsync(default!,default!,default!,default!,default);
    }
    [Fact]
    public async Task Stale_SQL_completion_returns_conflict_without_token_or_promotion()
    {
        var(h,_,_)=Prepare();var c=Controller(h);
        h.LoginProofs.CompleteAsync(Arg.Any<string>(),Arg.Any<TwoFactorSession>(),Arg.Any<string?>(),Arg.Any<bool>(),Arg.Any<short>(),Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new LoginProofTransition(false,"LOGIN_PROOF_STALE")));
        var e=AccountControllerHarness.ExtractEnvelope(await c.TwoFactorAuthenticate(new("123456",TwoFactorAuthMethod.EMAIL)),409);
        e.code.ShouldBe("LOGIN_PROOF_STALE");e.data!.accessToken.ShouldBeNull();
        _=h.LoginProofs.DidNotReceiveWithAnyArgs().PromoteAsync(default!,default!,default!,default!,default);
    }
    [Theory]
    [InlineData(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP,TwoFactorAuthMethod.SMS_KEY)]
    [InlineData(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP,TwoFactorAuthMethod.EMAIL)]
    public async Task Combo_records_first_proof_and_issues_versioned_TOTP_challenge_before_final_promotion(TwoFactorAuthConfiguration configuration,TwoFactorAuthMethod first)
    {
        var(h,_,hash)=Prepare(configuration);var c=Controller(h);
        var data=AccountControllerHarness.ExtractData(await c.TwoFactorAuthenticate(new("123456",first)),200);
        data.accessToken.ShouldBeNull();data.currentRequiredMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        h.ProofState.Stored[hash].completedMethods.ShouldBe([first]);h.ProofState.Stored[hash].challengeId.ShouldNotBeNull();
        _=h.LoginProofs.DidNotReceiveWithAnyArgs().PromoteAsync(default!,default!,default!,default!,default);
        var verifier=Substitute.For<IAuthenticatorAppLoginVerifier>();
        verifier.VerifyForLoginAsync(Arg.Any<Guid>(),"123456",Arg.Any<Instant>(),Arg.Any<CancellationToken>()).Returns(Task.FromResult(AuthenticatorAppLoginVerificationResult.Success()));
        c=Controller(h,verifier);
        AccountControllerHarness.ExtractData(await c.TwoFactorAuthenticate(new("123456",TwoFactorAuthMethod.AUTHENTICATOR_APP)),200).accessToken.ShouldBe(Final);
    }
    [Fact]
    public async Task Wrong_method_is_rejected_before_SQL_proof_and_TOTP_verification()
    {
        var(h,_,_)=Prepare(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);var c=Controller(h);
        AccountControllerHarness.ExtractEnvelope(await c.TwoFactorAuthenticate(new("123456",TwoFactorAuthMethod.AUTHENTICATOR_APP)),400).code.ShouldBe("TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED");
        _=h.LoginProofs.DidNotReceiveWithAnyArgs().CompleteAsync(default!,default!,default,default,default,default);
    }
    [Fact]
    public async Task Restored_cache_completion_cannot_grant_SQL_proof()
    {
        var(h,p,hash)=Prepare();p.MarkCurrentProofAccepted();p.MarkComplete();
        h.TwoFactorSessionService.GetSession(hash,cancellationToken:Arg.Any<CancellationToken>()).Returns(Task.FromResult<TwoFactorSession?>(p));
        var c=Controller(h);AccountControllerHarness.ExtractData(await c.TwoFactorAuthenticate(new("654321",TwoFactorAuthMethod.EMAIL)),401).accessToken.ShouldBeNull();
        _=h.TwoFactorSessionService.DidNotReceiveWithAnyArgs().GetSession(default!,cancellationToken:Arg.Any<CancellationToken>());
        _=h.LoginProofs.DidNotReceiveWithAnyArgs().PromoteAsync(default!,default!,default!,default!,default);
    }
    [Fact]
    public async Task Committed_completion_can_resume_after_cache_loss_without_repeating_proof()
    {
        var(h,p,hash)=Prepare();p.MarkCurrentProofAccepted();p.MarkComplete();p.progressVersion=3;p.challengeId=null;
        h.ProofState.Stored[hash]=p;var c=Controller(h);
        AccountControllerHarness.ExtractData(await c.TwoFactorAuthenticate(new("123456",TwoFactorAuthMethod.EMAIL)),200).accessToken.ShouldBe(Final);
        _=h.LoginProofs.DidNotReceiveWithAnyArgs().CompleteAsync(default!,default!,default,default,default,default);
    }
    [Theory]
    [InlineData(AuthenticatorAppLoginVerifier.EnrollmentUnavailableCode)] [InlineData(AuthenticatorAppLoginVerifier.SecretUnavailableCode)]
    public async Task TOTP_dependency_failure_does_not_charge_durable_proof_attempt(string code)
    {
        var(h,_,hash)=Prepare(TwoFactorAuthConfiguration.AUTHENTICATOR_APP);var verifier=Substitute.For<IAuthenticatorAppLoginVerifier>();
        verifier.VerifyForLoginAsync(Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<Instant>(),Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(AuthenticatorAppLoginVerificationResult.Failed(code)));
        var c=Controller(h,verifier);var e=AccountControllerHarness.ExtractEnvelope(await c.TwoFactorAuthenticate(new("123456",TwoFactorAuthMethod.AUTHENTICATOR_APP)),503);
        e.code.ShouldBe(code);h.ProofState.Stored[hash].challengeAttempts.ShouldBe((short)0);
        _=h.LoginProofs.DidNotReceiveWithAnyArgs().CompleteAsync(default!,default!,default,default,default,default);
    }
    [Fact]
    public async Task Promotion_denial_returns_conflict_and_no_active_cache_write()
    {
        var(h,_,_)=Prepare();h.LoginProofs.PromoteAsync(Arg.Any<string>(),Arg.Any<TwoFactorSession>(),Arg.Any<string>(),Arg.Any<ActiveSession>(),Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new LoginProofTransition(false,"LOGIN_PROOF_STALE")));var c=Controller(h);
        AccountControllerHarness.ExtractData(await c.TwoFactorAuthenticate(new("123456",TwoFactorAuthMethod.EMAIL)),409).accessToken.ShouldBeNull();
        _=h.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!,default!,default,cancellationToken:Arg.Any<CancellationToken>());
    }
}
