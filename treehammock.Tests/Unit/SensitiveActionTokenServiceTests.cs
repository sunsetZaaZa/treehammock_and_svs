using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;
using treehammock.DataLayer.Security;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;
namespace treehammock.Tests.Unit;

// Service orchestration with explicit authority/proof doubles; real SQL has separate schedules.
public class SensitiveActionTokenServiceTests
{
    private sealed class Harness
    {
        public readonly ISensitiveActionTokenRepo Repo=Substitute.For<ISensitiveActionTokenRepo>();
        public readonly IPasswordWorkService Work=Substitute.For<IPasswordWorkService>();
        public readonly ISensitiveActionAdmissionPolicy Admission=Substitute.For<ISensitiveActionAdmissionPolicy>();
        public readonly IAuthenticatorAppLoginVerifier Factor=Substitute.For<IAuthenticatorAppLoginVerifier>();
        public readonly Guid Account=Guid.NewGuid(),Stamp=Guid.NewGuid();
        public readonly AccountSensitiveActionService Service;
        public Harness()
        {
            Admission.CheckAsync(Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<string?>(),Arg.Any<CancellationToken>()).Returns((string?)null);
            Repo.BeginPasswordProof(Arg.Any<SensitivePasswordAdmission>(),Arg.Any<CancellationToken>()).Returns(new SensitiveProofAdmission(true,"ADMITTED",new byte[128],false));
            Work.VerifyBytesAsync(Arg.Any<byte[]>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(true);
            Repo.FinishPasswordProof(Arg.Any<SensitivePasswordCompletion>(),Arg.Any<CancellationToken>()).Returns(new SensitiveProofCompletion(true,"SENSITIVE_ACTION_TOKEN_ISSUED",SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),false));
            Service=new(Repo,Options.Create(new SensitiveActionSettings()),Work,Admission,Options.Create(new LoginSettings {TwoFactorChallengePepper="shared-cor08-test-pepper"}),Factor);
        }
        public SensitiveActionReauthenticationCommand Command=>new(Account,Stamp,"session-hash","correct password",SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP);
    }
    [Theory]
    [InlineData("SENSITIVE_ACTION_RATE_LIMITED",429)]
    [InlineData(AbuseReasonCodes.CounterStoreUnavailable,503)]
    public async Task Cache_denial_has_no_authority_or_hasher_call(string reason,int status)
    {
        var h=new Harness();h.Admission.CheckAsync(Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<string?>(),Arg.Any<CancellationToken>()).Returns(reason);
        (await h.Service.ReauthenticateAsync(h.Command)).StatusCode.ShouldBe(status);
        await h.Repo.DidNotReceiveWithAnyArgs().BeginPasswordProof(default!);
        await h.Work.DidNotReceiveWithAnyArgs().VerifyBytesAsync(default!,default!);
    }
    [Theory]
    [InlineData("SENSITIVE_ACTION_ATTEMPT_LIMIT",429)]
    [InlineData("SENSITIVE_ACTION_AUTHORITY_DENIED",423)]
    [InlineData("SENSITIVE_ACTION_FACTOR_UNAVAILABLE",503)]
    public async Task Durable_limit_live_lockout_or_unavailable_factor_denies_before_hasher(string code,int status)
    {
        var h=new Harness();h.Repo.BeginPasswordProof(Arg.Any<SensitivePasswordAdmission>(),Arg.Any<CancellationToken>()).Returns(new SensitiveProofAdmission(false,code,null,false));
        (await h.Service.ReauthenticateAsync(h.Command)).StatusCode.ShouldBe(status);
        await h.Work.DidNotReceiveWithAnyArgs().VerifyBytesAsync(default!,default!);
    }
    [Fact]
    public async Task Correct_password_issues_only_a_hashed_target_bound_grant()
    {
        var h=new Harness();var result=await h.Service.ReauthenticateAsync(h.Command);
        result.Succeeded.ShouldBeTrue();result.Token.ShouldNotBeNullOrWhiteSpace();result.ProofSession.ShouldBeNull();
        await h.Repo.Received(1).FinishPasswordProof(Arg.Is<SensitivePasswordCompletion>(c=>c.Verified && c.TokenHash.Length==64 && c.TokenHash!=result.Token),Arg.Any<CancellationToken>());
        await h.Repo.Received(1).BeginPasswordProof(Arg.Is<SensitivePasswordAdmission>(a=>a.TargetHash.Length==64 && a.Purpose==h.Command.Purpose),Arg.Any<CancellationToken>());
    }
    [Fact]
    public async Task Wrong_password_is_recorded_without_grant_or_factor_session()
    {
        var h=new Harness();h.Work.VerifyBytesAsync(Arg.Any<byte[]>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(false);
        h.Repo.FinishPasswordProof(Arg.Any<SensitivePasswordCompletion>(),Arg.Any<CancellationToken>()).Returns(new SensitiveProofCompletion(false,AccountSensitiveActionService.ReauthenticationFailedCode,null,false));
        var result=await h.Service.ReauthenticateAsync(h.Command);result.StatusCode.ShouldBe(401);result.Token.ShouldBeNull();result.ProofSession.ShouldBeNull();
        await h.Repo.Received(1).FinishPasswordProof(Arg.Is<SensitivePasswordCompletion>(c=>!c.Verified),Arg.Any<CancellationToken>());
    }
    [Fact]
    public async Task Password_alone_leaves_required_factor_pending_and_never_returns_grant()
    {
        var h=new Harness();h.Repo.FinishPasswordProof(Arg.Any<SensitivePasswordCompletion>(),Arg.Any<CancellationToken>()).Returns(new SensitiveProofCompletion(true,"SENSITIVE_ACTION_FACTOR_PROOF_REQUIRED",SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),true));
        var result=await h.Service.ReauthenticateAsync(h.Command);
        result.Succeeded.ShouldBeFalse();result.StatusCode.ShouldBe(202);result.ProofSession.ShouldNotBeNullOrWhiteSpace();result.Token.ShouldBeNull();
        await h.Repo.DidNotReceiveWithAnyArgs().FinishFactorProof(default,default,default!,default!,default!);
    }
    [Fact]
    public async Task Overload_abandons_reservation_without_recording_an_incorrect_proof()
    {
        var h=new Harness();h.Work.VerifyBytesAsync(Arg.Any<byte[]>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(Task.FromException<bool>(new PasswordWorkBusyException()));
        await Should.ThrowAsync<PasswordWorkBusyException>(()=>h.Service.ReauthenticateAsync(h.Command));
        await h.Repo.Received(1).AbandonPasswordProof(h.Account,h.Stamp,Arg.Any<Guid>(),Arg.Any<CancellationToken>());
        await h.Repo.DidNotReceiveWithAnyArgs().FinishPasswordProof(default!);
    }
    [Fact]
    public async Task Factor_limit_denies_before_verifier_and_password_hasher()
    {
        var h=new Harness();h.Repo.ReserveFactorProof(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<int>(),Arg.Any<CancellationToken>()).Returns(false);
        var result=await h.Service.CompleteFactorProofAsync(new(h.Account,h.Stamp,"session-hash",new string('x',32),"123456"));result.StatusCode.ShouldBe(429);
        await h.Factor.DidNotReceiveWithAnyArgs().VerifyForLoginAsync(default,default!,default);
        await h.Work.DidNotReceiveWithAnyArgs().VerifyBytesAsync(default!,default!);
    }
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Only_verified_existing_factor_can_complete_proof(bool verified)
    {
        var h=new Harness();h.Repo.ReserveFactorProof(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<int>(),Arg.Any<CancellationToken>()).Returns(true);
        h.Factor.VerifyForLoginAsync(Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<Instant>(),Arg.Any<CancellationToken>()).Returns(verified?AuthenticatorAppLoginVerificationResult.Success():AuthenticatorAppLoginVerificationResult.Failed(AuthenticatorAppLoginVerifier.IncorrectCode));
        h.Repo.FinishFactorProof(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(new SensitiveProofCompletion(true,AccountSensitiveActionService.TokenIssuedCode,SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),false));
        var result=await h.Service.CompleteFactorProofAsync(new(h.Account,h.Stamp,"session-hash",new string('x',32),"123456"));
        result.Succeeded.ShouldBe(verified);
        if(!verified){result.Token.ShouldBeNull();await h.Repo.DidNotReceiveWithAnyArgs().FinishFactorProof(default,default,default!,default!,default!);}
    }
    [Theory,InlineData("123456"),InlineData("1234567"),InlineData("12345678")]
    public async Task Existing_enrolled_digit_count_can_complete_sensitive_factor_proof(string code)
    {
        var h=new Harness();
        h.Repo.ReserveFactorProof(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<int>(),Arg.Any<CancellationToken>()).Returns(true);
        h.Factor.VerifyForLoginAsync(h.Account,code,Arg.Any<Instant>(),Arg.Any<CancellationToken>()).Returns(AuthenticatorAppLoginVerificationResult.Success());
        h.Repo.FinishFactorProof(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(new SensitiveProofCompletion(true,AccountSensitiveActionService.TokenIssuedCode,SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),false));
        (await h.Service.CompleteFactorProofAsync(new(h.Account,h.Stamp,"session-hash",new string('x',32),code))).Succeeded.ShouldBeTrue();
        await h.Factor.Received(1).VerifyForLoginAsync(h.Account,code,Arg.Any<Instant>(),Arg.Any<CancellationToken>());
    }
    [Fact]
    public async Task Consumption_is_refused_outside_domain_transaction_and_wrong_target_has_no_binding()
    {
        var h=new Harness();var token=new string('x',32);
        (await h.Service.ValidateAsync(new(h.Account,h.Stamp,"session-hash",token,SensitiveActionPurpose.TWO_FACTOR_METHOD_REMOVE,true,"factor:3"))).Code.ShouldBe("SENSITIVE_ACTION_TRANSACTION_REQUIRED");
        await h.Repo.DidNotReceiveWithAnyArgs().ValidateGrant(default,default,default!,default!,default,default!);
        h.Repo.ValidateGrant(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<SensitiveActionPurpose>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(false);
        var denied=await h.Service.ValidateAsync(new(h.Account,h.Stamp,"session-hash",token,SensitiveActionPurpose.TWO_FACTOR_METHOD_REMOVE,false,"factor:2"));denied.Succeeded.ShouldBeFalse();denied.Grant.ShouldBeNull();
    }
    [Fact]
    public async Task Cache_fallback_cannot_admit_sensitive_password_proof()
    {
        var store=Substitute.For<IAbuseCounterStore>();store.IncrementAsync(Arg.Any<AbuseCounterKey>(),Arg.Any<AbuseCounterLimit>(),Arg.Any<CancellationToken>()).Returns(new CounterDecision(true,0,10,TimeSpan.FromMinutes(15),null,AbuseReasonCodes.CounterStoreUnavailable));
        var policy=new SensitiveActionAdmissionPolicy(store,Options.Create(new SensitiveActionSettings()),Options.Create(new LoginSettings {TwoFactorChallengePepper="shared-test-pepper"}));
        (await policy.CheckAsync(Guid.NewGuid(),"session-hash","203.0.113.9")).ShouldBe(AbuseReasonCodes.CounterStoreUnavailable);
    }
}
