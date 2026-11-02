using NodaTime;
using NSubstitute;
using treehammock.DataLayer.Cache;
using treehammock.Repos;
using treehammock.Rigging.Cache;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Tests.Infrastructure;

// Controller/routing substitution only. Its independent cloned store ensures
// cache objects cannot grant proof. Actual locking/expiry/receipt semantics run
// in Cor10LoginProofTests; this fixture makes no database qualification claim.
public sealed class LoginProofTestDouble
{
    public ILoginProofRepo Repo { get; } = Substitute.For<ILoginProofRepo>();
    public Dictionary<string,TwoFactorSession> Stored { get; } = new(StringComparer.Ordinal);
    public Func<bool> AuthorityCurrent { get; set; } = () => true;
    public LoginProofTestDouble()
    {
        Repo.LoadAsync(Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(c =>
        {
            Stored.TryGetValue(c.ArgAt<string>(0),out var p);
            var now=SystemClock.Instance.GetCurrentInstant();
            return Task.FromResult(p is null||!AuthorityCurrent()||p.expiration<=now||p.cutOff<=now?null:Clone(p));
        });
        Repo.BeginAsync(Arg.Any<string>(),Arg.Any<TwoFactorSession>(),Arg.Any<CancellationToken>()).Returns(c =>
        {
            var p=Clone(c.ArgAt<TwoFactorSession>(1));Stored.Clear();Stored[c.ArgAt<string>(0)]=p;
            return Task.FromResult(new LoginProofTransition(true,"PENDING_TWO_FACTOR_SET",Clone(p)));
        });
        Repo.IssueAsync(Arg.Any<string>(),Arg.Any<TwoFactorSession>(),Arg.Any<short>(),Arg.Any<int>(),Arg.Any<CancellationToken>()).Returns(c =>
        {
            string hash=c.ArgAt<string>(0);var proposal=c.ArgAt<TwoFactorSession>(1);
            if(!Stored.TryGetValue(hash,out var current)||current.progressVersion!=proposal.progressVersion)
                return Task.FromResult(new LoginProofTransition(false,"LOGIN_PROOF_STALE"));
            if(current.nextChallengeAllowedAt>SystemClock.Instance.GetCurrentInstant()&&!(proposal.challengedMethod==TwoFactorAuthMethod.AUTHENTICATOR_APP&&current.challengeId is null&&current.completedMethods.Count>0))
                return Task.FromResult(new LoginProofTransition(false,"TWO_FACTOR_CHALLENGE_COOLDOWN",Clone(current)));
            var p=Clone(proposal);p.progressVersion++;p.challengeId=Guid.NewGuid();
            p.requiredMethods=Required(p.selectedConfiguration);p.completedMethods=current.selectedConfiguration==p.selectedConfiguration?current.completedMethods.ToList():[];
            p.currentExpectedMethod=p.requiredMethods.Skip(p.completedMethods.Count).Cast<TwoFactorAuthMethod?>().FirstOrDefault();
            p.challengeResends=(short)(current.challengeResends+(p.challengedMethod==TwoFactorAuthMethod.AUTHENTICATOR_APP?0:1));
            p.nextChallengeAllowedAt=SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromSeconds(c.ArgAt<int>(3)));
            Stored[hash]=p;return Task.FromResult(new LoginProofTransition(true,"TWO_FACTOR_CHALLENGE_ISSUED",Clone(p)));
        });
        Repo.CompleteAsync(Arg.Any<string>(),Arg.Any<TwoFactorSession>(),Arg.Any<string?>(),Arg.Any<bool>(),Arg.Any<short>(),Arg.Any<CancellationToken>()).Returns(c =>
        {
            string hash=c.ArgAt<string>(0);var proposal=c.ArgAt<TwoFactorSession>(1);
            if(!Stored.TryGetValue(hash,out var p)||p.progressVersion!=proposal.progressVersion||p.challengeId!=proposal.challengeId)
                return Task.FromResult(new LoginProofTransition(false,"LOGIN_PROOF_STALE"));
            if(p.challengeExpiration is null||p.challengeExpiration<=SystemClock.Instance.GetCurrentInstant())
                return Task.FromResult(new LoginProofTransition(false,"PENDING_TWO_FACTOR_EXPIRED"));
            p=Clone(p);p.progressVersion++;
            bool accepted=p.challengedMethod==TwoFactorAuthMethod.AUTHENTICATOR_APP?c.ArgAt<bool>(3):p.challengeCodeHash==c.ArgAt<string?>(2);
            string code;
            if(accepted)
            {
                p.completedMethods.Add(p.challengedMethod!.Value);p.currentExpectedMethod=p.requiredMethods.Skip(p.completedMethods.Count).Cast<TwoFactorAuthMethod?>().FirstOrDefault();
                p.state=p.currentExpectedMethod is null?TwoFactorSessionState.Complete:TwoFactorSession.StateForMethod(p.currentExpectedMethod.Value);
                p.challengeId=null;p.challengedMethod=null;p.challengeCodeHash=null;p.challengeExpiration=null;p.challengeAttempts=0;code="LOGIN_PROOF_ACCEPTED";
            }
            else {p.challengeAttempts++;code=p.challengeAttempts>=c.ArgAt<short>(4)?"TWO_FACTOR_CHALLENGE_ATTEMPT_LIMIT":"TWO_FACTOR_CHALLENGE_INCORRECT";
                if(p.challengeAttempts>=c.ArgAt<short>(4)) {p.state=TwoFactorSessionState.Failed;p.challengeCodeHash=null;} }
            Stored[hash]=p;return Task.FromResult(new LoginProofTransition(accepted,code,Clone(p)));
        });
        Repo.CancelAsync(Arg.Any<string>(),Arg.Any<TwoFactorSession>(),Arg.Any<CancellationToken>()).Returns(c =>
        {
            string hash=c.ArgAt<string>(0);var proposal=c.ArgAt<TwoFactorSession>(1);
            if(!Stored.TryGetValue(hash,out var p)||p.progressVersion!=proposal.progressVersion||p.challengeId!=proposal.challengeId)
                return Task.FromResult(new LoginProofTransition(false,"LOGIN_PROOF_STALE"));
            p=Clone(p);p.progressVersion++;p.challengeId=null;p.challengeCodeHash=null;p.challengeExpiration=null;p.challengedMethod=null;
            Stored[hash]=p;return Task.FromResult(new LoginProofTransition(true,"TWO_FACTOR_CHALLENGE_CANCELLED",Clone(p)));
        });
        Repo.PromoteAsync(Arg.Any<string>(),Arg.Any<TwoFactorSession>(),Arg.Any<string>(),Arg.Any<ActiveSession>(),Arg.Any<CancellationToken>()).Returns(c =>
        {
            string hash=c.ArgAt<string>(0);var proposal=c.ArgAt<TwoFactorSession>(1);
            bool accepted=Stored.TryGetValue(hash,out var p)&&p.isComplete&&p.progressVersion==proposal.progressVersion;
            if(accepted) Stored.Remove(hash);
            return Task.FromResult(new LoginProofTransition(accepted,accepted?"TWO_FACTOR_NEW_LOGIN_PROMOTED":"LOGIN_PROOF_STALE"));
        });
    }
    public static TwoFactorSession Clone(TwoFactorSession p)=>CacheJsonSettings.Deserialize<TwoFactorSession>(CacheJsonSettings.Serialize(p))!;
    public static List<TwoFactorAuthMethod> Required(TwoFactorAuthConfiguration? c)=>c switch
    {
        TwoFactorAuthConfiguration.SMS=>[TwoFactorAuthMethod.SMS_KEY],TwoFactorAuthConfiguration.EMAIL=>[TwoFactorAuthMethod.EMAIL],
        TwoFactorAuthConfiguration.AUTHENTICATOR_APP=>[TwoFactorAuthMethod.AUTHENTICATOR_APP],
        TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP=>[TwoFactorAuthMethod.SMS_KEY,TwoFactorAuthMethod.AUTHENTICATOR_APP],
        TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP=>[TwoFactorAuthMethod.EMAIL,TwoFactorAuthMethod.AUTHENTICATOR_APP],_=>[]
    };
}
