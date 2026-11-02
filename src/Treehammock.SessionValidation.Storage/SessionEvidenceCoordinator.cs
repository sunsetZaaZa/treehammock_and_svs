using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using NodaTime;
using Treehammock.SessionValidation.Core;
namespace Treehammock.SessionValidation.Storage;

// Queue admission must be nonblocking/bounded. The local owned worker performs a NEW guarded database read.
// A callback cannot submit state, a key or an asserted account; it cannot affect the decision.
public interface IGuardedSessionRefillQueue { bool TryRequest(string credentialHash,Guid expectedEpoch); }
public sealed record ValidatedSessionSubject(Guid AccountId,Guid FamilyId,long Generation,int ProtocolVersion,
    int FeatureTier,ImmutableArray<string> Capabilities)
{ public override string ToString()=>nameof(ValidatedSessionSubject); }
internal sealed record VerifiedRequestContext(string WebKey,SessionIdentity Identity,SessionLifetime Lifetime,EntitlementPolicyInputs Entitlements)
{ public override string ToString()=>nameof(VerifiedRequestContext); }
public sealed record SessionEvidenceDecision(SessionDecision Decision,ValidatedSessionSubject? Subject=null,Instant? ValidUntil=null)
{
    // Internal application adapter; not part of SVS's subject/wire contract. Never contains a key.
    internal VerifiedRequestContext? ApplicationContext { get; init; }
    internal Func<bool>? EvidenceCurrent { get; init; }
    public override string ToString()=>$"SessionEvidenceDecision({Decision})";
}

public sealed class SessionEvidenceCoordinator
{
    private readonly CoherentSessionCacheReader _cache;
    private readonly IReadonlySessionAuthority _authority;
    private readonly ITreehammockSessionPolicyEvaluator _policy;
    private readonly IGuardedSessionRefillQueue? _refill;
    private readonly IClock _clock;
    private readonly string _issuer;
    private readonly TimeSpan _budget;
    public SessionEvidenceCoordinator(CoherentSessionCacheReader cache,IReadonlySessionAuthority authority,
        string issuer,TimeSpan requestBudget,IGuardedSessionRefillQueue? refill=null,
        ITreehammockSessionPolicyEvaluator? policy=null,IClock? clock=null)
    {
        if(string.IsNullOrWhiteSpace(issuer)||requestBudget<TimeSpan.FromMilliseconds(1)||requestBudget>TimeSpan.FromSeconds(5))throw new ArgumentException("Bounded request and issuer required.");
        _cache=cache;_authority=authority;_issuer=issuer;_budget=requestBudget;_refill=refill;_policy=policy??new TreehammockSessionPolicyEvaluator();_clock=clock??SystemClock.Instance;
    }
    public Task<SessionEvidenceDecision> ValidateAsync(string credential,string requiredCapability,Instant deadline,CancellationToken cancellationToken=default)
        =>ValidateCoreAsync(credential,requiredCapability,deadline,cancellationToken,false);
    internal Task<SessionEvidenceDecision> ValidateApplicationAsync(string credential,string requiredCapability,Instant deadline,CancellationToken cancellationToken=default)
        =>ValidateCoreAsync(credential,requiredCapability,deadline,cancellationToken,true);
    private async Task<SessionEvidenceDecision> ValidateCoreAsync(string credential,string requiredCapability,Instant deadline,CancellationToken cancellationToken,bool application)
    {
        cancellationToken.ThrowIfCancellationRequested();var time=new RequestTimeGuard(_clock);var before=time.GetCurrentInstant();
        if(deadline<=before||string.IsNullOrWhiteSpace(credential)||credential.Length>8192||Encoding.UTF8.GetByteCount(credential)>8192||string.IsNullOrWhiteSpace(requiredCapability)||requiredCapability.Length>128)return new(SessionDecision.Unavailable);
        if(deadline>before+Duration.FromTimeSpan(_budget))deadline=before+Duration.FromTimeSpan(_budget);
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);timeout.CancelAfter((deadline-before).ToTimeSpan());
        string hash=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(credential)));
        try
        {
            var cached=await _cache.ReadAsync(hash,deadline,timeout.Token,time);
            if(cached is not null)
            {
                bool moved=false;
                try
                {
                    if(!Current(time,before,deadline,timeout.Token))return new(SessionDecision.Unavailable);
                    moved=true;
                    var result=await EvaluateOwned(cached.Projection,cached,credential,requiredCapability,deadline,time,timeout.Token,application);
                    if(!Current(time,before,deadline,timeout.Token))return new(SessionDecision.Unavailable);
                    // A usable hit's refusal never falls through to a different key.
                    if(_cache.Admission.IsCurrent(cached.Admission)&&time.GetCurrentInstant()<cached.NotAfter)
                        return Result(result,cached.Projection,deadline,cached.NotAfter,time,application) with{EvidenceCurrent=()=>_cache.Admission.IsCurrent(cached.Admission)};
                }
                finally { if(!moved)cached.Dispose(); }
            }
            if(!Current(time,before,deadline,timeout.Token))return new(SessionDecision.Unavailable);
            var refillAdmission=_cache.Admission.Capture();
            var read=await ReadOwned(hash,deadline,timeout.Token);
            if(read is null)return new(SessionDecision.Unavailable);
            bool transferred=false;
            try
            {
                if(!Current(time,before,deadline,timeout.Token))return new(SessionDecision.Unavailable);
                if(read.Status is AuthorityReadStatus.NotFound or AuthorityReadStatus.Unauthenticated)return new(SessionDecision.Unauthenticated);
                if(read.Status!=AuthorityReadStatus.Found||read.Projection is null)return new(SessionDecision.Unavailable);
                transferred=true;
                var result=await EvaluateOwned(read.Projection,read,credential,requiredCapability,deadline,time,timeout.Token,application);
                if(!Current(time,before,deadline,timeout.Token))return new(SessionDecision.Unavailable);
                var decision=Result(result,read.Projection,deadline,null,time,application);
                if(result.Decision is SessionDecision.Active or SessionDecision.Forbidden && refillAdmission is not null&&_cache.Admission.IsCurrent(refillAdmission))
                { try { _refill?.TryRequest(hash,refillAdmission.Space.Epoch); } catch(Exception) { /* Hint failure never changes validated DB evidence. */ } }
                return Current(time,before,deadline,timeout.Token)&&(decision.Decision!=SessionDecision.Active||decision.ValidUntil>time.GetCurrentInstant())&&time.Safe?decision:new(SessionDecision.Unavailable);
            }
            finally { if(!transferred)read.Dispose(); }
        }
        catch(OperationCanceledException)when(cancellationToken.IsCancellationRequested){throw;}
        catch(Exception){return new(SessionDecision.Unavailable);}
    }
    private static bool Current(RequestTimeGuard time,Instant before,Instant deadline,CancellationToken token)
    { var now=time.GetCurrentInstant();return time.Safe&&!token.IsCancellationRequested&&now>=before&&now<deadline; }
    private async Task<AuthorityReadResult?> ReadOwned(string hash,Instant deadline,CancellationToken token)
    {
        var pending=_authority.ReadAsync(hash,deadline,token);bool consumed=false;
        try{var result=await pending.WaitAsync(token);consumed=true;return result;}
        finally{if(!consumed)_=pending.ContinueWith(t=>{if(t.IsCompletedSuccessfully)t.Result?.Dispose();else _=t.Exception;},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);}
    }
    private async Task<VerifiedSessionAccess> EvaluateOwned(AuthSessionProjection projection,IDisposable owner,
        string credential,string capability,Instant deadline,IClock time,CancellationToken token,bool application)
    {
        Task<VerifiedSessionAccess>? pending=null;bool consumed=false;
        try
        {
            pending=Evaluate();
            async Task<VerifiedSessionAccess> Evaluate()=>application
                ? await projection.EvaluateApplicationAsync(_policy,credential,_issuer,capability,deadline,time,token)
                : new(await projection.EvaluateAccessAsync(_policy,credential,_issuer,capability,deadline,time,token));
            var result=await pending.WaitAsync(token);consumed=true;return result;
        }
        finally
        {
            if(pending is {IsCompleted:true})_=pending.Exception;
            if(consumed||pending is null||pending.IsCompleted)owner.Dispose();
            else _=pending.ContinueWith(t=>{_=t.Exception;owner.Dispose();},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
        }
    }
    private SessionEvidenceDecision Result(VerifiedSessionAccess evaluated,AuthSessionProjection projection,Instant deadline,Instant? cacheEnd,RequestTimeGuard time,bool application)
    {
        var result=evaluated.Decision;
        if(result!=SessionDecision.Active&&(!application||result!=SessionDecision.Forbidden))return new(result);
        var i=projection.Identity;var e=projection.Entitlements;var end=deadline;
        foreach(var limit in new Instant?[]{projection.Lifetime.AccessExpiration,projection.Lifetime.EffectiveHardExpiration,e.NextBoundary,e.EligibilityUntil,cacheEnd})if(limit is { } bound&&bound<end)end=bound;
        if(end<=time.GetCurrentInstant()||!time.Safe)return new(SessionDecision.Unavailable);
        return new(result,result==SessionDecision.Active?new ValidatedSessionSubject(i.AccountId,i.FamilyId,i.Generation,i.ProtocolVersion,e.FeatureTier,e.Capabilities):null,end)
        { ApplicationContext=application?new(evaluated.WebKey??string.Empty,i,projection.Lifetime,e):null };
    }
    public override string ToString()=>nameof(SessionEvidenceCoordinator);
}
