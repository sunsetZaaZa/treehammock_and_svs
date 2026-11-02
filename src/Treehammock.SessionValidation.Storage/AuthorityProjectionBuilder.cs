using System.Security.Cryptography;
using NodaTime;
namespace Treehammock.SessionValidation.Storage;

internal sealed class ProjectionCandidate(string? currentHash,CurrentSessionRow? row) : IDisposable
{
    internal string? CurrentHash { get; }=currentHash;
    internal CurrentSessionRow? Row { get; }=row;
    public void Dispose()=>Row?.Dispose();
    public override string ToString()=>nameof(ProjectionCandidate);
}
internal interface IAuthorityProjectionLease : IAsyncDisposable
{
    AuthorityVersion? Authority { get; }
    Task<ProjectionCandidate> ReadCurrentAsync(string expectedHash,CancellationToken token);
}
internal interface IAuthorityProjectionLeaseFactory
{ Task<IAuthorityProjectionLease> AcquireAsync(Guid account,TimeSpan budget,CancellationToken token); }

// Owns both the row lock and secret-bearing encoded bytes until future publication
// completes. This is not a fence receipt and cannot publish a cache record itself.
internal sealed class PreparedAuthorityProjection : IAsyncDisposable
{
    private IAuthorityProjectionLease? _lease;
    private byte[]? _payload;
    private readonly CancellationTokenSource _budget;
    private readonly RequestTimeGuard _time;
    private readonly Instant _deadline;
    internal CacheAuthorityHeader Header { get; }
    internal Instant? NotAfter { get; }
    internal string AccountKey { get; }
    internal string? CredentialKey { get; }
    internal PreparedAuthorityProjection(IAuthorityProjectionLease lease,byte[] payload,CacheAuthorityHeader header,
        Instant? notAfter,CoherentCacheKeySpace space,string? hash,CancellationTokenSource budget,RequestTimeGuard time,Instant deadline)
    { _lease=lease;_payload=payload;Header=header;NotAfter=notAfter;AccountKey=space.AccountKey(header.AccountId);
      CredentialKey=hash is null?null:space.CredentialKey(hash);_budget=budget;_time=time;_deadline=deadline; }
    internal ReadOnlyMemory<byte> Payload
    {
        get
        {
            var now=_time.GetCurrentInstant();
            if(_payload is null || !_time.Safe || _budget.IsCancellationRequested || now>=_deadline || NotAfter is {} end && now>=end)
                throw new InvalidOperationException("Prepared authority projection expired or disposed.");
            return _payload;
        }
    }
    public async ValueTask DisposeAsync()
    {
        var lease=Interlocked.Exchange(ref _lease,null);
        if(lease is null)return;
        var bytes=Interlocked.Exchange(ref _payload,null);
        if(bytes is not null)CryptographicOperations.ZeroMemory(bytes);
        _budget.Dispose();await lease.DisposeAsync();
    }
    public override string ToString()=>nameof(PreparedAuthorityProjection);
}

internal sealed class AuthorityProjectionBuilder
{
    private readonly IAuthorityProjectionLeaseFactory _factory;
    private readonly CoherentCacheKeySpace _space;
    private readonly Duration _maximumAge;
    private readonly TimeSpan _readBudget;
    private readonly IClock _clock;
    internal AuthorityProjectionBuilder(IAuthorityProjectionLeaseFactory factory,CoherentCacheKeySpace space,
        TimeSpan maximumAge,TimeSpan readBudget,IClock? clock=null)
    {
        if(maximumAge<TimeSpan.FromMilliseconds(1)||maximumAge>TimeSpan.FromMinutes(5)||readBudget<TimeSpan.FromMilliseconds(1)||readBudget>TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(maximumAge));
        _factory=factory;_space=space;_maximumAge=Duration.FromTimeSpan(maximumAge);_readBudget=readBudget;_clock=clock??SystemClock.Instance;
    }
    internal async Task<PreparedAuthorityProjection> PrepareAsync(Guid account,string expectedHash,Instant deadline,CancellationToken caller=default)
    {
        caller.ThrowIfCancellationRequested();var time=new RequestTimeGuard(_clock);var start=time.GetCurrentInstant();
        if(account==Guid.Empty||!YsqlSessionAuthority.IsHash(expectedHash))throw new ArgumentException("Server-resolved account and full credential binding required.");
        if(deadline<=start)throw new TimeoutException("Projection deadline expired.");
        if(deadline>start+Duration.FromTimeSpan(_readBudget))deadline=start+Duration.FromTimeSpan(_readBudget);
        var budget=CancellationTokenSource.CreateLinkedTokenSource(caller);budget.CancelAfter((deadline-start).ToTimeSpan());
        IAuthorityProjectionLease? lease=null;byte[]? bytes=null;bool transferred=false;
        try
        {
            var acquire=_factory.AcquireAsync(account,(deadline-start).ToTimeSpan(),budget.Token);
            try { lease=await acquire.WaitAsync(budget.Token); }
            catch { ObserveLateLease(acquire);throw; }
            Check(time,deadline,budget.Token);
            var version=lease.Authority;
            if(version is null||version.AccountId!=account||version.Revision.Value<0||
               version.Lifecycle is not ("Live" or "Deleted" or "Uninitialized")||
               version.Lifecycle=="Uninitialized" && version.Revision.Value!=0 ||
               version.Lifecycle!="Uninitialized" && version.Revision.Value==0)
                throw new InvalidOperationException("Missing or inconsistent locked authority.");
            var header=new CacheAuthorityHeader(_space.Environment,_space.Epoch,_space.Policy,CoherentCacheKeySpace.NewTransitionNonce(),
                version.Revision.Value,CachedAuthorityState.Blocked,account);
            Instant? notAfter=null;string? readyHash=null;
            if(version.Lifecycle=="Live")
            {
                var read=lease.ReadCurrentAsync(expectedHash,budget.Token);ProjectionCandidate candidate;
                try { candidate=await read.WaitAsync(budget.Token); }
                catch { ObserveLateCandidate(read);throw; }
                using(candidate)
                {
                    Check(time,deadline,budget.Token);
                    if(candidate.CurrentHash is {} current && current!=expectedHash)
                        throw new InvalidOperationException("Credential changed after account routing.");
                    if(candidate.Row is {} row)
                    {
                        if(candidate.CurrentHash!=expectedHash || row.Binding!=expectedHash || row.Identity.AccountId!=account)
                            throw new InvalidOperationException("Projection account/credential mismatch.");
                        using var mapped=AuthorityProjectionMapper.Map(row,expectedHash,time.GetCurrentInstant());
                        if(mapped.Status==AuthorityReadStatus.Found)
                        {
                            var entitlements=AuthorityProjectionMapper.ParseEntitlements(row.EntitlementJson);
                            // Keep the shared SVS-06 reader's current grant-rights policy.
                            if(entitlements.RightsEnabled)throw new InvalidOperationException("Unsupported enabled grant-rights policy.");
                            var end=row.ReadAt+_maximumAge;
                            end=Earlier(end,row.Lifetime.AccessExpiration);end=Earlier(end,row.Lifetime.EffectiveHardExpiration);
                            if(entitlements.NextBoundary is {} boundary)end=Earlier(end,boundary);
                            if(entitlements.EligibilityUntil is {} eligibility)end=Earlier(end,eligibility);
                            if(end<=time.GetCurrentInstant()||end<=row.ReadAt)throw new InvalidOperationException("Projection has no live finite interval.");
                            header=header with { State=CachedAuthorityState.Ready };
                            using var record=new CachedAccountAuthority(header,expectedHash,row.ReadAt,end,row.Identity,row.Lifetime,
                                new(true,row.VerificationStatus,row.UnlockWhen,row.AccountStamp,true),entitlements,row.Key);
                            bytes=CoherentCacheCodec.Encode(record);notAfter=end;readyHash=expectedHash;
                        }
                        else if(mapped.Status is not (AuthorityReadStatus.NotFound or AuthorityReadStatus.Unauthenticated))
                            throw new InvalidOperationException("Incomplete current authority projection.");
                    }
                }
            }
            if(bytes is null) { using var blocked=new CachedAccountAuthority(header);bytes=CoherentCacheCodec.Encode(blocked); }
            Check(time,deadline,budget.Token);
            var result=new PreparedAuthorityProjection(lease,bytes,header,notAfter,_space,readyHash,budget,time,deadline);transferred=true;return result;
        }
        finally
        {
            if(!transferred)
            {
                if(bytes is not null)CryptographicOperations.ZeroMemory(bytes);
                budget.Dispose();if(lease is not null)await lease.DisposeAsync();
            }
        }
    }
    private static Instant Earlier(Instant a,Instant b)=>a<b?a:b;
    private static void Check(RequestTimeGuard time,Instant deadline,CancellationToken token)
    { token.ThrowIfCancellationRequested();if(time.GetCurrentInstant()>=deadline||!time.Safe)throw new TimeoutException("Unsafe projection time observation."); }
    private static void ObserveLateCandidate(Task<ProjectionCandidate> task)
    { _=task.ContinueWith(t=>{if(t.IsCompletedSuccessfully)t.Result.Dispose();else _=t.Exception;},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default); }
    private static void ObserveLateLease(Task<IAuthorityProjectionLease> task)
    { _=task.ContinueWith(async t=>{if(t.IsCompletedSuccessfully){try{await t.Result.DisposeAsync();}catch{}}else _=t.Exception;},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default).Unwrap(); }
}
