using System.Security.Cryptography;
using NodaTime;
namespace Treehammock.SessionValidation.Storage;

internal enum ProjectionPublication { Published, Blocked, Conflict }
internal sealed class ConditionalProjectionPublisher(AuthorityProjectionBuilder builder,IAuthorityConditionalStore store,
    CoherentCacheKeySpace space,TimeSpan budget,IClock? clock=null)
{
    private readonly IClock _clock=clock??SystemClock.Instance;
    internal Task<ProjectionPublication> PublishAsync(Guid account,string hash,Instant deadline,long minimumRevision,CancellationToken caller=default)
        =>minimumRevision<1?throw new ArgumentOutOfRangeException(nameof(minimumRevision)):PublishCoreAsync(account,hash,deadline,minimumRevision,caller);
    // Warmup/repair/refill is a separate server-owned hint: it always acquires and
    // reads current authority, never carries an operation outcome or old payload.
    internal Task<ProjectionPublication> ReconcileAsync(Guid account,string currentHash,Instant deadline,CancellationToken caller=default)
        =>PublishCoreAsync(account,currentHash,deadline,null,caller);
    private async Task<ProjectionPublication> PublishCoreAsync(Guid account,string currentHash,Instant deadline,long? minimumRevision,CancellationToken caller)
    {
        caller.ThrowIfCancellationRequested();var time=new RequestTimeGuard(_clock);var start=time.GetCurrentInstant();
        if(budget<TimeSpan.FromMilliseconds(1)||budget>TimeSpan.FromSeconds(3))throw new ArgumentOutOfRangeException(nameof(budget));
        var end=start+Duration.FromTimeSpan(budget);if(deadline<end)end=deadline;
        Check(time,end,caller);
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(caller);timeout.CancelAfter((end-start).ToTimeSpan());
        // This always acquires a NEW lease and reads current committed DB state.
        // Its guard stays held across GET/init/CAS, including the unknown-outcome path.
        await using var prepared=await builder.PrepareAsync(account,currentHash,end,timeout.Token);
        if(minimumRevision is {} required && prepared.Header.Revision<required)throw new InvalidOperationException("Current authority precedes the established commit.");
        byte[]? prior=null;byte[]? blocked=null;
        try
        {
            prior=await CacheCommandWait.ReadAsync(store,prepared.AccountKey,timeout.Token);Check(time,end,timeout.Token);
            if(prior is null && prepared.Header.State==CachedAuthorityState.Ready)
            {
                using var record=new CachedAccountAuthority(prepared.Header with { State=CachedAuthorityState.Blocked,Nonce=CoherentCacheKeySpace.NewTransitionNonce() });
                blocked=CoherentCacheCodec.Encode(record);
                var initialize=new CacheTransition(space,account,null,blocked);
                if(!await ExchangeGuardedAsync(store,initialize,timeout.Token))return ProjectionPublication.Conflict;
                Check(time,end,timeout.Token);prior=blocked;blocked=null;
            }
            var now=time.GetCurrentInstant();Check(time,end,timeout.Token);
            int ttl=prepared.NotAfter is {} notAfter?(int)Math.Floor((notAfter-now).TotalMilliseconds):0;
            if(prepared.Header.State==CachedAuthorityState.Ready && ttl<1)throw new TimeoutException("Projection interval elapsed.");
            var transition=new CacheTransition(space,account,prior,prepared.Payload,ttl);
            if(!await ExchangeGuardedAsync(store,transition,timeout.Token))return ProjectionPublication.Conflict;
            Check(time,end,timeout.Token);_=prepared.Payload;
            return prepared.Header.State==CachedAuthorityState.Ready?ProjectionPublication.Published:ProjectionPublication.Blocked;
        }
        finally {if(prior is not null)CryptographicOperations.ZeroMemory(prior);if(blocked is not null)CryptographicOperations.ZeroMemory(blocked);}
    }
    // Keep the owning SQL lease through actual transport completion, including cancellation.
    private static async Task<bool> ExchangeGuardedAsync(IAuthorityConditionalStore store,CacheTransition command,CancellationToken token)
    {using(command){token.ThrowIfCancellationRequested();var result=await store.ExchangeAsync(command,token);token.ThrowIfCancellationRequested();return result;}}
    private static void Check(RequestTimeGuard time,Instant deadline,CancellationToken token)
    {token.ThrowIfCancellationRequested();if(time.GetCurrentInstant()>=deadline||!time.Safe)throw new TimeoutException("Unsafe publication time observation.");}
    public override string ToString()=>nameof(ConditionalProjectionPublisher);
}
