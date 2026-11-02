namespace Treehammock.SessionValidation.Api;
// Request slots remain held until downstream and response ownership settle.
internal sealed class RequestLifetime
{
    private readonly ServiceConcurrencyLimiter _limiter;
    internal RequestLifetime(int maximum,string stage="requests")=>_limiter=new(maximum,stage);
    internal int Active=>_limiter.Snapshot.Active;
    internal bool Open=>_limiter.Open;
    internal CapacitySnapshot Snapshot=>_limiter.Snapshot;
    internal IDisposable? TryEnter()=>_limiter.TryEnter();
    internal void Close()=>_limiter.Close();
    internal Task DrainAsync(CancellationToken token)=>_limiter.DrainAsync(token);
}
