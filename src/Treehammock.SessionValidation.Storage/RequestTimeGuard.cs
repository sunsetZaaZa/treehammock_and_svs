using NodaTime;
namespace Treehammock.SessionValidation.Storage;

// Per-request observed clock monotonicity, shared across cache, verification and final publication.
internal sealed class RequestTimeGuard(IClock clock) : IClock
{
    private readonly object _gate=new();
    private Instant? _latest;
    private bool _safe=true;
    internal bool Safe { get {lock(_gate)return _safe;} }
    public Instant GetCurrentInstant()
    {
        lock(_gate)
        {
            var now=clock.GetCurrentInstant();
            if(_latest is { } previous&&now<previous)_safe=false;
            if(_latest is null||now>_latest)_latest=now;
            return now;
        }
    }
}
