namespace Treehammock.SessionValidation.Storage;

public sealed record GuardedSessionRefillRequest(string CredentialHash,Guid ExpectedEpoch)
{ public override string ToString()=>nameof(GuardedSessionRefillRequest); }

// Hint queue only. A later admitted mTLS worker consumes it; nothing here publishes cache state.
public sealed class BoundedSessionRefillQueue : IGuardedSessionRefillQueue
{
    private readonly int _capacity;
    private readonly object _gate=new();
    private readonly Queue<GuardedSessionRefillRequest> _queue=new();
    private readonly HashSet<(string,Guid)> _queued=new();
    public BoundedSessionRefillQueue(int capacity=128)
    { if(capacity is <1 or >1024)throw new ArgumentOutOfRangeException(nameof(capacity));_capacity=capacity; }
    public bool TryRequest(string credentialHash,Guid expectedEpoch)
    {
        if(!YsqlSessionAuthority.IsHash(credentialHash)||expectedEpoch==Guid.Empty)return false;
        lock(_gate)
        {
            if(_queued.Contains((credentialHash,expectedEpoch)))return true;
            if(_queue.Count==_capacity)return false;
            _queued.Add((credentialHash,expectedEpoch));_queue.Enqueue(new(credentialHash,expectedEpoch));return true;
        }
    }
    public bool TryTake(out GuardedSessionRefillRequest? request)
    {
        lock(_gate)
        {
            if(!_queue.TryDequeue(out request))return false;
            _queued.Remove((request.CredentialHash,request.ExpectedEpoch));return true;
        }
    }
    public override string ToString()=>nameof(BoundedSessionRefillQueue);
}
