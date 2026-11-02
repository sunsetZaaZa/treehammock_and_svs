using System.Diagnostics.Metrics;
namespace Treehammock.SessionValidation.Api;
internal readonly record struct CapacitySnapshot(int Capacity,int Active,int Peak,long Accepted,long Rejected,int Queued);

// Immediate admission only: no semaphore waiters, linked lists or retry queue.
// Leases are released by raw-operation/response owners, not cancellation timers.
internal sealed class ServiceConcurrencyLimiter
{
    private sealed class Stage(string name){internal readonly string Name=name;internal long Accepted,Rejected,Active;}
    private static readonly Stage[] Stages=[new("requests"),new("foreground-sql"),new("cache-read"),new("raw-cache")];
    private static readonly Meter Meter=new("Treehammock.SessionValidation.Capacity","1.0");
    private static readonly Instrument[] Instruments=[
        Meter.CreateObservableCounter<long>("svs.capacity.accepted",()=>Stages.Select(s=>new Measurement<long>(Interlocked.Read(ref s.Accepted),new KeyValuePair<string,object?>("stage",s.Name)))),
        Meter.CreateObservableCounter<long>("svs.capacity.rejected",()=>Stages.Select(s=>new Measurement<long>(Interlocked.Read(ref s.Rejected),new KeyValuePair<string,object?>("stage",s.Name)))),
        Meter.CreateObservableGauge<long>("svs.capacity.active",()=>Stages.Select(s=>new Measurement<long>(Interlocked.Read(ref s.Active),new KeyValuePair<string,object?>("stage",s.Name))))];
    internal static (string Name,long Accepted,long Rejected,long Active)[] Totals()=>Stages.Select(s=>(s.Name,Interlocked.Read(ref s.Accepted),Interlocked.Read(ref s.Rejected),Interlocked.Read(ref s.Active))).ToArray();
    private readonly Stage _totals;
    private readonly object _sync=new();private readonly int _maximum;
    private int _active,_peak;private long _accepted,_rejected;private bool _closed;
    private TaskCompletionSource _empty=Empty();
    private static TaskCompletionSource Empty(){var value=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);value.SetResult();return value;}
    internal ServiceConcurrencyLimiter(int maximum,string stage="requests")
    {
        if(maximum is <1 or >2048 || stage is not ("requests" or "foreground-sql" or "cache-read" or "raw-cache"))throw new ArgumentException("Bounded capacity and fixed telemetry stage required.");
        _maximum=maximum;_totals=Stages.Single(s=>s.Name==stage);_ = Instruments;
    }
    internal CapacitySnapshot Snapshot{get{lock(_sync)return new(_maximum,_active,_peak,_accepted,_rejected,0);}}
    internal bool Open{get{lock(_sync)return !_closed;}}
    internal IDisposable? TryEnter()
    {
        lock(_sync)
        {
            if(_closed||_active==_maximum){_rejected++;Record(false,0);return null;}
            if(_active++==0)_empty=new(TaskCreationOptions.RunContinuationsAsynchronously);
            _accepted++;_peak=Math.Max(_peak,_active);Record(true,1);return new Lease(this);
        }
    }
    internal IDisposable EnterWith(Func<IDisposable> owner)
    {
        var lease=TryEnter()??throw new InvalidOperationException("Service capacity unavailable.");
        try{return new PairedLease(lease,owner());}catch{lease.Dispose();throw;}
    }
    internal void Close(){lock(_sync)_closed=true;}
    internal Task DrainAsync(CancellationToken token){lock(_sync){_closed=true;return _empty.Task.WaitAsync(token);}}
    private void Record(bool accepted,int delta)
    {
        // Exporters poll these totals; no external callback runs on admission.
        if(delta==0)Interlocked.Increment(ref _totals.Rejected);
        else if(accepted)Interlocked.Increment(ref _totals.Accepted);
        if(delta!=0)Interlocked.Add(ref _totals.Active,delta);
    }
    private void Release(){lock(_sync){if(--_active==0)_empty.TrySetResult();Record(false,-1);}}
    private sealed class Lease(ServiceConcurrencyLimiter owner):IDisposable
    {private ServiceConcurrencyLimiter? _owner=owner;public void Dispose()=>Interlocked.Exchange(ref _owner,null)?.Release();}
    private sealed class PairedLease(IDisposable capacity,IDisposable operation):IDisposable
    {private int _done;public void Dispose(){if(Interlocked.Exchange(ref _done,1)!=0)return;try{operation.Dispose();}finally{capacity.Dispose();}}}
}
