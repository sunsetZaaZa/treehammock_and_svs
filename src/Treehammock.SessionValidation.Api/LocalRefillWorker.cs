using System.Diagnostics;
using Treehammock.SessionValidation.Storage;
namespace Treehammock.SessionValidation.Api;
internal interface ILocalPublication : IAsyncDisposable
{
    bool Ready {get;}
    Task PublishAsync(GuardedSessionRefillRequest work,CancellationToken token);
    Task<IReadOnlyList<string>> ScanAsync(string? after,int limit,CancellationToken token);
}
internal sealed class LocalRefillWorker : IGuardedSessionRefillQueue,IAsyncDisposable
{
    private readonly object _sync=new();
    private readonly RefillSettings _settings;
    private readonly ILocalPublication _publisher;
    private readonly Func<Guid,bool> _epoch;
    private readonly Queue<(GuardedSessionRefillRequest Work,long At)> _queue=[];
    private readonly HashSet<(string,Guid)> _owned=[];
    private readonly Dictionary<(string,Guid),long> _recent=[];
    private readonly CancellationTokenSource _stop=new();
    private readonly SemaphoreSlim _available=new(0);
    private readonly Task[] _loops;
    private readonly Task _scan;
    private bool _closed;
    private Task? _finish;
    private double _tokens;
    private long _refilled=Stopwatch.GetTimestamp();
    internal LocalRefillWorker(RefillSettings settings,ILocalPublication publisher,Func<Guid,bool> epoch)
    {
        settings.ValidateBounds();_settings=settings;_publisher=publisher;_epoch=epoch;_tokens=settings.PublicationsPerSecond;
        _loops=Enumerable.Range(0,settings.Workers).Select(_=>RunAsync()).ToArray();_scan=settings.WarmupIntervalMilliseconds==0?Task.CompletedTask:ScanLoopAsync();
    }
    internal int OwnedCount{get{lock(_sync)return _owned.Count;}}
    internal int RecentCount{get{lock(_sync)return _recent.Count;}}
    public bool TryRequest(string hash,Guid epoch)
    {
        if(!HostSettings.Pin(hash)||epoch==Guid.Empty)return false;
        lock(_sync)
        {
            if(_closed)return false;var key=(hash,epoch);long now=Stopwatch.GetTimestamp();
            if(_owned.Contains(key))return true;
            if(_recent.TryGetValue(key,out var at)&&Stopwatch.GetElapsedTime(at,now).TotalMilliseconds<_settings.CompletedCooldownMilliseconds)return true;
            if(_owned.Count==_settings.QueueCapacity)return false;
            _owned.Add(key);_queue.Enqueue((new(hash,epoch),now));_available.Release();return true;
        }
    }
    private async Task PermitAsync(CancellationToken token)
    {
        while(true)
        {
            double seconds;
            lock(_sync)
            {
                long now=Stopwatch.GetTimestamp();_tokens=Math.Min(_settings.PublicationsPerSecond,_tokens+Stopwatch.GetElapsedTime(_refilled,now).TotalSeconds*_settings.PublicationsPerSecond);_refilled=now;
                if(_tokens>=1){_tokens--;return;}seconds=(1-_tokens)/_settings.PublicationsPerSecond;
            }
            await Task.Delay(TimeSpan.FromSeconds(seconds),token);
        }
    }
    private async Task RunAsync()
    {
        try
        {
            while(true)
            {
                await _available.WaitAsync(_stop.Token);(GuardedSessionRefillRequest Work,long At) item;
                lock(_sync){if(_closed)return;item=_queue.Dequeue();}
                try
                {
                    await PermitAsync(_stop.Token);
                    if(Stopwatch.GetElapsedTime(item.At).TotalMilliseconds>=_settings.MaximumQueueAgeMilliseconds||!_epoch(item.Work.ExpectedEpoch)||!_publisher.Ready)continue;
                    using var budget=CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);budget.CancelAfter(_settings.OperationTimeoutMilliseconds);
                    // No WaitAsync releases ownership ahead of the actual provider's cleanup.
                    await _publisher.PublishAsync(item.Work,budget.Token);
                }
                catch(OperationCanceledException){}
                catch{/* Drop. A later independent miss can try after bounded cooldown. */}
                finally
                {
                    lock(_sync)
                    {
                        var key=(item.Work.CredentialHash,item.Work.ExpectedEpoch);_owned.Remove(key);
                        if(_recent.Count>=_settings.QueueCapacity&&!_recent.ContainsKey(key))_recent.Remove(_recent.MinBy(x=>x.Value).Key);
                        _recent[key]=Stopwatch.GetTimestamp();
                    }
                }
            }
        }
        catch(OperationCanceledException)when(_stop.IsCancellationRequested){}
    }
    private async Task ScanLoopAsync()
    {
        string? after=null;
        try
        {
            using var timer=new PeriodicTimer(TimeSpan.FromMilliseconds(_settings.WarmupIntervalMilliseconds));
            while(await timer.WaitForNextTickAsync(_stop.Token))
            {
                if(!_publisher.Ready||!_epoch(_settings.Epoch))continue;
                try
                {
                    using var budget=CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);budget.CancelAfter(_settings.OperationTimeoutMilliseconds);
                    var hashes=await _publisher.ScanAsync(after,Math.Min(_settings.QueueCapacity,128),budget.Token);
                    if(hashes.Count>128)throw new InvalidOperationException("Bounded scan required.");
                    foreach(string h in hashes){budget.Token.ThrowIfCancellationRequested();TryRequest(h,_settings.Epoch);}
                    after=hashes.Count==0?null:hashes[^1];
                }
                catch(OperationCanceledException)when(_stop.IsCancellationRequested){throw;}
                catch{/* No replacement scan until the actual prior operation settled. */}
            }
        }
        catch(OperationCanceledException)when(_stop.IsCancellationRequested){}
    }
    internal Task StopAsync()
    {
        lock(_sync)
        {
            if(_finish is not null)return _finish;_closed=true;
            while(_queue.TryDequeue(out var item))_owned.Remove((item.Work.CredentialHash,item.Work.ExpectedEpoch));
            // Cancel callbacks may reenter diagnostics or wait for the worker lock.
            // Run them after leaving this lock, retaining the one finish task.
            return _finish=Task.Run(async()=>{await _stop.CancelAsync();await FinishAsync();});
        }
    }
    private async Task FinishAsync(){try{await Task.WhenAll(_loops.Append(_scan));}finally{await _publisher.DisposeAsync();_stop.Dispose();_available.Dispose();}}
    public async ValueTask DisposeAsync(){try{await StopAsync().WaitAsync(TimeSpan.FromSeconds(3));}catch(TimeoutException){}}
    public override string ToString()=>nameof(LocalRefillWorker);
}
