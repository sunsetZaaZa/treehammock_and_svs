using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;

namespace treehammock.Rigging.Delivery;

// A deadline bounds the caller's wait; ownership bounds unfinished local work.
public sealed class DeliveryExecutionPolicy : IHostedService
{
    public static DeliveryExecutionPolicy Default { get; } = new(Options.Create(new DeliveryOutboxSettings()));
    private static readonly AsyncLocal<DeliveryBudget?> Ambient = new();
    private readonly SemaphoreSlim _capacity;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly ConcurrentDictionary<Guid,Task> _owned = new();
    private readonly TimeSpan _total, _attempt, _drain;
    public int ActiveOperations => _owned.Count;
    public int AvailableCapacity => _capacity.CurrentCount;
    public DeliveryExecutionPolicy(IOptions<DeliveryOutboxSettings> options)
    {
        var s=options.Value;
        if(s.ProviderTimeoutSeconds is <1 or >30 || s.ProviderAttemptTimeoutSeconds is <1 or >30 || s.ProviderAttemptTimeoutSeconds>s.ProviderTimeoutSeconds || s.CancellationDrainSeconds is <1 or >5 || s.MaxConcurrentSends is <1 or >8)
            throw new ArgumentException("Invalid delivery execution budgets.");
        _total=TimeSpan.FromSeconds(s.ProviderTimeoutSeconds);_attempt=TimeSpan.FromSeconds(s.ProviderAttemptTimeoutSeconds);
        _drain=TimeSpan.FromSeconds(s.CancellationDrainSeconds);_capacity=new(s.MaxConcurrentSends,s.MaxConcurrentSends);
    }
    public async Task<T> RunAsync<T>(CancellationToken token,Func<DeliveryBudget,Task<T>> action,Func<T> notStarted,Func<T> unknown,
        DateTimeOffset? expiresAt=null,Func<CancellationToken,Task<bool>>? canSend=null,Func<T,Task>? lateResult=null)
    {
        // Nested throttle/provider/SMTP/SMS boundaries inherit the same absolute budget and slot.
        if(Ambient.Value is { } inherited)return await action(inherited);
        var budget=new DeliveryBudget(_total,_attempt,token,_shutdown.Token,expiresAt,canSend);
        bool acquired=false,transferred=false;Guid owner=Guid.NewGuid();var finished=new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            try {await _capacity.WaitAsync(budget.Token);acquired=true;budget.Token.ThrowIfCancellationRequested();}
            catch(OperationCanceledException){return notStarted();}
            if(!budget.HasTimeRemaining)return notStarted();
            _owned[owner]=finished.Task;
            Task<T> work=InvokeAsync(action,budget);
            if(!await CompleteBeforeCancellation(work,budget.Token))
            {
                budget.Cancel();
                await Task.WhenAny(work,Task.Delay(_drain));
                if(!work.IsCompleted)
                {
                    transferred=true;
                    _=ObserveOwnedAsync(work,budget,owner,finished,lateResult);
                    return unknown();
                }
            }
            try {return await work;}
            catch {return unknown();}
        }
        finally
        {
            if(!transferred){budget.Dispose();if(acquired){_owned.TryRemove(owner,out _);_capacity.Release();finished.TrySetResult(true);}}
        }
    }
    private static async Task<T> InvokeAsync<T>(Func<DeliveryBudget,Task<T>> action,DeliveryBudget budget)
    {
        var prior=Ambient.Value;Ambient.Value=budget;
        try {return await action(budget);}finally{Ambient.Value=prior;}
    }
    private static async Task<bool> CompleteBeforeCancellation(Task work,CancellationToken token)
    {
        using var waiter=CancellationTokenSource.CreateLinkedTokenSource(token);
        try {await Task.WhenAny(work,Task.Delay(Timeout.InfiniteTimeSpan,waiter.Token));return work.IsCompleted;}
        finally {waiter.Cancel();}
    }
    private async Task ObserveOwnedAsync<T>(Task<T> work,DeliveryBudget budget,Guid owner,TaskCompletionSource<bool> finished,Func<T,Task>? lateResult)
    {
        // Never release/reuse a slot merely because its caller stopped waiting. Observe every fault.
        try {T result=await work;if(lateResult is not null)await lateResult(result);}catch { /* Durable Unknown/abandoned claim remains authoritative. */ }
        finally {budget.Dispose();_owned.TryRemove(owner,out _);_capacity.Release();finished.TrySetResult(true);}
    }
    public Task StartAsync(CancellationToken token)=>Task.CompletedTask;
    public async Task StopAsync(CancellationToken token)
    {
        _shutdown.Cancel();
        var work=Task.WhenAll(_owned.Values.ToArray());
        await Task.WhenAny(work,Task.Delay(_drain,token));
        // Uncooperative work remains tracked and retains capacity; shutdown cannot assert its termination.
    }
}

public sealed class DeliveryBudget : IDisposable
{
    private readonly CancellationTokenSource _source;
    private readonly Stopwatch _elapsed=Stopwatch.StartNew();
    private readonly TimeSpan _total,_attempt;
    private readonly Func<CancellationToken,Task<bool>>? _canSend;
    public CancellationToken Token=>_source.Token;
    public bool HasTimeRemaining=>!Token.IsCancellationRequested && _elapsed.Elapsed<_total;
    internal DeliveryBudget(TimeSpan total,TimeSpan attempt,CancellationToken caller,CancellationToken shutdown,DateTimeOffset? expiresAt,Func<CancellationToken,Task<bool>>? canSend)
    {
        _total=expiresAt is { } expiry ? TimeSpan.FromTicks(Math.Max(0,Math.Min(total.Ticks,(expiry-DateTimeOffset.UtcNow).Ticks))) : total;
        _attempt=attempt;_canSend=canSend;_source=CancellationTokenSource.CreateLinkedTokenSource(caller,shutdown);
        _source.CancelAfter(_total);
    }
    public void Cancel()=>_source.Cancel();
    public async Task<bool> CheckAuthorityAsync()
    {
        if(Token.IsCancellationRequested || _elapsed.Elapsed>=_total)return false;
        bool live=_canSend is null || await _canSend(Token);
        return live && !Token.IsCancellationRequested && _elapsed.Elapsed<_total;
    }
    public async Task<DeliveryAttemptBudget?> BeginAttemptAsync(CancellationToken caller)
    {
        if(caller.IsCancellationRequested || !await CheckAuthorityAsync())return null;
        TimeSpan left=_total-_elapsed.Elapsed;if(left<=TimeSpan.Zero)return null;
        return new(Token,caller,left<_attempt?left:_attempt,Cancel);
    }
    public void Dispose()=>_source.Dispose();
}

public sealed class DeliveryAttemptBudget : IDisposable
{
    private readonly CancellationTokenSource _source;
    private readonly CancellationTokenRegistration _stopChain;
    public CancellationToken Token=>_source.Token;
    internal DeliveryAttemptBudget(CancellationToken root,CancellationToken caller,TimeSpan timeout,Action stopChain)
    {
        _source=CancellationTokenSource.CreateLinkedTokenSource(root,caller);
        _stopChain=_source.Token.Register(stopChain);_source.CancelAfter(timeout);
    }
    public void Dispose(){_stopChain.Dispose();_source.Dispose();}
}
