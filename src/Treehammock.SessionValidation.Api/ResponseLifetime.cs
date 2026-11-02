namespace Treehammock.SessionValidation.Api;

// Request slots cover both the downstream task and actual response completion.
// Aborting transport does not release an uncooperative downstream provider.
internal sealed class ResponseLifetime
{
    private readonly IDisposable _request;
    private readonly IDisposable? _fleet;
    private readonly CancellationTokenSource _timeout;
    private CancellationTokenRegistration _aborted;
    private int _response,_downstream,_released;
    internal ResponseLifetime(HttpContext context,IDisposable request,IDisposable? fleet,int milliseconds)
    {
        _request=request;_fleet=fleet;
        var original=context.RequestAborted;
        _timeout=CancellationTokenSource.CreateLinkedTokenSource(original);
        context.Response.OnCompleted(()=>{ResponseDone();return Task.CompletedTask;});
        _aborted=original.Register(ResponseDone);
        context.RequestAborted=_timeout.Token;_timeout.CancelAfter(milliseconds);
    }
    internal void ResponseDone(){Interlocked.Exchange(ref _response,1);Release();}
    internal void DownstreamDone(){Interlocked.Exchange(ref _downstream,1);Release();}
    private void Release()
    {
        if(Volatile.Read(ref _response)==0||Volatile.Read(ref _downstream)==0||Interlocked.Exchange(ref _released,1)!=0)return;
        _aborted.Unregister();_timeout.Dispose();_fleet?.Dispose();_request.Dispose();
    }
}
