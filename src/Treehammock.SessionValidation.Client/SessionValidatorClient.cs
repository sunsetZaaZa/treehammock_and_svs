using System.Security.Cryptography;
using System.Text;
using Google.Protobuf;
using Treehammock.SessionValidation.Contracts;
using Treehammock.SessionValidation.Contracts.V1;
namespace Treehammock.SessionValidation.Client;
public enum ValidationDecision{Active,Unauthenticated,Forbidden,Unavailable}
public sealed class ValidatedSubject
{
    internal ValidatedSubject(ValidateReply r){AccountId=UuidCodec.Decode(r.AccountIdUuid);SessionFamilyId=UuidCodec.Decode(r.SessionFamilyUuid);Generation=r.Generation;ProtocolVersion=r.SessionProtocolVersion;ValidUntil=DateTimeOffset.FromUnixTimeMilliseconds(r.ValidUntilUnixMs);}
    public Guid AccountId{get;}public Guid SessionFamilyId{get;}public long Generation{get;}public uint ProtocolVersion{get;}public DateTimeOffset ValidUntil{get;}
    public override string ToString()=>nameof(ValidatedSubject);
}
public sealed class ValidationResult
{
    internal ValidationResult(ValidationDecision d,ValidatedSubject? s=null){Decision=d;Subject=s;}
    public ValidationDecision Decision{get;}public ValidatedSubject? Subject{get;}
    public int HttpStatusCode=>Decision switch{ValidationDecision.Active=>200,ValidationDecision.Unauthenticated=>401,ValidationDecision.Forbidden=>403,_=>503};
    public override string ToString()=>$"ValidationResult({Decision})";
}
// Reuse connections, never positive authorization. One call belongs to one consumer request.
public sealed class SessionValidatorClient:IAsyncDisposable
{
    private readonly ClientOptions _options;private readonly IValidationTransport _transport;private readonly TimeProvider _time;private readonly object _gate=new();private readonly CancellationTokenSource _stop=new();private readonly TaskCompletionSource _drained=new(TaskCreationOptions.RunContinuationsAsynchronously);private int _active;private bool _closed;private Task? _cleanup;private static readonly UTF8Encoding Utf8=new(false,true);
    public SessionValidatorClient(ClientOptions options):this(options.Snapshot(),null,TimeProvider.System){}
    internal SessionValidatorClient(ClientOptions options,IValidationTransport? transport,TimeProvider time){_options=options;_time=time;_transport=transport??new GrpcValidationTransport(options);}
    internal int ActiveCalls{get{lock(_gate)return _active;}}internal Task Cleanup{get{lock(_gate)return _cleanup??Task.CompletedTask;}}
    private static ValidationResult Unavailable()=>new(ValidationDecision.Unavailable);
    public async Task<ValidationResult> ValidateAsync(string accessCredential,string action,DateTimeOffset deadline,CancellationToken cancellationToken=default)
    {
        var started=_time.GetUtcNow();long stamp=_time.GetTimestamp();var effective=started.AddMilliseconds(_options.RequestTimeoutMilliseconds);if(deadline<effective)effective=deadline;
        if(effective<=started||cancellationToken.IsCancellationRequested||!CallerPolicy.IsSupportedAction(action)||string.IsNullOrWhiteSpace(accessCredential)||accessCredential.Length>ContractLimits.CredentialBytes||accessCredential.Any(char.IsControl))return Unavailable();
        try{if(Utf8.GetByteCount(accessCredential)>ContractLimits.CredentialBytes)return Unavailable();}catch(EncoderFallbackException){return Unavailable();}
        lock(_gate){if(_closed||_active==_options.MaximumConcurrentCalls)return Unavailable();_active++;}
        Task<byte[]>? pending=null;byte[]? request=null;byte[]? response=null;bool received=false;
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken,_stop.Token);
        try
        {
            if(!_transport.TrustCurrent)return Unavailable();string requestId=Guid.NewGuid().ToString("N");
            request=new ValidateRequest{ContractVersion=ContractLimits.Version,AccessCredential=ByteString.CopyFrom(Utf8.GetBytes(accessCredential)),RequestedAction=action,RequestId=requestId}.ToByteArray();
            var remaining=effective-_time.GetUtcNow();if(remaining<=TimeSpan.Zero||_time.GetUtcNow()<started)return Unavailable();timeout.CancelAfter(remaining);
            pending=_transport.CallAsync(request,effective,timeout.Token);response=await pending.WaitAsync(timeout.Token);received=true;
            var now=ReceiptTime(started,stamp,effective);if(now is null||timeout.IsCancellationRequested||!_transport.TrustCurrent)return Unavailable();
            var context=new ReplyContext(requestId,_options.PolicyVersion,started,effective,now.Value);if(ContractCodec.DecodeReplyBinary(response,context,out var reply)!=ContractError.None)return Unavailable();
            var decision=reply!.Decision switch{Decision.Active=>ValidationDecision.Active,Decision.Unauthenticated=>ValidationDecision.Unauthenticated,Decision.Forbidden=>ValidationDecision.Forbidden,_=>ValidationDecision.Unavailable};
            var result=new ValidationResult(decision,decision==ValidationDecision.Active?new ValidatedSubject(reply):null);now=ReceiptTime(started,stamp,effective);
            return now is not null&&!timeout.IsCancellationRequested&&_transport.TrustCurrent&&ContractRules.CheckReply(reply,context with{Now=now.Value})==ContractError.None?result:Unavailable();
        }
        catch{return Unavailable();}
        finally
        {
            if(response is not null)CryptographicOperations.ZeroMemory(response);
            if(pending is not null&&!pending.IsCompleted){var owned=request;_=pending.ContinueWith(t=>{if(t.IsCompletedSuccessfully&&!received)CryptographicOperations.ZeroMemory(t.Result);else _=t.Exception;if(owned is not null)CryptographicOperations.ZeroMemory(owned);Release();},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);}
            else{if(pending is{IsCompletedSuccessfully:true}&&!received)CryptographicOperations.ZeroMemory(pending.Result);if(pending is not null)_=pending.Exception;if(request is not null)CryptographicOperations.ZeroMemory(request);Release();}
        }
    }
    private DateTimeOffset? ReceiptTime(DateTimeOffset started,long stamp,DateTimeOffset deadline){var now=_time.GetUtcNow();var elapsed=_time.GetElapsedTime(stamp);if(now<started||elapsed<TimeSpan.Zero||elapsed>=deadline-started)return null;var monotonic=started+elapsed;return now>monotonic?now:monotonic;}
    private void Release(){lock(_gate){_active--;if(_closed&&_active==0)_drained.TrySetResult();}}
    private async Task FinishAsync(){try{await _stop.CancelAsync();}catch{}await _drained.Task;try{_transport.Dispose();}finally{_stop.Dispose();}}
    public async ValueTask DisposeAsync(){Task cleanup;lock(_gate){if(_cleanup is null){_closed=true;if(_active==0)_drained.TrySetResult();_cleanup=FinishAsync();}cleanup=_cleanup;}try{await cleanup.WaitAsync(TimeSpan.FromMilliseconds(_options.ShutdownTimeoutMilliseconds));}catch(TimeoutException){}}
}
