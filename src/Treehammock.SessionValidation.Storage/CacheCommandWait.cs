using System.Security.Cryptography;
namespace Treehammock.SessionValidation.Storage;
internal static class CacheCommandWait
{
    internal static async Task<byte[]?> ReadAsync(IAuthorityConditionalStore store,string key,CancellationToken token)
    {
        Task<byte[]?>? work=null;bool consumed=false;
        try { token.ThrowIfCancellationRequested();work=store.GetAsync(key,token);var bytes=await work.WaitAsync(token);consumed=true;return bytes; }
        finally
        {
            if(!consumed && work is not null)_=work.ContinueWith(t=>{if(t.IsCompletedSuccessfully && t.Result is {} bytes)CryptographicOperations.ZeroMemory(bytes);else _=t.Exception;},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
        }
    }
    // Takes ownership even when starting the adapter throws synchronously.
    internal static async Task<bool> ExchangeAsync(IAuthorityConditionalStore store,CacheTransition command,CancellationToken token)
    {
        Task<bool>? work=null;
        try { token.ThrowIfCancellationRequested();work=store.ExchangeAsync(command,token);return await work.WaitAsync(token); }
        finally
        {
            if(work is null||work.IsCompleted){if(work is not null)_=work.Exception;command.Dispose();}
            else _=work.ContinueWith(t=>{_=t.Exception;command.Dispose();},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
        }
    }
}
