using Treehammock.SessionValidation.Storage;
namespace Treehammock.SessionValidation.Api;

// Preserve the exact shared builder while owning late native acquisition/read
// tasks beyond its caller-facing cancellation window.
internal sealed class OwnedProjectionLeases(IAuthorityProjectionLeaseFactory inner,Func<IDisposable> ownership):IAuthorityProjectionLeaseFactory
{
    public async Task<IAuthorityProjectionLease> AcquireAsync(Guid account,TimeSpan budget,CancellationToken token)
    {
        var owner=ownership();
        try{return new Lease(await inner.AcquireAsync(account,budget,token),owner);}
        catch{owner.Dispose();throw;}
    }
    private sealed class Lease(IAuthorityProjectionLease inner,IDisposable owner):IAuthorityProjectionLease
    {
        private Task<ProjectionCandidate>? _read;
        private int _disposed;
        public AuthorityVersion? Authority=>inner.Authority;
        public Task<ProjectionCandidate> ReadCurrentAsync(string hash,CancellationToken token)=>_read=inner.ReadCurrentAsync(hash,token);
        public async ValueTask DisposeAsync()
        {
            if(Interlocked.Exchange(ref _disposed,1)!=0)return;
            try
            {
                if(_read is {} read)try{await read;}catch{/* Owning builder observes/erases the result. */}
                await inner.DisposeAsync();
            }
            finally{owner.Dispose();}
        }
    }
}
