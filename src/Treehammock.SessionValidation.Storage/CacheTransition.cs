using System.Security.Cryptography;
namespace Treehammock.SessionValidation.Storage;

internal interface IAuthorityConditionalStore
{
    bool Available { get; }
    // Results/arguments are owned by the caller. An adapter that abandons a native
    // wait must retain its own copies until that command actually completes.
    Task<byte[]?> GetAsync(string accountKey,CancellationToken token);
    Task<bool> ExchangeAsync(CacheTransition transition,CancellationToken token);
}
internal sealed class CacheTransition : IDisposable
{
    internal byte[]? Prior { get; }
    internal byte[] Next { get; }
    internal CacheAuthorityHeader Header { get; }
    internal CacheAuthorityHeader? PriorHeader { get; }
    internal string AccountKey { get; }
    internal string? CredentialKey { get; }
    internal string? Hash { get; }
    internal int TtlMilliseconds { get; }
    internal CacheTransition(CoherentCacheKeySpace space,Guid account,byte[]? prior,ReadOnlyMemory<byte> next,int ttlMilliseconds=0)
    {
        using var decoded=Decode(next,space,account);Header=decoded.Header;
        using var previous=prior is null?null:Decode(prior,space,account);PriorHeader=previous?.Header;
        if(previous is null && Header.State!=CachedAuthorityState.Blocked || previous is not null &&
            (Header.Nonce==previous.Header.Nonce || Header.Revision<previous.Header.Revision ||
             Header.State==CachedAuthorityState.Ready && previous.Header.State==CachedAuthorityState.Ready && Header.Revision!=previous.Header.Revision))
            throw new InvalidOperationException("Unsafe authority transition.");
        if(Header.State==CachedAuthorityState.Ready)
        {
            if(ttlMilliseconds is <1 or >300000)throw new ArgumentOutOfRangeException(nameof(ttlMilliseconds));
            Hash=decoded.CredentialHash!;CredentialKey=space.CredentialKey(Hash);
        }
        else if(ttlMilliseconds!=0)throw new ArgumentException("Blocked fences must persist.");
        AccountKey=space.AccountKey(account);TtlMilliseconds=ttlMilliseconds;
        Prior=prior?.ToArray();Next=next.ToArray();
    }
    internal static CachedAccountAuthority Decode(ReadOnlyMemory<byte> bytes,CoherentCacheKeySpace space,Guid account)
    {
        if(!CoherentCacheCodec.TryDecode(bytes,out var decoded))throw new InvalidOperationException("Malformed authority cache record.");
        var h=decoded!.Header;
        if(h.Environment!=space.Environment||h.Epoch!=space.Epoch||h.Policy!=space.Policy||h.AccountId!=account)
        { decoded.Dispose();throw new InvalidOperationException("Foreign authority namespace or account."); }
        return decoded;
    }
    public void Dispose(){if(Prior is {} p)CryptographicOperations.ZeroMemory(p);CryptographicOperations.ZeroMemory(Next);}
    public override string ToString()=>nameof(CacheTransition);
}

