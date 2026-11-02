using System.Security.Cryptography;
using NodaTime;
using Treehammock.SessionValidation.Core;
namespace Treehammock.SessionValidation.Storage;

public enum CachedAuthorityState { Unspecified, Blocked, Ready }
public sealed record CacheAuthorityHeader(string Environment, Guid Epoch, string Policy, string Nonce,
    long Revision, CachedAuthorityState State, Guid AccountId)
{ public override string ToString() => nameof(CacheAuthorityHeader); }
public sealed record CachedAccountState(bool Exists, short VerificationStatus, Instant? UnlockWhen,
    Guid CurrentStamp, bool SessionCurrent)
{ public override string ToString() => nameof(CachedAccountState); }

// Shared, server-only writer/reader storage format. Constructing/decoding it is NOT admission proof.
// Signing bytes are deliberately absent from public properties and all wire contracts.
public sealed class CachedAccountAuthority : IDisposable
{
    private byte[]? _key;
    public CacheAuthorityHeader Header { get; }
    public Instant? ProducedAt { get; }
    public Instant? NotAfter { get; }
    public SessionIdentity? Identity { get; }
    public SessionLifetime? Lifetime { get; }
    public CachedAccountState? Account { get; }
    public EntitlementPolicyInputs? Entitlements { get; }
    internal byte[]? Key => _key;
    public string? CredentialHash { get; }
    public CachedAccountAuthority(CacheAuthorityHeader header) { Header=header; }
    public CachedAccountAuthority(CacheAuthorityHeader header, string credentialHash, Instant producedAt, Instant notAfter,
        SessionIdentity identity, SessionLifetime lifetime, CachedAccountState account,
        EntitlementPolicyInputs entitlements, byte[] signingKey)
    { Header=header;CredentialHash=credentialHash;ProducedAt=producedAt;NotAfter=notAfter;Identity=identity;Lifetime=lifetime;
      Account=account;Entitlements=entitlements;_key=(byte[])signingKey.Clone(); }
    public void Dispose() { var key=Interlocked.Exchange(ref _key,null);if(key is not null)CryptographicOperations.ZeroMemory(key); }
    public override string ToString()=>nameof(CachedAccountAuthority);
}

public sealed class CoherentCacheKeySpace
{
    public string Environment { get; }
    public Guid Epoch { get; }
    public string Policy { get; }
    public CoherentCacheKeySpace(string environment, Guid epoch, string policy)
    {
        if(!IsLabel(environment,32) || epoch==Guid.Empty || !IsLabel(policy,64))throw new ArgumentException("Invalid coherent namespace.");
        Environment=environment;Epoch=epoch;Policy=policy;
    }
    internal static bool IsLabel(string? value,int max)=>value is {Length:>0} && value.Length<=max && value.All(c=>c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.');
    public string CredentialKey(string hash)
    { if(!YsqlSessionAuthority.IsHash(hash))throw new ArgumentException("Invalid binding.");return $"svs:authority:v1:{Environment}:{Epoch:N}:credential:{hash}"; }
    public string AccountKey(Guid account)
    { if(account==Guid.Empty)throw new ArgumentException("Invalid account.");return $"svs:authority:v1:{Environment}:{Epoch:N}:account:{account:N}"; }
    public static string NewTransitionNonce()=>Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public override string ToString()=>nameof(CoherentCacheKeySpace);
}
