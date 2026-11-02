using System.Security.Cryptography;
using System.Text;
using NodaTime;
using StackExchange.Redis;
using Treehammock.SessionValidation.Core;
namespace Treehammock.SessionValidation.Storage;

// Transport contract returns an owned byte array. No cache mutation commands exist on this surface.
public interface ICoherentCacheGetStore
{ Task<byte[]?> GetAsync(string key,CancellationToken cancellationToken); }

public sealed class DragonflyGetStore : ICoherentCacheGetStore,IDisposable
{
    private readonly IDatabase _database;
    private readonly IConnectionMultiplexer _connection;
    private readonly SessionCacheAdmission _admission;
    public DragonflyGetStore(IConnectionMultiplexer connection,SessionCacheAdmission admission,int database=0)
    {
        _database=connection.GetDatabase(database);_connection=connection;_admission=admission;
        connection.ConnectionFailed+=ConnectionChanged;connection.ConnectionRestored+=ConnectionChanged;
        connection.ConfigurationChanged+=ConfigurationChanged;connection.ConfigurationChangedBroadcast+=ConfigurationChanged;
    }
    private void ConnectionChanged(object? sender,ConnectionFailedEventArgs e)=>_admission.Quarantine();
    private void ConfigurationChanged(object? sender,EndPointEventArgs e)=>_admission.Quarantine();
    public void Dispose()
    {
        _admission.Quarantine();_connection.ConnectionFailed-=ConnectionChanged;_connection.ConnectionRestored-=ConnectionChanged;
        _connection.ConfigurationChanged-=ConfigurationChanged;_connection.ConfigurationChangedBroadcast-=ConfigurationChanged;
    }
    public async Task<byte[]?> GetAsync(string key,CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Caller must pin/qualify the actual primary before future admission. DemandMaster alone
        // does not prove endpoint/epoch identity or safe asynchronous failover.
        var pending=_database.StringGetAsync(key,CommandFlags.DemandMaster|CommandFlags.NoRedirect);
        bool consumed=false;
        try
        {
            var value=await pending.WaitAsync(cancellationToken);consumed=true;
            return value.IsNull?null:(byte[]?)value;
        }
        catch(RedisException){_admission.Quarantine();throw;}
        finally
        {
            if(!consumed)_=pending.ContinueWith(t=>{
                if(t.IsCompletedSuccessfully){byte[]? bytes=(byte[]?)t.Result;if(bytes is not null)CryptographicOperations.ZeroMemory(bytes);}
                else _=t.Exception;
            },CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
        }
    }
    public override string ToString()=>nameof(DragonflyGetStore);
}

// Public construction is unadmitted. Only the friend application can install the
// actual process/connection/fleet lifetime. One incarnation per instance, no re-enable.
public sealed class SessionCacheAdmission
{
    private CacheAdmissionSnapshot? _current;
    private int _quarantined,_admitted;
    public bool CacheReady=>Capture() is not null;
    // SVS-08 read-only hint query retained; never grants admission.
    public bool IsCurrentEpoch(Guid epoch)=>epoch!=Guid.Empty && Capture()?.Space.Epoch==epoch;
    public void Quarantine(){Interlocked.Exchange(ref _quarantined,1);Volatile.Write(ref _current,null);}
    internal CacheAdmissionSnapshot? Capture()
    {
        var snapshot=Volatile.Read(ref _current);
        return Volatile.Read(ref _quarantined)==0&&snapshot is not null&&(snapshot.Current?.Invoke()??true)?snapshot:null;
    }
    internal bool IsCurrent(CacheAdmissionSnapshot snapshot)=>ReferenceEquals(Capture(),snapshot);
    internal void Admit(CoherentCacheKeySpace space,ICoherentCacheGetStore store,Func<bool> current)
    {
        ArgumentNullException.ThrowIfNull(current);
        if(!current()||Volatile.Read(ref _quarantined)!=0||Interlocked.CompareExchange(ref _admitted,1,0)!=0)
            throw new InvalidOperationException("Reader incarnation cannot be admitted.");
        Volatile.Write(ref _current,new(space,store,current));
        if(!current()||Volatile.Read(ref _quarantined)!=0)Quarantine();
    }
    internal static SessionCacheAdmission ForQualification(CoherentCacheKeySpace space,ICoherentCacheGetStore store)
    { var gate=new SessionCacheAdmission();gate._current=new(space,store);return gate; }
    public override string ToString()=>nameof(SessionCacheAdmission);
}
internal sealed record CacheAdmissionSnapshot(CoherentCacheKeySpace Space,ICoherentCacheGetStore Store,Func<bool>? Current=null)
{ public override string ToString()=>nameof(CacheAdmissionSnapshot); }

internal sealed class CacheSessionEvidence(AuthSessionProjection projection,CacheAdmissionSnapshot admission,
    Instant producedAt,Instant notAfter) : IDisposable
{
    internal AuthSessionProjection Projection { get; }=projection;
    internal CacheAdmissionSnapshot Admission { get; }=admission;
    internal Instant ProducedAt { get; }=producedAt;
    internal Instant NotAfter { get; }=notAfter;
    public void Dispose()=>Projection.Dispose();
}

public sealed class CoherentSessionCacheReader
{
    private readonly ICoherentCacheGetStore _store;
    private readonly Duration _maximumAge;
    private readonly TimeSpan _budget;
    internal SessionCacheAdmission Admission { get; }
    public CoherentSessionCacheReader(ICoherentCacheGetStore store,SessionCacheAdmission admission,
        TimeSpan cacheBudget,TimeSpan maximumProjectionAge)
    {
        if(cacheBudget<TimeSpan.FromMilliseconds(1)||cacheBudget>TimeSpan.FromSeconds(3)||maximumProjectionAge<TimeSpan.FromMilliseconds(1)||maximumProjectionAge>TimeSpan.FromMinutes(5))throw new ArgumentOutOfRangeException(nameof(cacheBudget));
        _store=store;Admission=admission;_budget=cacheBudget;_maximumAge=Duration.FromTimeSpan(maximumProjectionAge);
    }
    internal async Task<CacheSessionEvidence?> ReadAsync(string hash,Instant deadline,CancellationToken cancellationToken,RequestTimeGuard time)
    {
        cancellationToken.ThrowIfCancellationRequested();var snapshot=Admission.Capture();var before=time.GetCurrentInstant();
        if(snapshot is null||!ReferenceEquals(snapshot.Store,_store)||!YsqlSessionAuthority.IsHash(hash)||deadline<=before)return null;
        using var budget=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(TimeSpan.FromTicks(Math.Min(_budget.Ticks,(deadline-before).ToTimeSpan().Ticks)));
        try
        {
            Guid account;
            byte[]? index=await GetOwned(snapshot.Space.CredentialKey(hash),budget.Token);
            try
            {
                if(!Current(snapshot,before,deadline,budget.Token,time)||index is not {Length:32})return null;
                string hint=new UTF8Encoding(false,true).GetString(index);
                if(!Guid.TryParseExact(hint,"N",out account)||account==Guid.Empty||hint!=account.ToString("N"))return null;
            }
            finally { if(index is not null)CryptographicOperations.ZeroMemory(index); }
            byte[]? bytes=await GetOwned(snapshot.Space.AccountKey(account),budget.Token);
            try
            {
                var now=time.GetCurrentInstant();
                if(!Current(snapshot,before,deadline,budget.Token,time)||bytes is null||!CoherentCacheCodec.TryDecode(bytes,out var decoded))return null;
                using var record=decoded!;
                var h=record.Header;var i=record.Identity;var l=record.Lifetime;var a=record.Account;var t=record.Entitlements;
                if(h.State!=CachedAuthorityState.Ready||h.Environment!=snapshot.Space.Environment||h.Epoch!=snapshot.Space.Epoch||h.Policy!=snapshot.Space.Policy||h.AccountId!=account||record.CredentialHash!=hash||
                    i is null||l is null||a is null||t is null||record.Key is null||record.ProducedAt is not { } produced||record.NotAfter is not { } end)return null;
                if(!i.Value.IsWellFormed||i.Value.AccountId!=account||a.CurrentStamp!=i.Value.AccountStamp||!a.Exists||!a.SessionCurrent||a.VerificationStatus!=1||a.UnlockWhen>produced||
                    produced>now||end<=now||end<=produced||end>produced+_maximumAge||
                    end>l.Value.AccessExpiration||end>l.Value.EffectiveHardExpiration||
                    (t.NextBoundary is { } boundary&&end>boundary)||(t.EligibilityUntil is { } eligibility&&end>eligibility)||
                    t.RightsEnabled||t.EvaluatedAt>produced||!EntitlementRules.IsCurrent(account,t.AccountId,t.Version,t.FeatureTier,t.Capabilities,t.GrantsPresent,t.RightsEnabled,t.EvaluatedAt,t.NextBoundary,now))return null;
                return new(new(hash,record.Key,i.Value,l.Value,t,produced),snapshot,produced,end);
            }
            finally { if(bytes is not null)CryptographicOperations.ZeroMemory(bytes); }
        }
        catch(OperationCanceledException)when(cancellationToken.IsCancellationRequested){throw;}
        catch(Exception){return null;}
    }
    private bool Current(CacheAdmissionSnapshot snapshot,Instant before,Instant deadline,CancellationToken token,RequestTimeGuard time)
    { var now=time.GetCurrentInstant();return time.Safe&&!token.IsCancellationRequested&&Admission.IsCurrent(snapshot)&&now>=before&&now<deadline; }
    private async Task<byte[]?> GetOwned(string key,CancellationToken token)
    {
        Task<byte[]?> pending=_store.GetAsync(key,token);bool consumed=false;
        try { var bytes=await pending.WaitAsync(token);consumed=true;return bytes; }
        finally
        { if(!consumed)_=pending.ContinueWith(t=>{if(t.IsCompletedSuccessfully&&t.Result is { } bytes)CryptographicOperations.ZeroMemory(bytes);else _=t.Exception;},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default); }
    }
    public override string ToString()=>nameof(CoherentSessionCacheReader);
}
