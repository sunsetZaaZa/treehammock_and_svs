using System.Globalization;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using StackExchange.Redis;
namespace Treehammock.SessionValidation.Storage;

internal sealed class DragonflyAuthorityStore : IAuthorityConditionalStore,IDisposable
{
    private readonly IConnectionMultiplexer _connection;
    private readonly IDatabase _database;
    private readonly CoherentCacheKeySpace _space;
    private readonly EndPoint _endpoint;
    private readonly SemaphoreSlim _slots;
    private int _quarantined;
    internal static readonly string Script=ReadScript();
    private static string ReadScript()
    { using var stream=typeof(DragonflyAuthorityStore).Assembly.GetManifestResourceStream("Treehammock.SessionValidation.Storage.authority-transition.lua")??throw new InvalidOperationException("Missing authority primitive.");using var reader=new StreamReader(stream);return reader.ReadToEnd(); }
    internal DragonflyAuthorityStore(IConnectionMultiplexer connection,int database,CoherentCacheKeySpace space,int maximumConcurrentCommands)
    {
        if(maximumConcurrentCommands is <1 or >64)throw new ArgumentOutOfRangeException(nameof(maximumConcurrentCommands));
        _connection=connection;_database=connection.GetDatabase(database);_space=space;_slots=new(maximumConcurrentCommands,maximumConcurrentCommands);
        var endpoints=connection.GetEndPoints(true);if(endpoints.Length!=1)throw new ArgumentException("One configured primary required.");_endpoint=endpoints[0];
        connection.ConnectionFailed+=ConnectionChanged;connection.ConnectionRestored+=ConnectionChanged;
        connection.ConfigurationChanged+=ConfigurationChanged;connection.ConfigurationChangedBroadcast+=ConfigurationChanged;connection.ErrorMessage+=ServerError;
        try {Check();}catch {Dispose();throw;}
    }
    private void ConnectionChanged(object? sender,ConnectionFailedEventArgs e)=>Quarantine();
    private void ConfigurationChanged(object? sender,EndPointEventArgs e)=>Quarantine();
    private void ServerError(object? sender,RedisErrorEventArgs e)=>Quarantine();
    public bool Available=>Ready&&_connection.IsConnected;
    internal bool Ready=>Volatile.Read(ref _quarantined)==0;
    internal void Quarantine()=>Interlocked.Exchange(ref _quarantined,1);
    private void Check()
    {
        if(!Ready)throw PublicationCacheUnavailableException.For("authority-writer");
        var endpoints=_connection.GetEndPoints(false);
        var server=_connection.GetServer(_endpoint);
        if(!_connection.IsConnected||endpoints.Length!=1||!endpoints[0].Equals(_endpoint)||!server.IsConnected||server.IsReplica||server.ServerType!=ServerType.Standalone)
        {Quarantine();throw PublicationCacheUnavailableException.For("authority-primary");}
    }
    internal static RedisValue[] Arguments(CacheTransition command)=>[
        command.Prior is null?"0":"1",command.Prior is null?RedisValue.EmptyString:command.Prior,command.Next,
        command.Header.Environment,command.Header.Epoch.ToString("N"),command.Header.Policy,command.Header.AccountId.ToString("N"),
        command.Header.Nonce,command.Header.Revision.ToString(CultureInfo.InvariantCulture),command.Header.State.ToString(),
        command.TtlMilliseconds.ToString(CultureInfo.InvariantCulture),command.PriorHeader?.Nonce??"",command.PriorHeader?.Revision.ToString(CultureInfo.InvariantCulture)??"",command.Hash??""];
    private bool AccountKey(string key)
    {
        var prefix=$"svs:authority:v1:{_space.Environment}:{_space.Epoch:N}:account:";
        return key.StartsWith(prefix,StringComparison.Ordinal)&&Guid.TryParseExact(key[prefix.Length..],"N",out var account)&&account!=Guid.Empty&&key==_space.AccountKey(account);
    }
    public async Task<byte[]?> GetAsync(string key,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();if(!AccountKey(key))throw new ArgumentException("Account namespace required.");
        await _slots.WaitAsync(token);Task<RedisValue>? work=null;bool consumed=false;
        try
        {
            Check();token.ThrowIfCancellationRequested();work=_database.StringGetAsync(key,CommandFlags.DemandMaster|CommandFlags.NoRedirect);
            var result=await work.WaitAsync(token);Check();consumed=true;return result.IsNull?null:(byte[]?)result;
        }
        catch(OperationCanceledException) when(token.IsCancellationRequested){Quarantine();throw;}
        catch {Quarantine();throw PublicationCacheUnavailableException.For("authority-get");}
        finally
        {
            if(work is null||work.IsCompleted)
            {if(!consumed&&work is {IsCompletedSuccessfully:true})Clear((byte[]?)work.Result);if(work is not null)_=work.Exception;_slots.Release();}
            else _=work.ContinueWith(t=>{if(t.IsCompletedSuccessfully)Clear((byte[]?)t.Result);else _=t.Exception;_slots.Release();},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
        }
    }
    public async Task<bool> ExchangeAsync(CacheTransition source,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();using var cancellation=token.Register(Quarantine);await _slots.WaitAsync(token);Task<RedisResult>? work=null;CacheTransition? owned=null;
        try
        {
            Check();token.ThrowIfCancellationRequested();owned=new(_space,source.Header.AccountId,source.Prior,source.Next,source.TtlMilliseconds);
            RedisKey[] keys=owned.CredentialKey is {} index?[owned.AccountKey,index]:[owned.AccountKey];
            work=_database.ScriptEvaluateAsync(Script,keys,Arguments(owned),CommandFlags.DemandMaster|CommandFlags.NoRedirect);
            var result=(int)await work;token.ThrowIfCancellationRequested();Check();
            if(result is not (0 or 1))throw new InvalidOperationException("Authority primitive rejected its inputs.");
            return result==1;
        }
        catch(OperationCanceledException) when(token.IsCancellationRequested){Quarantine();throw;}
        catch {Quarantine();throw PublicationCacheUnavailableException.For("authority-transition");}
        finally
        {
            if(work is null||work.IsCompleted){if(work is not null)_=work.Exception;owned?.Dispose();_slots.Release();}
            else {var pendingOwner=owned;_=work.ContinueWith(t=>{_=t.Exception;pendingOwner?.Dispose();_slots.Release();},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);}
        }
    }
    private static void Clear(byte[]? bytes){if(bytes is not null)CryptographicOperations.ZeroMemory(bytes);}
    public void Dispose()
    {
        Quarantine();_connection.ConnectionFailed-=ConnectionChanged;_connection.ConnectionRestored-=ConnectionChanged;
        _connection.ConfigurationChanged-=ConfigurationChanged;_connection.ConfigurationChangedBroadcast-=ConfigurationChanged;_connection.ErrorMessage-=ServerError;
        // Semaphore stays alive for late native completions. Runtime owns the connection.
    }
    public override string ToString()=>nameof(DragonflyAuthorityStore);
}
