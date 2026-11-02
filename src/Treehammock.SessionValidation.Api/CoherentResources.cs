using NodaTime;
using Npgsql;
using Treehammock.SessionValidation.Storage;
using treehammock.Rigging.Fleet;
namespace Treehammock.SessionValidation.Api;

internal interface IRuntimeCache : ICoherentCacheGetStore,IAsyncDisposable
{
    void OwnOperations(Func<IDisposable> ownership) {}
    bool ReaderReady{get;}
    bool PublisherReady{get;}
    IAuthorityConditionalStore Publisher{get;}
    Task PrepareAsync(CancellationToken token);
    void Quarantine();
    Task StopAsync(CancellationToken token);
    Task ProbeAsync(string purpose,CancellationToken token);
}
internal interface IRuntimeDatabase : IAsyncDisposable
{
    bool Ready{get;}
    void OwnOperations(Func<IDisposable> ownership) {}
    Task DrainAuditAsync(CancellationToken token) => Task.CompletedTask;
    DatabaseIdentityAuditStatus LastAudit{get;}
    IReadonlySessionAuthority Foreground{get;}
    IAuthorityProjectionLeaseFactory RefillLeases{get;}
    Task AuditAsync(CancellationToken token);
    Task<Guid?> RouteAsync(string hash,CancellationToken token);
    Task<IReadOnlyList<string>> ScanAsync(string? after,int maximum,CancellationToken token);
    Task CheckBindingAsync(FleetBinding binding,bool activation,CancellationToken token);
    Task ProbeAsync(string purpose,CancellationToken token);
}
internal interface IFleetResources
{
    AuthorityFleetGate Gate{get;}
    string IdentityHash{get;}
    bool RefillReady{get;}
    Task VerifyAsync(FleetBinding binding,bool activation,CancellationToken token);
    void Activate(FleetBinding binding);
    void Quarantine();
    Task DrainAsync(CancellationToken token);
    Task<FleetIsolationProof> ProbeAsync(CancellationToken token);
}
// Normal composition uses the real separate SQL/cache backends. The internal component
// constructor lets local tests substitute infrastructure, never an admission Boolean.
internal sealed class CoherentResources : IHostResources,IFleetResources
{
    private readonly HostSettings _settings;
    private readonly IRuntimeDatabase _database;
    private readonly IRuntimeCache _cache;
    private readonly LocalRefillWorker _worker;
    private readonly CoherentCacheKeySpace _space;
    private FleetBinding? _binding;
    private int _activated,_stopped;
    public AuthorityFleetGate Gate{get;}
    public SessionCacheAdmission Admission{get;}=new();
    public bool DatabaseReady=>_database.Ready;
    public DatabaseIdentityAuditStatus LastAudit=>_database.LastAudit;
    public SessionEvidenceCoordinator Coordinator{get;}
    internal CoherentResources(HostSettings settings):this(settings,new RuntimeDatabase(settings),new RuntimeCache(settings)){}
    internal CoherentResources(HostSettings settings,IRuntimeDatabase database,IRuntimeCache cache)
    {
        _settings=settings;_database=database;_cache=cache;Gate=new(settings.Fleet!);database.OwnOperations(Gate.Enter);cache.OwnOperations(Gate.Enter);var r=settings.Refill!;_space=new(r.Environment,r.Epoch,r.Policy);
        _worker=new(r,new Publication(this),Admission.IsCurrentEpoch);
        Coordinator=new(new(cache,Admission,TimeSpan.FromMilliseconds(100),TimeSpan.FromSeconds(30)),new OwnedAuthority(this,database.Foreground),settings.Issuer,TimeSpan.FromMilliseconds(settings.RequestTimeoutMilliseconds),_worker);
    }
    internal FleetIdentity[] Identities()=>FleetProtocol.Identities("SVS",[new("validator","SQL",_settings.Roles.Validator),new("refiller","SQL",_settings.Roles.Refiller),new("cache-reader","Cache",_settings.Cache.Username),new("cache-refiller","Cache",_settings.Refill!.PublisherCache.Username)]);
    public string IdentityHash=>FleetProtocol.IdentityHash("SVS",Identities());
    private bool Current=>Volatile.Read(ref _stopped)==0&&_binding is {} b&&Gate.Current(b);
    public bool RefillReady=>Current&&_binding!.Mode==FleetMode.CoherentAdmitted&&_cache.PublisherReady;
    public Task DrainAuditAsync(CancellationToken token)=>_database.DrainAuditAsync(token);
    public Task AuditAsync(CancellationToken token)=>_database.AuditAsync(token);
    public async Task VerifyAsync(FleetBinding b,bool activation,CancellationToken token)
    {
        b.Validate();if(b.Realm!=_settings.Fleet!.Realm||b.Participants.SingleOrDefault(x=>x.Id==Gate.Instance) is not {Kind:"SVS"} p||p.IdentityHash!=IdentityHash||
            b.SqlIdentities!=new FleetSqlIdentities(_settings.Roles.App,_settings.Roles.Coordinator,_settings.Roles.Validator,_settings.Roles.Refiller,_settings.Roles.Maintenance))throw new InvalidOperationException("Actual named identities differ from binding.");
        if(Volatile.Read(ref _stopped)!=0)throw new InvalidOperationException("Drained incarnation cannot be reused.");
        await _database.AuditAsync(token);if(!_database.Ready)throw new InvalidOperationException("Foreground SQL identity not admitted.");
        await _database.CheckBindingAsync(b,activation,token);
        if(b.Mode==FleetMode.CoherentAdmitted)
        {
            var r=_settings.Refill!;if(b.Environment!=r.Environment||b.Epoch!=r.Epoch||b.Policy!=r.Policy||b.PrimaryRunId!=r.PrimaryRunId)throw new InvalidOperationException("Coherent primary/epoch mismatch.");
            await _cache.PrepareAsync(token);if(!_cache.ReaderReady||!_cache.PublisherReady)throw new InvalidOperationException("Cache identity/primary unavailable.");
        }
    }
    public void Activate(FleetBinding binding)
    {
        if(Interlocked.Exchange(ref _activated,1)!=0)throw new InvalidOperationException("One activation per process incarnation.");
        _binding=binding;
        if(binding.Mode==FleetMode.CoherentAdmitted)Admission.Admit(_space,_cache,()=>Current&&_cache.ReaderReady);
    }
    public void Quarantine(){Admission.Quarantine();_cache.Quarantine();Gate.Quarantine();}
    public Task StopRefillAsync()=>_worker.StopAsync();
    public async Task DrainAsync(CancellationToken token)
    {
        Interlocked.Exchange(ref _stopped,1);Quarantine();
        // Closing actual transports may settle stalled native operations; ownership
        // remains held by the worker and foreground gate until cleanup completes.
        await Task.WhenAll(_worker.StopAsync(),_cache.StopAsync(token)).WaitAsync(token);
    }
    public async Task<FleetIsolationProof> ProbeAsync(CancellationToken token)
    {
        if(Gate.Mode!=FleetMode.Quarantined)throw new InvalidOperationException("Quarantine required.");
        await _database.ProbeAsync("validator",token);await _database.ProbeAsync("refiller",token);
        await _cache.ProbeAsync("cache-reader",token);await _cache.ProbeAsync("cache-refiller",token);return new(Identities());
    }
    private sealed class OwnedAuthority(CoherentResources owner,IReadonlySessionAuthority inner):IReadonlySessionAuthority
    {
        public async Task<AuthorityReadResult> ReadAsync(string hash,Instant deadline,CancellationToken token=default)
        {using var lease=owner.Gate.Enter();return await inner.ReadAsync(hash,deadline,token);}
    }
    private sealed class Publication(CoherentResources owner):ILocalPublication
    {
        public bool Ready=>owner.RefillReady;
        public async Task PublishAsync(GuardedSessionRefillRequest work,CancellationToken token)
        {
            if(!Ready||!owner.Admission.IsCurrentEpoch(work.ExpectedEpoch))return;using var lease=owner.Gate.Enter();
            var r=owner._settings.Refill!;var end=SystemClock.Instance.GetCurrentInstant()+Duration.FromMilliseconds(r.OperationTimeoutMilliseconds);
            var account=await owner._database.RouteAsync(work.CredentialHash,token);token.ThrowIfCancellationRequested();
            if(account is null||!Ready||!owner.Admission.IsCurrentEpoch(work.ExpectedEpoch))return;
            var builder=new AuthorityProjectionBuilder(new OwnedProjectionLeases(owner._database.RefillLeases,owner.Gate.Enter),owner._space,TimeSpan.FromSeconds(30),TimeSpan.FromMilliseconds(r.OperationTimeoutMilliseconds));
            await new ConditionalProjectionPublisher(builder,owner._cache.Publisher,owner._space,TimeSpan.FromMilliseconds(r.OperationTimeoutMilliseconds)).ReconcileAsync(account.Value,work.CredentialHash,end,token);
            if(!Ready)throw new InvalidOperationException("Publisher incarnation changed.");
        }
        public async Task<IReadOnlyList<string>> ScanAsync(string? after,int maximum,CancellationToken token)
        {if(!Ready)return Array.Empty<string>();using var lease=owner.Gate.Enter();return await owner._database.ScanAsync(after,maximum,token);}
        public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
    }
    private readonly object _disposeSync=new();
    private Task? _disposeTask;
    public async ValueTask DisposeAsync()
    {
        Task finish;lock(_disposeSync)finish=_disposeTask??=FinishAsync();
        try{await finish.WaitAsync(TimeSpan.FromSeconds(3));}catch(TimeoutException){}
    }
    private async Task FinishAsync()
    {
        Interlocked.Exchange(ref _stopped,1);Quarantine();
        await Task.WhenAll(_worker.StopAsync(),_cache.StopAsync(CancellationToken.None),_database.DrainAuditAsync(CancellationToken.None));
        while(Gate.Reply(FleetProtocol.Nonce()).Active!=0)await Task.Delay(20);
        await _cache.DisposeAsync();await _database.DisposeAsync();
    }
}
internal sealed class RuntimeDatabase : IRuntimeDatabase
{
    private readonly HostSettings _settings;
    private readonly ServiceConcurrencyLimiter _sql;
    private readonly ValidatorDatabaseIdentity _identity;
    private readonly SvsRefillDatabase _refill;
    private Func<IDisposable>? _ownership;
    public void OwnOperations(Func<IDisposable> ownership)=>_ownership=ownership;
    public Task DrainAuditAsync(CancellationToken token)=>_identity.DrainAuditAsync(token);
    public bool Ready=>_identity.DatabaseFallbackReady;
    public DatabaseIdentityAuditStatus LastAudit{get;private set;}
    public IReadonlySessionAuthority Foreground{get;}
    public IAuthorityProjectionLeaseFactory RefillLeases=>_refill;
    internal RuntimeDatabase(HostSettings settings)
    {
        _settings=settings;_sql=new(settings.Capacity.ForegroundSqlOperations,"foreground-sql");_identity=YsqlAuthorityDataSource.CreateTreehammockValidator(settings.DatabaseConnectionString,settings.Roles);
        var roles=new Dictionary<string,string>{{"App",settings.Roles.App},{"Coordinator",settings.Roles.Coordinator},{"Validator",settings.Roles.Validator},{"Refiller",settings.Roles.Refiller},{"Maintenance",settings.Roles.Maintenance},{"Owner",settings.Roles.Owner},{"ValidatorRead",settings.Roles.ValidatorRead}};
        try{_refill=new(settings.Refill!.DatabaseConnectionString,roles,SessionAuthorityBackend.Yugabyte,"public");Foreground=new YsqlSessionAuthority(_identity,TimeSpan.FromSeconds(1),ownOperation:()=>_sql.EnterWith(()=>_ownership?.Invoke()??throw new InvalidOperationException("Missing raw SQL owner.")));}catch{_identity.DisposeAsync().AsTask().GetAwaiter().GetResult();throw;}
    }
    public async Task AuditAsync(CancellationToken token)=>LastAudit=(await _identity.RefreshIdentityAsync(token)).Status;
    public Task<Guid?> RouteAsync(string hash,CancellationToken token)=>_refill.ResolveAccountAsync(hash,token);
    public Task<IReadOnlyList<string>> ScanAsync(string? after,int maximum,CancellationToken token)=>_refill.ReadCandidateHashesAsync(after,maximum,token);
    public async Task CheckBindingAsync(FleetBinding b,bool activation,CancellationToken token)
    {
        if(!Ready)throw new InvalidOperationException("SQL identity unavailable.");
        await using var c=await _identity.Source.OpenConnectionAsync(token);await using var tx=await c.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead,token);
        await using(var setup=new NpgsqlCommand("set transaction read only; set local yb_read_from_followers=off; set local search_path=pg_catalog; set local statement_timeout='2s'",c,tx))await setup.ExecuteNonQueryAsync(token);
        await using var command=new NpgsqlCommand("select generation,phase,binding::text from public.ths_fleet_control where singleton and realm=@realm and barrier=@barrier and inventory_hash=@inventory",c,tx){CommandTimeout=3};
        command.Parameters.AddWithValue("realm",b.Realm);command.Parameters.AddWithValue("barrier",b.Barrier);command.Parameters.AddWithValue("inventory",b.InventoryHash);
        await using(var reader=await command.ExecuteReaderAsync(token))
        {
            if(!await reader.ReadAsync(token)||reader.GetInt64(0)!=b.Generation||reader.GetString(1)!=(activation?b.Mode.ToString():"Preparing")||reader.IsDBNull(2))throw new InvalidOperationException("Uncommitted fleet binding.");
            var actual=FleetProtocol.Read<FleetBinding>(System.Text.Encoding.UTF8.GetBytes(reader.GetString(2)));actual.Validate();if(FleetProtocol.Digest(actual)!=FleetProtocol.Digest(b))throw new InvalidOperationException("Durable fleet binding mismatch.");
        }
        await tx.CommitAsync(token);if(!Ready)throw new InvalidOperationException("SQL admission expired.");
    }
    public async Task ProbeAsync(string purpose,CancellationToken token)
    {
        string connection=purpose=="validator"?_settings.DatabaseConnectionString:purpose=="refiller"?_settings.Refill!.DatabaseConnectionString:throw new ArgumentException("Named SQL purpose required.");
        await using var c=new NpgsqlConnection(new NpgsqlConnectionStringBuilder(connection){Pooling=false}.ConnectionString);
        try{await c.OpenAsync(token);}catch(PostgresException e)when(e.SqlState is "28000" or "28P01"){return;}throw new InvalidOperationException("Retired SQL identity still authenticates.");
    }
    public async ValueTask DisposeAsync(){await _sql.DrainAsync(CancellationToken.None);await _refill.DisposeAsync();await _identity.DisposeAsync();}
}
