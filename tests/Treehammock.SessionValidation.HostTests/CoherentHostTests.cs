using Google.Protobuf;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using NodaTime;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.Contracts.V1;
using Treehammock.SessionValidation.Storage;
using treehammock.Rigging.Config;
using treehammock.Rigging.Fleet;
using Xunit;
namespace Treehammock.SessionValidation.HostTests;

public sealed class CoherentHostTests(HostFixture fixture):IClassFixture<HostFixture>
{
    internal static HostSettings Settings(HostFixture f)
    {
        var initial=f.Settings();using var socket=new TcpListener(IPAddress.Loopback,0);socket.Start();int port=((IPEndPoint)socket.LocalEndpoint).Port;
        var sql=new Npgsql.NpgsqlConnectionStringBuilder(initial.DatabaseConnectionString){Username=initial.Roles.Refiller,Password="different-refill-secret",MaxPoolSize=2,SearchPath="public,pg_catalog,pg_temp"};
        var refill=new RefillSettings{DatabaseConnectionString=sql.ConnectionString,PublisherCache=initial.Cache with{Username="svs-refiller",Password="different-cache-secret"},Environment="qualification",Epoch=Guid.NewGuid(),Policy="auth.v1",PrimaryRunId=new('a',40),DragonflyVersion="v1.29.0"};
        var fleet=new AuthorityFleetSettings{InstanceId="svs-local",Realm=Guid.NewGuid(),CheckpointPath=Path.Combine(f.Directory,Guid.NewGuid()+".checkpoint"),Port=port,ServerCertificatePath=initial.ServerCertificatePath,ServerCertificatePassword=initial.ServerCertificatePassword,ControllerRootCertificatePath=initial.ClientRootCertificatePath,ControllerPins=[HostFixture.Pin(f.NextClient)]};
        var node=JsonSerializer.SerializeToNode(initial,HostSettings.Json)!.AsObject();node["refill"]=JsonSerializer.SerializeToNode(refill,HostSettings.Json);node["fleet"]=JsonSerializer.SerializeToNode(fleet,HostSettings.Json);
        node["actionPolicy"]=JsonNode.Parse("""{"version":"coherent-test.v1","requirements":{"backup.read":"account.read","backup.write":"account.manage"}}""");
        return node.Deserialize<HostSettings>(HostSettings.Json)!;
    }
    internal static FleetBinding Binding(HostSettings s,CoherentResources resources,long generation=1)=>new(s.Fleet!.Realm,generation,Guid.NewGuid(),FleetProtocol.Nonce(),FleetMode.CoherentAdmitted,s.Refill!.Environment,s.Refill.Epoch,s.Refill.Policy,s.Refill.PrimaryRunId,new(s.Roles.App,s.Roles.Coordinator,s.Roles.Validator,s.Roles.Refiller,s.Roles.Maintenance),[new(s.Fleet.InstanceId,"SVS",resources.IdentityHash),new("ths-local","TreeHammock",new('B',64))],FleetPolicyHashes.Database,FleetPolicyHashes.Cache);
    internal static FleetRequest Request(string action,FleetReply status,FleetBinding b,string? prepared=null)=>new(action,FleetProtocol.Nonce(),status.BootId,b.Generation,b.Barrier,b.InventoryHash,b,prepared);
    internal static async Task<(HttpStatusCode Status,FleetReply? Reply)> Control(HttpClient client,FleetRequest request)
    {
        using var body=new StringContent(JsonSerializer.Serialize(request,FleetProtocol.Json),Encoding.UTF8);body.Headers.ContentType=new("application/json");
        using var reply=await client.PostAsync(FleetProtocol.Path,body,TestContext.Current.CancellationToken);var bytes=await reply.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken);
        return(reply.StatusCode,reply.IsSuccessStatusCode?FleetProtocol.Read<FleetReply>(bytes):null);
    }
    [Fact] public async Task Production_factory_registers_real_coherent_resources_without_manual_admission_flags()
    {
        var s=Settings(fixture);await using var app=SvsHost.Build(s);var resources=Assert.IsType<CoherentResources>(app.Services.GetRequiredService<IHostResources>());
        Assert.Equal(FleetMode.Unadmitted,resources.Gate.Mode);Assert.False(resources.Admission.CacheReady);Assert.False(resources.RefillReady);
    }
    [Theory][InlineData("active",Decision.Active)][InlineData("signature",Decision.Unauthenticated)][InlineData("forbidden",Decision.Forbidden)]
    public async Task Private_v2_activation_enables_normal_signed_cache_hits_with_zero_foreground_SQL_or_refill(string kind,Decision expected)
    {
        var s=Settings(fixture);using var authority=new RpcResourcesOwner();var db=new Database(authority.Value);var cache=new Cache(s,authority.Value);
        await using var app=SvsHost.Build(s,c=>new CoherentResources(c,db,cache));await app.StartAsync(TestContext.Current.CancellationToken);
        var resources=(CoherentResources)app.Services.GetRequiredService<IHostResources>();using var controller=fixture.Http(s,fixture.NextClient);controller.BaseAddress=new($"https://127.0.0.1:{s.Fleet!.Port}");
        var status=(await Control(controller,new("status",FleetProtocol.Nonce(),Guid.Empty,0,Guid.Empty,""))).Reply!;Assert.Equal("SVS",status.Kind);Assert.Equal(resources.IdentityHash,status.IdentityHash);
        var binding=Binding(s,resources);db.Expected=binding;
        var preparation=await Control(controller,Request("prepare",status,binding));Assert.Equal(HttpStatusCode.OK,preparation.Status);Assert.False(resources.Admission.CacheReady);
        db.Committed=true;var activation=await Control(controller,Request("activate",status,binding,preparation.Reply!.Prepared));Assert.Equal(HttpStatusCode.OK,activation.Status);Assert.True(resources.Admission.CacheReady);Assert.True(resources.RefillReady);
        int checks=db.BindingChecks,audits=db.Audits;db.Down=true;
        string token=authority.Value.Credential(kind=="signature");cache.Set(token);
        using var client=fixture.Http(s,fixture.Client);
        for(int n=0;n<3;n++)
        {
            var reply=await RpcWire.Call(client,RpcWire.Request(token,kind=="forbidden"?"backup.write":"backup.read").ToByteArray(),token:TestContext.Current.CancellationToken);
            Assert.Equal(0,reply.Status);Assert.Equal(expected,RpcWire.Reply(reply.Body).Decision);
        }
        Assert.Equal(0,db.Reads);Assert.Equal(0,db.Routes);Assert.Equal(0,db.Scans);Assert.Equal(0,cache.Writes);Assert.Equal(6,cache.Gets);Assert.Equal(checks,db.BindingChecks);Assert.Equal(audits,db.Audits);
        cache.Quarantine();Assert.False(resources.Admission.CacheReady);
    }
    [Fact] public async Task Drain_waits_for_full_response_and_late_SQL_then_probes_each_actual_named_identity()
    {
        var s=Settings(fixture);using var authority=new RpcResourcesOwner();var db=new Database(authority.Value);var cache=new Cache(s,authority.Value);
        await using var app=SvsHost.Build(s,c=>new CoherentResources(c,db,cache));await app.StartAsync(TestContext.Current.CancellationToken);
        var r=(CoherentResources)app.Services.GetRequiredService<IHostResources>();using var controller=fixture.Http(s,fixture.NextClient);controller.BaseAddress=new($"https://127.0.0.1:{s.Fleet!.Port}");
        var status=(await Control(controller,new("status",FleetProtocol.Nonce(),Guid.Empty,0,Guid.Empty,""))).Reply!;var binding=Binding(s,r);db.Expected=binding;
        var preparation=await Control(controller,Request("prepare",status,binding));db.Committed=true;await Control(controller,Request("activate",status,binding,preparation.Reply!.Prepared));
        db.Pending=new(TaskCreationOptions.RunContinuationsAsynchronously);using var client=fixture.Http(s,fixture.Client);
        // Synchronize cancellation after actual SQL entry; a 100ms transport
        // deadline could otherwise expire during the first TLS handshake.
        using var caller=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var call=RpcWire.Call(client,RpcWire.Request(authority.Value.Credential()).ToByteArray(),"4000m",token:caller.Token);
        await TestWait.Until(()=>db.Reads==1);caller.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>call);
        var requests=app.Services.GetRequiredService<RequestLifetime>();var response=requests.TryEnter()!;using var responseFleet=r.Gate.Enter();
        var next=binding with{Generation=2,Barrier=Guid.NewGuid()};var drain=Control(controller,Request("drain",status,next));
        await TestWait.Until(()=>r.Gate.Mode==FleetMode.Quarantined);Assert.False(drain.IsCompleted);Assert.True(r.Gate.Reply(FleetProtocol.Nonce()).Active>=2);
        db.Pending.SetResult(new(AuthorityReadStatus.Unavailable));await TestWait.Until(()=>r.Gate.Reply(FleetProtocol.Nonce()).Active==1);Assert.False(drain.IsCompleted);
        response.Dispose();responseFleet.Dispose();var drained=await drain;Assert.Equal(HttpStatusCode.OK,drained.Status);Assert.Equal(0,drained.Reply!.Active);
        var probe=Request("probe",status,next);Assert.Equal(HttpStatusCode.Conflict,(await Control(controller,probe)).Status);
        db.Retired=true;cache.Retired=true;var proof=(await Control(controller,probe with{Nonce=FleetProtocol.Nonce()})).Reply!.Isolation!;
        Assert.Equal(r.Identities(),proof.Rejected);Assert.Equal(new[]{"validator","validator","refiller"},db.Probes);Assert.Equal(new[]{"cache-reader","cache-refiller"},cache.Probes);
    }
    [Fact] public async Task Actual_Kestrel_response_completion_remains_counted_after_handler_returns()
    {
        var s=Settings(fixture);using var authority=new RpcResourcesOwner();var db=new Database(authority.Value);var cache=new Cache(s,authority.Value);
        await using var app=SvsHost.Build(s,c=>new CoherentResources(c,db,cache));
        var completedEntered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var testToken=TestContext.Current.CancellationToken;app.MapGet("/test-response",async context=>{context.Response.OnCompleted(async()=>{completedEntered.SetResult();await release.Task;});await context.Response.WriteAsync("ok",testToken);});
        await app.StartAsync(TestContext.Current.CancellationToken);var r=(CoherentResources)app.Services.GetRequiredService<IHostResources>();
        using var controller=fixture.Http(s,fixture.NextClient);controller.BaseAddress=new($"https://127.0.0.1:{s.Fleet!.Port}");
        var status=(await Control(controller,new("status",FleetProtocol.Nonce(),Guid.Empty,0,Guid.Empty,""))).Reply!;var binding=Binding(s,r);db.Expected=binding;
        var preparation=await Control(controller,Request("prepare",status,binding));db.Committed=true;await Control(controller,Request("activate",status,binding,preparation.Reply!.Prepared));
        using var client=fixture.Http(s,fixture.Client);using var response=await client.GetAsync("/test-response",TestContext.Current.CancellationToken);Assert.Equal("ok",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));await completedEntered.Task.WaitAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1,r.Gate.Reply(FleetProtocol.Nonce()).Active);Assert.Equal(1,app.Services.GetRequiredService<RequestLifetime>().Active);
        var drain=Control(controller,Request("drain",status,binding with{Generation=2,Barrier=Guid.NewGuid()}));await TestWait.Until(()=>r.Gate.Mode==FleetMode.Quarantined);Assert.False(drain.IsCompleted);
        release.SetResult();Assert.Equal(0,(await drain).Reply!.Active);
    }
    [Fact] public async Task Fleet_listener_requires_exact_controller_pin_and_public_listener_has_no_control_route()
    {
        var s=Settings(fixture);using var authority=new RpcResourcesOwner();var db=new Database(authority.Value);var cache=new Cache(s,authority.Value);
        await using var app=SvsHost.Build(s,c=>new CoherentResources(c,db,cache));await app.StartAsync(TestContext.Current.CancellationToken);
        using var publicClient=fixture.Http(s,fixture.Client);using var publicReply=await publicClient.PostAsync(FleetProtocol.Path,new StringContent("{}"),TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.NotFound,publicReply.StatusCode);
        using var wrongController=fixture.Http(s,fixture.Client);wrongController.BaseAddress=new($"https://127.0.0.1:{s.Fleet!.Port}");
        await Assert.ThrowsAsync<HttpRequestException>(async()=>{using var denied=await wrongController.PostAsync(FleetProtocol.Path,new StringContent("{}"),TestContext.Current.CancellationToken);});
    }
    internal sealed class RpcResourcesOwner:IDisposable{internal readonly RpcResources Value=new();public void Dispose()=>Value.DisposeAsync().AsTask().GetAwaiter().GetResult();}
    internal sealed class Database(RpcResources source):IRuntimeDatabase,IReadonlySessionAuthority,IAuthorityProjectionLeaseFactory
    {
        internal bool Down,Committed,Retired;internal int Reads,Routes,Scans,Audits,BindingChecks;internal FleetBinding? Expected;internal TaskCompletionSource<AuthorityReadResult>? Pending;
        internal readonly List<string> Probes=[];
        public bool Ready=>!Down;public DatabaseIdentityAuditStatus LastAudit=>DatabaseIdentityAuditStatus.Verified;public IReadonlySessionAuthority Foreground=>this;public IAuthorityProjectionLeaseFactory RefillLeases=>this;
        public Task AuditAsync(CancellationToken token){Audits++;return Task.CompletedTask;}
        public Task CheckBindingAsync(FleetBinding b,bool activation,CancellationToken token){BindingChecks++;if(FleetProtocol.Digest(b)!=FleetProtocol.Digest(Expected)||activation!=Committed)throw new InvalidOperationException("SQL phase/binding mismatch.");return Task.CompletedTask;}
        public Task<AuthorityReadResult> ReadAsync(string hash,Instant deadline,CancellationToken cancellationToken=default){Reads++;return Pending?.Task??(Down?Task.FromResult(new AuthorityReadResult(AuthorityReadStatus.Unavailable)):source.ReadAsync(hash,deadline,cancellationToken));}
        public Task<Guid?> RouteAsync(string hash,CancellationToken token){Routes++;return Task.FromResult<Guid?>(null);}
        public Task<IReadOnlyList<string>> ScanAsync(string? after,int maximum,CancellationToken token){Scans++;return Task.FromResult<IReadOnlyList<string>>([]);}
        public Task ProbeAsync(string purpose,CancellationToken token){Probes.Add(purpose);if(!Retired)throw new InvalidOperationException("Login still valid or proof unavailable.");return Task.CompletedTask;}
        public Task<IAuthorityProjectionLease> AcquireAsync(Guid account,TimeSpan budget,CancellationToken token)=>throw new InvalidOperationException("No fabricated projection.");
        public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
    }
    internal sealed class Cache(HostSettings settings,RpcResources source):IRuntimeCache,IAuthorityConditionalStore
    {
        private bool _ready;private byte[]? _payload;private string? _hash;internal int Gets,Writes;internal bool Retired;internal readonly List<string> Probes=[];
        public bool ReaderReady=>_ready;public bool PublisherReady=>_ready;public bool Available=>_ready;public IAuthorityConditionalStore Publisher=>this;
        public Task PrepareAsync(CancellationToken token){_ready=true;return Task.CompletedTask;}public void Quarantine()=>_ready=false;
        public void Set(string credential)
        {
            _hash=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(credential)));var now=SystemClock.Instance.GetCurrentInstant();var i=source.Identity;var s=settings.Refill!;
            using var record=new CachedAccountAuthority(new(s.Environment,s.Epoch,s.Policy,CoherentCacheKeySpace.NewTransitionNonce(),7,CachedAuthorityState.Ready,i.AccountId),_hash,now,now+Duration.FromSeconds(20),i,new(now+Duration.FromMinutes(1),now+Duration.FromHours(1),null),new(true,1,null,i.AccountStamp,true),new(i.AccountId,1,1,["account.read"],false,now,now+Duration.FromMinutes(1),null,true),source.Key);
            _payload=CoherentCacheCodec.Encode(record);
        }
        public Task<byte[]?> GetAsync(string key,CancellationToken token){Gets++;return Task.FromResult(key.Contains(":credential:",StringComparison.Ordinal)?key.EndsWith(_hash??"never",StringComparison.Ordinal)?Encoding.UTF8.GetBytes(source.Identity.AccountId.ToString("N")):null:_payload?.ToArray());}
        public Task<bool> ExchangeAsync(CacheTransition transition,CancellationToken token){Writes++;throw new InvalidOperationException("Foreground cannot publish.");}
        public Task StopAsync(CancellationToken token){Quarantine();return Task.CompletedTask;}
        public Task ProbeAsync(string purpose,CancellationToken token){Probes.Add(purpose);if(!Retired)throw new InvalidOperationException("Cache login still valid or proof unavailable.");return Task.CompletedTask;}
        public ValueTask DisposeAsync(){if(_payload is not null)CryptographicOperations.ZeroMemory(_payload);return ValueTask.CompletedTask;}
    }
}
