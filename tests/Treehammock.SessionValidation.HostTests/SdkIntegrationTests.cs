using Google.Protobuf;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.Client;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.HostTests;
public sealed class SdkIntegrationTests(HostFixture fixture):IClassFixture<HostFixture>
{
    private HostSettings Settings(bool mapped=true)=>fixture.Settings(j=>{if(mapped)j["actionPolicy"]=JsonNode.Parse("""{"version":"sdk-test.v1","requirements":{"backup.read":"account.read","backup.write":"account.manage"}}""");});
    private ClientOptions Options(HostSettings h,string? policy=null,bool next=false)
    {
        var path=Path.Combine(fixture.Directory,"sdk-"+Guid.NewGuid().ToString("N")+".pfx");File.WriteAllBytes(path,(next?fixture.NextClient:fixture.Client).Export(X509ContentType.Pfx,"sdk-test"));return new(){TlsName="localhost",PrivateAddress="127.0.0.1",Port=h.Port,ServerRootCertificatePath=h.ServerRootCertificatePath,ServerLeafSha256=[HostFixture.Pin(fixture.Server)],ClientCertificatePath=path,ClientCertificatePassword="sdk-test",ClientRootCertificatePath=h.ClientRootCertificatePath,ServiceIdentity=HostFixture.Identity,PolicyVersion=policy??h.ActionPolicy.Version};
    }
    [Theory][InlineData("active",200)][InlineData("signature",401)][InlineData("forbidden",403)][InlineData("not-found",401)][InlineData("unavailable",503)][InlineData("unmapped",503)][InlineData("caller-denied",503)][InlineData("wrong-policy",503)]
    public async Task Typed_sdk_uses_normal_host_actual_mtls_signature_and_server_policy(string kind,int status)
    {
        var r=new RpcResources();if(kind=="not-found")r.Status=AuthorityReadStatus.NotFound;if(kind=="unavailable")r.Status=AuthorityReadStatus.Unavailable;var s=Settings(kind!="unmapped");await using var app=SvsHost.Build(s,_=>r);await app.StartAsync(TestContext.Current.CancellationToken);await using var sdk=new SessionValidatorClient(Options(s,kind=="wrong-policy"?"unexpected.v1":null));var result=await sdk.ValidateAsync(r.Credential(kind=="signature"),kind=="forbidden"?"backup.write":kind=="caller-denied"?"recovery_package.read":"backup.read",DateTimeOffset.UtcNow.AddSeconds(2),TestContext.Current.CancellationToken);Assert.Equal(status,result.HttpStatusCode);if(status==200){Assert.Equal(r.Identity.AccountId,result.Subject!.AccountId);Assert.Equal(7,result.Subject.Generation);}else Assert.Null(result.Subject);Assert.Equal(kind is "unmapped" or "caller-denied"?0:1,r.Calls);
    }
    [Fact] public async Task Next_pinned_certificate_and_changed_authority_are_seen_without_identity_reuse()
    {
        var r=new RpcResources();var s=Settings();await using var app=SvsHost.Build(s,_=>r);await app.StartAsync(TestContext.Current.CancellationToken);await using var sdk=new SessionValidatorClient(Options(s,next:true));string credential=r.Credential();Assert.Equal(200,(await sdk.ValidateAsync(credential,"backup.read",DateTimeOffset.UtcNow.AddSeconds(2),TestContext.Current.CancellationToken)).HttpStatusCode);r.Status=AuthorityReadStatus.NotFound;var refused=await sdk.ValidateAsync(credential,"backup.read",DateTimeOffset.UtcNow.AddSeconds(2),TestContext.Current.CancellationToken);Assert.Equal(401,refused.HttpStatusCode);Assert.Null(refused.Subject);Assert.Equal(2,r.Calls);
    }
    [Theory][InlineData(true)][InlineData(false)] public async Task Caller_deadline_or_cancellation_cancels_normal_host_authority(bool cancel)
    {
        var r=new RpcResources();var entered=new TaskCompletionSource<CancellationToken>(TaskCreationOptions.RunContinuationsAsynchronously);var late=new TaskCompletionSource<AuthorityReadResult>(TaskCreationOptions.RunContinuationsAsynchronously);r.Read=(_,_,ct)=>{entered.TrySetResult(ct);return late.Task;};var s=Settings();await using var app=SvsHost.Build(s,_=>r);await app.StartAsync(TestContext.Current.CancellationToken);await using var sdk=new SessionValidatorClient(Options(s));using var stop=new CancellationTokenSource();var pending=sdk.ValidateAsync(r.Credential(),"backup.read",DateTimeOffset.UtcNow.AddMilliseconds(cancel?1000:150),stop.Token);var observed=await entered.Task.WaitAsync(TimeSpan.FromSeconds(2),TestContext.Current.CancellationToken);if(cancel)stop.Cancel();var result=await pending;Assert.Equal(503,result.HttpStatusCode);Assert.Null(result.Subject);await TestWait.Until(()=>observed.IsCancellationRequested);late.SetResult(new(AuthorityReadStatus.NotFound));
    }
    [Theory][InlineData("invalid",3)][InlineData("expired",4)][InlineData("future",3)][InlineData("duplicate",3)][InlineData("overflow",3)]
    public async Task Absolute_transport_ceiling_is_strict_and_cannot_extend_grpc_budget(string fault,int status)
    {
        var r=new RpcResources();var s=Settings();await using var app=SvsHost.Build(s,_=>r);await app.StartAsync(TestContext.Current.CancellationToken);using var http=fixture.Http(s,fixture.Client);var value=fault switch{"invalid"=>"user-chosen-text","expired"=>"1","overflow"=>"999999999999999999999",_=>DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture)};if(fault=="duplicate")http.DefaultRequestHeaders.Add("svs-deadline-unix-ms",new[]{value,value});else http.DefaultRequestHeaders.Add("svs-deadline-unix-ms",value);var result=await RpcWire.Call(http,RpcWire.Request(r.Credential()).ToByteArray(),token:TestContext.Current.CancellationToken);Assert.Equal(status,result.Status);Assert.Empty(result.Body);Assert.Equal(0,r.Calls);
    }
}
