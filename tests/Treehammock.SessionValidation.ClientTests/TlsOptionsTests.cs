using Google.Protobuf;
using System.Net;
using System.Text.Json.Nodes;
using Treehammock.SessionValidation.Client;
using Xunit;
namespace Treehammock.SessionValidation.ClientTests;
public sealed class TlsOptionsTests
{
    [Theory][InlineData("public")][InlineData("wildcard")][InlineData("tls-path")][InlineData("port")][InlineData("pin")][InlineData("duplicate-pin")][InlineData("policy")][InlineData("identity")][InlineData("timeout")][InlineData("concurrency")][InlineData("connections")][InlineData("lifetime")][InlineData("shutdown")][InlineData("file")]
    public void Invalid_configuration_is_rejected_before_opening_channel(string fault)
    {
        using var f=new ClientFixture();var o=f.Options(j=>{switch(fault){case "public":j["privateAddress"]="8.8.8.8";break;case "wildcard":j["privateAddress"]="0.0.0.0";break;case "tls-path":j["tlsName"]="localhost/path";break;case "port":j["port"]=0;break;case "pin":j["serverLeafSha256"]=new JsonArray("invalid");break;case "duplicate-pin":j["serverLeafSha256"]=new JsonArray(ClientFixture.Pin(f.Server),ClientFixture.Pin(f.Server));break;case "policy":j["policyVersion"]="other policy";break;case "identity":j["serviceIdentity"]="forwarded-caller";break;case "timeout":j["requestTimeoutMilliseconds"]=5000;break;case "concurrency":j["maximumConcurrentCalls"]=0;break;case "connections":j["maximumConnections"]=17;break;case "lifetime":j["connectionLifetimeMilliseconds"]=0;break;case "shutdown":j["shutdownTimeoutMilliseconds"]=10001;break;case "file":j["serverRootCertificatePath"]="root.cer";break;}});Assert.Throws<ArgumentException>(()=>new SessionValidatorClient(o));
    }
    [Theory][InlineData("eku")][InlineData("identity")][InlineData("expired")][InlineData("future")][InlineData("no-san")][InlineData("root")]
    public void Client_certificate_requires_current_owned_key_chain_eku_and_exact_identity(string fault)
    {
        using var f=new ClientFixture();using var other=new ClientFixture();using var cert=f.Leaf(false,identity:fault=="identity"?"spiffe://sdk.test/service/other":fault=="no-san"?null:ClientFixture.Identity,eku:fault=="eku"?"1.3.6.1.5.5.7.3.1":null,before:fault=="expired"?DateTimeOffset.UtcNow.AddDays(-2):fault=="future"?DateTimeOffset.UtcNow.AddDays(1):null,after:fault=="expired"?DateTimeOffset.UtcNow.AddDays(-1):fault=="future"?DateTimeOffset.UtcNow.AddDays(2):null);File.WriteAllBytes(Path.Combine(f.Directory,"client.pfx"),cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx,"test-only"));Assert.Throws<ArgumentException>(()=>new SessionValidatorClient(f.Options(j=>{if(fault=="root")j["clientRootCertificatePath"]=Path.Combine(other.Directory,"root.cer");})));
    }
    [Theory][InlineData("pin")][InlineData("name")][InlineData("root")][InlineData("client-pin")]
    public async Task Actual_tls_rejects_wrong_server_trust_or_unregistered_client(string fault)
    {
        using var f=new ClientFixture();using var other=new ClientFixture();int calls=0;await using var app=f.ServerApp(c=>{calls++;return Task.CompletedTask;},clientPin:fault=="client-pin"?new string('0',64):null);await app.StartAsync(TestContext.Current.CancellationToken);var options=f.Options(j=>{if(fault=="pin")j["serverLeafSha256"]=new JsonArray(new string('0',64));if(fault=="name")j["tlsName"]="other.test";if(fault=="root")j["serverRootCertificatePath"]=Path.Combine(other.Directory,"root.cer");});await using var client=new SessionValidatorClient(options);Assert.Equal(503,(await client.ValidateAsync("credential","backup.read",DateTimeOffset.UtcNow.AddSeconds(2),TestContext.Current.CancellationToken)).HttpStatusCode);Assert.Equal(0,calls);
    }
    [Theory][InlineData(true)][InlineData(false)] public async Task Expired_client_or_pooled_server_leaf_is_refused_on_next_call(bool clientExpiry)
    {
        using var f=new ClientFixture(serverLifeSeconds:clientExpiry?null:3,clientLifeSeconds:clientExpiry?3:null);int calls=0;await using var app=f.ServerApp(async c=>{calls++;await ClientFixture.Write(c,ClientFixture.Reply(await ClientFixture.Read(c)).ToByteArray());});await app.StartAsync(TestContext.Current.CancellationToken);await using var client=new SessionValidatorClient(f.Options());Assert.Equal(200,(await client.ValidateAsync("credential","backup.read",DateTimeOffset.UtcNow.AddSeconds(2),TestContext.Current.CancellationToken)).HttpStatusCode);await Task.Delay(3200,TestContext.Current.CancellationToken);Assert.Equal(503,(await client.ValidateAsync("credential","backup.read",DateTimeOffset.UtcNow.AddSeconds(2),TestContext.Current.CancellationToken)).HttpStatusCode);Assert.Equal(1,calls);
    }
    [Fact] public async Task Reused_connections_and_new_connection_dns_rotation_are_owned_and_bounded()
    {
        using var f=new ClientFixture();int resolutions=0;var connections=new HashSet<string>();await using var app=f.ServerApp(async c=>{connections.Add(c.Connection.Id);await ClientFixture.Write(c,ClientFixture.Reply(await ClientFixture.Read(c)).ToByteArray());});await app.StartAsync(TestContext.Current.CancellationToken);var options=f.Options(j=>{j["privateAddress"]="";j["connectionLifetimeMilliseconds"]=3000;j["maximumConnections"]=1;}).Snapshot();using var transport=new GrpcValidationTransport(options,(_,_)=>{resolutions++;return Task.FromResult(new[]{IPAddress.Loopback});});await using var client=new SessionValidatorClient(options,transport,TimeProvider.System);for(int i=0;i<2;i++)Assert.Equal(200,(await client.ValidateAsync("credential","backup.read",DateTimeOffset.UtcNow.AddSeconds(2),TestContext.Current.CancellationToken)).HttpStatusCode);Assert.Equal(1,resolutions);Assert.Single(connections);await Task.Delay(3100,TestContext.Current.CancellationToken);Assert.Equal(200,(await client.ValidateAsync("credential","backup.read",DateTimeOffset.UtcNow.AddSeconds(2),TestContext.Current.CancellationToken)).HttpStatusCode);Assert.Equal(2,resolutions);Assert.Equal(2,connections.Count);
    }
    [Theory][InlineData("public")][InlineData("mixed")][InlineData("empty")][InlineData("many")]
    public async Task Resolved_public_mixed_or_unbounded_address_sets_never_open_connection(string fault)
    {
        using var f=new ClientFixture();var options=f.Options(j=>j["privateAddress"]="").Snapshot();var addresses=fault switch{"public"=>new[]{IPAddress.Parse("8.8.8.8")},"mixed"=>new[]{IPAddress.Loopback,IPAddress.Parse("8.8.8.8")},"empty"=>Array.Empty<IPAddress>(),_=>Enumerable.Repeat(IPAddress.Loopback,9).ToArray()};using var transport=new GrpcValidationTransport(options,(_,_)=>Task.FromResult(addresses));await using var client=new SessionValidatorClient(options,transport,TimeProvider.System);Assert.Equal(503,(await client.ValidateAsync("credential","backup.read",DateTimeOffset.UtcNow.AddSeconds(2),TestContext.Current.CancellationToken)).HttpStatusCode);
    }
}
