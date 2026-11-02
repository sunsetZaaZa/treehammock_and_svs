using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Svs12.Golden;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.Client;
using treehammock.Rigging.Fleet;
using Xunit;
namespace Treehammock.SessionValidation.HostTests;
public sealed class GoldenNormalHostTests(HostFixture fixture):IClassFixture<HostFixture>
{
    [Theory]
    [InlineData("issued-no-exp",200)][InlineData("ignored-jwt-exp",200)][InlineData("wrong-signing-key",401)]
    [InlineData("preauth-twofactor",401)][InlineData("missing-jti",401)][InlineData("forbidden-capability",403)]
    public async Task Actual_issued_tokens_cross_SDK_and_admitted_normal_host_with_SQL_down(string id,int expected)
    {
        var s=CoherentHostTests.Settings(fixture);using var authority=new CoherentHostTests.RpcResourcesOwner();TreehammockParityFixtures.Key().CopyTo(authority.Value.Key,0);
        var db=new CoherentHostTests.Database(authority.Value);var cache=new CoherentHostTests.Cache(s,authority.Value);
        await using var app=SvsHost.Build(s,c=>new CoherentResources(c,db,cache));await app.StartAsync(TestContext.Current.CancellationToken);
        var r=(CoherentResources)app.Services.GetRequiredService<IHostResources>();using var controller=fixture.Http(s,fixture.NextClient);controller.BaseAddress=new($"https://127.0.0.1:{s.Fleet!.Port}");
        var status=(await CoherentHostTests.Control(controller,new("status",FleetProtocol.Nonce(),Guid.Empty,0,Guid.Empty,""))).Reply!;var binding=CoherentHostTests.Binding(s,r);db.Expected=binding;
        var prepared=await CoherentHostTests.Control(controller,CoherentHostTests.Request("prepare",status,binding));Assert.Equal(HttpStatusCode.OK,prepared.Status);db.Committed=true;
        Assert.Equal(HttpStatusCode.OK,(await CoherentHostTests.Control(controller,CoherentHostTests.Request("activate",status,binding,prepared.Reply!.Prepared))).Status);db.Down=true;
        var profile=TreehammockParityFixtures.Case(id);string credential=TreehammockParityFixtures.Credential(profile);cache.Set(credential);
        string path=Path.Combine(fixture.Directory,Guid.NewGuid()+".pfx");File.WriteAllBytes(path,fixture.Client.Export(X509ContentType.Pfx,"golden-only"));
        await using var sdk=new SessionValidatorClient(new(){TlsName="localhost",PrivateAddress="127.0.0.1",Port=s.Port,ServerRootCertificatePath=s.ServerRootCertificatePath,ServerLeafSha256=[HostFixture.Pin(fixture.Server)],ClientCertificatePath=path,ClientCertificatePassword="golden-only",ClientRootCertificatePath=s.ClientRootCertificatePath,ServiceIdentity=HostFixture.Identity,PolicyVersion=s.ActionPolicy.Version});
        var reply=await sdk.ValidateAsync(credential,id=="forbidden-capability"?"backup.write":"backup.read",DateTimeOffset.UtcNow.AddSeconds(2),TestContext.Current.CancellationToken);
        Assert.Equal(expected,reply.HttpStatusCode);Assert.Equal(expected==200,reply.Subject is not null);Assert.Equal(0,db.Reads);Assert.Equal(0,db.Routes);Assert.Equal(0,cache.Writes);Assert.Equal(2,cache.Gets);
    }
}
