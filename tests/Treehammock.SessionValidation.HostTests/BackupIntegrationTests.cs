using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Backup.Identity;
using Microsoft.AspNetCore.Http;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.Client;
using Treehammock.SessionValidation.Storage;
using Xunit;
using Treehammock.SessionValidation.Core;
using SessionDecision = Backup.Identity.SessionDecision;
namespace Treehammock.SessionValidation.HostTests;
public sealed class BackupIntegrationTests(HostFixture fixture) : IClassFixture<HostFixture>
{
    private HostSettings Settings() => fixture.Settings(j => {
        j["callers"]![0]!["actions"] = JsonSerializer.SerializeToNode(new[]{"backup.read","backup.write","recovery_package.read","recovery_package.write"});
        j["actionPolicy"] = JsonNode.Parse("""{"version":"backup-test.v1","requirements":{"backup.read":"account.read","backup.write":"account.manage","recovery_package.read":"account.read","recovery_package.write":"account.manage"}}""");
    });
    private ClientOptions Options(HostSettings s, bool next = false) {
        var path = Path.Combine(fixture.Directory, Guid.NewGuid()+".pfx"); File.WriteAllBytes(path,(next?fixture.NextClient:fixture.Client).Export(X509ContentType.Pfx,"sdk-test"));
        return new(){TlsName="localhost",PrivateAddress="127.0.0.1",Port=s.Port,ServerRootCertificatePath=s.ServerRootCertificatePath,ServerLeafSha256=[HostFixture.Pin(fixture.Server)],ClientCertificatePath=path,ClientCertificatePassword="sdk-test",ClientRootCertificatePath=s.ClientRootCertificatePath,ServiceIdentity=HostFixture.Identity,PolicyVersion=s.ActionPolicy.Version};
    }
    [Theory][InlineData("active","backup.read",200)][InlineData("active","recovery_package.read",200)][InlineData("write","backup.write",403)][InlineData("write","recovery_package.write",403)][InlineData("signature","backup.read",401)][InlineData("purpose","backup.read",401)][InlineData("missing","backup.read",401)][InlineData("outage","backup.read",503)]
    public async Task Middleware_uses_real_sdk_mtls_and_never_client_ownership(string kind,string action,int status) {
        var r=new RpcResources(); if(kind=="missing")r.Status=AuthorityReadStatus.NotFound;if(kind=="outage")r.Status=AuthorityReadStatus.Unavailable;
        var s=Settings(); await using var host=SvsHost.Build(s,_=>r);await host.StartAsync(TestContext.Current.CancellationToken);
        await using var validator=new SvsIdentitySessionValidator(Options(s));var c=new DefaultHttpContext();c.Request.Path="/v1/session";c.Request.Headers.Authorization="Bearer "+r.Credential(kind=="signature",kind=="purpose"?"refresh_v2":"active_v2");c.Request.Headers["X-Subject-ID"]=Guid.NewGuid().ToString();c.Response.Body=new MemoryStream();c.SetEndpoint(new Endpoint(_=>Task.CompletedTask,new EndpointMetadataCollection(new RequiredSvsAction(action)),"test"));
        bool ran=false;await new IdentitySessionMiddleware(ctx=>{ran=true;var i=RequestIdentity.Required(ctx);Assert.Equal(r.Identity.AccountId,i.SubjectId);Assert.Equal(r.Identity.FamilyId,i.SessionFamilyId);Assert.Equal(7,i.Generation);Assert.Equal((uint)2,i.ProtocolVersion);Assert.Equal(action,i.RequestedAction);Assert.True(BackupOwnership.IsOwnedBy(i,r.Identity.AccountId));Assert.Equal(404,BackupOwnership.PrivateNotFoundStatus(i,Guid.NewGuid()));return Task.CompletedTask;}).InvokeAsync(c,validator);
        Assert.Equal(status,c.Response.StatusCode);Assert.Equal(status==200,ran);if(status!=200){Assert.Null(c.Features.Get<VerifiedRequestIdentity>());Assert.Equal("no-store",c.Response.Headers.CacheControl.ToString());}
    }
    [Fact] public async Task Revocation_is_checked_on_each_request_and_next_certificate_works() {
        var r=new RpcResources();var s=Settings();await using var host=SvsHost.Build(s,_=>r);await host.StartAsync(TestContext.Current.CancellationToken);await using var v=new SvsIdentitySessionValidator(Options(s,true));var token=r.Credential();Assert.Equal(SessionDecision.Active,(await v.ValidateCurrentSessionAsync(token,"backup.read",TestContext.Current.CancellationToken)).Decision);r.Status=AuthorityReadStatus.NotFound;Assert.Equal(SessionDecision.Unauthenticated,(await v.ValidateCurrentSessionAsync(token,"backup.read",TestContext.Current.CancellationToken)).Decision);Assert.Equal(2,r.Calls);
    }
    [Fact] public async Task Actual_backup_composition_requires_bearer_and_uses_svs() {
        var r=new RpcResources();var s=Settings();await using var host=SvsHost.Build(s,_=>r);await host.StartAsync(TestContext.Current.CancellationToken);var path=Path.Combine(fixture.Directory,Guid.NewGuid()+".json");File.WriteAllText(path,JsonSerializer.Serialize(Options(s),new JsonSerializerOptions{PropertyNamingPolicy=JsonNamingPolicy.CamelCase}));if(!OperatingSystem.IsWindows())File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite);
        await using var app=Backup.Api.BackupApiHost.Build(["--urls","http://127.0.0.1:0"],path);await app.StartAsync(TestContext.Current.CancellationToken);using var http=new HttpClient{BaseAddress=new Uri(app.Urls.Single())};Assert.Equal(401,(int)(await http.GetAsync("/v1/session",TestContext.Current.CancellationToken)).StatusCode);Assert.Equal(0,r.Calls);http.DefaultRequestHeaders.Authorization=new("Bearer",r.Credential());Assert.Equal(200,(int)(await http.GetAsync("/v1/session",TestContext.Current.CancellationToken)).StatusCode);r.Status=AuthorityReadStatus.Unavailable;var response=await http.GetAsync("/v1/session",TestContext.Current.CancellationToken);Assert.Equal(503,(int)response.StatusCode);Assert.True(response.Headers.CacheControl!.NoStore);Assert.True(response.Headers.CacheControl.Private);
    }
    [Fact] public async Task Absent_authority_has_no_json_or_local_jwt_fallback(){var s=Settings();await using var v=new SvsIdentitySessionValidator(Options(s));Assert.Equal(SessionDecision.AuthorityUnavailable,(await v.ValidateCurrentSessionAsync("opaque","backup.read",TestContext.Current.CancellationToken)).Decision);}
    [Fact] public async Task Retired_client_pin_is_refused_while_next_pin_is_accepted() {
        var r=new RpcResources();var s=fixture.Settings(j=>{j["callers"]![0]!["leafSha256"]=JsonSerializer.SerializeToNode(new[]{HostFixture.Pin(fixture.NextClient)});j["actionPolicy"]=JsonNode.Parse("""{"version":"backup-test.v1","requirements":{"backup.read":"account.read"}}""");});
        await using var host=SvsHost.Build(s,_=>r);await host.StartAsync(TestContext.Current.CancellationToken);await using var old=new SvsIdentitySessionValidator(Options(s));Assert.Equal(SessionDecision.AuthorityUnavailable,(await old.ValidateCurrentSessionAsync(r.Credential(),"backup.read",TestContext.Current.CancellationToken)).Decision);await using var next=new SvsIdentitySessionValidator(Options(s,true));Assert.Equal(SessionDecision.Active,(await next.ValidateCurrentSessionAsync(r.Credential(),"backup.read",TestContext.Current.CancellationToken)).Decision);
    }
    [Theory][InlineData(true)][InlineData(false)] public async Task Expired_or_wrong_binding_projection_never_grants_identity(bool expired) {
        var r=new RpcResources();r.Read=(hash,_,_)=>{var now=NodaTime.SystemClock.Instance.GetCurrentInstant();return Task.FromResult(new AuthorityReadResult(AuthorityReadStatus.Found,new AuthSessionProjection(expired?hash:new string('A',64),r.Key,r.Identity,new(now+NodaTime.Duration.FromSeconds(expired?-1:60),now+NodaTime.Duration.FromHours(1),null),new(r.Identity.AccountId,1,1,["account.read"],false,now,now+NodaTime.Duration.FromMinutes(1),null,true),now)));};var s=Settings();await using var host=SvsHost.Build(s,_=>r);await host.StartAsync(TestContext.Current.CancellationToken);await using var validator=new SvsIdentitySessionValidator(Options(s));var result=await validator.ValidateCurrentSessionAsync(r.Credential(),"backup.read",TestContext.Current.CancellationToken);Assert.Equal(SessionDecision.Unauthenticated,result.Decision);Assert.Null(result.Identity);
    }

}
