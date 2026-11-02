using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.HostTests;
using Xunit;
namespace Treehammock.SessionValidation.SystemTests;

// Compiled into the existing HostTests assembly to exercise the real listener
// without adding a production friend assembly or a substitute authentication path.
public sealed class MtlsBoundaryTests(HostFixture fixture) : IClassFixture<HostFixture>
{
    private static async Task Denied(HttpClient http, string path = "/health/live")
    {
        try { using var response = await http.GetAsync(path, TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); }
        catch (HttpRequestException) { /* TLS rejection before HTTP routing. */ }
    }
    [Theory]
    [InlineData("X-Forwarded-Client-Cert")][InlineData("X-SSL-Client-Cert")]
    [InlineData("X-Client-Cert")][InlineData("X-Service-Identity")]
    public async Task Direct_origin_requires_TLS_possession_despite_forwarded_identity(string header)
    {
        var settings=fixture.Settings();await using var app=SvsHost.Build(settings,_=>new FakeResources());await app.StartAsync(TestContext.Current.CancellationToken);
        using var http=fixture.Http(settings,null);http.DefaultRequestHeaders.Add(header,HostFixture.Pin(fixture.Client));await Denied(http);
    }
    [Fact] public async Task Public_certificate_replay_without_private_key_is_rejected()
    {
        using var publicOnly=X509CertificateLoader.LoadCertificate(fixture.Client.RawData);Assert.False(publicOnly.HasPrivateKey);
        var settings=fixture.Settings();await using var app=SvsHost.Build(settings,_=>new FakeResources());await app.StartAsync(TestContext.Current.CancellationToken);
        using var http=fixture.Http(settings,publicOnly);await Denied(http);
    }
    [Fact] public async Task Leaf_pin_does_not_bypass_foreign_CA()
    {
        using var foreign=new HostFixture();var settings=fixture.Settings(j=>j["callers"]![0]!["leafSha256"]=new JsonArray(HostFixture.Pin(foreign.Client)));
        await using var app=SvsHost.Build(settings,_=>new FakeResources());await app.StartAsync(TestContext.Current.CancellationToken);
        using var http=fixture.Http(settings,foreign.Client);await Denied(http);
    }
    [Fact] public async Task Old_leaf_is_rejected_after_reviewed_pin_retirement()
    {
        var settings=fixture.Settings(j=>j["callers"]![0]!["leafSha256"]=new JsonArray(HostFixture.Pin(fixture.NextClient)));
        await using var app=SvsHost.Build(settings,_=>new FakeResources());await app.StartAsync(TestContext.Current.CancellationToken);
        using var retired=fixture.Http(settings,fixture.Client);await Denied(retired);
        using var next=fixture.Http(settings,fixture.NextClient);using var response=await next.GetAsync("/health/live",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,response.StatusCode);
    }
    [Fact] public async Task Rolling_CA_overlap_keeps_two_separately_pinned_replicas_and_rejects_cross_trust()
    {
        using var next=new HostFixture();var oldSettings=fixture.Settings();var nextSettings=next.Settings();
        await using var oldApp=SvsHost.Build(oldSettings,_=>new FakeResources());await using var nextApp=SvsHost.Build(nextSettings,_=>new FakeResources());
        await oldApp.StartAsync(TestContext.Current.CancellationToken);await nextApp.StartAsync(TestContext.Current.CancellationToken);
        using var oldClient=fixture.Http(oldSettings,fixture.Client);using var nextClient=next.Http(nextSettings,next.Client);
        using var a=await oldClient.GetAsync("/health/live",TestContext.Current.CancellationToken);using var b=await nextClient.GetAsync("/health/live",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,a.StatusCode);Assert.Equal(HttpStatusCode.OK,b.StatusCode);
        using var crossOld=fixture.Http(oldSettings,next.Client);using var crossNext=next.Http(nextSettings,fixture.Client);await Denied(crossOld);await Denied(crossNext);
    }
    [Fact] public async Task HTTP2_connection_is_reused_without_caching_request_identity()
    {
        var settings=fixture.Settings();await using var app=SvsHost.Build(settings,_=>new FakeResources());
        app.MapGet("/transport-observation",(HttpContext context)=>Results.Text(context.Connection.Id));await app.StartAsync(TestContext.Current.CancellationToken);
        using var http=fixture.Http(settings,fixture.Client);string? connection=null;
        for(int i=0;i<6;i++)
        {
            using var response=await http.GetAsync("/transport-observation",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,response.StatusCode);Assert.Equal(HttpVersion.Version20,response.Version);
            string observed=await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);Assert.False(string.IsNullOrEmpty(observed));connection??=observed;Assert.Equal(connection,observed);
        }
    }
    [Fact] public async Task Error_response_never_echoes_exception_or_credential_canaries()
    {
        const string canary="svs16-private-exception-canary";var settings=fixture.Settings();await using var app=SvsHost.Build(settings,_=>new FakeResources());
        app.MapGet("/throw-private",()=>Task.FromException<IResult>(new InvalidOperationException(canary)));await app.StartAsync(TestContext.Current.CancellationToken);
        using var http=fixture.Http(settings,fixture.Client);
        try { using var response=await http.GetAsync("/throw-private",TestContext.Current.CancellationToken);Assert.DoesNotContain(canary,await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));Assert.NotEqual(HttpStatusCode.OK,response.StatusCode); }
        catch(HttpRequestException error){Assert.DoesNotContain(canary,error.ToString());}
    }
}
