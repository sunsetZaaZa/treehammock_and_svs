using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Google.Protobuf;
using Microsoft.Extensions.DependencyInjection;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.HostTests;
using Treehammock.SessionValidation.Contracts.V1;
using treehammock.Rigging.Fleet;
using Xunit;
namespace Treehammock.SessionValidation.SystemTests;
public sealed class OperationsTests(HostFixture fixture):IClassFixture<HostFixture>
{
    private const string Monitor="spiffe://intranet.local/service/svs-monitor";
    [Fact] public async Task Separate_monitor_role_scrapes_and_cannot_validate_or_be_forged_by_headers()
    {
        using var cert=fixture.Leaf(false,Monitor);var s=fixture.Settings(n=>n["monitoring"]=JsonSerializer.SerializeToNode(new MonitoringSettings(Monitor,[HostFixture.Pin(cert)]),HostSettings.Json));
        await using var app=SvsHost.Build(s,_=>new FakeResources());await app.StartAsync(TestContext.Current.CancellationToken);using var monitor=fixture.Http(s,cert);using var caller=fixture.Http(s,fixture.Client);
        using var response=await monitor.GetAsync("/metrics",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,response.StatusCode);Assert.Equal(HttpVersion.Version20,response.Version);Assert.Equal("no-store",response.Headers.CacheControl!.ToString());string text=await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);Assert.Contains("svs_ready 1",text);Assert.Contains("svs_clock_offset_known 0",text);Assert.DoesNotContain(Monitor,text);Assert.DoesNotContain("database-private-canary",text);
        using var status=await monitor.GetAsync("/operations/status",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,status.StatusCode);
        caller.DefaultRequestHeaders.Add("X-Forwarded-Client-Cert",HostFixture.Pin(cert));using var denied=await caller.GetAsync("/metrics",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Forbidden,denied.StatusCode);
        using var rpc=await monitor.PostAsync(RpcWire.Path,new ByteArrayContent([]),TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Forbidden,rpc.StatusCode);
    }
    [Fact] public void Monitor_cannot_reuse_validation_pin_or_identity()
    {
        var s=fixture.Settings(n=>n["monitoring"]=JsonSerializer.SerializeToNode(new MonitoringSettings(Monitor,[HostFixture.Pin(fixture.Client)]),HostSettings.Json));Assert.Throws<ArgumentException>(()=>s.Snapshot());
        s=fixture.Settings(n=>n["monitoring"]=JsonSerializer.SerializeToNode(new MonitoringSettings(HostFixture.Identity,[new string('B',64)]),HostSettings.Json));Assert.Throws<ArgumentException>(()=>s.Snapshot());
    }
    [Fact] public async Task Operational_routes_default_deny_existing_callers()
    {
        var s=fixture.Settings();await using var app=SvsHost.Build(s,_=>new FakeResources());await app.StartAsync(TestContext.Current.CancellationToken);using var c=fixture.Http(s,fixture.Client);
        foreach(var path in new[]{"/metrics","/operations/status"}){using var r=await c.GetAsync(path,TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Forbidden,r.StatusCode);}
    }
    [Fact] public async Task Healthy_database_does_not_admit_unadmitted_fleet()
    {
        var s=CoherentHostTests.Settings(fixture);using var a=new CoherentHostTests.RpcResourcesOwner();var db=new CoherentHostTests.Database(a.Value);var cache=new CoherentHostTests.Cache(s,a.Value);await using var app=SvsHost.Build(s,c=>new CoherentResources(c,db,cache));await app.StartAsync(TestContext.Current.CancellationToken);using var c=fixture.Http(s,fixture.Client);using var r=await c.GetAsync("/health/ready",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.ServiceUnavailable,r.StatusCode);Assert.Equal(FleetMode.Unadmitted,((CoherentResources)app.Services.GetRequiredService<IHostResources>()).Gate.Mode);
    }
    [Fact] public async Task Database_outage_keeps_cache_hits_zero_SQL_and_misses_unavailable_then_quarantine_closes_readiness()
    {
        var s=CoherentHostTests.Settings(fixture);using var a=new CoherentHostTests.RpcResourcesOwner();var db=new CoherentHostTests.Database(a.Value);var cache=new CoherentHostTests.Cache(s,a.Value);await using var app=SvsHost.Build(s,c=>new CoherentResources(c,db,cache));await app.StartAsync(TestContext.Current.CancellationToken);var resources=(CoherentResources)app.Services.GetRequiredService<IHostResources>();await Activate(s,resources,db);db.Down=true;string token=a.Value.Credential();cache.Set(token);using var c=fixture.Http(s,fixture.Client);
        using var health=await c.GetAsync("/health/ready",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,health.StatusCode);Assert.Contains("CacheReady",await health.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var hit=await RpcWire.Call(c,RpcWire.Request(token).ToByteArray(),token:TestContext.Current.CancellationToken);Assert.Equal(Decision.Active,RpcWire.Reply(hit.Body).Decision);Assert.Equal(0,db.Reads);Assert.Equal(0,db.Routes);Assert.Equal(0,cache.Writes);
        var miss=await RpcWire.Call(c,RpcWire.Request(a.Value.Credential(true)).ToByteArray(),token:TestContext.Current.CancellationToken);Assert.Equal(Decision.Unavailable,RpcWire.Reply(miss.Body).Decision);resources.Quarantine();using var closed=await c.GetAsync("/health/ready",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.ServiceUnavailable,closed.StatusCode);
    }
    [Fact] public async Task Cache_outage_retains_bounded_database_fallback_in_serving_fleet()
    {
        var s=CoherentHostTests.Settings(fixture);using var a=new CoherentHostTests.RpcResourcesOwner();var db=new CoherentHostTests.Database(a.Value);var cache=new CoherentHostTests.Cache(s,a.Value);await using var app=SvsHost.Build(s,c=>new CoherentResources(c,db,cache));await app.StartAsync(TestContext.Current.CancellationToken);var resources=(CoherentResources)app.Services.GetRequiredService<IHostResources>();await Activate(s,resources,db);cache.Quarantine();using var c=fixture.Http(s,fixture.Client);using var health=await c.GetAsync("/health/ready",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,health.StatusCode);Assert.Contains("DatabaseFallbackReady",await health.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));var r=await RpcWire.Call(c,RpcWire.Request(a.Value.Credential()).ToByteArray(),token:TestContext.Current.CancellationToken);Assert.Equal(Decision.Active,RpcWire.Reply(r.Body).Decision);Assert.Equal(1,db.Reads);Assert.Equal(0,cache.Writes);
    }
    [Fact] public async Task Certificate_expiry_warning_and_unknown_clock_do_not_grant_authority()
    {
        var s=fixture.Settings();var r=new FakeResources();var q=new RequestLifetime(1);using var life=new HostLifecycle(r,q,s);using var cert=new ServiceCertificates(s);await life.StartAsync(TestContext.Current.CancellationToken);var h=HealthEndpoints.Capture(life,r,cert,new DateTimeOffset(cert.Server.NotAfter.ToUniversalTime()).AddDays(-1));Assert.True(h.ServerCertificateNearExpiry);Assert.False(h.ClockOffsetKnown);Assert.False(h.AuthorityWriteReady);Assert.True(h.Ready);await life.StopAsync(TestContext.Current.CancellationToken);
    }
    [Fact] public void Metrics_are_fixed_cardinality_concurrent_and_do_not_truncate_slow_calls()
    {
        var m=new Metrics();Parallel.For(0,10000,n=>m.Record(n%5,TimeSpan.FromMilliseconds(n%100)));var h=new OperationalHealth(true,false,"NotReady",false,false,false,false,false,false);string text=m.Render(h);foreach(var d in new[]{"active","unauthenticated","forbidden","unavailable","refused"})Assert.Contains("decision=\""+d+"\"} 2000",text);Assert.Contains("svs_validation_handler_seconds_count 10000",text);Assert.True(text.Length<10000);var slow=new Metrics();slow.Record(3,TimeSpan.FromSeconds(6));text=slow.Render(h);Assert.Contains("le=\"5\"} 0",text);Assert.Contains("le=\"+Inf\"} 1",text);Assert.Contains("svs_validation_handler_seconds_sum 6",text);
    }
    private async Task Activate(HostSettings s,CoherentResources r,CoherentHostTests.Database db)
    {
        using var c=fixture.Http(s,fixture.NextClient);c.BaseAddress=new($"https://127.0.0.1:{s.Fleet!.Port}");var status=(await CoherentHostTests.Control(c,new("status",FleetProtocol.Nonce(),Guid.Empty,0,Guid.Empty,""))).Reply!;var b=CoherentHostTests.Binding(s,r);db.Expected=b;var prepared=await CoherentHostTests.Control(c,CoherentHostTests.Request("prepare",status,b));Assert.Equal(HttpStatusCode.OK,prepared.Status);db.Committed=true;Assert.Equal(HttpStatusCode.OK,(await CoherentHostTests.Control(c,CoherentHostTests.Request("activate",status,b,prepared.Reply!.Prepared))).Status);
    }
}
