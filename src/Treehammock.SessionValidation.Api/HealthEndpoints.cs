using System.Security.Claims;
using Treehammock.SessionValidation.Contracts;
namespace Treehammock.SessionValidation.Api;
public sealed record MonitoringSettings(string Identity,string[] LeafSha256)
{
    internal void Validate(ServiceCaller[] callers)
    {
        _=new CallerPolicy([new KeyValuePair<string,string[]>(Identity,["backup.read"])]);
        if(LeafSha256 is not {Length:>=1 and <=4}||LeafSha256.Any(p=>!HostSettings.Pin(p))||LeafSha256.Distinct(StringComparer.Ordinal).Count()!=LeafSha256.Length||callers.Any(c=>c.Identity==Identity||c.LeafSha256.Intersect(LeafSha256,StringComparer.Ordinal).Any()))throw new ArgumentException("Separate pinned monitor required.");
    }
    public override string ToString()=>nameof(MonitoringSettings);
}
internal sealed record OperationalHealth(bool Live,bool Ready,string Mode,bool DatabaseFallbackReady,bool CacheReady,bool RefillReady,bool AuthorityWriteReady,bool ServerCertificateNearExpiry,bool ClockOffsetKnown);
internal static class HealthEndpoints
{
    internal static OperationalHealth Capture(HostLifecycle life,IHostResources resources,ServiceCertificates certificates,DateTimeOffset? now=null)
    {
        bool ready=life.Ready,db=resources.DatabaseReady,cache=resources.Admission.CacheReady;
        return new(life.Live,ready,!ready?"NotReady":cache?db?"CacheAndDatabaseReady":"CacheReady":"DatabaseFallbackReady",db,cache,db&&resources is IFleetResources f&&f.RefillReady,false,certificates.Server.NotAfter.ToUniversalTime()-(now??DateTimeOffset.UtcNow).UtcDateTime<=TimeSpan.FromDays(7),false);
    }
    internal static bool IsOperational(PathString p)=>p=="/metrics"||p=="/operations/status";
    internal static bool IsMonitor(ClaimsPrincipal p,HostSettings s)=>s.Monitoring is {} m&&p.FindFirstValue(ClaimTypes.NameIdentifier)==m.Identity;
    internal static void Map(WebApplication app)
    {
        app.MapGet("/health/live",(HostLifecycle l)=>Results.Json(new{status=l.Live?"live":"stopped"},statusCode:l.Live?200:503));
        app.MapGet("/health/ready",(HostLifecycle l,IHostResources r,ServiceCertificates c)=>{var h=Capture(l,r,c);return Results.Json(h,statusCode:h.Ready?200:503);});
        app.MapGet("/operations/status",(HostLifecycle l,IHostResources r,ServiceCertificates c,RequestLifetime q)=>Results.Json(new{health=Capture(l,r,c),requests=q.Snapshot}));
        app.MapGet("/metrics",(HostLifecycle l,IHostResources r,ServiceCertificates c,Metrics m)=>Results.Text(m.Render(Capture(l,r,c)),"text/plain; version=0.0.4"));
    }
}
