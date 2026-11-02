using treehammock.Rigging.Config;
namespace Treehammock.SessionValidation.Api;

// Optional configured local worker. There is no outbound refill HTTP destination.
public sealed class RefillSettings
{
    public string DatabaseConnectionString { get; init; } = "";
    public CacheConnectionSettings PublisherCache { get; init; } = new("",0,"","","","","");
    public string Environment { get; init; } = "";
    public Guid Epoch { get; init; }
    public string Policy { get; init; } = "";
    public string PrimaryRunId { get; init; } = "";
    public string DragonflyVersion { get; init; } = "";
    public int QueueCapacity { get; init; } = 128;
    public int Workers { get; init; } = 2;
    public int PublicationsPerSecond { get; init; } = 10;
    public int CompletedCooldownMilliseconds { get; init; } = 1000;
    public int MaximumQueueAgeMilliseconds { get; init; } = 5000;
    public int OperationTimeoutMilliseconds { get; init; } = 1500;
    public int WarmupIntervalMilliseconds { get; init; }
    internal void ValidateBounds()
    {
        if(QueueCapacity is <1 or >1024||Workers is <1 or >8||PublicationsPerSecond is <1 or >1000||CompletedCooldownMilliseconds is <1 or >30000||MaximumQueueAgeMilliseconds is <100 or >30000||OperationTimeoutMilliseconds is <100 or >3000||WarmupIntervalMilliseconds!=0&&(WarmupIntervalMilliseconds is <1000 or >300000))throw new ArgumentException("Bounded local refill settings required.");
    }
    internal void Validate(HostSettings host)
    {
        ValidateBounds();if(host.Fleet is null)throw new ArgumentException("Local publication requires the actual fleet lifecycle.");
        var db=new Npgsql.NpgsqlConnectionStringBuilder(DatabaseConnectionString);var foreground=new Npgsql.NpgsqlConnectionStringBuilder(host.DatabaseConnectionString);
        if(db.Username!=host.Roles.Refiller||db.Password==foreground.Password||string.IsNullOrEmpty(db.Password)||!db.Pooling||db.MaxPoolSize!=Workers||db.MinPoolSize!=0||db.SearchPath!="public,pg_catalog,pg_temp"||db.SslMode!=Npgsql.SslMode.VerifyFull||db.Host!=foreground.Host||db.Port!=foreground.Port||db.Database!=foreground.Database||!Path.IsPathFullyQualified(db.RootCertificate??"")||!File.Exists(db.RootCertificate))throw new ArgumentException("Distinct bounded verified refiller SQL pool required.");
        using var unused=Storage.YsqlAuthorityDataSource.Create(DatabaseConnectionString);
        var c=PublisherCache;if(c is null||!HostSettings.PrivateAddress(c.Address)||c.Port!=host.Cache.Port||c.Address!=host.Cache.Address||!treehammock.Rigging.Fleet.FleetProtocol.Name(c.Username)||c.Username==host.Cache.Username||c.Password==host.Cache.Password||string.IsNullOrEmpty(c.Password)||!HostSettings.Pin(c.LeafSha256)||!Path.IsPathFullyQualified(c.RootCertificatePath)||!File.Exists(c.RootCertificatePath)||Uri.CheckHostName(c.TlsName)!=UriHostNameType.Dns)throw new ArgumentException("Distinct pinned cache publisher on the same primary required.");
        if(!treehammock.Rigging.Fleet.FleetProtocol.Name(host.Cache.Username)||!treehammock.Rigging.Fleet.FleetProtocol.Label(Environment,32)||Epoch==Guid.Empty||!treehammock.Rigging.Fleet.FleetProtocol.Label(Policy,64)||PrimaryRunId is not {Length:40}||PrimaryRunId.Any(c=>c is not (>= '0' and <= '9' or >= 'a' and <= 'f'))||string.IsNullOrWhiteSpace(DragonflyVersion))throw new ArgumentException("Explicit coherent incarnation required.");
    }
    public override string ToString()=>nameof(RefillSettings);
}
