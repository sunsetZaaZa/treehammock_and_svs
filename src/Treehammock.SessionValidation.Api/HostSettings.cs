using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Treehammock.SessionValidation.Contracts;
using Treehammock.SessionValidation.Storage;
namespace Treehammock.SessionValidation.Api;

public sealed record ServiceCaller(string Identity, string[] Actions, string[] LeafSha256)
{ public override string ToString() => nameof(ServiceCaller); }
public sealed record CacheConnectionSettings(string Address, int Port, string TlsName, string Username, string Password, string RootCertificatePath, string LeafSha256)
{ public override string ToString() => nameof(CacheConnectionSettings); }
public sealed class HostSettings
{
    public string BindAddress { get; init; } = "";
    public int Port { get; init; }
    public string ServerCertificatePath { get; init; } = "";
    public string ServerCertificatePassword { get; init; } = "";
    public string ServerRootCertificatePath { get; init; } = "";
    public string ClientRootCertificatePath { get; init; } = "";
    public ServiceCaller[] Callers { get; init; } = [];
    public string DatabaseConnectionString { get; init; } = "";
    public TreehammockRoleMap Roles { get; init; } = new("", "", "", "", "", "");
    public CacheConnectionSettings Cache { get; init; } = new("", 0, "", "", "", "", "");
    public ActionPolicySettings ActionPolicy { get; init; } = new();
    public CapacitySettings Capacity { get; init; } = new();
    public MonitoringSettings? Monitoring { get; init; }
    public RefillSettings? Refill { get; init; }
    public treehammock.Rigging.Config.AuthorityFleetSettings? Fleet { get; init; }
    public string Issuer { get; init; } = "";
    public int MaximumConnections { get; init; } = 128;
    public int MaximumConcurrentRequests { get; init; } = 64;
    public int Http2StreamsPerConnection { get; init; } = 32;
    public int RequestTimeoutMilliseconds { get; init; } = 2000;
    public int ShutdownTimeoutMilliseconds { get; init; } = 5000;
    public int AuditIntervalMilliseconds { get; init; } = 10000;
    internal static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 16 };
    public static HostSettings Load(string path)
    {
        if (!Path.IsPathFullyQualified(path) || new FileInfo(path).Length > 65536) throw new ArgumentException("Bounded absolute configuration file required.");
        byte[] bytes = File.ReadAllBytes(path);
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
            Unique(document.RootElement);
            return JsonSerializer.Deserialize<HostSettings>(bytes, Json) ?? throw new ArgumentException("Host configuration required.");
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }
    private static void Unique(JsonElement node)
    {
        if (node.ValueKind == JsonValueKind.Object)
        { var seen = new HashSet<string>(StringComparer.Ordinal); foreach (var p in node.EnumerateObject()) { if (!seen.Add(p.Name)) throw new ArgumentException("Duplicate configuration property."); Unique(p.Value); } }
        else if (node.ValueKind == JsonValueKind.Array) foreach (var item in node.EnumerateArray()) Unique(item);
    }
    internal HostSettings Snapshot()
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(this, Json);
        try { var result = JsonSerializer.Deserialize<HostSettings>(bytes, Json)!; result.Validate(); return result; }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }
    internal void Validate()
    {
        if (!PrivateAddress(BindAddress) || Port is < 1 or > 65535 || string.IsNullOrWhiteSpace(Issuer) || Issuer.Length > 256 ||
            MaximumConnections is < 1 or > 1024 || MaximumConcurrentRequests is < 1 or > 1024 || Http2StreamsPerConnection is < 1 or > 128 ||
            RequestTimeoutMilliseconds is < 1 or > 5000 || ShutdownTimeoutMilliseconds is < 100 or > 10000 || AuditIntervalMilliseconds is < 1000 or > 10000)
            throw new ArgumentException("Explicit private listener and bounded host settings required.");
        foreach (string path in new[] { ServerCertificatePath, ServerRootCertificatePath, ClientRootCertificatePath, Cache?.RootCertificatePath ?? "" })
            if (!Path.IsPathFullyQualified(path) || !File.Exists(path)) throw new ArgumentException("Explicit certificate files required.");
        if (Callers is not { Length: >= 1 and <= 64 } || Callers.Any(c => c is null || c.LeafSha256 is not { Length: >= 1 and <= 4 } || c.LeafSha256.Any(p => !Pin(p)))) throw new ArgumentException("Explicit pinned callers required.");
        _ = new CallerPolicy(Callers.Select(c => new KeyValuePair<string, string[]>(c.Identity, c.Actions)));
        if (Callers.SelectMany(c => c.LeafSha256).Distinct(StringComparer.Ordinal).Count() != Callers.Sum(c => c.LeafSha256.Length)) throw new ArgumentException("Duplicate caller certificate pin.");
        if (Cache is null || !PrivateAddress(Cache.Address) || Cache.Port is < 1 or > 65535 || string.IsNullOrWhiteSpace(Cache.TlsName) || string.IsNullOrWhiteSpace(Cache.Username) || Cache.Username == "default" || string.IsNullOrEmpty(Cache.Password) || !Pin(Cache.LeafSha256)) throw new ArgumentException("Dedicated private verified cache connection required.");
        Monitoring?.Validate(Callers);
        ActionPolicy.Validate(); Refill?.Validate(this);
        if(Fleet is not null){System.ComponentModel.DataAnnotations.Validator.ValidateObject(Fleet,new(Fleet),true);if(Refill is null||Fleet.Port==Port)throw new ArgumentException("Complete separate private fleet/refill configuration required.");}
        Roles.Validate();
        var db = new Npgsql.NpgsqlConnectionStringBuilder(DatabaseConnectionString);
        if (!db.Pooling || db.MaxPoolSize is < 1 or > 16) throw new ArgumentException("Owned validator pool must be enabled and bounded to 16.");
        if (db.Username != Roles.Validator || db.SslMode != Npgsql.SslMode.VerifyFull || string.IsNullOrWhiteSpace(db.RootCertificate) || !Path.IsPathFullyQualified(db.RootCertificate) || !File.Exists(db.RootCertificate) || string.IsNullOrEmpty(db.Password)) throw new ArgumentException("Owned validator connection with explicit verified root required.");
        if(Capacity is null)throw new ArgumentException("Capacity settings required.");
        Capacity.Validate(this);
        using var unused = YsqlAuthorityDataSource.Create(DatabaseConnectionString);
    }
    internal static bool Pin(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
    internal static bool PrivateAddress(string? value)
    {
        if (!IPAddress.TryParse(value, out var ip)) return false;
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) return ip.IsIPv6UniqueLocal;
        var b = ip.GetAddressBytes(); return b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168;
    }
    public override string ToString() => nameof(HostSettings);
}
