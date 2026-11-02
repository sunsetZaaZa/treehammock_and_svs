using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.Storage;
namespace Treehammock.SessionValidation.HostTests;

public sealed class HostFixture : IDisposable
{
    internal const string Identity = "spiffe://intranet.local/service/contact-backup";
    internal string Directory { get; } = Path.Combine(Path.GetTempPath(), "svs07-" + Guid.NewGuid().ToString("N"));
    internal X509Certificate2 Root { get; }
    internal X509Certificate2 Server { get; }
    internal X509Certificate2 Client { get; }
    internal X509Certificate2 NextClient { get; }
    public HostFixture()
    {
        System.IO.Directory.CreateDirectory(Directory);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=SVS07 test root", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        Root = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(30));
        Server = Leaf(true); Client = Leaf(false); NextClient = Leaf(false);
        File.WriteAllBytes(Path.Combine(Directory, "root.cer"), Root.RawData);
        File.WriteAllBytes(Path.Combine(Directory, "server.pfx"), Server.Export(X509ContentType.Pfx, "test-pfx-password"));
    }
    internal X509Certificate2 Leaf(bool server, string? identity = Identity, string? eku = null, DateTimeOffset? before = null, DateTimeOffset? after = null, bool includeEku = true)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=SVS07 test leaf", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        if (includeEku) request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(eku ?? (server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2")) }, true));
        var san = new SubjectAlternativeNameBuilder();
        if (server) { san.AddDnsName("localhost"); san.AddIpAddress(IPAddress.Loopback); }
        else if (identity is not null) san.AddUri(new Uri(identity));
        if (server || identity is not null) request.CertificateExtensions.Add(san.Build());
        using var cert = request.Create(Root, before ?? DateTimeOffset.UtcNow.AddMinutes(-10), after ?? DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        return cert.CopyWithPrivateKey(key);
    }
    internal static string Pin(X509Certificate2 cert) => Convert.ToHexString(SHA256.HashData(cert.RawData));
    internal HostSettings Settings(Action<JsonObject>? change = null)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
        var options = new HostSettings
        {
            BindAddress = "127.0.0.1", Port = port, ServerCertificatePath = Path.Combine(Directory, "server.pfx"), ServerCertificatePassword = "test-pfx-password",
            ServerRootCertificatePath = Path.Combine(Directory, "root.cer"), ClientRootCertificatePath = Path.Combine(Directory, "root.cer"),
            Callers = [new(Identity, ["backup.read", "backup.write"], [Pin(Client), Pin(NextClient)])],
            Roles = new("app", "coordinator", "validator", "maintenance", "owner", "treehammock_svs_read"),
            DatabaseConnectionString = new Npgsql.NpgsqlConnectionStringBuilder { Host = "127.0.0.1", Port = 1, Database = "owned", Username = "validator", Password = "database-private-canary", SslMode = Npgsql.SslMode.VerifyFull, RootCertificate = Path.Combine(Directory, "root.cer"), Enlist = false, MaxPoolSize = 8, MinPoolSize = 0, Timeout = 1, CommandTimeout = 2, CancellationTimeout = 1000 }.ConnectionString,
            Cache = new("127.0.0.1", 1, "localhost", "svs-reader", "cache-private-canary", Path.Combine(Directory, "root.cer"), Pin(Server)),
            Issuer = "test-issuer"
        };
        var node = JsonSerializer.SerializeToNode(options, HostSettings.Json)!.AsObject(); change?.Invoke(node);
        return node.Deserialize<HostSettings>(HostSettings.Json)!;
    }
    internal HttpClient Http(HostSettings settings, X509Certificate2? client, bool trustServer = true)
    {
        var handler = new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false, UseCookies = false };
        handler.SslOptions = new SslClientAuthenticationOptions
        {
            ClientCertificates = client is null ? [] : new X509CertificateCollection { client },
            RemoteCertificateValidationCallback = (_, cert, _, errors) =>
            {
                if (!trustServer || cert is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
                using var leaf = X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
                return Pin(leaf) == Pin(Server) && ServiceCertificates.ValidLeaf(leaf, Root, "1.3.6.1.5.5.7.3.1");
            }
        };
        return new(handler) { BaseAddress = new Uri($"https://127.0.0.1:{settings.Port}"), DefaultRequestVersion = HttpVersion.Version20, DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact, Timeout = TimeSpan.FromSeconds(4) };
    }
    public void Dispose() { Client.Dispose(); NextClient.Dispose(); Server.Dispose(); Root.Dispose(); System.IO.Directory.Delete(Directory, true); }
}

internal sealed class FakeResources : IHostResources
{
    internal DatabaseIdentityAuditStatus Next = DatabaseIdentityAuditStatus.Verified;
    internal int Audits, Disposals;
    internal TaskCompletionSource AuditedAgain = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public bool DatabaseReady => LastAudit == DatabaseIdentityAuditStatus.Verified;
    public DatabaseIdentityAuditStatus LastAudit { get; private set; }
    public SessionCacheAdmission Admission { get; } = new();
    public SessionEvidenceCoordinator Coordinator { get; } = new(new(new NullStore(), new(), TimeSpan.FromMilliseconds(100), TimeSpan.FromSeconds(30)), new NullAuthority(), "test-issuer", TimeSpan.FromSeconds(1));
    public Task AuditAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); LastAudit = Next; if (Interlocked.Increment(ref Audits) > 1) AuditedAgain.TrySetResult(); return Task.CompletedTask; }
    public ValueTask DisposeAsync() { Interlocked.Increment(ref Disposals); Admission.Quarantine(); return ValueTask.CompletedTask; }
    private sealed class NullStore : ICoherentCacheGetStore { public Task<byte[]?> GetAsync(string key, CancellationToken token) => throw new InvalidOperationException("Unadmitted cache must not be queried."); }
    private sealed class NullAuthority : IReadonlySessionAuthority { public Task<AuthorityReadResult> ReadAsync(string accessTokenHash, NodaTime.Instant deadline, CancellationToken cancellationToken = default) => Task.FromException<AuthorityReadResult>(new InvalidOperationException("Substituted authority unavailable.")); }
}
