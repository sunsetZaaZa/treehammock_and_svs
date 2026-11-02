using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.HostTests;

public sealed class HostConfigurationTests(HostFixture fixture) : IClassFixture<HostFixture>
{
    [Theory]
    [InlineData("wildcard")][InlineData("public")][InlineData("dns-bind")][InlineData("no-port")][InlineData("connections")][InlineData("requests")][InlineData("streams")]
    [InlineData("deadline")][InlineData("shutdown")][InlineData("audit")][InlineData("no-caller")][InlineData("wildcard-action")][InlineData("duplicate-pin")]
    [InlineData("bad-pin")][InlineData("bad-identity")][InlineData("missing-cert")][InlineData("cache-public")][InlineData("cache-default-user")][InlineData("cache-no-password")]
    [InlineData("cache-no-pin")][InlineData("writer-db")][InlineData("plaintext-db")][InlineData("unverified-db")][InlineData("unbounded-pool")][InlineData("no-pool")][InlineData("no-root")]
    public void Rejects_incomplete_public_or_unbounded_configuration(string kind)
    {
        var settings = fixture.Settings(j =>
        {
            switch (kind)
            {
                case "wildcard": j["bindAddress"] = "0.0.0.0"; break; case "public": j["bindAddress"] = "8.8.8.8"; break; case "dns-bind": j["bindAddress"] = "localhost"; break;
                case "no-port": j["port"] = 0; break; case "connections": j["maximumConnections"] = 0; break; case "requests": j["maximumConcurrentRequests"] = 2000; break;
                case "streams": j["http2StreamsPerConnection"] = 0; break; case "deadline": j["requestTimeoutMilliseconds"] = 6000; break; case "shutdown": j["shutdownTimeoutMilliseconds"] = 0; break;
                case "audit": j["auditIntervalMilliseconds"] = 31000; break;
                case "no-caller": j["callers"] = new JsonArray(); break; case "wildcard-action": j["callers"]![0]!["actions"] = new JsonArray("*"); break;
                case "duplicate-pin": j["callers"]![0]!["leafSha256"] = new JsonArray(HostFixture.Pin(fixture.Client), HostFixture.Pin(fixture.Client)); break;
                case "bad-pin": j["callers"]![0]!["leafSha256"] = new JsonArray("bad"); break;
                case "bad-identity": j["callers"]![0]!["identity"] = "spiffe://intranet.local/service/*"; break;
                case "missing-cert": j["serverCertificatePath"] = "relative.pfx"; break;
                case "cache-public": j["cache"]!["address"] = "8.8.8.8"; break; case "cache-default-user": j["cache"]!["username"] = "default"; break;
                case "cache-no-password": j["cache"]!["password"] = ""; break; case "cache-no-pin": j["cache"]!["leafSha256"] = ""; break;
                default:
                    var db = new Npgsql.NpgsqlConnectionStringBuilder(j["databaseConnectionString"]!.GetValue<string>());
                    switch (kind) { case "writer-db": db.Username = "coordinator"; break; case "plaintext-db": db.SslMode = Npgsql.SslMode.Disable; break; case "unverified-db": db.SslMode = Npgsql.SslMode.Require; break; case "unbounded-pool": db.MaxPoolSize = 1000; break; case "no-pool": db.Pooling = false; break; case "no-root": db.RootCertificate = ""; break; }
                    j["databaseConnectionString"] = db.ConnectionString; break;
            }
        });
        Assert.ThrowsAny<ArgumentException>(() => SvsHost.Build(settings, _ => new FakeResources()));
    }
    [Theory][InlineData("unknown")][InlineData("duplicate")][InlineData("oversized")]
    public void JSON_configuration_is_closed_and_bounded(string kind)
    {
        string data = JsonSerializer.Serialize(fixture.Settings(), HostSettings.Json);
        data = kind switch { "unknown" => data[..^1] + ",\"nativePassed\":true}", "duplicate" => data[..^1] + ",\"port\":4444}", _ => new string(' ', 65537) };
        string path = Path.Combine(fixture.Directory, kind + ".json"); File.WriteAllText(path, data);
        Assert.ThrowsAny<Exception>(() => HostSettings.Load(path));
    }
    [Fact] public async Task Normal_production_registration_keeps_typed_resources_and_cache_unadmitted()
    {
        await using var app = SvsHost.Build(fixture.Settings());
        var resources = app.Services.GetRequiredService<IHostResources>(); Assert.IsType<HostResources>(resources);
        Assert.False(resources.DatabaseReady); Assert.False(resources.Admission.CacheReady);
        Assert.Same(resources.Coordinator, app.Services.GetRequiredService<SessionEvidenceCoordinator>());
        var decision = await resources.Coordinator.ValidateAsync("synthetic-credential", "backup.read", NodaTime.SystemClock.Instance.GetCurrentInstant() + NodaTime.Duration.FromSeconds(1), TestContext.Current.CancellationToken);
        Assert.Equal(Treehammock.SessionValidation.Core.SessionDecision.Unavailable, decision.Decision);
    }
    [Fact] public void Settings_and_connection_wrappers_have_redacted_string_representations()
    {
        var options = fixture.Settings();
        foreach (var text in new[] { options.ToString(), options.Cache.ToString(), options.Roles.ToString(), options.Callers[0].ToString() })
        { Assert.DoesNotContain("private-canary", text); Assert.DoesNotContain("test-pfx-password", text); }
    }
    [Theory][InlineData("expired")][InlineData("client-eku")][InlineData("no-key")]
    public void Invalid_server_certificate_prevents_host_construction(string kind)
    {
        using var leaf = kind == "expired" ? fixture.Leaf(true, before: DateTimeOffset.UtcNow.AddDays(-2), after: DateTimeOffset.UtcNow.AddDays(-1)) : fixture.Leaf(kind != "client-eku");
        string path = Path.Combine(fixture.Directory, kind + ".pfx");
        byte[] bytes;
        if (kind == "no-key") { using var publicOnly = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(leaf.RawData); bytes = publicOnly.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "test-pfx-password"); }
        else bytes = leaf.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, "test-pfx-password");
        File.WriteAllBytes(path, bytes);
        Assert.ThrowsAny<Exception>(() => SvsHost.Build(fixture.Settings(j => j["serverCertificatePath"] = path), _ => new FakeResources()));
    }
}
