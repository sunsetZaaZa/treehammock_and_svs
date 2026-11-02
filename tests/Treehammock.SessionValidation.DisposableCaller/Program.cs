using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Treehammock.SessionValidation.Client;

// Disposable test consumer only. Each process owns distinct client TLS material;
// requests go through the real SDK to the selected replica, with no positive cache.
var json = new JsonSerializerOptions { PropertyNameCaseInsensitive = true, UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow };
var directory = Environment.GetEnvironmentVariable("SVS15_FIXTURE_DIRECTORY") ?? "/run/fixture";
if (!Path.IsPathFullyQualified(directory)) throw new InvalidOperationException();
var settings = JsonSerializer.Deserialize<Settings>(File.ReadAllBytes(Path.Combine(directory, "config.json")), json) ?? throw new InvalidOperationException();
if (args is ["--deny-data-network"])
{
    foreach (var endpoint in new[] { ("172.29.90.20", 5433), ("172.29.90.30", 6379), ("172.29.92.11", 5444) })
    {
        using var budget = new CancellationTokenSource(1500);
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        try { await socket.ConnectAsync(endpoint.Item1, endpoint.Item2, budget.Token); return 1; }
        catch (Exception e) when (e is SocketException or OperationCanceledException) { }
    }
    Console.WriteLine("CALLER_DATA_AND_CONTROL_NETWORK_DENIED"); return 0;
}
if (settings.Clients.Length != 2 || settings.DriverPin.Length != 64) throw new InvalidOperationException();
var clients = settings.Clients.Select(x => new SessionValidatorClient(x)).ToArray();
using var root = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(directory, "controller-ca.pem"));
using var server = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(directory, "server.pfx"), "", X509KeyStorageFlags.EphemeralKeySet);
var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.WebHost.ConfigureKestrel(k =>
{
    k.Limits.MaxRequestBodySize = 12288; k.Limits.MaxConcurrentConnections = 16;
    k.Listen(IPAddress.Parse(settings.Address), 9443, l =>
    {
        l.Protocols = HttpProtocols.Http1;
        l.UseHttps(new HttpsConnectionAdapterOptions
        {
            ServerCertificate = server, ClientCertificateMode = ClientCertificateMode.RequireCertificate,
            ClientCertificateValidation = (cert, _, _) =>
            {
                if (cert is null || Convert.ToHexString(SHA256.HashData(cert.RawData)) != settings.DriverPin) return false;
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(root);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.2"));
                return chain.Build(cert);
            }
        });
    });
});
var app = builder.Build();
app.Use(async (context, next) => { context.Response.Headers.CacheControl = "no-store"; await next(context); });
app.MapGet("/health", () => Results.Json(new { ready = true, caller = settings.Identity }));
app.MapPost("/validate", async (Input input, HttpContext context) =>
{
    if (input.Replica is < 0 or > 1 || input.Credential.Length > 8192) return Results.BadRequest();
    var result = await clients[input.Replica].ValidateAsync(input.Credential, input.Action,
        DateTimeOffset.UtcNow.AddSeconds(4), context.RequestAborted);
    // Do not echo credentials, identity claims or raw protocol responses.
    return Results.Json(new { decision = result.Decision.ToString(), caller = settings.Identity, replica = input.Replica }, statusCode: result.HttpStatusCode);
});
try { await app.RunAsync(); } finally { foreach (var client in clients) await client.DisposeAsync(); }
return 0;
sealed record Input(string Credential, string Action, int Replica);
sealed record Settings(string Identity, string Address, string DriverPin, ClientOptions[] Clients);
