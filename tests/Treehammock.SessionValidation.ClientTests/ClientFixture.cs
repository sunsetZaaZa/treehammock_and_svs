using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Google.Protobuf;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Logging;
using Treehammock.SessionValidation.Client;
using Treehammock.SessionValidation.Contracts;
using Treehammock.SessionValidation.Contracts.V1;
namespace Treehammock.SessionValidation.ClientTests;
internal sealed class ClientFixture:IDisposable
{
    internal const string Identity="spiffe://sdk.test/service/consumer";
    internal string Directory{get;}=Path.Combine(Path.GetTempPath(),"svs09-"+Guid.NewGuid().ToString("N"));
    internal X509Certificate2 Root{get;}internal X509Certificate2 Server{get;}internal X509Certificate2 Client{get;}internal int Port{get;}
    internal ClientFixture(int? serverLifeSeconds=null,int? clientLifeSeconds=null)
    {
        System.IO.Directory.CreateDirectory(Directory);if(!OperatingSystem.IsWindows())File.SetUnixFileMode(Directory,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);var csr=new CertificateRequest("CN=SDK test root",key,HashAlgorithmName.SHA256);csr.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));csr.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign,true));Root=csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-10),DateTimeOffset.UtcNow.AddDays(10));
        Server=Leaf(true,after:serverLifeSeconds is{}s?DateTimeOffset.UtcNow.AddSeconds(s):null);Client=Leaf(false,after:clientLifeSeconds is{}c?DateTimeOffset.UtcNow.AddSeconds(c):null);
        File.WriteAllBytes(Path.Combine(Directory,"root.cer"),Root.RawData);File.WriteAllBytes(Path.Combine(Directory,"client.pfx"),Client.Export(X509ContentType.Pfx,"test-only"));var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();Port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();
    }
    internal X509Certificate2 Leaf(bool server,string? identity=Identity,string? eku=null,DateTimeOffset? before=null,DateTimeOffset? after=null)
    {
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);var csr=new CertificateRequest("CN=SDK test leaf",key,HashAlgorithmName.SHA256);csr.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));csr.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature,true));csr.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new(eku??(server?"1.3.6.1.5.5.7.3.1":"1.3.6.1.5.5.7.3.2"))},true));var san=new SubjectAlternativeNameBuilder();if(server)san.AddDnsName("localhost");else if(identity is not null)san.AddUri(new Uri(identity));if(server||identity is not null)csr.CertificateExtensions.Add(san.Build());using var leaf=csr.Create(Root,before??DateTimeOffset.UtcNow.AddMinutes(-5),after??DateTimeOffset.UtcNow.AddDays(1),RandomNumberGenerator.GetBytes(16));return leaf.CopyWithPrivateKey(key);
    }
    internal static string Pin(X509Certificate2 c)=>Convert.ToHexString(SHA256.HashData(c.RawData));
    internal static readonly JsonSerializerOptions JsonOptions=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase};
    internal ClientOptions Options(Action<JsonObject>? change=null)
    {
        var o=new ClientOptions{TlsName="localhost",PrivateAddress="127.0.0.1",Port=Port,ServerRootCertificatePath=Path.Combine(Directory,"root.cer"),ServerLeafSha256=[Pin(Server)],ClientCertificatePath=Path.Combine(Directory,"client.pfx"),ClientCertificatePassword="test-only",ClientRootCertificatePath=Path.Combine(Directory,"root.cer"),ServiceIdentity=Identity,PolicyVersion="sdk-test.v1"};var node=JsonSerializer.SerializeToNode(o,JsonOptions)!.AsObject();change?.Invoke(node);return node.Deserialize<ClientOptions>(JsonOptions)!;
    }
    internal WebApplication ServerApp(RequestDelegate handler,X509Certificate2? server=null,string? clientPin=null)
    {
        var b=WebApplication.CreateSlimBuilder();b.Logging.ClearProviders();b.WebHost.UseKestrel(o=>o.Listen(IPAddress.Loopback,Port,e=>{e.Protocols=HttpProtocols.Http2;e.UseHttps(h=>{h.ServerCertificate=server??Server;h.SslProtocols=SslProtocols.Tls12|SslProtocols.Tls13;h.ClientCertificateMode=ClientCertificateMode.RequireCertificate;h.ClientCertificateValidation=(c,_,_)=>Pin(c)==(clientPin??Pin(Client));});}));var app=b.Build();app.Run(handler);return app;
    }
    internal static async Task<ValidateRequest> Read(HttpContext c)
    {
        var b=new byte[5];await c.Request.Body.ReadExactlyAsync(b);int n=BinaryPrimitives.ReadInt32BigEndian(b.AsSpan(1));if(n is <1 or >9216||b[0]!=0)throw new InvalidOperationException("Bounded test request required.");b=new byte[n];await c.Request.Body.ReadExactlyAsync(b);return ValidateRequest.Parser.ParseFrom(b);
    }
    internal static ValidateReply Reply(ValidateRequest r)=>new(){Decision=Decision.Active,ContractVersion=1,RequestId=r.RequestId,DecisionId=Guid.NewGuid().ToString("N"),PolicyVersion="sdk-test.v1",CheckedAtUnixMs=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),AccountIdUuid=UuidCodec.Encode(Guid.Parse("12345678-1234-4234-8234-123456789abc")),SessionFamilyUuid=UuidCodec.Encode(Guid.NewGuid()),Generation=7,SessionProtocolVersion=2,ValidUntilUnixMs=DateTimeOffset.UtcNow.AddMilliseconds(500).ToUnixTimeMilliseconds()};
    internal static async Task Write(HttpContext c,byte[] b,int status=0,byte flag=0)
    {
        c.Response.ContentType="application/grpc";c.Response.Headers.CacheControl="no-store";c.Response.DeclareTrailer("grpc-status");if(b.Length!=0){var frame=new byte[b.Length+5];frame[0]=flag;BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(1),b.Length);b.CopyTo(frame,5);await c.Response.Body.WriteAsync(frame);}c.Response.AppendTrailer("grpc-status",status.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }
    public void Dispose(){Client.Dispose();Server.Dispose();Root.Dispose();System.IO.Directory.Delete(Directory,true);}
}
