using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using NodaTime;
using NodaTime.Serialization.JsonNet;
using NSubstitute;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.Security;
using treehammock.Rigging.DependencyInjection;
using treehammock.Rigging.Hosting;
using treehammock.Rigging.Operations;
using treehammock.Rigging.Dependencies;
using treehammock.Rigging.Authorization;
using treehammock.Services;
using treehammock.Tests.Unit;

namespace treehammock.Tests.Infrastructure;

// Owned loopback listeners; explicit ephemeral PublicOrigin overrides avoid shared fixed ports.
internal sealed class Cor23GPublicHttpFixture : IAsyncDisposable
{
    internal readonly Cor23GLinkFixture Links=new();
    internal HttpClient Client=null!;
    internal string PublicOrigin="";
    private readonly List<WebApplication> _apps=new();
    private readonly List<HttpClient> _clients=new();
    private X509Certificate2? _certificate;
    internal static void Configure(IServiceCollection services,Cor23GLinkFixture links)
    {
        new Cor23EAuthorityFixture().Configure(services);
        services.RemoveAll<IAccountRepo>();services.AddSingleton(links.Repo);
        services.RemoveAll<IDurableDeliveryService>();services.AddSingleton<IDurableDeliveryService>(links.Delivery);
        var work=Substitute.For<IPasswordWorkService>();work.HashBytesAsync(Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(new byte[treehammock.Rigging.Security.AccountCryptoSizes.PasswordHashBytes]);
        services.RemoveAll<IPasswordWorkService>();services.AddSingleton(work);
        var admission=Substitute.For<ISignupAdmissionPolicy>();admission.CheckAsync(Arg.Any<string>(),Arg.Any<string?>(),Arg.Any<string?>(),Arg.Any<CancellationToken>()).Returns((treehammock.RiggingSupport.Status.HttpMessage?)null);
        services.RemoveAll<ISignupAdmissionPolicy>();services.AddSingleton(admission);
    }
    internal static async Task<Cor23GPublicHttpFixture> StartAsync(string profile,CancellationToken token)
    {
        var fixture=new Cor23GPublicHttpFixture();
        try { await fixture.StartCoreAsync(profile,token);return fixture; }
        catch { await fixture.DisposeAsync();throw; }
    }
    private async Task StartCoreAsync(string profile,CancellationToken token)
    {
        bool proxy=profile is "ContainerReverseProxy" or "ReverseProxy",tls=profile is "LocalHttps" or "ReverseProxy";
        if(tls)_certificate=Certificate();
        var settings=Cor23EAuthorityFixture.Settings();settings["AbuseControlSettings:Enabled"]="false";
        var builder=Builder();builder.Configuration.Sources.Clear();builder.Configuration.AddInMemoryCollection(settings);
        builder.WebHost.ConfigureKestrel(options=>options.Listen(IPAddress.Loopback,0,listen=> { if(tls&&!proxy)listen.UseHttps(_certificate!); }));
        builder.Services.AddTreehammockServices(builder.Configuration,builder.Environment);Configure(builder.Services,Links);
        // This fixture starts owned listeners first, then freezes their explicit public origin in the real producer.
        builder.Services.RemoveAll<IAccountService>();builder.Services.AddSingleton<IAccountService>(_=>Links.Service(PublicOrigin));
        builder.Services.AddControllers().AddApplicationPart(typeof(treehammock.Controllers.AccountRegistrationController).Assembly)
            .AddNewtonsoftJson(options=>options.SerializerSettings.ConfigureForNodaTime(DateTimeZoneProviders.Tzdb));
        var origin=builder.Build();_apps.Add(origin);
        origin.UseMiddleware<SecurityResponseCacheMiddleware>();origin.UseMiddleware<HttpExceptionFallbackMiddleware>();
        var forwarded=new ForwardedHeadersOptions {ForwardedHeaders=ForwardedHeaders.XForwardedFor|ForwardedHeaders.XForwardedProto,ForwardLimit=1,RequireHeaderSymmetry=true};
        forwarded.KnownNetworks.Clear();forwarded.KnownProxies.Clear();forwarded.KnownProxies.Add(IPAddress.Loopback);
        origin.UseForwardedHeaders(forwarded);origin.UseRouting();origin.UseMiddleware<RequestBodyMiddleware>();
        origin.UseMiddleware<SecurityOperationMiddleware>();origin.UseMiddleware<DependencyExceptionMiddleware>();origin.UseMiddleware<JsonWebTokenMiddleware>();
        origin.MapControllers();
        origin.MapPost("/fixture/generate",async context=>
        {
            Links.Accessor.HttpContext=context;
            await Links.CaptureAsync((AccountService)context.RequestServices.GetRequiredService<IAccountService>(),context.RequestAborted);
            await context.Response.WriteAsJsonAsync(Links.Delivery.Intents.Select(i=>i.Payload.Value).ToArray(),context.RequestAborted);
        });
        await origin.StartAsync(token);string originAddress=Address(origin);
        if(!proxy)PublicOrigin=originAddress;
        else
        {
            var upstream=ClientFor(originAddress);_clients.Add(upstream);
            var edgeBuilder=Builder();edgeBuilder.WebHost.ConfigureKestrel(options=>options.Listen(IPAddress.Loopback,0,listen=> {if(tls)listen.UseHttps(_certificate!);}));
            var edge=edgeBuilder.Build();_apps.Add(edge);edge.UseMiddleware<SecurityResponseCacheMiddleware>();
            edge.Run(async context=>
            {
                using var request=new HttpRequestMessage(new HttpMethod(context.Request.Method),context.Request.Path+context.Request.QueryString);
                if(context.Request.ContentLength>0||context.Request.Headers.ContainsKey("Transfer-Encoding"))request.Content=new StreamContent(context.Request.Body);
                foreach(var header in context.Request.Headers)
                    if(header.Key is not "Host" and not "Connection" and not "Content-Length")
                        if(!request.Headers.TryAddWithoutValidation(header.Key,header.Value.ToArray()))request.Content?.Headers.TryAddWithoutValidation(header.Key,header.Value.ToArray());
                // Known loopback edge supplies scheme/IP; forwarded Host remains deliberately untrusted input.
                request.Headers.Remove("X-Forwarded-For");request.Headers.TryAddWithoutValidation("X-Forwarded-For","127.0.0.1");
                request.Headers.Remove("X-Forwarded-Proto");request.Headers.TryAddWithoutValidation("X-Forwarded-Proto",tls?"https":"http");
                using var response=await upstream.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,context.RequestAborted);
                context.Response.StatusCode=(int)response.StatusCode;
                foreach(var header in response.Headers.Concat(response.Content.Headers))
                    if(header.Key is not "Transfer-Encoding" and not "Connection")context.Response.Headers[header.Key]=header.Value.ToArray();
                await response.Content.CopyToAsync(context.Response.Body,context.RequestAborted);
            });
            await edge.StartAsync(token);PublicOrigin=Address(edge);
        }
        Client=ClientFor(PublicOrigin);_clients.Add(Client);
    }
    private static WebApplicationBuilder Builder()
    {
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions {EnvironmentName="Testing",ContentRootPath=Cor23GPublicOriginTests.ProjectRoot()});builder.Logging.ClearProviders();return builder;
    }
    private static string Address(WebApplication app)
    {
        var address=new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single());
        return new UriBuilder(address){Host="localhost"}.Uri.GetLeftPart(UriPartial.Authority);
    }
    private HttpClient ClientFor(string address)
    {
        var handler=new HttpClientHandler {AllowAutoRedirect=false};
        if(_certificate is not null)handler.ServerCertificateCustomValidationCallback=(_,certificate,_,errors)=>certificate is not null&&certificate.GetCertHashString()==_certificate.GetCertHashString()&&(errors==SslPolicyErrors.None||errors==SslPolicyErrors.RemoteCertificateChainErrors);
        return new(handler){BaseAddress=new Uri(address),Timeout=TimeSpan.FromSeconds(10)};
    }
    private static X509Certificate2 Certificate()
    {
        using var key=RSA.Create(2048);var request=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        var names=new SubjectAlternativeNameBuilder();names.AddDnsName("localhost");names.AddIpAddress(IPAddress.Loopback);request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection {new Oid("1.3.6.1.5.5.7.3.1")},false));
        using var certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(1));return new(certificate.Export(X509ContentType.Pfx));
    }
    public async ValueTask DisposeAsync()
    {
        foreach(var client in _clients)client.Dispose();
        Exception? failure=null;
        foreach(var app in _apps.AsEnumerable().Reverse())
        {
            using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try {await app.StopAsync(stop.Token);}catch(Exception error){failure??=error;}
            try {await app.DisposeAsync();}catch(Exception error){failure??=error;}
        }
        _certificate?.Dispose();if(failure is not null)throw failure;
    }
}
