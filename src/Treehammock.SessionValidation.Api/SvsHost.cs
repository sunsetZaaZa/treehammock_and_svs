using System.Net;
using System.Security.Claims;
using System.Security.Authentication;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Grpc.AspNetCore.Server.Model;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Treehammock.SessionValidation.Contracts;
namespace Treehammock.SessionValidation.Api;

public static class SvsHost
{
    public static WebApplication Build(HostSettings settings) => Build(settings, s => s.Fleet is null ? new HostResources(s) : new CoherentResources(s));
    internal static WebApplication Build(HostSettings settings, Func<HostSettings, IHostResources> resourcesFactory)
    {
        var config = settings.Snapshot();
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { Args = [], EnvironmentName = Environments.Production, ApplicationName = typeof(SvsHost).Assembly.FullName });
        builder.Configuration.Sources.Clear(); builder.Logging.ClearProviders();
        builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromMilliseconds(config.ShutdownTimeoutMilliseconds));
        builder.Services.AddSingleton(config);
        builder.Services.AddSingleton<Metrics>();
        builder.Services.AddSingleton(_ => new ServiceCertificates(config));
        if(config.Fleet is not null)
        {
            builder.Services.AddSingleton(_=>new FleetCertificates(config));
            builder.Services.AddSingleton(sp=>new FleetAgent(config,sp.GetRequiredService<IHostResources>(),sp.GetRequiredService<HostLifecycle>(),sp.GetRequiredService<RequestLifetime>(),sp.GetRequiredService<FleetCertificates>()));
        }
        builder.Services.AddSingleton(new RequestLifetime(config.MaximumConcurrentRequests));
        builder.Services.AddSingleton<IHostResources>(_ => resourcesFactory(config));
        builder.Services.AddSingleton(sp => sp.GetRequiredService<IHostResources>().Coordinator);
        builder.Services.AddSingleton(new CallerPolicy(config.Callers.Select(c => new KeyValuePair<string, string[]>(c.Identity, c.Actions))));
        builder.Services.AddSingleton(sp => new HostLifecycle(sp.GetRequiredService<IHostResources>(), sp.GetRequiredService<RequestLifetime>(), config)); builder.Services.AddHostedService(sp => sp.GetRequiredService<HostLifecycle>());
        builder.WebHost.UseKestrel((context, options) =>
        {
            var certificates = options.ApplicationServices.GetRequiredService<ServiceCertificates>();
            options.AddServerHeader = false; options.AllowSynchronousIO = false;
            options.Limits.MaxConcurrentConnections = config.MaximumConnections;
            options.Limits.MaxRequestBodySize = 16384; options.Limits.MaxRequestHeadersTotalSize = 16384;
            options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(3); options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(30);
            options.Limits.Http2.MaxStreamsPerConnection = config.Http2StreamsPerConnection;
            if(config.Fleet is {} fleet) options.Listen(IPAddress.Parse(fleet.BindAddress),fleet.Port, endpoint =>
            {
                var trust=options.ApplicationServices.GetRequiredService<FleetCertificates>(); endpoint.Protocols=HttpProtocols.Http1AndHttp2;
                endpoint.UseHttps(https=>{https.ServerCertificate=trust.Server;https.ClientCertificateMode=ClientCertificateMode.RequireCertificate;https.SslProtocols=SslProtocols.Tls12|SslProtocols.Tls13;https.HandshakeTimeout=TimeSpan.FromSeconds(3);https.ClientCertificateValidation=(cert,_,_)=>trust.Authenticate(cert);});
            });
            options.Listen(IPAddress.Parse(config.BindAddress), config.Port, endpoint =>
            {
                endpoint.Protocols = HttpProtocols.Http2;
                endpoint.UseHttps(https => { https.ServerCertificate = certificates.Server; https.ClientCertificateMode = ClientCertificateMode.RequireCertificate; https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13; https.HandshakeTimeout = TimeSpan.FromSeconds(3); https.ClientCertificateValidation = (cert, _, _) => certificates.Authenticate(cert) is not null; });
            });
        });
        builder.Services.AddSingleton(sp => new ValidationService(sp.GetRequiredService<Storage.SessionEvidenceCoordinator>(), sp.GetRequiredService<CallerPolicy>(), config,sp.GetRequiredService<Metrics>()));
        builder.Services.AddGrpc(o => { o.MaxReceiveMessageSize = ContractLimits.BinaryRequestBytes; o.MaxSendMessageSize = ContractLimits.BinaryReplyBytes; o.EnableDetailedErrors = false; o.CompressionProviders.Clear(); });
        builder.Services.AddSingleton<IServiceMethodProvider<ValidationService>, ValidationMethods>();
        var app = builder.Build();
        var operations=new RequestLifetime(2);
        app.Use(async (context, next) =>
        {
            if(config.Fleet is {} fleet && context.Connection.LocalPort==fleet.Port)
            {
                var bodyLimit=context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>();
                if(bodyLimit is {IsReadOnly:false})bodyLimit.MaxRequestBodySize=treehammock.Rigging.Fleet.FleetProtocol.MaximumBodyBytes+1;
                if(context.Request.Path==treehammock.Rigging.Fleet.FleetProtocol.Path && context.Request.Method=="POST") await context.RequestServices.GetRequiredService<FleetAgent>().InvokeAsync(context);
                else context.Response.StatusCode=404;
                return;
            }
            if(context.Request.Path==treehammock.Rigging.Fleet.FleetProtocol.Path){context.Response.StatusCode=404;return;}
            context.Items[ValidationService.StartedKey] = DateTimeOffset.UtcNow;
            context.Response.Headers.CacheControl = "no-store";
            var certificates = context.RequestServices.GetRequiredService<ServiceCertificates>();
            string? peer = certificates.Authenticate(await context.Connection.GetClientCertificateAsync(context.RequestAborted));
            if (!context.Request.IsHttps || peer is null || context.Request.Protocol != "HTTP/2") { context.Response.StatusCode = 403; return; }
            context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, peer)], "private-mtls"));
            bool monitor=HealthEndpoints.IsMonitor(context.User,config);
            if(HealthEndpoints.IsOperational(context.Request.Path))
            {
                if(!monitor){context.Response.StatusCode=403;return;}
                var slot=operations.TryEnter();if(slot is null){context.Response.StatusCode=503;return;}
                var opOwner=new ResponseLifetime(context,slot,null,config.RequestTimeoutMilliseconds);Task? operation=null;
                try{operation=next(context);await operation.WaitAsync(context.RequestAborted);}
                catch{context.Abort();opOwner.ResponseDone();throw;}
                finally{if(operation is null||operation.IsCompleted){if(operation is not null)_=operation.Exception;opOwner.DownstreamDone();}else _=operation.ContinueWith(t=>{_=t.Exception;opOwner.DownstreamDone();},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);}
                return;
            }
            if(monitor){context.Response.StatusCode=403;return;}
            // gRPC's option setup may restore default gzip providers after Clear().
            // Refuse encoded messages before its body reader/decompressor runs.
            if (context.Request.Path == "/treehammock.sessionvalidation.v1.SessionValidator/Validate" &&
                (context.Request.Headers.ContentEncoding.Count != 0 ||
                 context.Request.Headers.TryGetValue("grpc-encoding", out var encoding) && (encoding.Count != 1 || encoding[0] != "identity")))
            {
                context.Response.ContentType = "application/grpc"; context.Response.Headers["grpc-status"] = "12";
                context.Response.Headers["grpc-accept-encoding"] = "identity"; return;
            }
            bool health = context.Request.Path is var path && (path == "/health/live" || path == "/health/ready");
            if (health) { await next(context); return; }
            var requests = context.RequestServices.GetRequiredService<RequestLifetime>(); var lease = requests.TryEnter();
            if (lease is null) { context.Response.StatusCode = 503; return; }
            IDisposable? fleetLease=null;
            try { if(context.RequestServices.GetRequiredService<IHostResources>() is IFleetResources fleetResources) fleetLease=fleetResources.Gate.Enter(); }
            catch(InvalidOperationException){lease.Dispose();context.Response.StatusCode=503;return;}
            var owner=new ResponseLifetime(context,lease,fleetLease,config.RequestTimeoutMilliseconds);
            Task? pending=null;
            try { pending=next(context); await pending.WaitAsync(context.RequestAborted); }
            catch(OperationCanceledException) when(context.RequestAborted.IsCancellationRequested){context.Abort();owner.ResponseDone();}
            catch { context.Abort();owner.ResponseDone();throw; }
            finally
            {
                if(pending is null || pending.IsCompleted){if(pending is not null)_=pending.Exception;owner.DownstreamDone();}
                else _=pending.ContinueWith(t=>{_=t.Exception;owner.DownstreamDone();},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
            }
        });
        HealthEndpoints.Map(app);
        app.MapGrpcService<ValidationService>();
        return app;
    }
}
