using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using treehammock.Rigging.Fleet;
namespace Treehammock.SessionValidation.Api;

internal sealed class FleetCertificates : IDisposable
{
    private readonly X509Certificate2 _root;
    private readonly HashSet<string> _pins;
    internal X509Certificate2 Server{get;}
    internal FleetCertificates(HostSettings settings)
    {
        var fleet=settings.Fleet!;_root=X509CertificateLoader.LoadCertificateFromFile(fleet.ControllerRootCertificatePath);Server=null!;
        try
        {
            ServiceCertificates.RequireRoot(_root);
            Server=X509CertificateLoader.LoadPkcs12FromFile(fleet.ServerCertificatePath,fleet.ServerCertificatePassword,X509KeyStorageFlags.EphemeralKeySet);
            using var serverRoot=X509CertificateLoader.LoadCertificateFromFile(settings.ServerRootCertificatePath);
            ServiceCertificates.RequireRoot(serverRoot);
            if(!Server.HasPrivateKey||!ServiceCertificates.ValidLeaf(Server,serverRoot,"1.3.6.1.5.5.7.3.1"))throw new ArgumentException("Invalid fleet server certificate.");
            _pins=fleet.ControllerPins.ToHashSet(StringComparer.Ordinal);
        }
        catch{Server?.Dispose();_root.Dispose();throw;}
    }
    internal bool Authenticate(X509Certificate2? certificate)=>certificate is not null && certificate.RawData.Length<=16384 && _pins.Contains(Convert.ToHexString(SHA256.HashData(certificate.RawData))) && ServiceCertificates.ValidLeaf(certificate,_root,"1.3.6.1.5.5.7.3.2");
    public void Dispose(){Server.Dispose();_root.Dispose();}
}

internal sealed class FleetAgent(HostSettings settings,IHostResources resources,HostLifecycle lifecycle,RequestLifetime requests,FleetCertificates certificates)
{
    private readonly SemaphoreSlim _commands=new(1,1);
    internal async Task InvokeAsync(HttpContext context)
    {
        context.Response.Headers.CacheControl="no-store";
        if(!context.Request.IsHttps||!certificates.Authenticate(await context.Connection.GetClientCertificateAsync(context.RequestAborted))){context.Response.StatusCode=403;return;}
        if(context.Request.QueryString.HasValue||context.Request.Headers.ContentEncoding.Count!=0||context.Request.ContentType!="application/json"||context.Request.ContentLength is >FleetProtocol.MaximumBodyBytes){context.Response.StatusCode=400;return;}
        if(!await _commands.WaitAsync(0,context.RequestAborted)){context.Response.StatusCode=429;return;}
        var fleet=(IFleetResources)resources;
        try
        {
            using var budget=CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);budget.CancelAfter(settings.Fleet!.DrainTimeoutMilliseconds);
            byte[] body=new byte[FleetProtocol.MaximumBodyBytes+1];int length=0;
            while(length<body.Length){int n=await context.Request.Body.ReadAsync(body.AsMemory(length),budget.Token);if(n==0)break;length+=n;}
            if(length==body.Length)throw new InvalidOperationException("Unbounded fleet message.");
            var request=FleetProtocol.Read<FleetRequest>(body.AsSpan(0,length));
            if(!FleetProtocol.Hash(request.Nonce))throw new InvalidOperationException("Invalid challenge.");
            FleetIsolationProof? proof=null;
            switch(request.Action)
            {
                case "status":break;
                case "drain":
                    await fleet.Gate.DrainAsync(request,async t=>
                    {
                        await lifecycle.StopAuditAsync(t);
                        await Task.WhenAll(fleet.DrainAsync(t),requests.DrainAsync(t));
                    },budget.Token);break;
                case "probe":
                    var current=fleet.Gate.Reply(request.Nonce);
                    if(request.BootId!=current.BootId||request.Generation!=current.Generation||request.Barrier!=current.Barrier||request.InventoryHash!=current.InventoryHash)throw new InvalidOperationException("Foreign isolation challenge.");
                    proof=await fleet.ProbeAsync(budget.Token);break;
                case "prepare":await fleet.Gate.PrepareAsync(request,(b,t)=>fleet.VerifyAsync(b,false,t),budget.Token);break;
                case "activate":
                    await fleet.Gate.ActivateAsync(request,(b,t)=>fleet.VerifyAsync(b,true,t),budget.Token);
                    fleet.Activate(fleet.Gate.Binding());break;
                default:throw new InvalidOperationException("Unknown fleet action.");
            }
            context.Response.ContentType="application/json";
            await JsonSerializer.SerializeAsync(context.Response.Body,fleet.Gate.Reply(request.Nonce) with{Kind="SVS",IdentityHash=fleet.IdentityHash,Isolation=proof},FleetProtocol.Json,budget.Token);
        }
        catch(OperationCanceledException){fleet.Quarantine();if(!context.Response.HasStarted)context.Response.StatusCode=503;else context.Abort();}
        catch{fleet.Quarantine();if(!context.Response.HasStarted)context.Response.StatusCode=409;else context.Abort();}
        finally{_commands.Release();}
    }
}
