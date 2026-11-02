using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using treehammock.Models.Api;
using treehammock.Tests.Integration;
using treehammock.Rigging.Config;
using treehammock.Rigging.Hosting;
using treehammock.Rigging.Operations;

namespace treehammock.Tests.Infrastructure;

public sealed class Cor23FVisits { public int Accepted; }
[ApiController]
[Route("/fixture/body")]
public sealed class Cor23FBodyController(Cor23FVisits visits) : ControllerBase
{
    [HttpPost]
    public ApiResponse<Dictionary<string,string>> Post([FromBody] Dictionary<string,string> body)
    { Interlocked.Increment(ref visits.Accepted); return ApiResponse<Dictionary<string,string>>.Success(200,"BODY_ACCEPTED",body); }
}

internal sealed class Cor23FBodyFixture : IAsyncDisposable
{
    public WebApplication App { get; }
    public HttpClient Client { get; private set; } = null!;
    public Cor23FVisits Visits => App.Services.GetRequiredService<Cor23FVisits>();
    private Cor23FBodyFixture(WebApplication app) => App=app;
    internal static async Task<Cor23FBodyFixture> StartAsync(bool kestrel, RequestBodySettings settings)
    {
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName="Testing" });
        builder.Logging.ClearProviders();
        if(kestrel) builder.WebHost.UseKestrel(options=> { options.Listen(IPAddress.Loopback,0);options.Limits.MaxRequestBodySize=settings.EncodedBytes+1L; });
        else builder.WebHost.UseTestServer();
        builder.Services.AddSingleton<IOptions<RequestBodySettings>>(Options.Create(settings));
        builder.Services.AddSingleton<RequestBodyPolicy>(); builder.Services.AddSingleton<Cor23FVisits>();builder.Services.AddSingleton<Cor23FHold>();
        builder.Services.AddControllers().AddApplicationPart(typeof(Cor23FBodyController).Assembly)
            .ConfigureApiBehaviorOptions(options=>options.InvalidModelStateResponseFactory=context=>ApiResponses.InvalidModelState(context.ModelState));
        var app=builder.Build();var fixture=new Cor23FBodyFixture(app);
        app.UseMiddleware<SecurityResponseCacheMiddleware>();app.UseMiddleware<HttpExceptionFallbackMiddleware>();
        app.UseMiddleware<RequestBodyMiddleware>();
        app.Use(async (context,next)=>
        {
            if(context.Request.Path=="/fixture/body")
            {
                byte[] first=await SecurityOperationMiddleware.CanonicalBodyAsync(context);
                byte[] second=await SecurityOperationMiddleware.CanonicalBodyAsync(context);
                if(!first.SequenceEqual(second) || context.Request.Body.Position!=0) throw new InvalidOperationException("Canonical input was consumed.");
            }
            await next();
        });
        app.MapControllers().WithMetadata(app.Services.GetRequiredService<RequestBodyPolicy>().Limits);
        app.MapPost("/fixture/unrelated",()=>Task.FromException(new IOException("private-credential-proof")));
        app.MapPost("/fixture/hold",async context=>
        {
            var hold=context.RequestServices.GetRequiredService<Cor23FHold>();
            int count=Interlocked.Increment(ref hold.Entered);
            if(count==settings.ConcurrentRequests) hold.Full.TrySetResult(true);
            await hold.Release.Task.WaitAsync(context.RequestAborted);
            context.Response.StatusCode=204;
        });
        try
        {
            using var start=new CancellationTokenSource(TimeSpan.FromSeconds(10));await app.StartAsync(start.Token);
            fixture.Client=kestrel ? new HttpClient { BaseAddress=new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single()),Timeout=TimeSpan.FromSeconds(10) } : app.GetTestClient();
            fixture.Client.Timeout=TimeSpan.FromSeconds(10);return fixture;
        }
        catch { await app.DisposeAsync();throw; }
    }
    internal static byte[] Encode(byte[] bytes,string encoding)
    {
        using var output=new MemoryStream();
        using(Stream compressor=encoding switch {
            "gzip"=>new GZipStream(output,CompressionLevel.Fastest,true),
            "deflate"=>new ZLibStream(output,CompressionLevel.Fastest,true),
            "br"=>new BrotliStream(output,CompressionLevel.Fastest,true),
            _=>throw new ArgumentException("Unknown encoding.") }) compressor.Write(bytes);
        return output.ToArray();
    }
    internal static HttpRequestMessage Request(byte[] bytes,string? encoding=null,bool chunked=false,string route="/fixture/body")
    {
        var request=new HttpRequestMessage(HttpMethod.Post,route);
        request.Content=chunked ? new ChunkedContent(bytes) : new ByteArrayContent(bytes);
        request.Content.Headers.ContentType=new MediaTypeHeaderValue("application/json");
        if(encoding is not null) request.Content.Headers.TryAddWithoutValidation("Content-Encoding",encoding);
        return request;
    }
    private sealed class ChunkedContent(byte[] bytes) : HttpContent
    {
        protected override bool TryComputeLength(out long length) { length=0;return false; }
        protected override async Task SerializeToStreamAsync(Stream stream,TransportContext? context)
        {
            for(int offset=0;offset<bytes.Length;offset+=17)
                await stream.WriteAsync(bytes.AsMemory(offset,Math.Min(17,bytes.Length-offset)));
        }
    }
    internal static byte[] JsonBytes(int length)
    {
        if(length<8) throw new ArgumentOutOfRangeException(nameof(length));
        return Encoding.UTF8.GetBytes("{\"v\":\""+new string('a',length-8)+"\"}");
    }
    internal static async Task AssertError(HttpResponseMessage response,int status,string code)
    {
        Assert.Equal(status,(int)response.StatusCode);Cor23ENoStoreHttpTests.AssertPrivate(response);
        using var document=JsonDocument.Parse(await response.Content.ReadAsStringAsync());var root=document.RootElement;
        Assert.False(root.GetProperty("success").GetBoolean());Assert.Equal(status,root.GetProperty("statusCode").GetInt32());
        Assert.Equal(code,root.GetProperty("code").GetString());Assert.Equal(JsonValueKind.Null,root.GetProperty("data").ValueKind);
        Assert.Equal(JsonValueKind.Null,root.GetProperty("errors").ValueKind);
    }
    public async ValueTask DisposeAsync()
    {
        Client?.Dispose();using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { await App.StopAsync(stop.Token); } finally { await App.DisposeAsync(); }
    }
}
internal sealed class Cor23FHold
{
    internal int Entered;
    internal readonly TaskCompletionSource<bool> Full=new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal readonly TaskCompletionSource<bool> Release=new(TaskCreationOptions.RunContinuationsAsynchronously);
}
