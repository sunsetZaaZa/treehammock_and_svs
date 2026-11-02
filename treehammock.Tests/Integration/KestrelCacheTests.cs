using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using NodaTime;
using NodaTime.Serialization.JsonNet;
using treehammock.Controllers;
using treehammock.DataLayer.Cache;
using treehammock.Models.Api;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.DependencyInjection;
using treehammock.Rigging.Dependencies;
using treehammock.Rigging.Hosting;
using treehammock.Rigging.Operations;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

// Real owned loopback Kestrel origin and intermediary; framework HTTP response cache, not a cache double.
// Origin uses actual controllers/auth middleware with explicit authority/cache/JWT substitutes.
public sealed class Cor23EKestrelCacheTests
{
    private sealed class Stack : IAsyncDisposable
    {
        private readonly List<WebApplication> _apps = new();
        private readonly List<HttpClient> _clients = new();
        public readonly ConcurrentDictionary<string,int> OriginCalls = new();
        public readonly Cor23EAuthorityFixture Authority = new();
        public HttpClient Direct { get; private set; } = null!;
        public HttpClient Proxy { get; private set; } = null!;
        private static string Root()
        {
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            while(directory is not null && !File.Exists(Path.Combine(directory.FullName,"treehammock.sln"))) directory=directory.Parent;
            return directory?.FullName ?? throw new InvalidOperationException("Cannot locate source root.");
        }
        private static Uri Address(WebApplication app)
            => new(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single());
        private HttpClient Client(Uri address)
        {
            var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect=false, UseCookies=false })
                { BaseAddress=address, Timeout=TimeSpan.FromSeconds(10) };
            _clients.Add(client); return client;
        }
        private static WebApplicationBuilder Builder()
        {
            var builder=WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName="Testing",ContentRootPath=Root() });
            builder.WebHost.ConfigureKestrel(options=>options.Listen(IPAddress.Loopback,0));
            return builder;
        }
        public static async Task<Stack> StartAsync(CancellationToken token, bool policy=true)
        {
            var stack=new Stack();
            try { await stack.StartCoreAsync(token,policy); return stack; }
            catch { await stack.DisposeAsync(); throw; }
        }
        private async Task StartCoreAsync(CancellationToken token, bool policy)
        {
            var builder=Builder();builder.Configuration.Sources.Clear();builder.Configuration.AddInMemoryCollection(Cor23EAuthorityFixture.Settings());
            builder.Services.AddTreehammockServices(builder.Configuration,builder.Environment);
            Authority.Configure(builder.Services);
            builder.Services.AddControllers().AddApplicationPart(typeof(AccountProfileController).Assembly)
                .ConfigureApiBehaviorOptions(options=>options.InvalidModelStateResponseFactory=context=>ApiResponses.InvalidModelState(context.ModelState))
                .AddNewtonsoftJson(options=>options.SerializerSettings.ConfigureForNodaTime(DateTimeZoneProviders.Tzdb));
            var origin=builder.Build();_apps.Add(origin);
            // Deliberately public, credential-free fixture branch proves that the intermediary really stores responses.
            // No production route bypasses the privacy policy.
            origin.Map("/fixture-public-control",branch=>branch.Run(async context=>
            {
                OriginCalls.AddOrUpdate("/fixture-public-control",1,(_,count)=>count+1);
                context.Response.Headers.CacheControl="public,max-age=60";
                await context.Response.WriteAsync("public-fixture-control",context.RequestAborted);
            }));
            if(policy) origin.UseMiddleware<SecurityResponseCacheMiddleware>();
            origin.UseMiddleware<HttpExceptionFallbackMiddleware>();
            var forwarded=new ForwardedHeadersOptions { ForwardedHeaders=ForwardedHeaders.XForwardedFor|ForwardedHeaders.XForwardedProto,ForwardLimit=1,RequireHeaderSymmetry=true };
            forwarded.KnownNetworks.Clear();forwarded.KnownProxies.Clear();forwarded.KnownProxies.Add(IPAddress.Loopback);
            origin.UseForwardedHeaders(forwarded);
            origin.UseRouting();
            origin.Use(async(context,next)=>
            {
                OriginCalls.AddOrUpdate(context.Request.Path.Value!,1,(_,count)=>count+1);
                // Simulate a downstream cache attribute/header writer. The earliest policy must win on the wire.
                if(context.Request.Path=="/fixture-cache-overwrite") context.Response.OnStarting(()=>
                {
                    context.Response.Headers.CacheControl="public,max-age=60";
                    context.Response.Headers.Remove("Pragma");context.Response.Headers.Remove("Expires");
                    return Task.CompletedTask;
                });
                await next();
            });
            origin.UseMiddleware<SecurityOperationMiddleware>();origin.UseMiddleware<DependencyExceptionMiddleware>();origin.UseMiddleware<JsonWebTokenMiddleware>();
            origin.MapControllers();
            origin.MapGet("/fixture-cache-overwrite",async context=>
            {
                string subject=context.Items[AuthContextItems.ActiveSession] is ActiveSession session ? session.accountId.ToString("D") : "anonymous";
                context.Response.Headers["AppStatus"]=subject;
                await context.Response.WriteAsync(subject,context.RequestAborted);
            });
            origin.MapGet("/fixture-exception",(HttpContext _) => Task.FromException(new InvalidOperationException("credential-body-must-not-leak")));
            await origin.StartAsync(token);Direct=Client(Address(origin));
            var upstream=Client(Address(origin));
            var proxyBuilder=Builder();proxyBuilder.Services.AddResponseCaching(options=>{options.SizeLimit=1024*1024;options.MaximumBodySize=65536;});
            var proxy=proxyBuilder.Build();_apps.Add(proxy);proxy.UseResponseCaching();
            proxy.Run(async context=>
            {
                using var request=new HttpRequestMessage(new HttpMethod(context.Request.Method),context.Request.Path+context.Request.QueryString);
                foreach(var header in context.Request.Headers)
                    if(header.Key is not "Host" and not "Connection" and not "Content-Length") request.Headers.TryAddWithoutValidation(header.Key,header.Value.ToArray());
                request.Headers.Remove("X-Forwarded-For");request.Headers.Remove("X-Forwarded-Proto");
                request.Headers.Add("X-Forwarded-For","127.0.0.1");request.Headers.Add("X-Forwarded-Proto","https");
                using var response=await upstream.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,context.RequestAborted);
                context.Response.StatusCode=(int)response.StatusCode;
                foreach(var header in response.Headers.Concat(response.Content.Headers))
                    if(header.Key is not "Transfer-Encoding" and not "Connection") context.Response.Headers[header.Key]=header.Value.ToArray();
                await response.Content.CopyToAsync(context.Response.Body,context.RequestAborted);
            });
            await proxy.StartAsync(token);Proxy=Client(Address(proxy));
        }
        public async ValueTask DisposeAsync()
        {
            // Drain hosts before disposing outbound clients; bounded cleanup owns every socket/task.
            Exception? first=null;
            foreach(var app in _apps.AsEnumerable().Reverse())
            {
                try { using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(5));await app.StopAsync(stop.Token); }
                catch(Exception error) { first ??=error; }
                try { await app.DisposeAsync(); } catch(Exception error) { first ??=error; }
            }
            foreach(var client in _clients) client.Dispose();
            if(first is not null) throw first;
        }
    }

    [Theory]
    [InlineData(false, "/account/view")] [InlineData(true, "/account/view")]
    [InlineData(false, "/account/sessions")] [InlineData(true, "/account/sessions")]
    [InlineData(false, "/account/adjust/email/verify?payload=fixture-proof")] [InlineData(true, "/account/adjust/email/verify?payload=fixture-proof")]
    [InlineData(false, "/fixture-cache-overwrite")] [InlineData(true, "/fixture-cache-overwrite")]
    public async Task Shared_cache_does_not_reuse_two_accounts_or_anonymous_bodies_or_credential_headers(bool bearer,string route)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);deadline.CancelAfter(TimeSpan.FromSeconds(30));
        await using var stack=await Stack.StartAsync(deadline.Token);
        for(int n=0;n<2;n++)
        {
            using var control=await stack.Proxy.GetAsync("/fixture-public-control",deadline.Token);
            Assert.Equal("public-fixture-control",await control.Content.ReadAsStringAsync(deadline.Token));Assert.True(control.Headers.CacheControl!.Public);
        }
        Assert.Equal(1,stack.OriginCalls["/fixture-public-control"]); // A disabled cache cannot satisfy this oracle.
        string[] subjects=[Cor23EAuthorityFixture.FirstToken,Cor23EAuthorityFixture.SecondToken];
        foreach(string? subject in new string?[] {subjects[0],subjects[1],null,subjects[0]})
        {
            using var directRequest=Cor23ENoStoreHttpTests.Request(HttpMethod.Get,route,subject,bearer);
            using var direct=await stack.Direct.SendAsync(directRequest,deadline.Token);Cor23ENoStoreHttpTests.AssertPrivate(direct);
            using var request=Cor23ENoStoreHttpTests.Request(HttpMethod.Get,route,subject,bearer);
            using var response=await stack.Proxy.SendAsync(request,deadline.Token);Cor23ENoStoreHttpTests.AssertPrivate(response);
            bool privateController=route is "/account/view" or "/account/sessions";
            Assert.Equal(subject is null && privateController ? HttpStatusCode.Unauthorized : HttpStatusCode.OK,response.StatusCode);
            string body=await response.Content.ReadAsStringAsync(deadline.Token);
            if(subject is not null)
            {
                var session=stack.Authority.Subjects[subject];
                Assert.Equal(session.familyId.ToString("D"),response.Headers.GetValues(SessionProtocol.FamilyHeader).Single());
                string other=subjects.Single(value=>value!=subject);
                Assert.DoesNotContain(stack.Authority.Subjects[other].familyId.ToString("D"),body);
                if(route=="/account/view") Assert.Contains(subject+"@example.test",body);
                if(route=="/fixture-cache-overwrite") { Assert.Equal(session.accountId.ToString("D"),body);
                    Assert.Equal(session.accountId.ToString("D"),response.Headers.GetValues("AppStatus").Single()); }
                Assert.Equal(AccessTokenHashUtility.Hash(subject),response.Headers.GetValues(SessionProtocol.ClearTokenHashHeader).Single());
            }
            else { Assert.False(response.Headers.Contains(SessionProtocol.FamilyHeader));
                Assert.False(response.Headers.Contains(SessionProtocol.ClearTokenHashHeader)); }
        }
        Assert.Equal(8,stack.OriginCalls[route.Split('?')[0]]); // Four direct + four forwarded, every request reaches origin.
        using var failure=await stack.Proxy.GetAsync("/fixture-exception",deadline.Token);
        Assert.Equal(HttpStatusCode.InternalServerError,failure.StatusCode);Cor23ENoStoreHttpTests.AssertPrivate(failure);
        Assert.DoesNotContain("credential-body-must-not-leak",await failure.Content.ReadAsStringAsync(deadline.Token));
    }

    [Fact]
    public async Task Fixture_mutation_without_host_policy_demonstrates_legacy_cross_account_cache_reuse()
    {
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));await using var stack=await Stack.StartAsync(deadline.Token,policy:false);
        using var firstRequest=Cor23ENoStoreHttpTests.Request(HttpMethod.Get,"/fixture-cache-overwrite",Cor23EAuthorityFixture.FirstToken);
        using var first=await stack.Proxy.SendAsync(firstRequest,deadline.Token);string firstBody=await first.Content.ReadAsStringAsync(deadline.Token);
        using var secondRequest=Cor23ENoStoreHttpTests.Request(HttpMethod.Get,"/fixture-cache-overwrite",Cor23EAuthorityFixture.SecondToken);
        using var second=await stack.Proxy.SendAsync(secondRequest,deadline.Token);
        Assert.Equal(firstBody,await second.Content.ReadAsStringAsync(deadline.Token));
        Assert.Equal(first.Headers.GetValues(SessionProtocol.FamilyHeader),second.Headers.GetValues(SessionProtocol.FamilyHeader));
        Assert.Equal(1,stack.OriginCalls["/fixture-cache-overwrite"]);
    }
}
