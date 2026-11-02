using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;
using treehammock.Rigging.DependencyInjection;
using treehammock.Rigging.Hosting;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public sealed class Cor23GPublicOriginTests
{
    internal static string ProjectRoot()
    {
        var current=new DirectoryInfo(AppContext.BaseDirectory);
        while(current is not null&&!File.Exists(Path.Combine(current.FullName,"treehammock.sln")))current=current.Parent;
        return current?.FullName??throw new InvalidOperationException("Project root unavailable.");
    }
    [Theory]
    [InlineData("LocalHttps","https://localhost:5001")]
    [InlineData("Container","http://localhost:5001")]
    [InlineData("ContainerReverseProxy","http://localhost:8080")]
    [InlineData("Testing","http://localhost:5001")]
    [InlineData("Development","https://localhost:5001")]
    public void Current_profiles_bind_one_origin_matching_the_documented_listener(string profile,string expected)
    {
        var config=new ConfigurationBuilder().AddJsonFile(Path.Combine(ProjectRoot(),"appsettings.json")).AddJsonFile(Path.Combine(ProjectRoot(),"appsettings."+profile+".json")).Build();
        var settings=config.GetRequiredSection("RegistrationSettings").Get<RegistrationSettings>()!;
        Assert.Equal(expected,settings.PublicOrigin);Assert.True(VerificationLinkBuilder.AllowedForEnvironment(settings.PublicOrigin,profile));
    }
    [Theory]
    [InlineData("http")] [InlineData("https")] [InlineData("IIS Express")]
    public void Launch_profiles_bind_their_actual_listener_or_IIS_SSL_origin(string profile)
    {
        using var launch=System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(ProjectRoot(),"Properties/launchSettings.json")));
        var lane=launch.RootElement.GetProperty("profiles").GetProperty(profile);
        var overrides=lane.GetProperty("environmentVariables").EnumerateObject().ToDictionary(value=>value.Name.Replace("__",":"),value=>(string?)value.Value.GetString());
        var config=new ConfigurationBuilder().AddJsonFile(Path.Combine(ProjectRoot(),"appsettings.json")).AddJsonFile(Path.Combine(ProjectRoot(),"appsettings.Development.json")).AddInMemoryCollection(overrides).Build();
        string expected=profile=="IIS Express"?"https://localhost:"+launch.RootElement.GetProperty("iisSettings").GetProperty("iisExpress").GetProperty("sslPort").GetInt32():lane.GetProperty("applicationUrl").GetString()!;
        Assert.Equal(expected,config["RegistrationSettings:PublicOrigin"]);Assert.True(VerificationLinkBuilder.AllowedForEnvironment(expected,"Development"));
        var hosting=config.GetSection("HostingSettings").Get<HostingSettings>()!;
        if(profile=="IIS Express")Assert.False(hosting.ConfigureKestrel);
        else {Assert.Equal(hosting.Port,new Uri(expected).Port);Assert.Equal(hosting.UseHttps,new Uri(expected).Scheme=="https");}
    }
    [Theory]
    [InlineData(null)] [InlineData("")] [InlineData("/relative")] [InlineData("ftp://example.test")]
    [InlineData("https://user:password@example.test")] [InlineData("https://example.test/path")]
    [InlineData("https://example.test/?query=1")] [InlineData("https://example.test/#fragment")]
    [InlineData(" https://example.test")] [InlineData("https://example.test\\path")]
    [InlineData("http://0.0.0.0:5001")] [InlineData("http://[::]:5001")] [InlineData("https://example.test:0")] [InlineData("https://example.test/a/..")] [InlineData("https://example.test/%2e/")]
    public void Invalid_or_missing_origin_has_no_relative_or_untrusted_fallback(string? origin)
        => Assert.Throws<ArgumentException>(()=>new VerificationLinkBuilder(origin));
    [Theory]
    [InlineData("Production","http://api.example.test",false)] [InlineData("Production","https://localhost:5001",false)]
    [InlineData("Production",null,false)] [InlineData("Production","https://api.example.test",true)]
    [InlineData("ReverseProxy","http://api.example.test",false)] [InlineData("Staging","http://api.example.test",false)]
    [InlineData("Container","http://localhost:5001",true)] [InlineData("Testing","http://localhost:5001",true)]
    public void Environment_policy_requires_explicit_HTTPS_for_deployments(string profile,string? origin,bool allowed)
        => Assert.Equal(allowed,VerificationLinkBuilder.AllowedForEnvironment(origin,profile));
    [Theory]
    [InlineData("proof+/?=&%# \"雪")] [InlineData("//evil.example/route?payload=changed")]
    public void Every_fixed_route_encodes_and_round_trips_the_entire_payload(string payload)
    {
        var links=new VerificationLinkBuilder("https://API.example.test:8443/");
        foreach(var pair in new[]{(links.Registration(payload),"/account/verifyaccount"),(links.EmailChange(payload),"/account/adjust/email/verify"),(links.Delete(payload),"/account/wipeout/verify")})
        {
            var uri=new Uri(pair.Item1);Assert.Equal("https://api.example.test:8443",uri.GetLeftPart(UriPartial.Authority));Assert.Equal(pair.Item2,uri.AbsolutePath);
            Assert.Equal(payload,Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query)["payload"].ToString());Assert.Equal("",uri.Fragment);
        }
    }
    [Fact]
    public void Reverse_proxy_requires_operator_input_and_obsolete_origin_settings_fail_binding()
    {
        var config=new ConfigurationBuilder().AddJsonFile(Path.Combine(ProjectRoot(),"appsettings.json")).AddJsonFile(Path.Combine(ProjectRoot(),"appsettings.ReverseProxy.json")).Build();
        Assert.Equal("",config["RegistrationSettings:PublicOrigin"]);
        var services=new ServiceCollection();services.AddTreehammockServices(config);
        using var provider=services.BuildServiceProvider();Assert.Throws<OptionsValidationException>(()=>provider.GetRequiredService<IOptions<RegistrationSettings>>().Value);
        var settings=TestConfiguration.ValidSettings();settings["RegistrationSettings:AccountVerificationBaseUrl"]="https://obsolete.example.test";
        var invalid=new ServiceCollection();invalid.AddTreehammockServices(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());
        using var old=invalid.BuildServiceProvider();Assert.Throws<InvalidOperationException>(()=>old.GetRequiredService<IOptions<RegistrationSettings>>().Value);
    }
    [Fact]
    public async Task Frozen_origin_does_not_follow_mutated_options_or_spoofed_request_headers()
    {
        var fixture=new Cor23GLinkFixture();var service=fixture.Service("https://api.example.test:8443");fixture.Registration.PublicOrigin="https://mutated.example.test";
        var context=new Microsoft.AspNetCore.Http.DefaultHttpContext();context.Request.Host=new("evil.example.test");context.Request.Headers["X-Forwarded-Host"]="evil.example.test";context.Request.Headers["Forwarded"]="host=evil.example.test;proto=http";fixture.Accessor.HttpContext=context;
        await fixture.CaptureAsync(service,TestContext.Current.CancellationToken);
        Assert.All(fixture.Delivery.Intents,intent=>Assert.Equal("https://api.example.test:8443",new Uri(intent.Payload.Value).GetLeftPart(UriPartial.Authority)));
    }
    [Theory]
    [InlineData(null)] [InlineData("http://api.example.test")] [InlineData("https://localhost:5001")]
    public async Task Invalid_Production_origin_stops_host_start_before_any_delivery_worker(string? origin)
    {
        var settings=TestConfiguration.ValidSettings();settings["RegistrationSettings:PublicOrigin"]=origin;
        settings["DatabaseSettings:profile"]="Production";settings["SecurityOperationSettings:HmacKeys:1"]=Convert.ToBase64String(new byte[32]);
        var worker=new DeliveryStartWitness();
        using var host=new HostBuilder().UseEnvironment("Production").ConfigureAppConfiguration((_,builder)=>builder.AddInMemoryCollection(settings))
            .ConfigureServices((context,services)=> { services.AddTreehammockServices(context.Configuration,context.HostingEnvironment);foreach(var d in services.Where(d=>d.ServiceType==typeof(IHostedService)).ToArray())services.Remove(d);services.AddSingleton<IHostedService>(worker); }).Build();
        var failure=await Assert.ThrowsAsync<OptionsValidationException>(()=>host.StartAsync());Assert.Contains(failure.Failures,message=>message.Contains("PublicOrigin"));Assert.False(worker.Started);
    }
    private sealed class DeliveryStartWitness : IHostedService
    {
        internal bool Started;
        public Task StartAsync(CancellationToken token){Started=true;return Task.CompletedTask;}
        public Task StopAsync(CancellationToken token)=>Task.CompletedTask;
    }
}
