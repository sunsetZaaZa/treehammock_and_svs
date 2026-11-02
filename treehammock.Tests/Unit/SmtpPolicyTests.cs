using MailKit.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Rigging.DependencyInjection;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public sealed class Cor23HSmtpPolicyTests
{
    private static SMTPSettings Settings()=>new(){SMTPQualifiedDomain="127.0.0.1",SMTPPort=1025,SMTPUsername="fixture-user",SMTPPassword="fixture-password",NoReplyEmailAddress="sender@example.test"};
    [Theory]
    [InlineData("Production",false)] [InlineData("Development",false)] [InlineData("LocalHttps",false)]
    [InlineData("Container",false)] [InlineData("ContainerReverseProxy",false)] [InlineData("ReverseProxy",false)]
    [InlineData("Testing",true)] [InlineData(null,false)] [InlineData("testing",false)]
    public void Plaintext_requires_exact_Testing_environment_even_when_loopback_and_permission_are_explicit(string? environment,bool allowed)
    {
        var settings=Settings();settings.TransportMode=SmtpTransportMode.IsolatedPlaintext;settings.AllowIsolatedPlaintext=true;
        Assert.Equal(allowed,SmtpTransportPolicy.AllowedForEnvironment(settings,environment));
        if(allowed)Assert.False(new SmtpTransportPolicy(settings,environment).RequireEncryption);
        else Assert.Throws<OptionsValidationException>(()=>new SmtpTransportPolicy(settings,environment));
    }
    [Theory]
    [InlineData("127.0.0.1",true)] [InlineData("::1",true)] [InlineData("localhost",false)]
    [InlineData("relay.example.test",false)] [InlineData("10.0.0.1",false)] [InlineData("0.0.0.0",false)]
    public void Plaintext_relay_must_be_a_literal_loopback_address_not_a_resolvable_or_internal_host(string host,bool allowed)
    {
        var settings=Settings();settings.TransportMode=SmtpTransportMode.IsolatedPlaintext;settings.AllowIsolatedPlaintext=true;settings.SMTPQualifiedDomain=host;
        Assert.Equal(allowed,SmtpTransportPolicy.AllowedForEnvironment(settings,"Testing"));
    }
    [Theory]
    [InlineData(99,false,1025)] [InlineData(2,false,1025)] [InlineData(0,true,1025)]
    [InlineData(1,true,1025)] [InlineData(0,false,465)] [InlineData(1,false,587)] [InlineData(0,false,0)]
    public void Unsupported_numeric_modes_and_conflicting_permission_or_ports_fail_validation(int mode,bool allow,int port)
    {
        var settings=Settings();settings.TransportMode=(SmtpTransportMode)mode;settings.AllowIsolatedPlaintext=allow;settings.SMTPPort=port;
        Assert.False(SmtpTransportPolicy.AllowedForEnvironment(settings,"Testing"));
        var error=Assert.Throws<OptionsValidationException>(()=>new SmtpTransportPolicy(settings,"Testing"));
        Assert.DoesNotContain(settings.SMTPPassword,error.Message);Assert.DoesNotContain(settings.SMTPUsername,error.Message);
    }
    [Theory]
    [InlineData("https://relay.example.test")] [InlineData("relay.example.test:587")] [InlineData(" relay.example.test")]
    [InlineData("relay.example.test/path")] [InlineData("relay\n.example.test")]
    public void Transport_host_rejects_URL_port_path_and_control_character_shapes(string host)
    {
        var settings=Settings();settings.SMTPQualifiedDomain=host;Assert.False(SmtpTransportPolicy.AllowedForEnvironment(settings,"Production"));
    }
    [Theory]
    [InlineData("RequiredStartTls",587,SecureSocketOptions.StartTls)]
    [InlineData("ImplicitTls",465,SecureSocketOptions.SslOnConnect)]
    public void Production_secure_modes_map_only_to_required_encryption_and_default_factory_preserves_certificate_validation(string mode,int port,SecureSocketOptions expected)
    {
        var settings=Settings();settings.TransportMode=Enum.Parse<SmtpTransportMode>(mode);settings.SMTPPort=port;
        var policy=new SmtpTransportPolicy(settings,"Production");Assert.Equal(expected,policy.SocketOptions);Assert.True(policy.RequireEncryption);
        using var client=new SmtpClientFactory().Create();Assert.Null(client.ServerCertificateValidationCallback);Assert.True(client.CheckCertificateRevocation);
        Assert.Equal(System.Security.Authentication.SslProtocols.Tls12|System.Security.Authentication.SslProtocols.Tls13,client.SslProtocols);
    }
    [Fact]
    public void Every_shipped_configuration_retains_required_TLS_and_plaintext_permission_disabled()
    {
        foreach(string profile in new[]{"Example","Development","LocalHttps","Container","ContainerReverseProxy","ReverseProxy","Testing"})
        {
            var config=new ConfigurationBuilder().AddJsonFile(Path.Combine(Cor23GPublicOriginTests.ProjectRoot(),"appsettings.json")).AddJsonFile(Path.Combine(Cor23GPublicOriginTests.ProjectRoot(),"appsettings."+profile+".json")).Build();
            var settings=config.GetSection("SMTPSettings").Get<SMTPSettings>()!;
            Assert.Equal(SmtpTransportMode.RequiredStartTls,settings.TransportMode);Assert.False(settings.AllowIsolatedPlaintext);Assert.True(SmtpTransportPolicy.AllowedForEnvironment(settings,profile));
        }
    }
    [Theory]
    [InlineData("Auto")] [InlineData("StartTlsWhenAvailable")] [InlineData("None")] [InlineData("99")]
    public void Opportunistic_removed_or_undefined_transport_values_cannot_bind_as_a_runtime_policy(string value)
    {
        var settings=TestConfiguration.ValidSettings();settings["SMTPSettings:TransportMode"]=value;
        var services=new ServiceCollection();services.AddTreehammockServices(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());using var provider=services.BuildServiceProvider();
        var error=Record.Exception(()=>provider.GetRequiredService<IOptions<SMTPSettings>>().Value);
        if(value=="99")Assert.IsType<OptionsValidationException>(error);
        else Assert.IsType<InvalidOperationException>(error);
    }
    [Fact]
    public void Unknown_TLS_property_cannot_silently_leave_the_secure_default_or_bypass_policy()
    {
        var settings=TestConfiguration.ValidSettings();settings["SMTPSettings:IgnoreCertificateErrors"]="true";
        var services=new ServiceCollection();services.AddTreehammockServices(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());using var provider=services.BuildServiceProvider();
        Assert.Throws<InvalidOperationException>(()=>provider.GetRequiredService<IOptions<SMTPSettings>>().Value);
    }
    [Theory]
    [InlineData("Production")] [InlineData("Development")] [InlineData("LocalHttps")]
    [InlineData("Container")] [InlineData("ContainerReverseProxy")] [InlineData("ReverseProxy")]
    public async Task Deployable_host_rejects_plaintext_before_any_delivery_worker_starts(string environment)
    {
        var settings=TestConfiguration.ValidSettings();settings["SMTPSettings:TransportMode"]="IsolatedPlaintext";settings["SMTPSettings:AllowIsolatedPlaintext"]="true";settings["SMTPSettings:SMTPQualifiedDomain"]="127.0.0.1";
        settings["RegistrationSettings:PublicOrigin"]="https://api.example.test";
        settings["DatabaseSettings:profile"]="Production";settings["SecurityOperationSettings:HmacKeys:1"]=Convert.ToBase64String(new byte[32]);
        var worker=new Witness();using var host=new HostBuilder().UseEnvironment(environment).ConfigureAppConfiguration((_,builder)=>builder.AddInMemoryCollection(settings))
            .ConfigureServices((context,services)=>{services.AddTreehammockServices(context.Configuration,context.HostingEnvironment);foreach(var d in services.Where(d=>d.ServiceType==typeof(IHostedService)).ToArray())services.Remove(d);services.AddSingleton<IHostedService>(worker);}).Build();
        var error=await Assert.ThrowsAsync<OptionsValidationException>(()=>host.StartAsync());Assert.Contains(error.Failures,f=>f.Contains("SMTPSettings"));Assert.False(worker.Started);
    }
    [Fact]
    public async Task Explicit_Testing_host_starts_with_real_provider_and_loopback_plaintext_policy()
    {
        var settings=TestConfiguration.ValidSettings();settings["SMTPSettings:TransportMode"]="IsolatedPlaintext";settings["SMTPSettings:AllowIsolatedPlaintext"]="true";settings["SMTPSettings:SMTPQualifiedDomain"]="127.0.0.1";
        using var host=new HostBuilder().UseEnvironment("Testing").ConfigureAppConfiguration((_,builder)=>builder.AddInMemoryCollection(settings))
            .ConfigureServices((context,services)=>{services.AddTreehammockServices(context.Configuration,context.HostingEnvironment);foreach(var d in services.Where(d=>d.ServiceType==typeof(IHostedService)).ToArray())services.Remove(d);}).Build();
        await host.StartAsync();Assert.IsType<treehammock.Services.SMTPService>(host.Services.GetRequiredService<treehammock.Services.ISMTPService>());
        Assert.False(host.Services.GetRequiredService<SmtpTransportPolicy>().RequireEncryption);await host.StopAsync();
    }
    private sealed class Witness : IHostedService
    {
        internal bool Started;
        public Task StartAsync(CancellationToken token){Started=true;return Task.CompletedTask;}
        public Task StopAsync(CancellationToken token)=>Task.CompletedTask;
    }
}
