using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Rigging.DependencyInjection;
using treehammock.Rigging.Hosting;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class HostingSettingsTests
{
    [Theory]
    [InlineData("0")]
    [InlineData("8")]
    [InlineData("9")]
    [InlineData("999")]
    [InlineData("-1")]
    [InlineData("invalid")]
    [InlineData("")]
    public void Unsupported_protocols_fail_validation_and_direct_listener_configuration(string protocols)
    {
        var settings = new HostingSettings { Protocols = protocols };
        settings.Validate(new System.ComponentModel.DataAnnotations.ValidationContext(settings)).ShouldNotBeEmpty();
        Should.Throw<InvalidOperationException>(() => settings.GetProtocols());
        Dictionary<string, string?> configured = TestConfiguration.ValidSettings();
        configured["HostingSettings:Protocols"] = protocols;
        BuildHostingOptionsException(configured).Message.ShouldContain("HostingSettings");
    }

    [Theory]
    [InlineData("Http1", 1)]
    [InlineData("http2", 2)]
    [InlineData("Http3", 4)]
    [InlineData("Http1, Http3", 5)]
    [InlineData("Http2, Http3", 6)]
    [InlineData("Http1AndHttp2AndHttp3", 7)]
    [InlineData("1", 1)]
    [InlineData("2", 2)]
    [InlineData("3", 3)]
    [InlineData("4", 4)]
    [InlineData("5", 5)]
    [InlineData("6", 6)]
    [InlineData("7", 7)]
    public void Supported_nonzero_protocol_combinations_retain_the_requested_mask(string protocols, int expected)
    {
        var settings = new HostingSettings { Protocols = protocols };
        settings.Validate(new System.ComponentModel.DataAnnotations.ValidationContext(settings)).ShouldBeEmpty();
        settings.GetProtocols().ShouldBe((HttpProtocols)expected);
    }

    [Fact]
    public void Valid_config_binds_hosting_settings()
    {
        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(TestConfiguration.ValidSettings())
            .Build();

        services.AddTreehammockServices(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();

        HostingSettings settings = provider.GetRequiredService<IOptions<HostingSettings>>().Value;

        settings.ConfigureKestrel.ShouldBeTrue();
        settings.Port.ShouldBe(5001);
        settings.BindAddress.ShouldBe("0.0.0.0");
        settings.UseHttps.ShouldBeTrue();
        settings.GetProtocols().ShouldBe(HttpProtocols.Http1AndHttp2AndHttp3);
        settings.UseHttpsRedirection.ShouldBeTrue();
        settings.UseForwardedHeaders.ShouldBeFalse();
    }

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("localhost")]
    public void Invalid_bind_address_fails_options_validation(string bindAddress)
    {
        Dictionary<string, string?> settings = TestConfiguration.ValidSettings();
        settings["HostingSettings:BindAddress"] = bindAddress;

        OptionsValidationException exception = BuildHostingOptionsException(settings);

        exception.Message.ShouldContain("HostingSettings");
    }

    [Fact]
    public void Invalid_forwarded_header_network_fails_options_validation()
    {
        Dictionary<string, string?> settings = TestConfiguration.ValidSettings();
        settings["HostingSettings:KnownNetworks:0"] = "10.0.0.0/not-a-prefix";

        OptionsValidationException exception = BuildHostingOptionsException(settings);

        exception.Message.ShouldContain("HostingSettings");
    }

    [Fact]
    public void Forwarded_headers_are_limited_to_forwarded_for_and_proto()
    {
        var settings = new HostingSettings
        {
            UseForwardedHeaders = true,
            ForwardLimit = 2,
            KnownProxies = new[] { "10.0.0.10" },
            KnownNetworks = new[] { "10.0.1.0/24" }
        };

        ForwardedHeadersOptions options = HostingConfigurator.CreateForwardedHeadersOptions(settings);

        options.ForwardedHeaders.ShouldBe(ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto);
        options.ForwardLimit.ShouldBe(2);
        options.KnownProxies.ShouldContain(System.Net.IPAddress.Parse("10.0.0.10"));
        options.KnownNetworks.Count.ShouldBe(1);
    }

    [Fact]
    public void Trust_all_forwarded_header_proxies_clears_default_loopback_trust_lists()
    {
        var settings = new HostingSettings
        {
            TrustAllForwardedHeaderProxies = true
        };

        ForwardedHeadersOptions options = HostingConfigurator.CreateForwardedHeadersOptions(settings);

        options.KnownProxies.ShouldBeEmpty();
        options.KnownNetworks.ShouldBeEmpty();
    }

    private static OptionsValidationException BuildHostingOptionsException(IReadOnlyDictionary<string, string?> settings)
    {
        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        services.AddTreehammockServices(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();

        Exception? exception = Record.Exception(() => provider.GetRequiredService<IOptions<HostingSettings>>().Value);

        exception.ShouldNotBeNull();
        return exception.ShouldBeOfType<OptionsValidationException>();
    }
}
