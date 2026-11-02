using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Rigging.DependencyInjection;

namespace treehammock.Tests.Unit;

public class HostingProfileConfigurationTests
{
    [Fact]
    public void Testing_profile_disables_kestrel_https_and_forwarded_headers_for_test_host()
    {
        HostingSettings settings = BindHostingProfile("appsettings.Testing.json");

        settings.ConfigureKestrel.ShouldBeFalse();
        settings.UseHttps.ShouldBeFalse();
        settings.UseHttpsRedirection.ShouldBeFalse();
        settings.UseForwardedHeaders.ShouldBeFalse();
        settings.Protocols.ShouldBe("Http1AndHttp2");
    }

    [Fact]
    public void Local_https_profile_binds_direct_development_hosting_shape()
    {
        HostingSettings settings = BindHostingProfile("appsettings.LocalHttps.json");

        settings.ConfigureKestrel.ShouldBeTrue();
        settings.Port.ShouldBe(5001);
        settings.BindAddress.ShouldBe("0.0.0.0");
        settings.UseHttps.ShouldBeTrue();
        settings.UseHttpsRedirection.ShouldBeTrue();
        settings.UseForwardedHeaders.ShouldBeFalse();
    }

    [Fact]
    public void Container_profile_binds_plain_http_without_forwarded_headers()
    {
        HostingSettings settings = BindHostingProfile("appsettings.Container.json");

        settings.ConfigureKestrel.ShouldBeTrue();
        settings.Port.ShouldBe(5001);
        settings.BindAddress.ShouldBe("0.0.0.0");
        settings.UseHttps.ShouldBeFalse();
        settings.Protocols.ShouldBe("Http1AndHttp2");
        settings.UseHttpsRedirection.ShouldBeFalse();
        settings.UseForwardedHeaders.ShouldBeFalse();
        settings.KnownProxies.ShouldBeEmpty();
        settings.KnownNetworks.ShouldBeEmpty();
    }


    [Fact]
    public void Container_reverse_proxy_profile_binds_plain_http_with_forwarded_headers()
    {
        HostingSettings settings = BindHostingProfile("appsettings.ContainerReverseProxy.json");

        settings.ConfigureKestrel.ShouldBeTrue();
        settings.Port.ShouldBe(5001);
        settings.BindAddress.ShouldBe("0.0.0.0");
        settings.UseHttps.ShouldBeFalse();
        settings.Protocols.ShouldBe("Http1AndHttp2");
        settings.UseHttpsRedirection.ShouldBeFalse();
        settings.UseForwardedHeaders.ShouldBeTrue();
        settings.ForwardLimit.ShouldBe(1);
        settings.RequireHeaderSymmetry.ShouldBeTrue();
        settings.TrustAllForwardedHeaderProxies.ShouldBeTrue();
        settings.KnownProxies.ShouldBeEmpty();
        settings.KnownNetworks.ShouldBeEmpty();
    }

    [Fact]
    public void Reverse_proxy_profile_binds_plain_http_with_forwarded_headers()
    {
        HostingSettings settings = BindHostingProfile("appsettings.ReverseProxy.json");

        settings.ConfigureKestrel.ShouldBeTrue();
        settings.UseHttps.ShouldBeFalse();
        settings.UseHttpsRedirection.ShouldBeFalse();
        settings.UseForwardedHeaders.ShouldBeTrue();
        settings.KnownNetworks.ShouldContain("10.42.0.0/16");
        settings.TrustAllForwardedHeaderProxies.ShouldBeFalse();
    }

    [Theory]
    [InlineData("appsettings.Testing.json")]
    [InlineData("appsettings.LocalHttps.json")]
    [InlineData("appsettings.Container.json")]
    [InlineData("appsettings.ContainerReverseProxy.json")]
    [InlineData("appsettings.ReverseProxy.json")]
    public void Hosting_profile_overlays_validate_with_example_config(string profileFile)
    {
        Exception? exception = Record.Exception(() => BindHostingProfile(profileFile));

        exception.ShouldBeNull();
    }

    private static HostingSettings BindHostingProfile(string profileFile)
    {
        string projectRoot = ProjectRoot();
        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddJsonFile(Path.Combine(projectRoot, "appsettings.Example.json"), optional: false, reloadOnChange: false)
            .AddJsonFile(Path.Combine(projectRoot, profileFile), optional: false, reloadOnChange: false)
            .Build();

        services.AddTreehammockServices(configuration);

        using ServiceProvider provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IOptions<HostingSettings>>().Value;
    }

    private static string ProjectRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return directory.FullName;
    }
}
