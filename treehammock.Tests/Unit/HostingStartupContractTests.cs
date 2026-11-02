using Shouldly;

namespace treehammock.Tests.Unit;

public class HostingStartupContractTests
{
    [Fact]
    public void Program_uses_hosting_settings_for_kestrel_and_https_pipeline()
    {
        string program = File.ReadAllText(ProjectFile("Program.cs"));

        program.ShouldContain("GetRequiredSection(\"HostingSettings\")");
        program.ShouldContain("HostingConfigurator.ConfigureKestrel");
        program.ShouldContain("hostingSettings.UseHttpsRedirection");
        program.ShouldContain("hostingSettings.UseForwardedHeaders");
        program.ShouldNotContain("ListenAnyIP(5001");
        program.ShouldNotContain("app.UseHttpsRedirection();\n\napp.UseResponseCompression();");
    }

    [Fact]
    public void Example_config_documents_reverse_proxy_hosting_shape()
    {
        string example = File.ReadAllText(ProjectFile("appsettings.Example.json"));

        example.ShouldContain("\"HostingSettings\"");
        example.ShouldContain("\"UseForwardedHeaders\"");
        example.ShouldContain("\"KnownProxies\"");
        example.ShouldContain("\"KnownNetworks\"");
    }

    [Fact]
    public void Repository_contains_explicit_hosting_profiles()
    {
        string projectRoot = ProjectRoot();

        File.Exists(Path.Combine(projectRoot, "appsettings.Testing.json")).ShouldBeTrue();
        File.Exists(Path.Combine(projectRoot, "appsettings.LocalHttps.json")).ShouldBeTrue();
        File.Exists(Path.Combine(projectRoot, "appsettings.ReverseProxy.json")).ShouldBeTrue();

        string testingProfile = File.ReadAllText(Path.Combine(projectRoot, "appsettings.Testing.json"));
        string reverseProxyProfile = File.ReadAllText(Path.Combine(projectRoot, "appsettings.ReverseProxy.json"));

        testingProfile.ShouldContain("\"ConfigureKestrel\": false");
        testingProfile.ShouldContain("\"UseHttpsRedirection\": false");
        reverseProxyProfile.ShouldContain("\"UseForwardedHeaders\": true");
        reverseProxyProfile.ShouldContain("\"KnownNetworks\"");
    }

    [Fact]
    public void Test_factory_overlays_testing_hosting_profile_on_example_config()
    {
        string factory = File.ReadAllText(ProjectFile("treehammock.Tests", "Infrastructure", "TreehammockWebApplicationFactory.cs"));

        factory.ShouldContain("appsettings.Example.json");
        factory.ShouldContain("appsettings.Testing.json");
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

    private static string ProjectFile(params string[] relativePathParts)
    {
        return Path.Combine(new[] { ProjectRoot() }.Concat(relativePathParts).ToArray());
    }
}
