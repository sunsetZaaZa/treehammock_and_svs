using System.Reflection;
using System.Xml.Linq;
using Shouldly;

namespace treehammock.Tests.Unit;

public class Cor23SBuildIdentityTests
{
    [Fact]
    public void Loaded_application_and_test_assemblies_share_configuration_and_output_directory()
    {
        var tests = typeof(Cor23SBuildIdentityTests).Assembly;
        var application = typeof(Program).Assembly;
        string configuration = tests.GetCustomAttribute<AssemblyConfigurationAttribute>()!.Configuration;
        new[] { "Debug", "Release", "Sandbox" }.ShouldContain(configuration);
        application.GetCustomAttribute<AssemblyConfigurationAttribute>()!.Configuration.ShouldBe(configuration);
        Path.GetDirectoryName(application.Location).ShouldBe(Path.GetDirectoryName(tests.Location));
        new DirectoryInfo(Path.GetDirectoryName(tests.Location)!).Parent!.Name.ShouldBe(configuration);
        tests.ManifestModule.ModuleVersionId.ShouldNotBe(Guid.Empty);
        application.ManifestModule.ModuleVersionId.ShouldNotBe(Guid.Empty);
    }

    [Theory]
    [InlineData("treehammock.sln")]
    [InlineData("eng/treehammock.SqlContracts.sln")]
    public void Every_solution_project_maps_each_declared_configuration_to_itself(string solution)
    {
        string source = File.ReadAllText(Path.Combine(Root(), solution));
        foreach (string line in source.Split('\n').Where(l => l.Contains(".ActiveCfg =") || l.Contains(".Build.0 =")))
        {
            string configuration = line.Split('|')[0].Split('.').Last();
            line.Split('=')[1].Trim().ShouldBe(configuration + "|Any CPU");
        }
    }

    [Theory]
    [InlineData("treehammock.Tests")]
    [InlineData("treehammock.Tests.SqlContracts")]
    [InlineData("treehammock.Tests.System")]
    public void Test_application_reference_explicitly_uses_the_test_configuration(string project)
    {
        var xml = XDocument.Load(Path.Combine(Root(), project, project + ".csproj"));
        xml.Descendants("ProjectReference").Single().Element("SetConfiguration")!.Value.ShouldBe("Configuration=$(Configuration)");
    }

    private static string Root()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln"))) directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Source root missing.");
    }
}
