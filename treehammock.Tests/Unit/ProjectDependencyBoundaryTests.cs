using System.Xml.Linq;
using Shouldly;

namespace treehammock.Tests.Unit;

public class ProjectDependencyBoundaryTests
{
    [Fact]
    public void Coverage_collector_is_locked_test_only_and_does_not_flow_into_application()
    {
        using var testLock = System.Text.Json.JsonDocument.Parse(File.ReadAllText(ProjectFile("treehammock.Tests", "packages.lock.json")));
        var packages = testLock.RootElement.GetProperty("dependencies").GetProperty("net8.0");
        packages.GetProperty("Microsoft.NET.Test.Sdk").GetProperty("dependencies")
            .GetProperty("Microsoft.CodeCoverage").GetString().ShouldBe("17.14.1");
        packages.GetProperty("Microsoft.CodeCoverage").GetProperty("resolved").GetString().ShouldBe("17.14.1");
        using var appLock = System.Text.Json.JsonDocument.Parse(File.ReadAllText(ProjectFile("packages.lock.json")));
        appLock.RootElement.GetProperty("dependencies").GetProperty("net8.0")
            .TryGetProperty("Microsoft.CodeCoverage", out _).ShouldBeFalse();
        var settings = XDocument.Load(ProjectFile("eng", "coverage.runsettings"));
        settings.Descendants("DataCollector").Single().Attribute("friendlyName")!.Value.ShouldBe("Code Coverage");
        settings.Descendants("Format").Single().Value.ShouldBe("cobertura");
        settings.Descendants("IncludeTestAssembly").Single().Value.ShouldBe("False");
    }

    private static readonly string[] TestOnlyPackages =
    [
        "Microsoft.NET.Test.Sdk",
        "Microsoft.CodeCoverage",
        "Microsoft.AspNetCore.Mvc.Testing",
        "Microsoft.AspNetCore.TestHost",
        "xunit.v3",
        "Moq",
        "NSubstitute",
        "Shouldly",
        "AutoFixture",
        "AutoFixture.AutoNSubstitute"
    ];

    private static readonly string[] RequiredTestPackages =
    [
        "Microsoft.NET.Test.Sdk",
        "Microsoft.AspNetCore.Mvc.Testing",
        "Microsoft.AspNetCore.TestHost",
        "xunit.v3",
        "xunit.runner.visualstudio",
        "NSubstitute",
        "Shouldly",
        "AutoFixture",
        "AutoFixture.AutoNSubstitute"
    ];

    private static readonly string[] RemovedTestPackages =
    [
        "Moq",
        "xunit",
        "coverlet.collector"
    ];

    [Fact]
    public void App_project_does_not_reference_test_only_packages()
    {
        XDocument project = XDocument.Load(ProjectFile("treehammock.csproj"));
        string[] packageNames = PackageReferenceNames(project);

        foreach (string testPackage in TestOnlyPackages)
        {
            packageNames.ShouldNotContain(testPackage);
        }
    }

    [Fact]
    public void Test_project_owns_test_framework_and_mocking_packages()
    {
        XDocument project = XDocument.Load(ProjectFile("treehammock.Tests", "treehammock.Tests.csproj"));
        XDocument sqlProject = XDocument.Load(ProjectFile("treehammock.Tests.SqlContracts", "treehammock.Tests.SqlContracts.csproj"));
        XDocument systemProject = XDocument.Load(ProjectFile("treehammock.Tests.System", "treehammock.Tests.System.csproj"));
        string[] packageNames = PackageReferenceNames(project).Concat(PackageReferenceNames(sqlProject)).Concat(PackageReferenceNames(systemProject)).Distinct().ToArray();

        foreach (string testPackage in RequiredTestPackages)
        {
            packageNames.ShouldContain(testPackage);
        }

        foreach (string removedPackage in RemovedTestPackages)
        {
            packageNames.ShouldNotContain(removedPackage);
        }
    }

    [Fact]
    public void Test_project_package_references_are_private_assets()
    {
        XDocument project = XDocument.Load(ProjectFile("treehammock.Tests", "treehammock.Tests.csproj"));
        XDocument sqlProject = XDocument.Load(ProjectFile("treehammock.Tests.SqlContracts", "treehammock.Tests.SqlContracts.csproj"));
        XDocument systemProject = XDocument.Load(ProjectFile("treehammock.Tests.System", "treehammock.Tests.System.csproj"));
        IEnumerable<XElement> packageReferences = project.Descendants("PackageReference").Concat(sqlProject.Descendants("PackageReference")).Concat(systemProject.Descendants("PackageReference"));

        foreach (XElement packageReference in packageReferences)
        {
            string? packageName = packageReference.Attribute("Include")?.Value;
            packageName.ShouldNotBeNullOrWhiteSpace();

            string privateAssets = packageReference.Element("PrivateAssets")?.Value.Trim() ?? string.Empty;
            privateAssets.ShouldBe("all", $"Package '{packageName}' should not flow outside the test project.");
        }
    }

    [Fact]
    public void App_project_excludes_nested_test_project_sources_from_runtime_compile_items()
    {
        string appProject = File.ReadAllText(ProjectFile("treehammock.csproj"));

        appProject.ShouldContain("<Compile Remove=\"treehammock.Tests\\**\" />");
        appProject.ShouldContain("<Content Remove=\"treehammock.Tests\\**\" />");
        appProject.ShouldContain("<EmbeddedResource Remove=\"treehammock.Tests\\**\" />");
        appProject.ShouldContain("<None Remove=\"treehammock.Tests\\**\" />");
        appProject.ShouldContain("<Compile Remove=\"treehammock.Tests.SqlContracts\\**\" />");
        appProject.ShouldContain("<Content Remove=\"treehammock.Tests.SqlContracts\\**\" />");
        appProject.ShouldContain("<EmbeddedResource Remove=\"treehammock.Tests.SqlContracts\\**\" />");
        appProject.ShouldContain("<None Remove=\"treehammock.Tests.SqlContracts\\**\" />");
        appProject.ShouldContain("<Compile Remove=\"treehammock.Tests.System\\**\" />");
        appProject.ShouldContain("<Content Remove=\"treehammock.Tests.System\\**\" />");
        appProject.ShouldContain("<EmbeddedResource Remove=\"treehammock.Tests.System\\**\" />");
        appProject.ShouldContain("<None Remove=\"treehammock.Tests.System\\**\" />");
        appProject.ShouldContain("<Compile Remove=\"treehammock.Tests\\**\" />");
        appProject.ShouldContain("<Content Remove=\"treehammock.Tests\\**\" />");
        appProject.ShouldContain("<EmbeddedResource Remove=\"treehammock.Tests\\**\" />");
        appProject.ShouldContain("<None Remove=\"treehammock.Tests\\**\" />");
        appProject.ShouldContain("<Compile Remove=\"treehammock.Tests.SqlContracts\\**\" />");
        appProject.ShouldContain("<Content Remove=\"treehammock.Tests.SqlContracts\\**\" />");
        appProject.ShouldContain("<EmbeddedResource Remove=\"treehammock.Tests.SqlContracts\\**\" />");
        appProject.ShouldContain("<None Remove=\"treehammock.Tests.SqlContracts\\**\" />");
        appProject.ShouldContain("<Compile Remove=\"treehammock.Tests.System\\**\" />");
        appProject.ShouldContain("<Content Remove=\"treehammock.Tests.System\\**\" />");
        appProject.ShouldContain("<EmbeddedResource Remove=\"treehammock.Tests.System\\**\" />");
        appProject.ShouldContain("<None Remove=\"treehammock.Tests.System\\**\" />");
    }

    [Fact]
    public void Runtime_sources_and_sql_baseline_do_not_use_removed_external_provider_name()
    {
        string removedProviderName = "Au" + "thy";
        string[] sourcePatterns = ["*.cs", "*.sql"];

        foreach (string pattern in sourcePatterns)
        {
            foreach (string sourceFile in Directory.EnumerateFiles(ProjectRoot(), pattern, SearchOption.AllDirectories))
            {
                if (IsIgnoredPath(sourceFile))
                {
                    continue;
                }

                string source = File.ReadAllText(sourceFile);
                source.ShouldNotContain(removedProviderName);
                source.ShouldNotContain(removedProviderName.ToUpperInvariant());
                source.ShouldNotContain(removedProviderName.ToLowerInvariant());
            }
        }
    }

    [Fact]
    public void Package_versions_are_centrally_managed()
    {
        XDocument centralPackageVersions = XDocument.Load(ProjectFile("Directory.Packages.props"));
        XDocument appProject = XDocument.Load(ProjectFile("treehammock.csproj"));
        XDocument testProject = XDocument.Load(ProjectFile("treehammock.Tests", "treehammock.Tests.csproj"));
        XDocument sqlTestProject = XDocument.Load(ProjectFile("treehammock.Tests.SqlContracts", "treehammock.Tests.SqlContracts.csproj"));
        XDocument systemTestProject = XDocument.Load(ProjectFile("treehammock.Tests.System", "treehammock.Tests.System.csproj"));
        string[] centrallyPinnedPackages = PackageVersionNames(centralPackageVersions);

        centralPackageVersions
            .Descendants("ManagePackageVersionsCentrally")
            .Single()
            .Value
            .Trim()
            .ShouldBe("true");

        centralPackageVersions
            .Descendants("CentralPackageVersionOverrideEnabled")
            .Single()
            .Value
            .Trim()
            .ShouldBe("false");

        foreach (XElement packageReference in appProject.Descendants("PackageReference").Concat(testProject.Descendants("PackageReference")).Concat(sqlTestProject.Descendants("PackageReference")).Concat(systemTestProject.Descendants("PackageReference")))
        {
            string? packageName = packageReference.Attribute("Include")?.Value;
            packageName.ShouldNotBeNullOrWhiteSpace();
            packageReference.Attribute("Version").ShouldBeNull($"Package '{packageName}' should take its version from Directory.Packages.props.");
            centrallyPinnedPackages.ShouldContain(packageName!, $"Package '{packageName}' should have exactly one central version pin.");
        }
    }

    [Fact]
    public void Central_package_versions_are_stable_release_pins()
    {
        XDocument centralPackageVersions = XDocument.Load(ProjectFile("Directory.Packages.props"));
        XElement[] packageVersions = centralPackageVersions.Descendants("PackageVersion").ToArray();

        packageVersions.ShouldNotBeEmpty();
        centralPackageVersions
            .Descendants("RestorePackagesWithLockFile")
            .Single()
            .Value
            .Trim()
            .ShouldBe("true");

        foreach (XElement packageVersion in packageVersions)
        {
            string? packageName = packageVersion.Attribute("Include")?.Value;
            string? version = packageVersion.Attribute("Version")?.Value;

            packageName.ShouldNotBeNullOrWhiteSpace();
            version.ShouldNotBeNullOrWhiteSpace($"Package '{packageName}' should have an explicit version pin.");
            version!.Contains('*').ShouldBeFalse($"Package '{packageName}' should not use floating versions.");
            version.Contains('-').ShouldBeFalse($"Package '{packageName}' should not use prerelease versions for 1.0 stabilization.");
            version.StartsWith("[", StringComparison.Ordinal).ShouldBeFalse($"Package '{packageName}' should use an exact central version, not a version range.");
            version.StartsWith("(", StringComparison.Ordinal).ShouldBeFalse($"Package '{packageName}' should use an exact central version, not a version range.");
        }
    }

    private static string[] PackageReferenceNames(XDocument project)
    {
        return project
            .Descendants("PackageReference")
            .Select(package => package.Attribute("Include")?.Value)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => name!)
            .ToArray();
    }


    private static string[] PackageVersionNames(XDocument project)
    {
        return project
            .Descendants("PackageVersion")
            .Select(package => package.Attribute("Include")?.Value)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => name!)
            .ToArray();
    }

    private static bool IsIgnoredPath(string sourceFile)
    {
        if (sourceFile.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal) ||
            sourceFile.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
        {
            return true;
        }

        string root = ProjectRoot();
        string relative = Path.GetRelativePath(root, sourceFile);
        string[] ignoredSegments =
        [
            "treehammock.Tests",
            "treehammock.Tests.SqlContracts",
            "treehammock.Tests.System",
            "treehammock.Tests",
            "treehammock.Tests.SqlContracts",
            "treehammock.Tests.System",
            "bin",
            "obj"
        ];

        return ignoredSegments.Any(segment => relative.StartsWith(segment + Path.DirectorySeparatorChar, StringComparison.Ordinal));
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
