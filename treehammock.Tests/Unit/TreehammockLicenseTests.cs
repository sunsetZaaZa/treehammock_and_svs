using System.Xml.Linq;
using Shouldly;

namespace treehammock.Tests.Unit;

public class TreehammockLicenseTests
{
    [Fact]
    public void Repository_includes_mit_license_file()
    {
        string license = File.ReadAllText(ProjectFile("LICENSE"));
        string normalizedLicense = NormalizeWhitespace(license);

        license.ShouldStartWith("MIT License");
        license.ShouldContain("Copyright (c) 2026 Treehammock contributors");
        normalizedLicense.ShouldContain("Permission is hereby granted, free of charge");
        normalizedLicense.ShouldContain("sublicense, and/or sell copies of the Software");
        normalizedLicense.ShouldContain("THE SOFTWARE IS PROVIDED \"AS IS\"");
    }

    [Fact]
    public void Project_metadata_declares_mit_license_expression_for_all_projects()
    {
        XDocument props = XDocument.Load(ProjectFile("Directory.Build.props"));

        props.Descendants("PackageLicenseExpression")
            .Single()
            .Value
            .Trim()
            .ShouldBe("MIT");

        props.Descendants("Authors")
            .Single()
            .Value
            .Trim()
            .ShouldBe("Treehammock contributors");
    }

    private static string NormalizeWhitespace(string value)
    {
        return string.Join(" ", value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
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
