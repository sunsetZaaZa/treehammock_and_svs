using Shouldly;

namespace treehammock.Tests.Unit;

public class ReleaseHardeningTests
{
    [Fact]
    public void Release_source_files_do_not_keep_todo_or_fixme_markers()
    {
        string[] sourceRoots =
        [
            "Controllers",
            "DataLayer",
            "Entities",
            "Models",
            "Repos",
            "Rigging",
            "RiggingSupport",
            "Services",
        ];

        foreach (string sourceRoot in sourceRoots)
        {
            foreach (string file in Directory.EnumerateFiles(ProjectFile(sourceRoot), "*.cs", SearchOption.AllDirectories))
            {
                string relativePath = Path.GetRelativePath(ProjectRoot(), file);
                string source = File.ReadAllText(file);

                source.ShouldNotContain("TODO", Case.Insensitive, $"{relativePath} should use release-matrix language instead of TODO comments.");
                source.ShouldNotContain("FIXME", Case.Insensitive, $"{relativePath} should not keep unresolved FIXME comments for 1.0.0.");
            }
        }
    }

    [Fact]
    public void Password_reset_service_does_not_keep_not_implemented_placeholder_code()
    {
        string service = File.ReadAllText(ProjectFile("Services", "PasswordResetService.cs"));

        service.ShouldNotContain("NotImplementedCode");
        service.ShouldNotContain("PASSWORD_RESET_NOT_IMPLEMENTED");
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
