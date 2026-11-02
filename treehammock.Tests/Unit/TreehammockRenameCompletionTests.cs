using System.Text;
using Shouldly;

namespace treehammock.Tests.Unit;

public class TreehammockRenameCompletionTests
{
    private static readonly string[] LegacyProductTokens =
    [
        string.Concat("contact", "raptor"),
        string.Concat("Contact", "Raptor"),
        string.Concat("CONTACT", "RAPTOR"),
        string.Concat("contact", "-", "raptor"),
        string.Concat("contact", "_", "raptor")
    ];

    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".bru",
        ".cfg",
        ".cmd",
        ".config",
        ".cs",
        ".csproj",
        ".dockerignore",
        ".html",
        ".json",
        ".md",
        ".props",
        ".ps1",
        ".sh",
        ".sln",
        ".sql",
        ".txt",
        ".user",
        ".yaml",
        ".yml"
    };

    [Fact]
    public void Repository_file_and_directory_names_are_treehammock_only()
    {
        foreach (string entry in Directory.EnumerateFileSystemEntries(ProjectRoot(), "*", SearchOption.AllDirectories))
        {
            if (IsIgnoredPath(entry))
            {
                continue;
            }

            string relativePath = Path.GetRelativePath(ProjectRoot(), entry);

            foreach (string legacyToken in LegacyProductTokens)
            {
                relativePath.ShouldNotContain(legacyToken, Case.Insensitive, $"Rename sweep found legacy product token in path '{relativePath}'.");
            }
        }
    }

    [Fact]
    public void Text_repository_content_is_treehammock_only()
    {
        foreach (string file in Directory.EnumerateFiles(ProjectRoot(), "*", SearchOption.AllDirectories))
        {
            if (IsIgnoredPath(file) || !IsTextFile(file))
            {
                continue;
            }

            string relativePath = Path.GetRelativePath(ProjectRoot(), file);
            string content = File.ReadAllText(file, Encoding.UTF8);

            foreach (string legacyToken in LegacyProductTokens)
            {
                content.ShouldNotContain(legacyToken, Case.Insensitive, $"Rename sweep found legacy product token in text file '{relativePath}'.");
            }
        }
    }

    private static bool IsTextFile(string file)
    {
        string fileName = Path.GetFileName(file);
        string extension = Path.GetExtension(fileName);

        return TextExtensions.Contains(extension) ||
               fileName.Equals(".dockerignore", StringComparison.OrdinalIgnoreCase) ||
               fileName.Equals("Dockerfile", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsIgnoredPath(string path)
    {
        string relativePath = Path.GetRelativePath(ProjectRoot(), path);
        string[] ignoredSegments =
        [
            ".git",
            ".vs",
            "bin",
            "obj",
            "TestResults"
        ];

        return ignoredSegments.Any(segment =>
            relativePath.Equals(segment, StringComparison.Ordinal) ||
            relativePath.StartsWith(segment + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
            relativePath.Contains(Path.DirectorySeparatorChar + segment + Path.DirectorySeparatorChar, StringComparison.Ordinal));
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
