using System.Text.Json;
using Shouldly;

namespace treehammock.Tests.Unit;

public class LaunchSettingsJsonTests
{
    [Fact]
    public void LaunchSettings_json_is_valid_strict_json_without_trailing_comments()
    {
        string path = ProjectFile("Properties", "launchSettings.json");
        string source = File.ReadAllText(path);

        source.TrimStart().ShouldStartWith("{");
        source.ShouldNotContain("//Add environment variables for Twilio");

        using JsonDocument document = JsonDocument.Parse(source);

        document.RootElement.TryGetProperty("profiles", out JsonElement profiles).ShouldBeTrue();
        profiles.ValueKind.ShouldBe(JsonValueKind.Object);
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
