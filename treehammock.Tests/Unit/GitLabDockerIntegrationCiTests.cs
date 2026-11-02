using Shouldly;

namespace treehammock.Tests.Unit;

public class GitLabDockerIntegrationCiTests
{
    [Fact]
    public void Docker_direct_integration_child_pipeline_starts_postgres_dragonfly_and_api_without_haproxy()
    {
        string child = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "docker-direct.yml"));

        child.ShouldContain("docker-integration-direct:");
        child.ShouldContain("image: docker:27-cli");
        child.ShouldContain("docker:27-dind");
        child.ShouldContain("DOCKER_BUILDKIT: \"1\"");
        child.ShouldContain("stage: integration");
        child.ShouldContain("docker compose version");
        child.ShouldContain("./eng/docker-http-contracts-direct.sh");
        child.ShouldContain("docker-compose.integration.yml");
        child.ShouldContain("docker-compose.api-direct.yml");
        child.ShouldContain("--profile http");
        child.ShouldContain("$CI_PIPELINE_SOURCE == \"parent_pipeline\"");

        child.ShouldNotContain("docker-compose.api-proxy.yml");
        child.ShouldNotContain("--profile proxy");
        child.ShouldNotContain("--profile http-proxy");
    }

    [Fact]
    public void Docker_proxy_integration_child_pipeline_starts_postgres_dragonfly_api_and_haproxy()
    {
        string child = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "docker-proxy.yml"));

        child.ShouldContain("docker-integration-proxy:");
        child.ShouldContain("image: docker:27-cli");
        child.ShouldContain("docker:27-dind");
        child.ShouldContain("DOCKER_BUILDKIT: \"1\"");
        child.ShouldContain("stage: integration");
        child.ShouldContain("docker compose version");
        child.ShouldContain("./eng/docker-http-contracts-proxy.sh");
        child.ShouldContain("docker-compose.integration.yml");
        child.ShouldContain("docker-compose.api-proxy.yml");
        child.ShouldContain("--profile proxy");
        child.ShouldContain("--profile http-proxy");
        child.ShouldContain("$CI_PIPELINE_SOURCE == \"parent_pipeline\"");
    }

    [Fact]
    public void Docker_system_child_pipeline_starts_full_stack_and_system_test_runner()
    {
        string child = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "docker-system.yml"));
        string script = File.ReadAllText(ProjectFile("eng", "docker-system-stack-tests.sh"));

        child.ShouldContain("docker-system-stack-tests:");
        child.ShouldContain("docker:27-dind");
        child.ShouldContain("./eng/docker-system-stack-tests.sh");
        script.ShouldContain("docker-compose.integration.yml");
        script.ShouldContain("docker-compose.api-proxy.yml");
        script.ShouldContain("docker-compose.ci-system.yml");
        script.ShouldContain("--profile proxy");
        script.ShouldContain("--profile system");
    }

    [Fact]
    public void Root_dispatcher_names_match_required_usage_modes()
    {
        string root = File.ReadAllText(ProjectFile(".gitlab-ci.yml"));

        root.ShouldContain("trigger-dotnet-unit-pipeline:");
        root.ShouldContain("trigger-dotnet-integration-pipeline:");
        root.ShouldContain("trigger-dotnet-sql-pipeline:");
        root.ShouldContain("trigger-docker-direct-pipeline:");
        root.ShouldContain("trigger-docker-proxy-pipeline:");
        root.ShouldContain("trigger-docker-system-pipeline:");
        root.ShouldContain("RUN_DOTNET_UNIT_PIPELINE");
        root.ShouldContain("RUN_DOTNET_INTEGRATION_PIPELINE");
        root.ShouldContain("RUN_DOTNET_SQL_PIPELINE");
        root.ShouldContain("RUN_DOCKER_DIRECT_PIPELINE");
        root.ShouldContain("RUN_DOCKER_PROXY_PIPELINE");
        root.ShouldContain("RUN_DOCKER_SYSTEM_PIPELINE");
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
