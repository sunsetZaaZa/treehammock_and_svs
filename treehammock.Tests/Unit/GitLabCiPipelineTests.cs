using Shouldly;

namespace treehammock.Tests.Unit;

public class GitLabCiPipelineTests
{
    [Fact]
    public void Root_gitlab_pipeline_dispatches_validation_and_release_child_pipelines()
    {
        string root = File.ReadAllText(ProjectFile(".gitlab-ci.yml"));

        root.ShouldContain("stages:");
        root.ShouldContain("  - dispatch");
        root.ShouldContain("trigger-dotnet-unit-pipeline:");
        root.ShouldContain("trigger-dotnet-integration-pipeline:");
        root.ShouldContain("trigger-dotnet-sql-pipeline:");
        root.ShouldContain("trigger-docker-direct-pipeline:");
        root.ShouldContain("trigger-docker-proxy-pipeline:");
        root.ShouldContain("trigger-docker-system-pipeline:");
        root.ShouldContain("trigger-release-pipeline:");
        root.ShouldContain("local: .gitlab/ci/pipelines/dotnet-unit.yml");
        root.ShouldContain("local: .gitlab/ci/pipelines/dotnet-integration.yml");
        root.ShouldContain("local: .gitlab/ci/pipelines/dotnet-sql.yml");
        root.ShouldContain("local: .gitlab/ci/pipelines/docker-direct.yml");
        root.ShouldContain("local: .gitlab/ci/pipelines/docker-proxy.yml");
        root.ShouldContain("local: .gitlab/ci/pipelines/docker-system.yml");
        root.ShouldContain("local: .gitlab/ci/pipelines/release.yml");
        root.ShouldContain("strategy: depend");
        root.ShouldContain("pipeline_variables: true");

        string legacyPipelinePrefix = string.Concat("CONTACT", "RAPTOR", "_PIPELINE");
        root.ShouldNotContain($"{legacyPipelinePrefix} ==");
        root.ShouldNotContain($"{legacyPipelinePrefix} =~");
        root.ShouldNotContain("RUN_SQL_CONTRACTS");
        root.ShouldNotContain("RUN_DOCKER_INTEGRATION");
    }

    [Fact]
    public void Each_child_pipeline_has_its_own_explicit_trigger_variable()
    {
        string root = File.ReadAllText(ProjectFile(".gitlab-ci.yml"));

        PipelineJob(root, "trigger-dotnet-unit-pipeline").ShouldContain("RUN_DOTNET_UNIT_PIPELINE == \"true\"");
        PipelineJob(root, "trigger-dotnet-integration-pipeline").ShouldContain("RUN_DOTNET_INTEGRATION_PIPELINE == \"true\"");
        PipelineJob(root, "trigger-dotnet-integration-pipeline").ShouldContain("$CI_PIPELINE_SOURCE == \"merge_request_event\"");
        PipelineJob(root, "trigger-dotnet-sql-pipeline").ShouldContain("RUN_DOTNET_SQL_PIPELINE == \"true\"");
        PipelineJob(root, "trigger-docker-direct-pipeline").ShouldContain("RUN_DOCKER_DIRECT_PIPELINE == \"true\"");
        PipelineJob(root, "trigger-docker-proxy-pipeline").ShouldContain("RUN_DOCKER_PROXY_PIPELINE == \"true\"");
        PipelineJob(root, "trigger-docker-system-pipeline").ShouldContain("RUN_DOCKER_SYSTEM_PIPELINE == \"true\"");
        PipelineJob(root, "trigger-release-pipeline").ShouldContain("RUN_RELEASE_PIPELINE == \"true\"");
        PipelineJob(root, "trigger-release-pipeline").ShouldContain("$CI_COMMIT_TAG =~ /^v");

        root.ShouldContain("RUN_ALL_TREEHAMMOCK_PIPELINES == \"true\"");
        root.ShouldContain("$CI_PIPELINE_SOURCE == \"web\"");
    }

    [Fact]
    public void Dotnet_unit_child_pipeline_runs_only_unit_test_namespace()
    {
        string child = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "dotnet-unit.yml"));
        string unitScript = File.ReadAllText(ProjectFile("eng", "dotnet-unit-tests.sh"));

        child.ShouldContain("dotnet-unit-tests:");
        child.ShouldContain("image: mcr.microsoft.com/dotnet/sdk:8.0");
        child.ShouldContain("stage: unit");
        child.ShouldContain("./eng/check-locks.sh");
        child.ShouldContain("./eng/dotnet-unit-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        child.ShouldContain("**/treehammock-unit-tests.trx");
        child.ShouldContain("$CI_PIPELINE_SOURCE == \"parent_pipeline\"");

        unitScript.ShouldContain("treehammock.Tests/treehammock.Tests.csproj");
        unitScript.ShouldContain("FullyQualifiedName~treehammock.Tests.Unit");
        unitScript.ShouldNotContain("treehammock.Tests.Integration");
        unitScript.ShouldNotContain("Category!=DeferredSqlProcedureContract");

        child.ShouldNotContain("postgres:16");
        child.ShouldNotContain("dragonfly");
        child.ShouldNotContain("haproxy");
        child.ShouldNotContain("docker compose");
    }

    [Fact]
    public void Dotnet_integration_child_pipeline_runs_only_in_process_integration_namespace()
    {
        string child = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "dotnet-integration.yml"));
        string integrationScript = File.ReadAllText(ProjectFile("eng", "dotnet-integration-tests.sh"));

        child.ShouldContain("dotnet-integration-tests:");
        child.ShouldContain("image: mcr.microsoft.com/dotnet/sdk:8.0");
        child.ShouldContain("stage: integration");
        child.ShouldContain("./eng/check-locks.sh");
        child.ShouldContain("./eng/dotnet-integration-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        child.ShouldContain("**/treehammock-integration-tests.trx");
        child.ShouldContain("$CI_PIPELINE_SOURCE == \"parent_pipeline\"");

        integrationScript.ShouldContain("treehammock.Tests/treehammock.Tests.csproj");
        integrationScript.ShouldContain("FullyQualifiedName~treehammock.Tests.Integration");
        integrationScript.ShouldNotContain("treehammock.Tests.Unit");
        integrationScript.ShouldNotContain("treehammock.Tests.SqlContracts");

        child.ShouldNotContain("postgres:16");
        child.ShouldNotContain("docker compose");
    }

    [Fact]
    public void Dotnet_sql_child_pipeline_runs_project_tests_with_disposable_postgres()
    {
        string child = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "dotnet-sql.yml"));

        child.ShouldContain("dotnet-sql-contract-tests:");
        child.ShouldContain("image: mcr.microsoft.com/dotnet/sdk:8.0");
        child.ShouldContain("stage: sql");
        child.ShouldContain("postgres:16");
        child.ShouldContain("POSTGRES_DB: treehammock_contract");
        child.ShouldContain("TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS: \"true\"");
        child.ShouldContain("TREEHAMMOCK_DB_CONTRACT_CONNECTION: \"Host=postgres;Port=5432;Database=treehammock_contract;Username=postgres;Password=postgres\"");
        child.ShouldContain("pg_isready");
        child.ShouldContain("./eng/sql-contracts.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        child.ShouldContain("$CI_PIPELINE_SOURCE == \"parent_pipeline\"");
    }

    [Fact]
    public void Docker_system_child_pipeline_runs_full_compose_stack_through_haproxy()
    {
        string child = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "docker-system.yml"));

        child.ShouldContain("docker-system-stack-tests:");
        child.ShouldContain("image: docker:27-cli");
        child.ShouldContain("docker:27-dind");
        child.ShouldContain("DOCKER_BUILDKIT: \"1\"");
        child.ShouldContain("stage: system");
        child.ShouldContain("docker compose version");
        child.ShouldContain("./eng/docker-system-stack-tests.sh");
        child.ShouldContain("docker-compose.integration.yml");
        child.ShouldContain("docker-compose.api-proxy.yml");
        child.ShouldContain("docker-compose.ci-system.yml");
        child.ShouldContain("treehammock-system-tests.trx");
        child.ShouldContain("treehammock-system-stack.log");
        child.ShouldContain("$CI_PIPELINE_SOURCE == \"parent_pipeline\"");
    }

    [Fact]
    public void Docker_context_keeps_gitlab_pipeline_files_available_for_contract_tests()
    {
        string dockerIgnore = File.ReadAllText(ProjectFile(".dockerignore"));

        dockerIgnore.ShouldContain("!.gitlab-ci.yml");
        dockerIgnore.ShouldNotContain(string.Concat(".git", "hub"));
    }

    private static string PipelineJob(string pipeline, string jobName)
    {
        string startMarker = $"\n{jobName}:";
        int start = pipeline.IndexOf(startMarker, StringComparison.Ordinal);
        if (start < 0 && pipeline.StartsWith($"{jobName}:", StringComparison.Ordinal))
        {
            start = 0;
        }

        start.ShouldBeGreaterThanOrEqualTo(0, $"Pipeline job was not found: {jobName}");

        int searchStart = start + startMarker.Length;
        int nextJob = FindNextTopLevelJob(pipeline, searchStart);
        return nextJob >= 0 ? pipeline.Substring(start, nextJob - start) : pipeline.Substring(start);
    }

    private static int FindNextTopLevelJob(string pipeline, int start)
    {
        string[] reservedTopLevelKeys =
        [
            "stages:",
            "workflow:",
            "variables:",
            "default:",
            "include:"
        ];

        for (int index = pipeline.IndexOf('\n', start); index >= 0; index = pipeline.IndexOf('\n', index + 1))
        {
            int lineStart = index + 1;
            int lineEnd = pipeline.IndexOf('\n', lineStart);
            if (lineEnd < 0)
            {
                lineEnd = pipeline.Length;
            }

            string line = pipeline.Substring(lineStart, lineEnd - lineStart);
            if (string.IsNullOrWhiteSpace(line) || char.IsWhiteSpace(line[0]))
            {
                continue;
            }

            if (line.EndsWith(":", StringComparison.Ordinal)
                && !reservedTopLevelKeys.Contains(line, StringComparer.Ordinal))
            {
                return lineStart;
            }
        }

        return -1;
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
