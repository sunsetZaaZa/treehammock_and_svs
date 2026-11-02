using Shouldly;

namespace treehammock.Tests.Unit;

public class DockerSqlContractRunnerTests
{
    [Fact]
    public void Compose_stack_defines_sql_contract_test_runner_service()
    {
        string compose = File.ReadAllText(ProjectFile("docker-compose.integration.yml"));

        compose.ShouldContain("  sql-contract-tests:");
        compose.ShouldContain("target: build");
        compose.ShouldContain("profiles: [\"sql\"]");
        compose.ShouldContain("postgres:");
        compose.ShouldContain("condition: service_healthy");
        compose.ShouldContain("TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS: \"true\"");
        compose.ShouldContain("TREEHAMMOCK_DB_CONTRACT_CONNECTION: Host=postgres;Port=5432;Database=treehammock;Username=treehammock;Password=${TREEHAMMOCK_FIXTURE_DB_PASSWORD:?Initialize fixture credentials}");
        compose.ShouldContain("command: [\"./eng/sql-contracts.sh\", \"--configuration\", \"Release\", \"--locked-restore\"]");
    }

    [Fact]
    public void Docker_sql_contract_scripts_run_profiled_compose_runner()
    {
        File.Exists(ProjectFile("eng", "docker-sql-contracts.sh")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "docker-sql-contracts.ps1")).ShouldBeTrue();

        string bashScript = File.ReadAllText(ProjectFile("eng", "docker-sql-contracts.sh"));
        string powershellScript = File.ReadAllText(ProjectFile("eng", "docker-sql-contracts.ps1"));

        bashScript.ShouldContain("./eng/check-locks.sh");
        bashScript.ShouldContain("docker compose");
        bashScript.ShouldContain("-f docker-compose.integration.yml");
        bashScript.ShouldContain("--profile sql");
        bashScript.ShouldContain("run --rm --build");
        bashScript.ShouldContain("sql-contract-tests");

        powershellScript.ShouldContain("./eng/check-locks.ps1");
        powershellScript.ShouldContain("-FilePath 'docker' -Arguments (@('compose'");
        powershellScript.ShouldContain("'-f', 'docker-compose.integration.yml'");
        powershellScript.ShouldContain("'--profile', 'sql'");
        powershellScript.ShouldContain("'run', '--rm', '--build'");
        powershellScript.ShouldContain("sql-contract-tests");
    }

    [Fact]
    public void Docker_down_includes_sql_profile_for_runner_cleanup()
    {
        string bashScript = File.ReadAllText(ProjectFile("eng", "docker-down.sh"));
        string powershellScript = File.ReadAllText(ProjectFile("eng", "docker-down.ps1"));

        bashScript.ShouldContain("--profile sql");
        powershellScript.ShouldContain("'--profile', 'sql'");
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
