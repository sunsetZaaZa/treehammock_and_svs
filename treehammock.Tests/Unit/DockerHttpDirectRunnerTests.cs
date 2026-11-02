using Shouldly;

namespace treehammock.Tests.Unit;

public class DockerHttpDirectRunnerTests
{
    [Fact]
    public void Compose_stack_defines_direct_http_contract_test_runner_service()
    {
        string compose = File.ReadAllText(ProjectFile("docker-compose.integration.yml"));

        compose.ShouldContain("  http-contract-tests-direct:");
        compose.ShouldContain("image: node:22-alpine");
        compose.ShouldContain("profiles: [\"http\"]");
        compose.ShouldContain("api:");
        compose.ShouldContain("condition: service_started");
        compose.ShouldContain("TREEHAMMOCK_BASE_URL: http://api:5001");
        compose.ShouldContain("/work/eng/compose-http-proof.mjs");
        compose.ShouldContain("./artifacts/compose-proof:/reports");
        string runner = File.ReadAllText(ProjectFile("eng", "compose-http-proof.mjs"));
        runner.ShouldContain("'npm',['install'");
        runner.ShouldContain("'--bail','--reporter-json'");
        runner.ShouldContain("validateReport(report,expected)");

    }

    [Fact]
    public void Direct_http_contract_scripts_run_profiled_compose_runner()
    {
        File.Exists(ProjectFile("eng", "docker-http-contracts-direct.sh")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "docker-http-contracts-direct.ps1")).ShouldBeTrue();

        string bashScript = File.ReadAllText(ProjectFile("eng", "docker-http-contracts-direct.sh"));
        string powershellScript = File.ReadAllText(ProjectFile("eng", "docker-http-contracts-direct.ps1"));

        bashScript.ShouldContain("./eng/check-locks.sh");
        bashScript.ShouldContain("docker compose");
        bashScript.ShouldContain("-f docker-compose.integration.yml");
        bashScript.ShouldContain("--profile http");
        bashScript.ShouldContain("run --rm --build");
        bashScript.ShouldContain("http-contract-tests-direct");

        powershellScript.ShouldContain("./eng/check-locks.ps1");
        powershellScript.ShouldContain("-FilePath 'docker' -Arguments (@('compose'");
        powershellScript.ShouldContain("'-f', 'docker-compose.integration.yml'");
        powershellScript.ShouldContain("'--profile', 'http'");
        powershellScript.ShouldContain("'run', '--rm', '--build'");
        powershellScript.ShouldContain("http-contract-tests-direct");
    }

    [Fact]
    public void Bruno_direct_collection_targets_health_endpoints_through_api_service()
    {
        File.Exists(ProjectFile("tests", "http", "bruno", "treehammock", "bruno.json")).ShouldBeTrue();
        File.Exists(ProjectFile("tests", "http", "bruno", "treehammock", "environments", "docker-direct.bru")).ShouldBeTrue();
        File.Exists(ProjectFile("tests", "http", "bruno", "treehammock", "health", "live.bru")).ShouldBeTrue();
        File.Exists(ProjectFile("tests", "http", "bruno", "treehammock", "health", "ready.bru")).ShouldBeTrue();

        string environment = File.ReadAllText(ProjectFile("tests", "http", "bruno", "treehammock", "environments", "docker-direct.bru"));
        string live = File.ReadAllText(ProjectFile("tests", "http", "bruno", "treehammock", "health", "live.bru"));
        string ready = File.ReadAllText(ProjectFile("tests", "http", "bruno", "treehammock", "health", "ready.bru"));

        environment.ShouldContain("baseUrl: http://api:5001");
        live.ShouldContain("url: {{baseUrl}}/health/live");
        live.ShouldContain("expect(res.getStatus()).to.equal(200)");
        live.ShouldContain("expect(body.status).to.equal(\"live\")");
        ready.ShouldContain("url: {{baseUrl}}/health/ready");
        ready.ShouldContain("expect(res.getStatus()).to.equal(200)");
        ready.ShouldContain("expect(body.status).to.equal(\"ready\")");
    }

    [Fact]
    public void Docker_down_includes_http_profile_for_runner_cleanup()
    {
        string bashScript = File.ReadAllText(ProjectFile("eng", "docker-down.sh"));
        string powershellScript = File.ReadAllText(ProjectFile("eng", "docker-down.ps1"));

        bashScript.ShouldContain("--profile http");
        powershellScript.ShouldContain("'--profile', 'http'");
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
