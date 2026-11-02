using Shouldly;

namespace treehammock.Tests.Unit;

public class DockerDeveloperWrapperScriptsTests
{
    [Fact]
    public void Docker_developer_wrapper_scripts_exist_for_every_supported_mode()
    {
        string[] scriptNames =
        [
            "docker-help",
            "docker-unit-tests",
            "docker-api-image",
            "docker-postgres-up",
            "docker-dragonfly-up",
            "docker-infra-up",
            "docker-api-direct-up",
            "docker-api-proxy-up",
            "docker-api-proxy-scale",
            "docker-all-runtime-up",
            "docker-sql-contracts",
            "docker-http-contracts-direct",
            "docker-http-contracts-proxy",
            "docker-system-stack-tests",
            "docker-host-system-stack-tests",
            "docker-all-tests",
            "docker-down"
        ];

        foreach (string scriptName in scriptNames)
        {
            File.Exists(ProjectFile("eng", $"{scriptName}.sh")).ShouldBeTrue($"Missing Bash wrapper: {scriptName}.sh");
            File.Exists(ProjectFile("eng", $"{scriptName}.ps1")).ShouldBeTrue($"Missing PowerShell wrapper: {scriptName}.ps1");
        }
    }

    [Fact]
    public void Docker_help_scripts_document_selectable_runtime_and_test_modes()
    {
        string bashHelp = File.ReadAllText(ProjectFile("eng", "docker-help.sh"));
        string powershellHelp = File.ReadAllText(ProjectFile("eng", "docker-help.ps1"));

        foreach (string help in new[] { bashHelp, powershellHelp })
        {
            help.ShouldContain("./eng/restore-locks");
            help.ShouldContain("docker-postgres-up");
            help.ShouldContain("docker-dragonfly-up");
            help.ShouldContain("docker-infra-up");
            help.ShouldContain("docker-api-direct-up");
            help.ShouldContain("docker-api-proxy-up");
            help.ShouldContain("docker-api-proxy-scale");
            help.ShouldContain("docker-all-runtime-up");
            help.ShouldContain("docker-sql-contracts");
            help.ShouldContain("docker-http-contracts-direct");
            help.ShouldContain("docker-http-contracts-proxy");
            help.ShouldContain("docker-system-stack-tests");
            help.ShouldContain("docker-host-system-stack-tests");
            help.ShouldContain("docker-all-tests");
            help.ShouldContain("docker-down");
        }
    }

    [Fact]
    public void Docker_all_runtime_scripts_start_every_long_running_service_through_haproxy_mode()
    {
        string bashScript = File.ReadAllText(ProjectFile("eng", "docker-all-runtime-up.sh"));
        string powershellScript = File.ReadAllText(ProjectFile("eng", "docker-all-runtime-up.ps1"));

        bashScript.ShouldContain("./eng/check-locks.sh");
        bashScript.ShouldContain("-f docker-compose.integration.yml");
        bashScript.ShouldContain("-f docker-compose.api-proxy.yml");
        bashScript.ShouldContain("--profile proxy");
        bashScript.ShouldContain("up --build");
        bashScript.ShouldContain("postgres dragonfly api haproxy");

        powershellScript.ShouldContain("./eng/check-locks.ps1");
        powershellScript.ShouldContain("'-f', 'docker-compose.integration.yml'");
        powershellScript.ShouldContain("'-f', 'docker-compose.api-proxy.yml'");
        powershellScript.ShouldContain("'--profile', 'proxy'");
        powershellScript.ShouldContain("'up', '--build'");
        powershellScript.ShouldContain("'postgres', 'dragonfly', 'api', 'haproxy'");
    }

    [Fact]
    public void Docker_all_tests_scripts_run_every_docker_backed_validation_lane_in_order()
    {
        string bashScript = File.ReadAllText(ProjectFile("eng", "docker-all-tests.sh"));
        string powershellScript = File.ReadAllText(ProjectFile("eng", "docker-all-tests.ps1"));

        bashScript.ShouldContain("./eng/docker-unit-tests.sh");
        bashScript.ShouldContain("./eng/docker-sql-contracts.sh");
        bashScript.ShouldContain("./eng/docker-http-contracts-direct.sh");
        bashScript.ShouldContain("./eng/docker-http-contracts-proxy.sh");
        bashScript.ShouldContain("./eng/docker-system-stack-tests.sh");

        powershellScript.ShouldContain("./eng/docker-unit-tests.ps1");
        powershellScript.ShouldContain("./eng/docker-sql-contracts.ps1");
        powershellScript.ShouldContain("./eng/docker-http-contracts-direct.ps1");
        powershellScript.ShouldContain("./eng/docker-http-contracts-proxy.ps1");
        powershellScript.ShouldContain("./eng/docker-system-stack-tests.ps1");
    }

    [Fact]
    public void Docker_wrappers_are_fail_fast_scripts()
    {
        foreach (string script in Directory.GetFiles(ProjectFile("eng"), "docker-*.sh"))
        {
            string content = File.ReadAllText(script);
            content.ShouldStartWith("#!/usr/bin/env bash");
            content.ShouldContain("set -euo pipefail");
        }

        foreach (string script in Directory.GetFiles(ProjectFile("eng"), "docker-*.ps1"))
        {
            string content = File.ReadAllText(script);
            content.ShouldContain("Set-StrictMode -Version Latest");
            content.ShouldContain("$ErrorActionPreference = 'Stop'");
        }
    }


    [Fact]
    public void Docker_bash_wrappers_use_cli_selector_to_avoid_podman_shim_on_windows()
    {
        string selector = File.ReadAllText(ProjectFile("eng", "docker-cli.sh"));

        selector.ShouldContain("docker.exe");
        selector.ShouldContain("Podman emulation");
        selector.ShouldContain("TREEHAMMOCK_DOCKER_CLI");
        selector.ShouldContain("TREEHAMMOCK_DOCKER_SELECTED");
        selector.ShouldContain("treehammock_pull_with_retry");
        selector.ShouldContain("TREEHAMMOCK_SKIP_DOCKER_PULLS");
        selector.ShouldContain("TREEHAMMOCK_DOTNET_SDK_IMAGE");
        selector.ShouldContain("TREEHAMMOCK_DOTNET_RUNTIME_IMAGE");
        selector.ShouldContain("mcr.microsoft.com/dotnet/aspnet:8.0");
        selector.ShouldContain("treehammock_pull_dotnet_dockerfile_images");
        selector.ShouldContain("TREEHAMMOCK_ALLOW_SDK_RUNTIME_FALLBACK");
        selector.ShouldContain("TREEHAMMOCK_DISABLE_SDK_RUNTIME_FALLBACK");
        selector.ShouldContain("Using the SDK image as the final API base");
        selector.ShouldContain("treehammock_write_compose_image_override");
        selector.ShouldContain("TREEHAMMOCK_DOCKER_COMPOSE_IMAGE_OVERRIDE_FILE");
        selector.ShouldNotContain(string.Concat("CONTACT", "RAPTOR"));

        string[] dockerBackedBashScripts =
        [
            "docker-all-runtime-up.sh",
            "docker-api-direct-up.sh",
            "docker-api-image.sh",
            "docker-api-proxy-scale.sh",
            "docker-api-proxy-up.sh",
            "docker-down.sh",
            "docker-dragonfly-up.sh",
            "docker-host-system-stack-tests.sh",
            "docker-http-contracts-direct.sh",
            "docker-http-contracts-proxy.sh",
            "docker-infra-up.sh",
            "docker-postgres-up.sh",
            "docker-sql-contracts.sh",
            "docker-system-stack-tests.sh",
            "docker-unit-tests.sh"
        ];

        foreach (string scriptName in dockerBackedBashScripts)
        {
            string script = File.ReadAllText(ProjectFile("eng", scriptName));
            script.ShouldContain("source ./eng/docker-cli.sh");
        }

        string systemStackScript = File.ReadAllText(ProjectFile("eng", "docker-system-stack-tests.sh"));
        systemStackScript.ShouldContain("treehammock_pull_with_retry");
        systemStackScript.ShouldContain("treehammock_pull_dotnet_dockerfile_images");
        systemStackScript.ShouldContain("compose_image_override=\"$(treehammock_write_compose_image_override)\"");
        systemStackScript.ShouldContain("-f \"$compose_image_override\"");
        string hostSystemStackScript = File.ReadAllText(ProjectFile("eng", "docker-host-system-stack-tests.sh"));
        hostSystemStackScript.ShouldContain("treehammock_pull_with_retry");
        hostSystemStackScript.ShouldContain("wait_for_system_readiness()");
        hostSystemStackScript.ShouldContain("eng/test-ownership.py api-ready");

        string compose = File.ReadAllText(ProjectFile("docker-compose.integration.yml"));
        compose.ShouldContain("DOTNET_SDK_IMAGE: ${TREEHAMMOCK_DOTNET_SDK_IMAGE:-mcr.microsoft.com/dotnet/sdk:8.0}");
        compose.ShouldContain("DOTNET_RUNTIME_IMAGE: ${TREEHAMMOCK_DOTNET_RUNTIME_IMAGE:-mcr.microsoft.com/dotnet/aspnet:8.0}");

        File.ReadAllText(ProjectFile("docker-compose.ci-system.yml"))
            .ShouldContain("image: ${TREEHAMMOCK_DOTNET_SDK_IMAGE:-mcr.microsoft.com/dotnet/sdk:8.0}");

        File.ReadAllText(ProjectFile("eng", "docker-api-image.sh"))
            .ShouldContain("--build-arg \"DOTNET_RUNTIME_IMAGE=${TREEHAMMOCK_DOTNET_RUNTIME_IMAGE}\"");
    }


    [Fact]
    public void Dockerfile_shares_nuget_cache_mount_across_restore_build_test_and_publish_stages()
    {
        string dockerfile = File.ReadAllText(ProjectFile("Dockerfile"));

        dockerfile.ShouldContain("RUN --mount=type=cache,id=treehammock-nuget,target=/root/.nuget/packages");
        dockerfile.ShouldContain("dotnet restore treehammock.sln --locked-mode");
        dockerfile.ShouldContain("dotnet build treehammock.sln");
        dockerfile.ShouldContain("dotnet test treehammock.Tests/treehammock.Tests.csproj");
        dockerfile.ShouldContain("dotnet publish treehammock.csproj");

        int publishStage = dockerfile.IndexOf("FROM unit-test AS publish", StringComparison.Ordinal);
        publishStage.ShouldBeGreaterThanOrEqualTo(0);
        string publishSection = dockerfile[publishStage..];

        publishSection.ShouldContain("RUN --mount=type=cache,id=treehammock-nuget,target=/root/.nuget/packages");
        publishSection.ShouldContain("dotnet publish treehammock.csproj");
        publishSection.ShouldContain("--no-build");
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
