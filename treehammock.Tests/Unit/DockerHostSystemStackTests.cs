using Shouldly;

namespace treehammock.Tests.Unit;

public sealed class DockerHostSystemStackTests
{
    [Fact]
    public void Host_system_stack_scripts_run_backend_and_system_tests_on_host_without_mcr_dotnet_images()
    {
        string bashScript = File.ReadAllText(ProjectFile("eng", "docker-host-system-stack-tests.sh"));
        string powershellScript = File.ReadAllText(ProjectFile("eng", "docker-host-system-stack-tests.ps1"));
        string compose = File.ReadAllText(ProjectFile("docker-compose.local-system.yml"));
        string haproxy = File.ReadAllText(ProjectFile("deploy", "haproxy", "haproxy.host-system.cfg"));

        bashScript.ShouldNotContain("mcr.microsoft.com/dotnet");
        powershellScript.ShouldNotContain("mcr.microsoft.com/dotnet");
        bashScript.ShouldContain("eng/test-ownership.py api-start");
        powershellScript.ShouldContain("Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force");
        powershellScript.ShouldContain("-FilePath $selectedHost -Arguments $lockArguments");
        powershellScript.ShouldNotContain("-FilePath 'powershell.exe'");
        powershellScript.ShouldContain("-Stage 'host-api-start' -FilePath $apiPython");
        powershellScript.ShouldContain("treehammock.Tests.System/treehammock.Tests.System.csproj");

        string commandLauncher = File.ReadAllText(ProjectFile("eng", "docker-host-system-stack-tests.cmd"));
        commandLauncher.ShouldContain("-ExecutionPolicy Bypass");
        commandLauncher.ShouldContain("docker-host-system-stack-tests.ps1");
        compose.ShouldContain("haproxy-host");
        compose.ShouldContain("network_mode: host");
        haproxy.ShouldContain("127.0.0.1:5001");
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
