using Shouldly;

namespace treehammock.Tests.Unit;

public class TreehammockEnvironmentContractTests
{
    [Fact]
    public void Sql_gate_scripts_use_treehammock_environment_variables_only()
    {
        string sqlContracts = File.ReadAllText(ProjectFile("eng", "sql-contracts.sh"));
        string releaseProof = File.ReadAllText(ProjectFile("eng", "release-proof.sh"));
        string sqlContractsPowerShell = File.ReadAllText(ProjectFile("eng", "sql-contracts.ps1"));
        string releaseProofPowerShell = File.ReadAllText(ProjectFile("eng", "release-proof.ps1"));

        sqlContracts.ShouldContain("TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS");
        sqlContracts.ShouldContain("TREEHAMMOCK_DB_CONTRACT_CONNECTION");
        releaseProof.ShouldContain("TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS");
        releaseProof.ShouldContain("TREEHAMMOCK_DB_CONTRACT_CONNECTION");
        sqlContractsPowerShell.ShouldContain("TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS");
        sqlContractsPowerShell.ShouldContain("TREEHAMMOCK_DB_CONTRACT_CONNECTION");
        releaseProofPowerShell.ShouldContain("TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS");
        releaseProofPowerShell.ShouldContain("TREEHAMMOCK_DB_CONTRACT_CONNECTION");

        string legacyPrefix = string.Concat("CONTACT", "RAPTOR");
        sqlContracts.ShouldNotContain(legacyPrefix);
        releaseProof.ShouldNotContain(legacyPrefix);
        sqlContractsPowerShell.ShouldNotContain(legacyPrefix);
        releaseProofPowerShell.ShouldNotContain(legacyPrefix);
    }

    [Fact]
    public void Removed_environment_compatibility_helpers_are_not_committed()
    {
        File.Exists(ProjectFile("eng", "treehammock-env.sh")).ShouldBeFalse();
        File.Exists(ProjectFile("eng", "treehammock-env.ps1")).ShouldBeFalse();
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
