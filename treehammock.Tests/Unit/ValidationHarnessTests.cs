using Shouldly;

namespace treehammock.Tests.Unit;

public class ValidationHarnessTests
{
    [Fact]
    public void Validation_harness_files_are_committed()
    {
        File.Exists(ProjectFile("global.json")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "validate.sh")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "validate.ps1")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "sql-contracts.sh")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "sql-contracts.ps1")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "restore-locks.sh")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "restore-locks.ps1")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "check-locks.sh")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "check-locks.ps1")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "build-proof.sh")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "build-proof.ps1")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "release-proof.sh")).ShouldBeTrue();
        File.Exists(ProjectFile("eng", "release-proof.ps1")).ShouldBeTrue();
        File.Exists(ProjectFile(".gitlab-ci.yml")).ShouldBeTrue();
        File.Exists(ProjectFile(".gitlab", "ci", "pipelines", "dotnet-unit.yml")).ShouldBeTrue();
        File.Exists(ProjectFile(".gitlab", "ci", "pipelines", "dotnet-integration.yml")).ShouldBeTrue();
        File.Exists(ProjectFile(".gitlab", "ci", "pipelines", "dotnet-sql.yml")).ShouldBeTrue();
        File.Exists(ProjectFile(".gitlab", "ci", "pipelines", "docker-direct.yml")).ShouldBeTrue();
        File.Exists(ProjectFile(".gitlab", "ci", "pipelines", "docker-proxy.yml")).ShouldBeTrue();
        File.Exists(ProjectFile(".gitlab", "ci", "pipelines", "docker-system.yml")).ShouldBeTrue();
        File.Exists(ProjectFile(".gitlab", "ci", "pipelines", "release.yml")).ShouldBeTrue();
    }

    [Fact]
    public void Default_validation_runs_fast_solution_without_sql_contract_project()
    {
        string bashHarness = File.ReadAllText(ProjectFile("eng", "validate.sh"));
        string powershellHarness = File.ReadAllText(ProjectFile("eng", "validate.ps1"));
        string rootPipeline = File.ReadAllText(ProjectFile(".gitlab-ci.yml"));
        string unitPipeline = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "dotnet-unit.yml"));
        string integrationPipeline = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "dotnet-integration.yml"));
        string sqlPipeline = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "dotnet-sql.yml"));

        bashHarness.ShouldContain("FullyQualifiedName~treehammock.Tests.Unit");
        bashHarness.ShouldContain("FullyQualifiedName~treehammock.Tests.Integration");
        bashHarness.ShouldNotContain("Category!=DeferredSqlProcedureContract");
        powershellHarness.ShouldNotContain("Category!=DeferredSqlProcedureContract");
        unitPipeline.ShouldContain("./eng/dotnet-unit-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        unitPipeline.ShouldContain("treehammock-unit-tests.trx");
        integrationPipeline.ShouldContain("./eng/dotnet-integration-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        integrationPipeline.ShouldContain("treehammock-integration-tests.trx");
        sqlPipeline.ShouldContain("./eng/sql-contracts.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        rootPipeline.ShouldContain("trigger-dotnet-integration-pipeline:");
        rootPipeline.ShouldContain("RUN_DOTNET_INTEGRATION_PIPELINE");
        rootPipeline.ShouldContain("trigger-dotnet-sql-pipeline:");
        rootPipeline.ShouldContain("RUN_DOTNET_SQL_PIPELINE");
        rootPipeline.ShouldContain("trigger-release-pipeline:");
        rootPipeline.ShouldContain("local: .gitlab/ci/pipelines/release.yml");
        rootPipeline.ShouldContain("$CI_COMMIT_TAG =~ /^v");
    }

    [Fact]
    public void Sql_contract_harness_requires_explicit_opt_in_and_disposable_connection()
    {
        string bashHarness = File.ReadAllText(ProjectFile("eng", "sql-contracts.sh"));
        string powershellHarness = File.ReadAllText(ProjectFile("eng", "sql-contracts.ps1"));
        string sqlPipeline = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "dotnet-sql.yml"));

        bashHarness.ShouldContain("TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS");
        bashHarness.ShouldContain("TREEHAMMOCK_DB_CONTRACT_CONNECTION");
        bashHarness.ShouldContain("treehammock.Tests.SqlContracts/treehammock.Tests.SqlContracts.csproj");

        powershellHarness.ShouldContain("TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS");
        powershellHarness.ShouldContain("TREEHAMMOCK_DB_CONTRACT_CONNECTION");
        powershellHarness.ShouldContain("treehammock.Tests.SqlContracts/treehammock.Tests.SqlContracts.csproj");

        sqlPipeline.ShouldContain("postgres:16");
        sqlPipeline.ShouldContain("treehammock_contract");
        sqlPipeline.ShouldContain("TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS: \"true\"");
        sqlPipeline.ShouldContain("treehammock.Tests.SqlContracts");
        sqlPipeline.ShouldContain("TREEHAMMOCK_DB_CONTRACT_CONNECTION");
    }

    [Fact]
    public void Build_proof_and_lock_audit_scripts_are_wired_into_ci_contract()
    {
        string buildProof = File.ReadAllText(ProjectFile("eng", "build-proof.sh"));
        string lockAudit = File.ReadAllText(ProjectFile("eng", "check-locks.sh"));
        string sqlPipeline = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "dotnet-sql.yml"));
        string releaseRoot = File.ReadAllText(ProjectFile(".gitlab-ci.yml"));
        string releasePipeline = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "release.yml"));

        buildProof.ShouldContain("command -v dotnet");
        buildProof.ShouldContain("./eng/validate.sh");
        buildProof.ShouldContain("./eng/sql-contracts.sh");
        lockAudit.ShouldContain("packages.lock.json");
        lockAudit.ShouldContain("--warn-only");
        sqlPipeline.ShouldContain("./eng/check-locks.sh");
        sqlPipeline.ShouldContain("./eng/sql-contracts.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        sqlPipeline.ShouldNotContain("./eng/check-locks.sh --warn-only");
        releaseRoot.ShouldContain("trigger-release-pipeline:");
        releaseRoot.ShouldContain("local: .gitlab/ci/pipelines/release.yml");
        releasePipeline.ShouldContain("./eng/dotnet-unit-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        releasePipeline.ShouldContain("./eng/dotnet-integration-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        releasePipeline.ShouldContain("./eng/sql-contracts.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        releasePipeline.ShouldContain("TREEHAMMOCK_DB_CONTRACT_CONNECTION");
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
