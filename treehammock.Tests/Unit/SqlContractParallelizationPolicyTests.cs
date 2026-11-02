using Shouldly;

namespace treehammock.Tests.Unit;

public class SqlContractParallelizationPolicyTests
{
    [Fact]
    public void Sql_contract_test_assembly_disables_parallelization()
    {
        string assemblyInfo = File.ReadAllText(ProjectFile("treehammock.Tests.SqlContracts", "Properties", "AssemblyInfo.cs"));

        assemblyInfo.ShouldContain("CollectionBehavior");
        assemblyInfo.ShouldContain("DisableTestParallelization = true");
        assemblyInfo.ShouldContain("pg_extension_name_index");
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