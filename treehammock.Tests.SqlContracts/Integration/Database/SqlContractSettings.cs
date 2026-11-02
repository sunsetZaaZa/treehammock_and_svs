namespace treehammock.Tests.Integration.Database;

internal static class DeferredSqlProcedureContractSettings
{
    public const string EnableDeferredSqlContractsEnvironmentVariable = "TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS";
    public const string ConnectionStringEnvironmentVariable = "TREEHAMMOCK_DB_CONTRACT_CONNECTION";

    public static string SkipReason =>
        $"SQL contract tests require a disposable PostgreSQL database. Set {EnableDeferredSqlContractsEnvironmentVariable}=true and {ConnectionStringEnvironmentVariable} to run them.";

    public static string? ConnectionString =>
        Environment.GetEnvironmentVariable(ConnectionStringEnvironmentVariable);

    public static bool ShouldRun()
    {
        string? enabled = Environment.GetEnvironmentVariable(EnableDeferredSqlContractsEnvironmentVariable);
        if (!string.Equals(enabled, "true", StringComparison.OrdinalIgnoreCase) && enabled != "1")
        {
            return false;
        }

        return !string.IsNullOrWhiteSpace(ConnectionString);
    }
}
