using System.Text.RegularExpressions;
using Shouldly;

namespace treehammock.Tests.Unit;

public class SessionSqlConcurrencyContractTests
{
    [Fact]
    public void Set_session_locks_account_row_before_mutating_sessions()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        string body = FunctionBody(sql, "set_session");

        body.ShouldContain("for update");
        Regex.IsMatch(
                body,
                @"select\s+a\.cut_off\s+into\s+currentAccountCutOff\s+from\s+accounts\s+a\s+where\s+a\.account_id\s*=\s*p_accountId\s+and\s+a\.security_stamp\s*=\s*p_accountSecurityStamp\s+for\s+update\s*;",
                RegexOptions.IgnoreCase | RegexOptions.Singleline)
            .ShouldBeTrue("set_session must lock the account row before expiring old sessions or inserting the new one.");

        int accountLockIndex = body.IndexOf("for update", StringComparison.OrdinalIgnoreCase);
        int sessionUpdateIndex = body.IndexOf("update sessions", StringComparison.OrdinalIgnoreCase);
        int sessionInsertIndex = body.IndexOf("insert into sessions", StringComparison.OrdinalIgnoreCase);

        accountLockIndex.ShouldBeGreaterThanOrEqualTo(0);
        accountLockIndex.ShouldBeLessThan(sessionUpdateIndex);
        accountLockIndex.ShouldBeLessThan(sessionInsertIndex);
    }

    [Fact]
    public void Rotate_active_session_locks_account_before_old_session_row()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        string body = FunctionBody(sql, "rotate_active_session");

        Regex.IsMatch(
                body,
                @"select\s+a\.cut_off\s+into\s+currentAccountCutOff\s+from\s+accounts\s+a\s+where\s+a\.account_id\s*=\s*p_accountId\s+and\s+a\.security_stamp\s*=\s*p_accountSecurityStamp\s+for\s+update\s*;",
                RegexOptions.IgnoreCase | RegexOptions.Singleline)
            .ShouldBeTrue("rotate_active_session must use the same account-scoped serialization lock as direct login.");

        int accountLockIndex = body.IndexOf("from accounts a", StringComparison.OrdinalIgnoreCase);
        int sessionLockIndex = body.IndexOf("from sessions s", StringComparison.OrdinalIgnoreCase);
        int sessionInsertIndex = body.IndexOf("insert into sessions", StringComparison.OrdinalIgnoreCase);

        accountLockIndex.ShouldBeGreaterThanOrEqualTo(0);
        sessionLockIndex.ShouldBeGreaterThanOrEqualTo(0);
        accountLockIndex.ShouldBeLessThan(sessionLockIndex, "Rotation should acquire the account lock before locking the old session row to avoid direct-login/refresh deadlock order inversions.");
        accountLockIndex.ShouldBeLessThan(sessionInsertIndex);
    }
    private static string FunctionBody(string sql, string functionName)
    {
        Match match = Regex.Match(
            sql,
            $@"create\s+or\s+replace\s+function\s+{Regex.Escape(functionName)}\s*\(.*?\n\$\$;",
            RegexOptions.IgnoreCase | RegexOptions.Singleline);

        match.Success.ShouldBeTrue($"Could not find SQL function '{functionName}'.");
        return match.Value;
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
