using Shouldly;

namespace treehammock.Tests.Unit;

public class TwoFactorEnrollmentLimitContractTests
{
    [Fact]
    public void Canonical_sql_enforces_one_verified_factor_per_method()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        sql.ShouldContain("ux_two_factor_one_verified_email_per_account");
        sql.ShouldContain("where verified = true and method = 1");
        sql.ShouldContain("ux_two_factor_one_verified_sms_per_account");
        sql.ShouldContain("where verified = true and method = 2");
        sql.ShouldContain("ux_two_factor_one_verified_authenticator_app");
        sql.ShouldContain("where verified = true and method = 3 and revoked_at is null");
        sql.ShouldContain("revoked_at timestamp with time zone null");
        sql.ShouldContain("revoked_reason text null");
        sql.ShouldContain("ux_two_factor_one_pending_setup_per_account");

        string authenticatorIndex = Slice(sql, "create unique index if not exists ux_two_factor_one_verified_authenticator_app", "create table if not exists pending_two_factor_sessions");
        authenticatorIndex.ShouldNotContain("now()");
    }

    [Fact]
    public void Begin_twofactor_setup_rejects_existing_verified_method_regardless_of_destination()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        string function = sql[sql.IndexOf("create or replace function cor16_begin_twofactor_setup", StringComparison.Ordinal)..];

        function.ShouldContain("where t.account_id=p_accountId");
        function.ShouldContain("t.method=p_method");
        function.ShouldContain("and t.verified");
        function.ShouldContain("TWO_FACTOR_SETUP_DUPLICATE");
        function.ShouldNotContain("lower(t.email_address) = normalized_email");
        function.ShouldNotContain("t.phone_number = normalized_phone and t.phone_country_code = normalized_phone_country");
    }

    [Fact]
    public void Verify_twofactor_setup_checks_duplicate_method_before_promotion()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        string function = Slice(sql, "create or replace function verify_twofactor_setup", "create or replace function begin_authenticator_app_setup");

        int duplicateCheck = function.IndexOf("TWO_FACTOR_SETUP_DUPLICATE", StringComparison.Ordinal);
        int promotion = function.IndexOf("set verified=true", StringComparison.Ordinal);

        duplicateCheck.ShouldBeGreaterThan(0);
        promotion.ShouldBeGreaterThan(duplicateCheck);
        function.ShouldContain("t.setup_request_id=p_requestId and t.setup_version=p_requestVersion and t.token=p_tokenHash");
        function.ShouldContain("when unique_violation then");
        function.ShouldContain("TWO_FACTOR_SETUP_DUPLICATE");
    }


    [Fact]
    public void Authenticator_setup_sql_rejects_second_active_app_with_stable_revocation_guard()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        string begin = Slice(sql, "create or replace function cor08_authorized_begin_authenticator_app_setup", "create or replace function cor08_authorized_remove_twofactor_method");
        string complete = Slice(sql, "create or replace function complete_authenticator_app_setup_and_rotate_session", "create or replace function cancel_authenticator_app_setup");

        begin.ShouldContain("t.method = 3");
        begin.ShouldContain("t.verified = true");
        begin.ShouldContain("t.revoked_at is null");
        begin.ShouldContain("TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED");
        complete.ShouldContain("t.method = 3");
        complete.ShouldContain("t.verified = true");
        complete.ShouldContain("t.revoked_at is null");
        complete.ShouldContain("TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED");
    }
    private static string Slice(string text, string startMarker, string endMarker)
    {
        int start = text.IndexOf(startMarker, StringComparison.Ordinal);
        start.ShouldBeGreaterThanOrEqualTo(0);
        int end = text.IndexOf(endMarker, start + startMarker.Length, StringComparison.Ordinal);
        end.ShouldBeGreaterThan(start);
        return text[start..end];
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
