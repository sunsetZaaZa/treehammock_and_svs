using System.Text.RegularExpressions;
using Shouldly;

namespace treehammock.Tests.Unit;

public class PasswordResetSqlSchemaContractTests
{
    [Fact]
    public void Password_reset_schema_is_account_bound_and_single_active_per_account()
    {
        string sql = BaselineSql();

        sql.ShouldContain("create table if not exists password_reset_requests");
        sql.ShouldContain("password_reset_request_id uuid primary key");
        sql.ShouldContain("account_id uuid not null references accounts(account_id) on delete cascade");
        sql.ShouldContain("create unique index if not exists ux_password_reset_requests_one_active_per_account");
        sql.ShouldContain("where consumed_at is null");
        sql.ShouldContain("and cancelled_at is null");
    }


    [Fact]
    public void Password_reset_sql_persists_pending_reset_two_factor_sessions()
    {
        string sql = BaselineSql();

        sql.ShouldContain("create table if not exists pending_password_reset_sessions");
        sql.ShouldContain("reset_access_token_hash text primary key");
        sql.ShouldContain("password_reset_request_id uuid not null unique references password_reset_requests(password_reset_request_id) on delete cascade");
        sql.ShouldContain("available_configurations smallint[] not null default array[]::smallint[]");
        sql.ShouldContain("selected_two_factor_configuration smallint null");
        sql.ShouldContain("required_methods smallint[] not null default array[]::smallint[]");
        sql.ShouldContain("completed_methods smallint[] not null default array[]::smallint[]");
        sql.ShouldContain("current_expected_method smallint null");
        sql.ShouldContain("challenge_code_hash text null");
        sql.ShouldContain("two_factor_completed_at timestamp with time zone null");
        sql.ShouldContain("create or replace function transition_pending_password_reset_session");
        sql.ShouldContain("create or replace function get_pending_password_reset_session");
        sql.ShouldContain("create or replace function revoke_pending_password_reset_session");
        sql.ShouldContain("create or replace function revoke_pending_password_reset_sessions_for_account");
    }

    [Fact]
    public void Two_factor_schema_contains_protected_authenticator_app_secret_columns()
    {
        string sql = BaselineSql();

        sql.ShouldContain("totp_secret_ciphertext bytea null");
        sql.ShouldContain("totp_secret_nonce bytea null");
        sql.ShouldContain("totp_secret_tag bytea null");
        sql.ShouldContain("totp_secret_version integer null");
        sql.ShouldContain("totp_last_used_step bigint null");
        sql.ShouldNotContain("totp_secret text");
    }

    [Fact]
    public void Password_reset_schema_allows_delivery_channels_only()
    {
        string sql = BaselineSql();

        sql.ShouldContain("method in ('sms', 'email')");
        sql.ShouldContain("method = 'sms' and delivery_channel = 'sms' and requires_key_code = true and requires_totp = false");
        sql.ShouldContain("method = 'email' and delivery_channel = 'email' and requires_key_code = true and requires_totp = false");
        sql.ShouldNotContain("'sms_code'");
        sql.ShouldNotContain("'email_code'");
        sql.ShouldNotContain("'sms_code_totp'");
        sql.ShouldNotContain("'email_code_totp'");
        sql.ShouldNotContain("'authenticator_app_totp'");
        sql.ShouldNotContain("method = 'authenticator_app_totp'");
        sql.ShouldNotContain("or v_has_authenticator");
        sql.ShouldNotContain("or not v_has_authenticator");
        sql.ShouldContain("else\n        return query select false, 'PASSWORD_RESET_DELIVERY_CHANNEL_INELIGIBLE'");
    }

    [Fact]
    public void Password_reset_expiration_and_attempts_are_backend_supplied()
    {
        string sql = BaselineSql();

        sql.ShouldContain("expires_at timestamp with time zone not null");
        sql.ShouldContain("max_attempts integer not null");
        sql.ShouldContain("constraint ck_password_reset_expiration check (expires_at > created_at)");
        sql.ShouldNotContain("expires_at timestamp with time zone not null default now() + interval");
        sql.ShouldContain("p_expiresAt timestamp with time zone");
        sql.ShouldContain("p_maxAttempts integer");
    }

    [Fact]
    public void Password_reset_sql_surface_contains_required_lifecycle_functions()
    {
        string sql = BaselineSql();
        string[] requiredFunctions =
        [
            "lookup_password_reset_account",
            "register_password_reset_request_rate_limit",
            "cleanup_password_reset_rate_limits",
            "create_password_reset_request",
            "cancel_password_reset_request",
            "get_pending_password_reset_session",
            "transition_pending_password_reset_session",
            "revoke_pending_password_reset_session",
            "revoke_pending_password_reset_sessions_for_account",
            "get_password_reset_request_for_finalize",
            "get_password_reset_totp_enrollment",
            "mark_password_reset_totp_step_used",
            "register_password_reset_failed_attempt",
            "promote_password_reset",
            "cleanup_expired_password_reset_requests"
        ];

        foreach (string functionName in requiredFunctions)
        {
            Regex.IsMatch(sql, $@"create\s+or\s+replace\s+function\s+{functionName}\s*\(", RegexOptions.IgnoreCase)
                .ShouldBeTrue($"Missing SQL lifecycle function {functionName}.");
        }
    }
    [Fact]
    public void Password_reset_lookup_contract_returns_eligibility_without_client_account_id()
    {
        string sql = BaselineSql();

        sql.ShouldContain("create or replace function lookup_password_reset_account");
        sql.ShouldContain("p_identifier text");
        sql.ShouldContain("account_security_stamp uuid");
        sql.ShouldContain("email_verified boolean");
        sql.ShouldContain("sms_verified boolean");
        sql.ShouldContain("authenticator_verified boolean");
        sql.ShouldContain("where lower(a.email_address) = normalized_identifier");
        sql.ShouldContain("or lower(a.username) = normalized_identifier");
        sql.ShouldContain("t.method = 2");
        sql.ShouldContain("t.method = 3");
        sql.ShouldContain("t.totp_secret_ciphertext is not null");
        sql.ShouldContain("t.totp_secret_nonce is not null");
        sql.ShouldContain("t.totp_secret_tag is not null");
    }

    [Fact]
    public void Password_reset_totp_sql_contract_loads_verified_authenticator_app_and_marks_steps_used()
    {
        string sql = BaselineSql();

        sql.ShouldContain("create or replace function get_password_reset_totp_enrollment");
        sql.ShouldContain("p_accountId uuid");
        sql.ShouldContain("p_now timestamp with time zone");
        sql.ShouldContain("t.method = 3");
        sql.ShouldContain("t.verified = true");
        sql.ShouldContain("t.totp_secret_ciphertext is not null");
        sql.ShouldContain("t.totp_secret_nonce is not null");
        sql.ShouldContain("t.totp_secret_tag is not null");
        sql.ShouldContain("totp_last_used_step bigint");

        sql.ShouldContain("create or replace function mark_password_reset_totp_step_used");
        sql.ShouldContain("p_twoFactorIndex bigint");
        sql.ShouldContain("p_timeStep bigint");
        sql.ShouldContain("for update");
        sql.ShouldContain("p_timeStep <= existing_step");
        sql.ShouldContain("TOTP_REPLAY_DETECTED");
        sql.ShouldContain("TOTP_STEP_ACCEPTED");
    }

    [Fact]
    public void Password_reset_promotion_uses_account_password_material_and_security_stamp_without_account_cutoff()
    {
        string sql = BaselineSql();

        sql.ShouldContain("p_hashedPassword bytea");
        sql.ShouldContain("p_saltOne bytea");
        sql.ShouldContain("p_siv bytea");
        sql.ShouldContain("p_nonce bytea");
        sql.ShouldContain("p_newSecurityStamp uuid");
        sql.ShouldContain("security_stamp = p_newSecurityStamp");

        string promoteFunction = Slice(sql, "create or replace function promote_password_reset", "create or replace function cleanup_expired_password_reset_requests");
        promoteFunction.ShouldContain("v_promoted_at := greatest(clock_timestamp(), v_reset.created_at);");
        Regex accountUpdate = new(
            @"update\s+accounts\s+a\s+set(?<body>.*?)where\s+a\.account_id\s*=\s*p_accountId\s*;",
            RegexOptions.IgnoreCase | RegexOptions.Singleline);
        Match accountUpdateMatch = accountUpdate.Match(promoteFunction);
        accountUpdateMatch.Success.ShouldBeTrue("promote_password_reset must update account password material.");
        accountUpdateMatch.Groups["body"].Value.ShouldNotContain("cut_off", Case.Insensitive);
    }

    [Fact]
    public void Password_reset_promotion_invalidates_existing_sessions_without_account_cutoff()
    {
        string sql = BaselineSql();

        sql.ShouldContain("update sessions s");
        sql.ShouldContain("when s.cut_off is null then v_promoted_at");
        sql.ShouldContain("when s.cut_off > v_promoted_at then v_promoted_at");
        sql.ShouldContain("where s.account_id = p_accountId");
    }

    [Fact]
    public void Password_reset_sql_does_not_store_raw_user_proofs()
    {
        string sql = BaselineSql();

        sql.ShouldContain("key_code_hash text null");
        sql.ShouldContain("key_code_hash_version integer null");
        sql.ShouldContain("requires_key_code boolean not null default true");
        sql.ShouldNotContain("key_code text not null");
        sql.ShouldNotContain("totp_code text");
        sql.ShouldNotContain("new_password");
        sql.ShouldNotContain("verify_password");
    }


    [Fact]
    public void Password_reset_sql_contains_request_rate_limit_contracts()
    {
        string sql = BaselineSql();

        sql.ShouldContain("create table if not exists password_reset_rate_limits");
        sql.ShouldContain("last_request_at timestamp with time zone null");
        sql.ShouldContain("create or replace function register_password_reset_request_rate_limit");
        sql.ShouldContain("p_requestWindow interval");
        sql.ShouldContain("p_requestLimit integer");
        sql.ShouldContain("p_requestCooldown interval");
        sql.ShouldContain("p_blockPeriod interval");
        sql.ShouldContain("PASSWORD_RESET_REQUEST_COOLDOWN");
        sql.ShouldContain("PASSWORD_RESET_RATE_LIMITED");
        sql.ShouldContain("create or replace function cleanup_password_reset_rate_limits");
    }

    [Fact]
    public void Password_reset_cancel_contract_records_delivery_failures()
    {
        string sql = BaselineSql();

        sql.ShouldContain("create or replace function cancel_password_reset_request");
        sql.ShouldContain("p_reasonCode text");
        sql.ShouldContain("PASSWORD_RESET_DELIVERY_FAILED");
        sql.ShouldContain("password_reset_delivery_failed");
        sql.ShouldContain("set cancelled_at = v_cancelled_at");
    }

    [Fact]
    public void Password_reset_failed_attempt_contract_cancels_exhausted_finalization_attempts()
    {
        string sql = BaselineSql();

        sql.ShouldContain("v_attempt_count := v_reset.attempt_count + 1;");
        sql.ShouldContain("if v_attempt_count >= v_reset.max_attempts then");
        sql.ShouldContain("cancelled_at = v_failed_at");
        sql.ShouldContain("PASSWORD_RESET_ATTEMPTS_EXCEEDED");
    }
    private static string Slice(string text, string start, string end)
    {
        int startIndex = text.IndexOf(start, StringComparison.OrdinalIgnoreCase);
        startIndex.ShouldBeGreaterThanOrEqualTo(0);
        int endIndex = text.IndexOf(end, startIndex, StringComparison.OrdinalIgnoreCase);
        endIndex.ShouldBeGreaterThan(startIndex);
        return text[startIndex..endIndex];
    }

    private static string BaselineSql() =>
        File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

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
