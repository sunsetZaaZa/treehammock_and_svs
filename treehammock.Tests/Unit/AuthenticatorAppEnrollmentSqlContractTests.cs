using System.Reflection;
using NodaTime;
using NpgsqlTypes;
using Shouldly;

using treehammock.Repos;

namespace treehammock.Tests.Unit;

public class AuthenticatorAppEnrollmentSqlContractTests
{
    [Fact]
    public void AuthenticatorAppEnrollmentRepo_declares_sql_function_constants()
    {
        AuthenticatorAppEnrollmentRepo.BeginAuthenticatorAppSetupFunction.ShouldBe("cor08_authorized_begin_authenticator_app_setup");
        AuthenticatorAppEnrollmentRepo.GetPendingAuthenticatorAppSetupFunction.ShouldBe("get_pending_authenticator_app_setup");
        AuthenticatorAppEnrollmentRepo.RecordAuthenticatorAppSetupFailureFunction.ShouldBe("record_authenticator_app_setup_failure");
        AuthenticatorAppEnrollmentRepo.CompleteAuthenticatorAppSetupAndRotateSessionFunction.ShouldBe("complete_authenticator_app_setup_and_rotate_session");
        AuthenticatorAppEnrollmentRepo.CancelAuthenticatorAppSetupFunction.ShouldBe("cancel_authenticator_app_setup");
        AuthenticatorAppEnrollmentRepo.GetVerifiedTotpEnrollmentForAccountFunction.ShouldBe("get_verified_totp_enrollment_for_account");
        AuthenticatorAppEnrollmentRepo.MarkTotpStepUsedFunction.ShouldBe("mark_totp_step_used");
    }

    [Fact]
    public void AuthenticatorAppEnrollmentRepo_uses_expected_database_types()
    {
        AuthenticatorAppEnrollmentRepo.InstantDbType.ShouldBe(NpgsqlDbType.TimestampTz);
        AuthenticatorAppEnrollmentRepo.ProtectedSecretDbType.ShouldBe(NpgsqlDbType.Bytea);
    }


    [Fact]
    public void AuthenticatorAppEnrollmentRepo_interface_exposes_setup_and_shared_totp_contracts()
    {
        typeof(IAuthenticatorAppEnrollmentRepo).GetMethod(nameof(IAuthenticatorAppEnrollmentRepo.BeginAuthenticatorAppSetupAsync)).ShouldNotBeNull();
        typeof(IAuthenticatorAppEnrollmentRepo).GetMethod(nameof(IAuthenticatorAppEnrollmentRepo.GetPendingAuthenticatorAppSetupAsync)).ShouldNotBeNull();
        typeof(IAuthenticatorAppEnrollmentRepo).GetMethod(nameof(IAuthenticatorAppEnrollmentRepo.RecordAuthenticatorAppSetupFailureAsync)).ShouldNotBeNull();
        typeof(IAuthenticatorAppEnrollmentRepo).GetMethod(nameof(IAuthenticatorAppEnrollmentRepo.CompleteAuthenticatorAppSetupAndRotateSessionAsync)).ShouldNotBeNull();
        typeof(IAuthenticatorAppEnrollmentRepo).GetMethod(nameof(IAuthenticatorAppEnrollmentRepo.CancelAuthenticatorAppSetupAsync)).ShouldNotBeNull();
        typeof(IAuthenticatorAppEnrollmentRepo).GetMethod(nameof(IAuthenticatorAppEnrollmentRepo.GetVerifiedTotpEnrollmentForAccountAsync)).ShouldNotBeNull();
        typeof(IAuthenticatorAppEnrollmentRepo).GetMethod(nameof(IAuthenticatorAppEnrollmentRepo.MarkTotpStepUsedAsync)).ShouldNotBeNull();
    }

    [Fact]
    public void Begin_setup_command_stores_protected_secret_and_hashed_setup_identifier_only()
    {
        PropertyInfo[] properties = typeof(BeginAuthenticatorAppSetupCommand).GetProperties();

        properties.Any(property => property.Name == nameof(BeginAuthenticatorAppSetupCommand.SetupTokenHash) && property.PropertyType == typeof(string)).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(BeginAuthenticatorAppSetupCommand.TotpSecretCiphertext) && property.PropertyType == typeof(byte[])).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(BeginAuthenticatorAppSetupCommand.TotpSecretNonce) && property.PropertyType == typeof(byte[])).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(BeginAuthenticatorAppSetupCommand.TotpSecretTag) && property.PropertyType == typeof(byte[])).ShouldBeTrue();
        properties.Any(property => property.Name.Contains("SetupId", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();
        properties.Any(property => property.Name.Contains("ManualEntry", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();
        properties.Any(property => property.Name.Contains("Otpauth", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();
        properties.Any(property => property.Name.Contains("TotpCode", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();
    }

    [Fact]
    public void Authenticator_setup_result_models_do_not_carry_plaintext_secret_or_totp_code()
    {
        Type[] models =
        [
            typeof(AuthenticatorAppSetupBeginCommandResult),
            typeof(PendingAuthenticatorAppSetupRecord),
            typeof(AuthenticatorAppSetupFailureCommandResult),
            typeof(AuthenticatorAppSetupCompletionCommandResult),
            typeof(AuthenticatorAppSetupCancelCommandResult),
            typeof(VerifiedTotpEnrollmentRecord),
            typeof(TotpStepReplayCommandResult)
        ];

        foreach (Type model in models)
        {
            PropertyInfo[] properties = model.GetProperties();
            properties.Any(property => property.Name.Contains("Plaintext", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse(model.Name);
            properties.Any(property => property.Name.Contains("TotpCode", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse(model.Name);
            properties.Any(property => property.Name.Contains("ManualEntry", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse(model.Name);
            properties.Any(property => property.Name.Contains("Otpauth", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse(model.Name);
        }
    }

    [Fact]
    public void Authenticator_completion_result_carries_rotated_account_security_stamp()
    {
        typeof(AuthenticatorAppSetupCompletionCommandResult).GetProperty(nameof(AuthenticatorAppSetupCompletionCommandResult.AccountSecurityStamp))!
            .PropertyType.ShouldBe(typeof(Guid?));
    }

    [Fact]
    public void Pending_setup_record_carries_protected_secret_fields_only()
    {
        PropertyInfo[] properties = typeof(PendingAuthenticatorAppSetupRecord).GetProperties();

        properties.Any(property => property.Name == nameof(PendingAuthenticatorAppSetupRecord.TotpSecretCiphertext) && property.PropertyType == typeof(byte[])).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PendingAuthenticatorAppSetupRecord.TotpSecretNonce) && property.PropertyType == typeof(byte[])).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PendingAuthenticatorAppSetupRecord.TotpSecretTag) && property.PropertyType == typeof(byte[])).ShouldBeTrue();
        properties.Any(property => property.Name == nameof(PendingAuthenticatorAppSetupRecord.Expiration) && property.PropertyType == typeof(Instant?)).ShouldBeTrue();
    }

    [Fact]
    public void Canonical_sql_contains_authenticator_app_enrollment_functions_and_provider_columns()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        sql.ShouldContain("create or replace function begin_authenticator_app_setup");
        sql.ShouldContain("create or replace function get_pending_authenticator_app_setup");
        sql.ShouldContain("create or replace function record_authenticator_app_setup_failure");
        sql.ShouldContain("create or replace function complete_authenticator_app_setup_and_rotate_session");
        sql.ShouldContain("create or replace function cancel_authenticator_app_setup");
        sql.ShouldContain("create or replace function get_verified_totp_enrollment_for_account");
        sql.ShouldContain("create or replace function mark_totp_step_used");
        sql.ShouldContain("totp_provider_type smallint null");
        sql.ShouldContain("totp_provider_enrollment_id text null");
        sql.ShouldContain("totp_provider_account_binding_hash text null");
        sql.ShouldContain("ux_two_factor_one_verified_email_per_account");
        sql.ShouldContain("ux_two_factor_one_verified_sms_per_account");
        sql.ShouldContain("ux_two_factor_one_verified_authenticator_app");
        sql.ShouldContain("revoked_at timestamp with time zone null");
        sql.ShouldContain("revoked_reason text null");
        sql.ShouldContain("where verified = true and method = 3 and revoked_at is null");
    }


    [Fact]
    public void Two_factor_details_sql_advertises_only_usable_local_authenticator_enrollments()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        int start = sql.IndexOf("create or replace function get_twofactor_details", StringComparison.Ordinal);
        int end = sql.IndexOf("create or replace function begin_twofactor_setup", start, StringComparison.Ordinal);
        string function = sql[start..end];

        function.ShouldContain("t.verified = true");
        function.ShouldContain("t.method <> 3");
        function.ShouldContain("t.revoked_at is null");
        function.ShouldContain("t.totp_provider_type = 1");
        function.ShouldContain("t.totp_secret_ciphertext is not null");
        function.ShouldContain("coalesce(t.totp_secret_version, 0) > 0");
    }

    [Fact]
    public void Authenticator_completion_sql_recomputes_two_auth_usage_from_usable_verified_methods()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        int start = sql.IndexOf("create or replace function complete_authenticator_app_setup_and_rotate_session", StringComparison.Ordinal);
        int end = sql.IndexOf("create or replace function cancel_authenticator_app_setup", start, StringComparison.Ordinal);
        string function = sql[start..end];

        function.ShouldContain("TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED");
        function.ShouldContain("t.revoked_at is null");
        function.ShouldContain("revoked_at = null");
        function.ShouldContain("revoked_reason = null");
        function.ShouldContain("new_account_stamp uuid := gen_random_uuid()");
        function.ShouldContain("set security_stamp = new_account_stamp");
        function.ShouldContain("verified_count smallint");
        function.ShouldContain("select count(*)::smallint");
        function.ShouldContain("t.method in (1, 2)");
        function.ShouldContain("t.method = 3");
        function.ShouldContain("t.totp_provider_type = 1");
        function.ShouldContain("octet_length(t.totp_secret_ciphertext) > 0");
        function.ShouldContain("octet_length(t.totp_secret_nonce) > 0");
        function.ShouldContain("octet_length(t.totp_secret_tag) > 0");
        function.ShouldContain("coalesce(t.totp_secret_version, 0) > 0");
        function.ShouldContain("two_auth_usage = greatest(verified_count, 1)::smallint");
        function.ShouldNotContain("two_auth_usage = 1");
        function.ShouldContain("account_security_stamp) values");
        function.ShouldContain("new_account_stamp");
        function.ShouldContain("AUTHENTICATOR_SETUP_VERIFIED_SESSION_ROTATED");
        function.ShouldContain("select * into old_session from sessions");
        function.ShouldContain("s.access_token_hash = p_expectedOldAccessTokenHash");
        function.ShouldContain("update sessions set access_expiration = least(access_expiration, greatest(created_on, moment))");
        function.ShouldContain("insert into sessions(access_token_hash, account_id, refresh_token");
        function.ShouldContain("delete from pending_two_factor_sessions ptfs where ptfs.account_id = p_accountId");
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
