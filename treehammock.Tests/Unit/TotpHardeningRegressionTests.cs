using Shouldly;

namespace treehammock.Tests.Unit;

public class TotpHardeningRegressionTests
{
    [Fact]
    public void Authenticator_setup_api_requires_sensitive_action_for_start_and_idempotency_for_setup_verify_cancel()
    {
        string controller = File.ReadAllText(ProjectFile("Controllers", "AccountTwoFactorController.cs"));
        string setup = Extract(controller,
            "public async Task<ActionResult<ApiResponse<StartAuthenticatorAppSetupResponse>>> StartAuthenticatorAppSetup",
            "[HttpPost(\"twofactor/authenticator/verify\")]");
        string verify = Extract(controller,
            "public async Task<ActionResult<ApiResponse<VerifyAuthenticatorAppSetupResponse>>> VerifyAuthenticatorAppSetup",
            "[HttpPost(\"twofactor/authenticator/cancel\")]");
        string cancel = Extract(controller,
            "public async Task<ActionResult<ApiResponse<CancelAuthenticatorAppSetupResponse>>> CancelAuthenticatorAppSetup",
            "[HttpPost(\"setuptwofactormethod\")]");

        setup.ShouldContain("BeginAuthenticatedMutationIdempotency(activeSession, \"account/twofactor/authenticator/setup\", requireKey: true, payload: payload)");
        verify.ShouldContain("BeginAuthenticatedMutationIdempotency(activeSession, \"account/twofactor/authenticator/verify\", requireKey: true, payload: payload)");
        cancel.ShouldContain("BeginAuthenticatedMutationIdempotency(activeSession, \"account/twofactor/authenticator/cancel\", requireKey: true, payload: payload)");

        setup.ShouldContain("ValidateSensitiveActionToken(");
        setup.ShouldContain("consume: false");
        setup.ShouldContain("tokenValidation.Grant");
        setup.ShouldContain("MissingSensitiveActionToken() ? StatusCodes.Status428PreconditionRequired : StatusCodes.Status401Unauthorized");
        verify.ShouldNotContain("ValidateSensitiveActionToken(");
        cancel.ShouldNotContain("ValidateSensitiveActionToken(");

        setup.ShouldContain("CompleteAuthenticatedMutationIdempotency(idempotency, outcome)");
        verify.ShouldContain("CompleteAuthenticatedMutationIdempotency(idempotency, outcome)");
        cancel.ShouldContain("CompleteAuthenticatedMutationIdempotency(idempotency, outcome)");
    }

    [Fact]
    public void Authenticator_setup_idempotency_replay_does_not_replay_secret_material()
    {
        string controller = File.ReadAllText(ProjectFile("Controllers", "AccountTwoFactorController.cs"));
        string setup = Extract(controller,
            "public async Task<ActionResult<ApiResponse<StartAuthenticatorAppSetupResponse>>> StartAuthenticatorAppSetup",
            "async Task<ActionResult<ApiResponse<StartAuthenticatorAppSetupResponse>>> CompleteAndReturn");
        string replayBlock = Extract(setup,
            "var idempotencyReplay = IdempotencyReplayOutcome(",
            "if (idempotencyReplay != null)");

        replayBlock.ShouldContain("supportedAuthenticatorApps = SupportedAuthenticatorApps");
        replayBlock.ShouldNotContain("setupId =");
        replayBlock.ShouldNotContain("manualEntryKey =");
        replayBlock.ShouldNotContain("otpauthUri =");
        replayBlock.ShouldNotContain("accessToken =");
    }

    [Fact]
    public void Login_and_password_reset_share_verified_enrollment_and_replay_marker()
    {
        string login = File.ReadAllText(ProjectFile("Services", "AuthenticatorAppLoginService.cs"));
        string reset = File.ReadAllText(ProjectFile("Services", "PasswordResetTotpService.cs"));

        foreach (string source in new[] { login, reset })
        {
            source.ShouldContain("GetVerifiedTotpEnrollmentForAccountAsync");
            source.ShouldContain("MarkTotpStepUsedAsync");
            source.ShouldContain("TotpProviderType.LOCAL_RFC6238");
            source.ShouldContain("ReplayDetectedCode");
            source.ShouldContain("Array.Clear(secret)");
            source.ShouldNotContain("IPasswordResetTotpRepo");
            source.ShouldNotContain("PasswordResetTotpRepo");
        }
    }

    [Fact]
    public void Authenticator_setup_completion_sql_is_atomic_and_rotates_current_session()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        string function = Extract(sql,
            "create or replace function complete_authenticator_app_setup_and_rotate_session(",
            "create or replace function cancel_authenticator_app_setup(");

        function.ShouldContain("for update");
        function.ShouldContain("new_account_stamp uuid := gen_random_uuid()");
        function.ShouldContain("totp_last_used_step = p_timeStep");
        function.ShouldContain("update accounts a set security_stamp = new_account_stamp");
        function.ShouldContain("two_factor_auth_method = 3");
        function.ShouldContain("update sessions set access_expiration = least(access_expiration, greatest(created_on, moment))");
        function.ShouldContain("insert into sessions(access_token_hash");
        function.ShouldContain("account_security_stamp) values");
        function.ShouldContain("delete from pending_two_factor_sessions ptfs where ptfs.account_id = p_accountId");
        function.ShouldContain("AUTHENTICATOR_SETUP_VERIFIED_SESSION_ROTATED");
    }

    [Fact]
    public void Local_totp_hardening_does_not_log_raw_setup_or_totp_proof_material()
    {
        string[] forbiddenTokens =
        [
            "totpCode",
            "SetupId",
            "setupId",
            "ManualEntryKey",
            "manualEntryKey",
            "OtpauthUri",
            "otpauthUri",
            "SensitiveActionToken",
            "sensitiveActionToken"
        ];

        string[] roots = ["Controllers", "Services", "Repos", "Rigging"];
        foreach (string root in roots)
        {
            foreach (string file in Directory.EnumerateFiles(ProjectFile(root), "*.cs", SearchOption.AllDirectories))
            {
                string relative = Path.GetRelativePath(ProjectRoot(), file);
                string[] lines = File.ReadAllLines(file);
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i];
                    if (!line.Contains(".Log", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    foreach (string forbidden in forbiddenTokens)
                    {
                        line.Contains(forbidden, StringComparison.Ordinal).ShouldBeFalse($"{relative}:{i + 1} must not log raw authenticator setup/proof material.");
                    }
                }
            }
        }
    }

    [Fact]
    public void Sensitive_action_tokens_are_hash_only_short_lived_and_purpose_bound()
    {
        string service = File.ReadAllText(ProjectFile("Services", "SensitiveActionTokenService.cs"));
        string repo = File.ReadAllText(ProjectFile("Repos", "SensitiveActionTokenRepo.cs"));
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        service.ShouldContain("AccountVerificationTokenUtility.GenerateToken(_settings.TokenBytes)");
        service.ShouldContain("AccountVerificationTokenUtility.HashToken(token)");
        service.ShouldContain("_settings.ExpirationMinutes");
        service.ShouldContain("SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP");
        string targets = File.ReadAllText(ProjectFile("Rigging", "Security", "SensitiveActionTargets.cs"));
        targets.ShouldContain("SensitiveActionPurpose.TWO_FACTOR_METHOD_REMOVE");
        service.ShouldContain("SessionBindingHash");

        repo.ShouldContain("tokenHash");
        repo.ShouldNotContain("rawToken");
        repo.ShouldNotContain("plainToken");

        sql.ShouldContain("sensitive_action_grants");
        sql.ShouldContain("token_hash");
        sql.ShouldContain("purpose");
        sql.ShouldContain("credential_stamp");
        sql.ShouldContain("session_hash");
        sql.ShouldContain("family_id");
        sql.ShouldContain("factor_policy");
        sql.ShouldContain("target_hash");
        sql.ShouldContain("make_interval(mins=>p_minutes)");
        sql.ShouldContain("consumed_on");
    }
    private static string Extract(string source, string start, string end)
    {
        int startIndex = source.IndexOf(start, StringComparison.Ordinal);
        startIndex.ShouldBeGreaterThanOrEqualTo(0, $"Start marker was not found: {start}");
        int endIndex = source.IndexOf(end, startIndex + start.Length, StringComparison.Ordinal);
        endIndex.ShouldBeGreaterThan(startIndex, $"End marker was not found after {start}: {end}");
        return source[startIndex..endIndex];
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
