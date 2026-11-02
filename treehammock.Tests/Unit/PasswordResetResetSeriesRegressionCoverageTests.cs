using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using NodaTime;
using Newtonsoft.Json;
using Shouldly;

using treehammock.Controllers;
using treehammock.DataLayer.Cache;
using treehammock.Models.PasswordReset;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public sealed class PasswordResetResetSeriesRegressionCoverageTests
{
    [Theory]
    [InlineData(nameof(PasswordResetController.RequestReset), "request", typeof(RequestPasswordResetRequest))]
    [InlineData(nameof(PasswordResetController.VerifyResetToken), "verify", typeof(VerifyPasswordResetTokenRequest))]
    [InlineData(nameof(PasswordResetController.SelectTwoFactorConfiguration), "twofactor/select", typeof(SelectPasswordResetTwoFactorConfigurationRequest))]
    [InlineData(nameof(PasswordResetController.VerifyTwoFactorProof), "twofactor/verify", typeof(VerifyPasswordResetTwoFactorRequest))]
    [InlineData(nameof(PasswordResetController.FinalizeReset), "finalize", typeof(FinalizePasswordResetRequest))]
    public void Password_reset_reset_series_public_endpoint_set_is_locked(
        string actionName,
        string expectedRoute,
        Type expectedPayloadType)
    {
        MethodInfo method = typeof(PasswordResetController).GetMethod(actionName).ShouldNotBeNull();

        HttpPostAttribute post = method
            .GetCustomAttributes(typeof(HttpPostAttribute), inherit: true)
            .Cast<HttpPostAttribute>()
            .Single();

        post.Template.ShouldBe(expectedRoute);
        method.GetParameters().First().ParameterType.ShouldBe(expectedPayloadType);
    }

    [Fact]
    public void Password_reset_result_code_vocabulary_covers_token_selection_proof_gate_and_completion_paths()
    {
        string[] requiredConstants =
        [
            nameof(PasswordResetService.RequestAcceptedCode),
            nameof(PasswordResetService.TokenVerifiedCode),
            nameof(PasswordResetService.TwoFactorSelectionRequiredCode),
            nameof(PasswordResetService.TwoFactorConfigurationNotAvailableCode),
            nameof(PasswordResetService.TwoFactorChallengeSentCode),
            nameof(PasswordResetService.TwoFactorAuthenticatorCodeRequiredCode),
            nameof(PasswordResetService.TwoFactorProofAcceptedNextProofRequiredCode),
            nameof(PasswordResetService.TwoFactorCompleteCode),
            nameof(PasswordResetService.TwoFactorRequiredCode),
            nameof(PasswordResetService.TwoFactorNotCompleteCode),
            nameof(PasswordResetService.TwoFactorMethodNotCurrentlyRequiredCode),
            nameof(PasswordResetService.TwoFactorChallengeInvalidCode),
            nameof(PasswordResetService.SessionExpiredCode),
            nameof(PasswordResetService.CompletedCode)
        ];

        foreach (string constantName in requiredConstants)
        {
            FieldInfo field = typeof(PasswordResetService).GetField(constantName, BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
                .ShouldNotBeNull();

            field.IsLiteral.ShouldBeTrue($"{constantName} must remain a compile-time public result code constant.");
            field.GetRawConstantValue().ShouldBeOfType<string>().ShouldNotBeNullOrWhiteSpace();
        }
    }

    [Theory]
    [MemberData(nameof(EmailBootstrapRegressionCases))]
    public void Email_bootstrapped_password_reset_policy_never_double_counts_email(
        List<TwoFactorAuthMethod> verifiedMethods,
        List<TwoFactorAuthConfiguration> expectedConfigurations)
    {
        PasswordResetTwoFactorConfigurationResolver
            .AvailableFromMethods(verifiedMethods, PasswordResetBootstrapProof.EmailResetToken)
            .ShouldBe(expectedConfigurations);
    }

    public static TheoryData<List<TwoFactorAuthMethod>, List<TwoFactorAuthConfiguration>> EmailBootstrapRegressionCases()
    {
        return new TheoryData<List<TwoFactorAuthMethod>, List<TwoFactorAuthConfiguration>>
        {
            { [TwoFactorAuthMethod.EMAIL], [] },
            { [TwoFactorAuthMethod.SMS_KEY], [TwoFactorAuthConfiguration.SMS] },
            { [TwoFactorAuthMethod.AUTHENTICATOR_APP], [TwoFactorAuthConfiguration.AUTHENTICATOR_APP] },
            { [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.SMS_KEY], [TwoFactorAuthConfiguration.SMS] },
            { [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP], [TwoFactorAuthConfiguration.AUTHENTICATOR_APP] },
            { [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP], [TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP] },
            { [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP], [TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP] }
        };
    }

    [Fact]
    public void Password_reset_ordered_combo_session_cannot_complete_before_all_required_proofs()
    {
        Instant now = Instant.FromUtc(2026, 5, 21, 18, 0);
        var session = new PasswordResetSession(
            Guid.NewGuid(),
            "token-hash",
            PasswordResetBootstrapProof.EmailResetToken,
            [TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP],
            now,
            now.Plus(Duration.FromMinutes(2)));

        session.SelectConfiguration(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, now);

        session.state.ShouldBe(PasswordResetSessionState.AwaitingSmsCode);
        session.currentExpectedMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        session.IsCurrentlyExpecting(TwoFactorAuthMethod.AUTHENTICATOR_APP).ShouldBeFalse();
        Should.Throw<InvalidOperationException>(() => session.MarkTwoFactorComplete(now));
        session.canChangePassword.ShouldBeFalse();

        session.MarkCurrentProofAccepted();

        session.state.ShouldBe(PasswordResetSessionState.AwaitingAuthenticatorCode);
        session.currentExpectedMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        session.completedMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY]);
        session.remainingMethods.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.canChangePassword.ShouldBeFalse();

        session.MarkCurrentProofAccepted();
        session.MarkTwoFactorComplete(now.Plus(Duration.FromSeconds(30)));

        session.state.ShouldBe(PasswordResetSessionState.TwoFactorComplete);
        session.currentExpectedMethod.ShouldBeNull();
        session.completedMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        session.remainingMethods.ShouldBeEmpty();
        session.canChangePassword.ShouldBeTrue();
    }

    [Fact]
    public void Password_reset_session_json_contract_matches_sql_persistence_columns()
    {
        string sql = BaselineSql();
        string[] jsonFields =
        [
            "passwordResetRequestId",
            "accountId",
            "resetAccessTokenHash",
            "bootstrapProof",
            "state",
            "availableConfigurationsSnapshot",
            "selectedConfiguration",
            "requiredMethods",
            "completedMethods",
            "currentExpectedMethod",
            "challengeCodeHash",
            "challengeExpiration",
            "challengeAttempts",
            "challengeResends",
            "nextChallengeAllowedAt",
            "createdOn",
            "expiresAt",
            "selectedAt",
            "twoFactorCompletedAt",
            "passwordChangedAt"
        ];

        foreach (string jsonField in jsonFields)
        {
            typeof(PasswordResetSession)
                .GetProperties()
                .Single(property => property.Name == jsonField)
                .GetCustomAttribute<JsonPropertyAttribute>()
                .ShouldNotBeNull($"{jsonField} must be part of the durable reset-session JSON contract.");
        }

        string table = Slice(sql, "create table if not exists pending_password_reset_sessions", "create index if not exists ix_pending_password_reset_sessions_account_current");
        table.ShouldContain("password_reset_request_id uuid");
        table.ShouldContain("account_id uuid not null");
        table.ShouldContain("reset_access_token_hash text primary key");
        table.ShouldContain("bootstrap_proof smallint not null");
        table.ShouldContain("state smallint not null");
        table.ShouldContain("available_configurations smallint[] not null");
        table.ShouldContain("selected_two_factor_configuration smallint null");
        table.ShouldContain("required_methods smallint[] not null");
        table.ShouldContain("completed_methods smallint[] not null");
        table.ShouldContain("current_expected_method smallint null");
        table.ShouldContain("challenge_code_hash text null");
        table.ShouldContain("challenge_expiration timestamp with time zone null");
        table.ShouldContain("challenge_attempts integer not null");
        table.ShouldContain("challenge_resends integer not null");
        table.ShouldContain("next_challenge_allowed_at timestamp with time zone null");
        table.ShouldContain("created_on timestamp with time zone not null");
        table.ShouldContain("expires_at timestamp with time zone not null");
        table.ShouldContain("selected_at timestamp with time zone null");
        table.ShouldContain("two_factor_completed_at timestamp with time zone null");
        table.ShouldContain("password_changed_at timestamp with time zone null");
    }

    [Fact]
    public void Password_reset_service_does_not_promote_password_during_token_or_twofactor_verification()
    {
        string service = File.ReadAllText(ProjectFile("Services", "PasswordResetService.cs"));
        string verifyToken = Slice(service, "public async Task<PasswordResetVerifyResult> VerifyResetToken", "public async Task<PasswordResetTwoFactorSelectResult> SelectTwoFactorConfiguration");
        string verifyTwoFactor = Slice(service, "public async Task<PasswordResetTwoFactorVerifyResult> VerifyTwoFactorProof", "public async Task<PasswordResetFinalizeResult> FinalizeReset");
        string finalize = Slice(service, "public async Task<PasswordResetFinalizeResult> FinalizeReset", "private async Task<PasswordResetFinalizeResult?> GatePasswordChangeOnResetSessionCompletion");

        verifyToken.ShouldNotContain("PromotePasswordReset(");
        verifyTwoFactor.ShouldNotContain("PromotePasswordReset(");
        verifyTwoFactor.ShouldContain("MarkTwoFactorComplete");
        verifyTwoFactor.ShouldContain("TwoFactorMethodNotCurrentlyRequiredCode");
        finalize.ShouldContain("GatePasswordChangeOnResetSessionCompletion");
        finalize.ShouldContain("TwoFactorRequiredCode");
        finalize.ShouldContain("ResolveAvailablePasswordResetConfigurations(reset)");
    }

    [Fact]
    public void Password_reset_sql_revokes_pending_sessions_on_terminal_reset_transitions()
    {
        string sql = BaselineSql();
        string cancel = Slice(sql, "create or replace function cancel_password_reset_request", "create or replace function get_pending_password_reset_session");
        string failedAttempt = Slice(sql, "create or replace function register_password_reset_failed_attempt", "create or replace function promote_password_reset");
        string promote = Slice(sql, "create or replace function promote_password_reset", "create or replace function cleanup_expired_password_reset_requests");
        string cleanup = Slice(sql, "create or replace function cleanup_expired_password_reset_requests", "create or replace function place_activation");

        cancel.ShouldContain("update pending_password_reset_sessions pprs");
        cancel.ShouldContain("revoked_reason = v_reason_code");

        failedAttempt.ShouldContain("revoked_reason = 'PASSWORD_RESET_EXPIRED'");
        failedAttempt.ShouldContain("revoked_reason = 'PASSWORD_RESET_ATTEMPTS_EXCEEDED'");

        promote.ShouldContain("revoked_reason = 'PASSWORD_RESET_EXPIRED'");
        promote.ShouldContain("revoked_reason = 'PASSWORD_RESET_ACCOUNT_STALE'");
        promote.ShouldContain("revoked_reason = 'PASSWORD_RESET_COMPLETED'");
        promote.ShouldContain("set state = 8");
        promote.ShouldContain("password_changed_at = v_promoted_at");

        cleanup.ShouldContain("update pending_password_reset_sessions pprs");
        cleanup.ShouldContain("revoked_reason = 'PASSWORD_RESET_EXPIRED'");
    }

    [Fact]
    public void Twofactor_method_removal_fails_closed_if_reset_session_revocation_fails()
    {
        string sql = BaselineSql();
        string removeMethod = sql[sql.IndexOf("create or replace function cor08_authorized_remove_twofactor_method", StringComparison.Ordinal)..];

        removeMethod.ShouldContain("delete from pending_two_factor_sessions p");
        removeMethod.ShouldContain("revoke_pending_password_reset_sessions_for_account");
        removeMethod.ShouldContain("PASSWORD_RESET_SESSION_REVOKED_BY_TWO_FACTOR_METHOD_REMOVAL");
        removeMethod.ShouldContain("if coalesce(reset_session_revoke_result, false) = false then");
        removeMethod.ShouldContain("'TWO_FACTOR_METHOD_REMOVE_FAILED'::text");
    }
    private static string BaselineSql()
    {
        return File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
    }

    private static string Slice(string source, string start, string end)
    {
        int startIndex = source.IndexOf(start, StringComparison.OrdinalIgnoreCase);
        startIndex.ShouldBeGreaterThanOrEqualTo(0, $"Could not find slice start '{start}'.");

        int endIndex = source.IndexOf(end, startIndex + start.Length, StringComparison.OrdinalIgnoreCase);
        endIndex.ShouldBeGreaterThan(startIndex, $"Could not find slice end '{end}'.");

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
