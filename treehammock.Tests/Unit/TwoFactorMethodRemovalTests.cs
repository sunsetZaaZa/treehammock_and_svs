using Microsoft.AspNetCore.Http;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.DataLayer.Cache;
using treehammock.Models.Api;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class TwoFactorMethodRemovalTests
{
    [Fact]
    public async Task Remove_authenticator_app_revokes_only_authenticator_dependent_configurations()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        ActiveSession session = harness.SetAuthenticatedSession();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName] = "sensitive-remove-token";
        harness.AccountRepo.RemoveTwoFactorMethod(
                session.accountId,
                session.accountSecurityStamp,
                TwoFactorAuthMethod.AUTHENTICATOR_APP,
                Arg.Any<Instant>(), cancellationToken: Arg.Any<CancellationToken>(), grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant?>())
            .Returns(new TwoFactorMethodRemovalCommandResult(
                true,
                "TWO_FACTOR_METHOD_REMOVED",
                TwoFactorAuthMethod.AUTHENTICATOR_APP,
                [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.SMS_KEY],
                [TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.EMAIL]));

        var actionResult = await controller.RemoveTwoFactorMethod(new RemoveTwoFactorMethodRequest(TwoFactorAuthMethod.AUTHENTICATOR_APP));

        RemoveTwoFactorMethodResponse response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status200OK);
        response.outcome.ShouldBeTrue();
        response.result.ShouldBe(HttpMessage.TWO_FACTOR_METHOD_REMOVED);
        response.removedMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        response.twoFactorAuthMethods.ShouldNotBeNull();
        response.availableTwoFactorAuthConfigurations.ShouldNotBeNull();
        response.twoFactorAuthMethods!.ShouldBe([TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.SMS_KEY]);
        response.availableTwoFactorAuthConfigurations!.ShouldBe([TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.EMAIL]);
        response.availableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        response.availableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        response.availableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP);
        await harness.SensitiveActionService.Received(1).ValidateAsync(
            Arg.Is<SensitiveActionValidationCommand>(command => command.Purpose == SensitiveActionPurpose.TWO_FACTOR_METHOD_REMOVE),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Remove_sms_keeps_email_and_authenticator_app_options_when_they_remain_verified()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        ActiveSession session = harness.SetAuthenticatedSession();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName] = "sensitive-remove-token";
        harness.AccountRepo.RemoveTwoFactorMethod(
                session.accountId,
                session.accountSecurityStamp,
                TwoFactorAuthMethod.SMS_KEY,
                Arg.Any<Instant>(), cancellationToken: Arg.Any<CancellationToken>(), grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant?>())
            .Returns(new TwoFactorMethodRemovalCommandResult(
                true,
                "TWO_FACTOR_METHOD_REMOVED",
                TwoFactorAuthMethod.SMS_KEY,
                [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP],
                [TwoFactorAuthConfiguration.EMAIL, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP]));

        var actionResult = await controller.RemoveTwoFactorMethod(new RemoveTwoFactorMethodRequest(TwoFactorAuthMethod.SMS_KEY));

        RemoveTwoFactorMethodResponse response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status200OK);
        response.twoFactorAuthMethods.ShouldNotBeNull();
        response.availableTwoFactorAuthConfigurations.ShouldNotBeNull();
        response.twoFactorAuthMethods!.ShouldBe([TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        response.availableTwoFactorAuthConfigurations!.ShouldBe([
            TwoFactorAuthConfiguration.EMAIL,
            TwoFactorAuthConfiguration.AUTHENTICATOR_APP,
            TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP]);
        response.availableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.SMS);
        response.availableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
    }

    [Fact]
    public async Task Remove_method_returns_not_configured_when_repo_reports_no_active_method()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        ActiveSession session = harness.SetAuthenticatedSession();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName] = "sensitive-remove-token";
        harness.AccountRepo.RemoveTwoFactorMethod(
                session.accountId,
                session.accountSecurityStamp,
                TwoFactorAuthMethod.EMAIL,
                Arg.Any<Instant>(), cancellationToken: Arg.Any<CancellationToken>(), grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant?>())
            .Returns(new TwoFactorMethodRemovalCommandResult(
                false,
                "TWO_FACTOR_METHOD_NOT_CONFIGURED",
                TwoFactorAuthMethod.EMAIL,
                [TwoFactorAuthMethod.SMS_KEY],
                [TwoFactorAuthConfiguration.SMS]));

        var actionResult = await controller.RemoveTwoFactorMethod(new RemoveTwoFactorMethodRequest(TwoFactorAuthMethod.EMAIL));

        ApiResponse<RemoveTwoFactorMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status404NotFound);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_METHOD_NOT_CONFIGURED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.TWO_FACTOR_METHOD_NOT_CONFIGURED);
        envelope.data.twoFactorAuthMethods.ShouldNotBeNull();
        envelope.data.availableTwoFactorAuthConfigurations.ShouldNotBeNull();
        envelope.data.twoFactorAuthMethods!.ShouldBe([TwoFactorAuthMethod.SMS_KEY]);
        envelope.data.availableTwoFactorAuthConfigurations!.ShouldBe([TwoFactorAuthConfiguration.SMS]);
    }

    [Fact]
    public void Canonical_sql_revokes_removed_authenticator_material_and_expires_pending_sessions()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        int start = sql.IndexOf("create or replace function cor08_authorized_remove_twofactor_method", StringComparison.Ordinal);
        int end = sql.Length;
        string function = sql[start..end];

        function.ShouldContain("revoked_at = moment");
        function.ShouldContain("revoked_reason = 'user_removed'");
        function.ShouldContain("totp_secret_ciphertext = case when p_method = 3 then null");
        function.ShouldContain("totp_secret_nonce = case when p_method = 3 then null");
        function.ShouldContain("totp_secret_tag = case when p_method = 3 then null");
        function.ShouldContain("totp_last_used_step = case when p_method = 3 then null");
        function.ShouldContain("delete from pending_two_factor_sessions p");
        function.ShouldContain("where p.account_id = p_accountId");
        function.ShouldContain("revoke_pending_password_reset_sessions_for_account");
        function.ShouldContain("PASSWORD_RESET_SESSION_REVOKED_BY_TWO_FACTOR_METHOD_REMOVAL");
        function.ShouldContain("reset_session_revoke_result");
        function.ShouldContain("TWO_FACTOR_METHOD_REMOVE_FAILED");
        function.ShouldContain("resolve_available_twofactor_configurations(p_accountId)");
    }

    [Fact]
    public void Canonical_sql_exposes_account_wide_reset_session_revocation_for_method_removal()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        int start = sql.IndexOf("create or replace function revoke_pending_password_reset_sessions_for_account", StringComparison.Ordinal);
        int end = sql.IndexOf("create or replace function get_password_reset_request_for_finalize", start, StringComparison.Ordinal);
        string function = sql[start..end];

        function.ShouldContain("p_accountId uuid");
        function.ShouldContain("update pending_password_reset_sessions p");
        function.ShouldContain("where p.account_id = p_accountId");
        function.ShouldContain("and p.revoked_at is null");
        function.ShouldContain("revoked_reason = v_reason_code");
        function.ShouldContain("password_reset_session_revoked");
        function.ShouldContain("PASSWORD_RESET_SESSION_NOT_FOUND");
    }

    [Fact]
    public void Canonical_sql_uses_revocation_aware_active_method_indexes_and_queries()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        sql.ShouldContain("where verified = false and revoked_at is null");
        sql.ShouldContain("where verified = true and method = 1 and revoked_at is null");
        sql.ShouldContain("where verified = true and method = 2 and revoked_at is null");
        sql.ShouldContain("where verified = true and method = 3 and revoked_at is null");
        sql.ShouldContain("and t.revoked_at is null");
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
