using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Shouldly;

using treehammock.Controllers;
using treehammock.Models.Api;
using treehammock.Models.PasswordReset;
using treehammock.Repos;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class PasswordResetApiContractTests
{
    [Fact]
    public void Password_reset_controller_is_public_controller_based_api_surface()
    {
        typeof(PasswordResetController)
            .GetCustomAttributes(typeof(ApiControllerAttribute), inherit: true)
            .ShouldNotBeEmpty();

        typeof(PasswordResetController)
            .GetCustomAttributes(typeof(AllowAnonymous), inherit: true)
            .ShouldNotBeEmpty();

        typeof(PasswordResetController)
            .GetCustomAttributes(typeof(Authenticate), inherit: true)
            .ShouldBeEmpty("password reset request/finalize endpoints must be reachable before login");

        RouteAttribute route = typeof(PasswordResetController)
            .GetCustomAttributes(typeof(RouteAttribute), inherit: true)
            .Cast<RouteAttribute>()
            .Single();

        route.Template.ShouldBe("account/password-reset");
    }

    [Theory]
    [InlineData(nameof(PasswordResetController.RequestReset), "request")]
    [InlineData(nameof(PasswordResetController.VerifyResetToken), "verify")]
    [InlineData(nameof(PasswordResetController.SelectTwoFactorConfiguration), "twofactor/select")]
    [InlineData(nameof(PasswordResetController.VerifyTwoFactorProof), "twofactor/verify")]
    [InlineData(nameof(PasswordResetController.FinalizeReset), "finalize")]
    public void Password_reset_actions_advertise_expected_routes(string methodName, string routeTemplate)
    {
        var method = typeof(PasswordResetController).GetMethod(methodName);

        method.ShouldNotBeNull();
        HttpPostAttribute post = method!
            .GetCustomAttributes(typeof(HttpPostAttribute), inherit: true)
            .Cast<HttpPostAttribute>()
            .Single();

        post.Template.ShouldBe(routeTemplate);
    }

    [Fact]
    public void Password_reset_request_contract_allows_delivery_channels_only()
    {
        PasswordResetDeliveryChannels.IsSupported("email").ShouldBeTrue();
        PasswordResetDeliveryChannels.IsSupported("sms").ShouldBeTrue();
        PasswordResetDeliveryChannels.IsSupported("email_code").ShouldBeFalse();
        PasswordResetDeliveryChannels.IsSupported("sms_code").ShouldBeFalse();
        PasswordResetDeliveryChannels.IsSupported("authenticator_app_totp").ShouldBeFalse();
        PasswordResetDeliveryChannels.IsSupported("sms_code_totp").ShouldBeFalse();
        PasswordResetDeliveryChannels.IsSupported("email_code_totp").ShouldBeFalse();
        PasswordResetDeliveryChannels.IsSupported("carrier_pigeon").ShouldBeFalse();
    }

    [Fact]
    public void Password_reset_delivery_channel_normalization_is_centralized()
    {
        PasswordResetDeliveryChannels.Normalize(" EMAIL ").ShouldBe(PasswordResetDeliveryChannels.Email);
        PasswordResetDeliveryChannels.Normalize(null).ShouldBe(string.Empty);
        PasswordResetDeliveryChannels.IsSupported(" SMS ").ShouldBeTrue();
        PasswordResetDeliveryChannels.IsSupported(null).ShouldBeFalse();
        PasswordResetDeliveryChannels.SupportedDeliveryChannelsDescription.ShouldBe("email or sms");
    }

    [Fact]
    public void Finalize_contract_accepts_proof_and_password_fields_but_not_account_id()
    {
        typeof(FinalizePasswordResetRequest).GetProperty("resetId").ShouldNotBeNull();
        typeof(FinalizePasswordResetRequest).GetProperty("keyCode").ShouldNotBeNull();
        typeof(FinalizePasswordResetRequest).GetProperty("totpCode").ShouldNotBeNull();
        typeof(FinalizePasswordResetRequest).GetProperty("resetAccessToken").ShouldNotBeNull();
        typeof(FinalizePasswordResetRequest).GetProperty("password").ShouldNotBeNull();
        typeof(FinalizePasswordResetRequest).GetProperty("verifyPassword").ShouldNotBeNull();
        typeof(FinalizePasswordResetRequest).GetProperty("accountId").ShouldBeNull();
    }

    [Fact]
    public void Request_response_contract_returns_reset_id_for_non_enumerating_finalize_flow()
    {
        typeof(PasswordResetRequestResponse).GetProperty("resetId").ShouldNotBeNull();
        var response = new PasswordResetRequestResponse("accepted", Guid.Parse("018f7f7e-8da0-7d7c-a512-f5c7f72c2123"), PasswordResetRequestResponse.GenericAcceptedMessage);

        response.resetId.ShouldBe(Guid.Parse("018f7f7e-8da0-7d7c-a512-f5c7f72c2123"));
    }

    [Fact]
    public void Verify_response_contract_advertises_reset_session_selection_shape()
    {
        typeof(VerifyPasswordResetTokenRequest).GetProperty("resetId").ShouldNotBeNull();
        typeof(VerifyPasswordResetTokenRequest).GetProperty("keyCode").ShouldNotBeNull();
        typeof(VerifyPasswordResetTokenResponse).GetProperty("status").ShouldNotBeNull();
        typeof(VerifyPasswordResetTokenResponse).GetProperty("resetAccessToken").ShouldNotBeNull();
        typeof(VerifyPasswordResetTokenResponse).GetProperty("requiresTwoFactor").ShouldNotBeNull();
        typeof(VerifyPasswordResetTokenResponse).GetProperty("availableTwoFactorAuthConfigurations").ShouldNotBeNull();
        typeof(VerifyPasswordResetTokenResponse).GetProperty("expiresAt").ShouldNotBeNull();
        typeof(IPasswordResetService).GetMethod(nameof(IPasswordResetService.VerifyResetToken)).ShouldNotBeNull();
    }

    [Fact]
    public void Select_twofactor_contract_advertises_reset_session_state_shape()
    {
        typeof(SelectPasswordResetTwoFactorConfigurationRequest).GetProperty("resetAccessToken").ShouldNotBeNull();
        typeof(SelectPasswordResetTwoFactorConfigurationRequest).GetProperty("configuration").ShouldNotBeNull();
        typeof(SelectPasswordResetTwoFactorConfigurationRequest).GetProperty("destination").ShouldNotBeNull();
        typeof(SelectPasswordResetTwoFactorConfigurationResponse).GetProperty("status").ShouldNotBeNull();
        typeof(SelectPasswordResetTwoFactorConfigurationResponse).GetProperty("resetAccessToken").ShouldNotBeNull();
        typeof(SelectPasswordResetTwoFactorConfigurationResponse).GetProperty("selectedConfiguration").ShouldNotBeNull();
        typeof(SelectPasswordResetTwoFactorConfigurationResponse).GetProperty("currentRequiredMethod").ShouldNotBeNull();
        typeof(SelectPasswordResetTwoFactorConfigurationResponse).GetProperty("completedTwoFactorAuthMethods").ShouldNotBeNull();
        typeof(SelectPasswordResetTwoFactorConfigurationResponse).GetProperty("remainingTwoFactorAuthMethods").ShouldNotBeNull();
        typeof(SelectPasswordResetTwoFactorConfigurationResponse).GetProperty("availableTwoFactorAuthConfigurations").ShouldNotBeNull();
        typeof(SelectPasswordResetTwoFactorConfigurationResponse).GetProperty("expiresAt").ShouldNotBeNull();
        typeof(SelectPasswordResetTwoFactorConfigurationResponse).GetProperty("canChangePassword").ShouldNotBeNull();
        typeof(IPasswordResetService).GetMethod(nameof(IPasswordResetService.SelectTwoFactorConfiguration)).ShouldNotBeNull();
        typeof(IPasswordResetSessionService).ShouldNotBeNull();
    }

    [Fact]
    public void Verify_reset_twofactor_contract_advertises_ordered_proof_state_shape()
    {
        typeof(VerifyPasswordResetTwoFactorRequest).GetProperty("resetAccessToken").ShouldNotBeNull();
        typeof(VerifyPasswordResetTwoFactorRequest).GetProperty("method").ShouldNotBeNull();
        typeof(VerifyPasswordResetTwoFactorRequest).GetProperty("code").ShouldNotBeNull();
        typeof(VerifyPasswordResetTwoFactorResponse).GetProperty("status").ShouldNotBeNull();
        typeof(VerifyPasswordResetTwoFactorResponse).GetProperty("resetAccessToken").ShouldNotBeNull();
        typeof(VerifyPasswordResetTwoFactorResponse).GetProperty("selectedConfiguration").ShouldNotBeNull();
        typeof(VerifyPasswordResetTwoFactorResponse).GetProperty("currentRequiredMethod").ShouldNotBeNull();
        typeof(VerifyPasswordResetTwoFactorResponse).GetProperty("completedTwoFactorAuthMethods").ShouldNotBeNull();
        typeof(VerifyPasswordResetTwoFactorResponse).GetProperty("remainingTwoFactorAuthMethods").ShouldNotBeNull();
        typeof(VerifyPasswordResetTwoFactorResponse).GetProperty("expiresAt").ShouldNotBeNull();
        typeof(VerifyPasswordResetTwoFactorResponse).GetProperty("canChangePassword").ShouldNotBeNull();
        typeof(IPasswordResetService).GetMethod(nameof(IPasswordResetService.VerifyTwoFactorProof)).ShouldNotBeNull();
    }

    [Fact]
    public void Password_reset_settings_are_backend_configuration_controls()
    {
        typeof(PasswordResetSettings).GetProperty(nameof(PasswordResetSettings.CodeLength)).ShouldNotBeNull();
        typeof(PasswordResetSettings).GetProperty(nameof(PasswordResetSettings.CodeHashPepper)).ShouldNotBeNull();
        typeof(PasswordResetSettings).GetProperty(nameof(PasswordResetSettings.ExpirationMinutes)).ShouldNotBeNull();
        typeof(PasswordResetSettings).GetProperty(nameof(PasswordResetSettings.MaxAttempts)).ShouldNotBeNull();
        typeof(PasswordResetSettings).GetProperty(nameof(PasswordResetSettings.RequestCooldownSeconds)).ShouldNotBeNull();
        typeof(PasswordResetSettings).GetProperty(nameof(PasswordResetSettings.DailyRequestLimitPerAccount)).ShouldNotBeNull();
        typeof(PasswordResetSettings).GetProperty(nameof(PasswordResetSettings.DailyRequestLimitPerDestination)).ShouldNotBeNull();
        typeof(PasswordResetSettings).GetProperty(nameof(PasswordResetSettings.DailyRequestLimitPerIp)).ShouldNotBeNull();
        typeof(PasswordResetSettings).GetProperty(nameof(PasswordResetSettings.DailyRequestWindowHours)).ShouldNotBeNull();
        typeof(PasswordResetSettings).GetProperty(nameof(PasswordResetSettings.RateLimitBlockMinutes)).ShouldNotBeNull();
        typeof(PasswordResetSettings).GetProperty(nameof(PasswordResetSettings.CaptchaChallengeEnabled)).ShouldNotBeNull();
        typeof(PasswordResetSettings).GetProperty(nameof(PasswordResetSettings.CaptchaChallengeAfterRequests)).ShouldNotBeNull();
        typeof(IPasswordResetRateLimitKeyFactory).ShouldNotBeNull();
        typeof(IPasswordResetAbuseCounterKeyFactory).ShouldNotBeNull();
        typeof(IPasswordResetAbusePolicy).ShouldNotBeNull();
        typeof(IPasswordResetDeliveryService).ShouldNotBeNull();
        typeof(IPasswordResetTotpVerifier).ShouldNotBeNull();
        typeof(IPasswordResetPasswordMaterialFactory).ShouldNotBeNull();
    }

    [Fact]
    public void Totp_settings_and_secret_protector_are_backend_configuration_controls()
    {
        typeof(TotpSettings).GetProperty(nameof(TotpSettings.Issuer)).ShouldNotBeNull();
        typeof(TotpSettings).GetProperty(nameof(TotpSettings.Digits)).ShouldNotBeNull();
        typeof(TotpSettings).GetProperty(nameof(TotpSettings.PeriodSeconds)).ShouldNotBeNull();
        typeof(TotpSettings).GetProperty(nameof(TotpSettings.AllowedClockSkewSteps)).ShouldNotBeNull();
        typeof(TotpSettings).GetProperty(nameof(TotpSettings.HashAlgorithm)).ShouldNotBeNull();
        typeof(TotpSettings).GetProperty(nameof(TotpSettings.SecretBytes)).ShouldNotBeNull();
        typeof(TotpSettings).GetProperty(nameof(TotpSettings.ActiveProtectionKeyId)).ShouldNotBeNull();
        typeof(ITotpSecretProtector).ShouldNotBeNull();
        typeof(ProtectedTotpSecret).ShouldNotBeNull();
        typeof(IPasswordResetTotpRepo).ShouldNotBeNull();
        typeof(IAuthenticatorAppEnrollmentRepo).ShouldNotBeNull();
        typeof(ITotpCodeVerifier).ShouldNotBeNull();
    }

    [Fact]
    public void Password_reset_contract_has_database_surface_for_future_repository_work()
    {
        string root = ProjectRoot();
        string sql = File.ReadAllText(Path.Combine(root, "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        sql.ShouldContain("create table if not exists password_reset_requests");
        sql.ShouldContain("create or replace function create_password_reset_request");
        sql.ShouldContain("create or replace function cancel_password_reset_request");
        sql.ShouldContain("create or replace function promote_password_reset");
        sql.ShouldContain("create or replace function register_password_reset_request_rate_limit");
    }


    [Fact]
    public void Password_reset_delivery_contract_uses_email_and_sms_templates_without_plaintext_storage()
    {
        string root = ProjectRoot();
        string smtp = File.ReadAllText(Path.Combine(root, "Services", "SMTPService.cs"));
        string delivery = File.ReadAllText(Path.Combine(root, "Services", "PasswordResetDeliveryService.cs"));
        string templates = File.ReadAllText(Path.Combine(root, "Rigging", "Config", "EmailTemplateSettings.cs"));
        string subjects = File.ReadAllText(Path.Combine(root, "Rigging", "Config", "EmailSubjectSettings.cs"));

        smtp.ShouldContain("PasswordResetCodeLetter");
        delivery.ShouldContain("IPasswordResetDeliveryService");
        delivery.ShouldContain("StageAsync");
        delivery.ShouldContain("delivery.EnqueueAsync");
        templates.ShouldContain("PasswordResetCode");
        templates.ShouldContain("PasswordResetSmsCode");
        subjects.ShouldContain("PasswordResetCode");
        File.Exists(Path.Combine(root, "email_templates", "PasswordResetCode.html")).ShouldBeTrue();
        File.Exists(Path.Combine(root, "email_templates", "PasswordResetCode.txt")).ShouldBeTrue();
        File.Exists(Path.Combine(root, "sms_templates", "PasswordResetCode.txt")).ShouldBeTrue();
    }


    [Fact]
    public void Password_reset_request_orchestration_is_wired_to_repository_delivery_and_non_plaintext_code_services()
    {
        string source = File.ReadAllText(ProjectFile("Services", "PasswordResetService.cs"));

        source.ShouldContain("LookupPasswordResetAccountAsync");
        source.ShouldContain("RegisterRequestRateLimitAsync");
        source.ShouldContain("CheckPasswordResetRequestAbusePolicy");
        source.ShouldContain("CheckPasswordResetTokenVerificationAbusePolicy");
        source.ShouldContain("CheckPasswordResetTwoFactorProofAbusePolicy");
        source.ShouldContain("CheckPasswordResetFinalizeAbusePolicy");
        source.ShouldContain("VerifyResetToken");
        source.ShouldContain("SelectTwoFactorConfiguration");
        source.ShouldContain("VerifyTwoFactorProof");
        source.ShouldContain("PasswordResetTwoFactorSelectResult");
        source.ShouldContain("PasswordResetTwoFactorVerifyResult");
        source.ShouldContain("TwoFactorAuthenticatorCodeRequiredCode");
        source.ShouldContain("TwoFactorSessionPersistenceFailedCode");
        source.ShouldContain("TwoFactorCompleteCode");
        source.ShouldContain("TwoFactorRequiredCode");
        source.ShouldContain("TwoFactorNotCompleteCode");
        source.ShouldContain("TwoFactorMethodNotCurrentlyRequiredCode");
        source.ShouldContain("GatePasswordChangeOnResetSessionCompletion");
        source.ShouldContain("AccessTokenHashUtility.Hash(resetAccessToken)");
        source.ShouldContain("TokenVerifiedCode");
        source.ShouldContain("TwoFactorSelectionRequiredCode");
        source.ShouldContain("CreateResetAccessToken");
        source.ShouldContain("ResolveAvailablePasswordResetConfigurations");
        source.ShouldContain("PasswordResetTwoFactorConfigurationResolver.AvailableFromMethods");
        source.ShouldContain("GenerateKeyCode");
        source.ShouldContain("HashCode(resetId, keyCode)");
        source.ShouldContain("CreatePasswordResetRequestDbCommand");
        source.ShouldContain("_deliveryService.StageAsync");
        source.ShouldContain("PasswordResetDeliveryChannels.Email");
        source.ShouldContain("PasswordResetDeliveryChannels.Sms");
        source.ShouldContain("VerifyTotpForPasswordReset");
        source.ShouldContain("RegisterFailedAttemptAsync");
        source.ShouldContain("CreatePasswordMaterial");
        source.ShouldContain("PromotePasswordResetAsync");
        source.ShouldNotContain("CancelPasswordResetRequestAsync");
        source.ShouldContain("DeliveryFailedCode");
        source.ShouldContain("Guid publicResetId = Guid.NewGuid();");
        source.ShouldContain("return Accepted(publicResetId);");
        source.ShouldNotContain("return new PasswordResetRequestResult(IneligibleDeliveryChannelCode)");
        source.ShouldNotContain("return new PasswordResetRequestResult(LookupFailedCode)");
    }


    [Fact]
    public void Password_reset_finalize_requires_reset_access_token_or_reset_id_proof_field()
    {
        string controller = File.ReadAllText(ProjectFile("Controllers", "PasswordResetController.cs"));

        controller.ShouldContain("!hasResetAccessToken && payload.keyCode is null && payload.totpCode is null");
        controller.ShouldContain("resetAccessToken, keyCode, or totpCode is required.");
    }

    private static string ProjectFile(params string[] relativePathParts)
    {
        return Path.Combine(new[] { ProjectRoot() }.Concat(relativePathParts).ToArray());
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
}
