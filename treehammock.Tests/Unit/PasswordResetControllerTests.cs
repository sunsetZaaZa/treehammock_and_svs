using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Shouldly;

using treehammock.Controllers;
using treehammock.Models.Api;
using treehammock.Models.PasswordReset;
using treehammock.Services;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Tests.Unit;

public class PasswordResetControllerTests
{
    [Fact]
    public async Task Request_reset_returns_generic_accepted_for_valid_shape()
    {
        var service = new RecordingPasswordResetService();
        var controller = NewController(service);

        ActionResult<ApiResponse<PasswordResetRequestResponse>> result = await controller.RequestReset(
            new RequestPasswordResetRequest("reader@example.com", "EMAIL"),
            CancellationToken.None);

        var accepted = result.Result.ShouldBeOfType<ObjectResult>();
        accepted.StatusCode.ShouldBe(StatusCodes.Status202Accepted);
        var envelope = accepted.Value.ShouldBeOfType<ApiResponse<PasswordResetRequestResponse>>();
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBe("accepted");
        envelope.data.resetId.ShouldBe(Guid.Parse("018f7f7e-8da0-7d7c-a512-f5c7f72c2123"));
        envelope.data.message.ShouldBe(PasswordResetRequestResponse.GenericAcceptedMessage);
        service.LastRequestCommand.ShouldNotBeNull();
        service.LastRequestCommand!.Identifier.ShouldBe("reader@example.com");
        service.LastRequestCommand.DeliveryChannel.ShouldBe("email");
    }

    [Fact]
    public async Task Request_reset_rejects_blank_identifier()
    {
        var controller = NewController(new RecordingPasswordResetService());

        ActionResult<ApiResponse<PasswordResetRequestResponse>> result = await controller.RequestReset(
            new RequestPasswordResetRequest(" ", "email"),
            CancellationToken.None);

        var badRequest = result.Result.ShouldBeOfType<ObjectResult>();
        badRequest.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        var envelope = badRequest.Value.ShouldBeOfType<ApiResponse<PasswordResetRequestResponse>>();
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.Single().field.ShouldBe(nameof(RequestPasswordResetRequest.identifier));
    }

    [Fact]
    public async Task Request_reset_rejects_unsupported_delivery_channel()
    {
        var controller = NewController(new RecordingPasswordResetService());

        ActionResult<ApiResponse<PasswordResetRequestResponse>> result = await controller.RequestReset(
            new RequestPasswordResetRequest("reader@example.com", "carrier_pigeon"),
            CancellationToken.None);

        var badRequest = result.Result.ShouldBeOfType<ObjectResult>();
        badRequest.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        var envelope = badRequest.Value.ShouldBeOfType<ApiResponse<PasswordResetRequestResponse>>();
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.Single().field.ShouldBe(nameof(RequestPasswordResetRequest.deliveryChannel));
    }

    [Fact]
    public async Task Verify_valid_shape_returns_reset_token_response()
    {
        var service = new RecordingPasswordResetService();
        var resetId = Guid.NewGuid();
        var controller = NewController(service);

        ActionResult<ApiResponse<VerifyPasswordResetTokenResponse>> result = await controller.VerifyResetToken(
            new VerifyPasswordResetTokenRequest(resetId, " 49382710 "),
            CancellationToken.None);

        var ok = result.Result.ShouldBeOfType<ObjectResult>();
        ok.StatusCode.ShouldBe(StatusCodes.Status200OK);
        var envelope = ok.Value.ShouldBeOfType<ApiResponse<VerifyPasswordResetTokenResponse>>();
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe(PasswordResetService.TwoFactorSelectionRequiredCode);
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBe("two_factor_selection_required");
        envelope.data.resetAccessToken.ShouldBe("reset-access-token");
        envelope.data.requiresTwoFactor.ShouldBeTrue();
        envelope.data.availableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);
        service.LastVerifyCommand.ShouldNotBeNull();
        service.LastVerifyCommand!.ResetId.ShouldBe(resetId);
        service.LastVerifyCommand.KeyCode.ShouldBe("49382710");
    }

    [Fact]
    public async Task Verify_rejects_blank_key_code_before_service_call()
    {
        var service = new RecordingPasswordResetService();
        var controller = NewController(service);

        ActionResult<ApiResponse<VerifyPasswordResetTokenResponse>> result = await controller.VerifyResetToken(
            new VerifyPasswordResetTokenRequest(Guid.NewGuid(), " "),
            CancellationToken.None);

        var badRequest = result.Result.ShouldBeOfType<ObjectResult>();
        badRequest.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        var envelope = badRequest.Value.ShouldBeOfType<ApiResponse<VerifyPasswordResetTokenResponse>>();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.Single().field.ShouldBe(nameof(VerifyPasswordResetTokenRequest.keyCode));
        service.LastVerifyCommand.ShouldBeNull();
    }

    [Fact]
    public async Task Select_reset_twofactor_configuration_returns_current_required_method()
    {
        var service = new RecordingPasswordResetService();
        var controller = NewController(service);

        ActionResult<ApiResponse<SelectPasswordResetTwoFactorConfigurationResponse>> result = await controller.SelectTwoFactorConfiguration(
            new SelectPasswordResetTwoFactorConfigurationRequest(" reset-access-token ", TwoFactorAuthConfiguration.AUTHENTICATOR_APP),
            CancellationToken.None);

        var ok = result.Result.ShouldBeOfType<ObjectResult>();
        ok.StatusCode.ShouldBe(StatusCodes.Status200OK);
        var envelope = ok.Value.ShouldBeOfType<ApiResponse<SelectPasswordResetTwoFactorConfigurationResponse>>();
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe(PasswordResetService.TwoFactorAuthenticatorCodeRequiredCode);
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBe("authenticator_code_required");
        envelope.data.resetAccessToken.ShouldBe("reset-access-token");
        envelope.data.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        envelope.data.currentRequiredMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        envelope.data.remainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        envelope.data.canChangePassword.ShouldBeFalse();
        service.LastSelectCommand.ShouldNotBeNull();
        service.LastSelectCommand!.ResetAccessToken.ShouldBe("reset-access-token");
        service.LastSelectCommand.Configuration.ShouldBe(TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
    }

    [Fact]
    public async Task Select_reset_twofactor_configuration_rejects_blank_token_before_service_call()
    {
        var service = new RecordingPasswordResetService();
        var controller = NewController(service);

        ActionResult<ApiResponse<SelectPasswordResetTwoFactorConfigurationResponse>> result = await controller.SelectTwoFactorConfiguration(
            new SelectPasswordResetTwoFactorConfigurationRequest(" ", TwoFactorAuthConfiguration.AUTHENTICATOR_APP),
            CancellationToken.None);

        var badRequest = result.Result.ShouldBeOfType<ObjectResult>();
        badRequest.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        var envelope = badRequest.Value.ShouldBeOfType<ApiResponse<SelectPasswordResetTwoFactorConfigurationResponse>>();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.Single().field.ShouldBe(nameof(SelectPasswordResetTwoFactorConfigurationRequest.resetAccessToken));
        service.LastSelectCommand.ShouldBeNull();
    }

    [Fact]
    public async Task Finalize_rejects_mismatched_password_fields_before_service_call()
    {
        var service = new RecordingPasswordResetService();
        var controller = NewController(service);

        ActionResult<ApiResponse<FinalizePasswordResetResponse>> result = await controller.FinalizeReset(
            new FinalizePasswordResetRequest(Guid.NewGuid(), "49382710", null, "new long passphrase", "different passphrase"),
            CancellationToken.None);

        var badRequest = result.Result.ShouldBeOfType<ObjectResult>();
        badRequest.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        var envelope = badRequest.Value.ShouldBeOfType<ApiResponse<FinalizePasswordResetResponse>>();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.Single().field.ShouldBe(nameof(FinalizePasswordResetRequest.verifyPassword));
        service.LastFinalizeCommand.ShouldBeNull();
    }

    [Fact]
    public async Task Finalize_valid_shape_returns_completed_when_service_promotes_password()
    {
        var service = new RecordingPasswordResetService();
        var resetId = Guid.NewGuid();
        var controller = NewController(service);

        ActionResult<ApiResponse<FinalizePasswordResetResponse>> result = await controller.FinalizeReset(
            new FinalizePasswordResetRequest(resetId, "49382710", "123456", "new long passphrase", "new long passphrase"),
            CancellationToken.None);

        var completed = result.Result.ShouldBeOfType<ObjectResult>();
        completed.StatusCode.ShouldBe(StatusCodes.Status200OK);
        var envelope = completed.Value.ShouldBeOfType<ApiResponse<FinalizePasswordResetResponse>>();
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe(PasswordResetService.CompletedCode);
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBe("completed");
        service.LastFinalizeCommand.ShouldNotBeNull();
        service.LastFinalizeCommand!.ResetId.ShouldBe(resetId);
        service.LastFinalizeCommand.Password.ShouldBe("new long passphrase");
        service.LastFinalizeCommand.VerifyPassword.ShouldBe("new long passphrase");
    }

    [Fact]
    public async Task Finalize_accepts_reset_access_token_without_reset_id_proof_fields()
    {
        var service = new RecordingPasswordResetService();
        var controller = NewController(service);

        ActionResult<ApiResponse<FinalizePasswordResetResponse>> result = await controller.FinalizeReset(
            new FinalizePasswordResetRequest(Guid.Empty, null, null, "new long passphrase", "new long passphrase", " reset-access-token "),
            CancellationToken.None);

        var completed = result.Result.ShouldBeOfType<ObjectResult>();
        completed.StatusCode.ShouldBe(StatusCodes.Status200OK);
        var envelope = completed.Value.ShouldBeOfType<ApiResponse<FinalizePasswordResetResponse>>();
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe(PasswordResetService.CompletedCode);
        service.LastFinalizeCommand.ShouldNotBeNull();
        service.LastFinalizeCommand!.ResetId.ShouldBe(Guid.Empty);
        service.LastFinalizeCommand.ResetAccessToken.ShouldBe("reset-access-token");
    }

    private static PasswordResetController NewController(IPasswordResetService service)
    {
        return new PasswordResetController(service)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };
    }

    private sealed class RecordingPasswordResetService : IPasswordResetService
    {
        public RequestPasswordResetCommand? LastRequestCommand { get; private set; }
        public VerifyPasswordResetTokenCommand? LastVerifyCommand { get; private set; }
        public SelectPasswordResetTwoFactorConfigurationCommand? LastSelectCommand { get; private set; }
        public VerifyPasswordResetTwoFactorCommand? LastVerifyTwoFactorCommand { get; private set; }
        public FinalizePasswordResetCommand? LastFinalizeCommand { get; private set; }

        public Task<PasswordResetRequestResult> RequestReset(
            RequestPasswordResetCommand command,
            CancellationToken cancellationToken)
        {
            LastRequestCommand = command;
            return Task.FromResult(new PasswordResetRequestResult(PasswordResetService.RequestAcceptedCode, Guid.Parse("018f7f7e-8da0-7d7c-a512-f5c7f72c2123")));
        }

        public Task<PasswordResetVerifyResult> VerifyResetToken(
            VerifyPasswordResetTokenCommand command,
            CancellationToken cancellationToken)
        {
            LastVerifyCommand = command;
            return Task.FromResult(new PasswordResetVerifyResult(
                PasswordResetService.TwoFactorSelectionRequiredCode,
                StatusCodes.Status200OK,
                "two_factor_selection_required",
                "reset-access-token",
                true,
                [TwoFactorAuthConfiguration.AUTHENTICATOR_APP],
                null));
        }

        public Task<PasswordResetTwoFactorSelectResult> SelectTwoFactorConfiguration(
            SelectPasswordResetTwoFactorConfigurationCommand command,
            CancellationToken cancellationToken)
        {
            LastSelectCommand = command;
            return Task.FromResult(new PasswordResetTwoFactorSelectResult(
                PasswordResetService.TwoFactorAuthenticatorCodeRequiredCode,
                StatusCodes.Status200OK,
                "authenticator_code_required",
                command.ResetAccessToken,
                command.Configuration,
                TwoFactorAuthMethod.AUTHENTICATOR_APP,
                null,
                [],
                [TwoFactorAuthMethod.AUTHENTICATOR_APP],
                [TwoFactorAuthConfiguration.AUTHENTICATOR_APP],
                null,
                false));
        }

        public Task<PasswordResetTwoFactorVerifyResult> VerifyTwoFactorProof(
            VerifyPasswordResetTwoFactorCommand command,
            CancellationToken cancellationToken)
        {
            LastVerifyTwoFactorCommand = command;
            return Task.FromResult(new PasswordResetTwoFactorVerifyResult(
                PasswordResetService.TwoFactorCompleteCode,
                StatusCodes.Status200OK,
                "two_factor_complete",
                command.ResetAccessToken,
                TwoFactorAuthConfiguration.AUTHENTICATOR_APP,
                null,
                [TwoFactorAuthMethod.AUTHENTICATOR_APP],
                [],
                null,
                true));
        }

        public Task<PasswordResetFinalizeResult> FinalizeReset(
            FinalizePasswordResetCommand command,
            CancellationToken cancellationToken)
        {
            LastFinalizeCommand = command;
            return Task.FromResult(new PasswordResetFinalizeResult(
                PasswordResetService.CompletedCode,
                StatusCodes.Status200OK));
        }
    }
}
