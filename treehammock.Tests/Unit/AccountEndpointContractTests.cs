using Microsoft.AspNetCore.Http;
using Shouldly;
using NSubstitute;
using NodaTime;

using treehammock.Models.Account;
using treehammock.Models.Api;
using treehammock.Models.Authentication;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Security;
using treehammock.Rigging.Replay;
using treehammock.RiggingSupport.Status;
using treehammock.RiggingSupport.Enum;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class AccountEndpointContractTests
{
    [Fact]
    public async Task ModifyAccount_rejects_null_body_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateProfileController();

        var actionResult = await controller.ModifyAccount(null);

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrors(envelope);
    }

    [Fact]
    public async Task DeleteAccount_missing_body_without_auth_context_returns_unauthorized()
    {
        var controller = new AccountControllerHarness().CreateDeleteController();

        var actionResult = await controller.DeleteAccount(null);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
    }

    [Fact]
    public async Task LogoffAccount_missing_body_without_auth_context_returns_unauthorized()
    {
        var controller = new AccountControllerHarness().CreateSessionController();

        var actionResult = await controller.LogoffAccount(null);

        ApiResponse<AuthenticateLogoffResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
    }

    [Fact]
    public async Task ModifyAccount_rejects_empty_body_object_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateProfileController();
        var request = new AccountEditRequest(null, null);

        var actionResult = await controller.ModifyAccount(request);

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, string.Empty);
    }

    [Fact]
    public async Task ModifyAccount_rejects_blank_adjustment_fields_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateProfileController();
        var request = new AccountEditRequest("   ", "   ");

        var actionResult = await controller.ModifyAccount(request);

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(AccountEditRequest.emailAddress));
        AssertHasValidationErrorFor(envelope, nameof(AccountEditRequest.username));
    }

    [Fact]
    public async Task ModifyAccount_email_change_request_returns_pending_verification()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .RequestEmailChange(accountId, accountSecurityStamp, "reader@example.com", cancellationToken: Arg.Any<CancellationToken>(), grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>())
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(true, "ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING", null, "reader@example.com")));
        var request = new AccountEditRequest("  reader@example.com  ", null);

        var actionResult = await controller.ModifyAccount(request);

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status202Accepted);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING);
        request.emailAddress.ShouldBe("reader@example.com");
        await harness.AccountService.Received(1).RequestEmailChange(accountId, accountSecurityStamp, "reader@example.com", cancellationToken: Arg.Any<CancellationToken>(), grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>());
    }

    [Fact]
    public async Task ModifyAccount_email_delivery_failure_returns_adjust_delivery_failed()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .RequestEmailChange(accountId, accountSecurityStamp, "reader@example.com", cancellationToken: Arg.Any<CancellationToken>(), grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>())
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(false, "ACCOUNT_ADJUST_EMAIL_DELIVERY_FAILED", null, "reader@example.com")));

        var actionResult = await controller.ModifyAccount(new AccountEditRequest("reader@example.com", null));

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_ADJUST_EMAIL_DELIVERY_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_ADJUST_EMAIL_DELIVERY_FAILED);
    }

    [Fact]
    public async Task ModifyAccount_rejects_email_plus_username_as_ambiguous_adjustment()
    {
        var controller = new AccountControllerHarness().CreateProfileController();
        var request = new AccountEditRequest("reader@example.com", "reader");

        var actionResult = await controller.ModifyAccount(request);

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, string.Empty);
    }

    [Fact]
    public async Task ModifyAccount_username_without_auth_context_returns_unauthorized()
    {
        var controller = new AccountControllerHarness().CreateProfileController();
        var request = new AccountEditRequest(null, "reader");

        var actionResult = await controller.ModifyAccount(request);

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
    }

    [Fact]
    public async Task ModifyAccount_username_success_updates_authenticated_account()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountRepo
            .ModifyUsername(accountId, accountSecurityStamp, "new_reader")
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(true, "ACCOUNT_ADJUST_SUCCEEDED")));
        var request = new AccountEditRequest(null, "  new_reader  ");

        var actionResult = await controller.ModifyAccount(request);

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("ACCOUNT_ADJUST_SUCCEEDED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_ADJUST_SUCCEEDED);
        request.username.ShouldBe("new_reader");
        await harness.AccountRepo.Received(1).ModifyUsername(accountId, accountSecurityStamp, "new_reader", cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ModifyAccount_duplicate_username_returns_bad_request()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountRepo
            .ModifyUsername(accountId, accountSecurityStamp, "reader")
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(false, "ACCOUNT_ADJUST_DUPLICATE_USERNAME")));

        var actionResult = await controller.ModifyAccount(new AccountEditRequest(null, "reader"));

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_ADJUST_DUPLICATE_USERNAME");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_ADJUST_DUPLICATE_USERNAME);
    }

    [Fact]
    public async Task ModifyAccount_stale_account_security_stamp_returns_unauthorized()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountRepo
            .ModifyUsername(accountId, accountSecurityStamp, "reader")
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(false, "ACCOUNT_SECURITY_STAMP_MISMATCH")));

        var actionResult = await controller.ModifyAccount(new AccountEditRequest(null, "reader"));

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_SECURITY_STAMP_MISMATCH);
    }

    [Fact]
    public async Task ModifyAccount_missing_account_returns_not_found()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountRepo
            .ModifyUsername(accountId, accountSecurityStamp, "reader")
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(false, "ACCOUNT_NOT_FOUND")));

        var actionResult = await controller.ModifyAccount(new AccountEditRequest(null, "reader"));

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status404NotFound);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_NOT_FOUND");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_NOT_FOUND);
    }



    [Fact]
    public async Task ModifyAccount_missing_required_idempotency_key_returns_precondition_required_without_mutation()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        harness.SetAuthenticatedSession(Guid.NewGuid(), Guid.NewGuid());
        harness.AuthenticatedMutationIdempotencyService
            .BeginAsync(Arg.Is<AuthenticatedMutationIdempotencyRequest>(request =>
                request.RequireKey &&
                request.Route == "account/adjust" &&
                request.IdempotencyKey == null), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(AuthenticatedMutationIdempotencyBeginResult.MissingRequiredKeyResult()));

        var actionResult = await controller.ModifyAccount(new AccountEditRequest(null, "reader"));

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status428PreconditionRequired);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(AuthenticatedMutationIdempotencyConstants.MissingRequiredKeyCode);
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_ADJUST_FAILED);
        await harness.AccountRepo.DidNotReceive().ModifyUsername(Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.AccountService.DidNotReceive().RequestEmailChange(Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>(), grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>());
    }

    [Fact]
    public async Task ModifyAccount_invalid_idempotency_key_returns_validation_failed_without_mutation()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        harness.SetAuthenticatedSession(Guid.NewGuid(), Guid.NewGuid());
        harness.HttpContext.Request.Headers[AuthenticatedMutationIdempotencyConstants.HeaderName] = "bad key with spaces";
        harness.AuthenticatedMutationIdempotencyService
            .BeginAsync(Arg.Any<AuthenticatedMutationIdempotencyRequest>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(AuthenticatedMutationIdempotencyBeginResult.InvalidKeyResult()));

        var actionResult = await controller.ModifyAccount(new AccountEditRequest(null, "reader"));

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, AuthenticatedMutationIdempotencyConstants.HeaderName);
        await harness.AccountRepo.DidNotReceive().ModifyUsername(Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.AccountService.DidNotReceive().RequestEmailChange(Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>(), grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>());
    }

    [Fact]
    public async Task ModifyAccount_completed_idempotency_key_replays_result_without_mutation()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        harness.SetAuthenticatedSession(Guid.NewGuid(), Guid.NewGuid());
        harness.HttpContext.Request.Headers[AuthenticatedMutationIdempotencyConstants.HeaderName] = "client-key-12345";
        harness.AuthenticatedMutationIdempotencyService
            .BeginAsync(Arg.Any<AuthenticatedMutationIdempotencyRequest>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(AuthenticatedMutationIdempotencyBeginResult.ReplayCompletedResult(
                AuthenticatedMutationSafeResult.Capture(new ApiOutcome<AccountEditResponse>(new AccountEditResponse(HttpMessage.ACCOUNT_ADJUST_SUCCEEDED), StatusCodes.Status200OK, "ACCOUNT_ADJUST_SUCCEEDED")))));

        var actionResult = await controller.ModifyAccount(new AccountEditRequest(null, "reader"));

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("ACCOUNT_ADJUST_SUCCEEDED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_ADJUST_SUCCEEDED);
        await harness.AccountRepo.DidNotReceive().ModifyUsername(Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>());
        await harness.AccountService.DidNotReceive().RequestEmailChange(Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>(), grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>());
    }

    [Fact]
    public async Task ModifyAccount_duplicate_email_returns_bad_request()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .RequestEmailChange(accountId, accountSecurityStamp, "reader@example.com", cancellationToken: Arg.Any<CancellationToken>(), grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>())
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(false, "ACCOUNT_ADJUST_DUPLICATE_EMAIL")));

        var actionResult = await controller.ModifyAccount(new AccountEditRequest("reader@example.com", null));

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_ADJUST_DUPLICATE_EMAIL");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_ADJUST_DUPLICATE_EMAIL);
    }

    [Fact]
    public async Task VerifyEmailChange_valid_token_returns_adjust_succeeded()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        harness.AccountService
            .CompleteEmailChange("raw-token")
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(true, "ACCOUNT_ADJUST_SUCCEEDED", Guid.NewGuid())));

        var actionResult = await controller.ConfirmEmailChange(new AccountEmailChangeVerifyRequest("raw-token"));

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("ACCOUNT_ADJUST_SUCCEEDED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_ADJUST_SUCCEEDED);
        await harness.AccountService.Received(1).CompleteEmailChange("raw-token", cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyEmailChange_expired_token_returns_bad_request()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        harness.AccountService
            .CompleteEmailChange("expired-token")
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(false, "ACCOUNT_ADJUST_TOKEN_EXPIRED")));

        var actionResult = await controller.ConfirmEmailChange(new AccountEmailChangeVerifyRequest("expired-token"));

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_ADJUST_TOKEN_EXPIRED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_ADJUST_TOKEN_EXPIRED);
    }

    [Fact]
    public async Task VerifyEmailChange_public_token_throttle_returns_too_many_requests()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        harness.AccountService
            .CompleteEmailChange("raw-token")
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(false, AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded)));

        var actionResult = await controller.ConfirmEmailChange(new AccountEmailChangeVerifyRequest("raw-token"));

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status429TooManyRequests);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded);
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_ADJUST_FAILED);
    }

    [Fact]
    public async Task VerifyEmailChange_counter_store_unavailable_returns_service_unavailable()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        harness.AccountService
            .CompleteEmailChange("raw-token")
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(false, AbuseReasonCodes.CounterStoreUnavailable)));

        var actionResult = await controller.ConfirmEmailChange(new AccountEmailChangeVerifyRequest("raw-token"));

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status503ServiceUnavailable);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(AbuseReasonCodes.CounterStoreUnavailable);
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_ADJUST_FAILED);
    }

    [Fact]
    public async Task VerifyEmailChange_missing_payload_returns_validation_failed()
    {
        var controller = new AccountControllerHarness().CreateProfileController();

        var actionResult = await controller.ConfirmEmailChange(null);

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, "payload");
    }

    [Fact]
    public async Task VerifyEmailChange_oversized_payload_returns_validation_failed()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        string payload = new('x', AccountEmailChangeVerifyRequest.MaxEmailChangeTokenLength + 1);

        var actionResult = await controller.ConfirmEmailChange(new AccountEmailChangeVerifyRequest(payload));

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, "payload");
        await harness.AccountService.DidNotReceive().CompleteEmailChange(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ViewAccount_missing_auth_context_returns_unauthorized()
    {
        var controller = new AccountControllerHarness().CreateProfileController();

        var actionResult = await controller.ViewAccount();

        ApiResponse<AccountDetailsResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
    }

    [Fact]
    public async Task ViewAccount_authenticated_current_account_returns_safe_profile()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        Instant createdOn = SystemClock.Instance.GetCurrentInstant();
        var profile = new AccountProfile
        {
            emailAddress = "reader@example.com",
            username = "reader",
            createdOn = createdOn,
            verifyStatus = VerificationStatus.SUCCESSFUL,
            country = Country.USA,
            features = FeatureSet.basic,
            twoFactorEnabled = true
        };
        harness.AccountRepo
            .ViewAccount(accountId, accountSecurityStamp)
            .Returns(Task.FromResult<AccountViewResult?>(new AccountViewResult(true, "ACCOUNT_VIEW_SUCCEEDED", profile)));

        var actionResult = await controller.ViewAccount();

        ApiResponse<AccountDetailsResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("ACCOUNT_VIEW_SUCCEEDED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_VIEW_SUCCEEDED);
        envelope.data!.profile.ShouldBeSameAs(profile);
        await harness.AccountRepo.Received(1).ViewAccount(accountId, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ViewAccount_stale_account_security_stamp_returns_unauthorized()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountRepo
            .ViewAccount(accountId, accountSecurityStamp)
            .Returns(Task.FromResult<AccountViewResult?>(new AccountViewResult(false, "ACCOUNT_SECURITY_STAMP_MISMATCH", null)));

        var actionResult = await controller.ViewAccount();

        ApiResponse<AccountDetailsResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_SECURITY_STAMP_MISMATCH);
    }

    [Fact]
    public async Task ViewAccount_missing_account_returns_not_found()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateProfileController();
        harness.HttpContext.Request.Headers["Sensitive-Action-Token"]="fresh-email-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountRepo
            .ViewAccount(accountId, accountSecurityStamp)
            .Returns(Task.FromResult<AccountViewResult?>(new AccountViewResult(false, "ACCOUNT_NOT_FOUND", null)));

        var actionResult = await controller.ViewAccount();

        ApiResponse<AccountDetailsResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status404NotFound);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_NOT_FOUND");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_NOT_FOUND);
    }

    [Fact]
    public async Task DeleteAccount_authenticated_request_returns_pending_delete()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .RequestAccountDelete(accountId, accountSecurityStamp, null,cancellationToken: Arg.Any<CancellationToken>(),grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_PENDING", DeletionWorkflow.ONETIME, "reader@example.com")));

        var actionResult = await controller.DeleteAccount(null);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status202Accepted);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("ACCOUNT_DELETE_PENDING");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_PENDING);
        await harness.AccountService.Received(1).RequestAccountDelete(accountId, accountSecurityStamp, null,cancellationToken: Arg.Any<CancellationToken>(),grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>());
    }

    [Fact]
    public async Task DeleteAccount_authenticated_passphrase_request_returns_pending_delete()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .RequestAccountDelete(accountId, accountSecurityStamp, "delete me",cancellationToken: Arg.Any<CancellationToken>(),grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_PENDING", DeletionWorkflow.PASS_PHRASE, "reader@example.com")));
        var request = new AccountDeleteRequest("  delete me  ");

        var actionResult = await controller.DeleteAccount(request);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status202Accepted);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("ACCOUNT_DELETE_PENDING");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_PENDING);
        request.passPhrase.ShouldBe("delete me");
        await harness.AccountService.Received(1).RequestAccountDelete(accountId, accountSecurityStamp, "delete me",cancellationToken: Arg.Any<CancellationToken>(),grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>());
    }

    [Fact]
    public async Task DeleteAccount_stale_account_security_stamp_returns_unauthorized()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .RequestAccountDelete(accountId, accountSecurityStamp, null,cancellationToken: Arg.Any<CancellationToken>(),grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, "ACCOUNT_SECURITY_STAMP_MISMATCH")));

        var actionResult = await controller.DeleteAccount(null);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_SECURITY_STAMP_MISMATCH);
    }

    [Fact]
    public async Task DeleteAccount_missing_account_returns_not_found()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .RequestAccountDelete(accountId, accountSecurityStamp, null,cancellationToken: Arg.Any<CancellationToken>(),grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, "ACCOUNT_NOT_FOUND")));

        var actionResult = await controller.DeleteAccount(null);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status404NotFound);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_NOT_FOUND");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_NOT_FOUND);
    }

    [Fact]
    public async Task DeleteAccount_rate_limited_returns_too_many_requests()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .RequestAccountDelete(accountId, accountSecurityStamp, null,cancellationToken: Arg.Any<CancellationToken>(),grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, "ACCOUNT_DELETE_RATE_LIMITED")));

        var actionResult = await controller.DeleteAccount(null);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status429TooManyRequests);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_DELETE_RATE_LIMITED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_RATE_LIMITED);
    }

    [Fact]
    public async Task DeleteAccount_email_delivery_failure_returns_internal_server_error()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .RequestAccountDelete(accountId, accountSecurityStamp, null,cancellationToken: Arg.Any<CancellationToken>(),grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, "ACCOUNT_DELETE_EMAIL_DELIVERY_FAILED")));

        var actionResult = await controller.DeleteAccount(null);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_DELETE_EMAIL_DELIVERY_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_EMAIL_DELIVERY_FAILED);
    }

    [Fact]
    public async Task DeleteAccount_cleanup_failure_returns_internal_server_error()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .RequestAccountDelete(accountId, accountSecurityStamp, null,cancellationToken: Arg.Any<CancellationToken>(),grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, "ACCOUNT_DELETE_REQUEST_CLEANUP_FAILED")));

        var actionResult = await controller.DeleteAccount(null);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_DELETE_REQUEST_CLEANUP_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_REQUEST_CLEANUP_FAILED);
    }

    [Fact]
    public async Task LogoffAccount_valid_body_without_auth_context_returns_unauthorized()
    {
        var controller = new AccountControllerHarness().CreateSessionController();
        var request = new AuthenticateLogoffRequest();

        var actionResult = await controller.LogoffAccount(request);

        ApiResponse<AuthenticateLogoffResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
    }

    [Fact]
    public async Task ModifyAccount_rejects_invalid_email_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateProfileController();
        var request = new AccountEditRequest("not-an-email", null);

        var actionResult = await controller.ModifyAccount(request);

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(AccountEditRequest.emailAddress));
    }

    [Fact]
    public async Task ModifyAccount_rejects_empty_username_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateProfileController();
        var request = new AccountEditRequest(null, string.Empty);

        var actionResult = await controller.ModifyAccount(request);

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(AccountEditRequest.username));
    }

    [Fact]
    public async Task ModifyAccount_rejects_overlong_username_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateProfileController();
        var request = new AccountEditRequest(null, new string('u', AccountEditRequest.MaxUsernameLength + 1));

        var actionResult = await controller.ModifyAccount(request);

        ApiResponse<AccountEditResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(AccountEditRequest.username));
    }

    [Fact]
    public async Task DeleteAccount_rejects_blank_passphrase_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateDeleteController();
        var request = new AccountDeleteRequest("   ");

        var actionResult = await controller.DeleteAccount(request);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(AccountDeleteRequest.passPhrase));
    }

    [Fact]
    public async Task DeleteAccount_rejects_overlong_passphrase_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateDeleteController();
        var request = new AccountDeleteRequest(new string('p', AccountDeleteRequest.MaxPassPhraseLength + 1));

        var actionResult = await controller.DeleteAccount(request);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(AccountDeleteRequest.passPhrase));
    }


    [Fact]
    public void Deletion_mailbox_GET_is_read_only_encoded_and_uses_private_confirmation_headers()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        var response = controller.DeleteAccountConfirmation("\"><script>proof</script>");
        response.StatusCode.ShouldBe(200);
        response.Content.ShouldNotContain("<script>");
        response.Content.ShouldContain("name=\"operationKey\"");
        response.Content.ShouldContain("name=\"operationRecovery\"");
        harness.AccountService.ReceivedCalls().ShouldBeEmpty();
        harness.HttpContext.Response.Headers["Cache-Control"].ToString().ShouldBe("no-store");
        harness.HttpContext.Response.Headers["Referrer-Policy"].ToString().ShouldBe("no-referrer");
        harness.HttpContext.Response.Headers["Content-Security-Policy"].ToString().ShouldContain("form-action 'self'");
        controller.DeleteAccountConfirmation(" ").StatusCode.ShouldBe(400);
        controller.DeleteAccountConfirmation(new string('x', 513)).StatusCode.ShouldBe(400);
    }

    [Fact]
    public async Task VerifyDeleteAccount_valid_token_returns_verified()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        harness.AccountService
            .VerifyAccountDeleteToken("delete-token")
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_VERIFIED", DeletionWorkflow.ONETIME)));

        var actionResult = await controller.VerifyDeleteAccount("delete-token");

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("ACCOUNT_DELETE_VERIFIED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_VERIFIED);
        envelope.data!.workflow.ShouldBe(DeletionWorkflow.ONETIME);
        await harness.AccountService.Received(1).VerifyAccountDeleteToken("delete-token", cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyDeleteAccount_rejects_missing_payload_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateDeleteController();

        var actionResult = await controller.VerifyDeleteAccount("   ");

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, "payload");
    }

    [Fact]
    public async Task VerifyDeleteAccount_expired_token_returns_bad_request()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        harness.AccountService
            .VerifyAccountDeleteToken("delete-token")
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, "ACCOUNT_DELETE_TOKEN_EXPIRED")));

        var actionResult = await controller.VerifyDeleteAccount("delete-token");

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_DELETE_TOKEN_EXPIRED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_TOKEN_EXPIRED);
    }

    [Fact]
    public async Task VerifyDeleteAccount_public_token_throttle_returns_too_many_requests()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        harness.AccountService
            .VerifyAccountDeleteToken("delete-token")
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded)));

        var actionResult = await controller.VerifyDeleteAccount("delete-token");

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status429TooManyRequests);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded);
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_ATTEMPT_LIMITED);
    }

    [Fact]
    public async Task VerifyDeleteAccount_counter_store_unavailable_returns_service_unavailable()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        harness.AccountService
            .VerifyAccountDeleteToken("delete-token")
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, AbuseReasonCodes.CounterStoreUnavailable)));

        var actionResult = await controller.VerifyDeleteAccount("delete-token");

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status503ServiceUnavailable);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(AbuseReasonCodes.CounterStoreUnavailable);
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_FAILED);
    }

    [Fact]
    public async Task VerifyDeleteAccount_oversized_payload_returns_validation_failed()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        string payload = new('x', AccountDeleteVerifyRequest.MaxDeleteTokenLength + 1);

        var actionResult = await controller.VerifyDeleteAccount(payload);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, "payload");
        await harness.AccountService.DidNotReceive().VerifyAccountDeleteToken(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task FinalizeDeleteAccount_without_auth_context_returns_unauthorized()
    {
        var controller = new AccountControllerHarness().CreateDeleteController();
        var request = new AccountDeleteFinalizeRequest("delete-token");

        var actionResult = await controller.FinalizeDeleteAccount(request);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
    }

    [Fact]
    public async Task FinalizeDeleteAccount_authenticated_verified_token_returns_success_and_clear_token_header()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        string accessHash = "active-access-hash";
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp, accessHash);
        harness.AccountService
            .FinalizeAccountDelete(accountId, accountSecurityStamp, "delete-token", null,cancellationToken: Arg.Any<CancellationToken>(),sessionHash: Arg.Any<string>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_SUCCEEDED", DeletionWorkflow.NONE, null, accountId)));
        harness.ActiveUserCacheService.RevokeSession(accessHash, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        var request = new AccountDeleteFinalizeRequest("  delete-token  ");

        var actionResult = await controller.FinalizeDeleteAccount(request);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("ACCOUNT_DELETE_SUCCEEDED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_SUCCEEDED);
        request.deleteToken.ShouldBe("delete-token");
        controller.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        await harness.AccountService.Received(1).FinalizeAccountDelete(accountId, accountSecurityStamp, "delete-token", null,cancellationToken: Arg.Any<CancellationToken>(),sessionHash: Arg.Any<string>());
        await harness.ActiveUserCacheService.Received(1).RevokeSession(accessHash, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task FinalizeDeleteAccount_with_passphrase_sends_trimmed_passphrase_to_service()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .FinalizeAccountDelete(accountId, accountSecurityStamp, "delete-token", "secret",cancellationToken: Arg.Any<CancellationToken>(),sessionHash: Arg.Any<string>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_SUCCEEDED", DeletionWorkflow.NONE, null, accountId)));
        var request = new AccountDeleteFinalizeRequest("delete-token", "  secret  ");

        var actionResult = await controller.FinalizeDeleteAccount(request);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.code.ShouldBe("ACCOUNT_DELETE_SUCCEEDED");
        request.passPhrase.ShouldBe("secret");
        await harness.AccountService.Received(1).FinalizeAccountDelete(accountId, accountSecurityStamp, "delete-token", "secret",cancellationToken: Arg.Any<CancellationToken>(),sessionHash: Arg.Any<string>());
    }

    [Fact]
    public async Task FinalizeDeleteAccount_verify_required_returns_bad_request()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .FinalizeAccountDelete(accountId, accountSecurityStamp, "delete-token", null,cancellationToken: Arg.Any<CancellationToken>(),sessionHash: Arg.Any<string>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, "ACCOUNT_DELETE_VERIFY_REQUIRED")));

        var actionResult = await controller.FinalizeDeleteAccount(new AccountDeleteFinalizeRequest("delete-token"));

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_DELETE_VERIFY_REQUIRED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_VERIFY_REQUIRED);
    }

    [Fact]
    public async Task FinalizeDeleteAccount_valid_token_for_different_account_returns_token_mismatch()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .FinalizeAccountDelete(accountId, accountSecurityStamp, "delete-token", null,cancellationToken: Arg.Any<CancellationToken>(),sessionHash: Arg.Any<string>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, "ACCOUNT_DELETE_TOKEN_MISMATCH")));

        var actionResult = await controller.FinalizeDeleteAccount(new AccountDeleteFinalizeRequest("delete-token"));

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_DELETE_TOKEN_MISMATCH");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_TOKEN_MISMATCH);
    }

    [Fact]
    public async Task FinalizeDeleteAccount_attempt_limited_returns_too_many_requests()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .FinalizeAccountDelete(accountId, accountSecurityStamp, "delete-token", "secret",cancellationToken: Arg.Any<CancellationToken>(),sessionHash: Arg.Any<string>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, "ACCOUNT_DELETE_ATTEMPT_LIMITED")));

        var actionResult = await controller.FinalizeDeleteAccount(new AccountDeleteFinalizeRequest("delete-token", "secret"));

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status429TooManyRequests);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_DELETE_ATTEMPT_LIMITED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_ATTEMPT_LIMITED);
    }

    [Fact]
    public async Task FinalizeDeleteAccount_abuse_finalize_throttle_returns_too_many_requests()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .FinalizeAccountDelete(accountId, accountSecurityStamp, "delete-token", null,cancellationToken: Arg.Any<CancellationToken>(),sessionHash: Arg.Any<string>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, AbuseReasonCodes.AccountDeleteFinalizeAttemptsExceeded)));

        var actionResult = await controller.FinalizeDeleteAccount(new AccountDeleteFinalizeRequest("delete-token"));

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status429TooManyRequests);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(AbuseReasonCodes.AccountDeleteFinalizeAttemptsExceeded);
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_ATTEMPT_LIMITED);
    }

    [Fact]
    public async Task FinalizeDeleteAccount_counter_store_unavailable_returns_service_unavailable()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .FinalizeAccountDelete(accountId, accountSecurityStamp, "delete-token", null,cancellationToken: Arg.Any<CancellationToken>(),sessionHash: Arg.Any<string>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, AbuseReasonCodes.CounterStoreUnavailable)));

        var actionResult = await controller.FinalizeDeleteAccount(new AccountDeleteFinalizeRequest("delete-token"));

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status503ServiceUnavailable);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(AbuseReasonCodes.CounterStoreUnavailable);
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_DELETE_FAILED);
    }

    [Fact]
    public async Task FinalizeDeleteAccount_stale_account_security_stamp_returns_unauthorized()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateDeleteController();
        harness.HttpContext.Request.Headers[SensitiveActionTokenConstants.HeaderName]="fresh-proof";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.SetAuthenticatedSession(accountId, accountSecurityStamp);
        harness.AccountService
            .FinalizeAccountDelete(accountId, accountSecurityStamp, "delete-token", null,cancellationToken: Arg.Any<CancellationToken>(),sessionHash: Arg.Any<string>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, "ACCOUNT_SECURITY_STAMP_MISMATCH")));

        var actionResult = await controller.FinalizeDeleteAccount(new AccountDeleteFinalizeRequest("delete-token"));

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.ACCOUNT_SECURITY_STAMP_MISMATCH);
    }

    [Fact]
    public async Task FinalizeDeleteAccount_rejects_missing_delete_token_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateDeleteController();
        var request = new AccountDeleteFinalizeRequest("   ");

        var actionResult = await controller.FinalizeDeleteAccount(request);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(AccountDeleteFinalizeRequest.deleteToken));
    }

    [Fact]
    public async Task FinalizeDeleteAccount_rejects_blank_passphrase_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateDeleteController();
        var request = new AccountDeleteFinalizeRequest("delete-token", "   ");

        var actionResult = await controller.FinalizeDeleteAccount(request);

        ApiResponse<AccountDeleteResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(AccountDeleteFinalizeRequest.passPhrase));
    }

    private static void AssertHasValidationErrorFor<T>(ApiResponse<T> envelope, string field)
    {
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.ShouldContain(error => error.field == field);
    }


    [Fact]
    public void Account_verification_public_get_rejects_unbounded_token_length_before_lookup()
    {
        string controller = ReadAccountControllerSources();

        controller.ShouldContain("MaxPublicAccountVerificationTokenLength = 512");
        controller.ShouldContain("verifyToken.Length > MaxPublicAccountVerificationTokenLength");
        controller.ShouldContain("return AccountVerificationContent(_unsuccessfulAccountVerifyHtml);");
    }

    private static void AssertHasValidationErrors<T>(ApiResponse<T> envelope)
    {
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.ShouldNotBeEmpty();
        envelope.errors.ShouldContain(error => error.field == string.Empty);
    }

    private static string ReadAccountControllerSources()
    {
        string controllerDirectory = ProjectFile("Controllers");
        return string.Join(
            Environment.NewLine,
            Directory.GetFiles(controllerDirectory, "Account*Controller*.cs")
                .OrderBy(path => path, StringComparer.Ordinal)
                .Select(File.ReadAllText));
    }

    private static string ProjectFile(params string[] relativePathParts)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return Path.Combine(new[] { directory.FullName }.Concat(relativePathParts).ToArray());
    }
}

