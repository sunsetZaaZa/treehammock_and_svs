using Microsoft.AspNetCore.Http;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.Controllers;
using treehammock.Entities;
using treehammock.Models.Account;
using treehammock.Models.Api;
using treehammock.Rigging.Security;
using treehammock.Rigging.Abuse;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class AccountControllerSetupVerificationTests
{
    [Fact]
    public async Task AccountSetup_rejects_invalid_password_without_calling_service()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountCreationRequest("reader@example.com", "reader", "short", Country.USA);

        var actionResult = await controller.AccountSetup(payload);

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors.ShouldContain(error => error.field == nameof(AccountCreationRequest.password));
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_PASSWORD_REQUIREMENT);
        _ = harness.AccountService.DidNotReceiveWithAnyArgs().SetupUserAccount(default!, default, default!, default, default, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AccountSetup_rejects_invalid_email_without_calling_service()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountCreationRequest("not-an-email", "reader", "ValidPassword1!", Country.USA);

        var actionResult = await controller.AccountSetup(payload);

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors.ShouldContain(error => error.field == nameof(AccountCreationRequest.emailAddress));
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_FAILED);
        _ = harness.AccountService.DidNotReceiveWithAnyArgs().SetupUserAccount(default!, default, default!, default, default, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AccountSetup_rejects_supplied_short_username_without_falling_back_to_email_only()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountCreationRequest("reader@example.com", "ab", "ValidPassword1!", Country.USA);

        var actionResult = await controller.AccountSetup(payload);

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors.ShouldContain(error => error.field == nameof(AccountCreationRequest.username));
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_FAILED);
        _ = harness.AccountService.DidNotReceiveWithAnyArgs().SetupUserAccount(default!, default, default!, default, default, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AccountSetup_rejects_country_none_without_calling_service()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountCreationRequest("reader@example.com", "reader", "ValidPassword1!", Country.NONE);

        var actionResult = await controller.AccountSetup(payload);

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors.ShouldContain(error => error.field == nameof(AccountCreationRequest.country));
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_FAILED);
        _ = harness.AccountService.DidNotReceiveWithAnyArgs().SetupUserAccount(default!, default, default!, default, default, default, cancellationToken: Arg.Any<CancellationToken>());
    }


    [Fact]
    public async Task AccountSetup_rejects_unknown_country_without_calling_service()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountCreationRequest("reader@example.com", "reader", "ValidPassword1!", (Country)999);

        var actionResult = await controller.AccountSetup(payload);

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors.ShouldContain(error => error.field == nameof(AccountCreationRequest.country));
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_FAILED);
        _ = harness.AccountService.DidNotReceiveWithAnyArgs().SetupUserAccount(default!, default, default!, default, default, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task AccountSetup_allows_email_only_when_username_is_missing_or_blank(string? username)
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountCreationRequest("reader@example.com", username!, "ValidPassword1!", Country.USA);
        harness.AccountService.SetupUserAccount(payload.emailAddress, null, payload.password, payload.country, Arg.Any<Instant>(), AccountSetupAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(HttpMessage.ACCOUNT_CREATION_SUCCESSED));

        var actionResult = await controller.AccountSetup(payload);

        var response = AccountControllerHarness.ExtractData(actionResult);
        response.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_SUCCESSED);
        response.createdOn.ShouldNotBeNull();
        await harness.AccountService.Received(1).SetupUserAccount(payload.emailAddress, null, payload.password, payload.country, Arg.Any<Instant>(), AccountSetupAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AccountSetup_returns_duplicate_email_from_service()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountCreationRequest("reader@example.com", "reader", "ValidPassword1!", Country.USA);
        harness.AccountService.SetupUserAccount(payload.emailAddress, payload.username, payload.password, payload.country, Arg.Any<Instant>(), AccountSetupAction.BOTH, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL));

        var actionResult = await controller.AccountSetup(payload);

        var response = AccountControllerHarness.ExtractData(actionResult);
        response.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL);
        response.createdOn.ShouldBeNull();
    }

    [Fact]
    public async Task AccountSetup_returns_duplicate_username_from_service()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountCreationRequest("reader@example.com", "reader", "ValidPassword1!", Country.USA);
        harness.AccountService.SetupUserAccount(payload.emailAddress, payload.username, payload.password, payload.country, Arg.Any<Instant>(), AccountSetupAction.BOTH, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME));

        var actionResult = await controller.AccountSetup(payload);

        var response = AccountControllerHarness.ExtractData(actionResult);
        response.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME);
        response.createdOn.ShouldBeNull();
    }


    [Fact]
    public async Task AccountSetup_service_failure_returns_500_envelope()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountCreationRequest("reader@example.com", "reader", "ValidPassword1!", Country.USA);
        harness.AccountService.SetupUserAccount(payload.emailAddress, payload.username, payload.password, payload.country, Arg.Any<Instant>(), AccountSetupAction.BOTH, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(HttpMessage.ACCOUNT_CREATION_FAILED));

        var actionResult = await controller.AccountSetup(payload);

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.ACCOUNT_CREATION_FAILED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_FAILED);
        envelope.data.createdOn.ShouldBeNull();
    }

    [Fact]
    public async Task AccountSetup_verification_failure_returns_500_envelope()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountCreationRequest("reader@example.com", "reader", "ValidPassword1!", Country.USA);
        harness.AccountService.SetupUserAccount(payload.emailAddress, payload.username, payload.password, payload.country, Arg.Any<Instant>(), AccountSetupAction.BOTH, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED));

        var actionResult = await controller.AccountSetup(payload);

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED);
        envelope.data.createdOn.ShouldBeNull();
    }

    [Fact]
    public async Task AccountSetup_pending_verification_returns_accepted_with_createdOn()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountCreationRequest("reader@example.com", "reader", "ValidPassword1!", Country.USA);
        harness.AccountService.SetupUserAccount(payload.emailAddress, payload.username, payload.password, payload.country, Arg.Any<Instant>(), AccountSetupAction.BOTH, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING));

        var actionResult = await controller.AccountSetup(payload);

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status202Accepted);
        response.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING);
        response.createdOn.ShouldNotBeNull();
    }

    [Fact]
    public async Task AccountSetup_returns_success_createdOn_when_service_succeeds()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountCreationRequest("reader@example.com", "reader", "ValidPassword1!", Country.USA);
        harness.AccountService.SetupUserAccount(payload.emailAddress, payload.username, payload.password, payload.country, Arg.Any<Instant>(), AccountSetupAction.BOTH, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(HttpMessage.ACCOUNT_CREATION_SUCCESSED));

        var actionResult = await controller.AccountSetup(payload);

        var response = AccountControllerHarness.ExtractData(actionResult);
        response.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_SUCCESSED);
        response.createdOn.ShouldNotBeNull();
    }

    [Fact]
    public async Task ResendAccountVerification_valid_email_returns_accepted_resend_status()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountVerificationResendRequest("reader@example.com");
        harness.AccountService.ResendAccountVerification(payload.emailAddress, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(HttpMessage.ACCOUNT_CREATION_VERIFICATION_RESENT));

        var actionResult = await controller.ResendAccountVerification(payload);

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status202Accepted);
        envelope.code.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_RESENT.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_RESENT);
        await harness.AccountService.Received(1).ResendAccountVerification(payload.emailAddress, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ResendAccountVerification_rejects_invalid_email_without_calling_service()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountVerificationResendRequest("not-an-email");

        var actionResult = await controller.ResendAccountVerification(payload);

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors.ShouldContain(error => error.field == nameof(AccountVerificationResendRequest.emailAddress));
        _ = harness.AccountService.DidNotReceiveWithAnyArgs().ResendAccountVerification(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAccountCreation_valid_token_before_expiration_marks_account_verified()
    {
        var harness = new AccountControllerHarness();
        var token = "verify-token";
        var record = new AccountVerification(
            Guid.NewGuid(),
            AccountVerificationTokenUtility.HashToken(token),
            VerificationStatus.SENT,
            SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(10)),
            Period.FromHours(1)) { proofVersion = Guid.NewGuid(), accountSecurityStamp = Guid.NewGuid() };
        harness.AccountRepo.VerifyAccountForUse(token, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<AccountVerification?>(record));
        harness.AccountRepo.AccountPassedVerification(Arg.Any<AccountVerification>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        var controller = harness.CreateRegistrationController();

        var htmlResult = await controller.VerifyAccountCreation(token);

        string html = htmlResult.Content!;

        html.ShouldBe(AccountControllerBase.HTML_SUCCESSFUL_ACCOUNT_VERIFY);
        await harness.AccountRepo.Received(1).AccountPassedVerification(Arg.Is<AccountVerification>(v =>
            v.accountId == record.accountId &&
            v.verifyStatus == VerificationStatus.SENT &&
            v.sentWhen == record.sentWhen &&
            v.expiration == record.expiration &&
            v.proofVersion == record.proofVersion &&
            v.accountSecurityStamp == record.accountSecurityStamp), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAccountCreation_expired_token_marks_verification_expired()
    {
        var harness = new AccountControllerHarness();
        var token = "verify-token";
        var record = new AccountVerification(
            Guid.NewGuid(),
            AccountVerificationTokenUtility.HashToken(token),
            VerificationStatus.SENT,
            SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromHours(2)),
            Period.FromMinutes(30));
        harness.AccountRepo.VerifyAccountForUse(token, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<AccountVerification?>(record));
        harness.AccountRepo.AccountVerificationExpired(Arg.Any<AccountVerification>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        var controller = harness.CreateRegistrationController();

        var htmlResult = await controller.VerifyAccountCreation(token);

        string html = htmlResult.Content!;

        html.ShouldBe(AccountControllerBase.HTML_EXPIRED_ACCOUNT_VERIFY);
        await harness.AccountRepo.Received(1).AccountVerificationExpired(Arg.Is<AccountVerification>(v =>
            v.accountId == record.accountId &&
            v.verifyStatus == VerificationStatus.SENT &&
            v.proofVersion == record.proofVersion &&
            v.accountSecurityStamp == record.accountSecurityStamp), cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().AccountPassedVerification(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAccountCreation_already_verified_token_returns_deterministic_status_without_rewriting_record()
    {
        var harness = new AccountControllerHarness();
        var token = "verify-token";
        var record = new AccountVerification(
            Guid.NewGuid(),
            AccountVerificationTokenUtility.HashToken(token),
            VerificationStatus.SUCCESSFUL,
            SystemClock.Instance.GetCurrentInstant(),
            Period.FromHours(1));
        harness.AccountRepo.VerifyAccountForUse(token, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<AccountVerification?>(record));
        var controller = harness.CreateRegistrationController();

        var htmlResult = await controller.VerifyAccountCreation(token);

        string html = htmlResult.Content!;

        html.ShouldBe(AccountControllerBase.HTML_ALREADY_VERIFIED_ACCOUNT_VERIFY);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().AccountPassedVerification(default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().AccountVerificationExpired(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ResendAccountVerification_email_delivery_pending_uses_pending_code()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        var payload = new AccountVerificationResendRequest("reader@example.com");
        harness.AccountService.ResendAccountVerification(payload.emailAddress, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING));

        var actionResult = await controller.ResendAccountVerification(payload);

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status202Accepted);
        envelope.code.ShouldBe("ACCOUNT_CREATION_VERIFICATION_PENDING");
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task VerifyAccountCreation_rejects_blank_payload_without_repo_lookup(string? payload)
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();

        var htmlResult = await controller.VerifyAccountCreation(payload!);

        htmlResult.Content.ShouldBe(AccountControllerBase.HTML_UNSUCCESSFUL_ACCOUNT_VERIFY);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().VerifyAccountForUse(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAccountCreation_unknown_token_returns_failure_page()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateRegistrationController();
        harness.AccountRepo.VerifyAccountForUse("unknown-token", cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountVerification?>(null));

        var htmlResult = await controller.VerifyAccountCreation("unknown-token");

        htmlResult.Content.ShouldBe(AccountControllerBase.HTML_UNSUCCESSFUL_ACCOUNT_VERIFY);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().AccountPassedVerification(default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().AccountVerificationExpired(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAccountCreation_record_already_expired_returns_expired_page_without_rewriting_record()
    {
        var harness = new AccountControllerHarness();
        var token = "verify-token";
        var record = new AccountVerification(
            Guid.NewGuid(),
            AccountVerificationTokenUtility.HashToken(token),
            VerificationStatus.EXPIRED,
            SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromHours(2)),
            Period.FromMinutes(30));
        harness.AccountRepo.VerifyAccountForUse(token, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<AccountVerification?>(record));
        var controller = harness.CreateRegistrationController();

        var htmlResult = await controller.VerifyAccountCreation(token);

        htmlResult.Content.ShouldBe(AccountControllerBase.HTML_EXPIRED_ACCOUNT_VERIFY);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().AccountPassedVerification(default!, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().AccountVerificationExpired(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAccountCreation_mismatched_token_hash_returns_failure_page_without_completing()
    {
        var harness = new AccountControllerHarness();
        var token = "verify-token";
        var record = new AccountVerification(
            Guid.NewGuid(),
            AccountVerificationTokenUtility.HashToken("different-token"),
            VerificationStatus.SENT,
            SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(10)),
            Period.FromHours(1));
        harness.AccountRepo.VerifyAccountForUse(token, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<AccountVerification?>(record));
        var controller = harness.CreateRegistrationController();

        var htmlResult = await controller.VerifyAccountCreation(token);

        htmlResult.Content.ShouldBe(AccountControllerBase.HTML_UNSUCCESSFUL_ACCOUNT_VERIFY);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().AccountPassedVerification(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAccountCreation_completion_failure_returns_failure_page()
    {
        var harness = new AccountControllerHarness();
        var token = "verify-token";
        var record = new AccountVerification(
            Guid.NewGuid(),
            AccountVerificationTokenUtility.HashToken(token),
            VerificationStatus.REFRESHED,
            SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(10)),
            Period.FromHours(1));
        harness.AccountRepo.VerifyAccountForUse(token, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<AccountVerification?>(record));
        harness.AccountRepo.AccountPassedVerification(Arg.Any<AccountVerification>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(false));
        var controller = harness.CreateRegistrationController();

        var htmlResult = await controller.VerifyAccountCreation(token);

        htmlResult.Content.ShouldBe(AccountControllerBase.HTML_UNSUCCESSFUL_ACCOUNT_VERIFY);
        await harness.AccountRepo.Received(1).AccountPassedVerification(Arg.Any<AccountVerification>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAccountCreation_expired_token_returns_failure_page_when_expiration_persistence_fails()
    {
        var harness = new AccountControllerHarness();
        var token = "verify-token";
        var record = new AccountVerification(
            Guid.NewGuid(),
            AccountVerificationTokenUtility.HashToken(token),
            VerificationStatus.SENT,
            SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromHours(2)),
            Period.FromMinutes(30));
        harness.AccountRepo.VerifyAccountForUse(token, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<AccountVerification?>(record));
        harness.AccountRepo.AccountVerificationExpired(Arg.Any<AccountVerification>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(false));
        var controller = harness.CreateRegistrationController();

        var htmlResult = await controller.VerifyAccountCreation(token);

        htmlResult.Content.ShouldBe(AccountControllerBase.HTML_UNSUCCESSFUL_ACCOUNT_VERIFY);
        await harness.AccountRepo.Received(1).AccountVerificationExpired(Arg.Any<AccountVerification>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAccountCreation_uses_configured_success_html_template_when_available()
    {
        var harness = new AccountControllerHarness();
        string templatePath = Path.Combine(Path.GetTempPath(), $"account-verify-success-{Guid.NewGuid():N}.html");
        string expectedHtml = "<html><body><h1>Custom verified page</h1></body></html>";
        await File.WriteAllTextAsync(templatePath, expectedHtml);
        harness.EmailTemplateSettings.AccountVerificationSuccessPage = templatePath;

        try
        {
            var token = "verify-token";
            var record = new AccountVerification(
                Guid.NewGuid(),
                AccountVerificationTokenUtility.HashToken(token),
                VerificationStatus.SENT,
                SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(10)),
                Period.FromHours(1));
            harness.AccountRepo.VerifyAccountForUse(token, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<AccountVerification?>(record));
            harness.AccountRepo.AccountPassedVerification(Arg.Any<AccountVerification>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
            var controller = harness.CreateRegistrationController();

            var htmlResult = await controller.VerifyAccountCreation(token);

            htmlResult.Content.ShouldBe(expectedHtml);
        }
        finally
        {
            if (File.Exists(templatePath))
            {
                File.Delete(templatePath);
            }
        }
    }

    [Fact]
    public async Task VerifyAccountCreation_falls_back_to_constant_when_configured_template_is_missing()
    {
        var harness = new AccountControllerHarness();
        harness.EmailTemplateSettings.AccountVerificationFailurePage = Path.Combine(Path.GetTempPath(), $"missing-account-verify-{Guid.NewGuid():N}.html");
        harness.AccountRepo.VerifyAccountForUse("unknown-token", cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<AccountVerification?>(null));
        var controller = harness.CreateRegistrationController();

        var htmlResult = await controller.VerifyAccountCreation("unknown-token");

        htmlResult.Content.ShouldBe(AccountControllerBase.HTML_UNSUCCESSFUL_ACCOUNT_VERIFY);
    }

    [Fact]
    public async Task VerifyAccountCreation_abuse_denial_returns_failure_page_without_repo_lookup()
    {
        var harness = new AccountControllerHarness();
        harness.AbuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(
                Allowed: false,
                CurrentCount: 11,
                Limit: 10,
                Window: TimeSpan.FromMinutes(15),
                RetryAfter: TimeSpan.FromMinutes(15),
                ReasonCode: AbuseReasonCodes.CounterLimitExceeded)));
        var controller = harness.CreateRegistrationController();

        var htmlResult = await controller.VerifyAccountCreation("verify-token");

        htmlResult.Content.ShouldBe(AccountControllerBase.HTML_UNSUCCESSFUL_ACCOUNT_VERIFY);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().VerifyAccountForUse(default!, cancellationToken: Arg.Any<CancellationToken>());
    }


}
