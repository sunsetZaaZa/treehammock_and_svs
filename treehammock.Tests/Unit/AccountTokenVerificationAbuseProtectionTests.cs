using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.Models.Account;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class AccountTokenVerificationAbuseProtectionTests
{
    [Fact]
    public void Account_token_verification_key_factory_uses_safe_fingerprints_for_public_tokens()
    {
        var factory = new AccountTokenVerificationAbuseCounterKeyFactory();

        AbuseCounterKey token = factory.ForPublicToken("email-change", "raw-email-change-token");
        AbuseCounterKey ip = factory.ForPublicIpAddress("account-delete", "203.0.113.42");

        token.Feature.ShouldBe(AbuseFeature.PublicTokenVerification);
        token.Dimension.ShouldBe(AbuseCounterDimension.TokenFingerprint);
        token.Value.ShouldStartWith("abuse:publictokenverification:tokenfingerprint:email-change-");
        token.Value.ShouldNotContain("raw-email-change-token");
        token.Value.ShouldNotContain("email-change-token");

        ip.Feature.ShouldBe(AbuseFeature.PublicTokenVerification);
        ip.Dimension.ShouldBe(AbuseCounterDimension.IpFingerprint);
        ip.Value.ShouldStartWith("abuse:publictokenverification:ipfingerprint:account-delete-");
        ip.Value.ShouldNotContain("203.0.113.42");
    }

    [Fact]
    public void Account_token_verification_key_factory_uses_safe_fingerprints_for_delete_finalize_tokens()
    {
        var factory = new AccountTokenVerificationAbuseCounterKeyFactory();
        Guid accountId = Guid.NewGuid();

        AbuseCounterKey account = factory.ForAccountDeleteFinalizeAccount(accountId);
        AbuseCounterKey token = factory.ForAccountDeleteFinalizeToken("raw-delete-token");

        account.Feature.ShouldBe(AbuseFeature.AccountDeleteFinalize);
        account.Dimension.ShouldBe(AbuseCounterDimension.Account);
        account.Value.ShouldContain(accountId.ToString("N"));

        token.Feature.ShouldBe(AbuseFeature.AccountDeleteFinalize);
        token.Dimension.ShouldBe(AbuseCounterDimension.TokenFingerprint);
        token.Value.ShouldNotContain("raw-delete-token");
        token.Value.ShouldNotContain("delete-token");
    }

    [Fact]
    public async Task CompleteEmailChange_denies_before_repository_lookup_when_public_token_policy_is_exhausted()
    {
        var harness = CreateHarness();
        harness.AbuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(false, 11, 10, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15), AbuseReasonCodes.CounterLimitExceeded)));

        AccountAdjustResult? result = await harness.Service.CompleteEmailChange("raw-email-change-token");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeFalse();
        result.Code.ShouldBe(AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded);
        await harness.AccountRepo.DidNotReceive().CompleteEmailChange(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAccountDeleteToken_denies_before_repository_lookup_when_public_token_policy_is_exhausted()
    {
        var harness = CreateHarness();
        harness.AbuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(false, 11, 10, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15), AbuseReasonCodes.CounterLimitExceeded)));

        AccountDeleteCommandResult? result = await harness.Service.VerifyAccountDeleteToken("raw-delete-token");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeFalse();
        result.Code.ShouldBe(AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded);
        await harness.AccountRepo.DidNotReceive().VerifyDeleteAccountToken(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task FinalizeAccountDelete_denies_before_repository_lookup_when_delete_finalize_policy_is_exhausted()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.AbuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(false, 6, 5, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15), AbuseReasonCodes.CounterLimitExceeded)));

        AccountDeleteCommandResult? result = await harness.Service.FinalizeAccountDelete(accountId, accountSecurityStamp, "raw-delete-token", "secret");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeFalse();
        result.Code.ShouldBe(AbuseReasonCodes.AccountDeleteFinalizeAttemptsExceeded);
        await harness.AccountRepo.DidNotReceive().FinalizeAccountDelete(
            Arg.Any<Guid>(),
            Arg.Any<Guid>(),
            Arg.Any<string>(),
            Arg.Any<string?>(),
            Arg.Any<short>(),
            Arg.Any<Period>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task FinalizeAccountDelete_resets_account_and_token_counters_after_success()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.AccountRepo.FinalizeAccountDelete(
                accountId,
                accountSecurityStamp,
                Arg.Any<string>(),
                Arg.Any<string?>(),
                Arg.Any<short>(),
                Arg.Any<Period>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_SUCCEEDED")));

        AccountDeleteCommandResult? result = await harness.Service.FinalizeAccountDelete(accountId, accountSecurityStamp, "raw-delete-token", null);

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        await harness.AbuseCounterStore.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.AccountDeleteFinalize && key.Dimension == AbuseCounterDimension.Account),
            Arg.Any<CancellationToken>());
        await harness.AbuseCounterStore.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.AccountDeleteFinalize && key.Dimension == AbuseCounterDimension.TokenFingerprint),
            Arg.Any<CancellationToken>());
    }

    private static Harness CreateHarness()
    {
        var accountRepo = Substitute.For<IAccountRepo>();
        var smtpService = Substitute.For<ISMTPService>();
        var userSecretHasher = Substitute.For<IUserSecretHasher>();
        var deliveryThrottle = Substitute.For<IDeliveryAbuseThrottleService>();
        deliveryThrottle.ShouldAllowDeliveryAsync(Arg.Any<DeliveryAbuseThrottleRequest>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(AbuseDecision.Allow()));
        var abuseCounterStore = Substitute.For<IAbuseCounterStore>();
        abuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(true, 1, limit.MaxAttempts, limit.Window, null, null));
            });
        abuseCounterStore.ResetAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        var loginSettings = new LoginSettings
        {
            PasswordRetryLimit = 3,
            TwoAuthRetryLimit = 3,
            Argon2Iterations = 3,
            Argon2MemoryBytes = 67108864
        };
        var registrationSettings = new RegistrationSettings
        { PublicOrigin = "http://localhost.test",
            MinUsernameLength = 3,
            MaxUsernameLength = 30,
            MinPasswordLength = 8,
            MaxPasswordLength = 128,
            MaxEmailAddressLength = 255,
            AccountMetaDataRetries = 3,
            VerifyAccountPeriodWeeks = 0,
            VerifyAccountPeriodDays = 1,
            VerifyAccountPeriodHours = 0,
            EmailChangeVerifyPeriodWeeks = 0,
            EmailChangeVerifyPeriodDays = 1,
            EmailChangeVerifyPeriodHours = 0,
            AccountDeleteTokenPeriodWeeks = 0,
            AccountDeleteTokenPeriodDays = 1,
            AccountDeleteTokenPeriodHours = 0,
            DeleteRequestCooldownMinutes = 15,
            DeleteRequestWindowHours = 24,
            DeleteMaxRequestsPerWindow = 8,
            DeleteMaxFinalizeFailures = 5,
            DeleteFinalizeLockoutMinutes = 30
        };
        var emailSubjects = new EmailSubjectSettings();
        var httpContextAccessor = new HttpContextAccessor
        {
            HttpContext = new DefaultHttpContext()
        };
        httpContextAccessor.HttpContext.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.42");

        var service = new AccountService(new treehammock.Tests.Infrastructure.CapturingDurableDelivery(),
            accountRepo,
            Options.Create(loginSettings),
            Options.Create(registrationSettings),
            Options.Create(emailSubjects),
            userSecretHasher,
            new AccountTokenVerificationAbuseCounterKeyFactory(),
            abuseCounterStore,
            Options.Create(new AbuseControlSettings()),
            httpContextAccessor);

        return new Harness(service, accountRepo, abuseCounterStore);
    }

    private sealed record Harness(
        AccountService Service,
        IAccountRepo AccountRepo,
        IAbuseCounterStore AbuseCounterStore);
}
