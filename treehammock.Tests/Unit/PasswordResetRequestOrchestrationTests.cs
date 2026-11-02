using treehammock.Rigging.Delivery;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;

using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using treehammock.Services;
using treehammock.Models.PasswordReset;

namespace treehammock.Tests.Unit;

public class PasswordResetRequestOrchestrationTests
{
    [Fact]
    public async Task RequestReset_returns_generic_accepted_for_unknown_account_without_creating_or_delivering_reset()
    {
        Harness harness = CreateHarness();
        harness.AllowRateLimits();
        harness.Repo.LookupPasswordResetAccountAsync("reader@example.com", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetAccountLookupResult?>(new PasswordResetAccountLookupResult(
                false,
                "PASSWORD_RESET_ACCOUNT_NOT_FOUND",
                null,
                null,
                null,
                null,
                null,
                false,
                false,
                false)));

        PasswordResetRequestResult result = await harness.Service.RequestReset(
            new RequestPasswordResetCommand("reader@example.com", PasswordResetDeliveryChannels.Email, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        result.ResetId.ShouldNotBe(Guid.Empty);
        await harness.Repo.DidNotReceiveWithAnyArgs().CreatePasswordResetRequestAsync(default!, default);
        await harness.Delivery.DidNotReceiveWithAnyArgs().StageAsync(default!, default!, default);
    }

    [Fact]
    public async Task RequestReset_creates_reset_row_and_sends_email_when_email_channel_is_eligible()
    {
        Harness harness = CreateHarness();
        harness.AllowRateLimits();
        Guid accountId = Guid.NewGuid();
        Guid securityStamp = Guid.NewGuid();
        CreatePasswordResetRequestDbCommand? capturedCreate = null;
        PasswordResetDeliveryCommand? capturedDelivery = null;

        harness.Repo.LookupPasswordResetAccountAsync("reader@example.com", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetAccountLookupResult?>(new PasswordResetAccountLookupResult(
                true,
                "PASSWORD_RESET_ACCOUNT_FOUND",
                accountId,
                "reader@example.com",
                null,
                null,
                securityStamp,
                true,
                false,
                false)));
        harness.Generator.GenerateKeyCode().Returns("49382710");
        harness.Hasher.HashVersion.Returns(1);
        harness.Hasher.HashCode(Arg.Any<Guid>(), "49382710").Returns("hashed-reset-code");
        harness.Repo.CreatePasswordResetRequestAsync(Arg.Do<CreatePasswordResetRequestDbCommand>(command => capturedCreate = command), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                CreatePasswordResetRequestDbCommand command = call.Arg<CreatePasswordResetRequestDbCommand>();
                return Task.FromResult<CreatePasswordResetRequestDbResult?>(new CreatePasswordResetRequestDbResult(
                    true,
                    "PASSWORD_RESET_REQUEST_CREATED",
                    command.PasswordResetRequestId,
                    command.AccountId,
                    command.ExpiresAt));
            });
        harness.Delivery.StageAsync(Arg.Do<CreatePasswordResetRequestDbCommand>(command => capturedCreate = command), Arg.Do<PasswordResetDeliveryCommand>(command => capturedDelivery = command), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new DeliveryStageResult(true,"DELIVERY_PENDING")));

        Instant beforeRequest = SystemClock.Instance.GetCurrentInstant();
        PasswordResetRequestResult result = await harness.Service.RequestReset(
            new RequestPasswordResetCommand("reader@example.com", PasswordResetDeliveryChannels.Email, "192.0.2.10", "unit-test"),
            CancellationToken.None);
        Instant afterRequest = SystemClock.Instance.GetCurrentInstant();

        result.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        result.ResetId.ShouldNotBe(Guid.Empty);
        capturedCreate.ShouldNotBeNull();
        capturedCreate!.PasswordResetRequestId.ShouldBe(result.ResetId);
        capturedCreate.ExpiresAt.ShouldBeGreaterThanOrEqualTo(beforeRequest.Plus(Duration.FromMinutes(2)));
        capturedCreate.ExpiresAt.ShouldBeLessThanOrEqualTo(afterRequest.Plus(Duration.FromMinutes(2)));
        capturedCreate.AccountId.ShouldBe(accountId);
        capturedCreate.Method.ShouldBe(PasswordResetDeliveryChannels.Email);
        capturedCreate.DeliveryChannel.ShouldBe("email");
        capturedCreate.KeyCodeHash.ShouldBe("hashed-reset-code");
        capturedCreate.KeyCodeHashVersion.ShouldBe(1);
        capturedCreate.RequiresKeyCode.ShouldBeTrue();
        capturedCreate.DestinationMasked.ShouldBe("r***r@example.com");
        capturedCreate.RequiresTotp.ShouldBeFalse();
        capturedCreate.MaxAttempts.ShouldBe(5);
        capturedCreate.AccountSecurityStampAtRequest.ShouldBe(securityStamp);
        capturedDelivery.ShouldNotBeNull();
        capturedDelivery!.DeliveryChannel.ShouldBe("email");
        capturedDelivery.DestinationAddressOrPhone.ShouldBe("reader@example.com");
        capturedDelivery.KeyCode.ShouldBe("49382710");
    }

    [Fact]
    public async Task RequestReset_stage_denial_never_creates_or_cancels_a_working_proof()
    {
        Harness harness=CreateHarness();harness.AllowRateLimits();Guid account=Guid.NewGuid(),stamp=Guid.NewGuid();
        harness.Repo.LookupPasswordResetAccountAsync("reader@example.com",Arg.Any<Instant>(),Arg.Any<CancellationToken>()).Returns(new PasswordResetAccountLookupResult(true,"FOUND",account,"reader@example.com",null,null,stamp,true,false,false));
        harness.Delivery.StageAsync(Arg.Any<CreatePasswordResetRequestDbCommand>(),Arg.Any<PasswordResetDeliveryCommand>(),Arg.Any<CancellationToken>()).Returns(new DeliveryStageResult(false,"DELIVERY_REJECTED"));
        var result=await harness.Service.RequestReset(new("reader@example.com","email","192.0.2.10","test"),CancellationToken.None);result.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        await harness.Repo.DidNotReceiveWithAnyArgs().CreatePasswordResetRequestAsync(default!,default);
        await harness.Repo.DidNotReceiveWithAnyArgs().CancelPasswordResetRequestAsync(default,default,default!,default);
    }

    [Fact]
    public async Task RequestReset_does_not_create_reset_for_unsupported_totp_request_strategy()
    {
        Harness harness = CreateHarness();
        harness.AllowRateLimits();
        harness.Repo.LookupPasswordResetAccountAsync("reader@example.com", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetAccountLookupResult?>(new PasswordResetAccountLookupResult(
                true,
                "PASSWORD_RESET_ACCOUNT_FOUND",
                Guid.NewGuid(),
                "reader@example.com",
                null,
                null,
                Guid.NewGuid(),
                true,
                false,
                false)));

        PasswordResetRequestResult result = await harness.Service.RequestReset(
            new RequestPasswordResetCommand("reader@example.com", "email_code_totp", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        result.ResetId.ShouldNotBe(Guid.Empty);
        await harness.Repo.DidNotReceiveWithAnyArgs().CreatePasswordResetRequestAsync(default!, default);
        await harness.Delivery.DidNotReceiveWithAnyArgs().StageAsync(default!, default!, default);
    }

    [Fact]
    public async Task RequestReset_creates_sms_delivery_reset_when_phone_and_authenticator_are_eligible()
    {
        Harness harness = CreateHarness();
        harness.AllowRateLimits();
        CreatePasswordResetRequestDbCommand? capturedCreate = null;
        PasswordResetDeliveryCommand? capturedDelivery = null;
        Guid accountId = Guid.NewGuid();
        Guid securityStamp = Guid.NewGuid();

        harness.Repo.LookupPasswordResetAccountAsync("reader", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetAccountLookupResult?>(new PasswordResetAccountLookupResult(
                true,
                "PASSWORD_RESET_ACCOUNT_FOUND",
                accountId,
                "reader@example.com",
                "5555550101",
                "+1",
                securityStamp,
                true,
                true,
                true)));
        harness.Generator.GenerateKeyCode().Returns("49382710");
        harness.Hasher.HashVersion.Returns(1);
        harness.Hasher.HashCode(Arg.Any<Guid>(), "49382710").Returns("hashed-reset-code");
        harness.Repo.CreatePasswordResetRequestAsync(Arg.Do<CreatePasswordResetRequestDbCommand>(command => capturedCreate = command), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                CreatePasswordResetRequestDbCommand command = call.Arg<CreatePasswordResetRequestDbCommand>();
                return Task.FromResult<CreatePasswordResetRequestDbResult?>(new CreatePasswordResetRequestDbResult(
                    true,
                    "PASSWORD_RESET_REQUEST_CREATED",
                    command.PasswordResetRequestId,
                    command.AccountId,
                    command.ExpiresAt));
            });
        harness.Delivery.StageAsync(Arg.Do<CreatePasswordResetRequestDbCommand>(command => capturedCreate = command), Arg.Do<PasswordResetDeliveryCommand>(command => capturedDelivery = command), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new DeliveryStageResult(true,"DELIVERY_PENDING")));

        PasswordResetRequestResult result = await harness.Service.RequestReset(
            new RequestPasswordResetCommand("reader", PasswordResetDeliveryChannels.Sms, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        result.ResetId.ShouldNotBe(Guid.Empty);
        capturedCreate.ShouldNotBeNull();
        capturedCreate!.PasswordResetRequestId.ShouldBe(result.ResetId);
        capturedCreate.Method.ShouldBe(PasswordResetDeliveryChannels.Sms);
        capturedCreate.DeliveryChannel.ShouldBe("sms");
        capturedCreate.RequiresKeyCode.ShouldBeTrue();
        capturedCreate.RequiresTotp.ShouldBeFalse();
        capturedCreate.DestinationMasked.ShouldBe("***-***-0101");
        capturedDelivery.ShouldNotBeNull();
        capturedDelivery!.DeliveryChannel.ShouldBe("sms");
        capturedDelivery.DestinationAddressOrPhone.ShouldBe("+15555550101");
    }

    [Fact]
    public async Task RequestReset_rejects_unsupported_plain_email_method_string()
    {
        Harness harness = CreateHarness();
        harness.AllowRateLimits();

        harness.Repo.LookupPasswordResetAccountAsync("reader@example.com", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetAccountLookupResult?>(new PasswordResetAccountLookupResult(
                true,
                "PASSWORD_RESET_ACCOUNT_FOUND",
                Guid.NewGuid(),
                "reader@example.com",
                null,
                null,
                Guid.NewGuid(),
                true,
                false,
                true)));

        PasswordResetRequestResult result = await harness.Service.RequestReset(
            new RequestPasswordResetCommand("reader@example.com", "email_code", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        result.ResetId.ShouldNotBe(Guid.Empty);
        await harness.Repo.DidNotReceiveWithAnyArgs().CreatePasswordResetRequestAsync(default!, default);
        await harness.Delivery.DidNotReceiveWithAnyArgs().StageAsync(default!, default!, default);
    }

    [Fact]
    public async Task RequestReset_rejects_unsupported_plain_sms_method_string()
    {
        Harness harness = CreateHarness();
        harness.AllowRateLimits();

        harness.Repo.LookupPasswordResetAccountAsync("reader", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetAccountLookupResult?>(new PasswordResetAccountLookupResult(
                true,
                "PASSWORD_RESET_ACCOUNT_FOUND",
                Guid.NewGuid(),
                "reader@example.com",
                "5555550101",
                "+1",
                Guid.NewGuid(),
                true,
                true,
                true)));

        PasswordResetRequestResult result = await harness.Service.RequestReset(
            new RequestPasswordResetCommand("reader", "sms_code", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        result.ResetId.ShouldNotBe(Guid.Empty);
        await harness.Repo.DidNotReceiveWithAnyArgs().CreatePasswordResetRequestAsync(default!, default);
        await harness.Delivery.DidNotReceiveWithAnyArgs().StageAsync(default!, default!, default);
    }

    [Fact]
    public async Task RequestReset_creates_email_delivery_reset_when_email_and_authenticator_are_eligible()
    {
        Harness harness = CreateHarness();
        harness.AllowRateLimits();
        CreatePasswordResetRequestDbCommand? capturedCreate = null;
        PasswordResetDeliveryCommand? capturedDelivery = null;
        Guid accountId = Guid.NewGuid();
        Guid securityStamp = Guid.NewGuid();

        harness.Repo.LookupPasswordResetAccountAsync("reader@example.com", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetAccountLookupResult?>(new PasswordResetAccountLookupResult(
                true,
                "PASSWORD_RESET_ACCOUNT_FOUND",
                accountId,
                "reader@example.com",
                null,
                null,
                securityStamp,
                true,
                false,
                true)));
        harness.Generator.GenerateKeyCode().Returns("49382710");
        harness.Hasher.HashVersion.Returns(1);
        harness.Hasher.HashCode(Arg.Any<Guid>(), "49382710").Returns("hashed-reset-code");
        harness.Repo.CreatePasswordResetRequestAsync(Arg.Do<CreatePasswordResetRequestDbCommand>(command => capturedCreate = command), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                CreatePasswordResetRequestDbCommand command = call.Arg<CreatePasswordResetRequestDbCommand>();
                return Task.FromResult<CreatePasswordResetRequestDbResult?>(new CreatePasswordResetRequestDbResult(
                    true,
                    "PASSWORD_RESET_REQUEST_CREATED",
                    command.PasswordResetRequestId,
                    command.AccountId,
                    command.ExpiresAt));
            });
        harness.Delivery.StageAsync(Arg.Do<CreatePasswordResetRequestDbCommand>(command => capturedCreate = command), Arg.Do<PasswordResetDeliveryCommand>(command => capturedDelivery = command), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new DeliveryStageResult(true,"DELIVERY_PENDING")));

        PasswordResetRequestResult result = await harness.Service.RequestReset(
            new RequestPasswordResetCommand("reader@example.com", PasswordResetDeliveryChannels.Email, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        result.ResetId.ShouldNotBe(Guid.Empty);
        capturedCreate.ShouldNotBeNull();
        capturedCreate!.Method.ShouldBe(PasswordResetDeliveryChannels.Email);
        capturedCreate.DeliveryChannel.ShouldBe("email");
        capturedCreate.RequiresKeyCode.ShouldBeTrue();
        capturedCreate.RequiresTotp.ShouldBeFalse();
        capturedDelivery.ShouldNotBeNull();
        capturedDelivery!.DeliveryChannel.ShouldBe("email");
        capturedDelivery.DestinationAddressOrPhone.ShouldBe("reader@example.com");
    }

    [Fact]
    public async Task RequestReset_does_not_create_reset_for_unsupported_authenticator_app_only_channel()
    {
        Harness harness = CreateHarness();
        harness.AllowRateLimits();

        harness.Repo.LookupPasswordResetAccountAsync("reader@example.com", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetAccountLookupResult?>(new PasswordResetAccountLookupResult(
                true,
                "PASSWORD_RESET_ACCOUNT_FOUND",
                Guid.NewGuid(),
                "reader@example.com",
                null,
                null,
                Guid.NewGuid(),
                true,
                false,
                true)));

        PasswordResetRequestResult result = await harness.Service.RequestReset(
            new RequestPasswordResetCommand("reader@example.com", "authenticator_app_totp", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        result.ResetId.ShouldNotBe(Guid.Empty);
        harness.Generator.DidNotReceiveWithAnyArgs().GenerateKeyCode();
        await harness.Repo.DidNotReceiveWithAnyArgs().CreatePasswordResetRequestAsync(default!, default);
        await harness.Delivery.DidNotReceiveWithAnyArgs().StageAsync(default!, default!, default);
    }

    [Fact]
    public async Task RequestReset_throttles_identifier_before_account_lookup_and_returns_generic_accepted()
    {
        Harness harness = CreateHarness();
        harness.AbuseControlSettings.PasswordReset.Enabled = true;
        harness.AbuseCounterStore.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key =>
                    key.Feature == AbuseFeature.PasswordResetRequest
                    && key.Dimension == AbuseCounterDimension.IdentifierFingerprint),
                Arg.Any<AbuseCounterLimit>(),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    false,
                    limit.MaxAttempts + 1,
                    limit.MaxAttempts,
                    limit.Window,
                    TimeSpan.FromMinutes(15),
                    AbuseReasonCodes.PasswordResetRequestThrottleExceeded));
            });

        PasswordResetRequestResult result = await harness.Service.RequestReset(
            new RequestPasswordResetCommand("reader@example.com", PasswordResetDeliveryChannels.Email, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        result.ResetId.ShouldNotBe(Guid.Empty);
        await harness.Repo.DidNotReceiveWithAnyArgs().LookupPasswordResetAccountAsync(default!, default, default);
        await harness.Repo.DidNotReceiveWithAnyArgs().RegisterRequestRateLimitAsync(default!, default);
        await harness.Repo.DidNotReceiveWithAnyArgs().CreatePasswordResetRequestAsync(default!, default);
        await harness.Delivery.DidNotReceiveWithAnyArgs().StageAsync(default!, default!, default);
    }

    [Fact]
    public async Task RequestReset_applies_account_abuse_throttle_after_non_enumerating_lookup()
    {
        Harness harness = CreateHarness();
        harness.AllowRateLimits();
        harness.AbuseControlSettings.PasswordReset.Enabled = true;
        Guid accountId = Guid.NewGuid();
        harness.Repo.LookupPasswordResetAccountAsync("reader@example.com", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetAccountLookupResult?>(new PasswordResetAccountLookupResult(
                true,
                "PASSWORD_RESET_ACCOUNT_FOUND",
                accountId,
                "reader@example.com",
                null,
                null,
                Guid.NewGuid(),
                true,
                false,
                false)));
        harness.AbuseCounterStore.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key =>
                    key.Feature == AbuseFeature.PasswordResetRequest
                    && key.Dimension == AbuseCounterDimension.Account
                    && key.SafeId == accountId.ToString("N")),
                Arg.Any<AbuseCounterLimit>(),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    false,
                    limit.MaxAttempts + 1,
                    limit.MaxAttempts,
                    limit.Window,
                    TimeSpan.FromMinutes(15),
                    AbuseReasonCodes.PasswordResetRequestThrottleExceeded));
            });

        PasswordResetRequestResult result = await harness.Service.RequestReset(
            new RequestPasswordResetCommand("reader@example.com", PasswordResetDeliveryChannels.Email, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        result.ResetId.ShouldNotBe(Guid.Empty);
        await harness.Repo.DidNotReceiveWithAnyArgs().CreatePasswordResetRequestAsync(default!, default);
        await harness.Delivery.DidNotReceiveWithAnyArgs().StageAsync(default!, default!, default);
        await harness.AbuseCounterStore.Received(1).IncrementAsync(
            Arg.Is<AbuseCounterKey>(key => key.Dimension == AbuseCounterDimension.Account),
            Arg.Is<AbuseCounterLimit>(limit => limit.MaxAttempts == harness.AbuseControlSettings.PasswordReset.MaxRequestsPerAccountPerHour),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RequestReset_uses_ip_and_identifier_fingerprint_abuse_counters_without_raw_identifier_keys()
    {
        Harness harness = CreateHarness();
        harness.AllowRateLimits();
        harness.AbuseControlSettings.PasswordReset.Enabled = true;
        harness.Repo.LookupPasswordResetAccountAsync("reader@example.com", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetAccountLookupResult?>(new PasswordResetAccountLookupResult(
                false,
                "PASSWORD_RESET_ACCOUNT_NOT_FOUND",
                null,
                null,
                null,
                null,
                null,
                false,
                false,
                false)));

        PasswordResetRequestResult result = await harness.Service.RequestReset(
            new RequestPasswordResetCommand("reader@example.com", PasswordResetDeliveryChannels.Email, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        await harness.AbuseCounterStore.Received(1).IncrementAsync(
            Arg.Is<AbuseCounterKey>(key =>
                key.Feature == AbuseFeature.PasswordResetRequest
                && key.Dimension == AbuseCounterDimension.IpFingerprint
                && !key.Value.Contains("192.0.2.10", StringComparison.Ordinal)
                && !key.Value.Contains("reader", StringComparison.OrdinalIgnoreCase)),
            Arg.Is<AbuseCounterLimit>(limit => limit.MaxAttempts == harness.AbuseControlSettings.PasswordReset.MaxRequestsPerIpPerHour),
            Arg.Any<CancellationToken>());
        await harness.AbuseCounterStore.Received(1).IncrementAsync(
            Arg.Is<AbuseCounterKey>(key =>
                key.Feature == AbuseFeature.PasswordResetRequest
                && key.Dimension == AbuseCounterDimension.IdentifierFingerprint
                && !key.Value.Contains("reader@example.com", StringComparison.OrdinalIgnoreCase)),
            Arg.Is<AbuseCounterLimit>(limit => limit.MaxAttempts == harness.AbuseControlSettings.PasswordReset.MaxRequestsPerIdentifierPerHour),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Cor14_challenge_returns_before_lookup_and_is_forwarded_for_every_identifier()
    {
        var gate = Substitute.For<IPasswordResetPublicGate>();
        var challenge = new PasswordResetCaptchaChallenge("Turnstile", "site-key", "password_reset_request", "nonce", "ticket");
        gate.AdmitRequestAsync(Arg.Any<RequestPasswordResetCommand>(), Arg.Any<CancellationToken>()).Returns(new PasswordResetPublicAdmission(false, challenge));
        var h = CreateHarness(gate);
        foreach (string id in new[] { "reader@example.com", "unknown@example.com" })
        {
            var result = await h.Service.RequestReset(new(id, "email", "192.0.2.10", "test"), default);
            result.Code.ShouldBe(PasswordResetService.RequestAcceptedCode); result.CaptchaChallenge.ShouldBe(challenge);
        }
        await h.Repo.DidNotReceiveWithAnyArgs().LookupPasswordResetAccountAsync(default!, default, default);
        await h.Delivery.DidNotReceiveWithAnyArgs().StageAsync(default!, default!, default);
    }

    [Fact]
    public async Task Cor14_duplicate_pending_job_does_not_reveal_reused_public_id()
    {
        var h = CreateHarness(); h.AllowRateLimits(); var account = Guid.NewGuid(); var stamp = Guid.NewGuid(); var job = Guid.NewGuid();
        h.Repo.LookupPasswordResetAccountAsync(Arg.Any<string>(), Arg.Any<Instant>(), Arg.Any<CancellationToken>()).Returns(
            new PasswordResetAccountLookupResult(true, "FOUND", account, "reader@example.com", null, null, stamp, true, false, false));
        h.Delivery.ExistingAsync(account, stamp, "reset", Arg.Any<CancellationToken>()).Returns((Guid?)job);
        var first = await h.Service.RequestReset(new("reader@example.com", "email", "192.0.2.10", "test"), default);
        var second = await h.Service.RequestReset(new("reader@example.com", "email", "192.0.2.10", "test"), default);
        first.ResetId.ShouldNotBe(job); second.ResetId.ShouldNotBe(first.ResetId); second.ResetId.ShouldNotBe(job);
        await h.Delivery.DidNotReceiveWithAnyArgs().StageAsync(default!, default!, default);
    }

    private static Harness CreateHarness(IPasswordResetPublicGate? gate = null)
    {
        var repo = Substitute.For<IPasswordResetRepo>();
        var generator = Substitute.For<IPasswordResetCodeGenerator>();
        var hasher = Substitute.For<IPasswordResetCodeHasher>();
        var delivery = Substitute.For<IPasswordResetDeliveryService>();
        delivery.AdmitAsync(Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(true);
        var totpVerifier = Substitute.For<IPasswordResetTotpVerifier>();
        var passwordMaterialFactory = Substitute.For<IPasswordResetPasswordMaterialFactory>();
        PasswordResetSettings settings = Settings();
        var keyFactory = new PasswordResetRateLimitKeyFactory(Options.Create(settings));
        var abusePolicy = new PasswordResetAbusePolicy(Options.Create(settings));
        var abuseCounterKeyFactory = new PasswordResetAbuseCounterKeyFactory(Options.Create(settings));
        var abuseCounterStore = Substitute.For<IAbuseCounterStore>();
        AbuseControlSettings abuseControlSettings = new()
        {
            PasswordReset = new PasswordResetAbusePolicySettings { Enabled = false }
        };
        abuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    true,
                    1,
                    limit.MaxAttempts,
                    limit.Window,
                    null,
                    null));
            });
        abuseCounterStore.ResetAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);
        var service = new PasswordResetService(
            repo,
            generator,
            hasher,
            keyFactory,
            abusePolicy,
            abuseCounterKeyFactory,
            abuseCounterStore,
            Options.Create(abuseControlSettings),
            delivery,
            totpVerifier,
            passwordMaterialFactory,
            Options.Create(settings),
            Options.Create(RegistrationSettings()),
            NullLogger<PasswordResetService>.Instance, publicGate: gate);

        return new Harness(service, repo, generator, hasher, delivery, totpVerifier, passwordMaterialFactory, abuseCounterStore, abuseControlSettings);
    }

    private static PasswordResetSettings Settings()
    {
        return new PasswordResetSettings
        {
            CodeLength = 8,
            CodeHashPepper = "unit-test-password-reset-pepper",
            ExpirationMinutes = 2,
            MaxAttempts = 5,
            RequestCooldownSeconds = 60,
            DailyRequestLimitPerAccount = 5,
            DailyRequestLimitPerDestination = 5,
            DailyRequestLimitPerIp = 20,
            DailyRequestWindowHours = 24,
            RateLimitBlockMinutes = 30,
            CaptchaChallengeEnabled = false,
            CaptchaChallengeAfterRequests = 3
        };
    }

    private static RegistrationSettings RegistrationSettings()
    {
        return new RegistrationSettings
        { PublicOrigin = "http://localhost.test",
            MinUsernameLength = 3,
            MaxUsernameLength = 30,
            MinPasswordLength = 8,
            MaxPasswordLength = 128,
            MaxEmailAddressLength = 255,
            AccountMetaDataRetries = 3,
            VerifyAccountPeriodDays = 1,
            EmailChangeVerifyPeriodDays = 1,
            AccountDeleteTokenPeriodDays = 1
        };
    }

    private sealed record Harness(
        PasswordResetService Service,
        IPasswordResetRepo Repo,
        IPasswordResetCodeGenerator Generator,
        IPasswordResetCodeHasher Hasher,
        IPasswordResetDeliveryService Delivery,
        IPasswordResetTotpVerifier TotpVerifier,
        IPasswordResetPasswordMaterialFactory PasswordMaterialFactory,
        IAbuseCounterStore AbuseCounterStore,
        AbuseControlSettings AbuseControlSettings)
    {
        public void AllowRateLimits()
        {
            Repo.RegisterRequestRateLimitAsync(Arg.Any<PasswordResetRateLimitDbCommand>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult<PasswordResetRateLimitResult?>(new PasswordResetRateLimitResult(
                    true,
                    "PASSWORD_RESET_RATE_LIMIT_OK",
                    1,
                    null,
                    null)));
        }
    }
}
