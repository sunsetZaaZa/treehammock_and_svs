using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;

using treehammock.DataLayer;
using treehammock.Models.Activation;
using treehammock.Models.Recovery;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class DeliveryAbuseThrottleApplicationTests
{
    [Fact]
    public async Task Password_reset_delivery_throttle_denial_suppresses_provider_send()
    {
        var durable=new treehammock.Tests.Infrastructure.CapturingDurableDelivery {Allowed=false};var service=new PasswordResetDeliveryService(durable,Options.Create(new EmailSubjectSettings()));Guid account=Guid.NewGuid();
        (await service.AdmitAsync(account,"sms","+15555550101",CancellationToken.None)).ShouldBeFalse();durable.Admissions.Single().Account.ShouldBe(account);durable.Intents.ShouldBeEmpty();
    }

    [Fact]
    public async Task Activation_delivery_throttle_denial_suppresses_provider_send()
    {
        var h=new ActivationServiceTests.Harness();
        h.Delivery.AdmitWithReasonAsync(Arg.Any<AbuseFeature>(),Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(AbuseDecision.Deny(AbuseReasonCodes.DeliveryThrottleExceeded));
        (await h.Service.PlaceActivation(h.Account,h.Stamp,h.Creation(),SystemClock.Instance.GetCurrentInstant())).Result.ShouldBeFalse();
        await h.Delivery.DidNotReceiveWithAnyArgs().EnqueueAsync(default!,default);
        await h.Smtp.DidNotReceiveWithAnyArgs().Send(default!,default!,default!);
    }

    [Fact]
    public async Task Account_unlock_delivery_throttle_denial_preserves_generic_response_and_suppresses_provider_send()
    {
        var repo = Substitute.For<IAccountRecoveryRepo>();
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        var throttle = new CapturingDeliveryAbuseThrottleService(allow: false);
        Guid accountId = Guid.NewGuid();
        Guid stamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();

        repo.LookupLockedAccount("reader@example.com", now, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountRecoveryLookupResult?>(new AccountRecoveryLookupResult(
                true,
                AccountRecoveryService.PendingCode,
                accountId,
                "reader@example.com",
                null,
                null,
                stamp,
                now.Plus(Duration.FromMinutes(10)), Guid.Empty)));
        repo.BeginUnlock(accountId, Arg.Any<string>(), now, Arg.Any<Instant>(), AccountRecovery_Status.STANDBY, AccountUnlockDeliveryMethod.EMAIL, stamp, Arg.Any<Instant>(), Arg.Any<Guid>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.STANDBY));
        repo.CancelUnlock(accountId, Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.CANCELED));

        var durable=new treehammock.Tests.Infrastructure.CapturingDurableDelivery {Allowed=false};
        var service = new AccountRecoveryService(durable,
            repo,
            Options.Create(new EmailSubjectSettings()),
            NullLogger<AccountRecoveryService>.Instance);

        AccountRecoveryStartResult result = await service.StartRecovery(
            new AccountRecoveryRequest("reader@example.com", AccountUnlockDeliveryMethod.EMAIL),
            now);

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.PendingCode);
        durable.Admissions.Count.ShouldBe(1);
        durable.Intents.ShouldBeEmpty();
        await smtp.DidNotReceiveWithAnyArgs().AccountUnlockLetter(default!, default!, default!, token: Arg.Any<CancellationToken>());
        await sms.DidNotReceiveWithAnyArgs().SendCode(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Two_factor_delivery_throttle_denial_suppresses_provider_send()
    {
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        var throttle = new CapturingDeliveryAbuseThrottleService(allow: false);
        var service = new TwoFactorAuthenticateService(
            smtp,
            sms,
            Options.Create(new EmailSubjectSettings()),
            throttle);

        bool sent = await service.Email("reader@example.com", "123456", Guid.NewGuid());

        sent.ShouldBeFalse();
        throttle.AllowChecks.ShouldBe(1);
        await smtp.DidNotReceiveWithAnyArgs().TwoFactorKeyOutboundLetter(default!, default!, default!, token: Arg.Any<CancellationToken>());
        await sms.DidNotReceiveWithAnyArgs().SendCode(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }


    [Fact]
    public async Task Password_reset_provider_rejection_and_ambiguity_are_distinct()
    {
        var smtp=Substitute.For<ISMTPService>();var sms=Substitute.For<ISmsSender>();var p=new treehammock.Rigging.Delivery.DeliveryPayload("reset","email","reader@example.test","Reset","secret");Guid id=Guid.NewGuid();
        smtp.SendDurable(id,p,Arg.Any<CancellationToken>()).Returns(Task.FromResult(new treehammock.Rigging.Delivery.DeliverySendResult(treehammock.Rigging.Delivery.DeliverySendState.Rejected,"DELIVERY_REJECTED")));var adapter=new DeliveryProviderAdapter(smtp,sms);
        (await adapter.SendAsync(id,p,CancellationToken.None)).State.ShouldBe(treehammock.Rigging.Delivery.DeliverySendState.Rejected);
        smtp.SendDurable(id,p,Arg.Any<CancellationToken>()).Returns(Task.FromResult(new treehammock.Rigging.Delivery.DeliverySendResult(treehammock.Rigging.Delivery.DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN")));(await adapter.SendAsync(id,p,CancellationToken.None)).State.ShouldBe(treehammock.Rigging.Delivery.DeliverySendState.Unknown);
    }

    private sealed class CapturingDeliveryAbuseThrottleService : IDeliveryAbuseThrottleService
    {
        private readonly bool _allow;

        public CapturingDeliveryAbuseThrottleService(bool allow)
        {
            _allow = allow;
        }

        public int AllowChecks { get; private set; }

        public int ProviderFailures { get; private set; }

        public Task<AbuseDecision> ShouldAllowDeliveryAsync(
            DeliveryAbuseThrottleRequest request,
            CancellationToken cancellationToken = default)
        {
            AllowChecks++;
            return Task.FromResult(_allow
                ? AbuseDecision.Allow()
                : AbuseDecision.Deny(AbuseReasonCodes.DeliveryThrottleExceeded, TimeSpan.FromMinutes(15)));
        }

        public Task RecordProviderFailureAsync(
            DeliveryAbuseThrottleRequest request,
            CancellationToken cancellationToken = default)
        {
            ProviderFailures++;
            return Task.CompletedTask;
        }
    }
}
