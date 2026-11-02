using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.Models.Recovery;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class AccountRecoveryServiceTests
{
    private static readonly Guid LockoutEpoch = Guid.Parse("00000000-0000-0000-0000-000000001301");
    [Theory]
    [InlineData(AccountUnlockDeliveryMethod.EMAIL,"email","reader@example.com")]
    [InlineData(AccountUnlockDeliveryMethod.SMS,"sms","+15555550101")]
    public async Task StartRecovery_stages_bound_candidate_after_real_account_admission(AccountUnlockDeliveryMethod method,string channel,string destination)
    {
        var h=CreateHarness();Guid account=Guid.NewGuid(),stamp=Guid.NewGuid();Instant now=SystemClock.Instance.GetCurrentInstant();
        h.Repo.LookupLockedAccount("reader@example.com",now,Arg.Any<CancellationToken>()).Returns(LockedLookup(account,stamp,now.Plus(Duration.FromHours(1))));
        var result=await h.Service.StartRecovery(new AccountRecoveryRequest("reader@example.com",method),now);
        result.Result.ShouldBeTrue();result.Code.ShouldBe(AccountRecoveryService.PendingCode);
        var candidate=h.Delivery.Intents.Single();candidate.AccountId.ShouldBe(account);candidate.AccountStamp.ShouldBe(stamp);candidate.Purpose.ShouldBe("unlock");
        candidate.ProofHash.ShouldBe(treehammock.Rigging.Security.SecretHashUtility.HashToken(candidate.Payload.Value));candidate.Payload.Channel.ShouldBe(channel);candidate.Payload.Destination.ShouldBe(destination);
        h.Delivery.Admissions.Single().Account.ShouldBe(account);
        await h.Repo.DidNotReceiveWithAnyArgs().BeginUnlock(default,default!,default,default,default,default,default,default,default);
        await h.Repo.DidNotReceiveWithAnyArgs().CancelUnlock(default,default!);
    }

    [Theory][InlineData("unknown")][InlineData("snapshot")][InlineData("sms")]
    public async Task StartRecovery_missing_authority_or_destination_stages_nothing(string missing)
    {
        var h=CreateHarness();var now=SystemClock.Instance.GetCurrentInstant();
        var lookup=missing switch {
            "unknown"=>new AccountRecoveryLookupResult(false,"ACCOUNT_UNLOCK_NOT_LOCKED",null,null,null,null,null,null,null),
            "snapshot"=>new AccountRecoveryLookupResult(true,"ACCOUNT_UNLOCK_ACCOUNT_FOUND",Guid.NewGuid(),"reader@example.com",null,null,null,null,null),
            _=>new AccountRecoveryLookupResult(true,"ACCOUNT_UNLOCK_ACCOUNT_FOUND",Guid.NewGuid(),"reader@example.com",null,null,Guid.NewGuid(),now.Plus(Duration.FromHours(1)),LockoutEpoch)
        };
        h.Repo.LookupLockedAccount("reader@example.com",now,Arg.Any<CancellationToken>()).Returns(lookup);
        var result=await h.Service.StartRecovery(new AccountRecoveryRequest("reader@example.com",missing=="sms"?AccountUnlockDeliveryMethod.SMS:AccountUnlockDeliveryMethod.EMAIL),now);
        result.Result.ShouldBeTrue();result.Code.ShouldBe(AccountRecoveryService.PendingCode);h.Delivery.Admissions.ShouldBeEmpty();h.Delivery.Intents.ShouldBeEmpty();
    }

    [Theory][InlineData("denied")][InlineData("inflight")][InlineData("stale")]
    public async Task StartRecovery_denial_or_existing_or_stale_candidate_preserves_current_unlock(string outcome)
    {
        var h=CreateHarness();var now=SystemClock.Instance.GetCurrentInstant();
        h.Repo.LookupLockedAccount("reader@example.com",now,Arg.Any<CancellationToken>()).Returns(LockedLookup(Guid.NewGuid(),Guid.NewGuid(),now.Plus(Duration.FromHours(1))));
        h.Delivery.Allowed=outcome!="denied";h.Delivery.Existing=outcome=="inflight"?Guid.NewGuid():null;
        h.Delivery.Result=new(false,"ACCOUNT_UNLOCK_STALE_LOCKOUT");
        var result=await h.Service.StartRecovery(new AccountRecoveryRequest("reader@example.com"),now);
        result.Code.ShouldBe(AccountRecoveryService.PendingCode);h.Delivery.Intents.Count.ShouldBe(outcome=="stale"?1:0);
        await h.Repo.DidNotReceiveWithAnyArgs().BeginUnlock(default,default!,default,default,default,default,default,default,default);
        await h.Repo.DidNotReceiveWithAnyArgs().CancelUnlock(default,default!);
    }

    [Fact]
    public async Task VerifyRecovery_throttles_by_token_before_sql_when_unlock_verify_counter_is_exhausted()
    {
        var store = Substitute.For<IAbuseCounterStore>();
        store.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.AccountUnlock && key.Dimension == AbuseCounterDimension.TokenFingerprint),
                Arg.Any<AbuseCounterLimit>(),
                Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(
                Allowed: false,
                CurrentCount: 6,
                Limit: 5,
                Window: TimeSpan.FromMinutes(15),
                RetryAfter: TimeSpan.FromMinutes(5),
                ReasonCode: AbuseReasonCodes.CounterLimitExceeded)));
        var harness = CreateHarness(store);

        AccountRecoveryVerifyResult result = await harness.Service.VerifyRecovery(new AccountRecoveryVerifyRequest("token-123"));

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(AbuseReasonCodes.AccountUnlockVerifyAttemptsExceeded);
        await harness.Repo.DidNotReceiveWithAnyArgs().VerifyUnlock(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyRecovery_throttles_by_ip_before_sql_when_ip_counter_is_exhausted()
    {
        var store = Substitute.For<IAbuseCounterStore>();
        store.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                AbuseCounterKey key = call.ArgAt<AbuseCounterKey>(0);
                if (key.Dimension == AbuseCounterDimension.IpFingerprint)
                {
                    return Task.FromResult(new CounterDecision(
                        Allowed: false,
                        CurrentCount: 26,
                        Limit: 25,
                        Window: TimeSpan.FromMinutes(15),
                        RetryAfter: TimeSpan.FromMinutes(10),
                        ReasonCode: AbuseReasonCodes.CounterLimitExceeded));
                }

                AbuseCounterLimit limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    Allowed: true,
                    CurrentCount: 1,
                    Limit: limit.MaxAttempts,
                    Window: limit.Window,
                    RetryAfter: null,
                    ReasonCode: null));
            });
        var harness = CreateHarness(store);

        AccountRecoveryVerifyResult result = await harness.Service.VerifyRecovery(new AccountRecoveryVerifyRequest("token-123"));

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(AbuseReasonCodes.AccountUnlockVerifyAttemptsExceeded);
        await harness.Repo.DidNotReceiveWithAnyArgs().VerifyUnlock(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyRecovery_counter_store_unavailable_fails_closed_before_sql()
    {
        var store = Substitute.For<IAbuseCounterStore>();
        store.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(
                Allowed: false,
                CurrentCount: 0,
                Limit: 5,
                Window: TimeSpan.FromMinutes(15),
                RetryAfter: null,
                ReasonCode: AbuseReasonCodes.CounterStoreUnavailable)));
        var harness = CreateHarness(store);

        AccountRecoveryVerifyResult result = await harness.Service.VerifyRecovery(new AccountRecoveryVerifyRequest("token-123"));

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(AbuseReasonCodes.CounterStoreUnavailable);
        await harness.Repo.DidNotReceiveWithAnyArgs().VerifyUnlock(default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyRecovery_resets_token_and_ip_counters_after_successful_unlock()
    {
        var store = Substitute.For<IAbuseCounterStore>();
        store.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                AbuseCounterLimit limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    Allowed: true,
                    CurrentCount: 1,
                    Limit: limit.MaxAttempts,
                    Window: limit.Window,
                    RetryAfter: null,
                    ReasonCode: null));
            });
        store.ResetAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);
        var harness = CreateHarness(store);
        harness.Repo.VerifyUnlock("token-123", cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.COMPLETE));

        AccountRecoveryVerifyResult result = await harness.Service.VerifyRecovery(new AccountRecoveryVerifyRequest("token-123"));

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.VerifiedCode);
        await store.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.AccountUnlock && key.Dimension == AbuseCounterDimension.TokenFingerprint),
            Arg.Any<CancellationToken>());
        await store.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.AccountUnlock && key.Dimension == AbuseCounterDimension.IpFingerprint),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyRecovery_maps_complete_status_to_unlock_verified_result()
    {
        var harness = CreateHarness();
        harness.Repo.VerifyUnlock("token-123", cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.COMPLETE));

        AccountRecoveryVerifyResult result = await harness.Service.VerifyRecovery(new AccountRecoveryVerifyRequest("token-123"));

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.VerifiedCode);
    }

    [Fact]
    public async Task VerifyRecovery_maps_stale_lockout_snapshot_to_token_mismatch()
    {
        var harness = CreateHarness();
        harness.Repo.VerifyUnlock("token-123", cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.STALE_LOCKOUT));

        AccountRecoveryVerifyResult result = await harness.Service.VerifyRecovery(new AccountRecoveryVerifyRequest("token-123"));

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(AccountRecoveryService.TokenMismatchCode);
    }

    private static AccountRecoveryLookupResult LockedLookup(Guid accountId, Guid securityStamp, Instant unlockWhen)
    {
        return new AccountRecoveryLookupResult(
            true,
            "ACCOUNT_UNLOCK_ACCOUNT_FOUND",
            accountId,
            "reader@example.com",
            "+15555550101",
            null,
            securityStamp,
            unlockWhen, LockoutEpoch);
    }

    private static AccountRecoveryHarness CreateHarness(IAbuseCounterStore? abuseCounterStore = null)
    {
        var repo = Substitute.For<IAccountRecoveryRepo>();
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        var subjects = Options.Create(new EmailSubjectSettings { AccountUnlock = "Unlock your Treehammock account" });
        var httpContextAccessor = new HttpContextAccessor
        {
            HttpContext = new DefaultHttpContext()
        };
        httpContextAccessor.HttpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.42");

        var delivery = new treehammock.Tests.Infrastructure.CapturingDurableDelivery();
        var service = new AccountRecoveryService(delivery,
            repo,
            subjects,
            NullLogger<AccountRecoveryService>.Instance,
            new AccountUnlockAbuseCounterKeyFactory(),
            abuseCounterStore,
            Options.Create(new AbuseControlSettings()),
            httpContextAccessor);
        return new AccountRecoveryHarness(delivery, service, repo, smtp, sms, abuseCounterStore);
    }

    private sealed record AccountRecoveryHarness(
        treehammock.Tests.Infrastructure.CapturingDurableDelivery Delivery,
        AccountRecoveryService Service,
        IAccountRecoveryRepo Repo,
        ISMTPService SmtpService,
        ISmsSender SmsSender,
        IAbuseCounterStore? AbuseCounterStore);
}
