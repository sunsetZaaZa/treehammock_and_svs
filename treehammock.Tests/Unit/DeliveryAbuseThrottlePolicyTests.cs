using System.Net;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Shouldly;

using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class DeliveryAbuseThrottlePolicyTests
{
    [Fact]
    public async Task Email_delivery_policy_increments_account_destination_and_ip_counters_without_raw_pii()
    {
        var store = new CapturingAbuseCounterStore();
        var accountId = Guid.NewGuid();
        var service = CreateService(
            store,
            "203.0.113.42",
            new AbuseControlSettings
            {
                FailureCooldown = new FailureCooldownSettings { Enabled = false },
                Delivery = new DeliveryAbusePolicySettings
                {
                    MaxEmailDeliveriesPerAccountPerHour = 7,
                    MaxEmailDeliveriesPerIpPerHour = 11
                }
            });

        AbuseDecision decision = await service.ShouldAllowDeliveryAsync(new DeliveryAbuseThrottleRequest(
            AbuseFeature.Activation,
            "email",
            accountId,
            DeliveryAbuseThrottleService.SafeDestination("email", "Reader@Example.com")));

        decision.Allowed.ShouldBeTrue();
        store.Increments.Count.ShouldBe(3);
        store.Increments.ShouldContain(item =>
            item.Key.Feature == AbuseFeature.Delivery &&
            item.Key.Dimension == AbuseCounterDimension.Account &&
            item.Key.SafeId == $"email-{accountId:N}" &&
            item.Limit.MaxAttempts == 7 &&
            item.Limit.Window == TimeSpan.FromHours(1));
        store.Increments.ShouldContain(item =>
            item.Key.Dimension == AbuseCounterDimension.IdentifierFingerprint &&
            item.Key.SafeId.StartsWith("email-", StringComparison.Ordinal) &&
            item.Limit.MaxAttempts == 7);
        store.Increments.ShouldContain(item =>
            item.Key.Dimension == AbuseCounterDimension.IpFingerprint &&
            item.Key.SafeId.StartsWith("email-", StringComparison.Ordinal) &&
            item.Limit.MaxAttempts == 11);
        foreach (string key in store.Increments.Select(item => item.Key.Value))
        {
            key.Contains("reader", StringComparison.OrdinalIgnoreCase).ShouldBeFalse();
            key.Contains("example.com", StringComparison.OrdinalIgnoreCase).ShouldBeFalse();
            key.Contains("203.0.113.42", StringComparison.Ordinal).ShouldBeFalse();
        }
    }

    [Fact]
    public async Task Sms_delivery_policy_uses_sms_account_and_ip_limits()
    {
        var store = new CapturingAbuseCounterStore();
        var accountId = Guid.NewGuid();
        var service = CreateService(
            store,
            "198.51.100.7",
            new AbuseControlSettings
            {
                FailureCooldown = new FailureCooldownSettings { Enabled = false },
                Delivery = new DeliveryAbusePolicySettings
                {
                    MaxSmsDeliveriesPerAccountPerHour = 2,
                    MaxSmsDeliveriesPerIpPerHour = 4
                }
            });

        AbuseDecision decision = await service.ShouldAllowDeliveryAsync(new DeliveryAbuseThrottleRequest(
            AbuseFeature.AccountUnlock,
            "phone",
            accountId,
            DeliveryAbuseThrottleService.SafeDestination("sms", "+15555550123")));

        decision.Allowed.ShouldBeTrue();
        store.Increments.Count.ShouldBe(3);
        store.Increments.ShouldContain(item =>
            item.Key.Dimension == AbuseCounterDimension.Account &&
            item.Key.SafeId == $"sms-{accountId:N}" &&
            item.Limit.MaxAttempts == 2);
        store.Increments.ShouldContain(item =>
            item.Key.Dimension == AbuseCounterDimension.IpFingerprint &&
            item.Key.SafeId.StartsWith("sms-", StringComparison.Ordinal) &&
            item.Limit.MaxAttempts == 4);
        foreach (string key in store.Increments.Select(item => item.Key.Value))
        {
            key.Contains("15555550123", StringComparison.Ordinal).ShouldBeFalse();
            key.Contains("198.51.100.7", StringComparison.Ordinal).ShouldBeFalse();
        }
    }

    [Fact]
    public async Task Provider_failure_records_failure_cooldown_policy_for_delivery_method()
    {
        var store = new CapturingAbuseCounterStore();
        var service = CreateService(
            store,
            "203.0.113.42",
            new AbuseControlSettings
            {
                FailureCooldown = new FailureCooldownSettings
                {
                    Enabled = true,
                    FailureThreshold = 2,
                    WindowSeconds = 120,
                    CooldownSeconds = 300
                },
                Delivery = new DeliveryAbusePolicySettings
                {
                    CooldownSecondsAfterRepeatedFailures = 900
                }
            });

        await service.RecordProviderFailureAsync(new DeliveryAbuseThrottleRequest(
            AbuseFeature.PasswordResetRequest,
            "email",
            Guid.NewGuid(),
            DeliveryAbuseThrottleService.SafeDestination("email", "reader@example.com")));

        // Untyped caller/recipient failures are not provider outage evidence.
        store.Increments.ShouldBeEmpty();
        store.CooldownChecks.ShouldBeEmpty();
    }

    [Fact]
    public async Task Active_provider_failure_cooldown_denies_delivery_before_counters_increment()
    {
        var store = new CapturingAbuseCounterStore();
        var providerFailureKey = new AbuseCounterKey(
            AbuseFeature.Delivery,
            AbuseCounterDimension.DeliveryMethod,
            "providerfailure-sms");
        store.Cooldowns[providerFailureKey.Value] = new CooldownDecision(
            true,
            TimeSpan.FromMinutes(4),
            AbuseReasonCodes.FailureCooldownActive);
        var service = CreateService(
            store,
            "203.0.113.42",
            new AbuseControlSettings
            {
                FailureCooldown = new FailureCooldownSettings { Enabled = true }
            });

        AbuseDecision decision = await service.ShouldAllowDeliveryAsync(new DeliveryAbuseThrottleRequest(
            AbuseFeature.AccountUnlock,
            "sms",
            Guid.NewGuid(),
            DeliveryAbuseThrottleService.SafeDestination("sms", "+15555550123")));

        // Historical ephemeral channel keys are ignored; user budgets remain charged.
        decision.Allowed.ShouldBeTrue();
        store.CooldownChecks.ShouldBeEmpty();
        store.Increments.Count.ShouldBe(3);
    }

    [Fact]
    public async Task Failure_cooldown_disabled_skips_provider_failure_cooldown_gate()
    {
        var store = new CapturingAbuseCounterStore();
        var providerFailureKey = new AbuseCounterKey(
            AbuseFeature.Delivery,
            AbuseCounterDimension.DeliveryMethod,
            "providerfailure-email");
        store.Cooldowns[providerFailureKey.Value] = new CooldownDecision(
            true,
            TimeSpan.FromMinutes(4),
            AbuseReasonCodes.FailureCooldownActive);
        var service = CreateService(
            store,
            "203.0.113.42",
            new AbuseControlSettings
            {
                FailureCooldown = new FailureCooldownSettings { Enabled = false }
            });

        AbuseDecision decision = await service.ShouldAllowDeliveryAsync(new DeliveryAbuseThrottleRequest(
            AbuseFeature.Activation,
            "email",
            Guid.NewGuid(),
            DeliveryAbuseThrottleService.SafeDestination("email", "reader@example.com")));
        await service.RecordProviderFailureAsync(new DeliveryAbuseThrottleRequest(
            AbuseFeature.Activation,
            "email",
            Guid.NewGuid(),
            DeliveryAbuseThrottleService.SafeDestination("email", "reader@example.com")));

        decision.Allowed.ShouldBeTrue();
        store.CooldownChecks.ShouldBeEmpty();
        store.Increments.Count.ShouldBe(3);
        foreach ((AbuseCounterKey key, _) in store.Increments)
        {
            key.Dimension.ShouldNotBe(AbuseCounterDimension.DeliveryMethod);
        }
    }

    private static DeliveryAbuseThrottleService CreateService(
        CapturingAbuseCounterStore store,
        string remoteIpAddress,
        AbuseControlSettings settings)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(remoteIpAddress);
        var accessor = new HttpContextAccessor
        {
            HttpContext = context
        };

        return new DeliveryAbuseThrottleService(
            store,
            Options.Create(settings),
            accessor);
    }

    private sealed class CapturingAbuseCounterStore : IAbuseCounterStore
    {
        public List<(AbuseCounterKey Key, AbuseCounterLimit Limit)> Increments { get; } = new();

        public List<AbuseCounterKey> CooldownChecks { get; } = new();

        public Dictionary<string, CooldownDecision> Cooldowns { get; } = new(StringComparer.Ordinal);

        public Task<CounterDecision> IncrementAsync(
            AbuseCounterKey key,
            AbuseCounterLimit limit,
            CancellationToken cancellationToken = default)
        {
            Increments.Add((key, limit));
            return Task.FromResult(new CounterDecision(
                true,
                Increments.Count,
                limit.MaxAttempts,
                limit.Window,
                null,
                null));
        }

        public Task ResetAsync(
            AbuseCounterKey key,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<CooldownDecision> GetCooldownAsync(
            AbuseCounterKey key,
            CancellationToken cancellationToken = default)
        {
            CooldownChecks.Add(key);
            if (Cooldowns.TryGetValue(key.Value, out CooldownDecision? decision))
            {
                return Task.FromResult(decision);
            }

            return Task.FromResult(new CooldownDecision(false, null, null));
        }
    }
}
