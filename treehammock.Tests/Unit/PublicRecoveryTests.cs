using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;
using treehammock.Models.PasswordReset;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public sealed class Cor14PublicRecoveryTests
{
    private static RequestPasswordResetCommand Request(string id = "reader@example.com") => new(id, "email", "192.0.2.10", "test");
    [Theory]
    [InlineData(1)] [InlineData(3)]
    public async Task Actual_submission_count_requires_challenge_at_threshold_for_every_identifier(int threshold)
    {
        foreach (string id in new[] { "reader@example.com", "unknown@example.com" })
        {
            var h = new Harness(threshold);
            for (int attempt = 1; attempt <= 6; attempt++)
            {
                var result = await h.Gate.AdmitRequestAsync(Request(id), default);
                result.Allowed.ShouldBe(attempt < threshold);
                (result.Challenge != null).ShouldBe(attempt >= threshold);
            }
        }
    }
    [Fact]
    public async Task Valid_continuation_resumes_once_under_concurrency_and_uses_bound_action_and_nonce()
    {
        var h = new Harness(1); var command = Request();
        var challenge = (await h.Gate.AdmitRequestAsync(command, default)).Challenge!;
        var resume = command with { CaptchaToken = "provider-token", CaptchaContinuation = challenge.Continuation };
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => h.Gate.AdmitRequestAsync(resume, default)));
        results.Count(x => x.Allowed).ShouldBe(1);
        await h.Verifier.Received(1).VerifyAsync("provider-token", PasswordResetPublicGate.Action, challenge.Nonce, default);
    }
    [Theory]
    [InlineData("identifier")] [InlineData("channel")] [InlineData("ip")] [InlineData("signature")] [InlineData("expired")] [InlineData("future")] [InlineData("missing")] [InlineData("token")]
    public async Task Invalid_continuation_never_calls_provider(string change)
    {
        var h = new Harness(1); var command = Request();
        var c = (await h.Gate.AdmitRequestAsync(command, default)).Challenge!;
        command = command with { CaptchaToken = "token", CaptchaContinuation = c.Continuation };
        command = change switch
        {
            "identifier" => command with { Identifier = "other@example.com" },
            "channel" => command with { DeliveryChannel = "sms" },
            "ip" => command with { RequestIpAddress = "192.0.2.11" },
            "signature" => command with { CaptchaContinuation = c.Continuation[..^1] + (c.Continuation[^1] == '0' ? "1" : "0") },
            "token" => command with { CaptchaToken = null }, _ => command
        };
        if (change == "expired") h.Clock.Now += Duration.FromSeconds(180);
        if (change == "future") h.Clock.Now -= Duration.FromSeconds(1);
        if (change == "missing") h.Store.Rows.Clear();
        (await h.Gate.AdmitRequestAsync(command, default)).Allowed.ShouldBeFalse();
        await h.Verifier.DidNotReceiveWithAnyArgs().VerifyAsync(default!, default!, default!, default);
    }
    [Fact]
    public async Task Provider_failure_consumes_continuation_without_delivery_or_retry()
    {
        var h = new Harness(1); h.Verifier.VerifyAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(false);
        var command = Request(); var c = (await h.Gate.AdmitRequestAsync(command, default)).Challenge!;
        command = command with { CaptchaToken = "token", CaptchaContinuation = c.Continuation };
        (await h.Gate.AdmitRequestAsync(command, default)).Allowed.ShouldBeFalse();
        (await h.Gate.AdmitRequestAsync(command, default)).Allowed.ShouldBeFalse();
        await h.Verifier.Received(1).VerifyAsync("token", PasswordResetPublicGate.Action, c.Nonce, default);
    }
    [Fact]
    public async Task Provider_completion_after_continuation_deadline_cannot_resume()
    {
        var h = new Harness(1); var command = Request();
        var c = (await h.Gate.AdmitRequestAsync(command, default)).Challenge!;
        h.Verifier.VerifyAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(_ => { h.Clock.Now += Duration.FromSeconds(180); return Task.FromResult(true); });
        (await h.Gate.AdmitRequestAsync(command with { CaptchaToken = "token", CaptchaContinuation = c.Continuation }, default)).Allowed.ShouldBeFalse();
    }
    [Fact]
    public async Task Aggregate_admission_caps_nonce_allocation_before_arbitrary_ip_or_identifier_work()
    {
        var h = new Harness(1); h.Settings.PublicRequestsPerMinute = 5;
        for (int i = 0; i < 10000; i++) await h.Gate.AdmitRequestAsync(Request(Guid.NewGuid().ToString()) with { RequestIpAddress = $"192.0.{i / 256}.{i % 256}" }, default);
        h.Store.Rows.Count.ShouldBe(5);
        h.Counters.Rows.Count.ShouldBeLessThanOrEqualTo(6);
    }
    [Fact]
    public async Task Public_proof_admission_is_aggregate_and_ip_bound_even_when_other_abuse_controls_are_disabled()
    {
        var h = new Harness(1); h.Settings.PublicProofsPerMinute = 3;
        for (int i = 0; i < 100; i++) (await h.Gate.AdmitProofAsync($"192.0.2.{i}", default)).ShouldBe(i < 3);
        h.Counters.Rows.Count.ShouldBe(4);
    }
    [Fact]
    public void Random_reset_and_identifier_flood_has_fixed_key_cardinality()
    {
        var h = new Harness(1); var keys = new PasswordResetAbuseCounterKeyFactory(Options.Create(h.Settings));
        var reset = new HashSet<string>(); var identifier = new HashSet<string>();
        for (int i = 0; i < 50000; i++) { reset.Add(keys.ForTokenVerificationReset(Guid.NewGuid()).Value); identifier.Add(keys.ForRequestIdentifier(Guid.NewGuid().ToString()).Value); }
        reset.Count.ShouldBeLessThanOrEqualTo(PasswordResetPublicBuckets.Count);
        identifier.Count.ShouldBeLessThanOrEqualTo(PasswordResetPublicBuckets.Count);
    }
    [Theory]
    [InlineData("missing")] [InlineData("provider")] [InlineData("testkeys")] [InlineData("hosts")]
    public void Enabled_configuration_rejects_missing_or_nonproduction_adapter_settings(string mode)
    {
        var s = new Harness(1).Settings; s.CaptchaSiteKey = "production-site-key"; s.CaptchaSecretKey = "production-secret"; s.CaptchaAllowedHostnames = ["example.com"];
        if (mode == "missing") s.CaptchaSecretKey = "";
        if (mode == "provider") s.CaptchaProvider = "Fake";
        if (mode == "testkeys") s.CaptchaSiteKey = "1x00000000000000000000AA";
        if (mode == "hosts") s.CaptchaAllowedHostnames = [];
        Validator.TryValidateObject(s, new ValidationContext(s), new List<ValidationResult>(), true).ShouldBeFalse();
    }
    [Fact]
    public async Task Startup_rejects_permissive_test_verifier_and_continuation_store()
    {
        var h = new Harness(1);
        await Should.ThrowAsync<InvalidOperationException>(() => new PasswordResetCaptchaStartupGuard(Options.Create(h.Settings), h.Verifier, h.Store).StartAsync(default));
    }
    [Theory]
    [InlineData("valid", true)] [InlineData("action", false)] [InlineData("nonce", false)] [InlineData("host", false)]
    [InlineData("invalid", false)] [InlineData("malformed", false)] [InlineData("missing", false)] [InlineData("outage", false)] [InlineData("timeout", false)]
    public async Task Production_adapter_checks_provider_contract_and_fails_closed(string mode, bool allowed)
    {
        string? sent = null;
        var handler = new Handler(async (request, ct) =>
        {
            request.RequestUri!.ToString().ShouldBe(TurnstileCaptchaVerifier.Endpoint);
            sent = await request.Content!.ReadAsStringAsync(ct);
            if (mode == "timeout") await Task.Delay(Timeout.Infinite, ct);
            if (mode == "outage") return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            var data = new { success = mode != "invalid", action = mode == "action" ? "login" : PasswordResetPublicGate.Action,
                cdata = mode == "nonce" ? "other-nonce" : "bound-nonce", hostname = mode == "host" ? "attacker.example" : "example.com" };
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(mode == "malformed" ? "{" : mode == "missing" ? "{}" : JsonSerializer.Serialize(data), Encoding.UTF8, "application/json") };
        });
        using var client = new HttpClient(handler);
        var factory = Substitute.For<IHttpClientFactory>(); factory.CreateClient(TurnstileCaptchaVerifier.ClientName).Returns(client);
        var settings = new Harness(1).Settings; settings.CaptchaSecretKey = "secret"; settings.CaptchaAllowedHostnames = ["example.com"]; settings.CaptchaTimeoutMilliseconds = 100;
        (await new TurnstileCaptchaVerifier(factory, Options.Create(settings)).VerifyAsync("token", PasswordResetPublicGate.Action, "bound-nonce", default)).ShouldBe(allowed);
        sent.ShouldBe("secret=secret&response=token");
    }
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken); }
    private sealed class Clock : IClock { public Instant Now = Instant.FromUtc(2026, 10, 7, 0, 0); public Instant GetCurrentInstant() => Now; }
    private sealed class Nonces(Clock clock) : ICaptchaContinuationStore
    {
        public ConcurrentDictionary<string, Instant> Rows = new();
        public Task<bool> CreateAsync(string nonce, TimeSpan lifetime, CancellationToken ct) => Task.FromResult(Rows.TryAdd(nonce, clock.Now + Duration.FromTimeSpan(lifetime)));
        public Task<bool> ConsumeAsync(string nonce, CancellationToken ct) => Task.FromResult(Rows.TryRemove(nonce, out var deadline) && deadline > clock.Now);
    }
    private sealed class Counters : IAbuseCounterStore
    {
        public Dictionary<string, int> Rows = new();
        public Task<CounterDecision> IncrementAsync(AbuseCounterKey key, AbuseCounterLimit limit, CancellationToken ct = default)
        { lock (Rows) { int count = Rows[key.Value] = Rows.GetValueOrDefault(key.Value) + 1; return Task.FromResult(new CounterDecision(count <= limit.MaxAttempts, count, limit.MaxAttempts, limit.Window, null, null)); } }
        public Task ResetAsync(AbuseCounterKey key, CancellationToken ct = default) => throw new InvalidOperationException("Shared admission cannot reset.");
        public Task<CooldownDecision> GetCooldownAsync(AbuseCounterKey key, CancellationToken ct = default) => Task.FromResult(new CooldownDecision(false, null, null));
    }
    private sealed class Harness
    {
        public PasswordResetSettings Settings = new() { CodeHashPepper = "test-only-pepper-material", CaptchaChallengeEnabled = true, DailyRequestLimitPerIp = 100 };
        public Clock Clock = new(); public Counters Counters = new(); public Nonces Store;
        public ICaptchaVerifier Verifier = Substitute.For<ICaptchaVerifier>(); public PasswordResetPublicGate Gate;
        public Harness(int threshold)
        {
            Settings.CaptchaChallengeAfterRequests = threshold; Store = new(Clock);
            Verifier.VerifyAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(true);
            Gate = new(Counters, Verifier, Store, Options.Create(Settings), Clock);
        }
    }
}
