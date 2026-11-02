using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Treehammock.SessionValidation.Api;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.HostTests;

public sealed class HostTlsTests(HostFixture fixture) : IClassFixture<HostFixture>
{
    [Fact] public async Task Actual_HTTP2_mtls_listener_serves_private_health_only_and_ignores_ambient_urls()
    {
        string? prior = Environment.GetEnvironmentVariable("ASPNETCORE_URLS"); Environment.SetEnvironmentVariable("ASPNETCORE_URLS", "http://0.0.0.0:19777");
        var fake = new FakeResources(); var settings = fixture.Settings();
        try
        {
            await using var app = SvsHost.Build(settings, _ => fake); await app.StartAsync(TestContext.Current.CancellationToken);
            using var http = fixture.Http(settings, fixture.Client); using var response = await http.GetAsync("/health/ready", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal(HttpVersion.Version20, response.Version); Assert.Equal("no-store", response.Headers.CacheControl!.ToString());
            string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken); Assert.Contains("\"cacheReady\":false", body); Assert.Contains("\"authorityWriteReady\":false", body);
            Assert.All(app.Urls, url => Assert.StartsWith("https://127.0.0.1:", url));
            foreach (string path in new[] { "/login", "/swagger", "/debug", "/internal/v1/session-refill", "/internal/v1/authority-fleet" })
            { using var missing = await http.GetAsync(path, TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode); }
            Assert.Equal(1, fake.Audits);
            await app.StopAsync(TestContext.Current.CancellationToken);
        }
        finally { Environment.SetEnvironmentVariable("ASPNETCORE_URLS", prior); }
        Assert.Equal(1, fake.Disposals);
    }
    [Fact] public async Task Configured_next_leaf_pin_allows_reviewed_rotation()
    {
        var settings = fixture.Settings(); await using var app = SvsHost.Build(settings, _ => new FakeResources()); await app.StartAsync(TestContext.Current.CancellationToken);
        using var http = fixture.Http(settings, fixture.NextClient); using var response = await http.GetAsync("/health/live", TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
    [Theory][InlineData("missing")][InlineData("unregistered")][InlineData("wrong-ca")][InlineData("expired")][InlineData("future")][InlineData("wrong-eku")][InlineData("no-eku")][InlineData("wrong-spiffe")][InlineData("no-san")]
    public async Task Actual_TLS_rejects_missing_unknown_or_invalid_service_identity(string fault)
    {
        using var other = fault == "wrong-ca" ? new HostFixture() : null;
        using var cert = fault switch
        {
            "missing" => null, "wrong-ca" => other!.Leaf(false), "expired" => fixture.Leaf(false, after: DateTimeOffset.UtcNow.AddDays(-1), before: DateTimeOffset.UtcNow.AddDays(-2)),
            "future" => fixture.Leaf(false, before: DateTimeOffset.UtcNow.AddDays(1), after: DateTimeOffset.UtcNow.AddDays(2)),
            "wrong-eku" => fixture.Leaf(false, eku: "1.3.6.1.5.5.7.3.1"), "no-eku" => fixture.Leaf(false, includeEku: false),
            "wrong-spiffe" => fixture.Leaf(false, identity: "spiffe://intranet.local/service/attacker"), "no-san" => fixture.Leaf(false, identity: null), _ => fixture.Leaf(false)
        };
        var settings = fixture.Settings(j => { if (fault != "unregistered" && cert is not null) j["callers"]![0]!["leafSha256"] = new JsonArray(HostFixture.Pin(cert)); });
        await using var app = SvsHost.Build(settings, _ => new FakeResources()); await app.StartAsync(TestContext.Current.CancellationToken);
        using var http = fixture.Http(settings, cert);
        try { using var response = await http.GetAsync("/health/live", TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); }
        catch (HttpRequestException) { /* Expected TLS-level rejection before routing. */ }
    }
    [Fact] public async Task Forwarded_certificate_header_cannot_supply_identity()
    {
        var settings = fixture.Settings(); await using var app = SvsHost.Build(settings, _ => new FakeResources()); await app.StartAsync(TestContext.Current.CancellationToken);
        using var http = fixture.Http(settings, null); http.DefaultRequestHeaders.Add("X-Forwarded-Client-Cert", HostFixture.Pin(fixture.Client));
        await Assert.ThrowsAsync<HttpRequestException>(() => http.GetAsync("/health/live", TestContext.Current.CancellationToken));
    }
    [Fact] public async Task Client_rejects_untrusted_server_in_real_TLS()
    {
        var settings = fixture.Settings(); await using var app = SvsHost.Build(settings, _ => new FakeResources()); await app.StartAsync(TestContext.Current.CancellationToken);
        using var http = fixture.Http(settings, fixture.Client, trustServer: false);
        await Assert.ThrowsAsync<HttpRequestException>(() => http.GetAsync("/health/live", TestContext.Current.CancellationToken));
    }
    [Fact] public async Task Reused_TLS_connection_rechecks_client_expiration_before_each_reply()
    {
        using var leaf = fixture.Leaf(false, after: DateTimeOffset.UtcNow.AddSeconds(4));
        var settings = fixture.Settings(j => j["callers"]![0]!["leafSha256"] = new JsonArray(HostFixture.Pin(leaf)));
        await using var app = SvsHost.Build(settings, _ => new FakeResources()); await app.StartAsync(TestContext.Current.CancellationToken);
        using var http = fixture.Http(settings, leaf); using var first = await http.GetAsync("/health/live", TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        await Task.Delay(4500, TestContext.Current.CancellationToken);
        using var expired = await http.GetAsync("/health/live", TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.Forbidden, expired.StatusCode);
    }
    [Fact] public async Task HTTP11_cannot_reach_the_HTTP2_only_health_endpoint()
    {
        var settings = fixture.Settings(); await using var app = SvsHost.Build(settings, _ => new FakeResources()); await app.StartAsync(TestContext.Current.CancellationToken);
        using var http = fixture.Http(settings, fixture.Client); http.DefaultRequestVersion = HttpVersion.Version11;
        try { using var response = await http.GetAsync("/health/live", TestContext.Current.CancellationToken); Assert.NotEqual(HttpStatusCode.OK, response.StatusCode); }
        catch (HttpRequestException) { }
    }
    [Fact] public async Task Database_outage_is_live_but_not_ready_and_can_recover_on_background_inspection()
    {
        var fake = new FakeResources { Next = DatabaseIdentityAuditStatus.Unavailable }; var settings = fixture.Settings(j => j["auditIntervalMilliseconds"] = 1000);
        await using var app = SvsHost.Build(settings, _ => fake); await app.StartAsync(TestContext.Current.CancellationToken); using var http = fixture.Http(settings, fixture.Client);
        using var live = await http.GetAsync("/health/live", TestContext.Current.CancellationToken); using var ready = await http.GetAsync("/health/ready", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, live.StatusCode); Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
        fake.Next = DatabaseIdentityAuditStatus.Verified; await fake.AuditedAgain.Task.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
        using var recovered = await http.GetAsync("/health/ready", TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
    }
    [Fact] public async Task Startup_positive_privilege_violation_cannot_open_listener()
    {
        var fake = new FakeResources { Next = DatabaseIdentityAuditStatus.Rejected }; await using var app = SvsHost.Build(fixture.Settings(), _ => fake);
        await Assert.ThrowsAsync<InvalidOperationException>(() => app.StartAsync(TestContext.Current.CancellationToken)); Assert.False(fake.Admission.CacheReady);
    }
    [Fact] public async Task Positive_background_violation_closes_request_admission_without_faking_process_death()
    {
        var fake = new FakeResources(); var settings = fixture.Settings(j => j["auditIntervalMilliseconds"] = 1000);
        await using var app = SvsHost.Build(settings, _ => fake); await app.StartAsync(TestContext.Current.CancellationToken); fake.Next = DatabaseIdentityAuditStatus.Rejected;
        await fake.AuditedAgain.Task.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
        var requests = app.Services.GetRequiredService<RequestLifetime>(); await TestWait.Until(() => !requests.Open); Assert.False(requests.Open); Assert.False(fake.Admission.CacheReady);
    }
    [Fact] public async Task Timed_out_handler_keeps_its_slot_until_late_completion()
    {
        var settings = fixture.Settings(j => { j["maximumConcurrentRequests"] = 1; j["requestTimeoutMilliseconds"] = 100; });
        await using var app = SvsHost.Build(settings, _ => new FakeResources());
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        app.MapGet("/owned-test-work", async () => { entered.TrySetResult(); await finish.Task; return Results.Ok(); });
        await app.StartAsync(TestContext.Current.CancellationToken); using var http = fixture.Http(settings, fixture.Client);
        var first = http.GetAsync("/owned-test-work", TestContext.Current.CancellationToken);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);
            await Assert.ThrowsAsync<HttpRequestException>(() => first);
            var requests = app.Services.GetRequiredService<RequestLifetime>(); Assert.Equal(1, requests.Active);
            using var blocked = await http.GetAsync("/owned-test-work", TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.ServiceUnavailable, blocked.StatusCode);
            finish.TrySetResult();
            for (int i = 0; i < 100 && requests.Active != 0; i++) await Task.Delay(10, TestContext.Current.CancellationToken);
            Assert.Equal(0, requests.Active);
        }
        finally { finish.TrySetResult(); }
    }
    [Fact] public async Task Graceful_stop_waits_for_actual_owned_handler_completion()
    {
        var settings = fixture.Settings(); await using var app = SvsHost.Build(settings, _ => new FakeResources());
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        app.MapGet("/owned-test-work", async () => { entered.TrySetResult(); await finish.Task; return Results.Ok(); });
        await app.StartAsync(TestContext.Current.CancellationToken); using var http = fixture.Http(settings, fixture.Client); var work = http.GetAsync("/owned-test-work", TestContext.Current.CancellationToken);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken); var stop = app.StopAsync(TestContext.Current.CancellationToken);
        try { Assert.False(stop.IsCompleted); finish.TrySetResult(); using var response = await work; Assert.Equal(HttpStatusCode.OK, response.StatusCode); await stop.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken); }
        finally { finish.TrySetResult(); }
    }
}
