using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using treehammock.Rigging.Config;
using treehammock.Rigging.Health;
using treehammock.Tests.Infrastructure;
namespace treehammock.Tests.Integration;
public sealed class Cor23OReadinessHttpTests
{
    private sealed class Client : IHealthProbeClient
    {
        public int Calls;
        public Func<CancellationToken, Task<bool>> Run = _ => Task.FromResult(true);
        public Task<bool> ProbeAsync(HealthDependency dependency, CancellationToken token)
        { Interlocked.Increment(ref Calls); return Run(token); }
    }
    private static TreehammockWebApplicationFactory Host(Dictionary<string, string?> settings, HealthDependencyService? service = null) => new(settings, services =>
    {
        services.RemoveAll<IHostedService>(); // Unrelated workers require external services.
        if (service is not null)
        {
            services.RemoveAll<HealthDependencyService>(); services.RemoveAll<IHealthDependencyService>();
            services.AddSingleton(service); services.AddSingleton<IHealthDependencyService>(provider => provider.GetRequiredService<HealthDependencyService>());
            services.AddHostedService(provider => provider.GetRequiredService<HealthDependencyService>());
        }
    });
    [Fact]
    public async Task Real_public_routes_share_samples_report_freshness_and_keep_liveness_dependency_free()
    {
        var backend = new Client(); var sampler = new HealthDependencyService(backend, new() { SampleMaxAgeMilliseconds = 1000 });
        using var factory = Host(TestConfiguration.ValidSettings(), sampler); using var http = factory.CreateClient();
        using (var live = await http.GetAsync("/health/live")) { Assert.Equal(HttpStatusCode.OK, live.StatusCode); Assert.Equal(0, backend.Calls); }
        var requests = Enumerable.Range(0, 64).Select(i => http.GetAsync(i % 2 == 0 ? "/health/ready" : "/health/dependencies"));
        var replies = await Task.WhenAll(requests);
        try
        {
            Assert.Equal(4, backend.Calls);
            foreach (var reply in replies)
            {
                Assert.Equal(HttpStatusCode.OK, reply.StatusCode); Assert.True(reply.Headers.CacheControl?.NoStore);
                var body = await reply.Content.ReadFromJsonAsync<JsonElement>();
                Assert.Equal("ready", body.GetProperty("status").GetString()); Assert.Equal(4, body.GetProperty("dependencies").GetArrayLength());
                Assert.InRange(body.GetProperty("sampleAgeMilliseconds").GetInt64(), 0, 999);
                Assert.Equal(1000, body.GetProperty("freshnessLimitMilliseconds").GetInt32());
            }
        }
        finally { foreach (var reply in replies) reply.Dispose(); }
    }
    [Fact]
    public async Task Routed_outage_is_sanitized_503_and_liveness_remains_200()
    {
        var pending = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var backend = new Client { Run = _ => pending.Task };
        var sampler = new HealthDependencyService(backend, new() { TotalTimeoutMilliseconds = 150, DependencyTimeoutMilliseconds = 50 });
        using var factory = Host(TestConfiguration.ValidSettings(), sampler); using var http = factory.CreateClient();
        try
        {
            using var reply = await http.GetAsync("/health/ready"); Assert.Equal(HttpStatusCode.ServiceUnavailable, reply.StatusCode);
            string text = await reply.Content.ReadAsStringAsync(); Assert.DoesNotContain("password", text); Assert.Contains("unhealthy", text);
            using var live = await http.GetAsync("/health/live"); Assert.Equal(HttpStatusCode.OK, live.StatusCode); Assert.Equal(4, backend.Calls);
        }
        finally { pending.TrySetResult(true); await sampler.DisposeAsync(); }
    }
    [Theory]
    [InlineData("TotalTimeoutMilliseconds", "0")][InlineData("DependencyTimeoutMilliseconds", "2001")]
    [InlineData("SampleMaxAgeMilliseconds", "1001")][InlineData("UnknownBudget", "10")]
    public void Real_host_rejects_invalid_inverted_or_unknown_readiness_configuration(string key, string value)
    {
        var settings = TestConfiguration.ValidSettings(); settings["HealthProbeSettings:" + key] = value;
        using var factory = Host(settings); var error = Record.Exception(() => factory.CreateClient());
        Assert.NotNull(error); Assert.Contains("HealthProbeSettings", error.ToString());
    }
    [Fact]
    public void Real_host_rejects_a_missing_readiness_section()
    {
        var settings = TestConfiguration.ValidSettings();
        foreach (string key in settings.Keys.Where(k => k.StartsWith("HealthProbeSettings:")).ToArray()) settings.Remove(key);
        using var factory = Host(settings); Assert.NotNull(Record.Exception(() => factory.CreateClient()));
    }
}
