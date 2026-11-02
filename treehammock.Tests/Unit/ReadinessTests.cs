using System.Diagnostics;
using Microsoft.Extensions.Options;
using treehammock.Controllers;
using treehammock.Models.Api;
using treehammock.Rigging.Config;
using treehammock.Rigging.Health;
namespace treehammock.Tests.Unit;
public sealed class Cor23OReadinessTests
{
    private sealed class Client : IHealthProbeClient
    {
        internal readonly int[] Calls = new int[4];
        internal Func<HealthDependency, CancellationToken, Task<bool>> Run = (_, _) => Task.FromResult(true);
        public Task<bool> ProbeAsync(HealthDependency dependency, CancellationToken token)
        { Interlocked.Increment(ref Calls[(int)dependency]); return Run(dependency, token); }
    }
    private sealed class Clock : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref _ticks);
        public override DateTimeOffset GetUtcNow() => new DateTimeOffset(2026, 10, 9, 0, 0, 0, TimeSpan.Zero).AddTicks(GetTimestamp());
        internal void Advance(int milliseconds) => Interlocked.Add(ref _ticks, TimeSpan.FromMilliseconds(milliseconds).Ticks);
    }
    private static HealthProbeSettings Settings(int total = 1000, int dependency = 500, int age = 10) => new()
    { TotalTimeoutMilliseconds = total, DependencyTimeoutMilliseconds = dependency, SampleMaxAgeMilliseconds = age };
    private static TaskCompletionSource<bool> Pending() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static async Task Until(Func<bool> condition)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        while (!condition()) await Task.Delay(5, deadline.Token);
    }
    [Fact]
    public async Task Pre_canceled_call_and_dependency_free_liveness_start_no_work()
    {
        var client = new Client(); await using var service = new HealthDependencyService(client, Settings());
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.CheckAsync(canceled.Token));
        var controller = new HealthController(service); _ = controller.Live();
        Assert.Equal(0, client.Calls.Sum()); Assert.Equal(0, service.GetDiagnostics().ActiveSamples);
    }
    [Theory]
    [InlineData(HealthDependency.PostgreSql)][InlineData(HealthDependency.ActiveSessions)]
    [InlineData(HealthDependency.TwoFactorSessions)][InlineData(HealthDependency.AbuseCounters)]
    public async Task Each_hung_dependency_times_out_and_retains_one_raw_operation_across_later_probes(HealthDependency target)
    {
        var blocked = Pending(); var clock = new Clock(); var client = new Client();
        client.Run = (dependency, _) => dependency == target ? blocked.Task : Task.FromResult(true);
        await using var service = new HealthDependencyService(client, Settings(200, 50), clock);
        try
        {
            var timer = Stopwatch.StartNew(); var first = await service.CheckAsync();
            Assert.False(first.Ready); Assert.True(timer.Elapsed < TimeSpan.FromMilliseconds(500));
            Assert.Equal("dependency_deadline", first.dependencies.Single(d => d.name == HealthDependencyService.Name(target)).reasonCode);
            Assert.Equal(1, service.GetDiagnostics().PendingOperations[target]);
            for (int i = 0; i < 8; i++)
            {
                clock.Advance(20); var next = await service.CheckAsync();
                Assert.False(next.Ready);
                Assert.Equal("probe_in_progress", next.dependencies.Single(d => d.name == HealthDependencyService.Name(target)).reasonCode);
            }
            Assert.Equal(1, client.Calls[(int)target]);
            blocked.SetResult(true); await Until(() => service.GetDiagnostics().PendingOperations[target] == 0);
            clock.Advance(20); Assert.True((await service.CheckAsync()).Ready); Assert.Equal(2, client.Calls[(int)target]);
        }
        finally { blocked.TrySetResult(true); }
    }
    [Fact]
    public async Task Caller_cancellation_does_not_poison_the_shared_sample_for_other_waiters()
    {
        var blocked = Pending(); var client = new Client { Run = (_, token) => blocked.Task.WaitAsync(token) };
        await using var service = new HealthDependencyService(client, Settings(1000, 800, 250));
        using var caller = new CancellationTokenSource(); var canceled = service.CheckAsync(caller.Token);
        var waiting = Enumerable.Range(0, 64).Select(_ => service.CheckAsync()).ToArray();
        try
        {
            await Until(() => client.Calls.Sum() == 4); caller.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => canceled);
            Assert.All(service.GetDiagnostics().PendingOperations.Values, count => Assert.Equal(1, count));
            blocked.SetResult(true); Assert.All(await Task.WhenAll(waiting), report => Assert.True(report.Ready));
            Assert.All(client.Calls, calls => Assert.Equal(1, calls));
        }
        finally { blocked.TrySetResult(true); }
    }
    [Fact]
    public async Task All_four_hangs_finish_one_parallel_sample_within_the_aggregate_budget()
    {
        var blocked = Pending(); var client = new Client { Run = (_, _) => blocked.Task };
        await using var service = new HealthDependencyService(client, Settings(150, 100));
        try
        {
            var timer = Stopwatch.StartNew(); var report = await service.CheckAsync();
            Assert.False(report.Ready); Assert.True(timer.Elapsed < TimeSpan.FromMilliseconds(400));
            Assert.Equal(4, client.Calls.Sum()); Assert.All(service.GetDiagnostics().PendingOperations.Values, n => Assert.Equal(1, n));
        }
        finally { blocked.TrySetResult(true); }
    }
    [Fact]
    public async Task Late_fault_is_observed_and_cannot_publish_success_or_poison_recovery()
    {
        var blocked = Pending(); var client = new Client(); var clock = new Clock();
        client.Run = (d, _) => d == HealthDependency.PostgreSql && client.Calls[0] == 1 ? blocked.Task : Task.FromResult(true);
        await using var service = new HealthDependencyService(client, Settings(200, 50), clock);
        try
        {
            Assert.False((await service.CheckAsync()).Ready); blocked.SetException(new InvalidOperationException("fixture credential=never report"));
            await Until(() => service.GetDiagnostics().PendingOperations[HealthDependency.PostgreSql] == 0);
            clock.Advance(20); Assert.True((await service.CheckAsync()).Ready); Assert.Equal(2, client.Calls[0]);
        }
        finally { blocked.TrySetResult(true); }
    }
    [Fact]
    public async Task Completed_samples_have_monotonic_age_exact_expiry_and_explicit_HTTP_metadata()
    {
        var clock = new Clock(); var client = new Client();
        await using var service = new HealthDependencyService(client, Settings(age: 250), clock);
        var first = await service.CheckAsync(); Assert.True(first.Ready); Assert.False(first.cached);
        clock.Advance(249); var reused = await service.CheckAsync(); Assert.True(reused.Ready); Assert.True(reused.cached);
        Assert.Equal(249, reused.sampleAgeMilliseconds); Assert.Equal(4, client.Calls.Sum());
        var response = HealthStatusResponse.FromReport(reused);
        Assert.Equal(reused.sampledAtUtc, response.sampledAtUtc); Assert.Equal(250, response.freshnessLimitMilliseconds);
        clock.Advance(1); var refreshed = await service.CheckAsync(); Assert.False(refreshed.cached); Assert.Equal(8, client.Calls.Sum());
        Assert.Equal(0, refreshed.sampleAgeMilliseconds); Assert.True(refreshed.Ready);
    }
    [Fact]
    public async Task Mutable_settings_cannot_extend_the_sample_or_change_its_budget_after_composition()
    {
        var settings = Settings(age: 20); var clock = new Clock(); var client = new Client();
        await using var service = new HealthDependencyService(client, settings, clock);
        _ = await service.CheckAsync(); settings.SampleMaxAgeMilliseconds = 1000; settings.TotalTimeoutMilliseconds = 5000;
        clock.Advance(20); var report = await service.CheckAsync(); Assert.Equal(8, client.Calls.Sum()); Assert.Equal(20, report.freshnessLimitMilliseconds);
    }
    [Fact]
    public async Task Shutdown_stops_new_work_but_retains_unfinished_probes_until_their_cleanup_completes()
    {
        var blocked = Pending(); var client = new Client { Run = (_, _) => blocked.Task };
        var service = new HealthDependencyService(client, Settings(200, 50)); var check = service.CheckAsync();
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        try
        {
            await Until(() => client.Calls.Sum() == 4);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.StopAsync(canceled.Token));
            var report = await service.CheckAsync(); Assert.False(report.Ready); Assert.All(report.dependencies, d => Assert.Equal("host_stopping", d.reasonCode));
            Assert.Equal(4, client.Calls.Sum()); Assert.False(service.DisposeAsync().AsTask().IsCompleted);
            blocked.SetResult(true); await service.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(2));
            Assert.All(service.GetDiagnostics().PendingOperations.Values, n => Assert.Equal(0, n));
            Assert.False((await check).Ready); service.Dispose();
        }
        finally { blocked.TrySetResult(true); await service.DisposeAsync(); }
    }
    [Theory]
    [InlineData(49, 10, 10)][InlineData(5001, 10, 10)][InlineData(100, 101, 10)]
    [InlineData(100, 9, 10)][InlineData(100, 50, 9)][InlineData(100, 50, 1001)]
    public void Invalid_or_inverted_budgets_are_rejected(int total, int dependency, int age)
    {
        Assert.Throws<OptionsValidationException>(() => new HealthDependencyService(new Client(), Settings(total, dependency, age)));
    }
    [Fact]
    public async Task Failure_text_is_sanitized_and_readiness_requires_all_four_dependencies()
    {
        var client = new Client { Run = (_, _) => throw new Exception("password=fixture host=never expose") };
        await using var service = new HealthDependencyService(client, Settings()); var report = await service.CheckAsync();
        Assert.False(report.Ready); Assert.DoesNotContain("password", System.Text.Json.JsonSerializer.Serialize(report));
        Assert.All(report.dependencies, result => Assert.Contains(result.reasonCode, new[] { "database_unavailable", "cache_unavailable" }));
        Assert.False(new HealthDependencyReport(Array.Empty<HealthDependencyResult>()).Ready);
    }
    [Fact]
    public async Task Blocked_cancellation_callback_keeps_its_slot_owned_even_after_the_provider_task_finishes()
    {
        var returned = Pending(); var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = new Client(); var clock = new Clock();
        client.Run = (dependency, token) =>
        {
            if (dependency != HealthDependency.PostgreSql || client.Calls[0] > 1) return Task.FromResult(true);
            token.Register(() => { entered.TrySetResult(); release.Task.GetAwaiter().GetResult(); });
            return returned.Task;
        };
        await using var service = new HealthDependencyService(client, Settings(200, 50), clock);
        try
        {
            Assert.False((await service.CheckAsync()).Ready); await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
            returned.TrySetResult(true);
            clock.Advance(20); Assert.False((await service.CheckAsync()).Ready);
            Assert.Equal(1, client.Calls[0]); Assert.Equal(1, service.GetDiagnostics().PendingOperations[HealthDependency.PostgreSql]);
            release.TrySetResult(); await Until(() => service.GetDiagnostics().PendingOperations[HealthDependency.PostgreSql] == 0);
            clock.Advance(20); Assert.True((await service.CheckAsync()).Ready);
        }
        finally { returned.TrySetResult(true); release.TrySetResult(); }
    }

}
