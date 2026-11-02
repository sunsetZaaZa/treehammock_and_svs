using System.Data.Common;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Dependencies;
namespace treehammock.Rigging.Health;

public sealed record HealthDependencyResult(string name, string status, string? reasonCode = null, long? latencyMilliseconds = null)
{
    public bool Healthy => string.Equals(status, HealthDependencyStatus.Healthy, StringComparison.Ordinal);
}
public sealed record HealthDependencyReport(IReadOnlyList<HealthDependencyResult> dependencies,
    DateTimeOffset? sampledAtUtc = null, long? sampleAgeMilliseconds = null, long? sampleDurationMilliseconds = null,
    int? freshnessLimitMilliseconds = null, bool cached = false)
{
    public bool Ready => dependencies.Count == 4 && dependencies.All(dependency => dependency.Healthy);
    public string Status => Ready ? HealthDependencyStatus.Ready : HealthDependencyStatus.NotReady;
}
public static class HealthDependencyStatus
{
    public const string Live = "live", Ready = "ready", NotReady = "not_ready", Healthy = "healthy", Unhealthy = "unhealthy";
}
public interface IHealthDependencyService
{
    Task<HealthDependencyReport> CheckAsync(CancellationToken cancellationToken = default);
}
public enum HealthDependency { PostgreSql, ActiveSessions, TwoFactorSessions, AbuseCounters }
internal interface IHealthProbeClient
{
    // Includes resource cleanup. Completion must represent the raw operation, never just a timeout wrapper.
    Task<bool> ProbeAsync(HealthDependency dependency, CancellationToken cancellationToken);
}
internal sealed class HealthProbeClient(StorageContext storage, CacheConnectionOwner cacheConnections) : IHealthProbeClient
{
    private readonly CacheConnectionOwner _cacheConnections = cacheConnections;
    public Task<bool> ProbeAsync(HealthDependency dependency, CancellationToken cancellationToken) => dependency switch
    {
        HealthDependency.PostgreSql => PostgreSql(cancellationToken),
        HealthDependency.ActiveSessions => Cache(_cacheConnections.Get(CacheProfile.ActiveSessions), cancellationToken),
        HealthDependency.TwoFactorSessions => Cache(_cacheConnections.Get(CacheProfile.TwoFactorSessions), cancellationToken),
        HealthDependency.AbuseCounters => Cache(_cacheConnections.Get(CacheProfile.AbuseCounters), cancellationToken),
        _ => throw new ArgumentOutOfRangeException(nameof(dependency))
    };
    private async Task<bool> PostgreSql(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await using DbConnection connection = await storage.CreateConnection(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested(); // A late acquisition must be disposed without starting a command.
        await using DbCommand command = connection.CreateCommand();
        command.CommandText = "select 1";
        command.CommandTimeout = 2; // Independent provider brake; the sampler supplies the shorter application budget.
        object? value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return Convert.ToInt32(value) == 1;
    }
    private static async Task<bool> Cache(CacheConnectionSlot connection, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // No connect/wait here. Cold owned initialization reports unavailable immediately.
        // Keep the RAW PING task pending after a sampler timeout; ExecuteAsync would retire only its wait.
        _ = await connection.Database.PingAsync().ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return true;
    }
}
public sealed record HealthProbeDiagnostics(int ActiveSamples, IReadOnlyDictionary<HealthDependency, int> PendingOperations, bool Stopping);

// On-demand single-flight sampling. Host ownership is independent from caller cancellation.
public sealed class HealthDependencyService : IHealthDependencyService, IHostedService, IAsyncDisposable, IDisposable
{
    private sealed record Sample(IReadOnlyList<HealthDependencyResult> Results, DateTimeOffset CompletedAt, long CompletedTimestamp, long Duration);
    private readonly IHealthProbeClient _client;
    private readonly HealthProbeSettings _settings;
    private readonly TimeProvider _clock;
    private readonly object _gate = new();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly ProbeSlot[] _slots;
    private Task<Sample>? _flight;
    private Sample? _sample;
    private Task? _disposal;
    private bool _stopped;
    public HealthDependencyService(StorageContext storageContext, CacheConnectionOwner cacheConnections,
        IOptions<HealthProbeSettings>? settings = null, TimeProvider? clock = null)
        : this(new HealthProbeClient(storageContext, cacheConnections), settings?.Value ?? new(), clock) { }
    internal HealthDependencyService(IHealthProbeClient client, HealthProbeSettings settings, TimeProvider? clock = null)
    {
        var errors = new List<System.ComponentModel.DataAnnotations.ValidationResult>();
        if (!System.ComponentModel.DataAnnotations.Validator.TryValidateObject(settings,
            new System.ComponentModel.DataAnnotations.ValidationContext(settings), errors, validateAllProperties: true))
            throw new OptionsValidationException(nameof(HealthProbeSettings), typeof(HealthProbeSettings), errors.Select(e => e.ErrorMessage ?? "Invalid readiness settings."));
        _client = client; _clock = clock ?? TimeProvider.System;
        _settings = new() { TotalTimeoutMilliseconds = settings.TotalTimeoutMilliseconds,
            DependencyTimeoutMilliseconds = settings.DependencyTimeoutMilliseconds, SampleMaxAgeMilliseconds = settings.SampleMaxAgeMilliseconds };
        _slots = Enum.GetValues<HealthDependency>().Select(_ => new ProbeSlot()).ToArray();
    }
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate) if (_stopped) throw new ObjectDisposedException(nameof(HealthDependencyService));
        return Task.CompletedTask; // Starting/liveness never probes dependencies.
    }
    public async Task<HealthDependencyReport> CheckAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Task<Sample> flight;
        lock (_gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_stopped) return Unavailable("host_stopping");
            if (_sample is not null && Age(_sample) < _settings.SampleMaxAgeMilliseconds)
                return Present(_sample, cached: true);
            if (_flight is null || _flight.IsCompleted)
            {
                long started = _clock.GetTimestamp();
                _flight = Task.Run(() => RunSampleAsync(started));
                DependencyDeadline.Observe(_flight);
            }
            flight = _flight;
        }
        try
        {
            // Caller budget also covers scheduling and a join of an already running sample.
            Sample sample = await flight.WaitAsync(TimeSpan.FromMilliseconds(_settings.TotalTimeoutMilliseconds), _clock, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (_stopped) return Unavailable("host_stopping");
                if (Age(sample) >= _settings.SampleMaxAgeMilliseconds) return Unavailable("stale_sample");
                return Present(sample, cached: false);
            }
        }
        catch (TimeoutException) { cancellationToken.ThrowIfCancellationRequested(); return Unavailable("readiness_deadline"); }
        catch (Exception) { cancellationToken.ThrowIfCancellationRequested(); return Unavailable("probe_failed"); }
    }
    private async Task<Sample> RunSampleAsync(long started)
    {
        var probes = Enum.GetValues<HealthDependency>().Select(dependency => CheckOneAsync(dependency, started)).ToArray();
        HealthDependencyResult[] results = await Task.WhenAll(probes).ConfigureAwait(false);
        long duration = Elapsed(started);
        if (duration >= _settings.TotalTimeoutMilliseconds) results = AllUnhealthy("readiness_deadline");
        var sample = new Sample(Array.AsReadOnly(results), _clock.GetUtcNow(), _clock.GetTimestamp(), duration);
        lock (_gate) if (!_stopped) _sample = sample;
        return sample;
    }
    private async Task<HealthDependencyResult> CheckOneAsync(HealthDependency dependency, long started)
    {
        long remaining = _settings.TotalTimeoutMilliseconds - Elapsed(started);
        if (remaining <= 0) return Unhealthy(dependency, "readiness_deadline");
        int budget = (int)Math.Min(remaining, _settings.DependencyTimeoutMilliseconds);
        ProbeSlot slot = _slots[(int)dependency];
        Task<bool> work;
        long admitted;
        lock (_gate)
        {
            if (_stopped) return Unhealthy(dependency, "host_stopping");
            if (slot.Work is { IsCompleted: false }) return Unhealthy(dependency, "probe_in_progress");
            // Raw acquisition/command/PING and cleanup remain owned by this slot until they actually finish.
            admitted = _clock.GetTimestamp();
            work = slot.Work = Task.Run(() => ProbeOwnedAsync(dependency, budget, admitted));
            DependencyDeadline.Observe(work);
        }
        try
        {
            // This timer is independent from provider cancellation callbacks, which may finish late.
            bool healthy = await work.WaitAsync(TimeSpan.FromMilliseconds(budget), _clock).ConfigureAwait(false);
            if (Elapsed(admitted) >= budget) return Unhealthy(dependency, "dependency_deadline");
            return healthy ? new(Name(dependency), HealthDependencyStatus.Healthy, latencyMilliseconds: Elapsed(started))
                : Unhealthy(dependency, "unexpected_probe_result");
        }
        catch (TimeoutException) { return Unhealthy(dependency, "dependency_deadline"); }
        catch (OperationCanceledException) { return Unhealthy(dependency, "dependency_canceled"); }
        catch (Exception) { return Unhealthy(dependency, dependency == HealthDependency.PostgreSql ? "database_unavailable" : "cache_unavailable"); }
    }
    private async Task<bool> ProbeOwnedAsync(HealthDependency dependency, int budget, long queued)
    {
        lock (_gate) if (_stopped) throw new OperationCanceledException();
        long remaining = budget - Elapsed(queued);
        if (remaining <= 0) throw new OperationCanceledException(); // Queued work cannot start beyond admission time.
        using var operation = new CancellationTokenSource();
        using var finished = new CancellationTokenSource();
        // Only our lightweight timer sees host/finish signals. Providers see the isolated operation token.
        using var timerStop = CancellationTokenSource.CreateLinkedTokenSource(finished.Token, _shutdown.Token);
        Task cancellation = CancelProbeAsync(operation, remaining, timerStop.Token);
        try
        {
            operation.Token.ThrowIfCancellationRequested();
            return await _client.ProbeAsync(dependency, operation.Token).ConfigureAwait(false);
        }
        finally
        {
            finished.Cancel();
            // Cancellation callbacks are residual work too: never retire the slot while they remain active.
            await cancellation.ConfigureAwait(false);
        }
    }
    private async Task CancelProbeAsync(CancellationTokenSource operation, long remaining, CancellationToken timerStop)
    {
        try { await Task.Delay(TimeSpan.FromMilliseconds(remaining), _clock, timerStop).ConfigureAwait(false); }
        catch (OperationCanceledException) when (timerStop.IsCancellationRequested)
        {
            if (!_shutdown.IsCancellationRequested) return;
        }
        await operation.CancelAsync().ConfigureAwait(false);
    }

    private long Elapsed(long timestamp) => Math.Max(0, (long)_clock.GetElapsedTime(timestamp, _clock.GetTimestamp()).TotalMilliseconds);
    private long Age(Sample sample) => Elapsed(sample.CompletedTimestamp);
    private HealthDependencyReport Present(Sample sample, bool cached)
    {
        long age = Age(sample);
        if (age >= _settings.SampleMaxAgeMilliseconds) return Unavailable("stale_sample");
        return new(sample.Results, sample.CompletedAt, age, sample.Duration, _settings.SampleMaxAgeMilliseconds, cached);
    }
    private HealthDependencyReport Unavailable(string reason) => new(AllUnhealthy(reason), freshnessLimitMilliseconds: _settings.SampleMaxAgeMilliseconds);
    private static HealthDependencyResult[] AllUnhealthy(string reason) => Enum.GetValues<HealthDependency>().Select(d => Unhealthy(d, reason)).ToArray();
    private static HealthDependencyResult Unhealthy(HealthDependency dependency, string reason) => new(Name(dependency), HealthDependencyStatus.Unhealthy, reason);
    internal static string Name(HealthDependency dependency) => dependency switch
    {
        HealthDependency.PostgreSql => "postgresql", HealthDependency.ActiveSessions => "dragonfly_active_sessions",
        HealthDependency.TwoFactorSessions => "dragonfly_two_factor_sessions", HealthDependency.AbuseCounters => "dragonfly_abuse_counters",
        _ => throw new ArgumentOutOfRangeException(nameof(dependency))
    };
    public HealthProbeDiagnostics GetDiagnostics()
    {
        lock (_gate) return new(_flight is { IsCompleted: false } ? 1 : 0,
            Enum.GetValues<HealthDependency>().ToDictionary(d => d, d => _slots[(int)d].Work is { IsCompleted: false } ? 1 : 0), _stopped);
    }
    private sealed class ProbeSlot { public Task<bool>? Work; }
    public async Task StopAsync(CancellationToken cancellationToken) => await DisposeAsync().AsTask().WaitAsync(cancellationToken).ConfigureAwait(false);
    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposal is not null) return new(_disposal);
            _stopped = true; _sample = null;
            Task? flight = _flight;
            Task[] raw = _slots.Where(s => s.Work is not null).Select(s => (Task)s.Work!).ToArray();
            _disposal = Task.Run(async () =>
            {
                Task cancellation = _shutdown.CancelAsync();
                try
                {
                    if (flight is not null) { try { await flight.ConfigureAwait(false); } catch (Exception) { } }
                    // Late faults are availability outcomes; observe every task and drain cleanup before token disposal.
                    foreach (Task work in raw) { try { await work.ConfigureAwait(false); } catch (Exception) { } }
                    await cancellation.ConfigureAwait(false);
                }
                finally { _shutdown.Dispose(); }
            });
            DependencyDeadline.Observe(_disposal);
            return new(_disposal);
        }
    }
}
