using treehammock.Rigging.Dependencies;
using Microsoft.Extensions.Options;

using StackExchange.Redis;

using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;

namespace treehammock.Rigging.Abuse;

public sealed class DragonflyAbuseCounterStore : IAsyncDisposable, IDisposable, IAbuseCounterStore
{
    private readonly AbuseControlSettings _abuseSettings;
    private readonly AbuseCounterCacheSettings _cacheSettings;
    private readonly CacheConnectionSlot _slot;
    private readonly bool _ownsSlot;
    private readonly IPostgreSqlAbuseBudgetStore? _durable;
    private readonly HashSet<AbuseFeature> _durablePolicies;
    private readonly bool _requireDurable;
    private readonly TimeSpan _durableTimeout;

    public DragonflyAbuseCounterStore(
        IOptions<AbuseCounterCacheSettings> cacheSettings,
        IOptions<AbuseControlSettings> abuseSettings)
        : this(cacheSettings, abuseSettings, (IConnectionMultiplexer?)null)
    {
    }

    public DragonflyAbuseCounterStore(
        IOptions<AbuseCounterCacheSettings> cacheSettings,
        IOptions<AbuseControlSettings> abuseSettings,
        IConnectionMultiplexer? connection, IPostgreSqlAbuseBudgetStore? durable = null)
    {
        _cacheSettings = cacheSettings.Value;
        _abuseSettings = abuseSettings.Value;
        _slot = connection is null ? new CacheConnectionSlot(_cacheSettings) : new CacheConnectionSlot(_cacheSettings, connection);
        _durable = durable;
        _durablePolicies = new(_abuseSettings.PostgreSqlFallbackPolicies ?? []);
        _requireDurable = _abuseSettings.CounterFailureMode == AbuseCounterFailureMode.RequirePostgreSqlBudgetV1;
        _durableTimeout = TimeSpan.FromMilliseconds(Math.Clamp(_abuseSettings.PostgreSqlBudgetTimeoutMilliseconds, 50, 5000));
        _ownsSlot = true;
        _slot.Start();
    }
    public DragonflyAbuseCounterStore(IOptions<AbuseCounterCacheSettings> cacheSettings,
        IOptions<AbuseControlSettings> abuseSettings, CacheConnectionSlot slot, IPostgreSqlAbuseBudgetStore? durable = null)
    {
        _cacheSettings = cacheSettings.Value;
        _abuseSettings = abuseSettings.Value;
        _slot = slot;
        _durable = durable;
        _durablePolicies = new(_abuseSettings.PostgreSqlFallbackPolicies ?? []);
        _requireDurable = _abuseSettings.CounterFailureMode == AbuseCounterFailureMode.RequirePostgreSqlBudgetV1;
        _durableTimeout = TimeSpan.FromMilliseconds(Math.Clamp(_abuseSettings.PostgreSqlBudgetTimeoutMilliseconds, 50, 5000));
    }
    public IConnectionMultiplexer Connection => _slot.Connection;
    public IDatabase Database => _slot.Database;
    public ValueTask DisposeAsync() => _ownsSlot ? _slot.DisposeAsync() : ValueTask.CompletedTask;
    public void Dispose() { if (_ownsSlot) _slot.Dispose(); }

    public async Task<CounterDecision> IncrementAsync(
        AbuseCounterKey key,
        AbuseCounterLimit limit,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CounterDecision decision = await IncrementCoreAsync(key, limit, cancellationToken);
        AbuseOperationalTelemetry.RecordCounterAdmission(key.Feature, key.Dimension, decision);
        return decision;
    }

    private async Task<CounterDecision> IncrementCoreAsync(AbuseCounterKey key, AbuseCounterLimit limit, CancellationToken cancellationToken)
    {
        TimeSpan timeout = Timeout;
        CounterDecision? authoritative = null;
        if (UsesDurableBudget(key))
        {
            authoritative = await DurableIncrement(key, limit, cancellationToken);
            if (!authoritative.CanAdmit)
            {
                return authoritative;
            }
        }

        try
        {
            // Retain raw completion telemetry even if the caller's bounded wait has already ended.
            Task<CounterDecision> raw = CacheIncrementAsync(key, limit);
            var cached = await WithTimeout(raw, timeout, cancellationToken);
            return cached.CanAdmit && authoritative is not null ? authoritative : cached;
        }
        catch (TimeoutException)
        {
            return CounterStoreUnavailableDecision(key, limit, AbuseReasonCodes.CounterStoreTimeout, "increment", authoritative);
        }
        catch (RedisException)
        {
            return CounterStoreUnavailableDecision(key, limit, AbuseReasonCodes.CounterStoreUnavailable, "increment", authoritative);
        }
        catch (ObjectDisposedException)
        {
            return CounterStoreUnavailableDecision(key, limit, AbuseReasonCodes.CounterStoreUnavailable, "increment", authoritative);
        }
        catch (InvalidOperationException)
        {
            return CounterStoreUnavailableDecision(key, limit, AbuseReasonCodes.CounterStoreUnavailable, "increment", authoritative);
        }
        catch (DependencyUnavailableException)
        {
            return CounterStoreUnavailableDecision(key, limit, AbuseReasonCodes.CounterStoreUnavailable, "increment", authoritative);
        }
    }

    private async Task<CounterDecision> CacheIncrementAsync(AbuseCounterKey key, AbuseCounterLimit limit)
    {
        RedisResult reply = await Database.ScriptEvaluateAsync(AbuseCounterScripts.Increment,
            [key.Value, key.CooldownValue],
            [limit.MaxAttempts, (long)limit.Window.TotalMilliseconds,
                (long)(limit.Cooldown?.TotalMilliseconds ?? 0), AbuseReasonCodes.FailureCooldownActive], CommandFlags.None);
        RedisResult[] values = (RedisResult[])reply;
        if (values.Length != 5) throw new InvalidOperationException("Invalid counter script reply.");
        long admitted = (long)values[0], rawCount = (long)values[1], milliseconds = (long)values[2], reason = (long)values[3], created = (long)values[4];
        if (admitted is < 0 or > 1 || rawCount < 0 || milliseconds is < 0 or > 86400000 || reason is < 0 or > 2 || created is < 0 or > 1
            || admitted == 1 && (rawCount < 1 || rawCount > limit.MaxAttempts || reason != 0 || created != 0 || milliseconds != 0)
            || admitted == 0 && (reason == 0 || milliseconds == 0 || reason == 2 && rawCount <= limit.MaxAttempts) || created == 1 && (reason != 2 || milliseconds == 0 || limit.Cooldown is null || limit.Cooldown == TimeSpan.Zero))
            throw new InvalidOperationException("Invalid counter transition result.");
        string? reasonCode = admitted == 1 ? null : reason == 1 ? AbuseReasonCodes.FailureCooldownActive : AbuseReasonCodes.CounterLimitExceeded;
        var decision = new CounterDecision(admitted == 1, CheckedCount(rawCount), limit.MaxAttempts, limit.Window,
            milliseconds > 0 ? TimeSpan.FromMilliseconds(milliseconds) : null, reasonCode, CooldownCreated: created == 1);
        if (decision.CooldownCreated)
            AbuseOperationalTelemetry.RecordCooldownStarted(key.Feature, key.Dimension, AbuseReasonCodes.CounterLimitExceeded, "dragonfly");
        return decision;
    }

    public async Task ResetAsync(
        AbuseCounterKey key,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        TimeSpan timeout = Timeout;
        if (UsesDurableBudget(key))
        {
            try
            {
                if (_durable is null) throw new InvalidOperationException("Durable budget owner unavailable.");
                await DependencyDeadline.RunAsync(async ct => { await _durable.ResetAsync(key, ct); return true; }, _durableTimeout, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex) { RecordDurableFailure("reset", ex); return; }
        }

        try
        {
            _ = await WithTimeout(Database.KeyDeleteAsync([key.Value, key.CooldownValue], CommandFlags.None), timeout, cancellationToken);
        }
        catch (TimeoutException)
        {
            AbuseOperationalTelemetry.RecordCounterStoreFailure("reset", AbuseReasonCodes.CounterStoreTimeout);
        }
        catch (RedisException)
        {
            AbuseOperationalTelemetry.RecordCounterStoreFailure("reset", AbuseReasonCodes.CounterStoreUnavailable);
        }
        catch (ObjectDisposedException)
        {
            AbuseOperationalTelemetry.RecordCounterStoreFailure("reset", AbuseReasonCodes.CounterStoreUnavailable);
        }
        catch (InvalidOperationException)
        {
            AbuseOperationalTelemetry.RecordCounterStoreFailure("reset", AbuseReasonCodes.CounterStoreUnavailable);
        }
        catch (DependencyUnavailableException)
        {
            AbuseOperationalTelemetry.RecordCounterStoreFailure("reset", AbuseReasonCodes.CounterStoreUnavailable);
        }
    }

    public async Task<CooldownDecision> GetCooldownAsync(
        AbuseCounterKey key,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        TimeSpan timeout = Timeout;
        CooldownDecision? authoritative = null;
        if (UsesDurableBudget(key))
        {
            authoritative = await DurableCooldown(key, cancellationToken);
            if (authoritative.BlocksAdmission) return authoritative;
        }

        try
        {
            long repairMilliseconds = Math.Clamp(
                (long)(_abuseSettings.FailureCooldown.CooldownSeconds > 0
                    ? _abuseSettings.FailureCooldown.CooldownSeconds : _abuseSettings.FailureCooldown.WindowSeconds) * 1000,
                1, 86_400_000);
            RedisResult result = await WithTimeout(Database.ScriptEvaluateAsync(AbuseCounterScripts.Cooldown,
                [key.CooldownValue], [repairMilliseconds], CommandFlags.None), timeout, cancellationToken);
            long milliseconds = (long)result;
            return milliseconds > 0
                ? new CooldownDecision(true, TimeSpan.FromMilliseconds(milliseconds), AbuseReasonCodes.FailureCooldownActive)
                : new CooldownDecision(false, null, null);
        }
        catch (TimeoutException)
        {
            return CounterStoreUnavailableCooldown(AbuseReasonCodes.CounterStoreTimeout, "cooldown_lookup", authoritative);
        }
        catch (RedisException)
        {
            return CounterStoreUnavailableCooldown(AbuseReasonCodes.CounterStoreUnavailable, "cooldown_lookup", authoritative);
        }
        catch (ObjectDisposedException)
        {
            return CounterStoreUnavailableCooldown(AbuseReasonCodes.CounterStoreUnavailable, "cooldown_lookup", authoritative);
        }
        catch (InvalidOperationException)
        {
            return CounterStoreUnavailableCooldown(AbuseReasonCodes.CounterStoreUnavailable, "cooldown_lookup", authoritative);
        }
        catch (DependencyUnavailableException)
        {
            return CounterStoreUnavailableCooldown(AbuseReasonCodes.CounterStoreUnavailable, "cooldown_lookup", authoritative);
        }
    }

    private TimeSpan Timeout => TimeSpan.FromMilliseconds(Math.Clamp(_abuseSettings.DragonflyTimeoutMilliseconds, 10, 5000));

    private bool UsesDurableBudget(AbuseCounterKey key) => _requireDurable && _durablePolicies.Contains(key.Feature) && AbuseCounterPolicyCatalog.SupportsPostgreSqlBudget(key);

    private async Task<CounterDecision> DurableIncrement(AbuseCounterKey key, AbuseCounterLimit limit, CancellationToken token)
    {
        try
        {
            if (_durable is null) throw new InvalidOperationException("Durable budget owner unavailable.");
            var result = await DependencyDeadline.RunAsync(ct => _durable.IncrementAsync(key, limit, ct), _durableTimeout, token);
            if (result.Limit != limit.MaxAttempts || result.Window != limit.Window || result.CanAdmit && (result.CurrentCount <= 0 || result.CurrentCount > limit.MaxAttempts))
                throw new InvalidOperationException("Invalid durable admission result.");
            if (result.Unavailable)
            {
                string reason = result.ReasonCode == AbuseReasonCodes.CounterStoreTimeout ? AbuseReasonCodes.CounterStoreTimeout : AbuseReasonCodes.CounterStoreUnavailable;
                AbuseOperationalTelemetry.RecordCounterStoreFailure("increment",reason,"postgresql");
                return Unavailable(key,limit,reason);
            }
            return result;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            string reason = RecordDurableFailure("increment", ex);
            return Unavailable(key, limit, reason);
        }
    }

    private async Task<CooldownDecision> DurableCooldown(AbuseCounterKey key, CancellationToken token)
    {
        try
        {
            if (_durable is null) throw new InvalidOperationException("Durable budget owner unavailable.");
            return await DependencyDeadline.RunAsync(ct => _durable.GetCooldownAsync(key, ct), _durableTimeout, token);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception ex) { return new(true, null, RecordDurableFailure("cooldown_lookup", ex), CounterStoreAvailability.Unavailable); }
    }

    private static string RecordDurableFailure(string operation, Exception error)
    {
        string reason = error is TimeoutException or Npgsql.PostgresException { SqlState: "57014" or "55P03" } ? AbuseReasonCodes.CounterStoreTimeout : AbuseReasonCodes.CounterStoreUnavailable;
        AbuseOperationalTelemetry.RecordCounterStoreFailure(operation, reason, "postgresql");
        return reason;
    }

    private static CounterDecision Unavailable(AbuseCounterKey key, AbuseCounterLimit limit, string reason)
        => new(false, 0, limit.MaxAttempts, limit.Window, null, reason, CounterStoreAvailability.Unavailable);

    private CounterDecision CounterStoreUnavailableDecision(AbuseCounterKey key, AbuseCounterLimit limit,
        string reasonCode, string operation, CounterDecision? authoritative)
    {
        AbuseOperationalTelemetry.RecordCounterStoreFailure(operation, reasonCode);
        // A flag, existing account or proof row is never admission authority.
        if (authoritative?.CanAdmit == true)
        {
            return authoritative;
        }
        return Unavailable(key, limit, reasonCode);
    }

    private CooldownDecision CounterStoreUnavailableCooldown(string reasonCode, string operation, CooldownDecision? authoritative)
    {
        AbuseOperationalTelemetry.RecordCounterStoreFailure(operation, reasonCode);
        return authoritative is not null && !authoritative.Unavailable ? authoritative
            : new(true, null, reasonCode, CounterStoreAvailability.Unavailable);
    }

    private static int CheckedCount(long count)
    {
        return count > int.MaxValue ? int.MaxValue : (int)count;
    }

    private static Task<T> WithTimeout<T>(Task<T> task, TimeSpan timeout, CancellationToken cancellationToken)
        => DependencyDeadline.RunAsync(_ => task, timeout, cancellationToken);
}
