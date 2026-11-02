using Microsoft.Extensions.Options;
using NodaTime;
using treehammock.DataLayer.Cache;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;

namespace treehammock.Services;

// One sequential worker per host; no new database or cache clients are owned here.
public sealed class SessionCacheWarmupWorker(
    ISessionCacheWarmupRepo candidates,
    ISessionRepo sessions,
    IActiveUserCacheService cache,
    IOptions<SessionCacheWarmupSettings> options,
    IOptions<JWTSettings> jwtOptions,
    ILogger<SessionCacheWarmupWorker> logger) : BackgroundService
{
    private readonly SessionCacheWarmupSettings _settings = options.Value;
    private readonly JWTSettings _jwt = jwtOptions.Value;
    private string? _afterHash;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_settings.Enabled) return;
        // BackgroundService must never hold up host startup on a completed dependency task.
        await Task.Yield();
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        if (_settings.DurationSeconds > 0)
            lifetime.CancelAfter(TimeSpan.FromSeconds(_settings.DurationSeconds));
        try
        {
            while (!lifetime.IsCancellationRequested)
            {
                try
                {
                    using var batch = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                    batch.CancelAfter(TimeSpan.FromMilliseconds(_settings.BatchTimeoutMilliseconds));
                    int inserted = await WarmBatchAsync(batch.Token);
                    logger.LogDebug("Session cache warmup batch completed; {Inserted} missing entries inserted.", inserted);
                }
                catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { break; }
                catch (OperationCanceledException)
                {
                    logger.LogWarning("Session cache warmup batch deadline expired; retrying after the configured interval.");
                }
                catch (Exception)
                {
                    // Do not log provider exceptions, hashes, payloads or signing keys.
                    logger.LogWarning("Session cache warmup dependency unavailable; retrying after the configured interval.");
                }
                // Delay after completion/failure, so slow dependencies cannot create catch-up bursts.
                await Task.Delay(TimeSpan.FromSeconds(_settings.IntervalSeconds), lifetime.Token);
            }
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
    }

    internal async Task<int> WarmBatchAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var hashes = await candidates.ReadCandidateHashesAsync(_afterHash, _settings.BatchSize, cancellationToken);
        if (hashes.Count > _settings.BatchSize) throw new InvalidOperationException("Warmup candidate batch exceeded its limit.");
        int inserted = 0;
        foreach (string hash in hashes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Read afresh after enumeration, so rotation/logout/account-stamp changes are observed.
            var stored = await sessions.GetSession(hash, cancellationToken);
            if (stored?.sessionLifespan is not null && stored.refreshes is not null)
            {
                var session = SessionProtocol.FromSession(stored);
                TimeSpan ttl = CalculateTtl(session, _jwt, _settings.CacheTtlSeconds, SystemClock.Instance.GetCurrentInstant());
                if (ttl > TimeSpan.Zero && await cache.WarmSession(hash, session, ttl, cancellationToken)) inserted++;
            }
            // Advance only after an entry has completed. A failed cache command retries this entry next time.
            _afterHash = hash;
        }
        // Wrap only at end of a scan; missing/evicted entries can be revisited in subsequent cycles.
        if (hashes.Count < _settings.BatchSize) _afterHash = null;
        return inserted;
    }

    internal static TimeSpan CalculateTtl(ActiveSession session, JWTSettings jwt, int ttlSeconds, Instant now)
    {
        if (session.entitlements?.IsCurrent(session.accountId, now) != true) return TimeSpan.Zero;
        var configured = Duration.FromDays(jwt.RefreshTokenAliveDays) + Duration.FromHours(jwt.RefreshTokenAliveHours)
            + Duration.FromMinutes(jwt.RefreshTokenAliveMinutes);
        var expiry = now + Duration.FromSeconds(ttlSeconds);
        if (now + configured < expiry) expiry = now + configured;
        if (session.accessExpiration < expiry) expiry = session.accessExpiration;
        if (session.EffectiveSessionExpiration < expiry) expiry = session.EffectiveSessionExpiration;
        if (session.entitlements.NextBoundary is { } boundary && boundary < expiry) expiry = boundary;
        return expiry > now ? (expiry - now).ToTimeSpan() : TimeSpan.Zero;
    }
}
