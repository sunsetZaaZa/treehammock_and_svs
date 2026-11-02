using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using NodaTime;
using treehammock.DataLayer.Cache;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Dependencies;

namespace treehammock.Services;

public sealed record SessionRefreshOutcome(int Status, string Code, RefreshSessionResponse Response, ActiveSession? Session = null);

public sealed class SessionRefreshService(ISessionRefreshRepo repository, IJsonWebTokenUtility tokens,
    IActiveUserCacheService cache, IOptions<JWTSettings> options, IOptions<SessionCacheFallbackSettings> timeouts)
{
    public async Task<SessionRefreshOutcome> RefreshAsync(RefreshSessionRequest request, CancellationToken cancellation)
    {
        string refreshHash = AccessTokenHashUtility.Hash(request.refreshToken);
        RefreshSessionSnapshot? snapshot;
        try
        {
            snapshot = await DependencyDeadline.RunAsync(
                token => repository.FindAsync(refreshHash, request.sessionId, request.generation, token),
                timeouts.Value.DatabaseFallbackTimeout, cancellation);
        }
        catch (TimeoutException exception)
        {
            throw DependencyUnavailableException.Database("get_refresh_session", DependencyStage.Read, exception);
        }
        if (snapshot is null) return new(409, "REFRESH_CREDENTIAL_STALE", new());
        var settings = options.Value;
        int accessSeconds = checked(settings.RefreshTokenAliveDays_Short * 86400 + settings.RefreshTokenAliveHours_Short * 3600 + settings.RefreshTokenAliveMinutes_Short * 60);
        byte[] signingKey = RandomNumberGenerator.GetBytes(settings.RefreshTokenBytes);
        Guid identity = Guid.NewGuid();
        string accessToken = tokens.GenerateAccessToken(signingKey, snapshot.WebKey);
        string newHash = AccessTokenHashUtility.Hash(accessToken);
        RefreshSessionResult result = await repository.RotateAsync(snapshot, refreshHash, newHash, signingKey, identity,
            accessSeconds, settings.MinimumRefreshIntervalSeconds, cancellation);
        if (!result.Result) return new(result.Code == "REFRESH_TOO_EARLY" ? 429 : 409, result.Code, new());
        if (result.AccessExpiration is null || result.SessionExpiration is null || result.Entitlements is null)
            throw DependencyUnavailableException.InvalidResponse("refresh_session");
        var old = snapshot.Session;
        var current = new ActiveSession(old.accountId, signingKey, (short)Math.Min(32767, (old.refreshes ?? 0) + 1),
            old.createdOn, old.sessionLifespan!, result.AccessExpiration.Value, result.SessionExpiration.Value, result.CutOff,
            result.Entitlements.Features, identity, old.accountSecurityStamp, old.familyId, old.generation + 1,
            entitlements: result.Entitlements);
        // Durable SQL/receipt success owns the response. Cache repair cannot
        // change a committed rotation into a claimed rollback or token clear.
        try
        {
            var cacheEnd = result.Entitlements.NextBoundary is { } boundary && boundary < result.AccessExpiration.Value ? boundary : result.AccessExpiration.Value;
            var ttl = cacheEnd - SystemClock.Instance.GetCurrentInstant();
            if (ttl > Duration.Zero)
                await DependencyDeadline.RunAsync(token => cache.SetSession(newHash, current, ttl.ToTimeSpan(), cancellationToken: token),
                    timeouts.Value.CacheWriteTimeout, cancellation);
        }
        catch (Exception) { /* Authoritative fallback hydrates the committed generation. */ }
        try
        {
            await DependencyDeadline.RunAsync(token => cache.RevokeSession(snapshot.AccessTokenHash, cancellationToken: token),
                timeouts.Value.CacheRevokeTimeout, cancellation);
        }
        catch (Exception) { /* Trust validation rejects old cache hits. */ }
        var now = SystemClock.Instance.GetCurrentInstant();
        if (!current.entitlements!.IsCurrent(current.accountId, now))
        {
            var fresh = await DependencyDeadline.RunAsync(token => repository.FindAsync(AccessTokenHashUtility.Hash(SessionProtocol.Credentials(current).refreshToken), current.familyId, current.generation, token),
                timeouts.Value.DatabaseFallbackTimeout, cancellation);
            if (fresh?.Session.entitlements is null || !fresh.Session.entitlements.IsCurrent(current.accountId, SystemClock.Instance.GetCurrentInstant()))
                return new(409, "REFRESH_OUTPUT_EXPIRED", new());
            if (fresh.Session.securityStamp != identity || fresh.Session.accountSecurityStamp != old.accountSecurityStamp)
                return new(409, "REFRESH_OUTPUT_EXPIRED", new());
            current = SessionProtocol.FromSession(fresh.Session);
            now = SystemClock.Instance.GetCurrentInstant();
        }
        if (current.accessExpiration <= now || current.EffectiveSessionExpiration <= now)
            return new(409, "REFRESH_OUTPUT_EXPIRED", new());
        return new(200, "SESSION_REFRESHED", new(accessToken, SessionProtocol.Credentials(current)), current);
    }
}
