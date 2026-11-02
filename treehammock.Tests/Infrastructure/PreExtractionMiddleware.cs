// Frozen baseline nullable warning is retained in the production history.
#pragma warning disable CS8602
using Microsoft.AspNetCore.Http;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Dependencies;
using System.Security.Cryptography;

using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using NodaTime;

using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Repos;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Tests.Infrastructure;

// 1.0.0 stores authoritative session state in PostgreSQL and hydrates trusted cache entries from that source.
// Cross-shard Dragonfly replication and a dedicated cache-database topology are future cache/storage design work
// tracked in docs/release/RELEASE_FEATURE_MATRIX.md, not active runtime behavior.

public class Svs03PreExtractionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<Svs03PreExtractionMiddleware> _logger;

    public Svs03PreExtractionMiddleware(RequestDelegate next, ILogger<Svs03PreExtractionMiddleware>? logger = null)
    {
        _next = next;
        _logger = logger ?? NullLogger<Svs03PreExtractionMiddleware>.Instance;
    }

    public async Task InvokeAsync(
        HttpContext context,
        IActiveUserCacheService activeUsers,
        IJsonWebTokenUtility jwtUtils,
        ISessionRepo sessionRepo,
        IOptions<JWTSettings> jwtSettings,
        IOptions<SessionCacheFallbackSettings>? sessionCacheFallbackSettings = null)
    {
        CancellationToken cancellationToken = context.RequestAborted;
        SessionCacheFallbackSettings fallbackSettings = sessionCacheFallbackSettings?.Value ?? new SessionCacheFallbackSettings();

        context.Items[AuthContextItems.HashedAccessToken] = null;
        context.Items[AuthContextItems.WebKey] = null;
        context.Items[AuthContextItems.ActiveSession] = null;

        // Refresh authorizes its own opaque credential, including after access expiry.
        // Generic authentication never rotates or accepts a superseded generation.
        if (HttpMethods.IsPost(context.Request.Method) && string.Equals(context.Request.Path.Value?.TrimEnd('/'), SessionProtocol.RefreshPath, StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }

        string? accessToken = AccessTokenTransport.ReadRequestToken(context.Request.Headers);
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            await _next(context);
            return;
        }

        string accessTokenHash;
        try
        {
            accessTokenHash = AccessTokenHashUtility.Hash(accessToken);
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            await _next(context);
            return;
        }

        if (string.IsNullOrWhiteSpace(accessTokenHash))
        {
            await _next(context);
            return;
        }

        context.Response.Headers[SessionProtocol.ClearTokenHashHeader] = accessTokenHash;
        Instant currentMoment = SystemClock.Instance.GetCurrentInstant();
        ActiveSession? session = await SafeGetActiveSession(activeUsers, accessTokenHash, fallbackSettings, cancellationToken: cancellationToken);
        // Capture before authority validation repairs the mutable cache object.
        // Evaluation time alone changes on every SQL read and is not authority.
        var cachedAuthority = session is null ? null : CachedAuthority.Capture(session);
        if (session == null)
        {
            session = await TryLoadAuthoritativeSessionFromDatabase(sessionRepo, accessTokenHash, fallbackSettings.DatabaseFallbackTimeout, cancellationToken: cancellationToken);
            if (session == null)
            {
                context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
                await _next(context);
                return;
            }
        }
        else if (!await ValidateCachedSessionTrust(activeUsers, sessionRepo, accessTokenHash, session, fallbackSettings, cancellationToken))
        {
            context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
            await _next(context);
            return;
        }

        currentMoment = SystemClock.Instance.GetCurrentInstant();
        if (IsSessionHardExpired(session, currentMoment) || session.accessExpiration <= currentMoment)
        {
            await TryRevokeExpiredSession(activeUsers, sessionRepo, accessTokenHash, fallbackSettings, cancellationToken: cancellationToken);
            context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
            await _next(context);
            return;
        }

        (IntraMessage status, string? webKey) = await jwtUtils.ValidateAccessToken(
            accessToken,
            session.refreshToken,
            currentMoment,
            session.accessExpiration,
            JsonWebTokenPurpose.Active,
            Duration.Zero);

        if (!string.IsNullOrWhiteSpace(webKey))
        {
            if (status == IntraMessage.TOKEN_PASSED_VALIDATION)
            {
                TimeSpan cacheTtl = CalculateCacheTtl(session, jwtSettings.Value, currentMoment);

                if (cachedAuthority is null || !cachedAuthority.Matches(session))
                    await SafeSetActiveSession(activeUsers, accessTokenHash, session, cacheTtl, "active session cache hydration", fallbackSettings.CacheWriteTimeout, cancellationToken: cancellationToken);
                currentMoment = SystemClock.Instance.GetCurrentInstant();
                if (session.accessExpiration <= currentMoment || IsSessionHardExpired(session, currentMoment))
                {
                    context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
                    await _next(context);
                    return;
                }
                if (session.entitlements is null || !session.entitlements.IsCurrent(session.accountId, currentMoment))
                {
                    var fresh = await TryLoadAuthoritativeSessionFromDatabase(sessionRepo, accessTokenHash, fallbackSettings.DatabaseFallbackTimeout, cancellationToken);
                    if (fresh?.entitlements is null || fresh.accountId != session.accountId || fresh.protocolVersion != session.protocolVersion || fresh.securityStamp != session.securityStamp || fresh.accountSecurityStamp != session.accountSecurityStamp ||
                        fresh.familyId != session.familyId || fresh.generation != session.generation ||
                        !fresh.entitlements.IsCurrent(fresh.accountId, SystemClock.Instance.GetCurrentInstant()))
                    {
                        context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
                        await _next(context);
                        return;
                    }
                    session = fresh;
                }
                currentMoment = SystemClock.Instance.GetCurrentInstant();
                if (session.accessExpiration <= currentMoment || IsSessionHardExpired(session, currentMoment) ||
                    session.entitlements is null || !session.entitlements.IsCurrent(session.accountId, currentMoment))
                {
                    context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
                    await _next(context);
                    return;
                }
                SessionProtocol.WriteHeaders(context.Response, session);
                context.Items[AuthContextItems.HashedAccessToken] = accessTokenHash;
                context.Items[AuthContextItems.WebKey] = webKey;
                context.Items[AuthContextItems.ActiveSession] = session;
            }
            else
            {
                context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
            }
        }
        else
        {
            context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
        }

        await _next(context);
        return;
    }

    private sealed record CachedAuthority(Instant Access, Instant Hard, Instant? Cutoff,
        Guid SessionStamp, Guid AccountStamp, FeatureSet Features,
        treehammock.DataLayer.Entitlements.EntitlementProjection? Projection)
    {
        public static CachedAuthority Capture(ActiveSession s) => new(s.accessExpiration, s.sessionExpiration,
            s.cutOff, s.securityStamp, s.accountSecurityStamp, s.features, s.entitlements);
        public bool Matches(ActiveSession s)
        {
            var a = Projection; var b = s.entitlements;
            return Access == s.accessExpiration && Hard == s.sessionExpiration && Cutoff == s.cutOff &&
                SessionStamp == s.securityStamp && AccountStamp == s.accountSecurityStamp && Features == s.features &&
                a is not null && b is not null && a.AccountId == b.AccountId && a.Version == b.Version &&
                a.Features == b.Features && a.RightsEnabled == b.RightsEnabled && a.NextBoundary == b.NextBoundary &&
                a.EligibilityUntil == b.EligibilityUntil && a.Capabilities is not null && a.Grants is not null &&
                b.Capabilities is not null && b.Grants is not null &&
                a.Capabilities.SequenceEqual(b.Capabilities, StringComparer.Ordinal) && a.Grants.SequenceEqual(b.Grants);
        }
    }


    private async Task<bool> ValidateCachedSessionTrust(
        IActiveUserCacheService activeUsers,
        ISessionRepo sessionRepo,
        string accessTokenHash,
        ActiveSession session,
        SessionCacheFallbackSettings fallbackSettings, CancellationToken cancellationToken = default)
    {
        CachedSessionTrustResult? validation = await SafeValidateCachedSessionTrust(sessionRepo, accessTokenHash, session, fallbackSettings.DatabaseFallbackTimeout, cancellationToken: cancellationToken);
        if (validation?.Succeeded != true)
        {
            await SafeRevokeActiveSession(activeUsers, accessTokenHash, "stale active session cache revoke", fallbackSettings.CacheRevokeTimeout, cancellationToken: cancellationToken);
            return false;
        }

        if (validation.AccessExpiration is not null)
        {
            session.accessExpiration = validation.AccessExpiration.Value;
        }

        if (validation.SessionExpiration is not null)
        {
            session.sessionExpiration = validation.SessionExpiration.Value;
        }

        if (validation.FamilyId is Guid family && (family != session.familyId || validation.Generation != session.generation || validation.ProtocolVersion != session.protocolVersion))
            return false;
        if (validation.Entitlements is null) return false;
        if (!validation.Entitlements.IsCurrent(session.accountId, SystemClock.Instance.GetCurrentInstant()))
        {
            var fresh = await TryLoadAuthoritativeSessionFromDatabase(sessionRepo, accessTokenHash, fallbackSettings.DatabaseFallbackTimeout, cancellationToken);
            if (fresh?.entitlements is null || fresh.accountId != session.accountId || fresh.protocolVersion != session.protocolVersion || fresh.securityStamp != session.securityStamp || fresh.accountSecurityStamp != session.accountSecurityStamp ||
                fresh.familyId != session.familyId || fresh.generation != session.generation ||
                !fresh.entitlements.IsCurrent(fresh.accountId, SystemClock.Instance.GetCurrentInstant())) return false;
            validation = new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, fresh.accessExpiration, fresh.sessionExpiration,
                fresh.cutOff, fresh.securityStamp, fresh.accountSecurityStamp, FamilyId: fresh.familyId, Generation: fresh.generation,
                ProtocolVersion: fresh.protocolVersion, Entitlements: fresh.entitlements);
            session.accessExpiration = fresh.accessExpiration;
            session.sessionExpiration = fresh.sessionExpiration;
        }
        session.entitlements = validation.Entitlements;
        session.features = validation.Entitlements.Features;
        session.cutOff = validation.CutOff;

        if (validation.SecurityStamp is not null)
        {
            session.securityStamp = validation.SecurityStamp.Value;
        }

        if (validation.AccountSecurityStamp is not null)
        {
            session.accountSecurityStamp = validation.AccountSecurityStamp.Value;
        }

        return true;
    }

    private async Task<CachedSessionTrustResult?> SafeValidateCachedSessionTrust(
        ISessionRepo sessionRepo,
        string accessTokenHash,
        ActiveSession session,
        TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        try
        {
            CachedSessionTrustResult? result = await WithTimeout(deadlineToken => sessionRepo.ValidateCachedSessionTrust(accessTokenHash, session.accountId, session.securityStamp, session.accountSecurityStamp, cancellationToken: deadlineToken),
                timeout,
                timeoutValue: null,
                "active session cache trust validation",
                HashFingerprint(accessTokenHash), cancellationToken);
            if (result is null || result.Status == CachedSessionTrustStatus.Failed)
                throw DependencyUnavailableException.InvalidResponse("validate_cached_session_trust");
            if (result.Succeeded != true)
            {
                _logger.LogWarning(
                    "Active session cache trust validation failed with status {Status} and code {Code} for token hash {AccessTokenHashFingerprint} and account {AccountId}.",
                    result?.Status.ToString() ?? "NullResult",
                    result?.Code ?? "NullCode",
                    HashFingerprint(accessTokenHash),
                    session.accountId);
            }

            return result;
        }
        catch (OperationCanceledException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex) {
            _logger.LogWarning(
                ex,
                "Active session cache trust validation threw for token hash {AccessTokenHashFingerprint} and account {AccountId}.",
                HashFingerprint(accessTokenHash),
                session.accountId);
            throw DependencyUnavailableException.Database("validate_cached_session_trust", DependencyStage.Execute, ex);
        }
    }

    private async Task<ActiveSession?> SafeGetActiveSession(IActiveUserCacheService activeUsers, string accessTokenHash, SessionCacheFallbackSettings fallbackSettings, CancellationToken cancellationToken = default)
    {
        try
        {
            return await WithTimeout(deadlineToken => activeUsers.GetSession(accessTokenHash, cancellationToken: deadlineToken),
                fallbackSettings.CacheReadTimeout,
                timeoutValue: null,
                "active session cache read",
                HashFingerprint(accessTokenHash), cancellationToken);
        }
        catch (StaleActiveSessionCachePayloadException ex)
        {
            _logger.LogWarning(
                ex,
                "Active session cache payload was stale or malformed for token hash {AccessTokenHashFingerprint}; revoking cache entry and falling back to database session lookup.",
                HashFingerprint(accessTokenHash));

            await SafeRevokeActiveSession(activeUsers, accessTokenHash, "stale active session cache payload revoke", fallbackSettings.CacheRevokeTimeout, cancellationToken: cancellationToken);
            return null;
        }
        catch (OperationCanceledException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex) {
            _logger.LogWarning(
                ex,
                "Active session cache read failed for token hash {AccessTokenHashFingerprint}; falling back to database session lookup.",
                HashFingerprint(accessTokenHash));
            return null;
        }
    }

    private async Task<bool> SafeSetActiveSession(
        IActiveUserCacheService activeUsers,
        string accessTokenHash,
        ActiveSession session,
        TimeSpan cacheTtl,
        string operationName,
        TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        try
        {
            if (cacheTtl <= TimeSpan.Zero) return false;
            bool result = await WithTimeout(deadlineToken => activeUsers.SetSession(accessTokenHash, session, cacheTtl, cancellationToken: deadlineToken),
                timeout,
                timeoutValue: false,
                operationName,
                HashFingerprint(accessTokenHash), cancellationToken);
            if (!result)
            {
                _logger.LogWarning(
                    "Active session cache write returned false during {OperationName} for token hash {AccessTokenHashFingerprint}.",
                    operationName,
                    HashFingerprint(accessTokenHash));
            }

            return result;
        }
        catch (OperationCanceledException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex) {
            _logger.LogWarning(
                ex,
                "Active session cache write failed during {OperationName} for token hash {AccessTokenHashFingerprint}.",
                operationName,
                HashFingerprint(accessTokenHash));
            return false;
        }
    }

    private async Task<bool> SafeRevokeActiveSession(IActiveUserCacheService activeUsers, string accessTokenHash, string operationName, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        try
        {
            bool result = await WithTimeout(deadlineToken => activeUsers.RevokeSession(accessTokenHash, cancellationToken: deadlineToken),
                timeout,
                timeoutValue: false,
                operationName,
                HashFingerprint(accessTokenHash), cancellationToken);
            if (!result)
            {
                _logger.LogWarning(
                    "Active session cache revoke returned false during {OperationName} for token hash {AccessTokenHashFingerprint}.",
                    operationName,
                    HashFingerprint(accessTokenHash));
            }

            return result;
        }
        catch (OperationCanceledException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex) {
            _logger.LogWarning(
                ex,
                "Active session cache revoke failed during {OperationName} for token hash {AccessTokenHashFingerprint}.",
                operationName,
                HashFingerprint(accessTokenHash));
            return false;
        }
    }


    private async Task<ActiveSession?> TryLoadAuthoritativeSessionFromDatabase(
        ISessionRepo sessionRepo,
        string accessTokenHash,
        TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        try
        {
            Session? storedSession = await WithTimeout(deadlineToken => sessionRepo.GetSession(accessTokenHash, cancellationToken: deadlineToken),
                timeout,
                timeoutValue: null,
                "active session database fallback lookup",
                HashFingerprint(accessTokenHash), cancellationToken);

            if (storedSession is null) return null;
            if (storedSession.sessionLifespan is null || storedSession.refreshes is null)
                throw DependencyUnavailableException.InvalidResponse("get_session");

            return SessionProtocol.FromSession(storedSession);
        }
        catch (OperationCanceledException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex) {
            _logger.LogWarning(
                ex,
                "Active session database fallback lookup failed for token hash {AccessTokenHashFingerprint}.",
                HashFingerprint(accessTokenHash));
            throw DependencyUnavailableException.Database("get_session", DependencyStage.Execute, ex);
        }
    }

    private async Task<T> WithTimeout<T>(
        Func<CancellationToken, Task<T>> operation, TimeSpan timeout, T timeoutValue,
        string operationName, string accessTokenHashFingerprint, CancellationToken cancellationToken)
    {
        try { return await DependencyDeadline.RunAsync(operation, timeout, cancellationToken); }
        catch (TimeoutException ex)
        {
            _logger.LogWarning("Deadline expired during {OperationName} for token hash {Fingerprint}.", operationName, accessTokenHashFingerprint);
            if (operationName.Contains("database", StringComparison.Ordinal) || operationName.Contains("trust validation", StringComparison.Ordinal))
                throw DependencyUnavailableException.Database(operationName, DependencyStage.Execute, ex);
            return timeoutValue;
        }
    }

    private static string HashFingerprint(string accessTokenHash)
    {
        if (string.IsNullOrWhiteSpace(accessTokenHash))
        {
            return string.Empty;
        }

        return accessTokenHash.Length <= 12 ? accessTokenHash : accessTokenHash[..12];
    }

    private static bool IsSessionHardExpired(ActiveSession session, Instant currentMoment)
    {
        return session.EffectiveSessionExpiration <= currentMoment;
    }

    private async Task TryRevokeExpiredSession(IActiveUserCacheService activeUsers, ISessionRepo sessionRepo, string accessTokenHash, SessionCacheFallbackSettings fallbackSettings, CancellationToken cancellationToken = default)
    {
        await SafeRevokeActiveSession(activeUsers, accessTokenHash, "expired active session cache revoke", fallbackSettings.CacheRevokeTimeout, cancellationToken: cancellationToken);

        // Access expiry must not revoke the independent refresh lifetime.
        // Family invalidation is performed only by explicit logout/reset/revoke.
    }

    private static TimeSpan CalculateCacheTtl(ActiveSession session, JWTSettings settings, Instant currentMoment)
    {
        Period configuredCachePeriod = BuildConfiguredCachePeriod(settings);

        Instant configuredCacheExpiration = currentMoment.Plus(configuredCachePeriod.ToDuration());
        Instant effectiveExpiration = Earliest(session.accessExpiration, configuredCacheExpiration);
        effectiveExpiration = Earliest(effectiveExpiration, session.EffectiveSessionExpiration);
        if (session.entitlements?.NextBoundary is { } boundary) effectiveExpiration = Earliest(effectiveExpiration, boundary);

        Duration ttl = effectiveExpiration - currentMoment;
        if (ttl <= Duration.Zero)
        {
            return TimeSpan.Zero;
        }

        return ttl.ToTimeSpan();
    }

    private static Period BuildConfiguredCachePeriod(JWTSettings settings)
    {
        return new PeriodBuilder
        {
            Days = settings.RefreshTokenAliveDays,
            Hours = settings.RefreshTokenAliveHours,
            Minutes = settings.RefreshTokenAliveMinutes
        }.Build();
    }

    private static Instant Earliest(Instant left, Instant right)
    {
        return left <= right ? left : right;
    }
}
