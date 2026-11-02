using treehammock.Rigging.Dependencies;
using treehammock.DataLayer.Operations;
using treehammock.Repos;
using treehammock.Rigging.Database;
using treehammock.Rigging.Operations;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Options;

using StackExchange.Redis;

using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;

namespace treehammock.Rigging.Replay;

public static class AuthenticatedMutationIdempotencyConstants
{
    public const string HeaderName = "Idempotency-Key";
    public const string MissingRequiredKeyCode = "IDEMPOTENCY_KEY_REQUIRED";
    public const string InvalidKeyCode = "IDEMPOTENCY_KEY_INVALID";
    public const string ReplayInProgressCode = "IDEMPOTENCY_REPLAY_IN_PROGRESS";
    public const string ContentConflictCode = "IDEMPOTENCY_CONTENT_CONFLICT";
    public const string RecoveryRequiredCode = "IDEMPOTENCY_RECOVERY_REQUIRED";
    public const string AuthorityChangedCode = "IDEMPOTENCY_AUTHORITY_CHANGED";
    public const string ExpiredCode = "IDEMPOTENCY_EXPIRED";
    public const string StoreUnavailableCode = "IDEMPOTENCY_STORE_UNAVAILABLE";
}

public enum AuthenticatedMutationIdempotencyStatus
{
    NotApplied = 0,
    Started = 1,
    ReplayCompleted = 2,
    ReplayInProgress = 3,
    InvalidKey = 4,
    StoreUnavailable = 5,
    MissingRequiredKey = 6,
    ContentConflict = 7,
    RecoveryRequired = 8,
    AuthorityChanged = 9,
    Expired = 10
}

public sealed record AuthenticatedMutationIdempotencyRequest(
    Guid AccountId,
    string Method,
    string Route,
    string? IdempotencyKey,
    bool RequireKey = false,
    Guid? AccountSecurityStamp = null,
    byte[]? CanonicalRequest = null);

public sealed record AuthenticatedMutationIdempotencyReservation(string CacheKey, string ReservationToken,
    string Generation = "", string RequestHmac = "", Guid OperationId = default, byte[]? IdentityDigest = null);

public sealed record AuthenticatedMutationIdempotencyStoredResult(int StatusCode, string Code, string? SafeResponse = null);

public sealed record AuthenticatedMutationIdempotencyBeginResult(
    AuthenticatedMutationIdempotencyStatus Status,
    AuthenticatedMutationIdempotencyReservation? Reservation = null,
    AuthenticatedMutationIdempotencyStoredResult? StoredResult = null,
    string? ReasonCode = null,
    Guid? OperationId = null)
{
    public bool Started => Status == AuthenticatedMutationIdempotencyStatus.Started;
    public bool NotApplied => Status == AuthenticatedMutationIdempotencyStatus.NotApplied;

    public static AuthenticatedMutationIdempotencyBeginResult NotAppliedResult()
    {
        return new AuthenticatedMutationIdempotencyBeginResult(AuthenticatedMutationIdempotencyStatus.NotApplied);
    }

    public static AuthenticatedMutationIdempotencyBeginResult StartedResult(AuthenticatedMutationIdempotencyReservation reservation)
    {
        return new AuthenticatedMutationIdempotencyBeginResult(AuthenticatedMutationIdempotencyStatus.Started, reservation);
    }

    public static AuthenticatedMutationIdempotencyBeginResult ReplayCompletedResult(AuthenticatedMutationIdempotencyStoredResult result)
    {
        return new AuthenticatedMutationIdempotencyBeginResult(AuthenticatedMutationIdempotencyStatus.ReplayCompleted, StoredResult: result);
    }

    public static AuthenticatedMutationIdempotencyBeginResult ReplayInProgressResult()
    {
        return new AuthenticatedMutationIdempotencyBeginResult(
            AuthenticatedMutationIdempotencyStatus.ReplayInProgress,
            ReasonCode: AuthenticatedMutationIdempotencyConstants.ReplayInProgressCode);
    }

    public static AuthenticatedMutationIdempotencyBeginResult MissingRequiredKeyResult()
    {
        return new AuthenticatedMutationIdempotencyBeginResult(
            AuthenticatedMutationIdempotencyStatus.MissingRequiredKey,
            ReasonCode: AuthenticatedMutationIdempotencyConstants.MissingRequiredKeyCode);
    }

    public static AuthenticatedMutationIdempotencyBeginResult InvalidKeyResult()
    {
        return new AuthenticatedMutationIdempotencyBeginResult(
            AuthenticatedMutationIdempotencyStatus.InvalidKey,
            ReasonCode: AuthenticatedMutationIdempotencyConstants.InvalidKeyCode);
    }

    public static AuthenticatedMutationIdempotencyBeginResult StoreUnavailableResult()
    {
        return new AuthenticatedMutationIdempotencyBeginResult(
            AuthenticatedMutationIdempotencyStatus.StoreUnavailable,
            ReasonCode: AuthenticatedMutationIdempotencyConstants.StoreUnavailableCode);
    }
}

public interface IAuthenticatedMutationIdempotencyService
{
    Task<AuthenticatedMutationIdempotencyBeginResult> BeginAsync(
        AuthenticatedMutationIdempotencyRequest request,
        CancellationToken cancellationToken = default);

    Task CompleteStoredAsync(AuthenticatedMutationIdempotencyReservation? reservation,
        AuthenticatedMutationIdempotencyStoredResult result, CancellationToken cancellationToken = default)
        => CompleteAsync(reservation, result.StatusCode, result.Code, cancellationToken);

    Task<bool> RenewAsync(AuthenticatedMutationIdempotencyReservation reservation, CancellationToken cancellationToken = default)
        => Task.FromResult(false);

    Task CompleteAsync(
        AuthenticatedMutationIdempotencyReservation? reservation,
        int statusCode,
        string code,
        CancellationToken cancellationToken = default);
}

public sealed class NoOpAuthenticatedMutationIdempotencyService : IAuthenticatedMutationIdempotencyService
{
    public static NoOpAuthenticatedMutationIdempotencyService Instance { get; } = new();

    private NoOpAuthenticatedMutationIdempotencyService()
    {
    }

    public Task<AuthenticatedMutationIdempotencyBeginResult> BeginAsync(
        AuthenticatedMutationIdempotencyRequest request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(AuthenticatedMutationIdempotencyBeginResult.NotAppliedResult());
    }

    public Task CompleteAsync(
        AuthenticatedMutationIdempotencyReservation? reservation,
        int statusCode,
        string code,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }
}

public sealed class DragonflyAuthenticatedMutationIdempotencyService : IAsyncDisposable, IDisposable, IAuthenticatedMutationIdempotencyService
{
    private readonly AuthenticatedMutationIdempotencySettings _settings;
    private readonly CacheConnectionSlot _slot;
    private readonly bool _ownsSlot;
    private readonly AuthenticatedMutationReplayRepo? _receipts;
    public DragonflyAuthenticatedMutationIdempotencyService(IOptions<AbuseCounterCacheSettings> cacheSettings,
        IOptions<AbuseControlSettings> abuseSettings)
        : this(cacheSettings, abuseSettings, (IConnectionMultiplexer?)null) { }
    public DragonflyAuthenticatedMutationIdempotencyService(IOptions<AbuseCounterCacheSettings> cacheSettings,
        IOptions<AbuseControlSettings> abuseSettings, IConnectionMultiplexer? connection, StorageContext? storage = null)
    {
        _settings = abuseSettings.Value.AuthenticatedMutationIdempotency;
        _slot = connection is null ? new CacheConnectionSlot(cacheSettings.Value) : new CacheConnectionSlot(cacheSettings.Value, connection);
        _ownsSlot = true; _slot.Start();
        if (storage is not null) _receipts = new(storage, _settings);
    }
    public DragonflyAuthenticatedMutationIdempotencyService(IOptions<AbuseCounterCacheSettings> cacheSettings,
        IOptions<AbuseControlSettings> abuseSettings, CacheConnectionSlot slot, StorageContext? storage = null)
    {
        _settings = abuseSettings.Value.AuthenticatedMutationIdempotency; _slot = slot;
        if (storage is not null) _receipts = new(storage, _settings);
    }
    public IConnectionMultiplexer Connection => _slot.Connection;
    public IDatabase Database => _slot.Database;
    public ValueTask DisposeAsync() => _ownsSlot ? _slot.DisposeAsync() : ValueTask.CompletedTask;
    public void Dispose() { if (_ownsSlot) _slot.Dispose(); }
    public async Task<AuthenticatedMutationIdempotencyBeginResult> BeginAsync(
        AuthenticatedMutationIdempotencyRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested(); ArgumentNullException.ThrowIfNull(request);
        if (request.IdempotencyKey is null) return request.RequireKey
            ? AuthenticatedMutationIdempotencyBeginResult.MissingRequiredKeyResult()
            : AuthenticatedMutationIdempotencyBeginResult.NotAppliedResult();
        string? key = NormalizeClientKey(request.IdempotencyKey, _settings.MinKeyLength, _settings.MaxKeyLength);
        if (key is null) return AuthenticatedMutationIdempotencyBeginResult.InvalidKeyResult();
        // Cache availability/leases cannot authorize a write without durable request ownership.
        if (_receipts is null || request.AccountSecurityStamp is null || request.AccountSecurityStamp == Guid.Empty
            || request.CanonicalRequest is null || SecurityOperationRequestContext.Current is null)
            return AuthenticatedMutationIdempotencyBeginResult.StoreUnavailableResult();
        try
        {
            var durable = await _receipts.BeginAsync(request, key, cancellationToken);
            if (!durable.Started || durable.Reservation is null || !_settings.Enabled) return durable;
            var owner = durable.Reservation;
            long state = (long)await WithTimeout(Database.ScriptEvaluateAsync(AuthenticatedMutationReplayScripts.Reserve,
                [owner.CacheKey], Arguments(owner, _settings.InProgressTtlSeconds), CommandFlags.None), cancellationToken);
            return state == 1 ? durable : new(
                state == -1 ? AuthenticatedMutationIdempotencyStatus.ContentConflict : AuthenticatedMutationIdempotencyStatus.RecoveryRequired,
                ReasonCode: state == -1 ? AuthenticatedMutationIdempotencyConstants.ContentConflictCode : AuthenticatedMutationIdempotencyConstants.RecoveryRequiredCode,
                OperationId: owner.OperationId);
        }
        catch (SecurityOperationException) { throw; }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (Unavailable(ex)) { return AuthenticatedMutationIdempotencyBeginResult.StoreUnavailableResult(); }
    }
    public Task CompleteAsync(AuthenticatedMutationIdempotencyReservation? reservation, int statusCode,
        string code, CancellationToken cancellationToken = default)
        => CompleteStoredAsync(reservation, new(statusCode, code), cancellationToken);
    public async Task CompleteStoredAsync(AuthenticatedMutationIdempotencyReservation? reservation,
        AuthenticatedMutationIdempotencyStoredResult result, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (reservation is null || _receipts is null) return;
        // Save original safe envelope and terminally fence the operation FIRST. A lost cache
        // completion cannot erase the durable answer or hand a new owner mutation authority.
        bool saved;
        try { saved = await _receipts.CompleteAsync(reservation, result, cancellationToken); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (Unavailable(ex))
        {
            throw new SecurityOperationException("SECURITY_OPERATION_UNKNOWN", 503,
                new(reservation.OperationId, SecurityOperationState.Unknown, null, []));
        }
        if (!saved || !_settings.Enabled) return;
        try
        {
            var arguments = Arguments(reservation, _settings.CompletedTtlSeconds).Concat(new RedisValue[]
                { result.SafeResponse ?? "" }).ToArray();
            _ = await WithTimeout(Database.ScriptEvaluateAsync(AuthenticatedMutationReplayScripts.Complete,
                [reservation.CacheKey], arguments, CommandFlags.None), cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (Unavailable(ex)) { /* Durable SQL outcome remains authoritative. */ }
    }
    public async Task<bool> RenewAsync(AuthenticatedMutationIdempotencyReservation reservation, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_settings.Enabled || reservation.OperationId == Guid.Empty) return false;
        try
        {
            return (long)await WithTimeout(Database.ScriptEvaluateAsync(AuthenticatedMutationReplayScripts.Renew,
                [reservation.CacheKey], Arguments(reservation, _settings.InProgressTtlSeconds), CommandFlags.None), cancellationToken) == 1;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (Unavailable(ex)) { return false; }
    }
    private static RedisValue[] Arguments(AuthenticatedMutationIdempotencyReservation owner, int seconds)
        => [owner.ReservationToken, owner.Generation, owner.RequestHmac, owner.OperationId.ToString("N"), (long)Math.Clamp(seconds, 1, 900) * 1000];
    private static bool Unavailable(Exception ex) => ex is TimeoutException or OperationCanceledException or RedisException or ObjectDisposedException
        or InvalidOperationException or DependencyUnavailableException or Npgsql.NpgsqlException;
    public static string BuildCacheKey(Guid accountId, string method, string route, string normalizedClientKey)
        => "idempotency:authmutation:v2:{" + Convert.ToHexString(AuthenticatedMutationCanonicalRequest.Identity(accountId, method, route, normalizedClientKey)).ToLowerInvariant() + "}";
    public static string? NormalizeClientKey(string? value, int minLength, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string normalized = value.Trim();
        if (normalized.Length < minLength || normalized.Length > maxLength)
        {
            return null;
        }

        foreach (char c in normalized)
        {
            bool safe = c is >= 'a' and <= 'z'
                || c is >= 'A' and <= 'Z'
                || c is >= '0' and <= '9'
                || c == '_'
                || c == '-'
                || c == '.'
                || c == ':';

            if (!safe)
            {
                return null;
            }
        }

        return normalized;
    }


    private Task<T> WithTimeout<T>(Task<T> operation, CancellationToken cancellationToken)
        => DependencyDeadline.RunAsync(_ => operation, TimeSpan.FromMilliseconds(Math.Clamp(_settings.TimeoutMilliseconds, 1, 60)), cancellationToken);
}
