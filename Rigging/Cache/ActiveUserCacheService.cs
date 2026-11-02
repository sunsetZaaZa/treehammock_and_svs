using Microsoft.Extensions.Options;

using Newtonsoft.Json;
using StackExchange.Redis;

using treehammock.DataLayer.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;

namespace treehammock.Rigging.Cache;

public interface IActiveUserCacheService
{
    public Task<ActiveSession?> GetSession(string hashedAccessToken, CancellationToken cancellationToken = default);
    public Task<bool> SetSession(string newHashedAccessToken, ActiveSession session, TimeSpan expire, CommandFlags flags = CommandFlags.PreferMaster, CancellationToken cancellationToken = default);
    public Task<bool> WarmSession(string hashedAccessToken, ActiveSession session, TimeSpan expire, CancellationToken cancellationToken = default);
    public Task<bool> RevokeSession(string hashedAccessToken, CancellationToken cancellationToken = default);
    public Task<bool> AdjustExpiration(string newHashedAccessToken, TimeSpan expire, CancellationToken cancellationToken = default);
}

// Should use the active-session Redis database, usually index zero / 0.
public class ActiveUserCacheService : IAsyncDisposable, IDisposable, IActiveUserCacheService
{
    protected UserCacheSettings _config;

    private readonly CacheConnectionSlot _slot;
    private readonly bool _ownsSlot;
    public ActiveUserCacheService(IOptions<UserCacheSettings> config) : this(config, (IConnectionMultiplexer?)null) { }
    public ActiveUserCacheService(IOptions<UserCacheSettings> config, IConnectionMultiplexer? connection)
    {
        _config = config.Value;
        _slot = connection is null ? new CacheConnectionSlot(_config) : new CacheConnectionSlot(_config, connection);
        _ownsSlot = true;
        _slot.Start();
    }
    public ActiveUserCacheService(IOptions<UserCacheSettings> config, CacheConnectionSlot slot)
    { _config = config.Value; _slot = slot; }
    public ValueTask DisposeAsync() => _ownsSlot ? _slot.DisposeAsync() : ValueTask.CompletedTask;
    public void Dispose() { if (_ownsSlot) _slot.Dispose(); }

    public static ConfigurationOptions BuildConfiguration(UserCacheSettings config)
    {
        return new ConfigurationOptions()
        {
            EndPoints = { { config.servers, config.port }, },
            AllowAdmin = config.allowAdmin,
            Password = config.password,
            ClientName = config.clientName,
            ReconnectRetryPolicy = new LinearRetry((int)config.reconnectRetryPolicy),
            AbortOnConnectFail = config.abortOnConnectFail,
            ConnectTimeout = config.connectTimeoutMilliseconds,
            AsyncTimeout = config.asyncTimeoutMilliseconds,
            SyncTimeout = config.syncTimeoutMilliseconds,
            ConnectRetry = config.connectRetry,
            DefaultDatabase = config.database
        };
    }

    public IConnectionMultiplexer _connection => _slot.Connection;

    public IDatabase _database => _slot.Database;

    public async Task<ActiveSession?> GetSession(string hashedAccessToken, CancellationToken cancellationToken = default)
    {
        var redisResult = await _slot.ExecuteAsync(db => db.StringGetAsync(hashedAccessToken), cancellationToken);
        if (redisResult.IsNullOrEmpty)
        {
            return null;
        }

        try
        {
            return CacheJsonSettings.Deserialize<ActiveSession>(redisResult.ToString());
        }
        catch (JsonException exception)
        {
            throw new StaleActiveSessionCachePayloadException("Active-session cache payload is stale or malformed.", exception);
        }
        catch (ArgumentException exception)
        {
            throw new StaleActiveSessionCachePayloadException("Active-session cache payload is missing required security fields.", exception);
        }
    }

    public async Task<bool> SetSession(string hashedAccessToken, ActiveSession session, TimeSpan expire, CommandFlags flag = CommandFlags.PreferMaster, CancellationToken cancellationToken = default)
    {
        _ = AccountSecurityStampGuard.Require(session.accountSecurityStamp);
        var result = await _slot.ExecuteAsync(db => db.StringSetAsync(hashedAccessToken, CacheJsonSettings.Serialize(session), expire, When.Always, flag), cancellationToken);
        return result;
    }

    // Atomic SET NX: warming cannot overwrite an existing login/refresh/request projection.
    public async Task<bool> WarmSession(string hashedAccessToken, ActiveSession session, TimeSpan expire, CancellationToken cancellationToken = default)
    {
        _ = AccountSecurityStampGuard.Require(session.accountSecurityStamp);
        if (expire <= TimeSpan.Zero) return false;
        return await _slot.ExecuteAsync(db => db.StringSetAsync(hashedAccessToken,
            CacheJsonSettings.Serialize(session), expire, When.NotExists, CommandFlags.PreferMaster), cancellationToken);
    }

    public async Task<bool> RevokeSession(string hashedAccessToken, CancellationToken cancellationToken = default)
    {
        bool deleted = await _slot.ExecuteAsync(db => db.KeyDeleteAsync(hashedAccessToken), cancellationToken);
        if (deleted)
        {
            return true;
        }

        bool stillExists = await _slot.ExecuteAsync(db => db.KeyExistsAsync(hashedAccessToken), cancellationToken);
        return !stillExists;
    }

    public async Task<bool> AdjustExpiration(string hashedAccessToken, TimeSpan expire, CancellationToken cancellationToken = default)
    {
        var result = await _slot.ExecuteAsync(db => db.KeyExpireAsync(hashedAccessToken, expire), cancellationToken);
        return result;
    }
}
