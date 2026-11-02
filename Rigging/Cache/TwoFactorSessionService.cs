using Microsoft.Extensions.Options;

using Newtonsoft.Json;
using StackExchange.Redis;

using treehammock.DataLayer.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;

namespace treehammock.Rigging.Cache;

public interface ITwoFactorSessionService
{
    public Task<TwoFactorSession?> GetSession(string hashedAccessToken, CancellationToken cancellationToken = default);
    public Task<bool?> SetSession(string hashedAccessToken, TwoFactorSession session, TimeSpan expire, CommandFlags flags = CommandFlags.PreferMaster, CancellationToken cancellationToken = default);
    public Task<bool> RevokeSession(string hashedAccessToken, CancellationToken cancellationToken = default);
    public Task<bool> AdjustExpiration(string newHashedAccessToken, TimeSpan expire, CancellationToken cancellationToken = default);
}

// Should use the pending two-factor Redis database, usually index one / 1.
public class TwoFactorSessionService : IAsyncDisposable, IDisposable, ITwoFactorSessionService
{
    protected TwoFactorSessionCacheSettings _config;

    private readonly CacheConnectionSlot _slot;
    private readonly bool _ownsSlot;
    public TwoFactorSessionService(IOptions<TwoFactorSessionCacheSettings> config) : this(config, (IConnectionMultiplexer?)null) { }
    public TwoFactorSessionService(IOptions<TwoFactorSessionCacheSettings> config, IConnectionMultiplexer? connection)
    {
        _config = config.Value;
        _slot = connection is null ? new CacheConnectionSlot(_config) : new CacheConnectionSlot(_config, connection);
        _ownsSlot = true;
        _slot.Start();
    }
    public TwoFactorSessionService(IOptions<TwoFactorSessionCacheSettings> config, CacheConnectionSlot slot)
    { _config = config.Value; _slot = slot; }
    public ValueTask DisposeAsync() => _ownsSlot ? _slot.DisposeAsync() : ValueTask.CompletedTask;
    public void Dispose() { if (_ownsSlot) _slot.Dispose(); }

    public static ConfigurationOptions BuildConfiguration(TwoFactorSessionCacheSettings config)
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

    public async Task<TwoFactorSession?> GetSession(string hashedAccessToken, CancellationToken cancellationToken = default)
    {
        var redisResult = await _slot.ExecuteAsync(db => db.StringGetAsync(hashedAccessToken), cancellationToken);
        if (redisResult.IsNullOrEmpty)
        {
            return null;
        }

        try
        {
            return CacheJsonSettings.Deserialize<TwoFactorSession>(redisResult.ToString());
        }
        catch (JsonException exception)
        {
            throw new StalePendingTwoFactorCachePayloadException("Pending two-factor cache payload is stale or malformed.", exception);
        }
        catch (ArgumentException exception)
        {
            throw new StalePendingTwoFactorCachePayloadException("Pending two-factor cache payload is missing required security fields.", exception);
        }
    }

    public static string ProjectionScript { get; } = ReadProjectionScript();
    private static string ReadProjectionScript()
    {
        using var stream = typeof(TwoFactorSessionService).Assembly.GetManifestResourceStream("treehammock.PendingProofProjection.lua")
            ?? throw new InvalidOperationException("Missing pending proof projection script.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    public async Task<bool?> SetSession(string hashedAccessToken, TwoFactorSession session, TimeSpan expire, CommandFlags flag = CommandFlags.PreferMaster, CancellationToken cancellationToken = default)
    {
        _ = AccountSecurityStampGuard.Require(session.accountSecurityStamp);
        if (session.progressVersion < 1 || session.progressVersion > treehammock.Rigging.Authorization.SessionProtocol.MaximumGeneration)
            throw new ArgumentException("Invalid pending proof version.");
        var result = await _slot.ExecuteAsync(db => db.ScriptEvaluateAsync(ProjectionScript,
            new RedisKey[] { hashedAccessToken }, new RedisValue[] { CacheJsonSettings.Serialize(session),
                Math.Max(1L, (long)Math.Ceiling(expire.TotalMilliseconds)) }, flag), cancellationToken);
        return (long)result == 1;
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
