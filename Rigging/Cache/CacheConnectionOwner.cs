using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using treehammock.Rigging.Config;
using treehammock.Rigging.Dependencies;
namespace treehammock.Rigging.Cache;

public enum CacheProfile { ActiveSessions, TwoFactorSessions, AbuseCounters }
public enum CacheClientLifecycle { NotStarted, Connecting, RetryWaiting, Connected, Disconnected, Stopping, Disposed }

// Local snapshots only: no endpoint, configured client name, credentials or exception text.
public sealed record CacheClientDiagnostics(CacheClientLifecycle Lifecycle, long InitializationAttempts,
    long InitializationFailures, int PendingInitializations, bool HasClient, bool Connected,
    bool OwnsClient, int RetryDelayMilliseconds, bool DisposalFailed);

// One multiplexer per role, even when roles share an endpoint. Every production consumer borrows it.
public sealed class CacheConnectionOwner : IHostedService, IAsyncDisposable, IDisposable
{
    private readonly Dictionary<CacheProfile, CacheConnectionSlot> _slots;
    private readonly object _gate = new();
    private Task? _disposal;
    public CacheConnectionOwner(IOptions<UserCacheSettings> active, IOptions<TwoFactorSessionCacheSettings> twoFactor,
        IOptions<AbuseCounterCacheSettings> abuse, Func<ConfigurationOptions, Task<IConnectionMultiplexer>>? connect = null)
    {
        string instance = Guid.NewGuid().ToString("N");
        CacheConnectionSlot Slot(CacheProfile profile, UserCacheSettings settings) => new(settings, configuration =>
        {
            // Safe generation suffix supports CLIENT LIST qualification across overlapping host lifetimes.
            configuration.ClientName = $"{configuration.ClientName}:cor23n:{profile}:{instance}";
            return connect is null ? ConnectAsync(configuration) : connect(configuration);
        });
        _slots = new()
        {
            [CacheProfile.ActiveSessions] = Slot(CacheProfile.ActiveSessions, active.Value),
            [CacheProfile.TwoFactorSessions] = Slot(CacheProfile.TwoFactorSessions, twoFactor.Value),
            [CacheProfile.AbuseCounters] = Slot(CacheProfile.AbuseCounters, abuse.Value)
        };
    }
    private static async Task<IConnectionMultiplexer> ConnectAsync(ConfigurationOptions configuration) =>
        await ConnectionMultiplexer.ConnectAsync(configuration).ConfigureAwait(false);
    public CacheConnectionSlot Get(CacheProfile profile) => _slots[profile];
    public IReadOnlyDictionary<CacheProfile, CacheClientDiagnostics> GetDiagnostics() =>
        _slots.ToDictionary(pair => pair.Key, pair => pair.Value.GetDiagnostics());
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (_disposal is not null) throw new ObjectDisposedException(nameof(CacheConnectionOwner));
            foreach (var slot in _slots.Values) slot.Start();
        }
        return Task.CompletedTask;
    }
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        // Canceling the host's wait never abandons ownership of a late connection or its disposal.
        Task drain = DisposeAsync().AsTask();
        await drain.WaitAsync(cancellationToken).ConfigureAwait(false);
    }
    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            // Schedule outside this lock; neither connector nor multiplexer disposal runs under it.
            if (_disposal is null)
            {
                _disposal = Task.Run(async () =>
                    await Task.WhenAll(_slots.Values.Select(slot => slot.DisposeAsync().AsTask())).ConfigureAwait(false));
                _ = _disposal.ContinueWith(task => { _ = task.Exception; }, CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
            return new ValueTask(_disposal);
        }
    }
}

public sealed class CacheConnectionSlot : IAsyncDisposable, IDisposable
{
    private readonly UserCacheSettings _settings;
    private readonly Func<ConfigurationOptions, Task<IConnectionMultiplexer>> _connect;
    private readonly CancellationTokenSource _stop = new();
    private readonly object _gate = new();
    private Task? _worker;
    private Task? _disposal;
    private IConnectionMultiplexer? _connection;
    private bool _disposed;
    private readonly bool _borrowed;
    private CacheClientLifecycle _lifecycle;
    private long _attempts, _failures;
    private bool _pendingInitialization;
    private int _retryDelay;
    private bool _disposalFailed;
    public CacheConnectionSlot(UserCacheSettings settings, Func<ConfigurationOptions, Task<IConnectionMultiplexer>>? connect = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        // Options can be mutable. Neither a retry nor a request may retarget this logical client.
        _settings = Snapshot(settings);
        _connect = connect ?? (async configuration => await ConnectionMultiplexer.ConnectAsync(configuration).ConfigureAwait(false));
    }
    public CacheConnectionSlot(UserCacheSettings settings, IConnectionMultiplexer borrowed) : this(settings)
    {
        ArgumentNullException.ThrowIfNull(borrowed);
        _connection = borrowed; _borrowed = true; _lifecycle = CacheClientLifecycle.Connected;
    }
    private static UserCacheSettings Snapshot(UserCacheSettings settings) => new()
    {
        servers = settings.servers, port = settings.port, database = settings.database,
        clientName = settings.clientName, password = settings.password, allowAdmin = settings.allowAdmin,
        abortOnConnectFail = settings.abortOnConnectFail,
        reconnectRetryPolicy = Math.Clamp(settings.reconnectRetryPolicy, 10u, 60000u),
        connectTimeoutMilliseconds = Math.Clamp(settings.connectTimeoutMilliseconds, 10, 10000),
        asyncTimeoutMilliseconds = Math.Clamp(settings.asyncTimeoutMilliseconds, 10, 10000),
        syncTimeoutMilliseconds = Math.Clamp(settings.syncTimeoutMilliseconds, 10, 10000),
        connectRetry = settings.connectRetry
    };
    public CacheClientDiagnostics GetDiagnostics()
    {
        lock (_gate)
        {
            bool connected = !_disposed && _connection?.IsConnected == true;
            var state = !_disposed && _connection is not null
                ? connected ? CacheClientLifecycle.Connected : CacheClientLifecycle.Disconnected : _lifecycle;
            return new(state, _attempts, _failures, _pendingInitialization ? 1 : 0,
                _connection is not null, connected, !_borrowed, _retryDelay, _disposalFailed);
        }
    }
    public void Start()
    {
        lock (_gate)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(CacheConnectionSlot));
            if (!_borrowed && _worker is null) _worker = Task.Run(ConnectLoopAsync);
        }
    }
    public bool Ready
    {
        get { lock (_gate) return !_disposed && _connection?.IsConnected == true; }
    }
    public IConnectionMultiplexer Connection
    {
        get
        {
            lock (_gate)
            {
                if (_disposed) throw new ObjectDisposedException(nameof(CacheConnectionSlot));
                return _connection ?? throw DependencyUnavailableException.Cache("connection_not_ready");
            }
        }
    }
    public IDatabase Database
    {
        get
        {
            IConnectionMultiplexer connection = Connection;
            if (!_borrowed && !connection.IsConnected) throw DependencyUnavailableException.Cache("connection_not_ready");
            return connection.GetDatabase(_settings.database);
        }
    }
    internal int RetryDelayForFailure(long failures) => (int)Math.Min(60000L,
        (long)_settings.reconnectRetryPolicy * (1L << (int)Math.Clamp(failures - 1, 0, 16)));
    private async Task ConnectLoopAsync()
    {
        while (true)
        {
            lock (_gate)
            {
                if (_disposed) return;
                _pendingInitialization = true; _lifecycle = CacheClientLifecycle.Connecting;
                _retryDelay = 0; _attempts++;
            }
            IConnectionMultiplexer candidate;
            try
            {
                var configuration = ActiveUserCacheService.BuildConfiguration(_settings);
                configuration.AbortOnConnectFail = false;
                configuration.ConnectRetry = 0; // No stacked provider retries; the owner schedules initial retry.
                candidate = await _connect(configuration).ConfigureAwait(false)
                    ?? throw new InvalidOperationException("Cache connector returned no client.");
            }
            catch (Exception)
            {
                int delay;
                lock (_gate)
                {
                    _pendingInitialization = false; _failures++;
                    if (_disposed) return;
                    delay = _retryDelay = RetryDelayForFailure(_failures);
                    _lifecycle = CacheClientLifecycle.RetryWaiting;
                }
                try { await Task.Delay(TimeSpan.FromMilliseconds(delay), _stop.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (_stop.IsCancellationRequested) { return; }
                continue;
            }
            bool disposeCandidate;
            lock (_gate)
            {
                _pendingInitialization = false;
                disposeCandidate = _disposed;
                if (!disposeCandidate) { _connection = candidate; _lifecycle = CacheClientLifecycle.Connected; }
            }
            // A late result stays owned by this worker; never publish it or start a replacement.
            if (disposeCandidate) candidate.Dispose();
            return; // Subsequent reconnects belong to this same multiplexer, not another initializer.
        }
    }
    public async Task<T> ExecuteAsync<T>(Func<IDatabase, Task<T>> command, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try { return await DependencyDeadline.RunAsync(_ => command(Database), TimeSpan.FromMilliseconds(_settings.asyncTimeoutMilliseconds), cancellationToken); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is RedisException or TimeoutException or ObjectDisposedException or InvalidOperationException)
        { throw DependencyUnavailableException.Cache("cache_command", ex); }
    }
    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    public ValueTask DisposeAsync()
    {
        Task? worker;
        IConnectionMultiplexer? connection;
        TaskCompletionSource completion;
        lock (_gate)
        {
            if (_disposal is not null) return new ValueTask(_disposal);
            _disposed = true; _lifecycle = CacheClientLifecycle.Stopping; _retryDelay = 0;
            worker = _worker; connection = _connection; _connection = null;
            completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _disposal = completion.Task;
            // Observe faults even if a host cancels its shutdown wait; awaiting disposal still surfaces them.
            _ = _disposal.ContinueWith(task => { _ = task.Exception; }, CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
        _ = DisposeCoreAsync(worker, connection, completion);
        return new ValueTask(completion.Task);
    }
    private async Task DisposeCoreAsync(Task? worker, IConnectionMultiplexer? connection, TaskCompletionSource completion)
    {
        try
        {
            _stop.Cancel(); // External cancellation callbacks and disposal always run outside the gate.
            try { if (worker is not null) await worker.ConfigureAwait(false); }
            finally { if (!_borrowed) connection?.Dispose(); }
        }
        catch (Exception ex)
        {
            lock (_gate) _disposalFailed = true;
            Finish();
            completion.TrySetException(ex);
            return;
        }
        Finish();
        completion.TrySetResult();
        void Finish()
        {
            _stop.Dispose();
            lock (_gate) { _pendingInitialization = false; _lifecycle = CacheClientLifecycle.Disposed; }
        }
    }
}
