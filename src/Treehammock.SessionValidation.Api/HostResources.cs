using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NodaTime;
using StackExchange.Redis;
using Treehammock.SessionValidation.Storage;
namespace Treehammock.SessionValidation.Api;

internal interface IHostResources : IAsyncDisposable
{
    bool DatabaseReady { get; }
    DatabaseIdentityAuditStatus LastAudit { get; }
    SessionCacheAdmission Admission { get; }
    SessionEvidenceCoordinator Coordinator { get; }
    Task AuditAsync(CancellationToken token);
    Task DrainAuditAsync(CancellationToken token) => Task.CompletedTask;
    Task StopRefillAsync() => Task.CompletedTask;
}
internal sealed class HostResources : IHostResources
{
    private readonly ValidatorDatabaseIdentity _identity;
    private readonly ServiceConcurrencyLimiter _sql;
    private readonly OwnedCacheStore _cache;
    public SessionCacheAdmission Admission { get; } = new();
    public bool DatabaseReady => _identity.DatabaseFallbackReady;
    public DatabaseIdentityAuditStatus LastAudit { get; private set; }
    public SessionEvidenceCoordinator Coordinator { get; }
    internal HostResources(HostSettings settings)
    {
        _sql=new(settings.Capacity.ForegroundSqlOperations,"foreground-sql");
        _identity = YsqlAuthorityDataSource.CreateTreehammockValidator(settings.DatabaseConnectionString, settings.Roles);
        try
        {
            _cache = new OwnedCacheStore(settings.Cache, Admission);
            Coordinator = new(new(_cache, Admission, TimeSpan.FromMilliseconds(100), TimeSpan.FromSeconds(30)),
                new YsqlSessionAuthority(_identity, TimeSpan.FromSeconds(1),ownOperation:()=>_sql.TryEnter()??throw new InvalidOperationException("Foreground SQL capacity unavailable.")), settings.Issuer,
                TimeSpan.FromMilliseconds(settings.RequestTimeoutMilliseconds));
        }
        catch { _cache?.DisposeAsync().AsTask().GetAwaiter().GetResult(); _identity.DisposeAsync().AsTask().GetAwaiter().GetResult(); throw; }
    }
    public Task DrainAuditAsync(CancellationToken token) => _identity.DrainAuditAsync(token);
    public async Task AuditAsync(CancellationToken token) => LastAudit = (await _identity.RefreshIdentityAsync(token)).Status;
    public Task StopRefillAsync()=>_sql.DrainAsync(CancellationToken.None);
    public async ValueTask DisposeAsync() { await _sql.DrainAsync(CancellationToken.None);Admission.Quarantine(); await _cache.DisposeAsync(); await _identity.DisposeAsync(); }
}

// No cache connection is opened while the SVS-07 reader is unadmitted. The host
// owns the one eventual connection task and erases/disposes any late completion.
internal sealed class OwnedCacheStore : ICoherentCacheGetStore, IAsyncDisposable
{
    private readonly object _sync = new();
    private readonly CacheConnectionSettings _settings;
    private readonly SessionCacheAdmission _admission;
    private readonly X509Certificate2 _root;
    private Task<(IConnectionMultiplexer Connection, DragonflyGetStore Store)>? _pending;
    private bool _closed;
    internal OwnedCacheStore(CacheConnectionSettings settings, SessionCacheAdmission admission)
    { _settings = settings; _admission = admission; _root = X509CertificateLoader.LoadCertificateFromFile(settings.RootCertificatePath); try { ServiceCertificates.RequireRoot(_root); } catch { _root.Dispose(); throw; } }
    private async Task<(IConnectionMultiplexer, DragonflyGetStore)> ConnectAsync()
    {
        var options = new ConfigurationOptions { Ssl = true, SslHost = _settings.TlsName, User = _settings.Username, Password = _settings.Password, AbortOnConnectFail = false, ConnectRetry = 0, ConnectTimeout = 1000, AsyncTimeout = 1000, SyncTimeout = 1000, AllowAdmin = false, BacklogPolicy=BacklogPolicy.FailFast, IncludeDetailInExceptions=false, ConfigurationChannel = "", SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13 };
        options.EndPoints.Add(_settings.Address, _settings.Port);
        options.CertificateValidation += (_, certificate, _, errors) =>
        {
            if (certificate is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
            using var leaf = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
            return Convert.ToHexString(SHA256.HashData(leaf.RawData)) == _settings.LeafSha256 && ServiceCertificates.ValidLeaf(leaf, _root, "1.3.6.1.5.5.7.3.1");
        };
        var connection = await ConnectionMultiplexer.ConnectAsync(options);
        try { return (connection, new DragonflyGetStore(connection, _admission)); }
        catch { await connection.DisposeAsync(); throw; }
    }
    public async Task<byte[]?> GetAsync(string key, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); Task<(IConnectionMultiplexer Connection, DragonflyGetStore Store)> pending;
        lock (_sync) { ObjectDisposedException.ThrowIf(_closed, this); pending = _pending ??= ConnectAsync(); }
        var pair = await pending.WaitAsync(token); token.ThrowIfCancellationRequested();
        lock (_sync) ObjectDisposedException.ThrowIf(_closed, this);
        return await pair.Store.GetAsync(key, token);
    }
    public async ValueTask DisposeAsync()
    {
        Task<(IConnectionMultiplexer Connection, DragonflyGetStore Store)>? pending;
        lock (_sync) { if (_closed) return; _closed = true; pending = _pending; }
        _admission.Quarantine();
        if (pending is null) { _root.Dispose(); return; }
        // Connect has its own bounded budget. On a late provider, retain trust/key
        // ownership until completion instead of disposing resources still in use.
        async Task Finish()
        {
            try { var pair = await pending; pair.Store.Dispose(); await pair.Connection.DisposeAsync(); }
            catch { /* Connection errors are not logged with endpoint/credential data. */ }
            finally { _root.Dispose(); }
        }
        var finish = Finish(); try { await finish.WaitAsync(TimeSpan.FromSeconds(3)); } catch (TimeoutException) { _ = finish; }
    }
}
