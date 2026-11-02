using Microsoft.Extensions.Options;
using Npgsql;
using treehammock.Rigging.Config;
using treehammock.Rigging.Dependencies;
namespace treehammock.Rigging.Database;

public class StorageContext : IDisposable, IAsyncDisposable
{
    protected readonly DatabaseSettings _dbSettings;
    protected readonly NpgsqlDataSource _databaseInstance;
    private int _disposed;
    public treehammock.Services.SecurityOperationService SecurityOperations { get; }
    public StorageContext(IOptions<DatabaseSettings> dbSettings, IOptions<SecurityOperationSettings>? operationSettings = null, CancellationToken shutdown = default)
    {
        _dbSettings = dbSettings.Value;
        var builder = new NpgsqlDataSourceBuilder(BuildConnectionString(_dbSettings));
        builder.UseNodaTime();
        _databaseInstance = builder.Build();
        SecurityOperations = new(this, operationSettings?.Value ?? SecurityOperationSettings.Isolated(), shutdown);
    }
    public static string BuildConnectionString(DatabaseSettings settings)
    {
        bool production = string.Equals(settings.profile, "Production", StringComparison.OrdinalIgnoreCase);
        if (!production && !string.Equals(settings.profile, "Local", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Database profile must be Local or Production.");
        if (settings.minimumPoolSize > settings.maximumPoolSize)
            throw new ArgumentException("Minimum pool size cannot exceed maximum pool size.");
        var builder = new NpgsqlConnectionStringBuilder
        {
            Host = settings.servers, Port = settings.port, Database = settings.database,
            Username = settings.userId, Password = settings.password,
            SslMode = production ? SslMode.VerifyFull : SslMode.Disable,
            Pooling = true, MinPoolSize = settings.minimumPoolSize, MaxPoolSize = settings.maximumPoolSize,
            Timeout = settings.connectionTimeoutSeconds, CommandTimeout = settings.commandTimeoutSeconds,
            CancellationTimeout = settings.cancellationTimeoutMilliseconds,
            IncludeErrorDetail = false, PersistSecurityInfo = false
        };
        if (production && !string.IsNullOrWhiteSpace(settings.rootCertificate)) builder.RootCertificate = settings.rootCertificate;
        return builder.ConnectionString;
    }
    public virtual async Task<NpgsqlConnection> CreateConnection(CancellationToken cancellationToken = default)
    {
        try { return await _databaseInstance.OpenConnectionAsync(cancellationToken); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { throw DependencyUnavailableException.Database("open_connection", DependencyStage.Acquire, ex); }
    }
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0) _databaseInstance.Dispose();
    }
    public virtual async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0) await _databaseInstance.DisposeAsync();
    }
}
