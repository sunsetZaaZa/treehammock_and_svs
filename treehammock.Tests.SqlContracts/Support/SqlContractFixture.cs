using System.Runtime.ExceptionServices;
using Npgsql;

namespace treehammock.Tests.SqlContracts.Support;

/// <summary>Owns one schema, nonpooled connections and every scheduled task for one test.</summary>
internal sealed class SqlContractFixture : IAsyncDisposable
{
    private readonly NpgsqlDataSource _source;
    private readonly List<NpgsqlConnection> _connections = new();
    private readonly List<Task> _work = new();
    private readonly List<NpgsqlTransaction> _transactions = new();
    private readonly CancellationTokenSource _lifetime;
    private bool _disposed;

    private SqlContractFixture(string connectionString, CancellationToken caller)
    {
        Schema = "cor01_" + Guid.NewGuid().ToString("N");
        RunId = Environment.GetEnvironmentVariable("TREEHAMMOCK_CORRECTION_RUN_ID") ?? Guid.NewGuid().ToString("D");
        var settings = new NpgsqlConnectionStringBuilder(connectionString)
        {
            Pooling = false,
            Timeout = 5,
            CommandTimeout = 30,
            CancellationTimeout = 2000,
            SearchPath = "public",
            ApplicationName = Schema
        };
        _source = NpgsqlDataSource.Create(settings.ConnectionString);
        _lifetime = CancellationTokenSource.CreateLinkedTokenSource(caller);
        _lifetime.CancelAfter(TimeSpan.FromSeconds(30));
    }

    public string Schema { get; }
    public string RunId { get; }
    public CancellationToken Token => _lifetime.Token;
    public IReadOnlyList<NpgsqlConnection> Connections => _connections;
    public int ObservedTasks => _work.Count;

    public static async Task RunAsync(Func<SqlContractFixture, CancellationToken, Task> body, CancellationToken caller = default,
        bool installBaseline = true)
    {
        SqlContractFixture fixture = await CreateAsync(caller, installBaseline);
        Exception? primary = null;
        try { await body(fixture, fixture.Token); }
        catch (Exception error) { primary = error; }
        try { await fixture.DisposeAsync(); }
        catch (Exception cleanup)
        {
            if (primary is null) throw;
            primary.Data["COR01CleanupFailure"] = cleanup.GetType().Name;
        }
        if (primary is not null) ExceptionDispatchInfo.Capture(primary).Throw();
    }

    public static async Task<SqlContractFixture> CreateAsync(CancellationToken caller = default, bool installBaseline = true,
        string? setupSql = null, Action<string>? schemaAllocated = null)
    {
        if (!treehammock.Tests.Integration.Database.DeferredSqlProcedureContractSettings.ShouldRun())
            throw new InvalidOperationException(treehammock.Tests.Integration.Database.DeferredSqlProcedureContractSettings.SkipReason);
        var fixture = new SqlContractFixture(treehammock.Tests.Integration.Database.DeferredSqlProcedureContractSettings.ConnectionString!, caller);
        try
        {
            schemaAllocated?.Invoke(fixture.Schema);
            await using var connection = await fixture._source.OpenConnectionAsync(fixture.Token);
            await using var transaction = await connection.BeginTransactionAsync(fixture.Token);
            // Serialize extension bootstrap across independent jobs, not just this xUnit assembly.
            await fixture.ExecuteAsync(connection,
                "set local lock_timeout = '10s'; select pg_advisory_xact_lock(548013001); create extension if not exists pgcrypto with schema public;",
                transaction, fixture.Token);
            await fixture.ExecuteAsync(connection, $"create schema {fixture.Schema}; set local search_path to {fixture.Schema}, public;",
                transaction, fixture.Token);
            if (installBaseline)
                await fixture.ExecuteAsync(connection, await File.ReadAllTextAsync(BaselinePath(), fixture.Token), transaction, fixture.Token);
            if (setupSql is not null)
                await fixture.ExecuteAsync(connection, setupSql, transaction, fixture.Token);
            await transaction.CommitAsync(fixture.Token);
            return fixture;
        }
        catch (Exception primary)
        {
            try { await fixture.DisposeAsync(); }
            catch (Exception cleanup) { primary.Data["COR01CleanupFailure"] = cleanup.GetType().Name; }
            throw;
        }
    }

    public async Task<NpgsqlConnection> OpenConnectionAsync(CancellationToken cancellation = default, string? initializeSql = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(Token, cancellation);
        var connection = await _source.OpenConnectionAsync(linked.Token);
        try
        {
            await ExecuteAsync(connection, $"set search_path to {Schema}, public; set lock_timeout = '10s';", cancellation: linked.Token);
            if (initializeSql is not null) await ExecuteAsync(connection, initializeSql, cancellation: linked.Token);
            _connections.Add(connection);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    public T Observe<T>(T task) where T : Task
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _work.Add(task);
        return task;
    }

    public async Task<NpgsqlTransaction> BeginTransactionAsync(NpgsqlConnection connection)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var transaction = await connection.BeginTransactionAsync(Token);
        _transactions.Add(transaction);
        return transaction;
    }

    public async Task ExecuteAsync(NpgsqlConnection connection, string sql, NpgsqlTransaction? transaction = null,
        CancellationToken cancellation = default)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 30 };
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(Token, cancellation);
        await command.ExecuteNonQueryAsync(linked.Token);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Exception? failure = null;
        try
        {
            await _lifetime.CancelAsync().WaitAsync(cleanup.Token);
            // Cancellation-aware commands must finish before their connections and transactions close.
            try { await Task.WhenAll(_work).WaitAsync(cleanup.Token); }
            catch (Exception error)
            {
                // Cancellation is expected on teardown; still observe every task and preserve other faults.
                if (_work.Any(task => !task.IsCompleted)) failure = error;
                foreach (Task task in _work.Where(task => task.IsFaulted))
                {
                    AggregateException? taskError = task.Exception;
                    if (taskError is not null && taskError.Flatten().InnerExceptions.Any(inner => inner is not OperationCanceledException))
                        failure ??= taskError;
                }
            }
            foreach (var transaction in _transactions)
            {
                try { await transaction.DisposeAsync().AsTask().WaitAsync(cleanup.Token); }
                catch (Exception error) { failure ??= error; }
            }
            foreach (var connection in _connections)
            {
                try { await connection.DisposeAsync().AsTask().WaitAsync(cleanup.Token); }
                catch (Exception error) { failure ??= error; }
            }
            // A fresh administrative connection has public search_path and only drops this random schema.
            await using var admin = await _source.OpenConnectionAsync(cleanup.Token);
            await using var command = new NpgsqlCommand($"set lock_timeout = '2s'; drop schema if exists {Schema} cascade;", admin)
            { CommandTimeout = 5 };
            await command.ExecuteNonQueryAsync(cleanup.Token);
        }
        catch (Exception error) { failure ??= error; }
        finally
        {
            try { await _source.DisposeAsync().AsTask().WaitAsync(cleanup.Token); }
            catch (Exception error) { failure ??= error; }
            _lifetime.Dispose();
        }
        if (failure is not null)
            throw new InvalidOperationException($"Owned SQL fixture cleanup did not complete within its budget. Run={RunId}; schema={Schema}.", failure);
    }

    private static string BaselinePath()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.csproj")))
            directory = directory.Parent;
        if (directory is null) throw new InvalidOperationException("Cannot locate canonical baseline.");
        return Path.Combine(directory.FullName, "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql");
    }
}
