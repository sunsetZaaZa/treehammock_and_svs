using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Npgsql;

namespace treehammock.Rigging.Database.Migrations;

public sealed record DatabaseMigration(int Version, string Name, string Sha256, string Sql);
public sealed record DatabaseMigrationResult(int Applied, bool AdoptedLegacy);

/// <summary>Deployment-only, atomic migrations. HTTP startup never calls this runner.</summary>
public static class DatabaseMigrationRunner
{
    private const string ResourcePrefix = "treehammock.Migrations.";
    private static readonly Regex SchemaPattern = new("^[a-z][a-z0-9_]{0,62}$", RegexOptions.CultureInvariant);

    public static IReadOnlyList<DatabaseMigration> LoadMigrations()
    {
        using var manifest = JsonDocument.Parse(ReadResource("manifest.json"));
        var migrations = manifest.RootElement.EnumerateArray().Select(entry =>
        {
            string name = entry.GetProperty("name").GetString()!;
            byte[] bytes = ReadResource(name);
            string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            if (hash != entry.GetProperty("sha256").GetString())
                throw new InvalidOperationException("Migration resource checksum mismatch.");
            return new DatabaseMigration(entry.GetProperty("version").GetInt32(), name, hash, Encoding.UTF8.GetString(bytes));
        }).ToArray();
        ValidateBundle(migrations);
        return migrations;
    }

    private static void ValidateBundle(IReadOnlyList<DatabaseMigration> migrations)
    {
        if (migrations.Count == 0) throw new InvalidOperationException("Empty migration bundle.");
        for (int i = 0; i < migrations.Count; i++)
        {
            var migration = migrations[i];
            if (migration.Version != i + 1 || !Regex.IsMatch(migration.Name, "^[0-9]{3}_[a-z_]+\\.sql$") ||
                !migration.Name.StartsWith(migration.Version.ToString("D3") + "_", StringComparison.Ordinal) ||
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(migration.Sql))).ToLowerInvariant() != migration.Sha256)
                throw new InvalidOperationException("Invalid migration bundle ordering or checksum.");
        }
    }

    public static async Task<DatabaseMigrationResult> ApplyAsync(string connectionString, string schema = "public",
        bool adoptLegacy = false, CancellationToken cancellation = default, IReadOnlyList<DatabaseMigration>? migrations = null)
    {
        if (!IsAllowedSchema(schema)) throw new ArgumentException("Invalid migration schema.", nameof(schema));
        migrations ??= LoadMigrations();
        ValidateBundle(migrations);
        var settings = new NpgsqlConnectionStringBuilder(connectionString)
        {
            Pooling = false, Timeout = 5, CommandTimeout = 30, CancellationTimeout = 2000,
            IncludeErrorDetail = false, SearchPath = "public", ApplicationName = "treehammock-migrations:" + schema
        };
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        budget.CancelAfter(TimeSpan.FromMinutes(2));
        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        await connection.OpenAsync(budget.Token);
        await using var transaction = await connection.BeginTransactionAsync(budget.Token);
        await ExecuteAsync(connection, transaction, "set local lock_timeout = '10s'; set local statement_timeout = '30s';", budget.Token);
        // Extension bootstrap is shared with the owned SQL harness. Both leases
        // are transaction-scoped; cancellation, failure or disconnect releases them.
        await AcquireLeaseAsync(connection, transaction, "select pg_try_advisory_xact_lock(548013001)", null, budget.Token);
        await AcquireLeaseAsync(connection, transaction,
            "select pg_try_advisory_xact_lock(hashtextextended(current_database() || ':' || @schema, 0))", schema, budget.Token);
        await ExecuteAsync(connection, transaction, "create extension if not exists pgcrypto with schema public;", budget.Token);
        await using (var extension = new NpgsqlCommand("select n.nspname from pg_extension e join pg_namespace n on n.oid=e.extnamespace where e.extname='pgcrypto'", connection, transaction))
            if ((string?)await extension.ExecuteScalarAsync(budget.Token) != "public")
                throw new InvalidOperationException("pgcrypto must be installed in public before migration.");
        await ExecuteAsync(connection, transaction, $"create schema if not exists {Quote(schema)};", budget.Token);
        await SetPathAsync(connection, transaction, schema, budget.Token);
        bool hasHistory;
        await using (var command = new NpgsqlCommand("select to_regclass(@history) is not null", connection, transaction))
        {
            command.Parameters.AddWithValue("history", schema + ".treehammock_schema_history");
            hasHistory = (bool)(await command.ExecuteScalarAsync(budget.Token))!;
        }
        bool adopted = false;
        if (!hasHistory && await FingerprintAsync(connection, transaction, schema, budget.Token) != "{}")
        {
            if (!adoptLegacy) throw new InvalidOperationException("Existing schema requires explicit legacy adoption during maintenance.");
            // Install the frozen baseline in a transaction-owned shadow schema.
            // Compare columns/defaults, constraints, indexes, routines, triggers
            // and sequence configuration; retain actual target data and identities.
            string shadow = "cor02_adopt_" + Guid.NewGuid().ToString("N");
            await ExecuteAsync(connection, transaction, $"create schema {Quote(shadow)};", budget.Token);
            await SetPathAsync(connection, transaction, shadow, budget.Token);
            await ExecuteAsync(connection, transaction, migrations[0].Sql, budget.Token);
            string expected = await FingerprintAsync(connection, transaction, shadow, budget.Token);
            string actual = await FingerprintAsync(connection, transaction, schema, budget.Token);
            if (actual != expected) throw new InvalidOperationException("Legacy schema contract differs from the frozen baseline; adoption refused.");
            await SetPathAsync(connection, transaction, schema, budget.Token);
            await ExecuteAsync(connection, transaction, $"drop schema {Quote(shadow)} cascade;", budget.Token);
            adopted = true;
        }
        await ExecuteAsync(connection, transaction, """
            create table if not exists treehammock_schema_history(
                version integer primary key,
                name text not null unique,
                sha256 text not null check(length(sha256)=64),
                installed_at timestamp with time zone not null default clock_timestamp(),
                adopted_legacy boolean not null default false
            );
            """, budget.Token);
        var history = new List<(int Version, string Name, string Hash)>();
        await using (var command = new NpgsqlCommand("select version,name,sha256 from treehammock_schema_history order by version", connection, transaction))
        await using (var reader = await command.ExecuteReaderAsync(budget.Token))
            while (await reader.ReadAsync(budget.Token)) history.Add((reader.GetInt32(0), reader.GetString(1), reader.GetString(2)));
        for (int i = 0; i < history.Count; i++)
        {
            if (i >= migrations.Count || history[i].Version != i + 1 || history[i].Name != migrations[i].Name || history[i].Hash != migrations[i].Sha256)
                throw new InvalidOperationException("Migration history ordering, name or checksum mismatch; no migrations applied.");
        }
        if (hasHistory && history.Count == 0 && await FingerprintAsync(connection, transaction, schema, budget.Token) != "{}")
            throw new InvalidOperationException("Empty migration history on a nonempty schema; adoption cannot be bypassed.");
        int applied = 0;
        foreach (var migration in migrations.Skip(history.Count))
        {
            if (!(adopted && migration.Version == 1))
                await ExecuteAsync(connection, transaction, migration.Sql, budget.Token);
            await using var record = new NpgsqlCommand("insert into treehammock_schema_history(version,name,sha256,adopted_legacy) values(@version,@name,@hash,@adopted)", connection, transaction);
            record.Parameters.AddWithValue("version", migration.Version);
            record.Parameters.AddWithValue("name", migration.Name);
            record.Parameters.AddWithValue("hash", migration.Sha256);
            record.Parameters.AddWithValue("adopted", adopted && migration.Version == 1);
            await record.ExecuteNonQueryAsync(budget.Token);
            applied++;
        }
        await transaction.CommitAsync(budget.Token);
        return new DatabaseMigrationResult(applied, adopted);
    }

    private static async Task AcquireLeaseAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql,
        string? schema, CancellationToken cancellation)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        while (true)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            if (schema is not null) command.Parameters.AddWithValue("schema", schema);
            if ((bool)(await command.ExecuteScalarAsync(deadline.Token))!) return;
            await Task.Delay(50, deadline.Token);
        }
    }

    public static async Task<string> FingerprintAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string schema,
        CancellationToken cancellation = default)
    {
        if (!IsAllowedSchema(schema)) throw new ArgumentException("Invalid schema.", nameof(schema));
        await SetPathAsync(connection, transaction, schema, cancellation);
        await using var command = new NpgsqlCommand(Encoding.UTF8.GetString(ReadResource("catalog_contract.sql")), connection, transaction);
        command.Parameters.AddWithValue("schema", schema);
        return (string)(await command.ExecuteScalarAsync(cancellation))!;
    }

    private static Task SetPathAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string schema, CancellationToken cancellation) =>
        ExecuteAsync(connection, transaction, $"set local search_path to {Quote(schema)}, public;", cancellation);

    private static bool IsAllowedSchema(string schema) => SchemaPattern.IsMatch(schema) &&
        !schema.StartsWith("pg_", StringComparison.Ordinal) && schema != "information_schema";

    private static string Quote(string identifier) => "\"" + identifier + "\"";
    private static byte[] ReadResource(string name)
    {
        using var stream = typeof(DatabaseMigrationRunner).Assembly.GetManifestResourceStream(ResourcePrefix + name)
            ?? throw new InvalidOperationException("Missing embedded migration resource.");
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }
    private static async Task ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql, CancellationToken cancellation)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 30 };
        await command.ExecuteNonQueryAsync(cancellation);
    }
}
