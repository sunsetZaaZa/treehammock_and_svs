using System.Data;
using NodaTime;
using Npgsql;
using NpgsqlTypes;
namespace Treehammock.SessionValidation.Storage;

internal sealed class NpgsqlSnapshotExecutor(NpgsqlDataSource source) : IYsqlSnapshotExecutor
{
    internal const string Query = "select * from public.svs_read_current_session(@hash)";
    public async Task<CurrentSessionRow?> ReadAsync(string binding, TimeSpan budget, CancellationToken cancellationToken)
    {
        await using var connection = await source.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken);
        // Unsupported target settings fail closed. Never use follower reads or inherited writer context.
        await using (var setup = new NpgsqlCommand("set transaction read only; set local yb_read_from_followers = off; " +
            $"set local statement_timeout = {Math.Max(1, (int)budget.TotalMilliseconds)}; " +
            $"set local lock_timeout = {Math.Max(1, (int)budget.TotalMilliseconds)}", connection, transaction))
        { setup.CommandTimeout = Math.Max(1, (int)Math.Ceiling(budget.TotalSeconds)); await setup.ExecuteNonQueryAsync(cancellationToken); }
        CurrentSessionRow? result = null;
        try
        {
            await using (var command = new NpgsqlCommand(Query, connection, transaction))
            {
                command.CommandTimeout = Math.Max(1, (int)Math.Ceiling(budget.TotalSeconds));
                command.Parameters.AddWithValue("hash", NpgsqlDbType.Text, binding);
                await using var reader = await command.ExecuteReaderAsync(cancellationToken);
                if (await reader.ReadAsync(cancellationToken))
                {
                    result = ReadRow(reader);
                    if (await reader.ReadAsync(cancellationToken)) throw new DataException("Ambiguous authority");
                }
            }
            // No result escapes if transaction completion is unknown or failed.
            await transaction.CommitAsync(cancellationToken);
            return result;
        }
        catch { result?.Dispose(); throw; }
    }
    internal static CurrentSessionRow ReadRow(NpgsqlDataReader reader)
    {
        // Read key last, after all potentially malformed nonsecret columns.
        string hash = reader.GetString(0);
        var identity = new Core.SessionIdentity(reader.GetGuid(1),reader.GetGuid(2),reader.GetInt64(3),reader.GetInt32(4),reader.GetGuid(5),reader.GetGuid(6));
        var accountStamp = reader.GetGuid(7);
        var lifetime = new Core.SessionLifetime(reader.GetFieldValue<Instant>(9),reader.GetFieldValue<Instant>(10),
            Earlier(Optional(reader,11), Optional(reader,12)));
        var verification = reader.GetInt16(13); var unlock = Optional(reader,14);
        var readAt = reader.GetFieldValue<Instant>(15); var json = reader.GetString(16);
        return new(hash, identity, accountStamp, reader.GetFieldValue<byte[]>(8), lifetime, verification, unlock, readAt, json);
    }
    private static Instant? Optional(NpgsqlDataReader reader,int n) => reader.IsDBNull(n) ? null : reader.GetFieldValue<Instant>(n);
    private static Instant? Earlier(Instant? a, Instant? b) => a is null ? b : b is null ? a : a < b ? a : b;
}
