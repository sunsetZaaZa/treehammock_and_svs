using Npgsql;
using NpgsqlTypes;
using treehammock.DataLayer.Operations;
using treehammock.Rigging.Database;

namespace treehammock.Repos;

public sealed record SecurityOperationBinding(byte[] RequestHmac, byte[] RecoveryHmac, int KeyVersion);
public sealed class SecurityOperationRepo(StorageContext storage)
{
    public async Task<SecurityOperationBinding?> GetBindingAsync(Guid id, CancellationToken token)
    {
        await using var connection = await storage.CreateConnection(token);
        await using var command = new NpgsqlCommand("select request_hmac,recovery_hmac,hmac_version from security_operations where operation_id=@id", connection);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(token);
        return await reader.ReadAsync(token) ? new(reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1), reader.GetInt32(2)) : null;
    }
    public async Task<bool> ReserveAsync(Guid id, SecurityOperationBinding binding, string purpose,
        DateTimeOffset issuedAt, DateTimeOffset executeBefore, DateTimeOffset expiresAt, CancellationToken token)
    {
        await using var connection = await storage.CreateConnection(token);
        await using var command = new NpgsqlCommand("""
            insert into security_operations(operation_id,request_hmac,recovery_hmac,hmac_version,purpose,issued_at,execute_before,expires_at)
            values(@id,@request,@recovery,@version,@purpose,@issued,@execute,@expires)
            on conflict(operation_id) do nothing
            """, connection);
        command.Parameters.AddWithValue("id", id); command.Parameters.AddWithValue("request", binding.RequestHmac);
        command.Parameters.AddWithValue("recovery", binding.RecoveryHmac); command.Parameters.AddWithValue("version", binding.KeyVersion);
        command.Parameters.AddWithValue("purpose", purpose);
        command.Parameters.AddWithValue("issued", issuedAt.UtcDateTime); command.Parameters.AddWithValue("execute", executeBefore.UtcDateTime);
        command.Parameters.AddWithValue("expires", expiresAt.UtcDateTime);
        return await command.ExecuteNonQueryAsync(token) == 1;
    }
    public async Task<SecurityOperationStatus> ReconcileAsync(Guid id, CancellationToken token)
    {
        await using var connection = await storage.CreateConnection(token);
        await using var transaction = await connection.BeginTransactionAsync(token);
        string state;
        await using (var command = new NpgsqlCommand("select reconcile_security_operation(@id)", connection, transaction))
        {
            command.Parameters.AddWithValue("id", id);
            state = (string)(await command.ExecuteScalarAsync(token))!;
        }
        int? httpStatus = null;
        await using (var command = new NpgsqlCommand("select http_status from security_operations where operation_id=@id", connection, transaction))
        {
            command.Parameters.AddWithValue("id", id);
            object? value = await command.ExecuteScalarAsync(token); if (value is int status) httpStatus = status;
        }
        var steps = new List<SecurityOperationStep>();
        await using (var command = new NpgsqlCommand("select step_key,outcome_code,succeeded from security_operation_steps where operation_id=@id order by step_key", connection, transaction))
        {
            command.Parameters.AddWithValue("id", id);
            await using var reader = await command.ExecuteReaderAsync(token);
            while (await reader.ReadAsync(token)) steps.Add(new(reader.GetString(0), reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetBoolean(2)));
        }
        await transaction.CommitAsync(token);
        return new(id, Enum.Parse<SecurityOperationState>(state), httpStatus, steps);
    }
    public async Task CompleteRequestAsync(Guid id, int status, bool failed, CancellationToken token)
    {
        await using var connection = await storage.CreateConnection(token);
        await using var command = new NpgsqlCommand("""
            update security_operations set
                state = case when @failed then
                    case when exists(select 1 from security_operation_steps where operation_id=@id)
                        then 'PartiallyCommitted' else 'RolledBack' end
                    else 'Committed' end,
                http_status=@status,finished_at=clock_timestamp()
            where operation_id=@id and state='Pending'
            """, connection);
        // The UPDATE takes the same gate as any still-running child. It cannot
        // terminally fence a transaction that has not committed/rolled back yet.
        command.Parameters.AddWithValue("id", id); command.Parameters.AddWithValue("status", status);
        command.Parameters.AddWithValue("failed", failed);
        await command.ExecuteNonQueryAsync(token);
    }
    public async Task<int> PurgeAsync(int limit, CancellationToken token)
    {
        await using var connection = await storage.CreateConnection(token);
        await using var command = new NpgsqlCommand("select purge_security_operations(@limit)", connection);
        command.Parameters.AddWithValue("limit", limit);
        return (int)(await command.ExecuteScalarAsync(token))!;
    }
}
