using Npgsql;
using NpgsqlTypes;
using treehammock.Rigging.Database;
using treehammock.Services;
namespace treehammock.Repos;

public sealed record TotpRotationRow(ProtectedTotpSecret Envelope, long RowVersion);
public sealed class TotpReencryptionRepo(StorageContext storage)
{
    public async Task<List<TotpRotationRow>> ReadBatchAsync(string targetKey, Guid? after, int maximum, CancellationToken ct, bool includeTarget = false)
    {
        await using var connection = await storage.CreateConnection(ct);
        await using var command = new NpgsqlCommand("select account_id,totp_enrollment_id,totp_algorithm,totp_digits,totp_period_seconds,totp_clock_skew_steps,totp_key_id,totp_secret_ciphertext,totp_secret_nonce,totp_secret_tag,totp_secret_version,totp_row_version from two_factor_authentications where method=3 and totp_secret_ciphertext is not null and (@all or totp_key_id<>@target) and (@after::uuid is null or totp_enrollment_id>@after) order by totp_enrollment_id limit @maximum", connection);
        command.Parameters.AddWithValue("all", includeTarget); command.Parameters.AddWithValue("target", targetKey); command.Parameters.Add("after", NpgsqlDbType.Uuid).Value = (object?)after ?? DBNull.Value;
        command.Parameters.AddWithValue("maximum", maximum);
        await using var reader = await command.ExecuteReaderAsync(ct); var rows = new List<TotpRotationRow>();
        while (await reader.ReadAsync(ct))
        {
            var context = new TotpEnrollmentContext(reader.GetGuid(0), reader.GetGuid(1), new(reader.GetString(2), reader.GetInt32(3), reader.GetInt32(4), reader.GetInt32(5)));
            rows.Add(new(new(reader.GetFieldValue<byte[]>(7), reader.GetFieldValue<byte[]>(8), reader.GetFieldValue<byte[]>(9), reader.GetInt32(10), reader.GetString(6), context), reader.GetInt64(11)));
        }
        return rows;
    }
    public async Task<TotpRotationRow?> ReadEnrollmentAsync(Guid enrollmentId, CancellationToken ct)
    {
        await using var connection = await storage.CreateConnection(ct);
        await using var command = new NpgsqlCommand("select account_id,totp_enrollment_id,totp_algorithm,totp_digits,totp_period_seconds,totp_clock_skew_steps,totp_key_id,totp_secret_ciphertext,totp_secret_nonce,totp_secret_tag,totp_secret_version,totp_row_version from two_factor_authentications where totp_enrollment_id=@enrollment and totp_secret_ciphertext is not null", connection);
        command.Parameters.AddWithValue("enrollment", enrollmentId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null; // Concurrent removal has no retained material.
        var context = new TotpEnrollmentContext(reader.GetGuid(0), reader.GetGuid(1), new(reader.GetString(2), reader.GetInt32(3), reader.GetInt32(4), reader.GetInt32(5)));
        return new(new(reader.GetFieldValue<byte[]>(7), reader.GetFieldValue<byte[]>(8), reader.GetFieldValue<byte[]>(9), reader.GetInt32(10), reader.GetString(6), context), reader.GetInt64(11));
    }
    public async Task<bool> CompareExchangeAsync(TotpRotationRow observed, ProtectedTotpSecret replacement, CancellationToken ct)
    {
        if (replacement.Context != observed.Envelope.Context || replacement.Version != TotpSecretProtector.CurrentVersion)
            throw new InvalidOperationException("Rotation must preserve enrollment identity and parameters.");
        await using var connection = await storage.CreateConnection(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using var command = new NpgsqlCommand("select cor15_reencrypt_totp(@account,@enrollment,@version,@oldKey,@newKey,@cipher,@nonce,@tag)", connection, transaction);
        command.Parameters.AddWithValue("account", observed.Envelope.Context.AccountId); command.Parameters.AddWithValue("enrollment", observed.Envelope.Context.EnrollmentId);
        command.Parameters.AddWithValue("version", observed.RowVersion); command.Parameters.AddWithValue("oldKey", observed.Envelope.KeyId); command.Parameters.AddWithValue("newKey", replacement.KeyId);
        command.Parameters.AddWithValue("cipher", replacement.Ciphertext); command.Parameters.AddWithValue("nonce", replacement.Nonce); command.Parameters.AddWithValue("tag", replacement.Tag);
        bool applied = (bool)(await command.ExecuteScalarAsync(ct) ?? false);
        await transaction.CommitAsync(ct); return applied;
    }
    public async Task<long> RemainingAsync(string targetKey, CancellationToken ct)
    {
        await using var connection = await storage.CreateConnection(ct);
        await using var command = new NpgsqlCommand("select count(*) from two_factor_authentications where totp_secret_ciphertext is not null and totp_key_id<>@target", connection);
        command.Parameters.AddWithValue("target", targetKey); return (long)(await command.ExecuteScalarAsync(ct) ?? 0L);
    }
}
