using Npgsql;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
namespace treehammock.Repos;

public sealed record RetentionClaim(string Job, Guid Lease);
public sealed record RetentionBatch(int Eligible, int Affected, bool Wrapped);

public sealed class RetentionRepo(StorageContext storage)
{
    // Independent durable transactions: crashes roll back work/cursor together and
    // leave the claim recoverable after its lease. Maintenance creates no receipts.
    public async Task<RetentionClaim?> ClaimAsync(CancellationToken ct)
    {
        await using var c = await storage.CreateConnection(ct);
        await using var cmd = new NpgsqlCommand("select job_name,lease_id from cor22_claim_retention()", c) { CommandTimeout = 5 };
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? new(r.GetString(0), r.GetGuid(1)) : null;
    }

    public async Task<RetentionBatch> RunAsync(RetentionClaim claim, RetentionSettings settings, CancellationToken ct)
    {
        await using var c = await storage.CreateConnection(ct);
        await using var tx = await c.BeginTransactionAsync(ct);
        await using (var limits = new NpgsqlCommand("set local statement_timeout='5s';set local lock_timeout='500ms'", c, tx))
            await limits.ExecuteNonQueryAsync(ct);
        await using var cmd = new NpgsqlCommand("select eligible,affected,wrapped from cor22_retention_batch(@job,@lease,@batch,@accounts,@history,@audit,@unverified,@dry)", c, tx) { CommandTimeout = 6 };
        cmd.Parameters.AddWithValue("job", claim.Job); cmd.Parameters.AddWithValue("lease", claim.Lease);
        cmd.Parameters.AddWithValue("batch", settings.BatchSize); cmd.Parameters.AddWithValue("accounts", settings.AccountsPerBatch);
        cmd.Parameters.AddWithValue("history", settings.ProofHistoryDays); cmd.Parameters.AddWithValue("audit", settings.AuditHistoryDays);
        cmd.Parameters.AddWithValue("unverified", settings.UnverifiedAccountDays); cmd.Parameters.AddWithValue("dry", settings.DryRun);
        RetentionBatch result;
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            if (!await r.ReadAsync(ct)) throw new InvalidOperationException("Retention batch did not return an outcome.");
            result = new(r.GetInt32(0), r.GetInt32(1), r.GetBoolean(2));
        }
        await tx.CommitAsync(ct);
        return result;
    }

    public async Task RecordFailureAsync(RetentionClaim claim, string code, CancellationToken ct)
    {
        await using var c = await storage.CreateConnection(ct);
        await using var cmd = new NpgsqlCommand("select cor22_fail_retention(@job,@lease,@code)", c) { CommandTimeout = 5 };
        cmd.Parameters.AddWithValue("job", claim.Job); cmd.Parameters.AddWithValue("lease", claim.Lease);
        cmd.Parameters.AddWithValue("code", code);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
