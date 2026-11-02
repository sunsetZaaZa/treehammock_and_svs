using Npgsql;
using NpgsqlTypes;
using treehammock.Models.Activation;
using treehammock.Rigging.Database;
using treehammock.Rigging.Dependencies;
namespace treehammock.Repos;

// Use with a separately provisioned issuer-role StorageContext, never a caller-selected connection.
public sealed class EntitlementGrantRepo(StorageContext storage)
{
    public async Task<ActivationLifecycleResult> IssueAsync(EntitlementGrantApproval approval, CancellationToken token = default)
    {
        await using var operation = await storage.SecurityOperations.BeginAsync("EntitlementGrantRepo.Issue", approval,
            approval.AccountId, approval.AccountStamp, null, token);
        await using var cmd = RepositoryCommands.CreateFunctionCommand("cor19_issue_grant", operation.Connection,
            operation.Transaction, "grant", "account", "stamp", "catalog", "tier", "term", "cadence", "start", "end", "cycles", "redeem", "reference", "anchor", "denied");
        cmd.Parameters.AddWithValue("grant", approval.GrantId);
        cmd.Parameters.AddWithValue("account", approval.AccountId);
        cmd.Parameters.AddWithValue("stamp", approval.AccountStamp);
        cmd.Parameters.AddWithValue("catalog", approval.Catalog);
        cmd.Parameters.AddWithValue("tier", approval.Tier);
        cmd.Parameters.AddWithValue("term", approval.Term);
        cmd.Parameters.AddWithValue("cadence", approval.Cadence);
        cmd.Parameters.Add("start", NpgsqlDbType.TimestampTz).Value = (object?)approval.ApprovedStart ?? DBNull.Value;
        cmd.Parameters.Add("end", NpgsqlDbType.TimestampTz).Value = (object?)approval.AuthorizedEnd ?? DBNull.Value;
        cmd.Parameters.AddWithValue("cycles", approval.MaxCycles);
        cmd.Parameters.Add("redeem", NpgsqlDbType.TimestampTz).Value = approval.RedeemBefore;
        cmd.Parameters.AddWithValue("reference", approval.IssuerReference);
        cmd.Parameters.AddWithValue("anchor", approval.StartAnchor);
        cmd.Parameters.Add("denied", NpgsqlDbType.Array | NpgsqlDbType.Text).Value = approval.DeniedCapabilities;
        await using var reader = await cmd.ExecuteReaderAsync(operation.CancellationToken);
        if (!await reader.ReadAsync(operation.CancellationToken)) throw DependencyUnavailableException.InvalidResponse("cor19_issue_grant");
        var result = new ActivationLifecycleResult(reader.GetBoolean(0), reader.GetString(1));
        await reader.DisposeAsync();
        await operation.CommitAsync(result);
        return result;
    }
}
