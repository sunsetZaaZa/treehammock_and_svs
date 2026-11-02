using Npgsql;
using treehammock.DataLayer.Entitlements;
using treehammock.Entities;
using treehammock.Rigging.Database;
using treehammock.Rigging.Dependencies;
namespace treehammock.Repos;

public sealed class EntitlementRepo(StorageContext storage)
{
    internal static async Task<EntitlementProjection> ReadAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction,
        Guid account, CancellationToken token)
    {
        await using var command = new NpgsqlCommand("select cor20_resolve_account(@account)::text", connection, transaction);
        command.Parameters.AddWithValue("account", account);
        var value = await command.ExecuteScalarAsync(token);
        if (value is not string json) throw DependencyUnavailableException.InvalidResponse("cor20_resolve_account");
        return EntitlementProjection.Parse(json, account);
    }
    internal static async Task HydrateAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, Session session, CancellationToken token)
    {
        session.entitlements = await ReadAsync(connection, transaction, session.accountId, token);
        session.features = session.entitlements.Features;
    }
    public async Task<int> RenewAsync(CancellationToken token)
    {
        await using var connection = await storage.CreateConnection(token);
        await using var transaction = await connection.BeginTransactionAsync(token);
        await using var command = new NpgsqlCommand("select * from cor20_renew_batch(64)", connection, transaction);
        int count;
        await using (var reader = await command.ExecuteReaderAsync(token))
        {
            if (!await reader.ReadAsync(token) || !reader.GetBoolean(0)) throw DependencyUnavailableException.InvalidResponse("cor20_renew_batch");
            count = reader.GetInt32(2);
        }
        await transaction.CommitAsync(token);
        return count;
    }
}
