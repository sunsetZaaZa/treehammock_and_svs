using NodaTime;
using Npgsql;
using NpgsqlTypes;
using treehammock.Entities;
using treehammock.Rigging.Database;
using treehammock.Rigging.Dependencies;
using treehammock.DataLayer.Operations;

namespace treehammock.Repos;

public sealed record RefreshSessionSnapshot(Session Session, string AccessTokenHash, string WebKey);
public sealed record RefreshSessionResult(bool Result, string Code, Instant? AccessExpiration = null,
    Instant? SessionExpiration = null, Instant? CutOff = null,
    treehammock.DataLayer.Entitlements.EntitlementProjection? Entitlements = null);

public interface ISessionRefreshRepo
{
    Task<RefreshSessionSnapshot?> FindAsync(string refreshHash, Guid family, long generation, CancellationToken cancellation);
    Task<RefreshSessionResult> RotateAsync(RefreshSessionSnapshot snapshot, string refreshHash,
        string newHash, byte[] newKey, Guid newIdentity, int accessSeconds, int minimumInterval, CancellationToken cancellation);
}

public sealed class SessionRefreshRepo(StorageContext storage) : ISessionRefreshRepo
{
    public async Task<RefreshSessionSnapshot?> FindAsync(string refreshHash, Guid family, long generation, CancellationToken cancellation)
    {
        try
        {
            await using var connection = await storage.CreateConnection(cancellation);
            await using var command = new NpgsqlCommand("select * from get_refresh_session(@hash,@family,@generation)", connection);
            command.Parameters.AddWithValue("hash", refreshHash);
            command.Parameters.AddWithValue("family", family);
            command.Parameters.AddWithValue("generation", generation);
            await using var reader = await command.ExecuteReaderAsync(cancellation);
            if (!await reader.ReadAsync(cancellation)) return null;
            var session = new Session(reader.GetGuid(0), reader.GetFieldValue<byte[]>(1), reader.GetInt16(2), reader.GetInt16(3),
                reader.GetFieldValue<Instant>(4), reader.GetFieldValue<Period>(5), reader.GetFieldValue<Instant>(6),
                reader.GetFieldValue<Instant>(7), reader.IsDBNull(8) ? null : reader.GetFieldValue<Instant>(8),
                (treehammock.RiggingSupport.Enum.FeatureSet)reader.GetInt16(9), reader.GetGuid(10), reader.GetGuid(11),
                reader.GetGuid(12), reader.GetInt64(13), reader.GetInt32(14),
                treehammock.DataLayer.Entitlements.EntitlementProjection.Parse(reader.GetString(17), reader.GetGuid(0)));
            return new(session, reader.GetString(15), reader.GetString(16));
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { throw; }
        catch (Exception ex) { throw DependencyUnavailableException.Database("get_refresh_session", DependencyStage.Read, ex); }
    }

    public async Task<RefreshSessionResult> RotateAsync(RefreshSessionSnapshot snapshot, string refreshHash,
        string newHash, byte[] newKey, Guid newIdentity, int accessSeconds, int minimumInterval, CancellationToken cancellation)
    {
        Session session = snapshot.Session;
        try
        {
            await using var operation = await storage.SecurityOperations.BeginAsync("SessionRefreshRepo.Rotate",
                new { session.accountId, session.accountSecurityStamp, session.familyId, session.generation,
                    snapshot.AccessTokenHash, refreshHash, newHash, newIdentity, accessSeconds, minimumInterval },
                session.accountId, session.accountSecurityStamp, $"{session.familyId:D}:{session.generation}", cancellation);
            await using var command = new NpgsqlCommand("""
                select * from refresh_session(@account,@stamp,@family,@generation,@old,@refresh,@new,@key,@identity,@seconds,@interval)
                """, operation.Connection, operation.Transaction);
            command.Parameters.AddWithValue("account", session.accountId);
            command.Parameters.AddWithValue("stamp", session.accountSecurityStamp);
            command.Parameters.AddWithValue("family", session.familyId);
            command.Parameters.AddWithValue("generation", session.generation);
            command.Parameters.AddWithValue("old", snapshot.AccessTokenHash);
            command.Parameters.AddWithValue("refresh", refreshHash);
            command.Parameters.AddWithValue("new", newHash);
            command.Parameters.Add("key", NpgsqlDbType.Bytea).Value = newKey;
            command.Parameters.AddWithValue("identity", newIdentity);
            command.Parameters.AddWithValue("seconds", accessSeconds);
            command.Parameters.AddWithValue("interval", minimumInterval);
            RefreshSessionResult result;
            await using (var reader = await command.ExecuteReaderAsync(operation.CancellationToken))
            {
                if (!await reader.ReadAsync(operation.CancellationToken))
                    throw DependencyUnavailableException.InvalidResponse("refresh_session");
                result = new(reader.GetBoolean(0), reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetFieldValue<Instant>(2),
                    reader.IsDBNull(3) ? null : reader.GetFieldValue<Instant>(3),
                    reader.IsDBNull(4) ? null : reader.GetFieldValue<Instant>(4),
                    reader.GetBoolean(0) ? treehammock.DataLayer.Entitlements.EntitlementProjection.Parse(reader.GetString(5), session.accountId) : null);
            }
            await operation.CommitAsync(result);
            return result;
        }
        catch (SecurityOperationException) { throw; }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { throw; }
        catch (Exception ex) { throw DependencyUnavailableException.Database("refresh_session", DependencyStage.Execute, ex); }
    }
}
