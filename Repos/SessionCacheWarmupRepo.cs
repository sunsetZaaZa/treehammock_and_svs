using Npgsql;
using NpgsqlTypes;
using treehammock.Rigging.Database;

namespace treehammock.Repos;

public interface ISessionCacheWarmupRepo
{
    Task<IReadOnlyList<string>> ReadCandidateHashesAsync(string? afterHash, int limit, CancellationToken cancellationToken);
}

// Uses the existing database connection pool (Yugabyte YSQL or PostgreSQL).
// Only hashes are enumerated; GetSession remains the owner of session projections.
public sealed class SessionCacheWarmupRepo(StorageContext database) : ISessionCacheWarmupRepo
{
    internal const string CandidateSql = """
        select s.access_token_hash
          from sessions s
          join accounts a on a.account_id = s.account_id
         where (@afterHash is null or s.access_token_hash > @afterHash)
           and s.account_security_stamp = a.security_stamp
           and a.verify_status = 1
           and (a.unlock_when is null or a.unlock_when <= clock_timestamp())
           and s.access_expiration > clock_timestamp()
           and s.session_expiration > clock_timestamp()
           and (s.cut_off is null or s.cut_off > clock_timestamp())
           and (a.cut_off is null or a.cut_off > clock_timestamp())
           and s.session_lifespan is not null
           and s.protocol_version = 2
         order by s.access_token_hash
         limit @limit
        """;

    public async Task<IReadOnlyList<string>> ReadCandidateHashesAsync(string? afterHash, int limit, CancellationToken cancellationToken)
    {
        if (limit is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(limit));
        await using var connection = await database.CreateConnection(cancellationToken);
        await using var command = new NpgsqlCommand(CandidateSql, connection);
        command.Parameters.Add("afterHash", NpgsqlDbType.Text).Value = (object?)afterHash ?? DBNull.Value;
        command.Parameters.Add("limit", NpgsqlDbType.Integer).Value = limit;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var hashes = new List<string>(limit);
        while (await reader.ReadAsync(cancellationToken)) hashes.Add(reader.GetString(0));
        return hashes;
    }
}
