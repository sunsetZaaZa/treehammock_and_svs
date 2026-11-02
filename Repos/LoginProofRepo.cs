using NodaTime;
using Npgsql;
using NpgsqlTypes;
using treehammock.DataLayer.Cache;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Database;
using treehammock.Rigging.Dependencies;

namespace treehammock.Repos;

public sealed record LoginProofTransition(bool Result, string Code, TwoFactorSession? Snapshot = null);
public interface ILoginProofRepo
{
    Task<TwoFactorSession?> LoadAsync(string hash, CancellationToken cancellation);
    Task<LoginProofTransition> BeginAsync(string hash, TwoFactorSession snapshot, CancellationToken cancellation);
    Task<LoginProofTransition> IssueAsync(string hash, TwoFactorSession snapshot, short maxResends, int cooldownSeconds, CancellationToken cancellation);
    Task<LoginProofTransition> CompleteAsync(string hash, TwoFactorSession snapshot, string? codeHash, bool totpVerified, short maxAttempts, CancellationToken cancellation);
    Task<LoginProofTransition> CancelAsync(string hash, TwoFactorSession snapshot, CancellationToken cancellation);
    Task<LoginProofTransition> PromoteAsync(string hash, TwoFactorSession snapshot, string accessHash, ActiveSession active, CancellationToken cancellation);
}

// A snapshot is only a projection. Every command compares its version under
// account authority; SQL owns method order, attempts and proof completion.
public sealed class LoginProofRepo(StorageContext storage) : ILoginProofRepo
{
    public async Task<TwoFactorSession?> LoadAsync(string hash, CancellationToken cancellation)
    {
        try
        {
            await using var connection = await storage.CreateConnection(cancellation);
            await using var command = new NpgsqlCommand("select cor10_login_snapshot(@hash)::text", connection);
            command.Parameters.AddWithValue("hash", hash);
            var value = await command.ExecuteScalarAsync(cancellation);
            return value is string json ? CacheJsonSettings.Deserialize<TwoFactorSession>(json) : null;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { throw; }
        catch (Exception ex) { throw DependencyUnavailableException.Database("cor10_login_snapshot", DependencyStage.Read, ex); }
    }

    public Task<LoginProofTransition> BeginAsync(string hash, TwoFactorSession snapshot, CancellationToken cancellation)
        => Mutate("Begin", "select * from cor10_begin_login(@hash,@snapshot)", hash, snapshot,
            command => command.Parameters.Add("snapshot", NpgsqlDbType.Jsonb).Value = CacheJsonSettings.Serialize(snapshot), cancellation);

    public Task<LoginProofTransition> IssueAsync(string hash, TwoFactorSession snapshot, short maxResends, int cooldownSeconds, CancellationToken cancellation)
        => Mutate("Issue", "select * from cor10_issue_challenge(@hash,@stamp,@version,@configuration,@method,@destination,@verifier,@expires,@limit,@cooldown)", hash, snapshot, command =>
        {
            command.Parameters.AddWithValue("configuration", (short)snapshot.selectedConfiguration.GetValueOrDefault());
            command.Parameters.AddWithValue("method", (short)snapshot.challengedMethod.GetValueOrDefault());
            command.Parameters.AddWithValue("destination", snapshot.chosenDestination ?? (short)0);
            command.Parameters.Add("verifier", NpgsqlDbType.Text).Value = (object?)snapshot.challengeCodeHash ?? DBNull.Value;
            command.Parameters.AddWithValue("expires", snapshot.challengeExpiration ?? snapshot.expiration);
            command.Parameters.AddWithValue("limit", maxResends);
            command.Parameters.AddWithValue("cooldown", cooldownSeconds);
        }, cancellation);

    public Task<LoginProofTransition> CompleteAsync(string hash, TwoFactorSession snapshot, string? codeHash, bool totpVerified, short maxAttempts, CancellationToken cancellation)
        => Mutate("Complete", "select * from cor10_complete_proof(@hash,@stamp,@version,@challenge,@method,@verifier,@totp,@limit)", hash, snapshot, command =>
        {
            command.Parameters.Add("challenge", NpgsqlDbType.Uuid).Value = (object?)snapshot.challengeId ?? DBNull.Value;
            command.Parameters.AddWithValue("method", (short)snapshot.challengedMethod.GetValueOrDefault());
            command.Parameters.Add("verifier", NpgsqlDbType.Text).Value = (object?)codeHash ?? DBNull.Value;
            command.Parameters.AddWithValue("totp", totpVerified);
            command.Parameters.AddWithValue("limit", maxAttempts);
        }, cancellation);

    public Task<LoginProofTransition> CancelAsync(string hash, TwoFactorSession snapshot, CancellationToken cancellation)
        => Mutate("Cancel", "select * from cor10_cancel_challenge(@hash,@stamp,@version,@challenge)", hash, snapshot,
            command => command.Parameters.Add("challenge", NpgsqlDbType.Uuid).Value = (object?)snapshot.challengeId ?? DBNull.Value, cancellation);

    public Task<LoginProofTransition> PromoteAsync(string hash, TwoFactorSession snapshot, string accessHash, ActiveSession active, CancellationToken cancellation)
    {
        bool rotation = !string.IsNullOrWhiteSpace(snapshot.priorActiveAccessTokenHash);
        string arguments = rotation ? "@account,@hash,@stamp,@old," : "@account,@hash,@stamp,";
        string sql = "select result,code,null::text from " + (rotation ? "promote_twofactor_rotation_login(" : "promote_twofactor_new_login(")
            + arguments + "@new,@key,0::smallint,0::smallint,@created,@lifespan,@access,@hard,@cutoff,@features,@identity,@version)";
        return Mutate("Promote", sql, hash, snapshot, command =>
        {
            command.Parameters.AddWithValue("account", snapshot.accountId);
            if (rotation) command.Parameters.AddWithValue("old", snapshot.priorActiveAccessTokenHash!);
            command.Parameters.AddWithValue("new", accessHash);
            command.Parameters.AddWithValue("key", active.refreshToken);
            command.Parameters.AddWithValue("created", active.createdOn);
            command.Parameters.AddWithValue("lifespan", active.sessionLifespan);
            command.Parameters.AddWithValue("access", active.accessExpiration);
            command.Parameters.AddWithValue("hard", active.sessionExpiration);
            command.Parameters.Add("cutoff", NpgsqlDbType.TimestampTz).Value = (object?)active.cutOff ?? DBNull.Value;
            command.Parameters.AddWithValue("features", (short)active.features);
            command.Parameters.AddWithValue("identity", active.securityStamp);
        }, cancellation, active);
    }

    private async Task<LoginProofTransition> Mutate(string purpose, string sql, string hash, TwoFactorSession snapshot,
        Action<NpgsqlCommand> parameters, CancellationToken cancellation, ActiveSession? active = null)
    {
        try
        {
            await using var command = new NpgsqlCommand(sql);
            command.Parameters.AddWithValue("hash", hash);
            command.Parameters.AddWithValue("stamp", snapshot.accountSecurityStamp);
            command.Parameters.AddWithValue("version", snapshot.progressVersion);
            parameters(command);
            var boundInput = command.Parameters.Cast<NpgsqlParameter>().Select(parameter =>
                new { parameter.ParameterName, Value = parameter.Value is DBNull ? null : parameter.Value }).ToArray();
            string binding = treehammock.Rigging.Authorization.AccessTokenHashUtility.Hash(CacheJsonSettings.Serialize(boundInput));
            await using var operation = await storage.SecurityOperations.BeginAsync("LoginProofRepo." + purpose,
                new { binding, snapshot.accountId, snapshot.accountSecurityStamp, snapshot.progressVersion },
                snapshot.accountId, snapshot.accountSecurityStamp, snapshot.progressVersion.ToString(System.Globalization.CultureInfo.InvariantCulture), cancellation);
            command.Connection = operation.Connection;
            command.Transaction = operation.Transaction;
            LoginProofTransition result;
            await using (var reader = await command.ExecuteReaderAsync(operation.CancellationToken))
            {
                if (!await reader.ReadAsync(operation.CancellationToken)) throw DependencyUnavailableException.InvalidResponse("cor10_login_transition");
                result = new(reader.GetBoolean(0), reader.GetString(1), reader.IsDBNull(2) ? null : CacheJsonSettings.Deserialize<TwoFactorSession>(reader.GetString(2)));
            }
            if (result.Result && active is not null)
            {
                active.entitlements = await EntitlementRepo.ReadAsync(operation.Connection, operation.Transaction, active.accountId, operation.CancellationToken);
                active.features = active.entitlements.Features;
            }
            await operation.CommitAsync(result);
            return result;
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { throw; }
        catch (Exception ex) { throw DependencyUnavailableException.Database("cor10_login_" + purpose, DependencyStage.Execute, ex); }
    }
}
