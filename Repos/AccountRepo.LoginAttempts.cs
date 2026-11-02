using NodaTime;
using Npgsql;
using NpgsqlTypes;
using treehammock.DataLayer.Account;
using treehammock.DataLayer.Security;
using treehammock.Rigging.Dependencies;
using treehammock.Rigging.Security;

namespace treehammock.Repos;

public partial class AccountRepo
{
    private static async Task ReadLoginAttemptVersion(NpgsqlConnection connection, NpgsqlTransaction transaction, IntraAccount account, CancellationToken token)
    {
        await using var command = new NpgsqlCommand("select a.login_failures,a.unlock_when,coalesce(v.attempt_version,'00000000-0000-0000-0000-000000000000'::uuid) from accounts a left join account_login_attempt_versions v on v.account_id=a.account_id and v.credential_stamp=a.security_stamp where a.account_id=@id and a.security_stamp=@stamp", connection, transaction);
        command.Parameters.AddWithValue("id", account.accountId); command.Parameters.AddWithValue("stamp", account.accountSecurityStamp);
        await using var reader = await command.ExecuteReaderAsync(token);
        if (!await reader.ReadAsync(token)) throw DependencyUnavailableException.InvalidResponse("login_attempt_snapshot");
        account.loginFailures = reader.GetInt16(0); account.unlockWhen = reader.IsDBNull(1) ? null : reader.GetFieldValue<Instant>(1);
        account.loginAttemptVersion = reader.GetGuid(2);
    }
    public Task<LoginAttemptTransition> RecordLoginFailure(Guid accountId, Guid stamp, int charge, int limit, CancellationToken cancellationToken = default)
        => ChangeLoginAttempts("cor08_record_login_failure", accountId, stamp, new { charge, limit }, command =>
        { command.Parameters.AddWithValue("charge", charge); command.Parameters.AddWithValue("limit", limit); }, cancellationToken);
    public Task<LoginAttemptTransition> ClearLoginAttempts(Guid accountId, Guid stamp, Guid observedVersion, short observedFailures,
        Instant? observedUnlock, bool expiredCleanup, CancellationToken cancellationToken = default)
        => ChangeLoginAttempts("cor08_clear_login_attempts", accountId, stamp, new { observedVersion, observedFailures, observedUnlock, expiredCleanup }, command =>
        {
            command.Parameters.AddWithValue("version", observedVersion); command.Parameters.AddWithValue("failures", observedFailures);
            command.Parameters.Add("unlock", NpgsqlDbType.TimestampTz).Value = (object?)observedUnlock ?? DBNull.Value;
            command.Parameters.AddWithValue("cleanup", expiredCleanup);
        }, cancellationToken);
    private async Task<LoginAttemptTransition> ChangeLoginAttempts(string function, Guid id, Guid stamp, object content, Action<NpgsqlCommand> parameters, CancellationToken token)
    {
        AccountSecurityStampGuard.Require(stamp);
        await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo." + function, new { id, stamp, content }, id, stamp, null, token);
        string arguments = function == "cor08_record_login_failure" ? "@id,@stamp,@charge,@limit" : "@id,@stamp,@version,@failures,@unlock,@cleanup";
        try
        {
            await using var command = new NpgsqlCommand("select * from " + function + "(" + arguments + ")", operation.Connection, operation.Transaction);
            command.Parameters.AddWithValue("id", id); command.Parameters.AddWithValue("stamp", stamp); parameters(command);
            LoginAttemptTransition result;
            await using (var reader = await command.ExecuteReaderAsync(operation.CancellationToken))
            {
                if (!await reader.ReadAsync(operation.CancellationToken)) throw DependencyUnavailableException.InvalidResponse(function);
                result = new(reader.GetBoolean(0), reader.GetString(1), reader.GetInt16(2), reader.IsDBNull(3) ? null : reader.GetFieldValue<Instant>(3), reader.IsDBNull(4) ? Guid.Empty : reader.GetGuid(4));
            }
            await operation.CommitAsync(result); return result;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is NpgsqlException or TimeoutException or OperationCanceledException)
        { throw DependencyUnavailableException.Database(function, DependencyStage.Execute, ex); }
    }
}
