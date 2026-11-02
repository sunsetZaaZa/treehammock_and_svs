using treehammock.Rigging.Dependencies;
using Microsoft.Extensions.Logging;
using NodaTime;
using Npgsql;
using NpgsqlTypes;

using treehammock.Rigging.Database;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Repos;

public sealed record AccountRecoveryLookupResult(
    bool Result,
    string Code,
    Guid? AccountId,
    string? EmailAddress,
    string? PhoneNumber,
    string? PhoneCountryCode,
    Guid? AccountSecurityStamp,
    Instant? UnlockWhen,
    Guid? LockoutAttemptVersion);

public interface IAccountRecoveryRepo
{
    Task<AccountRecoveryLookupResult?> LookupLockedAccount(string identifier, Instant now, CancellationToken cancellationToken = default);
    Task<AccountRecovery_Status?> BeginUnlock(
        Guid accountId,
        string token,
        Instant createdOn,
        Instant expiration,
        AccountRecovery_Status status,
        AccountUnlockDeliveryMethod deliveryMethod,
        Guid accountSecurityStamp,
        Instant lockoutUnlockWhen, Guid lockoutAttemptVersion, CancellationToken cancellationToken = default);

    Task<AccountRecovery_Status?> CancelUnlock(Guid accountId, string token, CancellationToken cancellationToken = default);
    Task<AccountRecovery_Status?> VerifyUnlock(string token, CancellationToken cancellationToken = default);
}

public class AccountRecoveryRepo : IAccountRecoveryRepo
{
    internal const string LookupRecoveryAccountFunction = "lookup_locked_recovery_account";
    internal const string BeginRecoveryProcedure = "start_unlock_account";
    internal const string CancelRecoveryProcedure = "cancel_unlock_account";
    internal const string VerifyRecoveryProcedure = "verify_unlock_account";
    internal const NpgsqlDbType InstantDbType = NpgsqlDbType.TimestampTz;

    private readonly StorageContext _activeDatabase;
    private readonly ILogger<AccountRecoveryRepo> _logger;

    public AccountRecoveryRepo(StorageContext database, ILogger<AccountRecoveryRepo> logger)
    {
        _activeDatabase = database;
        _logger = logger;
    }

    public async Task<AccountRecoveryLookupResult?> LookupLockedAccount(string identifier, Instant now, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = LookupRecoveryAccountFunction;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection(cancellationToken);
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "identifier",
                "now");

            command.Parameters.Add("@identifier", NpgsqlDbType.Text).Value = identifier;
            command.Parameters.Add("@now", InstantDbType).Value = now;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    var result = new AccountRecoveryLookupResult(
                        dr.GetBoolean(0),
                        dr.GetString(1),
                        dr.IsDBNull(2) ? null : dr.GetGuid(2),
                        dr.IsDBNull(3) ? null : dr.GetString(3),
                        dr.IsDBNull(4) ? null : dr.GetString(4),
                        dr.IsDBNull(5) ? null : dr.GetString(5),
                        dr.IsDBNull(6) ? null : dr.GetGuid(6),
                        dr.IsDBNull(7) ? null : dr.GetFieldValue<Instant>(7),
                        dr.IsDBNull(8) ? null : dr.GetGuid(8));

                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await tran.CommitAsync(cancellationToken);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await tran.CommitAsync(cancellationToken);
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.IdentifierLookup(identifier, now), stage: dependencyStage);
            }

            return null;
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(LookupLockedAccount), stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountRecovery_Status?> BeginUnlock(
        Guid accountId,
        string token,
        Instant createdOn,
        Instant expiration,
        AccountRecovery_Status status,
        AccountUnlockDeliveryMethod deliveryMethod,
        Guid accountSecurityStamp,
        Instant lockoutUnlockWhen, Guid lockoutAttemptVersion, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = BeginRecoveryProcedure;

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRecoveryRepo.BeginUnlock", new { accountId, token, createdOn, expiration, status, deliveryMethod, accountSecurityStamp, lockoutUnlockWhen, lockoutAttemptVersion }, accountId, accountSecurityStamp, lockoutAttemptVersion.ToString("D"), cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "tokenHash",
                "createdOn",
                "expiration",
                "status",
                "method",
                "accountSecurityStamp",
                "lockoutUnlockWhen",
                "lockoutAttemptVersion");

            string tokenHash = SecretHashUtility.HashToken(token);

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;
            command.Parameters.Add("@createdOn", InstantDbType).Value = createdOn;
            command.Parameters.Add("@expiration", InstantDbType).Value = expiration;
            command.Parameters.Add("@status", NpgsqlDbType.Smallint).Value = (short)status;
            command.Parameters.Add("@method", NpgsqlDbType.Smallint).Value = (short)deliveryMethod;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@lockoutUnlockWhen", InstantDbType).Value = lockoutUnlockWhen;
            command.Parameters.Add("@lockoutAttemptVersion", NpgsqlDbType.Uuid).Value = lockoutAttemptVersion;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    AccountRecovery_Status result = (AccountRecovery_Status)dr.GetInt16(0);
                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("recovery_mutation");
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(
                    tran,
                    ex,
                    procedure,
                    new { accountId, createdOn, expiration, status, deliveryMethod, accountSecurityStamp, lockoutUnlockWhen }, stage: dependencyStage);
            }

            return null;
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(BeginUnlock), stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountRecovery_Status?> CancelUnlock(Guid accountId, string token, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = CancelRecoveryProcedure;

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRecoveryRepo.CancelUnlock", new { accountId, token }, accountId, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "tokenHash");

            string tokenHash = SecretHashUtility.HashToken(token);
            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    AccountRecovery_Status result = (AccountRecovery_Status)dr.GetInt16(0);
                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("recovery_mutation");
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { accountId }, stage: dependencyStage);
            }

            return null;
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(CancelUnlock), stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountRecovery_Status?> VerifyUnlock(string token, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = VerifyRecoveryProcedure;

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRecoveryRepo.VerifyUnlock", new { token }, null, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "tokenHash");

            string tokenHash = SecretHashUtility.HashToken(token);
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    AccountRecovery_Status result = (AccountRecovery_Status)dr.GetInt16(0);
                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("recovery_mutation");
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.VerificationTokenHashScope(tokenHash), stage: dependencyStage);
            }

            return null;
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(VerifyUnlock), stage: dependencyStage);
            return null;
        }
    }


    private void LogRepositoryFailure(Exception exception, string operation, object? scope = null, DependencyStage stage = DependencyStage.Acquire)
    {
        _logger.LogError(exception, "Repository operation {Operation} failed before a controlled repository result could be returned with scope {@Scope}.", operation, scope);
        throw DependencyUnavailableException.Database(operation, stage, exception);
    }

    private async Task RollbackAndLogAsync(NpgsqlTransaction tran, Exception exception, string procedure, object? scope = null, DependencyStage stage = DependencyStage.Execute)
    {
        try
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await tran.RollbackAsync(cleanup.Token);
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception rollbackException) {
            _logger.LogError(rollbackException, "Rollback failed for repository procedure {Procedure}.", procedure);
        }

        _logger.LogError(exception, "Repository procedure {Procedure} failed with scope {@Scope}.", procedure, scope);
        throw DependencyUnavailableException.Database(procedure ?? "repository_command", stage, exception);
    }
}
