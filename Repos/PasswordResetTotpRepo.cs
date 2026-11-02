using treehammock.Services;
using treehammock.Rigging.Dependencies;
using Microsoft.Extensions.Logging;
using NodaTime;
using Npgsql;
using NpgsqlTypes;

using treehammock.Rigging.Database;

namespace treehammock.Repos;

public sealed record PasswordResetTotpEnrollmentRecord(
    Guid AccountId,
    long TwoFactorIndex,
    short Method,
    byte[] TotpSecretCiphertext,
    byte[] TotpSecretNonce,
    byte[] TotpSecretTag,
    int TotpSecretVersion,
    long? TotpLastUsedStep, string? TotpKeyId = null, TotpEnrollmentContext? Context = null, long RowVersion = 0);

public sealed record PasswordResetTotpStepResult(bool Result, string Code);

public interface IPasswordResetTotpRepo
{
    Task<PasswordResetTotpEnrollmentRecord?> GetPasswordResetTotpEnrollmentAsync(
        Guid accountId,
        Instant now,
        CancellationToken cancellationToken);

    Task<PasswordResetTotpStepResult?> MarkPasswordResetTotpStepUsedAsync(
        Guid accountId,
        long twoFactorIndex,
        long timeStep, Guid enrollmentId,
        CancellationToken cancellationToken);
}

public sealed class PasswordResetTotpRepo : IPasswordResetTotpRepo
{
    internal const string GetPasswordResetTotpEnrollmentFunction = "get_password_reset_totp_enrollment";
    internal const string MarkPasswordResetTotpStepUsedFunction = "mark_password_reset_totp_step_used";
    internal const NpgsqlDbType InstantDbType = NpgsqlDbType.TimestampTz;
    internal const NpgsqlDbType ProtectedSecretDbType = NpgsqlDbType.Bytea;

    private readonly StorageContext _activeDatabase;
    private readonly ILogger<PasswordResetTotpRepo> _logger;

    public PasswordResetTotpRepo(StorageContext database, ILogger<PasswordResetTotpRepo> logger)
    {
        _activeDatabase = database;
        _logger = logger;
    }

    public async Task<PasswordResetTotpEnrollmentRecord?> GetPasswordResetTotpEnrollmentAsync(
        Guid accountId,
        Instant now,
        CancellationToken cancellationToken)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        const string procedure = GetPasswordResetTotpEnrollmentFunction;

        try
        {
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection(cancellationToken);
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "now");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@now", InstantDbType).Value = now;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    PasswordResetTotpEnrollmentRecord result = new(
                        dr.GetGuid(0),
                        dr.GetInt64(1),
                        dr.GetInt16(2),
                        dr.GetFieldValue<byte[]>(3),
                        dr.GetFieldValue<byte[]>(4),
                        dr.GetFieldValue<byte[]>(5),
                        dr.GetInt32(6),
                        dr.IsDBNull(7) ? null : dr.GetInt64(7), dr.GetString(8),
                        AuthenticatorAppEnrollmentRepo.ReadContext(dr, 9, accountId), dr.GetInt64(14));

                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await tran.CommitAsync(cancellationToken);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await tran.CommitAsync(cancellationToken);
                return null;
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { accountId }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(GetPasswordResetTotpEnrollmentAsync), new { accountId }, stage: dependencyStage);
            return null;
        }
    }

    public async Task<PasswordResetTotpStepResult?> MarkPasswordResetTotpStepUsedAsync(
        Guid accountId,
        long twoFactorIndex,
        long timeStep, Guid enrollmentId,
        CancellationToken cancellationToken)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        const string procedure = MarkPasswordResetTotpStepUsedFunction;

        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("PasswordResetTotpRepo.MarkPasswordResetTotpStepUsedAsync", new { accountId, twoFactorIndex, timeStep, enrollmentId }, accountId, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "twoFactorIndex",
                "timeStep", "enrollmentId");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@twoFactorIndex", NpgsqlDbType.Bigint).Value = twoFactorIndex;
            command.Parameters.Add("@timeStep", NpgsqlDbType.Bigint).Value = timeStep;
            command.Parameters.Add("@enrollmentId", NpgsqlDbType.Uuid).Value = enrollmentId;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    PasswordResetTotpStepResult result = new(
                        dr.GetBoolean(0),
                        dr.GetString(1));

                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("MarkPasswordResetTotpStepUsedAsync");
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { accountId, twoFactorIndex, timeStep, enrollmentId }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(MarkPasswordResetTotpStepUsedAsync), new { accountId, twoFactorIndex, timeStep, enrollmentId }, stage: dependencyStage);
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
