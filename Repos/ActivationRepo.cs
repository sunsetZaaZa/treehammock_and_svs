using treehammock.Rigging.Dependencies;
using Microsoft.Extensions.Logging;
using NodaTime;
using Npgsql;
using NpgsqlTypes;

using treehammock.DataLayer;
using treehammock.Rigging.Database;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Repos;

public interface IActivationRepo
{
    Task<treehammock.Services.ActivationCreationAdmission> AdmitCreationAsync(Guid accountId, Guid stamp,
        string sessionHash, Guid familyId, Guid grantId, long grantVersion, string proofHash, string email,
        short tier, short term, short cadence, string ipFingerprint,
        treehammock.Rigging.Config.ActivationAbusePolicySettings policy, CancellationToken cancellationToken = default);

    Task<treehammock.Models.Activation.ActivationLifecycleResult> TransitionAsync(Guid accountId, Guid stamp,
        string sessionHash, Guid familyId, Guid grantId, long grantVersion, Guid requestId,
        string? proofHash, string action, CancellationToken cancellationToken = default);

    Task<ActivationCommandResult?> PlaceActivation(
        Guid accountId,
        Guid accountSecurityStamp,
        string emailAddress,
        string code,
        Instant createdOn,
        DayDuration term,
        DurationRepeat interval,
        Instant closeOff,
        FeatureSet featureSet,
        PlatformBacker platformBacker,
        string platformText,
        ActivationStatus status,
        Period? delayedStart, CancellationToken cancellationToken = default);

    Task<ActivationCommandResult?> CancelActivationRequest(Guid accountId, Guid accountSecurityStamp, string code, Instant cancelledOn, CancellationToken cancellationToken = default);
    Task<ActivationCommandResult?> DisableActivation(Guid accountId, Guid accountSecurityStamp, string emailAddress, Instant createdOn, Instant closeOff, ActivationStatus status, CancellationToken cancellationToken = default);
    Task<ActivationVerifyCommandResult?> VerifyActivation(Guid accountId, Guid accountSecurityStamp, string emailAddress, string code, Instant createdOn, ushort position, ushort upperLimit, CancellationToken cancellationToken = default);
}

public class ActivationRepo : IActivationRepo
{
    internal const string PlaceActivationProcedure = "place_activation";
    internal const string CancelActivationRequestProcedure = "cancel_activation_request";
    internal const string DisableActivationProcedure = "disable_activation";
    internal const string VerifyActivationProcedure = "verify_activation";
    internal const NpgsqlDbType InstantDbType = NpgsqlDbType.TimestampTz;

    private readonly StorageContext _activeDatabase;
    private readonly ILogger<ActivationRepo> _logger;

    public ActivationRepo(StorageContext database, ILogger<ActivationRepo> logger)
    {
        _activeDatabase = database;
        _logger = logger;
    }

    public async Task<ActivationCommandResult?> PlaceActivation(
        Guid accountId,
        Guid accountSecurityStamp,
        string emailAddress,
        string code,
        Instant createdOn,
        DayDuration term,
        DurationRepeat interval,
        Instant closeOff,
        FeatureSet featureSet,
        PlatformBacker platformBacker,
        string platformText,
        ActivationStatus status,
        Period? delayedStart, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = PlaceActivationProcedure;

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("ActivationRepo.PlaceActivation", new { accountId, accountSecurityStamp, emailAddress, code, createdOn, term, interval, closeOff, featureSet, platformBacker, platformText, status, delayedStart }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "emailAddress",
                "code",
                "createdOn",
                "term",
                "interval",
                "closeOff",
                "featureSet",
                "platformBacker",
                "platformText",
                "status",
                "delayedStart");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = emailAddress;
            command.Parameters.Add("@code", NpgsqlDbType.Text).Value = code;
            command.Parameters.Add("@createdOn", InstantDbType).Value = createdOn;
            command.Parameters.Add("@term", NpgsqlDbType.Smallint).Value = (short)term;
            command.Parameters.Add("@interval", NpgsqlDbType.Smallint).Value = (short)interval;
            command.Parameters.Add("@closeOff", InstantDbType).Value = closeOff;
            command.Parameters.Add("@featureSet", NpgsqlDbType.Smallint).Value = (short)featureSet;
            command.Parameters.Add("@platformBacker", NpgsqlDbType.Smallint).Value = (short)platformBacker;
            command.Parameters.Add("@platformText", NpgsqlDbType.Text).Value = platformText;
            command.Parameters.Add("@status", NpgsqlDbType.Smallint).Value = (short)status;
            command.Parameters.Add("@delayedStart", NpgsqlDbType.Interval).Value = DbValue(delayedStart);

            try
            {
                dependencyStage = DependencyStage.Execute;
                ActivationCommandResult? result;
                // Materialize while the reader is owned; receipt and commit run after disposal.
                await using (NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken))
                {
                    dependencyStage = DependencyStage.Read;
                    result = await ReadActivationCommandResultAsync(dr, cancellationToken: cancellationToken);
                }
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.ActivationEmail(accountId, emailAddress, createdOn, closeOff, status), stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(PlaceActivation), stage: dependencyStage);
            return null;
        }
    }

    public async Task<ActivationCommandResult?> CancelActivationRequest(Guid accountId, Guid accountSecurityStamp, string code, Instant cancelledOn, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = CancelActivationRequestProcedure;

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("ActivationRepo.CancelActivationRequest", new { accountId, accountSecurityStamp, code, cancelledOn }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "code",
                "cancelledOn");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@code", NpgsqlDbType.Text).Value = code;
            command.Parameters.Add("@cancelledOn", InstantDbType).Value = cancelledOn;

            try
            {
                dependencyStage = DependencyStage.Execute;
                ActivationCommandResult? result;
                // Materialize while the reader is owned; receipt and commit run after disposal.
                await using (NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken))
                {
                    dependencyStage = DependencyStage.Read;
                    result = await ReadActivationCommandResultAsync(dr, cancellationToken: cancellationToken);
                }
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, procedure, new { accountId }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(CancelActivationRequest), stage: dependencyStage);
            return null;
        }
    }

    public async Task<ActivationCommandResult?> DisableActivation(Guid accountId, Guid accountSecurityStamp, string emailAddress, Instant createdOn, Instant closeOff, ActivationStatus status, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = DisableActivationProcedure;

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("ActivationRepo.DisableActivation", new { accountId, accountSecurityStamp, emailAddress, createdOn, closeOff, status }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "emailAddress",
                "createdOn",
                "closeOff",
                "status");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = emailAddress;
            command.Parameters.Add("@createdOn", InstantDbType).Value = createdOn;
            command.Parameters.Add("@closeOff", InstantDbType).Value = closeOff;
            command.Parameters.Add("@status", NpgsqlDbType.Smallint).Value = (short)status;

            try
            {
                dependencyStage = DependencyStage.Execute;
                ActivationCommandResult? result;
                // Materialize while the reader is owned; receipt and commit run after disposal.
                await using (NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken))
                {
                    dependencyStage = DependencyStage.Read;
                    result = await ReadActivationCommandResultAsync(dr, cancellationToken: cancellationToken);
                }
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.ActivationEmail(accountId, emailAddress, createdOn, closeOff, status), stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(DisableActivation), stage: dependencyStage);
            return null;
        }
    }

    public async Task<ActivationVerifyCommandResult?> VerifyActivation(Guid accountId, Guid accountSecurityStamp, string emailAddress, string code, Instant createdOn, ushort position, ushort upperLimit, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = VerifyActivationProcedure;

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("ActivationRepo.VerifyActivation", new { accountId, accountSecurityStamp, emailAddress, code, createdOn, position, upperLimit }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "emailAddress",
                "code",
                "createdOn",
                "position",
                "upperLimit");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = emailAddress;
            command.Parameters.Add("@code", NpgsqlDbType.Text).Value = code;
            command.Parameters.Add("@createdOn", InstantDbType).Value = createdOn;
            command.Parameters.Add("@position", NpgsqlDbType.Smallint).Value = (short)position;
            command.Parameters.Add("@upperLimit", NpgsqlDbType.Smallint).Value = (short)upperLimit;

            try
            {
                dependencyStage = DependencyStage.Execute;
                ActivationVerifyCommandResult? result;
                // Materialize while the reader is owned; receipt and commit run after disposal.
                await using (NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken))
                {
                    dependencyStage = DependencyStage.Read;
                    result = await ReadActivationVerifyCommandResultAsync(dr, cancellationToken: cancellationToken);
                }
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.ActivationVerificationEmail(accountId, emailAddress, position, upperLimit), stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(VerifyActivation), stage: dependencyStage);
            return null;
        }
    }

    public async Task<treehammock.Services.ActivationCreationAdmission> AdmitCreationAsync(Guid accountId, Guid stamp,
        string sessionHash, Guid familyId, Guid grantId, long grantVersion, string proofHash, string email,
        short tier, short term, short cadence, string ipFingerprint,
        treehammock.Rigging.Config.ActivationAbusePolicySettings policy, CancellationToken cancellationToken = default)
    {
        await using var op = await _activeDatabase.SecurityOperations.BeginAsync("ActivationRepo.AdmitCreation",
            new { accountId, stamp, sessionHash, familyId, grantId, grantVersion, proofHash, email, tier, term, cadence, ipFingerprint, policy },
            accountId, stamp, grantVersion.ToString(System.Globalization.CultureInfo.InvariantCulture), cancellationToken);
        await using var cmd = new NpgsqlCommand("select * from cor21_admit_creation(@account,@stamp,@session,@family,@grant,@version,@hash,@email,@tier,@term,@cadence,@ip,@accountMax,@identifierMax,@ipMax,@window,@cooldown)", op.Connection, op.Transaction);
        cmd.Parameters.AddWithValue("account", accountId); cmd.Parameters.AddWithValue("stamp", stamp);
        cmd.Parameters.AddWithValue("session", sessionHash); cmd.Parameters.AddWithValue("family", familyId);
        cmd.Parameters.AddWithValue("grant", grantId); cmd.Parameters.AddWithValue("version", grantVersion);
        cmd.Parameters.AddWithValue("hash", proofHash); cmd.Parameters.AddWithValue("email", email);
        cmd.Parameters.AddWithValue("tier", tier); cmd.Parameters.AddWithValue("term", term); cmd.Parameters.AddWithValue("cadence", cadence);
        cmd.Parameters.AddWithValue("ip", ipFingerprint); cmd.Parameters.AddWithValue("accountMax", policy.MaxCreateRequestsPerAccount);
        cmd.Parameters.AddWithValue("identifierMax", policy.MaxCreateRequestsPerIdentifier); cmd.Parameters.AddWithValue("ipMax", policy.MaxCreateRequestsPerIp);
        cmd.Parameters.AddWithValue("window", policy.CreateWindowSeconds); cmd.Parameters.AddWithValue("cooldown", policy.CreateCooldownSeconds);
        try
        {
            treehammock.Services.ActivationCreationAdmission result;
            await using (var reader = await cmd.ExecuteReaderAsync(op.CancellationToken))
            {
                if (!await reader.ReadAsync(op.CancellationToken)) throw DependencyUnavailableException.InvalidResponse("activation_creation_admission");
                result = new(reader.GetBoolean(0), reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetGuid(2), reader.IsDBNull(3) ? null : reader.GetInt32(3));
            }
            await op.CommitAsync(result);
            return result;
        }
        catch (OperationCanceledException) when (op.CancellationToken.IsCancellationRequested) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex) { throw DependencyUnavailableException.Database("activation_creation_admission", DependencyStage.Execute, ex); }
    }

    public async Task<treehammock.Models.Activation.ActivationLifecycleResult> TransitionAsync(
        Guid accountId, Guid stamp, string sessionHash, Guid familyId, Guid grantId, long grantVersion,
        Guid requestId, string? proofHash, string action, CancellationToken cancellationToken = default)
    {
        await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("ActivationRepo.Transition",
            new { accountId, stamp, sessionHash, familyId, grantId, grantVersion, requestId, proofHash, action },
            accountId, stamp, grantVersion.ToString(System.Globalization.CultureInfo.InvariantCulture), cancellationToken);
        await using var cmd = RepositoryCommands.CreateFunctionCommand("cor19_transition_activation",
            operation.Connection, operation.Transaction, "account", "stamp", "session", "family", "grant", "version", "request", "hash", "action");
        cmd.Parameters.AddWithValue("account", accountId);
        cmd.Parameters.AddWithValue("stamp", stamp);
        cmd.Parameters.AddWithValue("session", sessionHash);
        cmd.Parameters.AddWithValue("family", familyId);
        cmd.Parameters.AddWithValue("grant", grantId);
        cmd.Parameters.AddWithValue("version", grantVersion);
        cmd.Parameters.AddWithValue("request", requestId);
        cmd.Parameters.Add("hash", NpgsqlDbType.Text).Value = (object?)proofHash ?? DBNull.Value;
        cmd.Parameters.AddWithValue("action", action);
        try
        {
            treehammock.Models.Activation.ActivationLifecycleResult result;
            await using (var reader = await cmd.ExecuteReaderAsync(operation.CancellationToken))
            {
                if (!await reader.ReadAsync(operation.CancellationToken))
                    throw DependencyUnavailableException.InvalidResponse("cor19_transition_activation");
                result = new treehammock.Models.Activation.ActivationLifecycleResult(reader.GetBoolean(0), reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetInt64(2), reader.IsDBNull(3) ? null : reader.GetFieldValue<Instant>(3),
                    reader.IsDBNull(4) ? null : reader.GetFieldValue<Instant>(4), reader.IsDBNull(5) ? null : treehammock.DataLayer.Entitlements.EntitlementProjection.Parse(reader.GetString(5), accountId),
                    reader.IsDBNull(6) ? null : reader.GetInt16(6), reader.IsDBNull(7) ? null : reader.GetInt16(7), reader.IsDBNull(8) ? null : reader.GetInt16(8));
            }
            await operation.CommitAsync(result);
            return result;
        }
        catch (OperationCanceledException) when (operation.CancellationToken.IsCancellationRequested) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception ex) { throw DependencyUnavailableException.Database("cor19_transition_activation", DependencyStage.Execute, ex); }
    }

    internal static object DbValue(object? value)
    {
        return value ?? DBNull.Value;
    }

    private static async Task<ActivationCommandResult?> ReadActivationCommandResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("ReadActivationCommandResultAsync");
        }

        ActivationStatus? status = dr.IsDBNull(2) ? null : (ActivationStatus)dr.GetInt16(2);
        return new ActivationCommandResult(dr.GetBoolean(0), dr.GetString(1), status);
    }

    private static async Task<ActivationVerifyCommandResult?> ReadActivationVerifyCommandResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("ReadActivationVerifyCommandResultAsync");
        }

        bool result = dr.GetBoolean(0);
        string code = dr.GetString(1);
        ActivationQuery? activation = null;

        if (result)
        {
            activation = new ActivationQuery(
                (FeatureSet)dr.GetInt16(2),
                dr.GetFieldValue<Instant>(3),
                (DayDuration)dr.GetInt16(4),
                (DurationRepeat)dr.GetInt16(5));
        }

        return new ActivationVerifyCommandResult(result, code, activation);
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
