using treehammock.Rigging.Dependencies;
using System.Net;

using Microsoft.Extensions.Logging;
using NodaTime;
using Npgsql;
using NpgsqlTypes;

using treehammock.DataLayer.Cache;
using treehammock.Rigging.Database;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Repos;


internal sealed record PasswordResetIdentifierLogScope(string IdentifierKind, int IdentifierLength)
{
    public static PasswordResetIdentifierLogScope From(string? identifier)
    {
        string trimmed = identifier?.Trim() ?? string.Empty;

        if (trimmed.Length == 0)
        {
            return new PasswordResetIdentifierLogScope("blank", 0);
        }

        if (trimmed.Contains('@', StringComparison.Ordinal))
        {
            return new PasswordResetIdentifierLogScope("email", trimmed.Length);
        }

        bool containsDigit = false;
        bool phoneLike = true;

        foreach (char ch in trimmed)
        {
            if (char.IsDigit(ch))
            {
                containsDigit = true;
                continue;
            }

            if (ch is '+' or '-' or '(' or ')' or ' ' or '.')
            {
                continue;
            }

            phoneLike = false;
            break;
        }

        return phoneLike && containsDigit
            ? new PasswordResetIdentifierLogScope("phone", trimmed.Length)
            : new PasswordResetIdentifierLogScope("username", trimmed.Length);
    }
}

public sealed record PasswordResetAccountLookupResult(
    bool Result,
    string Code,
    Guid? AccountId,
    string? EmailAddress,
    string? PhoneNumber,
    string? PhoneCountryCode,
    Guid? AccountSecurityStamp,
    bool EmailVerified,
    bool SmsVerified,
    bool AuthenticatorVerified);

public sealed record CreatePasswordResetRequestDbCommand(
    Guid PasswordResetRequestId,
    Guid AccountId,
    string Method,
    string? DeliveryChannel,
    string? KeyCodeHash,
    int? KeyCodeHashVersion,
    string DestinationFingerprint,
    string DestinationMasked,
    bool RequiresKeyCode,
    bool RequiresTotp,
    Instant ExpiresAt,
    int MaxAttempts,
    string? RequestedByIp,
    string? RequestedByUserAgent,
    Guid AccountSecurityStampAtRequest);

public sealed record CreatePasswordResetRequestDbResult(
    bool Result,
    string Code,
    Guid? PasswordResetRequestId,
    Guid? AccountId,
    Instant? ExpiresAt);

public sealed record PasswordResetFinalizeRecord(
    bool Result,
    string Code,
    Guid? PasswordResetRequestId,
    Guid? AccountId,
    string? Method,
    string? DeliveryChannel,
    string? KeyCodeHash,
    int? KeyCodeHashVersion,
    bool? RequiresKeyCode,
    bool? RequiresTotp,
    Instant? ExpiresAt,
    Instant? ConsumedAt,
    Instant? CancelledAt,
    int? AttemptCount,
    int? MaxAttempts,
    Guid? AccountSecurityStampAtRequest,
    bool? EmailVerified = null,
    bool? SmsVerified = null,
    bool? AuthenticatorVerified = null,
    string? CurrentEmailAddress = null,
    string? CurrentPhoneNumber = null,
    string? CurrentPhoneCountryCode = null);

public sealed record RegisterPasswordResetFailedAttemptResult(
    bool Result,
    string Code,
    Guid? AccountId,
    int? AttemptCount,
    int? MaxAttempts,
    Instant? CancelledAt);

public sealed record PromotePasswordResetDbCommand(
    Guid PasswordResetRequestId,
    Guid AccountId,
    byte[] HashedPassword,
    byte[] SaltOne,
    byte[] Siv,
    byte[] Nonce,
    Guid NewSecurityStamp,
    Instant PromotedAt,
    string? ResetAccessTokenHash = null,
    long ExpectedSessionVersion = 0,
    long ExpectedChallengeVersion = 0);

public sealed record PromotePasswordResetResult(
    bool Result,
    string Code,
    Guid? AccountId,
    Guid? AccountSecurityStamp,
    Instant? ConsumedAt);

public sealed record PasswordResetRateLimitDbCommand(
    string RateLimitKey,
    Instant Now,
    Period RequestWindow,
    int RequestLimit,
    Period RequestCooldown,
    Period BlockPeriod);

public sealed record PasswordResetRateLimitResult(
    bool Result,
    string Code,
    int? RequestCount,
    Instant? BlockedUntil,
    int? RetryAfterSeconds);

public sealed record CancelPasswordResetRequestResult(
    bool Result,
    string Code,
    Guid? AccountId,
    Instant? CancelledAt);

public sealed record PasswordResetCleanupResult(
    bool Result,
    string Code,
    int CancelledCount,
    int DeletedCount);

public sealed record PasswordResetRateLimitCleanupResult(
    bool Result,
    string Code,
    int DeletedCount);

public sealed record PasswordResetSessionCommandResult(
    bool Result,
    string Code);


public interface IPasswordResetRepo
{
    Task<PasswordResetAccountLookupResult?> LookupPasswordResetAccountAsync(
        string identifier,
        Instant now,
        CancellationToken cancellationToken);

    Task<CreatePasswordResetRequestDbResult?> CreatePasswordResetRequestAsync(
        CreatePasswordResetRequestDbCommand command,
        CancellationToken cancellationToken);

    Task<PasswordResetFinalizeRecord?> GetPasswordResetRequestForFinalizeAsync(
        Guid resetId,
        CancellationToken cancellationToken);

    Task<RegisterPasswordResetFailedAttemptResult?> RegisterFailedAttemptAsync(
        Guid resetId,
        Instant failedAt,
        CancellationToken cancellationToken);

    Task<PromotePasswordResetResult?> PromotePasswordResetAsync(
        PromotePasswordResetDbCommand command,
        CancellationToken cancellationToken);

    Task<CancelPasswordResetRequestResult?> CancelPasswordResetRequestAsync(
        Guid resetId,
        Instant cancelledAt,
        string reasonCode,
        CancellationToken cancellationToken);

    Task<PasswordResetSession?> GetPendingPasswordResetSessionAsync(
        string resetAccessTokenHash,
        CancellationToken cancellationToken);

    Task<PasswordResetSessionCommandResult?> TransitionPendingPasswordResetSessionAsync(
        PasswordResetSession session,
        CancellationToken cancellationToken);

    Task<PasswordResetSessionCommandResult?> RevokePendingPasswordResetSessionAsync(
        string resetAccessTokenHash,
        Instant revokedAt,
        string reasonCode,
        CancellationToken cancellationToken, long expectedSessionVersion = 0, long expectedChallengeVersion = 0);

    Task<PasswordResetRateLimitResult?> RegisterRequestRateLimitAsync(
        PasswordResetRateLimitDbCommand command,
        CancellationToken cancellationToken);

    Task<PasswordResetCleanupResult?> CleanupExpiredPasswordResetRequestsAsync(
        Instant now,
        Period retention,
        CancellationToken cancellationToken);

    Task<PasswordResetRateLimitCleanupResult?> CleanupPasswordResetRateLimitsAsync(
        Instant now,
        Period retention,
        CancellationToken cancellationToken);
}

public sealed class PasswordResetRepo : IPasswordResetRepo
{
    internal const string LookupPasswordResetAccountFunction = "lookup_password_reset_account";
    internal const string CreatePasswordResetRequestFunction = "create_password_reset_request";
    internal const string GetPasswordResetRequestForFinalizeFunction = "get_password_reset_request_for_finalize";
    internal const string RegisterPasswordResetFailedAttemptFunction = "register_password_reset_failed_attempt";
    internal const string PromotePasswordResetFunction = "promote_password_reset";
    internal const string CancelPasswordResetRequestFunction = "cancel_password_reset_request";
    internal const string GetPendingPasswordResetSessionFunction = "get_pending_password_reset_session";
    internal const string TransitionPendingPasswordResetSessionFunction = "transition_pending_password_reset_session";
    internal const string RevokePendingPasswordResetSessionFunction = "revoke_pending_password_reset_session";
    internal const string RegisterPasswordResetRequestRateLimitFunction = "register_password_reset_request_rate_limit";
    internal const string CleanupExpiredPasswordResetRequestsFunction = "cleanup_expired_password_reset_requests";
    internal const string CleanupPasswordResetRateLimitsFunction = "cleanup_password_reset_rate_limits";

    internal const NpgsqlDbType InstantDbType = NpgsqlDbType.TimestampTz;
    internal const NpgsqlDbType PeriodDbType = NpgsqlDbType.Interval;
    internal const NpgsqlDbType PasswordMaterialDbType = NpgsqlDbType.Bytea;

    private readonly StorageContext _activeDatabase;
    private readonly ILogger<PasswordResetRepo> _logger;

    public PasswordResetRepo(StorageContext database, ILogger<PasswordResetRepo> logger)
    {
        _activeDatabase = database;
        _logger = logger;
    }

    public async Task<PasswordResetAccountLookupResult?> LookupPasswordResetAccountAsync(
        string identifier,
        Instant now,
        CancellationToken cancellationToken)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        const string procedure = LookupPasswordResetAccountFunction;

        try
        {
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
                    PasswordResetAccountLookupResult result = new(
                        dr.GetBoolean(0),
                        dr.GetString(1),
                        dr.IsDBNull(2) ? null : dr.GetGuid(2),
                        dr.IsDBNull(3) ? null : dr.GetString(3),
                        dr.IsDBNull(4) ? null : dr.GetString(4),
                        dr.IsDBNull(5) ? null : dr.GetString(5),
                        dr.IsDBNull(6) ? null : dr.GetGuid(6),
                        !dr.IsDBNull(7) && dr.GetBoolean(7),
                        !dr.IsDBNull(8) && dr.GetBoolean(8),
                        !dr.IsDBNull(9) && dr.GetBoolean(9));

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
                await RollbackAndLogAsync(tran, ex, procedure, PasswordResetIdentifierLogScope.From(identifier), stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(LookupPasswordResetAccountAsync), PasswordResetIdentifierLogScope.From(identifier), stage: dependencyStage);
            return null;
        }
    }

    public async Task<CreatePasswordResetRequestDbResult?> CreatePasswordResetRequestAsync(
        CreatePasswordResetRequestDbCommand resetCommand,
        CancellationToken cancellationToken)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        ArgumentNullException.ThrowIfNull(resetCommand);

        const string procedure = CreatePasswordResetRequestFunction;

        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("PasswordResetRepo.CreatePasswordResetRequestAsync", new { resetCommand }, resetCommand.AccountId, resetCommand.AccountSecurityStampAtRequest, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "passwordResetRequestId",
                "accountId",
                "method",
                "deliveryChannel",
                "keyCodeHash",
                "keyCodeHashVersion",
                "destinationFingerprint",
                "destinationMasked",
                "requiresKeyCode",
                "requiresTotp",
                "expiresAt",
                "maxAttempts",
                "requestedByIp",
                "requestedByUserAgent",
                "accountSecurityStampAtRequest");

            command.Parameters.Add("@passwordResetRequestId", NpgsqlDbType.Uuid).Value = resetCommand.PasswordResetRequestId;
            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = resetCommand.AccountId;
            command.Parameters.Add("@method", NpgsqlDbType.Text).Value = resetCommand.Method;
            command.Parameters.Add("@deliveryChannel", NpgsqlDbType.Text).Value = DbValue(resetCommand.DeliveryChannel);
            command.Parameters.Add("@keyCodeHash", NpgsqlDbType.Text).Value = DbValue(resetCommand.KeyCodeHash);
            command.Parameters.Add("@keyCodeHashVersion", NpgsqlDbType.Integer).Value = resetCommand.KeyCodeHashVersion is null ? DBNull.Value : resetCommand.KeyCodeHashVersion.Value;
            command.Parameters.Add("@destinationFingerprint", NpgsqlDbType.Text).Value = resetCommand.DestinationFingerprint;
            command.Parameters.Add("@destinationMasked", NpgsqlDbType.Text).Value = resetCommand.DestinationMasked;
            command.Parameters.Add("@requiresKeyCode", NpgsqlDbType.Boolean).Value = resetCommand.RequiresKeyCode;
            command.Parameters.Add("@requiresTotp", NpgsqlDbType.Boolean).Value = resetCommand.RequiresTotp;
            command.Parameters.Add("@expiresAt", InstantDbType).Value = resetCommand.ExpiresAt;
            command.Parameters.Add("@maxAttempts", NpgsqlDbType.Integer).Value = resetCommand.MaxAttempts;
            command.Parameters.Add("@requestedByIp", NpgsqlDbType.Inet).Value = InetDbValue(resetCommand.RequestedByIp);
            command.Parameters.Add("@requestedByUserAgent", NpgsqlDbType.Text).Value = DbValue(resetCommand.RequestedByUserAgent);
            command.Parameters.Add("@accountSecurityStampAtRequest", NpgsqlDbType.Uuid).Value = resetCommand.AccountSecurityStampAtRequest;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    CreatePasswordResetRequestDbResult result = new(
                        dr.GetBoolean(0),
                        dr.GetString(1),
                        dr.IsDBNull(2) ? null : dr.GetGuid(2),
                        dr.IsDBNull(3) ? null : dr.GetGuid(3),
                        dr.IsDBNull(4) ? null : dr.GetFieldValue<Instant>(4));

                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("CreatePasswordResetRequestAsync");
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { resetCommand.AccountId, resetCommand.Method, resetCommand.DeliveryChannel, resetCommand.RequiresKeyCode, resetCommand.RequiresTotp }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(CreatePasswordResetRequestAsync), stage: dependencyStage);
            return null;
        }
    }

    public async Task<PasswordResetFinalizeRecord?> GetPasswordResetRequestForFinalizeAsync(
        Guid resetId,
        CancellationToken cancellationToken)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        const string procedure = GetPasswordResetRequestForFinalizeFunction;

        try
        {
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection(cancellationToken);
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "passwordResetRequestId");

            command.Parameters.Add("@passwordResetRequestId", NpgsqlDbType.Uuid).Value = resetId;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    PasswordResetFinalizeRecord result = new(
                        dr.GetBoolean(0),
                        dr.GetString(1),
                        dr.IsDBNull(2) ? null : dr.GetGuid(2),
                        dr.IsDBNull(3) ? null : dr.GetGuid(3),
                        dr.IsDBNull(4) ? null : dr.GetString(4),
                        dr.IsDBNull(5) ? null : dr.GetString(5),
                        dr.IsDBNull(6) ? null : dr.GetString(6),
                        dr.IsDBNull(7) ? null : dr.GetInt32(7),
                        dr.IsDBNull(8) ? null : dr.GetBoolean(8),
                        dr.IsDBNull(9) ? null : dr.GetBoolean(9),
                        dr.IsDBNull(10) ? null : dr.GetFieldValue<Instant>(10),
                        dr.IsDBNull(11) ? null : dr.GetFieldValue<Instant>(11),
                        dr.IsDBNull(12) ? null : dr.GetFieldValue<Instant>(12),
                        dr.IsDBNull(13) ? null : dr.GetInt32(13),
                        dr.IsDBNull(14) ? null : dr.GetInt32(14),
                        dr.IsDBNull(15) ? null : dr.GetGuid(15),
                        dr.IsDBNull(16) ? null : dr.GetBoolean(16),
                        dr.IsDBNull(17) ? null : dr.GetBoolean(17),
                        dr.IsDBNull(18) ? null : dr.GetBoolean(18),
                        dr.IsDBNull(19) ? null : dr.GetString(19),
                        dr.IsDBNull(20) ? null : dr.GetString(20),
                        dr.IsDBNull(21) ? null : dr.GetString(21));

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
                await RollbackAndLogAsync(tran, ex, procedure, new { ResetScope = "password_reset_finalize" }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(GetPasswordResetRequestForFinalizeAsync), stage: dependencyStage);
            return null;
        }
    }

    public async Task<RegisterPasswordResetFailedAttemptResult?> RegisterFailedAttemptAsync(
        Guid resetId,
        Instant failedAt,
        CancellationToken cancellationToken)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        const string procedure = RegisterPasswordResetFailedAttemptFunction;

        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("PasswordResetRepo.RegisterFailedAttemptAsync", new { resetId, failedAt }, null, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "passwordResetRequestId",
                "failedAt");

            command.Parameters.Add("@passwordResetRequestId", NpgsqlDbType.Uuid).Value = resetId;
            command.Parameters.Add("@failedAt", InstantDbType).Value = failedAt;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    RegisterPasswordResetFailedAttemptResult result = new(
                        dr.GetBoolean(0),
                        dr.GetString(1),
                        dr.IsDBNull(2) ? null : dr.GetGuid(2),
                        dr.IsDBNull(3) ? null : dr.GetInt32(3),
                        dr.IsDBNull(4) ? null : dr.GetInt32(4),
                        dr.IsDBNull(5) ? null : dr.GetFieldValue<Instant>(5));

                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("RegisterFailedAttemptAsync");
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { failedAt }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(RegisterFailedAttemptAsync), stage: dependencyStage);
            return null;
        }
    }

    public async Task<PromotePasswordResetResult?> PromotePasswordResetAsync(
        PromotePasswordResetDbCommand promotion,
        CancellationToken cancellationToken)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        ArgumentNullException.ThrowIfNull(promotion);

        const string procedure = PromotePasswordResetFunction;

        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("PasswordResetRepo.PromotePasswordResetAsync", new { promotion }, promotion.AccountId, null, promotion.PasswordResetRequestId.ToString("N"), cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "passwordResetRequestId",
                "accountId",
                "hashedPassword",
                "saltOne",
                "siv",
                "nonce",
                "newSecurityStamp",
                "promotedAt", "resetAccessTokenHash", "expectedSessionVersion", "expectedChallengeVersion");

            command.Parameters.Add("@passwordResetRequestId", NpgsqlDbType.Uuid).Value = promotion.PasswordResetRequestId;
            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = promotion.AccountId;
            command.Parameters.Add("@hashedPassword", PasswordMaterialDbType).Value = promotion.HashedPassword;
            command.Parameters.Add("@saltOne", PasswordMaterialDbType).Value = promotion.SaltOne;
            command.Parameters.Add("@siv", PasswordMaterialDbType).Value = promotion.Siv;
            command.Parameters.Add("@nonce", PasswordMaterialDbType).Value = promotion.Nonce;
            command.Parameters.Add("@newSecurityStamp", NpgsqlDbType.Uuid).Value = promotion.NewSecurityStamp;
            command.Parameters.Add("@promotedAt", InstantDbType).Value = promotion.PromotedAt;
            command.Parameters.Add("@resetAccessTokenHash", NpgsqlDbType.Text).Value = DbValue(promotion.ResetAccessTokenHash);
            command.Parameters.Add("@expectedSessionVersion", NpgsqlDbType.Bigint).Value = promotion.ExpectedSessionVersion;
            command.Parameters.Add("@expectedChallengeVersion", NpgsqlDbType.Bigint).Value = promotion.ExpectedChallengeVersion;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    PromotePasswordResetResult result = new(
                        dr.GetBoolean(0),
                        dr.GetString(1),
                        dr.IsDBNull(2) ? null : dr.GetGuid(2),
                        dr.IsDBNull(3) ? null : dr.GetGuid(3),
                        dr.IsDBNull(4) ? null : dr.GetFieldValue<Instant>(4));

                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("PromotePasswordResetAsync");
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { promotion.AccountId }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(PromotePasswordResetAsync), stage: dependencyStage);
            return null;
        }
    }

    public async Task<CancelPasswordResetRequestResult?> CancelPasswordResetRequestAsync(
        Guid resetId,
        Instant cancelledAt,
        string reasonCode,
        CancellationToken cancellationToken)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        const string procedure = CancelPasswordResetRequestFunction;

        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("PasswordResetRepo.CancelPasswordResetRequestAsync", new { resetId, cancelledAt, reasonCode }, null, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "passwordResetRequestId",
                "cancelledAt",
                "reasonCode");

            command.Parameters.Add("@passwordResetRequestId", NpgsqlDbType.Uuid).Value = resetId;
            command.Parameters.Add("@cancelledAt", InstantDbType).Value = cancelledAt;
            command.Parameters.Add("@reasonCode", NpgsqlDbType.Text).Value = reasonCode;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    CancelPasswordResetRequestResult result = new(
                        dr.GetBoolean(0),
                        dr.GetString(1),
                        dr.IsDBNull(2) ? null : dr.GetGuid(2),
                        dr.IsDBNull(3) ? null : dr.GetFieldValue<Instant>(3));

                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("CancelPasswordResetRequestAsync");
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { reasonCode }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(CancelPasswordResetRequestAsync), stage: dependencyStage);
            return null;
        }
    }

    public async Task<PasswordResetSession?> GetPendingPasswordResetSessionAsync(
        string resetAccessTokenHash,
        CancellationToken cancellationToken)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        const string procedure = GetPendingPasswordResetSessionFunction;

        try
        {
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection(cancellationToken);
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "resetAccessTokenHash");

            command.Parameters.Add("@resetAccessTokenHash", NpgsqlDbType.Text).Value = resetAccessTokenHash;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    PasswordResetSession session = ReadPasswordResetSession(dr);
                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await tran.CommitAsync(cancellationToken);
                    return session;
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
                await RollbackAndLogAsync(tran, ex, procedure, new { ResetSession = "read" }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(GetPendingPasswordResetSessionAsync), stage: dependencyStage);
            return null;
        }
    }

    public async Task<PasswordResetSessionCommandResult?> TransitionPendingPasswordResetSessionAsync(
        PasswordResetSession session,
        CancellationToken cancellationToken)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        ArgumentNullException.ThrowIfNull(session);
        const string procedure = TransitionPendingPasswordResetSessionFunction;

        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("PasswordResetRepo.TransitionPendingPasswordResetSessionAsync", new { session }, session.accountId, null, session.passwordResetRequestId?.ToString("N"), cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "resetAccessTokenHash",
                "passwordResetRequestId",
                "accountId",
                "bootstrapProof",
                "state",
                "availableConfigurations",
                "selectedTwoFactorConfiguration",
                "requiredMethods",
                "completedMethods",
                "currentExpectedMethod",
                "challengeCodeHash",
                "challengeExpiration",
                "challengeAttempts",
                "challengeResends",
                "nextChallengeAllowedAt",
                "createdOn",
                "expiresAt",
                "selectedAt",
                "twoFactorCompletedAt",
                "passwordChangedAt", "transition", "expectedSessionVersion", "expectedChallengeVersion", "bootstrapCodeHash");

            command.Parameters.Add("@resetAccessTokenHash", NpgsqlDbType.Text).Value = session.resetAccessTokenHash;
            command.Parameters.Add("@passwordResetRequestId", NpgsqlDbType.Uuid).Value = DbValue(session.passwordResetRequestId);
            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = session.accountId;
            command.Parameters.Add("@bootstrapProof", NpgsqlDbType.Smallint).Value = (short)session.bootstrapProof;
            command.Parameters.Add("@state", NpgsqlDbType.Smallint).Value = (short)session.state;
            command.Parameters.Add("@availableConfigurations", NpgsqlDbType.Array | NpgsqlDbType.Smallint).Value = ToSmallintArray(session.availableConfigurationsSnapshot);
            command.Parameters.Add("@selectedTwoFactorConfiguration", NpgsqlDbType.Smallint).Value = DbValue(ToSmallint(session.selectedConfiguration));
            command.Parameters.Add("@requiredMethods", NpgsqlDbType.Array | NpgsqlDbType.Smallint).Value = ToSmallintArray(session.requiredMethods);
            command.Parameters.Add("@completedMethods", NpgsqlDbType.Array | NpgsqlDbType.Smallint).Value = ToSmallintArray(session.completedMethods);
            command.Parameters.Add("@currentExpectedMethod", NpgsqlDbType.Smallint).Value = DbValue(ToSmallint(session.currentExpectedMethod));
            command.Parameters.Add("@challengeCodeHash", NpgsqlDbType.Text).Value = DbValue(session.challengeCodeHash);
            command.Parameters.Add("@challengeExpiration", InstantDbType).Value = DbValue(session.challengeExpiration);
            command.Parameters.Add("@challengeAttempts", NpgsqlDbType.Integer).Value = session.challengeAttempts;
            command.Parameters.Add("@challengeResends", NpgsqlDbType.Integer).Value = session.challengeResends;
            command.Parameters.Add("@nextChallengeAllowedAt", InstantDbType).Value = DbValue(session.nextChallengeAllowedAt);
            command.Parameters.Add("@createdOn", InstantDbType).Value = session.createdOn;
            command.Parameters.Add("@expiresAt", InstantDbType).Value = session.expiresAt;
            command.Parameters.Add("@selectedAt", InstantDbType).Value = DbValue(session.selectedAt);
            command.Parameters.Add("@twoFactorCompletedAt", InstantDbType).Value = DbValue(session.twoFactorCompletedAt);
            command.Parameters.Add("@passwordChangedAt", InstantDbType).Value = DbValue(session.passwordChangedAt);
            command.Parameters.Add("@transition", NpgsqlDbType.Smallint).Value = (short)session.transition;
            command.Parameters.Add("@expectedSessionVersion", NpgsqlDbType.Bigint).Value = session.sessionVersion;
            command.Parameters.Add("@expectedChallengeVersion", NpgsqlDbType.Bigint).Value = session.challengeVersion;
            command.Parameters.Add("@bootstrapCodeHash", NpgsqlDbType.Text).Value = DbValue(session.bootstrapCodeHash);

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    PasswordResetSessionCommandResult result = new(dr.GetBoolean(0), dr.GetString(1));
                    if (result.Result)
                    {
                        session.sessionVersion = dr.GetInt64(2);
                        session.challengeVersion = dr.GetInt64(3);
                        session.factorPolicyVersion = dr.GetString(4);
                        session.accountSecurityStamp = dr.GetGuid(5);
                    }
                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("TransitionPendingPasswordResetSessionAsync");
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { session.accountId }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(TransitionPendingPasswordResetSessionAsync), new { session.accountId }, stage: dependencyStage);
            return null;
        }
    }

    public async Task<PasswordResetSessionCommandResult?> RevokePendingPasswordResetSessionAsync(
        string resetAccessTokenHash,
        Instant revokedAt,
        string reasonCode,
        CancellationToken cancellationToken, long expectedSessionVersion = 0, long expectedChallengeVersion = 0)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        const string procedure = RevokePendingPasswordResetSessionFunction;

        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("PasswordResetRepo.RevokePendingPasswordResetSessionAsync", new { resetAccessTokenHash, revokedAt, reasonCode, expectedSessionVersion, expectedChallengeVersion }, null, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "resetAccessTokenHash",
                "revokedAt",
                "reasonCode", "expectedSessionVersion", "expectedChallengeVersion");

            command.Parameters.Add("@resetAccessTokenHash", NpgsqlDbType.Text).Value = resetAccessTokenHash;
            command.Parameters.Add("@revokedAt", InstantDbType).Value = revokedAt;
            command.Parameters.Add("@reasonCode", NpgsqlDbType.Text).Value = reasonCode;
            command.Parameters.Add("@expectedSessionVersion", NpgsqlDbType.Bigint).Value = expectedSessionVersion;
            command.Parameters.Add("@expectedChallengeVersion", NpgsqlDbType.Bigint).Value = expectedChallengeVersion;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    PasswordResetSessionCommandResult result = new(dr.GetBoolean(0), dr.GetString(1));
                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("RevokePendingPasswordResetSessionAsync");
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { ResetSession = "revoke" }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(RevokePendingPasswordResetSessionAsync), stage: dependencyStage);
            return null;
        }
    }

    public async Task<PasswordResetRateLimitResult?> RegisterRequestRateLimitAsync(
        PasswordResetRateLimitDbCommand rateLimit,
        CancellationToken cancellationToken)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        ArgumentNullException.ThrowIfNull(rateLimit);

        const string procedure = RegisterPasswordResetRequestRateLimitFunction;

        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("PasswordResetRepo.RegisterRequestRateLimitAsync", new { rateLimit }, null, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "rateLimitKey",
                "now",
                "requestWindow",
                "requestLimit",
                "requestCooldown",
                "blockPeriod");

            command.Parameters.Add("@rateLimitKey", NpgsqlDbType.Text).Value = rateLimit.RateLimitKey;
            command.Parameters.Add("@now", InstantDbType).Value = rateLimit.Now;
            command.Parameters.Add("@requestWindow", PeriodDbType).Value = rateLimit.RequestWindow;
            command.Parameters.Add("@requestLimit", NpgsqlDbType.Integer).Value = rateLimit.RequestLimit;
            command.Parameters.Add("@requestCooldown", PeriodDbType).Value = rateLimit.RequestCooldown;
            command.Parameters.Add("@blockPeriod", PeriodDbType).Value = rateLimit.BlockPeriod;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    PasswordResetRateLimitResult result = new(
                        dr.GetBoolean(0),
                        dr.GetString(1),
                        dr.IsDBNull(2) ? null : dr.GetInt32(2),
                        dr.IsDBNull(3) ? null : dr.GetFieldValue<Instant>(3),
                        dr.IsDBNull(4) ? null : dr.GetInt32(4));

                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("RegisterRequestRateLimitAsync");
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { rateLimit.RateLimitKey, rateLimit.Now }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(RegisterRequestRateLimitAsync), stage: dependencyStage);
            return null;
        }
    }

    public async Task<PasswordResetCleanupResult?> CleanupExpiredPasswordResetRequestsAsync(
        Instant now,
        Period retention,
        CancellationToken cancellationToken)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        const string procedure = CleanupExpiredPasswordResetRequestsFunction;

        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("PasswordResetRepo.CleanupExpiredPasswordResetRequestsAsync", new { now, retention }, null, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "now",
                "retention");

            command.Parameters.Add("@now", InstantDbType).Value = now;
            command.Parameters.Add("@retention", PeriodDbType).Value = retention;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    PasswordResetCleanupResult result = new(
                        dr.GetBoolean(0),
                        dr.GetString(1),
                        dr.GetInt32(2),
                        dr.GetInt32(3));

                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("CleanupExpiredPasswordResetRequestsAsync");
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { now, retention }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(CleanupExpiredPasswordResetRequestsAsync), stage: dependencyStage);
            return null;
        }
    }

    public async Task<PasswordResetRateLimitCleanupResult?> CleanupPasswordResetRateLimitsAsync(
        Instant now,
        Period retention,
        CancellationToken cancellationToken)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        const string procedure = CleanupPasswordResetRateLimitsFunction;

        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("PasswordResetRepo.CleanupPasswordResetRateLimitsAsync", new { now, retention }, null, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "now",
                "retention");

            command.Parameters.Add("@now", InstantDbType).Value = now;
            command.Parameters.Add("@retention", PeriodDbType).Value = retention;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    PasswordResetRateLimitCleanupResult result = new(
                        dr.GetBoolean(0),
                        dr.GetString(1),
                        dr.GetInt32(2));

                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("CleanupPasswordResetRateLimitsAsync");
            }
            catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { now, retention }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(CleanupPasswordResetRateLimitsAsync), stage: dependencyStage);
            return null;
        }
    }

    private static PasswordResetSession ReadPasswordResetSession(NpgsqlDataReader dr)
    {
        Guid? passwordResetRequestId = dr.IsDBNull(0) ? null : dr.GetGuid(0);
        Guid accountId = dr.GetGuid(1);
        string resetAccessTokenHash = dr.GetString(2);
        PasswordResetBootstrapProof bootstrapProof = (PasswordResetBootstrapProof)dr.GetInt16(3);
        PasswordResetSessionState state = (PasswordResetSessionState)dr.GetInt16(4);
        List<TwoFactorAuthConfiguration> availableConfigurations = ReadConfigurationArray(dr, 5);
        TwoFactorAuthConfiguration? selectedConfiguration = dr.IsDBNull(6) ? null : (TwoFactorAuthConfiguration)dr.GetInt16(6);
        List<TwoFactorAuthMethod> requiredMethods = ReadMethodArray(dr, 7);
        List<TwoFactorAuthMethod> completedMethods = ReadMethodArray(dr, 8);
        TwoFactorAuthMethod? currentExpectedMethod = dr.IsDBNull(9) ? null : (TwoFactorAuthMethod)dr.GetInt16(9);
        string? challengeCodeHash = dr.IsDBNull(10) ? null : dr.GetString(10);
        Instant? challengeExpiration = dr.IsDBNull(11) ? null : dr.GetFieldValue<Instant>(11);
        int challengeAttempts = dr.GetInt32(12);
        int challengeResends = dr.GetInt32(13);
        Instant? nextChallengeAllowedAt = dr.IsDBNull(14) ? null : dr.GetFieldValue<Instant>(14);
        Instant createdOn = dr.GetFieldValue<Instant>(15);
        Instant expiresAt = dr.GetFieldValue<Instant>(16);
        Instant? selectedAt = dr.IsDBNull(17) ? null : dr.GetFieldValue<Instant>(17);
        Instant? twoFactorCompletedAt = dr.IsDBNull(18) ? null : dr.GetFieldValue<Instant>(18);
        Instant? passwordChangedAt = dr.IsDBNull(19) ? null : dr.GetFieldValue<Instant>(19);

        PasswordResetSession session = new(
            accountId,
            resetAccessTokenHash,
            bootstrapProof,
            availableConfigurations,
            createdOn,
            expiresAt,
            state,
            passwordResetRequestId);

        session.state = state;
        session.selectedConfiguration = selectedConfiguration;
        session.requiredMethods = requiredMethods;
        session.completedMethods = completedMethods;
        session.currentExpectedMethod = currentExpectedMethod;
        session.challengeCodeHash = challengeCodeHash;
        session.challengeExpiration = challengeExpiration;
        session.challengeAttempts = challengeAttempts;
        session.challengeResends = challengeResends;
        session.nextChallengeAllowedAt = nextChallengeAllowedAt;
        session.selectedAt = selectedAt;
        session.twoFactorCompletedAt = twoFactorCompletedAt;
        session.passwordChangedAt = passwordChangedAt;
        session.sessionVersion = dr.GetInt64(20);
        session.challengeVersion = dr.GetInt64(21);
        session.factorPolicyVersion = dr.GetString(22);
        session.accountSecurityStamp = dr.GetGuid(23);
        return session;
    }

    private static List<TwoFactorAuthConfiguration> ReadConfigurationArray(NpgsqlDataReader dr, int ordinal)
    {
        return dr.IsDBNull(ordinal)
            ? []
            : dr.GetFieldValue<short[]>(ordinal).Select(value => (TwoFactorAuthConfiguration)value).ToList();
    }

    private static List<TwoFactorAuthMethod> ReadMethodArray(NpgsqlDataReader dr, int ordinal)
    {
        return dr.IsDBNull(ordinal)
            ? []
            : dr.GetFieldValue<short[]>(ordinal).Select(value => (TwoFactorAuthMethod)value).ToList();
    }

    private static short[] ToSmallintArray(IEnumerable<TwoFactorAuthConfiguration>? values)
    {
        return values?.Select(value => (short)value).ToArray() ?? [];
    }

    private static short[] ToSmallintArray(IEnumerable<TwoFactorAuthMethod>? values)
    {
        return values?.Select(value => (short)value).ToArray() ?? [];
    }

    private static short? ToSmallint(TwoFactorAuthConfiguration? value)
    {
        return value.HasValue ? (short)value.Value : null;
    }

    private static short? ToSmallint(TwoFactorAuthMethod? value)
    {
        return value.HasValue ? (short)value.Value : null;
    }

    internal static object DbValue(object? value)
    {
        return value ?? DBNull.Value;
    }

    internal static object InetDbValue(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? DBNull.Value : IPAddress.Parse(value);
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
