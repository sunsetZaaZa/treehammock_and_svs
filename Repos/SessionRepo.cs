using treehammock.Rigging.Dependencies;
using System.Data;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NodaTime;
using Npgsql;
using NpgsqlTypes;

using treehammock.Entities;
using treehammock.DataLayer.Account;
using treehammock.Rigging.Config;
using treehammock.Rigging.Authorization;
using treehammock.RiggingSupport.Enum;
using treehammock.Rigging.Database;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Status;

namespace treehammock.Repos;

public interface ISessionRepo
{
    public Task<Session?> GetSession(string accessTokenHash, CancellationToken cancellationToken = default);
    public Task<IntraMessage?> SetSession(string accessTokenHash, Session record, CancellationToken cancellationToken = default);
    public Task<SessionRotationResult?> RotateActiveSession(Guid accountId, string expectedOldAccessTokenHash, string newAccessTokenHash, Session newSession, CancellationToken cancellationToken = default);
    public Task<CachedSessionTrustResult?> ValidateCachedSessionTrust(string accessTokenHash, Guid accountId, Guid securityStamp, Guid accountSecurityStamp, CancellationToken cancellationToken = default);
    public Task<bool?> ExpireSession(string accessTokenHash, Instant? newExpiration, CancellationToken cancellationToken = default);
    public Task<DbCommandResult?> LogoutCurrentSession(Guid accountId, string accessTokenHash, Guid accountSecurityStamp, CancellationToken cancellationToken = default);
    public Task<AccountStampRotationResult?> LogoutAllSessions(Guid accountId, Guid accountSecurityStamp, CancellationToken cancellationToken = default);
    public Task<IReadOnlyList<AccountSessionSummary>?> ListActiveSessions(Guid accountId, Guid accountSecurityStamp, string currentAccessTokenHash, CancellationToken cancellationToken = default);
    public Task<DbCommandResult?> RevokeSessionForAccount(Guid accountId, Guid targetSessionId, Guid accountSecurityStamp, string currentAccessTokenHash, CancellationToken cancellationToken = default);
}

public class SessionRepo : ISessionRepo
{
    internal const string GetSessionProcedure = "get_session";
    internal const string SetSessionProcedure = "set_session";
    internal const string ExpireSessionProcedure = "expire_session";
    internal const string RotateActiveSessionProcedure = "rotate_active_session";
    internal const string ValidateCachedSessionTrustProcedure = "validate_cached_session_trust";
    internal const string LogoutCurrentSessionProcedure = "logout_current_session";
    internal const string LogoutAllSessionsProcedure = "logout_all_sessions";
    internal const string ListActiveSessionsProcedure = "list_active_sessions";
    internal const string RevokeSessionForAccountProcedure = "revoke_session_for_account";

    internal const NpgsqlDbType AccessTokenHashDbType = NpgsqlDbType.Text;
    internal const NpgsqlDbType RefreshTokenDbType = NpgsqlDbType.Bytea;
    internal const NpgsqlDbType InstantDbType = NpgsqlDbType.TimestampTz;
    internal const NpgsqlDbType FeatureSetDbType = NpgsqlDbType.Smallint;
    internal const NpgsqlDbType SecurityStampDbType = NpgsqlDbType.Uuid;
    internal const NpgsqlDbType SessionIdDbType = NpgsqlDbType.Uuid;

    private readonly StorageContext _activeDatabase;
    private readonly JWTSettings _jwtSettings;
    private readonly ILogger<SessionRepo> _logger;

    public SessionRepo(StorageContext database, IOptions<JWTSettings> jwtSettings, ILogger<SessionRepo> logger)
    {
        _activeDatabase = database;
        _jwtSettings = jwtSettings.Value;
        _logger = logger;
    }

    public async Task<Session?> GetSession(string accessTokenHash, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = GetSessionProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection(cancellationToken);
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(procedure, conn, tran, "accessTokenHash");

            command.Parameters.Add("@accessTokenHash", AccessTokenHashDbType).Value = accessTokenHash;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    byte[] refreshTokenBuffer = new byte[_jwtSettings.RefreshTokenBytes];
                    dr.GetBytes(1, 0, refreshTokenBuffer, 0, _jwtSettings.RefreshTokenBytes);

                    Period? sessionLifespan = dr.IsDBNull(5) ? null : dr.GetFieldValue<Period>(5);
                    Instant accessExpiration = dr.GetFieldValue<Instant>(6);
                    Instant sessionExpiration = dr.GetFieldValue<Instant>(7);
                    Instant? cutOff = dr.FieldCount > 8 && !dr.IsDBNull(8) ? dr.GetFieldValue<Instant>(8) : null;
                    FeatureSet features = dr.FieldCount > 9 && !dr.IsDBNull(9) ? (FeatureSet)dr.GetInt16(9) : FeatureSet.basic;
                    Guid securityStamp = dr.FieldCount > 10 && !dr.IsDBNull(10)
                        ? dr.GetGuid(10)
                        : throw new DataException("get_session must return security_stamp.");
                    Guid accountSecurityStamp = dr.FieldCount > 11 && !dr.IsDBNull(11)
                        ? dr.GetGuid(11)
                        : throw new DataException("get_session must return account_security_stamp.");

                    var session = new Session(
                        dr.GetGuid(0),
                        refreshTokenBuffer,
                        dr.IsDBNull(2) ? null : dr.GetInt16(2),
                        dr.IsDBNull(3) ? null : dr.GetInt16(3),
                        dr.GetFieldValue<Instant>(4),
                        sessionLifespan,
                        accessExpiration,
                        sessionExpiration,
                        cutOff,
                        features,
                        securityStamp,
                        accountSecurityStamp, dr.GetGuid(12), dr.GetInt64(13), dr.GetInt32(14),
                        treehammock.DataLayer.Entitlements.EntitlementProjection.Parse(dr.GetString(15), dr.GetGuid(0)));

                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await tran.CommitAsync(cancellationToken);
                    return session;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await tran.CommitAsync(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.AccessTokenHashScope(accessTokenHash), stage: dependencyStage);
            }

            return null;
            }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(GetSession), stage: dependencyStage);
            return null;
        }
    }

    public async Task<IntraMessage?> SetSession(string accessTokenHash, Session workingSession, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = SetSessionProcedure;
            string[] parameterNames =
            {
                "accessTokenHash",
                "accountId",
                "refreshToken",
                "refreshes",
                "limit",
                "createdOn",
                "sessionLifespan",
                "accessExpiration",
                "sessionExpiration",
                "cutOff",
                "features",
                "securityStamp",
                "accountSecurityStamp"
            };

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("SessionRepo.SetSession", new { accessTokenHash, workingSession }, workingSession.accountId, workingSession.accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(procedure, conn, tran, parameterNames);

            command.Parameters.Add("@accessTokenHash", AccessTokenHashDbType).Value = accessTokenHash;
            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = workingSession.accountId;
            command.Parameters.Add("@refreshToken", RefreshTokenDbType).Value = workingSession.refreshToken;
            command.Parameters.Add("@refreshes", NpgsqlDbType.Smallint).Value = DbValue(workingSession.refreshes);
            command.Parameters.Add("@limit", NpgsqlDbType.Smallint).Value = DbValue(workingSession.limit);
            command.Parameters.Add("@createdOn", InstantDbType).Value = workingSession.createdOn;
            command.Parameters.Add("@sessionLifespan", NpgsqlDbType.Interval).Value = DbValue(workingSession.sessionLifespan);
            command.Parameters.Add("@accessExpiration", InstantDbType).Value = workingSession.accessExpiration;
            command.Parameters.Add("@sessionExpiration", InstantDbType).Value = workingSession.sessionExpiration;
            command.Parameters.Add("@cutOff", InstantDbType).Value = DbValue(workingSession.cutOff);
            command.Parameters.Add("@features", FeatureSetDbType).Value = (short)workingSession.features;
            command.Parameters.Add("@securityStamp", SecurityStampDbType).Value = workingSession.securityStamp;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(workingSession.accountSecurityStamp);

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    IntraMessage result = (IntraMessage)dr.GetInt16(dr.GetOrdinal("result"));
                    await dr.DisposeAsync();
                    if (result is IntraMessage.SUCCESSFUL or IntraMessage.AUTHENTICATION_PASSED)
                        await EntitlementRepo.HydrateAsync(conn, tran, workingSession, cancellationToken);
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(result);
                    return result;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("SetSession");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.AccountTokenHash(workingSession.accountId, accessTokenHash), stage: dependencyStage);
            }

            return null;
            }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(SetSession), stage: dependencyStage);
            return null;
        }
    }


    public async Task<SessionRotationResult?> RotateActiveSession(Guid accountId, string expectedOldAccessTokenHash, string newAccessTokenHash, Session newSession, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = RotateActiveSessionProcedure;
            string[] parameterNames =
            {
                "accountId",
                "expectedOldAccessTokenHash",
                "newAccessTokenHash",
                "refreshToken",
                "refreshes",
                "limit",
                "createdOn",
                "sessionLifespan",
                "accessExpiration",
                "sessionExpiration",
                "cutOff",
                "features",
                "securityStamp",
                "accountSecurityStamp"
            };

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("SessionRepo.RotateActiveSession", new { accountId, expectedOldAccessTokenHash, newAccessTokenHash, newSession }, accountId, newSession.accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(procedure, conn, tran, parameterNames);

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@expectedOldAccessTokenHash", AccessTokenHashDbType).Value = expectedOldAccessTokenHash;
            command.Parameters.Add("@newAccessTokenHash", AccessTokenHashDbType).Value = newAccessTokenHash;
            command.Parameters.Add("@refreshToken", RefreshTokenDbType).Value = newSession.refreshToken;
            command.Parameters.Add("@refreshes", NpgsqlDbType.Smallint).Value = DbValue(newSession.refreshes);
            command.Parameters.Add("@limit", NpgsqlDbType.Smallint).Value = DbValue(newSession.limit);
            command.Parameters.Add("@createdOn", InstantDbType).Value = newSession.createdOn;
            command.Parameters.Add("@sessionLifespan", NpgsqlDbType.Interval).Value = DbValue(newSession.sessionLifespan);
            command.Parameters.Add("@accessExpiration", InstantDbType).Value = newSession.accessExpiration;
            command.Parameters.Add("@sessionExpiration", InstantDbType).Value = newSession.sessionExpiration;
            command.Parameters.Add("@cutOff", InstantDbType).Value = DbValue(newSession.cutOff);
            command.Parameters.Add("@features", FeatureSetDbType).Value = (short)newSession.features;
            command.Parameters.Add("@securityStamp", SecurityStampDbType).Value = newSession.securityStamp;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(newSession.accountSecurityStamp);

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                SessionRotationResult result = await ReadSessionRotationResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                if (result.Succeeded) await EntitlementRepo.HydrateAsync(conn, tran, newSession, cancellationToken);
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.AccountTokenHashes(accountId, expectedOldAccessTokenHash, newAccessTokenHash), stage: dependencyStage);
                return null;
            }
            }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(RotateActiveSession), stage: dependencyStage);
            return null;
        }
    }

    internal static async Task<SessionRotationResult> ReadSessionRotationResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("rotate_active_session");
        }

        object value = dr[0];
        return new SessionRotationResult(ReadSessionRotationStatus(value));
    }

    internal static SessionRotationStatus ReadSessionRotationStatus(object? value)
    {
        if (value is null || value == DBNull.Value)
        {
            return SessionRotationStatus.Failed;
        }

        try
        {
            return value switch
            {
                SessionRotationStatus status => status,
                short status => Enum.IsDefined(typeof(SessionRotationStatus), (int)status) ? (SessionRotationStatus)status : SessionRotationStatus.Failed,
                int status => Enum.IsDefined(typeof(SessionRotationStatus), status) ? (SessionRotationStatus)status : SessionRotationStatus.Failed,
                long status => status >= int.MinValue && status <= int.MaxValue && Enum.IsDefined(typeof(SessionRotationStatus), (int)status)
                    ? (SessionRotationStatus)(int)status
                    : SessionRotationStatus.Failed,
                string status when Enum.TryParse(status, ignoreCase: true, out SessionRotationStatus parsed) => parsed,
                _ => SessionRotationStatus.Failed
            };
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return SessionRotationStatus.Failed;
        }
    }


    public async Task<CachedSessionTrustResult?> ValidateCachedSessionTrust(string accessTokenHash, Guid accountId, Guid securityStamp, Guid accountSecurityStamp, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = ValidateCachedSessionTrustProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection(cancellationToken);
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accessTokenHash",
                "accountId",
                "securityStamp",
                "accountSecurityStamp");

            command.Parameters.Add("@accessTokenHash", AccessTokenHashDbType).Value = accessTokenHash;
            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@securityStamp", SecurityStampDbType).Value = securityStamp;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(accountSecurityStamp);

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                CachedSessionTrustResult result = await ReadCachedSessionTrustResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await tran.CommitAsync(cancellationToken);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.AccountTokenHash(accountId, accessTokenHash), stage: dependencyStage);
                return null;
            }
            }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(ValidateCachedSessionTrust), stage: dependencyStage);
            return null;
        }
    }

    internal static async Task<CachedSessionTrustResult> ReadCachedSessionTrustResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("validate_cached_session_trust");
        }

        CachedSessionTrustStatus status = ReadCachedSessionTrustStatus(dr[0]);
        string? code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : null;
        Instant? accessExpiration = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetFieldValue<Instant>(2) : null;
        Instant? sessionExpiration = dr.FieldCount > 3 && !dr.IsDBNull(3) ? dr.GetFieldValue<Instant>(3) : null;
        Instant? cutOff = dr.FieldCount > 4 && !dr.IsDBNull(4) ? dr.GetFieldValue<Instant>(4) : null;
        Guid? currentSecurityStamp = dr.FieldCount > 5 && !dr.IsDBNull(5) ? dr.GetGuid(5) : null;
        Guid? currentAccountSecurityStamp = dr.FieldCount > 6 && !dr.IsDBNull(6) ? dr.GetGuid(6) : null;
        var result = new CachedSessionTrustResult(status, accessExpiration, sessionExpiration, cutOff, currentSecurityStamp, currentAccountSecurityStamp, code,
            !dr.IsDBNull(7) ? dr.GetGuid(7) : null,
            !dr.IsDBNull(8) ? dr.GetInt64(8) : null,
            !dr.IsDBNull(9) ? dr.GetInt32(9) : null,
            status == CachedSessionTrustStatus.Valid ? treehammock.DataLayer.Entitlements.EntitlementProjection.Parse(dr.GetString(10)) : null);
        if (result.Succeeded && (result.FamilyId is null || result.FamilyId == Guid.Empty ||
            result.Generation is null || result.Generation < 1 || result.Generation > SessionProtocol.MaximumGeneration ||
            result.ProtocolVersion != SessionProtocol.Version))
            throw DependencyUnavailableException.InvalidResponse("validate_cached_session_trust");
        return result;
    }

    internal static CachedSessionTrustStatus ReadCachedSessionTrustStatus(object? value)
    {
        if (value is null || value == DBNull.Value)
        {
            return CachedSessionTrustStatus.Failed;
        }

        try
        {
            return value switch
            {
                CachedSessionTrustStatus status => status,
                short status => Enum.IsDefined(typeof(CachedSessionTrustStatus), (int)status) ? (CachedSessionTrustStatus)status : CachedSessionTrustStatus.Failed,
                int status => Enum.IsDefined(typeof(CachedSessionTrustStatus), status) ? (CachedSessionTrustStatus)status : CachedSessionTrustStatus.Failed,
                long status => status >= int.MinValue && status <= int.MaxValue && Enum.IsDefined(typeof(CachedSessionTrustStatus), (int)status)
                    ? (CachedSessionTrustStatus)(int)status
                    : CachedSessionTrustStatus.Failed,
                string status when Enum.TryParse(status, ignoreCase: true, out CachedSessionTrustStatus parsed) => parsed,
                _ => CachedSessionTrustStatus.Failed
            };
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return CachedSessionTrustStatus.Failed;
        }
    }

    /**
     * Expires a session at the provided point in time. A null value means "expire now"; hard deletion is reserved for future cleanup jobs.
     */
    public async Task<bool?> ExpireSession(string accessTokenHash, Instant? newExpiration, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = ExpireSessionProcedure;
            Instant expiration = newExpiration ?? SystemClock.Instance.GetCurrentInstant();

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("SessionRepo.ExpireSession", new { accessTokenHash, newExpiration }, null, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(procedure, conn, tran, "accessTokenHash", "expiration");

            command.Parameters.Add("@accessTokenHash", AccessTokenHashDbType).Value = accessTokenHash;
            command.Parameters.Add("@expiration", InstantDbType).Value = expiration;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                bool result = await AccountRepo.ReadBooleanProcedureResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.AccessTokenHashExpiration(accessTokenHash, expiration), stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(ExpireSession), stage: dependencyStage);
            return null;
        }
    }


    public async Task<DbCommandResult?> LogoutCurrentSession(Guid accountId, string accessTokenHash, Guid accountSecurityStamp, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = LogoutCurrentSessionProcedure;

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("SessionRepo.LogoutCurrentSession", new { accountId, accessTokenHash, accountSecurityStamp }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accessTokenHash",
                "accountSecurityStamp");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accessTokenHash", AccessTokenHashDbType).Value = accessTokenHash;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(accountSecurityStamp);

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                DbCommandResult result = await ReadDbCommandResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.AccountTokenHash(accountId, accessTokenHash), stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(LogoutCurrentSession), RepositoryLogScopes.AccountTokenHash(accountId, accessTokenHash), stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountStampRotationResult?> LogoutAllSessions(Guid accountId, Guid accountSecurityStamp, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = LogoutAllSessionsProcedure;

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("SessionRepo.LogoutAllSessions", new { accountId, accountSecurityStamp }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(accountSecurityStamp);

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                AccountStampRotationResult result = await ReadAccountStampRotationResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
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
            LogRepositoryFailure(ex, nameof(LogoutAllSessions), new { accountId }, stage: dependencyStage);
            return null;
        }
    }



    public async Task<IReadOnlyList<AccountSessionSummary>?> ListActiveSessions(Guid accountId, Guid accountSecurityStamp, string currentAccessTokenHash, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = ListActiveSessionsProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection(cancellationToken);
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "currentAccessTokenHash");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(accountSecurityStamp);
            command.Parameters.Add("@currentAccessTokenHash", AccessTokenHashDbType).Value = currentAccessTokenHash;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                IReadOnlyList<AccountSessionSummary> result = await ReadAccountSessionSummariesAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await tran.CommitAsync(cancellationToken);
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
            LogRepositoryFailure(ex, nameof(ListActiveSessions), new { accountId }, stage: dependencyStage);
            return null;
        }
    }

    public async Task<DbCommandResult?> RevokeSessionForAccount(Guid accountId, Guid targetSessionId, Guid accountSecurityStamp, string currentAccessTokenHash, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            const string procedure = RevokeSessionForAccountProcedure;

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("SessionRepo.RevokeSessionForAccount", new { accountId, targetSessionId, accountSecurityStamp, currentAccessTokenHash }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "targetSessionId",
                "accountSecurityStamp",
                "currentAccessTokenHash");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@targetSessionId", SessionIdDbType).Value = targetSessionId;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(accountSecurityStamp);
            command.Parameters.Add("@currentAccessTokenHash", AccessTokenHashDbType).Value = currentAccessTokenHash;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                DbCommandResult result = await ReadDbCommandResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, procedure, new { accountId, targetSessionId }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(RevokeSessionForAccount), new { accountId, targetSessionId }, stage: dependencyStage);
            return null;
        }
    }

    internal static async Task<IReadOnlyList<AccountSessionSummary>> ReadAccountSessionSummariesAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        var sessions = new List<AccountSessionSummary>();
        while (await dr.ReadAsync(cancellationToken))
        {
            sessions.Add(new AccountSessionSummary(
                dr.GetGuid(0),
                dr.GetFieldValue<Instant>(1),
                dr.GetFieldValue<Instant>(2),
                dr.GetFieldValue<Instant>(3),
                dr.FieldCount > 4 && !dr.IsDBNull(4) ? (FeatureSet)dr.GetInt16(4) : FeatureSet.basic,
                dr.FieldCount > 5 && !dr.IsDBNull(5) && dr.GetBoolean(5),
                treehammock.DataLayer.Entitlements.EntitlementProjection.Parse(dr.GetString(6))));
        }

        return sessions;
    }

    internal static async Task<DbCommandResult> ReadDbCommandResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1)
            ? dr.GetString(1)
            : "UNKNOWN";

        return new DbCommandResult(result, code);
    }

    internal static async Task<AccountStampRotationResult> ReadAccountStampRotationResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1)
            ? dr.GetString(1)
            : "UNKNOWN";
        Guid? accountSecurityStamp = dr.FieldCount > 2 && !dr.IsDBNull(2)
            ? dr.GetGuid(2)
            : null;

        return new AccountStampRotationResult(result, code, accountSecurityStamp);
    }

    internal static object DbValue(object? value)
    {
        return value ?? DBNull.Value;
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
