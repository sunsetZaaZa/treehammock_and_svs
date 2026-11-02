using treehammock.Rigging.Delivery;
using treehammock.Rigging.Dependencies;
using System.Data;

using Npgsql;
using NpgsqlTypes;
using NodaTime;

using treehammock.Models.Account;
using treehammock.Models.Authentication;
using treehammock.Rigging.Database;
using treehammock.DataLayer.Account;
using treehammock.RiggingSupport.Status;
using treehammock.RiggingSupport.Enum;
using treehammock.Entities;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

namespace treehammock.Repos;

public enum CredentialLookupStatus
{
    Found,
    NotFound,
    Failed
}

public sealed record CredentialLookupResult
{
    private CredentialLookupResult(CredentialLookupStatus status, IntraAccount? account = null)
    {
        if (status == CredentialLookupStatus.Found && account == null)
        {
            throw new ArgumentNullException(nameof(account), "Found credential lookups must carry an account.");
        }

        if (status != CredentialLookupStatus.Found && account != null)
        {
            throw new ArgumentException("Only found credential lookups may carry an account.", nameof(account));
        }

        Status = status;
        Account = account;
    }

    public CredentialLookupStatus Status { get; }
    public IntraAccount? Account { get; }
    public bool Succeeded => Status == CredentialLookupStatus.Found;

    public static CredentialLookupResult Found(IntraAccount account) => new(CredentialLookupStatus.Found, account);
    public static CredentialLookupResult NotFound() => new(CredentialLookupStatus.NotFound);
    public static CredentialLookupResult Failed() => new(CredentialLookupStatus.Failed);
}


public enum TwoFactorDetailsLookupStatus
{
    Found,
    NotConfigured,
    Failed
}

public sealed record TwoFactorDetailsLookupResult
{
    private TwoFactorDetailsLookupResult(TwoFactorDetailsLookupStatus status, TwoFactorDetails? details = null)
    {
        if (status == TwoFactorDetailsLookupStatus.Found && details == null)
        {
            throw new ArgumentNullException(nameof(details), "Found two-factor detail lookups must carry details.");
        }

        if (status != TwoFactorDetailsLookupStatus.Found && details != null)
        {
            throw new ArgumentException("Only found two-factor detail lookups may carry details.", nameof(details));
        }

        Status = status;
        Details = details;
    }

    public TwoFactorDetailsLookupStatus Status { get; }
    public TwoFactorDetails? Details { get; }
    public bool Succeeded => Status == TwoFactorDetailsLookupStatus.Found;

    public static TwoFactorDetailsLookupResult Found(TwoFactorDetails details) => new(TwoFactorDetailsLookupStatus.Found, details);
    public static TwoFactorDetailsLookupResult NotConfigured() => new(TwoFactorDetailsLookupStatus.NotConfigured);
    public static TwoFactorDetailsLookupResult Failed() => new(TwoFactorDetailsLookupStatus.Failed);
}

public sealed record AccountVerificationResendResult(bool Result, string Code, string? EmailAddress);

public sealed record TwoFactorChallengeCommandResult(
    bool Result,
    string Code,
    short ChallengeAttempts,
    short ChallengeResends,
    Instant? ChallengeExpiration,
    Instant? NextChallengeAllowedAt);

public sealed record TwoFactorSetupCommandResult(
    bool Result,
    string Code,
    long? TwoFactorIndex,
    Instant? Expiration);

public sealed record TwoFactorSetupVerificationCommandResult(
    bool Result,
    string Code,
    short Attempts,
    Instant? Expiration);

public sealed record TwoFactorMethodRemovalCommandResult(
    bool Result,
    string Code,
    TwoFactorAuthMethod RemovedMethod,
    IReadOnlyList<TwoFactorAuthMethod> TwoFactorAuthMethods,
    IReadOnlyList<TwoFactorAuthConfiguration> AvailableTwoFactorAuthConfigurations);

public interface IAccountRepo
{
    Task<(long?, HttpMessage, string?)> SetupAccount(Account single, string verifyKeyHash, Period verificationExpiration, AccountSetupAction step, DeliveryIntent deliveryIntent, CancellationToken cancellationToken = default);
    Task<bool?> StartAccountVerification(Guid accountGuid, long? verificationIndex, CancellationToken cancellationToken = default);
    Task<AccountVerificationResendResult?> ResendAccountVerification(string emailAddress, string verifyKeyHash, Period verificationExpiration, CancellationToken cancellationToken = default);
    Task<AccountVerification?> VerifyAccountForUse(string verifyKey, CancellationToken cancellationToken = default);
    Task<bool?> AccountPassedVerification(AccountVerification record, CancellationToken cancellationToken = default);
    Task<bool?> AccountVerificationExpired(AccountVerification record, CancellationToken cancellationToken = default);
    Task<CredentialLookupResult> GetCredentials(AuthenticateLogin single, AccountLoginAction action, CancellationToken cancellationToken = default);
    Task<HttpMessage?> CheckSignupAvailability(string email, string? username, CancellationToken cancellationToken = default);
    Task<bool> UpgradePasswordHash(Guid account, Guid stamp, byte[] oldHash, byte[] newHash, CancellationToken cancellationToken = default);
    Task<TwoFactorDetailsLookupResult> GetTwoFactorDetails(Guid accountId, CancellationToken cancellationToken = default);
    Task<TwoFactorSetupCommandResult?> BeginTwoFactorSetup(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        string tokenHash,
        Instant createdOn,
        Instant expiration,
        string? emailAddress,
        string? phoneNumber,
        string? phoneCountryCode,
        string? authId,
        bool required, CancellationToken cancellationToken = default);
    Task<DbCommandResult?> CancelTwoFactorSetup(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        string tokenHash, CancellationToken cancellationToken = default);
    Task<TwoFactorSetupVerificationCommandResult?> VerifyTwoFactorSetup(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        string tokenHash,
        short maxAttempts,
        Instant moment, Guid enrollmentId, long setupVersion, Guid familyId, CancellationToken cancellationToken = default);
    Task<TwoFactorMethodRemovalCommandResult?> RemoveTwoFactorMethod(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        Instant moment, CancellationToken cancellationToken = default, treehammock.DataLayer.Security.SensitiveActionGrant? grant = null);
    Task<treehammock.DataLayer.Security.LoginAttemptTransition> RecordLoginFailure(Guid accountId, Guid stamp, int charge, int limit, CancellationToken cancellationToken = default);
    Task<treehammock.DataLayer.Security.LoginAttemptTransition> ClearLoginAttempts(Guid accountId, Guid stamp, Guid observedVersion, short observedFailures, Instant? observedUnlock, bool expiredCleanup, CancellationToken cancellationToken = default);
    Task<bool?> SetLockOut(Guid accountGuid, short? loginFailuress, CancellationToken cancellationToken = default);
    Task<bool?> RemoveLockOut(Guid accountGuid, CancellationToken cancellationToken = default);
    Task<bool?> SetLoginFailures(Guid accountGuid, int failures, CancellationToken cancellationToken = default);
    Task<bool?> SuccessfulLogin(Guid accountId, Guid accountSecurityStamp, CancellationToken cancellationToken = default);
    Task<bool?> RotateAccountSecurityStamp(Guid accountId, CancellationToken cancellationToken = default);
    Task<AccountAdjustResult?> ModifyUsername(Guid accountId, Guid accountSecurityStamp, string username, CancellationToken cancellationToken = default);
    Task<AccountAdjustResult?> RequestEmailChange(Guid accountId, Guid accountSecurityStamp, string newEmailAddress, string verifyKeyHash, Instant expiration, CancellationToken cancellationToken = default);
    Task<AccountAdjustResult?> CancelEmailChangeRequest(Guid accountId, Guid accountSecurityStamp, string verifyKeyHash, CancellationToken cancellationToken = default);
    Task<AccountAdjustResult?> CompleteEmailChange(string verifyKeyHash, CancellationToken cancellationToken = default);
    Task<AccountDeleteCommandResult?> AdmitAccountDelete(Guid accountId,Guid stamp,Guid admissionId,string proofHash,Instant expires,Period cooldown,Period window,short maxRequests,treehammock.DataLayer.Security.SensitiveActionGrant grant,CancellationToken cancellationToken=default);
    Task<AccountDeleteCommandResult?> RequestAccountDelete(
        Guid accountId,
        Guid accountSecurityStamp,
        string? passPhraseHash,
        string deleteTokenHash,
        Instant expiration,
        Period requestCooldown,
        Period requestWindow,
        short maxRequestsPerWindow, CancellationToken cancellationToken = default);
    Task<AccountDeleteCommandResult?> CancelAccountDeleteRequest(
        Guid accountId,
        Guid accountSecurityStamp,
        string deleteTokenHash, CancellationToken cancellationToken = default);
    Task<AccountDeleteCommandResult?> VerifyDeleteAccountToken(string deleteTokenHash, CancellationToken cancellationToken = default);
    Task<AccountDeleteCommandResult?> FinalizeAccountDelete(
        Guid accountId,
        Guid accountSecurityStamp,
        string deleteTokenHash,
        string? passPhrase,
        short maxFailedFinalizeAttempts,
        Period finalizeLockout, CancellationToken cancellationToken = default,string? sessionHash = null);
    Task<AccountDeletePurgeResult?> PurgeExpiredDeleteStandby(Instant moment, CancellationToken cancellationToken = default);
    Task<AccountEmailChangePurgeResult?> PurgeExpiredAccountEmailChangeRequests(Instant moment, CancellationToken cancellationToken = default);
    Task<AccountViewResult?> ViewAccount(Guid accountId, Guid accountSecurityStamp, CancellationToken cancellationToken = default);
}

public partial class AccountRepo : IAccountRepo
{
    internal const string SetupAccountEmailFunction = "setup_account_email";
    internal const string SetupAccountBothFunction = "setup_account_both";
    internal const string StartVerifyAccountFunction = "start_verify_account";
    internal const string ResendVerifyAccountFunction = "resend_verify_account";
    internal const string VerifyAccountForUseProcedure = "verify_account_for_use";
    internal const string CompleteVerifyAccountProcedure = "complete_verify_account";
    internal const string ExpireVerifyAccountProcedure = "expire_verify_account";
    internal const string RotateAccountSecurityStampProcedure = "rotate_account_security_stamp";
    internal const string BeginTwoFactorAuthDetailFunction = "begin_twofactor_auth_detail";
    internal const string BeginTwoFactorSetupFunction = "begin_twofactor_setup";
    internal const string CancelTwoFactorSetupFunction = "cancel_twofactor_setup";
    internal const string VerifyTwoFactorSetupFunction = "verify_twofactor_setup";
    internal const string RemoveTwoFactorMethodFunction = "cor08_authorized_remove_twofactor_method";
    internal const string ViewAccountFunction = "view_account";
    internal const string EditAccountUsernameFunction = "edit_account_username";
    internal const string RequestAccountEmailChangeFunction = "request_account_email_change";
    internal const string CancelAccountEmailChangeRequestFunction = "cancel_account_email_change_request";
    internal const string CompleteAccountEmailChangeFunction = "complete_account_email_change";
    internal const string PurgeExpiredAccountEmailChangeRequestsFunction = "purge_expired_account_email_change_requests";
    internal const string RequestAccountDeleteFunction = "request_account_delete";
    internal const string CancelAccountDeleteRequestFunction = "cancel_account_delete_request";
    internal const string VerifyAccountDeleteTokenFunction = "verify_account_delete_token";
    internal const string PrepareAccountDeleteFinalizeFunction = "prepare_account_delete_finalize";
    internal const string CommitAccountDeleteFinalizeFunction = "commit_account_delete_finalize";
    internal const string PurgeExpiredDeleteStandbyFunction = "purge_expired_delete_standby";

    internal const NpgsqlDbType WebKeyDbType = NpgsqlDbType.Text;
    internal const NpgsqlDbType HashedPasswordDbType = NpgsqlDbType.Bytea;
    internal const NpgsqlDbType SaltOneDbType = NpgsqlDbType.Bytea;
    internal const NpgsqlDbType SivDbType = NpgsqlDbType.Bytea;
    internal const NpgsqlDbType NonceDbType = NpgsqlDbType.Bytea;
    internal const NpgsqlDbType RefreshTokenDbType = NpgsqlDbType.Bytea;
    internal const NpgsqlDbType InstantDbType = NpgsqlDbType.TimestampTz;

    private readonly StorageContext _activeDatabase;
    private readonly JWTSettings _jwtSettings;
    private readonly ILogger<AccountRepo> _logger;
    private readonly IUserSecretHasher _userSecretHasher;

    private readonly DeliveryPayloadProtector _deliveryProtector;
    public AccountRepo(
        DeliveryPayloadProtector deliveryProtector,
        StorageContext database,
        IOptions<JWTSettings> jwtSettings,
        ILogger<AccountRepo> logger,
        IUserSecretHasher userSecretHasher)
    {
        _deliveryProtector = deliveryProtector;
        _activeDatabase = database;
        _jwtSettings = jwtSettings.Value;
        _logger = logger;
        _userSecretHasher = userSecretHasher;
    }

    internal static IntraAccount MapCredentialColumns(
        Guid accountId,
        byte[] hashedPassword,
        string webKey,
        byte[]? refreshToken,
        short refreshes,
        short limit,
        Instant createdOn,
        Period? lifespan,
        byte[] saltOne,
        byte[] siv,
        byte[] nonce,
        Instant? unlockWhen,
        short loginFailures,
        VerificationStatus verifyStatus,
        FeatureSet features,
        string? twoFactorAccessToken,
        TwoFactorAuthMethod twoFactorAuthMethod,
        short twoAuthUsage,
        Instant? cutOff = null,
        string? activeAccessTokenHash = null,
        Guid? accountSecurityStamp = null)
    {
        return new IntraAccount(
            accountId: accountId,
            hashedPassword: EnsureNonEmptyBytes(hashedPassword, nameof(IntraAccount.hashedPassword)),
            webKey: webKey,
            refreshToken: refreshToken,
            refreshes: refreshes,
            limit: limit,
            createdOn: createdOn,
            lifespan: lifespan,
            saltOne: EnsureByteLength(saltOne, AccountCryptoSizes.SaltOneBytes, nameof(IntraAccount.saltOne)),
            siv: EnsureByteLength(siv, AccountCryptoSizes.SivBytes, nameof(IntraAccount.siv)),
            nonce: EnsureByteLength(nonce, AccountCryptoSizes.NonceBytes, nameof(IntraAccount.nonce)),
            unlockWhen: unlockWhen,
            loginFailures: loginFailures,
            verifyStatus: verifyStatus,
            features: features,
            twoFactorAccessToken: twoFactorAccessToken,
            twoFactorAuthMethod: twoFactorAuthMethod,
            twoAuthUsage: twoAuthUsage,
            cutOff: cutOff,
            activeAccessTokenHash: activeAccessTokenHash,
            accountSecurityStamp: accountSecurityStamp);
    }


    internal static byte[] EnsureByteLength(byte[] value, int expectedLength, string fieldName)
    {
        if (value.Length != expectedLength)
        {
            throw new DataException($"{fieldName} expected {expectedLength} bytes but received {value.Length} bytes.");
        }

        return value;
    }

    internal static byte[] EnsureNonEmptyBytes(byte[] value, string fieldName)
    {
        if (value.Length == 0)
        {
            throw new DataException($"{fieldName} cannot be empty.");
        }

        return value;
    }


    private static byte[] ReadVariableBytes(NpgsqlDataReader reader, int ordinal, string fieldName)
    {
        if (reader.IsDBNull(ordinal))
        {
            throw new DataException($"{fieldName} cannot be null.");
        }

        byte[] value = reader.GetFieldValue<byte[]>(ordinal);
        if (value.Length <= 0)
        {
            throw new DataException($"{fieldName} cannot be empty.");
        }

        return value;
    }


    private static byte[] ReadFixedBytes(NpgsqlDataReader reader, int ordinal, int expectedLength, string fieldName)
    {
        if (reader.IsDBNull(ordinal))
        {
            throw new DataException($"{fieldName} cannot be null.");
        }

        byte[] value = reader.GetFieldValue<byte[]>(ordinal);
        if (value.Length != expectedLength)
        {
            throw new DataException($"{fieldName} expected {expectedLength} bytes but received {value.Length} bytes.");
        }

        return value;
    }

    private static string? ReadActiveAccessTokenHash(NpgsqlDataReader reader, byte[]? refreshToken)
    {
        const int ActiveAccessTokenHashOrdinal = 20;

        if (reader.FieldCount <= ActiveAccessTokenHashOrdinal)
        {
            if (refreshToken is not null)
            {
                throw new DataException("Credential lookup result for an active account session must include active_access_token_hash.");
            }

            return null;
        }

        if (reader.IsDBNull(ActiveAccessTokenHashOrdinal))
        {
            if (refreshToken is not null)
            {
                throw new DataException("Credential lookup result for an active account session returned a null active_access_token_hash.");
            }

            return null;
        }

        return reader.GetString(ActiveAccessTokenHashOrdinal);
    }

    private static Instant? ReadCredentialCutOff(NpgsqlDataReader reader)
    {
        const int CutOffOrdinal = 18;

        if (reader.FieldCount <= CutOffOrdinal)
        {
            throw new DataException("Credential lookup result must include account cut_off.");
        }

        return reader.IsDBNull(CutOffOrdinal) ? null : reader.GetFieldValue<Instant>(CutOffOrdinal);
    }

    private static Guid ReadCredentialAccountSecurityStamp(NpgsqlDataReader reader)
    {
        const int AccountSecurityStampOrdinal = 19;

        if (reader.FieldCount <= AccountSecurityStampOrdinal || reader.IsDBNull(AccountSecurityStampOrdinal))
        {
            throw new DataException("Credential lookup result must include account_security_stamp.");
        }

        Guid accountSecurityStamp = reader.GetGuid(AccountSecurityStampOrdinal);
        if (accountSecurityStamp == Guid.Empty)
        {
            throw new DataException("Credential lookup result returned an empty account_security_stamp.");
        }

        return accountSecurityStamp;
    }

    public async Task<(long?, HttpMessage, string?)> SetupAccount(Account single, string verifyKeyHash, Period verificationExpiration, AccountSetupAction step, DeliveryIntent deliveryIntent, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            string functionName = step == AccountSetupAction.BOTH
                ? SetupAccountBothFunction
                : SetupAccountEmailFunction;

            string[] parameterNames = step == AccountSetupAction.BOTH
                ? new[] { "accountId", "username", "emailAddress", "webKey", "hashedPassword", "saltOne", "siv", "nonce", "country", "verifyKeyHash", "createdOn", "verificationExpiration" }
                : new[] { "accountId", "emailAddress", "webKey", "hashedPassword", "saltOne", "siv", "nonce", "country", "verifyKeyHash", "createdOn", "verificationExpiration" };

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.SetupAccount", new { single, verifyKeyHash, verificationExpiration, step, deliveryIntent }, single.accountId, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(functionName, conn, tran, parameterNames);

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = single.accountId;
            if (step == AccountSetupAction.BOTH)
            {
                command.Parameters.Add("@username", NpgsqlDbType.Text).Value = single.username!;
            }

            command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = single.emailAddress;
            command.Parameters.Add("@webKey", WebKeyDbType).Value = single.webKey;
            command.Parameters.Add("@hashedPassword", HashedPasswordDbType).Value = single.hashedPassword;
            command.Parameters.Add("@saltOne", SaltOneDbType).Value = single.saltOne;
            command.Parameters.Add("@siv", SivDbType).Value = single.siv;
            command.Parameters.Add("@nonce", NonceDbType).Value = single.nonce;
            command.Parameters.Add("@country", NpgsqlDbType.Smallint).Value = (short)single.country;
            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = verifyKeyHash;
            command.Parameters.Add("@createdOn", InstantDbType).Value = single.createdOn;
            command.Parameters.Add("@verificationExpiration", NpgsqlDbType.Interval).Value = verificationExpiration;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    long? verificationIndex = dr.IsDBNull(0) ? null : dr.GetInt64(0);
                    HttpMessage outcome = (HttpMessage)dr.GetInt16(1);
                    await dr.DisposeAsync();
                    if(outcome==HttpMessage.ACCOUNT_CREATION_SUCCESSED && verificationIndex is long index)
                    {
                        await using var stampCommand=new NpgsqlCommand("select security_stamp from accounts where account_id=@id",conn,tran);
                        stampCommand.Parameters.AddWithValue("id",single.accountId);
                        Guid stamp=(Guid)(await stampCommand.ExecuteScalarAsync(cancellationToken))!;
                        var intent=deliveryIntent with { AccountStamp=stamp, Metadata=new {mode="start",verificationIndex=index} };
                        if(intent.AccountId!=single.accountId || intent.Purpose!="verify" || intent.ProofHash!=verifyKeyHash)
                            throw new InvalidOperationException("Signup delivery binding mismatch");
                        var queued=await DeliveryOutboxRepo.StageInAsync(conn,tran,_deliveryProtector.Protect(intent),cancellationToken);
                        if(!queued.Result)throw new InvalidOperationException("Signup delivery staging failed");
                    }
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync((verificationIndex, outcome, (string?)null));
                    return (verificationIndex, outcome, null);
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("SetupAccount");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, RepositoryLogScopes.AccountSetup(step, single.accountId, single.emailAddress, single.username), stage: dependencyStage);
                return (null, HttpMessage.ACCOUNT_CREATION_FAILED, ex.StackTrace);
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(SetupAccount), stage: dependencyStage);
            return (null, HttpMessage.ACCOUNT_CREATION_FAILED, null);
        }
    }

    public async Task<bool?> StartAccountVerification(Guid accountGuid, long? verificationIndex, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            if (verificationIndex is null)
            {
                return false;
            }

            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.StartAccountVerification", new { accountGuid, verificationIndex }, accountGuid, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(StartVerifyAccountFunction, conn, tran, "accountGuid", "verificationIndex");

            command.Parameters.Add("@accountGuid", NpgsqlDbType.Uuid).Value = accountGuid;
            command.Parameters.Add("@verificationIndex", NpgsqlDbType.Bigint).Value = verificationIndex.Value;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                bool result = await ReadBooleanProcedureResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountGuid, verificationIndex }, stage: dependencyStage);
                return null;
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(StartAccountVerification), stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountVerificationResendResult?> ResendAccountVerification(string emailAddress, string verifyKeyHash, Period verificationExpiration, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.ResendAccountVerification", new { emailAddress, verifyKeyHash, verificationExpiration }, null, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(ResendVerifyAccountFunction, conn, tran, "emailAddress", "verifyKeyHash", "verificationExpiration");

            command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = emailAddress;
            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = verifyKeyHash;
            command.Parameters.Add("@verificationExpiration", NpgsqlDbType.Interval).Value = verificationExpiration;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    bool result = !dr.IsDBNull(0) && dr.GetBoolean(0);
                    string code = dr.IsDBNull(1) ? "UNKNOWN" : dr.GetString(1);
                    string? targetEmailAddress = dr.IsDBNull(2) ? null : dr.GetString(2);
                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await operation.CommitAsync(new AccountVerificationResendResult(result, code, targetEmailAddress));
                    return new AccountVerificationResendResult(result, code, targetEmailAddress);
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                throw DependencyUnavailableException.InvalidResponse("command_result");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, RepositoryLogScopes.EmailAddressScope(emailAddress), stage: dependencyStage);
                return null;
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(ResendAccountVerification), stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountVerification?> VerifyAccountForUse(string verifyKey, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            string verifyKeyHash = AccountVerificationTokenUtility.HashToken(verifyKey);

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection(cancellationToken);
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(VerifyAccountForUseProcedure, conn, tran, "verifyKeyHash");

            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = verifyKeyHash;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                if (await dr.ReadAsync(cancellationToken))
                {
                    Instant? sentWhen = dr.IsDBNull(3) ? null : dr.GetFieldValue<Instant>(3);
                    Period? expiration = dr.IsDBNull(4) ? null : dr.GetFieldValue<Period>(4);
                    var verification = new AccountVerification(dr.GetGuid(0), dr.GetString(1), (VerificationStatus)dr.GetInt16(2), sentWhen, expiration) { proofVersion = dr.GetGuid(5), accountSecurityStamp = dr.GetGuid(6) };
                    await dr.DisposeAsync();
                    dependencyStage = DependencyStage.Commit;
                    await tran.CommitAsync(cancellationToken);
                    return verification;
                }

                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await tran.CommitAsync(cancellationToken);
                return null;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, stage: dependencyStage);
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(VerifyAccountForUse), stage: dependencyStage);
            return null;
        }
    }

    public async Task<bool?> AccountPassedVerification(AccountVerification record, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.AccountPassedVerification", new { record }, record.accountId, record.accountSecurityStamp, record.proofVersion.ToString("D"), cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(CompleteVerifyAccountProcedure, conn, tran, "accountId", "verifyKeyHash", "proofVersion", "accountSecurityStamp");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = record.accountId;
            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = record.verifyKey;
            command.Parameters.Add("@proofVersion", NpgsqlDbType.Uuid).Value = record.proofVersion;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = record.accountSecurityStamp;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                bool result = await ReadBooleanProcedureResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { record.accountId }, stage: dependencyStage);
                return null;
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(AccountPassedVerification), stage: dependencyStage);
            return null;
        }
    }

    public async Task<bool?> AccountVerificationExpired(AccountVerification record, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.AccountVerificationExpired", new { record }, record.accountId, record.accountSecurityStamp, record.proofVersion.ToString("D"), cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(ExpireVerifyAccountProcedure, conn, tran, "accountId", "verifyKeyHash", "proofVersion", "accountSecurityStamp");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = record.accountId;
            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = record.verifyKey;
            command.Parameters.Add("@proofVersion", NpgsqlDbType.Uuid).Value = record.proofVersion;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = record.accountSecurityStamp;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                bool result = await ReadBooleanProcedureResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { record.accountId }, stage: dependencyStage);
                return null;
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(AccountVerificationExpired), stage: dependencyStage);
            return null;
        }
    }

    public async Task<HttpMessage?> CheckSignupAvailability(string email, string? username, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var connection = await _activeDatabase.CreateConnection(cancellationToken);
            await using var command = new NpgsqlCommand("select exists(select 1 from accounts where lower(email_address)=lower(@email)),exists(select 1 from accounts where @username is not null and lower(username)=lower(@username))", connection);
            command.Parameters.AddWithValue("email", email);
            command.Parameters.Add("username", NpgsqlDbType.Text).Value = (object?)username ?? DBNull.Value;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) throw DependencyUnavailableException.InvalidResponse(nameof(CheckSignupAvailability));
            bool emailExists = reader.GetBoolean(0), nameExists = reader.GetBoolean(1);
            return (emailExists, nameExists) switch
            {
                (true, true) => HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME_EMAIL,
                (true, false) => HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL,
                (false, true) => HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME,
                _ => null
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is NpgsqlException or TimeoutException or OperationCanceledException)
        { throw DependencyUnavailableException.Database(nameof(CheckSignupAvailability), DependencyStage.Read, ex); }
    }
    public async Task<bool> UpgradePasswordHash(Guid account, Guid stamp, byte[] oldHash, byte[] newHash, CancellationToken cancellationToken = default)
    {
        AccountSecurityStampGuard.Require(stamp);
        await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.UpgradePasswordHash",
            new { account, stamp, oldHash, newHash }, account, stamp, null, cancellationToken);
        await using var command = new NpgsqlCommand("select upgrade_account_password_hash(@account,@stamp,@old,@new)", operation.Connection, operation.Transaction);
        command.Parameters.AddWithValue("account", account); command.Parameters.AddWithValue("stamp", stamp);
        command.Parameters.AddWithValue("old", oldHash); command.Parameters.AddWithValue("new", newHash);
        bool upgraded = (bool)(await command.ExecuteScalarAsync(operation.CancellationToken))!;
        await operation.CommitAsync(upgraded); return upgraded;
    }
    public async Task<CredentialLookupResult> GetCredentials(AuthenticateLogin single, AccountLoginAction action, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            string functionName;
            string[] parameterNames;

            if (action == AccountLoginAction.BOTH)
            {
                functionName = "check_account_both_creds";
                parameterNames = new[] { "username", "emailAddress" };
            }
            else if (action == AccountLoginAction.USERNAME)
            {
                functionName = "check_account_username_creds";
                parameterNames = new[] { "username" };
            }
            else if (action == AccountLoginAction.EMAIL)
            {
                functionName = "check_account_emailaddress_creds";
                parameterNames = new[] { "emailAddress" };
            }
            else
            {
                return CredentialLookupResult.Failed();
            }

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection(cancellationToken);
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(functionName, conn, tran, parameterNames);

            if (action == AccountLoginAction.BOTH || action == AccountLoginAction.USERNAME)
            {
                command.Parameters.Add("@username", NpgsqlDbType.Text).Value = single.username;
            }

            if (action == AccountLoginAction.BOTH || action == AccountLoginAction.EMAIL)
            {
                command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = single.emailAddress;
            }

            try
            {
                CredentialLookupResult result;
                dependencyStage = DependencyStage.Execute;
                await using (NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken))
                {
                            dependencyStage = DependencyStage.Read;
                    if (await dr.ReadAsync(cancellationToken))
                    {
                        byte[] hashedPassword = ReadVariableBytes(dr, 1, nameof(IntraAccount.hashedPassword));

                        byte[]? refreshToken = null;
                        if (!await dr.IsDBNullAsync(3))
                        {
                            refreshToken = ReadFixedBytes(dr, 3, _jwtSettings.RefreshTokenBytes, nameof(IntraAccount.refreshToken));
                        }

                        Period? lifespan = dr.IsDBNull(7) ? null : dr.GetFieldValue<Period>(7);

                        byte[] saltOneBuffer = ReadFixedBytes(dr, 8, AccountCryptoSizes.SaltOneBytes, nameof(IntraAccount.saltOne));
                        byte[] sivBuffer = ReadFixedBytes(dr, 9, AccountCryptoSizes.SivBytes, nameof(IntraAccount.siv));
                        byte[] nonceBuffer = ReadFixedBytes(dr, 10, AccountCryptoSizes.NonceBytes, nameof(IntraAccount.nonce));

                        Instant? unlockWhen = dr.IsDBNull(11) ? null : dr.GetFieldValue<Instant>(11);
                        string? twoFactorAccessToken = dr.IsDBNull(15) ? null : dr.GetString(15);
                        Instant? cutOff = ReadCredentialCutOff(dr);
                        Guid accountSecurityStamp = ReadCredentialAccountSecurityStamp(dr);
                        string? activeAccessTokenHash = ReadActiveAccessTokenHash(dr, refreshToken);

                        IntraAccount mapped = MapCredentialColumns(
                            accountId: dr.GetGuid(0),
                            hashedPassword: hashedPassword,
                            webKey: dr.GetString(2),
                            refreshToken: refreshToken,
                            refreshes: dr.GetInt16(4),
                            limit: dr.GetInt16(5),
                            createdOn: dr.GetFieldValue<Instant>(6),
                            lifespan: lifespan,
                            saltOne: saltOneBuffer,
                            siv: sivBuffer,
                            nonce: nonceBuffer,
                            unlockWhen: unlockWhen,
                            loginFailures: dr.GetInt16(12),
                            verifyStatus: (VerificationStatus)dr.GetInt16(13),
                            features: (FeatureSet)dr.GetInt16(14),
                            twoFactorAccessToken: twoFactorAccessToken,
                            twoFactorAuthMethod: (TwoFactorAuthMethod)dr.GetInt16(16),
                            twoAuthUsage: dr.GetInt16(17),
                            cutOff: cutOff,
                            activeAccessTokenHash: activeAccessTokenHash,
                            accountSecurityStamp: accountSecurityStamp);

                        mapped.entitlements = treehammock.DataLayer.Entitlements.EntitlementProjection.Parse(dr.GetString(21), mapped.accountId);
                        mapped.features = mapped.entitlements.Features;
                        result = CredentialLookupResult.Found(mapped);
                    }
                    else
                    {
                        result = CredentialLookupResult.NotFound();
                    }
                }

                if (result.Account is { } credentialAccount)
                    await ReadLoginAttemptVersion(conn, tran, credentialAccount, cancellationToken);
                dependencyStage = DependencyStage.Commit;

                await tran.CommitAsync(cancellationToken);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { action }, stage: dependencyStage);
                return CredentialLookupResult.Failed();
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(GetCredentials), stage: dependencyStage);
            return CredentialLookupResult.Failed();
        }
    }

    public Period FindLockoutPeriod(short? loginFailures)
    {
        PeriodBuilder lockoutPeriod = new PeriodBuilder();
        if (loginFailures != null)
        {
            lockoutPeriod.Hours = (long)((loginFailures + 1) * 2);
        }
        return lockoutPeriod.Build();
    }


    public async Task<TwoFactorDetailsLookupResult> GetTwoFactorDetails(Guid accountId, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            var methods = new List<TwoFactorAuthMethod>();
            var userAuthIds = new List<string>();
            var phoneNumbers = new List<string>();
            var phoneCountryCodes = new List<string>();
            var emailAddresses = new List<string>();

            await using (NpgsqlConnection conn = await _activeDatabase.CreateConnection(cancellationToken))
            {
                dependencyStage = DependencyStage.Begin;
                await using (NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken))
                {
                    await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand("get_twofactor_details", conn, tran, "accountId"))
                    {
                        command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;

                        try
                        {
                            dependencyStage = DependencyStage.Execute;
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                            dependencyStage = DependencyStage.Read;
                            while (await dr.ReadAsync(cancellationToken))
                            {
                                var method = (TwoFactorAuthMethod)dr.GetInt16(0);
                                methods.Add(method);

                                switch (method)
                                {
                                    case TwoFactorAuthMethod.AUTHENTICATOR_APP:
                                        AddIfNotBlank(userAuthIds, ReadOptionalString(dr, 1));
                                        break;
                                    case TwoFactorAuthMethod.SMS_KEY:
                                        AddIfNotBlank(phoneNumbers, ReadOptionalString(dr, 2));
                                        AddIfNotBlank(phoneCountryCodes, ReadOptionalString(dr, 3));
                                        break;
                                    case TwoFactorAuthMethod.EMAIL:
                                        AddIfNotBlank(emailAddresses, ReadOptionalString(dr, 4));
                                        break;
                                }
                            }

                            await dr.DisposeAsync();
                            dependencyStage = DependencyStage.Commit;
                            await tran.CommitAsync(cancellationToken);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                            await RollbackAndLogAsync(tran, ex, command.CommandText, stage: dependencyStage);
                            return TwoFactorDetailsLookupResult.Failed();
                        }
                        finally
                        {
                            await conn.CloseAsync();
                        }
                    }
                }
            }

            if (methods.Count == 0)
            {
                return TwoFactorDetailsLookupResult.NotConfigured();
            }

            return TwoFactorDetailsLookupResult.Found(new TwoFactorDetails(methods, userAuthIds, phoneNumbers, phoneCountryCodes, emailAddresses));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(GetTwoFactorDetails), stage: dependencyStage);
            return TwoFactorDetailsLookupResult.Failed();
        }
    }

    private static string ReadOptionalString(NpgsqlDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);
    }

    private static void AddIfNotBlank(List<string> values, string value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            values.Add(value);
        }
    }

    public async Task<bool?> SetLockOut(Guid accountGuid, short? loginFailures, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            bool? result = false;
            await using (var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.SetLockOut", new { accountGuid, loginFailures }, accountGuid, null, null, cancellationToken))
            {
                cancellationToken = operation.CancellationToken;
                NpgsqlConnection conn = operation.Connection;
                dependencyStage = DependencyStage.Begin;
                {
                    NpgsqlTransaction tran = operation.Transaction;
                    await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand("set_account_lockout", conn, tran, "accountGuid", "expiration"))
                    {
                        command.Parameters.Add("@accountGuid", NpgsqlDbType.Uuid).Value = accountGuid;
                        command.Parameters.Add("@expiration", NpgsqlDbType.Interval).Value = FindLockoutPeriod(loginFailures);

                        try
                        {
                            dependencyStage = DependencyStage.Execute;
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                            dependencyStage = DependencyStage.Read;
                            result = await ReadBooleanProcedureResultAsync(dr, cancellationToken: cancellationToken);
                            await dr.DisposeAsync();
                            dependencyStage = DependencyStage.Commit;
                            await operation.CommitAsync(result!);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                            await RollbackAndLogAsync(tran, ex, command.CommandText, stage: dependencyStage);
                            result = null;
                        }
                        finally
                        {
                            // The operation scope owns connection disposal and reconciliation.
                        }
                    }
                }
            }

            return result;
            }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(SetLockOut), stage: dependencyStage);
            return null;
        }
    }

    public async Task<bool?> RemoveLockOut(Guid accountGuid, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            bool? result = false;
            await using (var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.RemoveLockOut", new { accountGuid }, accountGuid, null, null, cancellationToken))
            {
                cancellationToken = operation.CancellationToken;
                NpgsqlConnection conn = operation.Connection;
                dependencyStage = DependencyStage.Begin;
                {
                    NpgsqlTransaction tran = operation.Transaction;
                   await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand("remove_account_lockout", conn, tran, "accountGuid"))
                   {
                        command.Parameters.Add("@accountGuid", NpgsqlDbType.Uuid).Value = accountGuid;

                        try
                        {
                            dependencyStage = DependencyStage.Execute;
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                            dependencyStage = DependencyStage.Read;
                            result = await ReadBooleanProcedureResultAsync(dr, cancellationToken: cancellationToken);
                            await dr.DisposeAsync();
                            dependencyStage = DependencyStage.Commit;
                            await operation.CommitAsync(result!);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                            await RollbackAndLogAsync(tran, ex, command.CommandText, stage: dependencyStage);
                            result = null;
                        }
                        finally
                        {
                            // The operation scope owns connection disposal and reconciliation.
                        }
                    }
                }
            }

            return result;
            }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(RemoveLockOut), stage: dependencyStage);
            return null;
        }
    }

    public async Task<bool?> SetLoginFailures(Guid accountGuid, int failures, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            bool? result = false;
            await using (var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.SetLoginFailures", new { accountGuid, failures }, accountGuid, null, null, cancellationToken))
            {
                cancellationToken = operation.CancellationToken;
                NpgsqlConnection conn = operation.Connection;
                dependencyStage = DependencyStage.Begin;
                {
                    NpgsqlTransaction tran = operation.Transaction;
                    await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand("set_account_login_failures", conn, tran, "accountGuid", "failures"))
                    {
                        command.Parameters.Add("@accountGuid", NpgsqlDbType.Uuid).Value = accountGuid;
                        command.Parameters.Add("@failures", NpgsqlDbType.Smallint).Value = (short)Math.Clamp(failures, short.MinValue, short.MaxValue);

                        try
                        {
                            dependencyStage = DependencyStage.Execute;
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                            dependencyStage = DependencyStage.Read;
                            result = await ReadBooleanProcedureResultAsync(dr, cancellationToken: cancellationToken);
                            await dr.DisposeAsync();
                            dependencyStage = DependencyStage.Commit;
                            await operation.CommitAsync(result!);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                            await RollbackAndLogAsync(tran, ex, command.CommandText, stage: dependencyStage);
                            result = null;
                        }
                        finally
                        {
                            // The operation scope owns connection disposal and reconciliation.
                        }
                    }
                }
            }

            return result;
            }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(SetLoginFailures), stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountAdjustResult?> ModifyUsername(Guid accountId, Guid accountSecurityStamp, string username, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.ModifyUsername", new { accountId, accountSecurityStamp, username }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                EditAccountUsernameFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "username");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@username", NpgsqlDbType.Text).Value = username;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                AccountAdjustResult result = await ReadAccountAdjustResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, RepositoryLogScopes.AccountUsername(accountId, username), stage: dependencyStage);
                return null;
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(ModifyUsername), RepositoryLogScopes.AccountUsername(accountId, username), stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountAdjustResult?> RequestEmailChange(
        Guid accountId,
        Guid accountSecurityStamp,
        string newEmailAddress,
        string verifyKeyHash,
        Instant expiration, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.RequestEmailChange", new { accountId, accountSecurityStamp, newEmailAddress, verifyKeyHash, expiration }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                RequestAccountEmailChangeFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "newEmailAddress",
                "verifyKeyHash",
                "expiration");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@newEmailAddress", NpgsqlDbType.Text).Value = newEmailAddress;
            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = verifyKeyHash;
            command.Parameters.Add("@expiration", InstantDbType).Value = expiration;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                AccountAdjustResult result = await ReadAccountAdjustResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, RepositoryLogScopes.AccountEmailAddress(accountId, newEmailAddress), stage: dependencyStage);
                return null;
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(RequestEmailChange), RepositoryLogScopes.AccountEmailAddress(accountId, newEmailAddress), stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountAdjustResult?> CancelEmailChangeRequest(
        Guid accountId,
        Guid accountSecurityStamp,
        string verifyKeyHash, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.CancelEmailChangeRequest", new { accountId, accountSecurityStamp, verifyKeyHash }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                CancelAccountEmailChangeRequestFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "verifyKeyHash");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = verifyKeyHash;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                AccountAdjustResult result = await ReadAccountAdjustResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId }, stage: dependencyStage);
                return null;
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(CancelEmailChangeRequest), new { accountId }, stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountAdjustResult?> CompleteEmailChange(string verifyKeyHash, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.CompleteEmailChange", new { verifyKeyHash }, null, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                CompleteAccountEmailChangeFunction,
                conn,
                tran,
                "verifyKeyHash");

            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = verifyKeyHash;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                AccountAdjustResult result = await ReadAccountAdjustResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, stage: dependencyStage);
                return null;
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(CompleteEmailChange), stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountDeleteCommandResult?> AdmitAccountDelete(Guid accountId,Guid stamp,Guid admissionId,string proofHash,Instant expires,Period cooldown,Period window,short maxRequests,treehammock.DataLayer.Security.SensitiveActionGrant grant,CancellationToken cancellationToken=default)
    {
        await using var operation=await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.AdmitAccountDelete",new {accountId,stamp,admissionId,proofHash,expires,cooldown,window,maxRequests,grant},accountId,stamp,null,cancellationToken);
        await using var command=new NpgsqlCommand("select * from cor18_admit_delete(@account,@stamp,@id,@hash,@expires,@cooldown,@window,@max,@session,@grant,@target)",operation.Connection,operation.Transaction);
        command.Parameters.AddWithValue("account",NpgsqlDbType.Uuid,accountId);command.Parameters.AddWithValue("stamp",NpgsqlDbType.Uuid,stamp);command.Parameters.AddWithValue("id",NpgsqlDbType.Uuid,admissionId);
        command.Parameters.AddWithValue("hash",NpgsqlDbType.Text,proofHash);command.Parameters.AddWithValue("expires",InstantDbType,expires);command.Parameters.AddWithValue("cooldown",NpgsqlDbType.Interval,cooldown);command.Parameters.AddWithValue("window",NpgsqlDbType.Interval,window);command.Parameters.AddWithValue("max",NpgsqlDbType.Smallint,maxRequests);
        command.Parameters.AddWithValue("session",NpgsqlDbType.Text,grant.SessionHash);command.Parameters.AddWithValue("grant",NpgsqlDbType.Text,grant.TokenHash);command.Parameters.AddWithValue("target",NpgsqlDbType.Text,grant.TargetHash);
        await using var dr=await command.ExecuteReaderAsync(operation.CancellationToken);var result=await ReadAccountDeleteRequestResultAsync(dr,operation.CancellationToken);await dr.DisposeAsync();await operation.CommitAsync(result);return result;
    }

    public async Task<AccountDeleteCommandResult?> RequestAccountDelete(
        Guid accountId,
        Guid accountSecurityStamp,
        string? passPhraseHash,
        string deleteTokenHash,
        Instant expiration,
        Period requestCooldown,
        Period requestWindow,
        short maxRequestsPerWindow, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.RequestAccountDelete", new { accountId, accountSecurityStamp, passPhraseHash, deleteTokenHash, expiration, requestCooldown, requestWindow, maxRequestsPerWindow }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                RequestAccountDeleteFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "passPhraseHash",
                "deleteTokenHash",
                "expiration",
                "requestCooldown",
                "requestWindow",
                "maxRequestsPerWindow");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@passPhraseHash", NpgsqlDbType.Text).Value = DbValue(passPhraseHash);
            command.Parameters.Add("@deleteTokenHash", NpgsqlDbType.Text).Value = deleteTokenHash;
            command.Parameters.Add("@expiration", InstantDbType).Value = expiration;
            command.Parameters.Add("@requestCooldown", NpgsqlDbType.Interval).Value = requestCooldown;
            command.Parameters.Add("@requestWindow", NpgsqlDbType.Interval).Value = requestWindow;
            command.Parameters.Add("@maxRequestsPerWindow", NpgsqlDbType.Smallint).Value = maxRequestsPerWindow;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                AccountDeleteCommandResult result = await ReadAccountDeleteRequestResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId }, stage: dependencyStage);
                return null;
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(RequestAccountDelete), new { accountId }, stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountDeleteCommandResult?> CancelAccountDeleteRequest(
        Guid accountId,
        Guid accountSecurityStamp,
        string deleteTokenHash, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.CancelAccountDeleteRequest", new { accountId, accountSecurityStamp, deleteTokenHash }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                CancelAccountDeleteRequestFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "deleteTokenHash");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@deleteTokenHash", NpgsqlDbType.Text).Value = deleteTokenHash;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                AccountDeleteCommandResult result = await ReadAccountDeleteRequestResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId }, stage: dependencyStage);
                return null;
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(CancelAccountDeleteRequest), new { accountId }, stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountDeleteCommandResult?> VerifyDeleteAccountToken(string deleteTokenHash, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.VerifyDeleteAccountToken", new { deleteTokenHash }, null, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                VerifyAccountDeleteTokenFunction,
                conn,
                tran,
                "deleteTokenHash");

            command.Parameters.Add("@deleteTokenHash", NpgsqlDbType.Text).Value = deleteTokenHash;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                AccountDeleteCommandResult result = await ReadAccountDeleteVerifyResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, stage: dependencyStage);
                return null;
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(VerifyDeleteAccountToken), stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountDeleteCommandResult?> FinalizeAccountDelete(Guid accountId,Guid accountSecurityStamp,string deleteTokenHash,string? passPhrase,short maxFailedFinalizeAttempts,Period finalizeLockout,CancellationToken cancellationToken=default,string? sessionHash=null)
    {
        AccountSecurityStampGuard.Require(accountSecurityStamp);
        if(string.IsNullOrWhiteSpace(sessionHash))return new(false,"ACCOUNT_DELETE_AUTHORITY_CHANGED");
        AccountDeleteFinalizePreparationResult snapshot;
        // No transaction/row lock or pooled connection is held during Argon2id verification.
        await using(var conn=await _activeDatabase.CreateConnection(cancellationToken))
        {
            await using var command=new NpgsqlCommand("select * from prepare_account_delete_finalize(@account,@stamp,@hash,@max,@lockout,@session)",conn);
            command.Parameters.AddWithValue("account",NpgsqlDbType.Uuid,accountId);command.Parameters.AddWithValue("stamp",NpgsqlDbType.Uuid,accountSecurityStamp);
            command.Parameters.AddWithValue("hash",NpgsqlDbType.Text,deleteTokenHash);command.Parameters.AddWithValue("max",NpgsqlDbType.Smallint,maxFailedFinalizeAttempts);
            command.Parameters.AddWithValue("lockout",NpgsqlDbType.Interval,finalizeLockout);command.Parameters.AddWithValue("session",NpgsqlDbType.Text,sessionHash);
            await using var reader=await command.ExecuteReaderAsync(cancellationToken);snapshot=await ReadAccountDeleteFinalizePreparationResultAsync(reader,cancellationToken);
        }
        if(!snapshot.Result)return new(false,snapshot.Code,snapshot.Workflow,null,snapshot.AccountId);
        bool satisfied=snapshot.Workflow!=DeletionWorkflow.PASS_PHRASE || (!string.IsNullOrWhiteSpace(passPhrase) && !string.IsNullOrWhiteSpace(snapshot.PassPhraseHash) && await _userSecretHasher.VerifyUserSecretAsync(passPhrase,snapshot.PassPhraseHash,cancellationToken));
        // The final receipt and conditional delete share one transaction. Snapshot identity/hash are CAS guards.
        await using var operation=await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.FinalizeAccountDelete",new {accountId,accountSecurityStamp,deleteTokenHash,snapshot.RequestId,snapshot.PassPhraseHash,satisfied,maxFailedFinalizeAttempts,finalizeLockout,sessionHash},accountId,accountSecurityStamp,snapshot.RequestId?.ToString(),cancellationToken);
        await using var commit=new NpgsqlCommand("select * from commit_account_delete_finalize(@account,@stamp,@hash,@satisfied,@max,@lockout,@request,@expectedHash,@session)",operation.Connection,operation.Transaction);
        commit.Parameters.AddWithValue("account",NpgsqlDbType.Uuid,accountId);commit.Parameters.AddWithValue("stamp",NpgsqlDbType.Uuid,accountSecurityStamp);
        commit.Parameters.AddWithValue("hash",NpgsqlDbType.Text,deleteTokenHash);commit.Parameters.AddWithValue("satisfied",NpgsqlDbType.Boolean,satisfied);
        commit.Parameters.AddWithValue("max",NpgsqlDbType.Smallint,maxFailedFinalizeAttempts);commit.Parameters.AddWithValue("lockout",NpgsqlDbType.Interval,finalizeLockout);
        commit.Parameters.AddWithValue("request",NpgsqlDbType.Uuid,DbValue(snapshot.RequestId));commit.Parameters.AddWithValue("expectedHash",NpgsqlDbType.Text,DbValue(snapshot.PassPhraseHash));commit.Parameters.AddWithValue("session",NpgsqlDbType.Text,sessionHash);
        await using var dr=await commit.ExecuteReaderAsync(operation.CancellationToken);var result=await ReadAccountDeleteFinalizeResultAsync(dr,operation.CancellationToken);await dr.DisposeAsync();
        await operation.CommitAsync(result);return result;
    }

    public async Task<AccountDeletePurgeResult?> PurgeExpiredDeleteStandby(Instant moment, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.PurgeExpiredDeleteStandby", new { moment }, null, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                PurgeExpiredDeleteStandbyFunction,
                conn,
                tran,
                "moment");

            command.Parameters.Add("@moment", InstantDbType).Value = moment;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                AccountDeletePurgeResult result = await ReadAccountDeletePurgeResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, stage: dependencyStage);
                return null;
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(PurgeExpiredDeleteStandby), stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountEmailChangePurgeResult?> PurgeExpiredAccountEmailChangeRequests(Instant moment, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.PurgeExpiredAccountEmailChangeRequests", new { moment }, null, null, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                PurgeExpiredAccountEmailChangeRequestsFunction,
                conn,
                tran,
                "moment");

            command.Parameters.Add("@moment", InstantDbType).Value = moment;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                AccountEmailChangePurgeResult result = await ReadAccountEmailChangePurgeResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, stage: dependencyStage);
                return null;
            }
            finally
            {
                // The operation scope owns connection disposal and reconciliation.
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(PurgeExpiredAccountEmailChangeRequests), stage: dependencyStage);
            return null;
        }
    }

    public async Task<AccountViewResult?> ViewAccount(Guid accountId, Guid accountSecurityStamp, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection(cancellationToken);
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                ViewAccountFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                AccountViewResult result = await ReadAccountViewResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await tran.CommitAsync(cancellationToken);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId }, stage: dependencyStage);
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(ViewAccount), new { accountId }, stage: dependencyStage);
            return null;
        }
    }

    private void AddTwoFactorPromotionSessionParameters(
        NpgsqlCommand command,
        Guid accountId,
        string expectedPreAuthAccessTokenHash,
        Guid accountSecurityStamp,
        string newAccessTokenHash,
        Session newSession)
    {
        command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
        command.Parameters.Add("@expectedTwoFactorAccessToken", NpgsqlDbType.Text).Value = expectedPreAuthAccessTokenHash;
        command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = AccountSecurityStampGuard.Require(accountSecurityStamp);
        command.Parameters.Add("@newAccessTokenHash", SessionRepo.AccessTokenHashDbType).Value = newAccessTokenHash;
        command.Parameters.Add("@refreshToken", RefreshTokenDbType).Value = newSession.refreshToken;
        command.Parameters.Add("@refreshes", NpgsqlDbType.Smallint).Value = DbValue(newSession.refreshes);
        command.Parameters.Add("@limit", NpgsqlDbType.Smallint).Value = DbValue(newSession.limit);
        command.Parameters.Add("@createdOn", InstantDbType).Value = newSession.createdOn;
        command.Parameters.Add("@sessionLifespan", NpgsqlDbType.Interval).Value = DbValue(newSession.sessionLifespan);
        command.Parameters.Add("@accessExpiration", InstantDbType).Value = newSession.accessExpiration;
        command.Parameters.Add("@sessionExpiration", InstantDbType).Value = newSession.sessionExpiration;
        command.Parameters.Add("@cutOff", InstantDbType).Value = DbValue(newSession.cutOff);
        command.Parameters.Add("@features", NpgsqlDbType.Smallint).Value = (short)newSession.features;
        command.Parameters.Add("@securityStamp", NpgsqlDbType.Uuid).Value = newSession.securityStamp;
    }


    internal static async Task<TwoFactorChallengeCommandResult> ReadTwoFactorChallengeCommandResultAsync(NpgsqlDataReader reader, CancellationToken cancellationToken = default)
    {
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = reader.FieldCount > 0 && !reader.IsDBNull(0) && reader.GetBoolean(0);
        string code = reader.FieldCount > 1 && !reader.IsDBNull(1) ? reader.GetString(1) : "UNKNOWN";
        short attempts = reader.FieldCount > 2 && !reader.IsDBNull(2) ? reader.GetInt16(2) : (short)0;
        short resends = reader.FieldCount > 3 && !reader.IsDBNull(3) ? reader.GetInt16(3) : (short)0;
        Instant? challengeExpiration = reader.FieldCount > 4 && !reader.IsDBNull(4) ? reader.GetFieldValue<Instant>(4) : null;
        Instant? nextChallengeAllowedAt = reader.FieldCount > 5 && !reader.IsDBNull(5) ? reader.GetFieldValue<Instant>(5) : null;
        return new TwoFactorChallengeCommandResult(result, code, attempts, resends, challengeExpiration, nextChallengeAllowedAt);
    }

    internal static async Task<TwoFactorSetupCommandResult> ReadTwoFactorSetupCommandResultAsync(NpgsqlDataReader reader, CancellationToken cancellationToken = default)
    {
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = reader.GetBoolean(0);
        string code = reader.GetString(1);
        long? twoFactorIndex = reader.IsDBNull(2) ? null : reader.GetInt64(2);
        Instant? expiration = reader.IsDBNull(3) ? null : reader.GetFieldValue<Instant>(3);
        return new TwoFactorSetupCommandResult(result, code, twoFactorIndex, expiration);
    }

    public async Task<TwoFactorSetupCommandResult?> BeginTwoFactorSetup(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        string tokenHash,
        Instant createdOn,
        Instant expiration,
        string? emailAddress,
        string? phoneNumber,
        string? phoneCountryCode,
        string? authId,
        bool required, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.BeginTwoFactorSetup", new { accountId, accountSecurityStamp, method, tokenHash, createdOn, expiration, emailAddress, phoneNumber, phoneCountryCode, authId, required }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                BeginTwoFactorSetupFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "method",
                "tokenHash",
                "createdOn",
                "expiration",
                "emailAddress",
                "phoneNumber",
                "phoneCountryCode",
                "authId",
                "required");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@method", NpgsqlDbType.Smallint).Value = (short)method;
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;
            command.Parameters.Add("@createdOn", InstantDbType).Value = createdOn;
            command.Parameters.Add("@expiration", InstantDbType).Value = expiration;
            command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = DbValue(emailAddress);
            command.Parameters.Add("@phoneNumber", NpgsqlDbType.Text).Value = DbValue(phoneNumber);
            command.Parameters.Add("@phoneCountryCode", NpgsqlDbType.Text).Value = DbValue(phoneCountryCode);
            command.Parameters.Add("@authId", NpgsqlDbType.Text).Value = DbValue(authId);
            command.Parameters.Add("@required", NpgsqlDbType.Boolean).Value = required;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                TwoFactorSetupCommandResult result = await ReadTwoFactorSetupCommandResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId, method }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(BeginTwoFactorSetup), new { accountId, method }, stage: dependencyStage);
            return null;
        }
    }

    public async Task<DbCommandResult?> CancelTwoFactorSetup(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        string tokenHash, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.CancelTwoFactorSetup", new { accountId, accountSecurityStamp, method, tokenHash }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                CancelTwoFactorSetupFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "method",
                "tokenHash");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@method", NpgsqlDbType.Smallint).Value = (short)method;
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                DbCommandResult result = await SessionRepo.ReadDbCommandResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId, method }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(CancelTwoFactorSetup), new { accountId, method }, stage: dependencyStage);
            return null;
        }
    }

    internal static async Task<TwoFactorSetupVerificationCommandResult> ReadTwoFactorSetupVerificationCommandResultAsync(NpgsqlDataReader reader, CancellationToken cancellationToken = default)
    {
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = reader.FieldCount > 0 && !reader.IsDBNull(0) && reader.GetBoolean(0);
        string code = reader.FieldCount > 1 && !reader.IsDBNull(1) ? reader.GetString(1) : "UNKNOWN";
        short attempts = reader.FieldCount > 2 && !reader.IsDBNull(2) ? reader.GetInt16(2) : (short)0;
        Instant? expiration = reader.FieldCount > 3 && !reader.IsDBNull(3) ? reader.GetFieldValue<Instant>(3) : null;
        return new TwoFactorSetupVerificationCommandResult(result, code, attempts, expiration);
    }

    public async Task<TwoFactorSetupVerificationCommandResult?> VerifyTwoFactorSetup(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        string tokenHash,
        short maxAttempts,
        Instant moment, Guid enrollmentId, long setupVersion, Guid familyId, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.VerifyTwoFactorSetup", new { accountId, accountSecurityStamp, method, tokenHash, maxAttempts, moment, enrollmentId, setupVersion, familyId }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                VerifyTwoFactorSetupFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "method",
                "tokenHash",
                "maxAttempts",
                "now", "requestId", "requestVersion", "familyId");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@method", NpgsqlDbType.Smallint).Value = (short)method;
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;
            command.Parameters.Add("@maxAttempts", NpgsqlDbType.Smallint).Value = maxAttempts;
            command.Parameters.Add("@now", InstantDbType).Value = moment;
            command.Parameters.Add("@requestId", NpgsqlDbType.Uuid).Value = enrollmentId;
            command.Parameters.Add("@requestVersion", NpgsqlDbType.Bigint).Value = setupVersion;
            command.Parameters.Add("@familyId", NpgsqlDbType.Uuid).Value = familyId;

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                TwoFactorSetupVerificationCommandResult result = await ReadTwoFactorSetupVerificationCommandResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId, method }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(VerifyTwoFactorSetup), new { accountId, method }, stage: dependencyStage);
            return null;
        }
    }

    internal static async Task<TwoFactorMethodRemovalCommandResult> ReadTwoFactorMethodRemovalCommandResultAsync(NpgsqlDataReader reader, CancellationToken cancellationToken = default)
    {
        if (!await reader.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = reader.FieldCount > 0 && !reader.IsDBNull(0) && reader.GetBoolean(0);
        string code = reader.FieldCount > 1 && !reader.IsDBNull(1) ? reader.GetString(1) : "UNKNOWN";
        TwoFactorAuthMethod removedMethod = reader.FieldCount > 2 && !reader.IsDBNull(2)
            ? (TwoFactorAuthMethod)reader.GetInt16(2)
            : TwoFactorAuthMethod.NONE;
        List<TwoFactorAuthMethod> methods = ReadTwoFactorAuthMethods(reader, 3);
        List<TwoFactorAuthConfiguration> configurations = ReadTwoFactorAuthConfigurations(reader, 4);
        return new TwoFactorMethodRemovalCommandResult(result, code, removedMethod, methods, configurations);
    }

    public async Task<TwoFactorMethodRemovalCommandResult?> RemoveTwoFactorMethod(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        Instant moment, CancellationToken cancellationToken = default, treehammock.DataLayer.Security.SensitiveActionGrant? grant = null)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            if (grant is null || grant.CanonicalTarget != SensitiveActionTargets.RemoveMethod(method))
                return new(false, "SENSITIVE_ACTION_GRANT_REQUIRED", method, [], []);
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.RemoveTwoFactorMethod", new { accountId, accountSecurityStamp, method, moment, grant }, accountId, accountSecurityStamp, null, cancellationToken);
            cancellationToken = operation.CancellationToken;
            NpgsqlConnection conn = operation.Connection;
            NpgsqlTransaction tran = operation.Transaction;
            dependencyStage = DependencyStage.Begin;
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                RemoveTwoFactorMethodFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "method",
                "now", "grant_session", "grant_token", "grant_target");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@method", NpgsqlDbType.Smallint).Value = (short)method;
            command.Parameters.Add("@now", InstantDbType).Value = moment;
            command.Parameters.AddWithValue("grant_session", grant.SessionHash);
            command.Parameters.AddWithValue("grant_token", grant.TokenHash);
            command.Parameters.AddWithValue("grant_target", grant.TargetHash);

            try
            {
                dependencyStage = DependencyStage.Execute;
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                dependencyStage = DependencyStage.Read;
                TwoFactorMethodRemovalCommandResult result = await ReadTwoFactorMethodRemovalCommandResultAsync(dr, cancellationToken: cancellationToken);
                await dr.DisposeAsync();
                dependencyStage = DependencyStage.Commit;
                await operation.CommitAsync(result);
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId, method }, stage: dependencyStage);
                return null;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(RemoveTwoFactorMethod), new { accountId, method }, stage: dependencyStage);
            return null;
        }
    }


    public async Task<bool?> SuccessfulLogin(Guid accountId, Guid accountSecurityStamp, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            bool? result = false;
            await using (var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.SuccessfulLogin", new { accountId, accountSecurityStamp }, accountId, accountSecurityStamp, null, cancellationToken))
            {
                cancellationToken = operation.CancellationToken;
                NpgsqlConnection conn = operation.Connection;
                dependencyStage = DependencyStage.Begin;
                {
                    NpgsqlTransaction tran = operation.Transaction;
                    await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand("successful_login", conn, tran, "accountId", "accountSecurityStamp"))
                    {
                        command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
                        command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;

                        try
                        {
                            dependencyStage = DependencyStage.Execute;
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                            dependencyStage = DependencyStage.Read;
                            result = await ReadBooleanProcedureResultAsync(dr, cancellationToken: cancellationToken);
                            await dr.DisposeAsync();
                            dependencyStage = DependencyStage.Commit;
                            await operation.CommitAsync(result!);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                            await RollbackAndLogAsync(tran, ex, command.CommandText, stage: dependencyStage);
                            result = null;
                        }
                        finally
                        {
                            // The operation scope owns connection disposal and reconciliation.
                        }
                    }
                }
            }

            return result;
            }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(SuccessfulLogin), stage: dependencyStage);
            return null;
        }
    }

    public async Task<bool?> RotateAccountSecurityStamp(Guid accountId, CancellationToken cancellationToken = default)
    {
        DependencyStage dependencyStage = DependencyStage.Acquire;
        try
        {
            bool? result = false;
            await using (var operation = await _activeDatabase.SecurityOperations.BeginAsync("AccountRepo.RotateAccountSecurityStamp", new { accountId }, accountId, null, null, cancellationToken))
            {
                cancellationToken = operation.CancellationToken;
                NpgsqlConnection conn = operation.Connection;
                dependencyStage = DependencyStage.Begin;
                {
                    NpgsqlTransaction tran = operation.Transaction;
                    await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(RotateAccountSecurityStampProcedure, conn, tran, "accountId"))
                    {
                        command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;

                        try
                        {
                            dependencyStage = DependencyStage.Execute;
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                            dependencyStage = DependencyStage.Read;
                            result = await ReadBooleanProcedureResultAsync(dr, cancellationToken: cancellationToken);
                            await dr.DisposeAsync();
                            dependencyStage = DependencyStage.Commit;
                            await operation.CommitAsync(result!);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
                            await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId }, stage: dependencyStage);
                            result = null;
                        }
                        finally
                        {
                            // The operation scope owns connection disposal and reconciliation.
                        }
                    }
                }
            }

            return result;
            }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
            catch (Exception ex) {
            LogRepositoryFailure(ex, nameof(RotateAccountSecurityStamp), stage: dependencyStage);
            return null;
        }
    }

    internal static async Task<AccountAdjustResult> ReadAccountAdjustResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        Guid? accountSecurityStamp = null;
        string? emailAddress = null;

        for (int index = 2; index < dr.FieldCount; index++)
        {
            if (dr.IsDBNull(index))
            {
                continue;
            }

            string columnName = dr.GetName(index);
            if (columnName.Equals("account_security_stamp", StringComparison.OrdinalIgnoreCase))
            {
                accountSecurityStamp = dr.GetGuid(index);
                continue;
            }

            if (columnName.Equals("email_address", StringComparison.OrdinalIgnoreCase))
            {
                emailAddress = dr.GetString(index);
            }
        }

        return new AccountAdjustResult(result, code, accountSecurityStamp, emailAddress);
    }

    internal static async Task<AccountDeleteCommandResult> ReadAccountDeleteRequestResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        string? emailAddress = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetString(2) : null;
        DeletionWorkflow workflow = dr.FieldCount > 3 && !dr.IsDBNull(3)
            ? (DeletionWorkflow)dr.GetInt16(3)
            : DeletionWorkflow.NONE;

        return new AccountDeleteCommandResult(result, code, workflow, emailAddress);
    }

    internal static async Task<AccountDeleteCommandResult> ReadAccountDeleteVerifyResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        DeletionWorkflow workflow = dr.FieldCount > 2 && !dr.IsDBNull(2)
            ? (DeletionWorkflow)dr.GetInt16(2)
            : DeletionWorkflow.NONE;

        return new AccountDeleteCommandResult(result, code, workflow);
    }

    internal static async Task<AccountDeleteFinalizePreparationResult> ReadAccountDeleteFinalizePreparationResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        Guid? accountId = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetGuid(2) : null;
        DeletionWorkflow workflow = dr.FieldCount > 3 && !dr.IsDBNull(3)
            ? (DeletionWorkflow)dr.GetInt16(3)
            : DeletionWorkflow.NONE;
        string? passPhraseHash = dr.FieldCount > 4 && !dr.IsDBNull(4) ? dr.GetString(4) : null;

        Guid? requestId=dr.FieldCount>5 && !dr.IsDBNull(5)?dr.GetGuid(5):null;
        return new AccountDeleteFinalizePreparationResult(result, code, accountId, workflow, passPhraseHash,requestId);
    }

    internal static async Task<AccountDeleteCommandResult> ReadAccountDeleteFinalizeResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        Guid? accountId = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetGuid(2) : null;
        return new AccountDeleteCommandResult(result, code, DeletionWorkflow.NONE, null, accountId);
    }

    internal static async Task<AccountDeletePurgeResult> ReadAccountDeletePurgeResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        int deletedCount = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetInt32(2) : 0;
        return new AccountDeletePurgeResult(result, code, deletedCount);
    }

    internal static async Task<AccountEmailChangePurgeResult> ReadAccountEmailChangePurgeResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        int deletedCount = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetInt32(2) : 0;
        return new AccountEmailChangePurgeResult(result, code, deletedCount);
    }

    internal static async Task<AccountViewResult> ReadAccountViewResultAsync(NpgsqlDataReader dr, CancellationToken cancellationToken = default)
    {
        if (!await dr.ReadAsync(cancellationToken))
        {
            throw DependencyUnavailableException.InvalidResponse("command_result");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";

        if (!result)
        {
            return new AccountViewResult(false, code, null);
        }

        List<TwoFactorAuthMethod> twoFactorAuthMethods = ReadTwoFactorAuthMethods(dr, 10);
        TwoFactorAuthConfiguration twoFactorAuthConfiguration = dr.FieldCount > 9 && !dr.IsDBNull(9)
            ? (TwoFactorAuthConfiguration)dr.GetInt16(9)
            : TwoFactorAuthConfigurationResolver.FromMethods(twoFactorAuthMethods);

        var profile = new AccountProfile
        {
            emailAddress = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetString(2) : string.Empty,
            username = dr.FieldCount > 3 && !dr.IsDBNull(3) ? dr.GetString(3) : null,
            createdOn = dr.FieldCount > 4 && !dr.IsDBNull(4) ? dr.GetFieldValue<Instant>(4) : Instant.MinValue,
            verifyStatus = dr.FieldCount > 5 && !dr.IsDBNull(5) ? (VerificationStatus)dr.GetInt16(5) : VerificationStatus.FAILED,
            country = dr.FieldCount > 6 && !dr.IsDBNull(6) ? (Country)dr.GetInt16(6) : Country.NONE,
            entitlements = treehammock.DataLayer.Entitlements.EntitlementProjection.Parse(dr.GetString(11)),
            features = dr.FieldCount > 7 && !dr.IsDBNull(7) ? (FeatureSet)dr.GetInt16(7) : FeatureSet.basic,
            twoFactorEnabled = dr.FieldCount > 8 && !dr.IsDBNull(8) && dr.GetBoolean(8),
            twoFactorAuthConfiguration = twoFactorAuthConfiguration,
            twoFactorAuthMethods = twoFactorAuthMethods,
            availableTwoFactorAuthConfigurations = TwoFactorAuthConfigurationResolver.AvailableFromMethods(twoFactorAuthMethods)
        };

        return new AccountViewResult(true, code, profile);
    }

    internal static List<TwoFactorAuthMethod> ReadTwoFactorAuthMethods(NpgsqlDataReader dr, int ordinal)
    {
        if (dr.FieldCount <= ordinal || dr.IsDBNull(ordinal))
        {
            return [];
        }

        short[] rawMethods;
        try
        {
            rawMethods = dr.GetFieldValue<short[]>(ordinal);
        }
        catch (InvalidCastException)
        {
            return [];
        }

        return rawMethods
            .Where(value => Enum.IsDefined(typeof(TwoFactorAuthMethod), (int)value))
            .Select(value => (TwoFactorAuthMethod)value)
            .Where(method => method is not TwoFactorAuthMethod.NONE)
            .Distinct()
            .ToList();
    }

    internal static List<TwoFactorAuthConfiguration> ReadTwoFactorAuthConfigurations(NpgsqlDataReader dr, int ordinal)
    {
        if (dr.FieldCount <= ordinal || dr.IsDBNull(ordinal))
        {
            return [];
        }

        short[] rawConfigurations;
        try
        {
            rawConfigurations = dr.GetFieldValue<short[]>(ordinal);
        }
        catch (InvalidCastException)
        {
            return [];
        }

        return rawConfigurations
            .Where(value => Enum.IsDefined(typeof(TwoFactorAuthConfiguration), (int)value))
            .Select(value => (TwoFactorAuthConfiguration)value)
            .Where(configuration => configuration is not TwoFactorAuthConfiguration.NONE and not TwoFactorAuthConfiguration.CUSTOM)
            .Distinct()
            .ToList();
    }


    internal static async Task<bool> ReadBooleanProcedureResultAsync(NpgsqlDataReader reader, int ordinal = 0, CancellationToken cancellationToken = default)
    {
        bool hasRow = await reader.ReadAsync(cancellationToken);
        if (!hasRow)
        {
            throw DependencyUnavailableException.InvalidResponse("ReadBooleanProcedureResultAsync");
        }

        return ReadBooleanResult(reader, ordinal);
    }

    internal static bool ReadBooleanResult(NpgsqlDataReader reader, int ordinal = 0)
    {
        object value = reader.GetValue(ordinal);
        return ReadBooleanValue(value);
    }

    internal static bool ReadBooleanValue(object? value)
    {
        return value switch
        {
            null => false,
            DBNull _ => false,
            bool boolValue => boolValue,
            short shortValue => shortValue > 0,
            int intValue => intValue > 0,
            long longValue => longValue > 0,
            _ => Convert.ToBoolean(value)
        };
    }

    internal static bool ReadBooleanContractResult(bool hasRow, object? value)
    {
        return hasRow && ReadBooleanValue(value);
    }


    internal static object DbValue(object? value)
    {
        return value ?? DBNull.Value;
    }

    internal static short? ToSmallint<TEnum>(TEnum? value) where TEnum : struct, Enum
    {
        return value.HasValue ? Convert.ToInt16(value.Value) : null;
    }

    internal static short[]? ToSmallintArray(IEnumerable<TwoFactorAuthMethod>? methods)
    {
        if (methods is null)
        {
            return null;
        }

        return methods.Select(method => Convert.ToInt16(method)).ToArray();
    }


    private void LogRepositoryFailure(Exception exception, string operation, object? scope = null, DependencyStage stage = DependencyStage.Acquire)
    {
        _logger.LogError(exception, "Repository operation {Operation} failed before a controlled repository result could be returned with scope {@Scope}.", operation, scope);
        throw DependencyUnavailableException.Database(operation, stage, exception);
    }

    private async Task RollbackAndLogAsync(NpgsqlTransaction tran, Exception exception, string? procedure, object? scope = null, DependencyStage stage = DependencyStage.Execute)
    {
        try
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await tran.RollbackAsync(cleanup.Token);
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (Exception rollbackException) {
            _logger.LogError(rollbackException, "Rollback failed for repository procedure {Procedure}.", procedure ?? "<unset>");
        }

        _logger.LogError(exception, "Repository procedure {Procedure} failed with scope {@Scope}.", procedure ?? "<unset>", scope);
        throw DependencyUnavailableException.Database(procedure ?? "repository_command", stage, exception);
    }
}
