using Microsoft.Extensions.Logging;
using NodaTime;
using Npgsql;
using NpgsqlTypes;
using treehammock.DataLayer.Security;
using treehammock.Rigging.Database;
using treehammock.Rigging.Dependencies;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
namespace treehammock.Repos;

public interface ISensitiveActionTokenRepo
{
    Task<SensitiveProofAdmission> BeginPasswordProof(SensitivePasswordAdmission admission, CancellationToken cancellationToken = default);
    Task<SensitiveProofCompletion> FinishPasswordProof(SensitivePasswordCompletion completion, CancellationToken cancellationToken = default);
    Task<bool> AbandonPasswordProof(Guid account, Guid stamp, Guid attempt, CancellationToken cancellationToken = default);
    Task<bool> ReserveFactorProof(Guid account, Guid stamp, string session, string handle, int limit, CancellationToken cancellationToken = default);
    Task<SensitiveProofCompletion> FinishFactorProof(Guid account, Guid stamp, string session, string handle, string token, CancellationToken cancellationToken = default);
    Task<bool> ValidateGrant(Guid account, Guid stamp, string session, string token, SensitiveActionPurpose purpose, string target, CancellationToken cancellationToken = default);
    // Legacy API signatures retained solely for fail-closed compatibility.
    Task<AccountReauthenticationCredentialResult?> GetReauthenticationCredentials(Guid accountId, Guid accountSecurityStamp, CancellationToken cancellationToken = default);
    Task<SensitiveActionTokenIssueCommandResult?> IssueToken(Guid accountId, Guid accountSecurityStamp, string sessionBindingHash,
        string tokenHash, SensitiveActionPurpose purpose, Instant createdOn, Instant expiration, bool consumeExistingTokens, CancellationToken cancellationToken = default);
    Task<SensitiveActionTokenValidationCommandResult?> ValidateToken(Guid accountId, Guid accountSecurityStamp, string sessionBindingHash,
        string tokenHash, SensitiveActionPurpose purpose, bool consume, Instant moment, CancellationToken cancellationToken = default);
}

public sealed class SensitiveActionTokenRepo(StorageContext activeDatabase, ILogger<SensitiveActionTokenRepo> logger) : ISensitiveActionTokenRepo
{
    internal const string GetReauthenticationCredentialsFunction = "get_account_reauthentication_credentials";
    internal const string IssueSensitiveActionTokenFunction = "issue_sensitive_action_token";
    internal const string ValidateSensitiveActionTokenFunction = "validate_sensitive_action_token";
    public Task<SensitiveProofAdmission> BeginPasswordProof(SensitivePasswordAdmission a, CancellationToken cancellationToken = default)
        => Execute("cor08_begin_password_proof", a.AccountId, a.Stamp, a,
            [a.AccountId,a.Stamp,a.SessionHash,a.AttemptId,(short)a.Purpose,a.TargetHash,a.Limit,a.WindowSeconds,a.LeaseSeconds],
            async (command, token) =>
            {
                await using var reader = await command.ExecuteReaderAsync(token);
                if (!await reader.ReadAsync(token)) throw DependencyUnavailableException.InvalidResponse("password_admission");
                return new SensitiveProofAdmission(reader.GetBoolean(0),reader.GetString(1),reader.IsDBNull(2)?null:reader.GetFieldValue<byte[]>(2),reader.GetBoolean(3));
            }, cancellationToken);
    public Task<SensitiveProofCompletion> FinishPasswordProof(SensitivePasswordCompletion c, CancellationToken cancellationToken = default)
        => Execute("cor08_finish_password_proof",c.AccountId,c.Stamp,c,
            [c.AccountId,c.Stamp,c.SessionHash,c.AttemptId,c.Verified,c.HandleHash,c.TokenHash,c.ExpirationMinutes], ReadCompletion,cancellationToken);
    public Task<bool> AbandonPasswordProof(Guid account,Guid stamp,Guid attempt,CancellationToken cancellationToken=default)
        => Execute("cor08_abandon_password_proof",account,stamp,new {account,stamp,attempt},[account,stamp,attempt],ReadBool,cancellationToken);
    public Task<bool> ReserveFactorProof(Guid account,Guid stamp,string session,string handle,int limit,CancellationToken cancellationToken=default)
        => Execute("cor08_reserve_factor_proof",account,stamp,new {account,stamp,session,handle,limit},[account,stamp,session,handle,limit],ReadBool,cancellationToken);
    public Task<SensitiveProofCompletion> FinishFactorProof(Guid account,Guid stamp,string session,string handle,string token,CancellationToken cancellationToken=default)
        => Execute("cor08_finish_factor_proof",account,stamp,new {account,stamp,session,handle,token},[account,stamp,session,handle,token],ReadCompletion,cancellationToken);
    public Task<bool> ValidateGrant(Guid account,Guid stamp,string session,string token,SensitiveActionPurpose purpose,string target,CancellationToken cancellationToken=default)
        => Execute("cor08_validate_sensitive_grant",account,stamp,new {account,stamp,session,token,purpose,target},[account,stamp,session,token,(short)purpose,target,false],ReadBool,cancellationToken);
    private async Task<T> Execute<T>(string function,Guid account,Guid stamp,object content,object[] values,Func<NpgsqlCommand,CancellationToken,Task<T>> read,CancellationToken token)
    {
        AccountSecurityStampGuard.Require(stamp);
        await using var operation=await activeDatabase.SecurityOperations.BeginAsync("SensitiveActionTokenRepo."+function,content,account,stamp,null,token);
        try
        {
            string args=string.Join(",",Enumerable.Range(0,values.Length).Select(n=>"@v"+n));
            await using var command=new NpgsqlCommand("select * from "+function+"("+args+")",operation.Connection,operation.Transaction);
            for(int n=0;n<values.Length;n++)command.Parameters.AddWithValue("v"+n,values[n]);
            T result=await read(command,operation.CancellationToken); await operation.CommitAsync(result!);return result;
        }
        catch(OperationCanceledException) when(token.IsCancellationRequested){throw;}
        catch(Exception ex) when(ex is NpgsqlException or TimeoutException or OperationCanceledException)
        {logger.LogWarning("Sensitive proof command {Command} unavailable.",function);throw DependencyUnavailableException.Database(function,DependencyStage.Execute,ex);}
    }
    private static async Task<bool> ReadBool(NpgsqlCommand command,CancellationToken token)=>(bool)(await command.ExecuteScalarAsync(token))!;
    private static async Task<SensitiveProofCompletion> ReadCompletion(NpgsqlCommand command,CancellationToken token)
    {
        await using var reader=await command.ExecuteReaderAsync(token);
        if(!await reader.ReadAsync(token))throw DependencyUnavailableException.InvalidResponse("sensitive_proof_completion");
        return new(reader.GetBoolean(0),reader.GetString(1),reader.IsDBNull(2)?null:reader.GetFieldValue<Instant>(2),reader.GetBoolean(3));
    }
    public Task<AccountReauthenticationCredentialResult?> GetReauthenticationCredentials(Guid accountId,Guid accountSecurityStamp,CancellationToken cancellationToken=default)
        => Task.FromResult<AccountReauthenticationCredentialResult?>(new(false,"SENSITIVE_ACTION_BUDGET_REQUIRED",null,null,null,accountSecurityStamp));
    public Task<SensitiveActionTokenIssueCommandResult?> IssueToken(Guid accountId,Guid accountSecurityStamp,string sessionBindingHash,string tokenHash,
        SensitiveActionPurpose purpose,Instant createdOn,Instant expiration,bool consumeExistingTokens,CancellationToken cancellationToken=default)
        =>Task.FromResult<SensitiveActionTokenIssueCommandResult?>(new(false,"SENSITIVE_ACTION_LEGACY_GRANT_DENIED",null,null));
    public Task<SensitiveActionTokenValidationCommandResult?> ValidateToken(Guid accountId,Guid accountSecurityStamp,string sessionBindingHash,string tokenHash,
        SensitiveActionPurpose purpose,bool consume,Instant moment,CancellationToken cancellationToken=default)
        =>Task.FromResult<SensitiveActionTokenValidationCommandResult?>(new(false,"SENSITIVE_ACTION_LEGACY_GRANT_DENIED",null));
    internal static async Task<AccountReauthenticationCredentialResult> ReadAccountReauthenticationCredentialResultAsync(NpgsqlDataReader dr,CancellationToken cancellationToken=default)
    {
        if(!await dr.ReadAsync(cancellationToken))throw DependencyUnavailableException.InvalidResponse("reauthentication");
        return new(dr.GetBoolean(0),dr.GetString(1),dr.IsDBNull(2)?null:dr.GetFieldValue<byte[]>(2),dr.IsDBNull(3)?null:(VerificationStatus)dr.GetInt16(3),dr.IsDBNull(4)?null:dr.GetFieldValue<Instant>(4),dr.IsDBNull(5)?null:dr.GetGuid(5));
    }
    internal static async Task<SensitiveActionTokenIssueCommandResult> ReadSensitiveActionTokenIssueCommandResultAsync(NpgsqlDataReader dr,CancellationToken cancellationToken=default)
    {
        if(!await dr.ReadAsync(cancellationToken))throw DependencyUnavailableException.InvalidResponse("sensitive_issue");
        return new(dr.GetBoolean(0),dr.GetString(1),dr.IsDBNull(2)?null:dr.GetGuid(2),dr.IsDBNull(3)?null:dr.GetFieldValue<Instant>(3));
    }
    internal static async Task<SensitiveActionTokenValidationCommandResult> ReadSensitiveActionTokenValidationCommandResultAsync(NpgsqlDataReader dr,CancellationToken cancellationToken=default)
    {
        if(!await dr.ReadAsync(cancellationToken))throw DependencyUnavailableException.InvalidResponse("sensitive_validate");
        return new(dr.GetBoolean(0),dr.GetString(1),dr.IsDBNull(2)?null:dr.GetFieldValue<Instant>(2));
    }
}
