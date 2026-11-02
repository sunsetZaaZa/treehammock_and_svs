using Microsoft.Extensions.Options;
using NodaTime;
using treehammock.DataLayer.Security;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Dependencies;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
namespace treehammock.Services;

public sealed record SensitiveActionReauthenticationCommand(Guid AccountId,Guid AccountSecurityStamp,string SessionBindingHash,
    string Password,SensitiveActionPurpose Purpose,string? Target=null,string? RemoteIp=null);
public sealed record SensitiveActionFactorProofCommand(Guid AccountId,Guid AccountSecurityStamp,string SessionBindingHash,string ProofSession,string Code,string? RemoteIp=null);
public sealed record SensitiveActionIssueResult(bool Succeeded,HttpMessage Result,string Code,string? Token=null,
    SensitiveActionPurpose? Purpose=null,Instant? Expiration=null,string? ProofSession=null,int? StatusCode=null);
public sealed record SensitiveActionValidationCommand(Guid AccountId,Guid AccountSecurityStamp,string SessionBindingHash,string Token,
    SensitiveActionPurpose Purpose,bool Consume=true,string? Target=null);
public sealed record SensitiveActionValidationResult(bool Succeeded,HttpMessage Result,string Code,SensitiveActionPurpose? Purpose=null,
    Instant? Expiration=null,SensitiveActionGrant? Grant=null);
public interface IAccountSensitiveActionService
{
    Task<SensitiveActionIssueResult> ReauthenticateAsync(SensitiveActionReauthenticationCommand command,CancellationToken cancellationToken=default);
    Task<SensitiveActionValidationResult> ValidateAsync(SensitiveActionValidationCommand command,CancellationToken cancellationToken=default);
    Task<SensitiveActionIssueResult> CompleteFactorProofAsync(SensitiveActionFactorProofCommand command,CancellationToken cancellationToken=default)
        => Task.FromResult(new SensitiveActionIssueResult(false,HttpMessage.SENSITIVE_ACTION_TOKEN_ISSUE_FAILED,"SENSITIVE_ACTION_FACTOR_UNAVAILABLE",StatusCode:503));
}
public sealed class AccountSensitiveActionService : IAccountSensitiveActionService
{
    public const string TokenIssuedCode="SENSITIVE_ACTION_TOKEN_ISSUED",InvalidPurposeCode="SENSITIVE_ACTION_INVALID_PURPOSE",
        ReauthenticationFailedCode="SENSITIVE_ACTION_REAUTHENTICATION_FAILED",TokenIssueFailedCode="SENSITIVE_ACTION_TOKEN_ISSUE_FAILED",
        TokenValidatedCode="SENSITIVE_ACTION_TOKEN_VALIDATED",TokenValidationFailedCode="SENSITIVE_ACTION_TOKEN_VALIDATION_FAILED";
    private readonly ISensitiveActionTokenRepo _repo;
    private readonly SensitiveActionSettings _settings;
    private readonly IPasswordWorkService _work;
    private readonly ISensitiveActionAdmissionPolicy? _admission;
    private readonly IAuthenticatorAppLoginVerifier? _factor;
    private readonly string _pepper;
    public AccountSensitiveActionService(ISensitiveActionTokenRepo sensitiveActionTokenRepo,IOptions<SensitiveActionSettings> settings,
        IPasswordWorkService? passwordWork=null,ISensitiveActionAdmissionPolicy? admission=null,IOptions<LoginSettings>? login=null,IAuthenticatorAppLoginVerifier? factor=null)
    {
        _repo=sensitiveActionTokenRepo;_settings=settings.Value;
        _work=passwordWork??PasswordWorkService.Default(login??Options.Create(new LoginSettings()));
        _admission=admission;_pepper=login?.Value.TwoFactorChallengePepper??"";_factor=factor;
    }
    public async Task<SensitiveActionIssueResult> ReauthenticateAsync(SensitiveActionReauthenticationCommand command,CancellationToken cancellationToken=default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if(!SensitiveActionTargets.Supported(command.Purpose))return Failure(InvalidPurposeCode,400);
        string? target=command.Target??(command.Purpose==SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP?SensitiveActionTargets.DefaultSetup:null);
        if(target is null || target.Length is <1 or >1024 || string.IsNullOrWhiteSpace(command.Password) || command.Password.Length >512 || string.IsNullOrWhiteSpace(command.SessionBindingHash))return Failure(ReauthenticationFailedCode,400);
        var denied=await Admission(command.AccountId,command.SessionBindingHash,command.RemoteIp,cancellationToken);
        if(denied is not null)return denied;
        string targetHash=SensitiveActionTargets.Hash(command.Purpose,target,_pepper);Guid attempt=Guid.NewGuid();
        SensitiveProofAdmission begin=await _repo.BeginPasswordProof(new(command.AccountId,command.AccountSecurityStamp,command.SessionBindingHash,attempt,
            command.Purpose,targetHash,_settings.MaxPasswordAttempts,_settings.AttemptWindowSeconds,_settings.PasswordProofLeaseSeconds),cancellationToken);
        if(!begin.Result || begin.PasswordHash is null)return Failure(begin.Code,begin.Code=="SENSITIVE_ACTION_ATTEMPT_LIMIT"?429:begin.Code=="SENSITIVE_ACTION_FACTOR_UNAVAILABLE"?503:423);
        bool verified;
        try{verified=await _work.VerifyBytesAsync(begin.PasswordHash,command.Password,cancellationToken);}
        catch(PasswordWorkBusyException)
        {
            // Release an admitted-but-unperformed password attempt. Cache request quotas
            // remain admission counters; no incorrect-password result is recorded.
            using var cleanup=new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try{await _repo.AbandonPasswordProof(command.AccountId,command.AccountSecurityStamp,attempt,cleanup.Token);}
            catch(Exception ex) when(ex is DependencyUnavailableException or OperationCanceledException or treehammock.DataLayer.Operations.SecurityOperationException){ }
            throw;
        }
        string handle=AccountVerificationTokenUtility.GenerateToken(_settings.TokenBytes);
        string token=AccountVerificationTokenUtility.GenerateToken(_settings.TokenBytes);
        var completed=await _repo.FinishPasswordProof(new(command.AccountId,command.AccountSecurityStamp,command.SessionBindingHash,attempt,verified,
            AccountVerificationTokenUtility.HashToken(handle),AccountVerificationTokenUtility.HashToken(token),_settings.ExpirationMinutes),cancellationToken);
        if(!completed.Result)return Failure(completed.Code,completed.Code==ReauthenticationFailedCode?401:409);
        if(completed.FactorRequired)return new(false,HttpMessage.SENSITIVE_ACTION_FACTOR_PROOF_REQUIRED,completed.Code,
            Purpose:command.Purpose,Expiration:completed.Expiration,ProofSession:handle,StatusCode:202);
        return new(true,HttpMessage.SENSITIVE_ACTION_TOKEN_ISSUED,TokenIssuedCode,token,command.Purpose,completed.Expiration,StatusCode:200);
    }
    public async Task<SensitiveActionIssueResult> CompleteFactorProofAsync(SensitiveActionFactorProofCommand command,CancellationToken cancellationToken=default)
    {
        if(string.IsNullOrEmpty(command.ProofSession) || command.ProofSession.Length is <16 or >512 || string.IsNullOrEmpty(command.Code) || command.Code.Length is <6 or >8 || !command.Code.All(char.IsAsciiDigit))return Failure(ReauthenticationFailedCode,400);
        var denied=await Admission(command.AccountId,command.SessionBindingHash,command.RemoteIp,cancellationToken);if(denied is not null)return denied;
        if(_factor is null)return Failure("SENSITIVE_ACTION_FACTOR_UNAVAILABLE",503);
        string handle=AccountVerificationTokenUtility.HashToken(command.ProofSession);
        if(!await _repo.ReserveFactorProof(command.AccountId,command.AccountSecurityStamp,command.SessionBindingHash,handle,_settings.MaxFactorAttempts,cancellationToken))
            return Failure("SENSITIVE_ACTION_FACTOR_PROOF_DENIED",429);
        var proof=await _factor.VerifyForLoginAsync(command.AccountId,command.Code,SystemClock.Instance.GetCurrentInstant(),cancellationToken);
        if(!proof.Verified)return Failure(proof.Code,proof.Status==ProofVerificationStatus.DependencyUnavailable?503:401);
        string token=AccountVerificationTokenUtility.GenerateToken(_settings.TokenBytes);
        var completed=await _repo.FinishFactorProof(command.AccountId,command.AccountSecurityStamp,command.SessionBindingHash,handle,
            AccountVerificationTokenUtility.HashToken(token),cancellationToken);
        if(!completed.Result)return Failure(completed.Code,409);
        return new(true,HttpMessage.SENSITIVE_ACTION_TOKEN_ISSUED,TokenIssuedCode,token,Expiration:completed.Expiration,StatusCode:200);
    }
    public async Task<SensitiveActionValidationResult> ValidateAsync(SensitiveActionValidationCommand command,CancellationToken cancellationToken=default)
    {
        if(command.Consume)return Invalid("SENSITIVE_ACTION_TRANSACTION_REQUIRED");
        if(!SensitiveActionTargets.Supported(command.Purpose))return Invalid(InvalidPurposeCode);
        string? target=command.Target??(command.Purpose==SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP?SensitiveActionTargets.DefaultSetup:null);
        if(target is null || target.Length is <1 or >1024 || string.IsNullOrEmpty(command.Token) || command.Token.Length is <16 or >512 || string.IsNullOrWhiteSpace(command.SessionBindingHash))return Invalid(TokenValidationFailedCode);
        if(_pepper.Length<16)throw DependencyUnavailableException.InvalidResponse("sensitive_target_key");
        string targetHash=SensitiveActionTargets.Hash(command.Purpose,target,_pepper),tokenHash=AccountVerificationTokenUtility.HashToken(command.Token);
        if(!await _repo.ValidateGrant(command.AccountId,command.AccountSecurityStamp,command.SessionBindingHash,tokenHash,command.Purpose,targetHash,cancellationToken))return Invalid(TokenValidationFailedCode);
        return new(true,HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATED,TokenValidatedCode,command.Purpose,
            Grant:new(command.SessionBindingHash,tokenHash,targetHash,target));
    }
    private async Task<SensitiveActionIssueResult?> Admission(Guid account,string session,string? ip,CancellationToken token)
    {
        if(_admission is null || _pepper.Length<16)return Failure(AbuseReasonCodes.CounterStoreUnavailable,503);
        string? denied=await _admission.CheckAsync(account,session,ip,token);
        return denied is null?null:Failure(denied,denied is AbuseReasonCodes.CounterStoreUnavailable or AbuseReasonCodes.CounterStoreTimeout?503:429);
    }
    private static SensitiveActionIssueResult Failure(string code,int status)=>new(false,HttpMessage.SENSITIVE_ACTION_REAUTHENTICATION_FAILED,code,StatusCode:status);
    private static SensitiveActionValidationResult Invalid(string code)=>new(false,HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATION_FAILED,code);
}
