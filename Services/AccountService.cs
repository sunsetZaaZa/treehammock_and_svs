using treehammock.Rigging.Delivery;
using treehammock.Entities;
using treehammock.Models.Account;
using treehammock.Repos;
using treehammock.Rigging.Security;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using MassTransit;

using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Http;
using NodaTime;
using NodaTime.Extensions;
using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace treehammock.Services;
public interface IAccountService
{
    Task<HttpMessage> SetupUserAccount(string emailAddress, string? username, string password, Country country, Instant createdOn, AccountSetupAction whichAction, CancellationToken cancellationToken = default);
    Task<HttpMessage> ResendAccountVerification(string emailAddress, CancellationToken cancellationToken = default);
    Task<AccountAdjustResult?> RequestEmailChange(Guid accountId, Guid accountSecurityStamp, string newEmailAddress, CancellationToken cancellationToken = default, treehammock.DataLayer.Security.SensitiveActionGrant? grant = null);
    Task<AccountAdjustResult?> CompleteEmailChange(string verifyKey, CancellationToken cancellationToken = default);
    Task<AccountDeleteCommandResult?> RequestAccountDelete(Guid accountId, Guid accountSecurityStamp, string? passPhrase, CancellationToken cancellationToken = default, treehammock.DataLayer.Security.SensitiveActionGrant? grant = null);
    Task<AccountDeleteCommandResult?> VerifyAccountDeleteToken(string deleteToken, CancellationToken cancellationToken = default);
    Task<AccountDeleteCommandResult?> FinalizeAccountDelete(Guid accountId, Guid accountSecurityStamp, string deleteToken, string? passPhrase, CancellationToken cancellationToken = default,string? sessionHash = null);
    Task<AccountDeletePurgeResult?> PurgeExpiredDeleteStandby(Instant? moment = null, CancellationToken cancellationToken = default);
    Task<AccountEmailChangePurgeResult?> PurgeExpiredAccountEmailChangeRequests(Instant? moment = null, CancellationToken cancellationToken = default);
}

public class AccountService : IAccountService
{
    private IAccountRepo _accountRepo { get; set; }
    private LoginSettings _loginSettings { get; set; }
    private RegistrationSettings _registrationSettings { get; set; }
    private EmailSubjectSettings _emailSubjectSettings { get; set; }
    private IUserSecretHasher _userSecretHasher { get; set; }
    private IAccountTokenVerificationAbuseCounterKeyFactory _accountTokenVerificationAbuseCounterKeyFactory { get; set; }
    private IAbuseCounterStore? _abuseCounterStore { get; set; }
    private AbuseControlSettings _abuseControlSettings { get; set; }
    private IHttpContextAccessor? _httpContextAccessor { get; set; }
    private readonly IPasswordWorkService _passwordWork;
    private readonly ISignupAdmissionPolicy _signupAdmission;

    private const int WebKeyPos = 0;
    private const int SaltPos = WebKeyPos + AccountCryptoSizes.WebKeyBytes;
    private const int SivPos = SaltPos + AccountCryptoSizes.SaltOneBytes;
    private const int NoncePos = SivPos + AccountCryptoSizes.SivBytes;
    private const int AccountSecretBytes = AccountCryptoSizes.WebKeyBytes + AccountCryptoSizes.SaltOneBytes + AccountCryptoSizes.SivBytes + AccountCryptoSizes.NonceBytes;

    private readonly IDurableDeliveryService _delivery;
    private readonly treehammock.Rigging.Hosting.VerificationLinkBuilder _verificationLinks;

    public AccountService(
        IDurableDeliveryService delivery,
        IAccountRepo accountRepo,
        IOptions<LoginSettings> loginSettings,
        IOptions<RegistrationSettings> registrationSettings,
        IOptions<EmailSubjectSettings> emailSubjectSettings,
        IUserSecretHasher userSecretHasher,
        IAccountTokenVerificationAbuseCounterKeyFactory? accountTokenVerificationAbuseCounterKeyFactory = null,
        IAbuseCounterStore? abuseCounterStore = null,
        IOptions<AbuseControlSettings>? abuseControlSettings = null,
        IHttpContextAccessor? httpContextAccessor = null,
        IPasswordWorkService? passwordWork = null,
        ISignupAdmissionPolicy? signupAdmission = null,
        treehammock.Rigging.Hosting.VerificationLinkBuilder? verificationLinks = null)
    {
        _verificationLinks = verificationLinks ?? new(registrationSettings.Value.PublicOrigin);
        _delivery = delivery;
        _accountRepo = accountRepo;
        _loginSettings = loginSettings.Value;
        _registrationSettings = registrationSettings.Value;
        _emailSubjectSettings = emailSubjectSettings.Value;
        _userSecretHasher = userSecretHasher;
        _accountTokenVerificationAbuseCounterKeyFactory = accountTokenVerificationAbuseCounterKeyFactory ?? new AccountTokenVerificationAbuseCounterKeyFactory();
        _abuseCounterStore = abuseCounterStore;
        _abuseControlSettings = abuseControlSettings?.Value ?? new AbuseControlSettings();
        _httpContextAccessor = httpContextAccessor;
        _passwordWork = passwordWork ?? PasswordWorkService.Default(loginSettings);
        _signupAdmission = signupAdmission ?? new SignupAdmissionPolicy(abuseCounterStore, Options.Create(_abuseControlSettings), loginSettings);
    }

    public byte[] GetPortion(byte[] whole, int length, int offset = 0)
    {
        byte[] result = new byte[length];
        for (int idx = 0; idx < length; idx++)
        {
            result[idx] = whole[idx + offset];
        }
        return result;
    }


    /*
     * Returns one of:
     *      HttpMessage.ACCOUNT_CREATION_SUCCESSED
     *      HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME
     *      HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL
     *      HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME_EMAIL
     *      HttpMessage.ACCOUNT_CREATION_FAILED
     */
    public async Task<HttpMessage> SetupUserAccount(string emailAddress, string? username, string password, Country country, Instant createdOn, AccountSetupAction whichAction, CancellationToken cancellationToken = default)
    {
        var admission = await _signupAdmission.CheckAsync(emailAddress, username,
            _httpContextAccessor?.HttpContext?.Connection.RemoteIpAddress?.ToString(), cancellationToken);
        if (admission is HttpMessage denied) return denied;
        var duplicate = await _accountRepo.CheckSignupAvailability(emailAddress, username, cancellationToken);
        if (duplicate is HttpMessage conflict) return conflict;
        Guid firstGuid = NewId.NextGuid();
        if (!await _delivery.AdmitAsync(AbuseFeature.Activation,"email",firstGuid,emailAddress,cancellationToken))
            return HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING;
        byte[] passwordHash = await _passwordWork.HashBytesAsync(password, cancellationToken);

        long? verificationIndex = null;
        HttpMessage outcome = HttpMessage.ACCOUNT_CREATION_FAILED;
        string? verifyKey = null;
        Guid accountGuid = Guid.Empty;
        int guidAttempts = 0;
        int webKeyAttempts = 0;

        while (guidAttempts < _registrationSettings.AccountMetaDataRetries && webKeyAttempts < _registrationSettings.AccountMetaDataRetries)
        {
            byte[] transit = RandomNumberGenerator.GetBytes(AccountSecretBytes);
            byte[] webKeyBytes = GetPortion(transit, AccountCryptoSizes.WebKeyBytes, WebKeyPos);
            accountGuid = guidAttempts+webKeyAttempts == 0 ? firstGuid : NewId.NextGuid();
            if(guidAttempts+webKeyAttempts>0 && !await _delivery.AdmitAsync(AbuseFeature.Activation,"email",accountGuid,emailAddress,cancellationToken))
                return HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING;
            string webKey = AccountVerificationTokenUtility.EncodeBase64Url(webKeyBytes);
            verifyKey = AccountVerificationTokenUtility.GenerateToken();
            string verifyKeyHash = AccountVerificationTokenUtility.HashToken(verifyKey);

            Period verificationExpiration = BuildVerificationPeriod();

            var newUser = new Account(
                accountGuid,
                emailAddress,
                username,
                passwordHash,
                createdOn,
                webKey,
                VerificationStatus.STARTED,
                GetPortion(transit, AccountCryptoSizes.SaltOneBytes, SaltPos),
                GetPortion(transit, AccountCryptoSizes.SivBytes, SivPos),
                GetPortion(transit, AccountCryptoSizes.NonceBytes, NoncePos),
                null,
                0,
                null,
                country,
                null,
                null);

            var deliveryIntent = new DeliveryIntent(accountGuid,Guid.Empty,"verify",verifyKeyHash,
                SystemClock.Instance.GetCurrentInstant().Plus(verificationExpiration.ToDuration()),new { mode="start" },
                new("verify-start","email",emailAddress,_emailSubjectSettings.AccountVerify,BuildVerificationUrl(verifyKey)));
            (verificationIndex, outcome, _) = await _accountRepo.SetupAccount(newUser, verifyKeyHash, verificationExpiration, whichAction, deliveryIntent, cancellationToken: cancellationToken);

            if (outcome == HttpMessage.ACCOUNT_CREATION_SUCCESSED)
            {
                break;
            }

            if (outcome == HttpMessage.DUPLICATE_USER_GUID)
            {
                guidAttempts++;
                continue;
            }

            if (outcome == HttpMessage.DUPLICATE_USER_WEBKEY)
            {
                webKeyAttempts++;
                continue;
            }

            if (outcome == HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME_EMAIL ||
                outcome == HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL ||
                outcome == HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME)
            {
                return outcome;
            }

            return HttpMessage.ACCOUNT_CREATION_FAILED;
        }

        if (outcome != HttpMessage.ACCOUNT_CREATION_SUCCESSED || verificationIndex == null || string.IsNullOrWhiteSpace(verifyKey))
        {
            return HttpMessage.ACCOUNT_CREATION_FAILED;
        }

        return HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING;
    }

    public async Task<HttpMessage> ResendAccountVerification(string emailAddress, CancellationToken cancellationToken = default)
    {
        if(string.IsNullOrWhiteSpace(emailAddress))return HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED;
        var owner=await _delivery.FindVerificationAccountAsync(emailAddress,cancellationToken);
        if(owner is null || owner.VerificationStatus==1)return HttpMessage.ACCOUNT_CREATION_VERIFICATION_RESENT;
        if(!await _delivery.AdmitAsync(AbuseFeature.Activation,"email",owner.AccountId,owner.Email,cancellationToken))
            return HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING;
        if(await _delivery.ExistingAsync(owner.AccountId,owner.Stamp,"verify",cancellationToken) is not null)return HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING;
        string token=AccountVerificationTokenUtility.GenerateToken();
        Period period=BuildVerificationPeriod();
        var result=await _delivery.EnqueueAsync(new(owner.AccountId,owner.Stamp,"verify",AccountVerificationTokenUtility.HashToken(token),
            SystemClock.Instance.GetCurrentInstant().Plus(period.ToDuration()),new {mode="resend",verificationSeconds=(int)period.ToDuration().TotalSeconds},
            new("verify","email",owner.Email,_emailSubjectSettings.AccountVerifyResend,BuildVerificationUrl(token))),cancellationToken);
        return result.Result?HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING:HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED;
    }

    public async Task<AccountAdjustResult?> RequestEmailChange(Guid accountId, Guid accountSecurityStamp, string newEmailAddress, CancellationToken cancellationToken = default, treehammock.DataLayer.Security.SensitiveActionGrant? grant = null)
    {
        AccountSecurityStampGuard.Require(accountSecurityStamp);
        newEmailAddress=newEmailAddress.Trim().ToLowerInvariant();
        if(grant is null || grant.CanonicalTarget!=SensitiveActionTargets.EmailChange(newEmailAddress))
            return new(false,"SENSITIVE_ACTION_GRANT_REQUIRED");
        var view=await _accountRepo.ViewAccount(accountId,accountSecurityStamp,cancellationToken);
        if(view?.Result!=true || string.IsNullOrWhiteSpace(view.Profile?.emailAddress))return new(false,view?.Code ?? "ACCOUNT_ADJUST_FAILED");
        string oldEmail=view.Profile.emailAddress;
        if(!await _delivery.AdmitAsync(AbuseFeature.Delivery,"email",accountId,newEmailAddress,cancellationToken) ||
           !await _delivery.AdmitAsync(AbuseFeature.Delivery,"email",accountId,oldEmail,cancellationToken))
            return new(false,HttpMessage.ACCOUNT_ADJUST_EMAIL_DELIVERY_FAILED.ToString());
        string token=AccountVerificationTokenUtility.GenerateToken();string hash=AccountVerificationTokenUtility.HashToken(token);
        Instant expires=SystemClock.Instance.GetCurrentInstant().Plus(BuildEmailChangeVerificationPeriod().ToDuration());
        var notice=new treehammock.Rigging.Delivery.DeliveryIntent(accountId,accountSecurityStamp,"email-notice",hash,expires,
            new {originEmail=oldEmail,requestProofHash=hash},new("email-change-notice","email",oldEmail,"Email change requested",
                "A registered email change was approved for your account. If you did not approve it, secure your account immediately."));
        var result=await _delivery.EnqueueAsync(new(accountId,accountSecurityStamp,"email",hash,expires,
            new {newEmailAddress,originEmail=oldEmail,grantSession=grant.SessionHash,grantToken=grant.TokenHash,grantTarget=grant.TargetHash},
            new("email","email",newEmailAddress,_emailSubjectSettings.AccountEmailChangeVerify,BuildEmailChangeVerificationUrl(token)),notice),cancellationToken);
        return new(result.Result,result.Result?HttpMessage.ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING.ToString():result.Code,accountSecurityStamp,newEmailAddress);
    }

    public async Task<AccountAdjustResult?> CompleteEmailChange(string verifyKey, CancellationToken cancellationToken = default)
    {
        verifyKey = verifyKey?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(verifyKey) ||
            verifyKey.Length > AccountEmailChangeVerifyRequest.MaxEmailChangeTokenLength)
        {
            return new AccountAdjustResult(false, HttpMessage.ACCOUNT_ADJUST_TOKEN_MISMATCH.ToString());
        }

        string verifyKeyHash = AccountVerificationTokenUtility.HashToken(verifyKey);
        if(await _delivery.IsPendingAsync("email",verifyKeyHash,cancellationToken))return new(false,HttpMessage.ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING.ToString());

        AbuseDecision abuseDecision = await CheckPublicTokenVerificationPolicy("email-change", verifyKey);
        if (!abuseDecision.Allowed)
        {
            return new AccountAdjustResult(false, abuseDecision.ReasonCode ?? AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded);
        }

        AccountAdjustResult? result = await _accountRepo.CompleteEmailChange(verifyKeyHash, cancellationToken: cancellationToken);
        if (result?.Result == true)
        {
            await ResetPublicTokenVerificationPolicy("email-change", verifyKey);
        }

        return result;
    }

    public async Task<AccountDeleteCommandResult?> RequestAccountDelete(Guid accountId, Guid accountSecurityStamp, string? passPhrase, CancellationToken cancellationToken = default, treehammock.DataLayer.Security.SensitiveActionGrant? grant = null)
    {
        AccountSecurityStampGuard.Require(accountSecurityStamp);
        if(grant is null || grant.CanonicalTarget!=SensitiveActionTargets.AccountDelete(passPhrase)) return new(false,"SENSITIVE_ACTION_GRANT_REQUIRED");
        string token=AccountVerificationTokenUtility.GenerateToken();
        string hash=SecretHashUtility.HashLookupToken(token);Guid admissionId=Guid.NewGuid();
        Instant expires=SystemClock.Instance.GetCurrentInstant().Plus(BuildAccountDeleteTokenPeriod().ToDuration());
        // Independent committed admission precedes provider admission and expensive hashing.
        var admission=await _accountRepo.AdmitAccountDelete(accountId,accountSecurityStamp,admissionId,hash,expires,
            BuildDeleteRequestCooldownPeriod(),BuildDeleteRequestWindowPeriod(),_registrationSettings.DeleteMaxRequestsPerWindow,grant,cancellationToken);
        if(admission?.Result!=true || string.IsNullOrWhiteSpace(admission.EmailAddress)) return admission ?? new(false,HttpMessage.ACCOUNT_DELETE_FAILED.ToString());
        string email=admission.EmailAddress;
        if(!await _delivery.AdmitAsync(AbuseFeature.Delivery,"email",accountId,email,cancellationToken))
            return new(false,HttpMessage.ACCOUNT_DELETE_EMAIL_DELIVERY_FAILED.ToString());
        string? passPhraseHash=string.IsNullOrWhiteSpace(passPhrase)?null:await _userSecretHasher.HashUserSecretAsync(passPhrase,cancellationToken);
        var result=await _delivery.EnqueueAsync(new(accountId,accountSecurityStamp,"delete",hash,expires,new {admissionId,passPhraseHash},
            new("delete","email",email,_emailSubjectSettings.AccountDeleteVerify,BuildAccountDeleteVerificationUrl(token),token)),cancellationToken);
        return new(result.Result,result.Result?HttpMessage.ACCOUNT_DELETE_PENDING.ToString():result.Code,
            passPhraseHash is null?DeletionWorkflow.ONETIME:DeletionWorkflow.PASS_PHRASE,email,accountId);
    }

    public async Task<AccountDeleteCommandResult?> VerifyAccountDeleteToken(string deleteToken, CancellationToken cancellationToken = default)
    {
        deleteToken = deleteToken?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(deleteToken))
        {
            return new AccountDeleteCommandResult(false, HttpMessage.ACCOUNT_DELETE_TOKEN_MISMATCH.ToString());
        }

        string deleteTokenHash = SecretHashUtility.HashLookupToken(deleteToken);
        if(await _delivery.IsPendingAsync("delete",deleteTokenHash,cancellationToken))return new(false,HttpMessage.ACCOUNT_DELETE_PENDING.ToString());

        AbuseDecision abuseDecision = await CheckPublicTokenVerificationPolicy("account-delete", deleteToken);
        if (!abuseDecision.Allowed)
        {
            return new AccountDeleteCommandResult(false, abuseDecision.ReasonCode ?? AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded);
        }

        AccountDeleteCommandResult? result = await _accountRepo.VerifyDeleteAccountToken(deleteTokenHash, cancellationToken: cancellationToken);
        if (result?.Result == true)
        {
            await ResetPublicTokenVerificationPolicy("account-delete", deleteToken);
        }

        return result;
    }

    public async Task<AccountDeleteCommandResult?> FinalizeAccountDelete(
        Guid accountId,
        Guid accountSecurityStamp,
        string deleteToken,
        string? passPhrase, CancellationToken cancellationToken = default,string? sessionHash = null)
    {
        AccountSecurityStampGuard.Require(accountSecurityStamp);

        deleteToken = deleteToken?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(deleteToken))
        {
            return new AccountDeleteCommandResult(false, HttpMessage.ACCOUNT_DELETE_TOKEN_MISMATCH.ToString());
        }

        if(await _delivery.IsPendingAsync("delete",SecretHashUtility.HashLookupToken(deleteToken),cancellationToken,accountId))return new(false,HttpMessage.ACCOUNT_DELETE_PENDING.ToString());
        AbuseDecision abuseDecision = await CheckAccountDeleteFinalizePolicy(accountId, deleteToken);
        if (!abuseDecision.Allowed)
        {
            return new AccountDeleteCommandResult(false, abuseDecision.ReasonCode ?? AbuseReasonCodes.AccountDeleteFinalizeAttemptsExceeded);
        }

        string deleteTokenHash = SecretHashUtility.HashLookupToken(deleteToken);

        AccountDeleteCommandResult? result = await _accountRepo.FinalizeAccountDelete(
            accountId,
            accountSecurityStamp,
            deleteTokenHash,
            passPhrase,
            _registrationSettings.DeleteMaxFinalizeFailures,
            BuildDeleteFinalizeLockoutPeriod(), cancellationToken: cancellationToken,sessionHash:sessionHash);

        if (result?.Result == true)
        {
            await ResetAccountDeleteFinalizePolicy(accountId, deleteToken);
        }

        return result;
    }

    public async Task<AccountDeletePurgeResult?> PurgeExpiredDeleteStandby(Instant? moment = null, CancellationToken cancellationToken = default)
    {
        return await _accountRepo.PurgeExpiredDeleteStandby(moment ?? SystemClock.Instance.GetCurrentInstant(), cancellationToken: cancellationToken);
    }

    public async Task<AccountEmailChangePurgeResult?> PurgeExpiredAccountEmailChangeRequests(Instant? moment = null, CancellationToken cancellationToken = default)
    {
        return await _accountRepo.PurgeExpiredAccountEmailChangeRequests(moment ?? SystemClock.Instance.GetCurrentInstant(), cancellationToken: cancellationToken);
    }




    private async Task<AbuseDecision> CheckPublicTokenVerificationPolicy(string flow, string token)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.PublicTokenVerification.Enabled
            || _abuseCounterStore is null)
        {
            return AbuseDecision.Allow();
        }

        TimeSpan window = TimeSpan.FromSeconds(_abuseControlSettings.PublicTokenVerification.VerifyAttemptWindowSeconds);
        TimeSpan cooldown = TimeSpan.FromSeconds(_abuseControlSettings.PublicTokenVerification.CooldownSecondsAfterExhaustion);
        var tokenLimit = new AbuseCounterLimit(
            _abuseControlSettings.PublicTokenVerification.MaxVerifyAttemptsPerToken,
            window,
            cooldown);
        var ipLimit = new AbuseCounterLimit(
            _abuseControlSettings.PublicTokenVerification.MaxVerifyAttemptsPerIp,
            window,
            cooldown);

        AbuseDecision tokenDecision = await IncrementAbuseCounter(
            _accountTokenVerificationAbuseCounterKeyFactory.ForPublicToken(flow, token),
            tokenLimit,
            AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded);
        if (!tokenDecision.Allowed)
        {
            return tokenDecision;
        }

        return await IncrementAbuseCounter(
            _accountTokenVerificationAbuseCounterKeyFactory.ForPublicIpAddress(flow, ResolveClientIpAddress()),
            ipLimit,
            AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded);
    }

    private async Task ResetPublicTokenVerificationPolicy(string flow, string token)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.PublicTokenVerification.Enabled
            || _abuseCounterStore is null)
        {
            return;
        }

        await _abuseCounterStore.ResetAsync(_accountTokenVerificationAbuseCounterKeyFactory.ForPublicToken(flow, token));
        await _abuseCounterStore.ResetAsync(_accountTokenVerificationAbuseCounterKeyFactory.ForPublicIpAddress(flow, ResolveClientIpAddress()));
    }

    private async Task<AbuseDecision> CheckAccountDeleteFinalizePolicy(Guid accountId, string deleteToken)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.AccountDelete.Enabled
            || _abuseCounterStore is null)
        {
            return AbuseDecision.Allow();
        }

        TimeSpan window = TimeSpan.FromSeconds(_abuseControlSettings.AccountDelete.FinalizeAttemptWindowSeconds);
        TimeSpan cooldown = TimeSpan.FromSeconds(_abuseControlSettings.AccountDelete.CooldownSecondsAfterExhaustion);
        var accountLimit = new AbuseCounterLimit(
            _abuseControlSettings.AccountDelete.MaxFinalizeAttemptsPerAccount,
            window,
            cooldown);
        var tokenLimit = new AbuseCounterLimit(
            _abuseControlSettings.AccountDelete.MaxFinalizeAttemptsPerToken,
            window,
            cooldown);

        AbuseDecision accountDecision = await IncrementAbuseCounter(
            _accountTokenVerificationAbuseCounterKeyFactory.ForAccountDeleteFinalizeAccount(accountId),
            accountLimit,
            AbuseReasonCodes.AccountDeleteFinalizeAttemptsExceeded);
        if (!accountDecision.Allowed)
        {
            return accountDecision;
        }

        return await IncrementAbuseCounter(
            _accountTokenVerificationAbuseCounterKeyFactory.ForAccountDeleteFinalizeToken(deleteToken),
            tokenLimit,
            AbuseReasonCodes.AccountDeleteFinalizeAttemptsExceeded);
    }

    private async Task ResetAccountDeleteFinalizePolicy(Guid accountId, string deleteToken)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.AccountDelete.Enabled
            || _abuseCounterStore is null)
        {
            return;
        }

        await _abuseCounterStore.ResetAsync(_accountTokenVerificationAbuseCounterKeyFactory.ForAccountDeleteFinalizeAccount(accountId));
        await _abuseCounterStore.ResetAsync(_accountTokenVerificationAbuseCounterKeyFactory.ForAccountDeleteFinalizeToken(deleteToken));
    }

    private async Task<AbuseDecision> IncrementAbuseCounter(
        AbuseCounterKey key,
        AbuseCounterLimit limit,
        string throttleReasonCode)
    {
        CounterDecision decision = await _abuseCounterStore!.IncrementAsync(key, limit);
        if (decision.CanAdmit)
        {
            return AbuseDecision.Allow();
        }

        string reasonCode = decision.ReasonCode == AbuseReasonCodes.CounterStoreUnavailable || decision.ReasonCode == AbuseReasonCodes.CounterStoreTimeout
            ? decision.ReasonCode!
            : throttleReasonCode;

        return AbuseDecision.Deny(reasonCode, decision.RetryAfter);
    }

    private string ResolveClientIpAddress()
    {
        IPAddress? remoteIp = _httpContextAccessor?.HttpContext?.Connection.RemoteIpAddress;
        return remoteIp?.ToString() ?? "unknown";
    }



    private Period BuildVerificationPeriod()
    {
        return new PeriodBuilder
        {
            Weeks = _registrationSettings.VerifyAccountPeriodWeeks,
            Days = _registrationSettings.VerifyAccountPeriodDays,
            Hours = _registrationSettings.VerifyAccountPeriodHours
        }.Build();
    }

    private Period BuildEmailChangeVerificationPeriod()
    {
        if (_registrationSettings.EmailChangeVerifyPeriodWeeks == 0 &&
            _registrationSettings.EmailChangeVerifyPeriodDays == 0 &&
            _registrationSettings.EmailChangeVerifyPeriodHours == 0)
        {
            return BuildVerificationPeriod();
        }

        return new PeriodBuilder
        {
            Weeks = _registrationSettings.EmailChangeVerifyPeriodWeeks,
            Days = _registrationSettings.EmailChangeVerifyPeriodDays,
            Hours = _registrationSettings.EmailChangeVerifyPeriodHours
        }.Build();
    }

    private Period BuildAccountDeleteTokenPeriod()
    {
        if (_registrationSettings.AccountDeleteTokenPeriodWeeks == 0 &&
            _registrationSettings.AccountDeleteTokenPeriodDays == 0 &&
            _registrationSettings.AccountDeleteTokenPeriodHours == 0)
        {
            return BuildVerificationPeriod();
        }

        return new PeriodBuilder
        {
            Weeks = _registrationSettings.AccountDeleteTokenPeriodWeeks,
            Days = _registrationSettings.AccountDeleteTokenPeriodDays,
            Hours = _registrationSettings.AccountDeleteTokenPeriodHours
        }.Build();
    }

    private Period BuildDeleteRequestCooldownPeriod()
    {
        return Period.FromMinutes(_registrationSettings.DeleteRequestCooldownMinutes);
    }

    private Period BuildDeleteRequestWindowPeriod()
    {
        return Period.FromHours(_registrationSettings.DeleteRequestWindowHours);
    }

    private Period BuildDeleteFinalizeLockoutPeriod()
    {
        return Period.FromMinutes(_registrationSettings.DeleteFinalizeLockoutMinutes);
    }


    private string BuildVerificationUrl(string verifyKey) => _verificationLinks.Registration(verifyKey);
    private string BuildEmailChangeVerificationUrl(string verifyKey) => _verificationLinks.EmailChange(verifyKey);
    private string BuildAccountDeleteVerificationUrl(string deleteToken) => _verificationLinks.Delete(deleteToken);
}
