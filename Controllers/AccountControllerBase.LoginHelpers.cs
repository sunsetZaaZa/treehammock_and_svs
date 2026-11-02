using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Globalization;

using NodaTime;
using Geralt;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Models.Authentication;
using treehammock.Models.Account;
using treehammock.Repos;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Authorization;
using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Services;
using treehammock.RiggingSupport.Status;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.Entities;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;
using treehammock.Rigging.Security;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Replay;
using treehammock.Models.Api;

namespace treehammock.Controllers;

public abstract partial class AccountControllerBase
{    protected ApiOutcome<AuthenticateResponse> SerializeAuthenticate(
        HttpMessage result,
        string? accessToken = null,
        List<TwoFactorAuthMethod>? twoFactorAuthMethods = null,
        Duration? lockoutDuration = null,
        int? statusCode = null,
        string? code = null,
        string? twoFactorAccessToken = null,
        List<TwoFactorAuthConfiguration>? availableTwoFactorAuthConfigurations = null,
        ActiveSession? issuedSession = null)
    {
        if (issuedSession is not null)
        {
            Response.Headers.CacheControl = "no-store";
            Instant publicationTime = SystemClock.Instance.GetCurrentInstant();
            if (issuedSession.accessExpiration <= publicationTime || issuedSession.EffectiveSessionExpiration <= publicationTime)
            {
                Response.Headers.Remove(SessionProtocol.VersionHeader);
                Response.Headers.Remove(SessionProtocol.FamilyHeader);
                Response.Headers.Remove(SessionProtocol.GenerationHeader);
                Response.Headers.Remove("AccessToken");
                Response.Headers.Remove("RefreshToken");
                return SerializeAuthenticate(HttpMessage.AUTHENTICATION_EXPIRED);
            }
            SessionProtocol.WriteHeaders(Response, issuedSession);
        }
        return new ApiOutcome<AuthenticateResponse>(
            new AuthenticateResponse(
                result,
                accessToken,
                twoFactorAuthMethods,
                lockoutDuration,
                twoFactorAccessToken,
                availableTwoFactorAuthConfigurations) { session = issuedSession is null ? null : SessionProtocol.Credentials(issuedSession) },
            statusCode ?? LoginStatus(result),
            code ?? result.ToString());
    }


    protected bool HasValidPasswordShape(AuthenticateLogin payload)
    {
        return !string.IsNullOrWhiteSpace(payload.password) &&
            payload.password.Length >= _registrationSettings.MinPasswordLength &&
            payload.password.Length <= _registrationSettings.MaxPasswordLength;
    }


    protected LoginIdentifierValidation ValidateLoginIdentifiers(AuthenticateLogin payload)
    {
        var errors = new List<ApiValidationError>();

        bool emailSupplied = !string.IsNullOrWhiteSpace(payload.emailAddress);
        bool emailValid = emailSupplied &&
            payload.emailAddress!.Length <= _registrationSettings.MaxEmailAddressLength &&
            _emailValidator.IsValid(payload.emailAddress);

        bool usernameSupplied = !string.IsNullOrWhiteSpace(payload.username);
        bool usernameValid = usernameSupplied &&
            payload.username!.Length >= _registrationSettings.MinUsernameLength &&
            payload.username.Length <= _registrationSettings.MaxUsernameLength;

        if (!emailSupplied && !usernameSupplied)
        {
            errors.Add(ValidationError(
                nameof(AuthenticateLogin.emailAddress),
                "Either emailAddress or username is required."));
            errors.Add(ValidationError(
                nameof(AuthenticateLogin.username),
                "Either emailAddress or username is required."));
        }

        if (emailSupplied && !emailValid)
        {
            errors.Add(ValidationError(
                nameof(AuthenticateLogin.emailAddress),
                $"emailAddress must be a valid email address no longer than {_registrationSettings.MaxEmailAddressLength} characters when supplied."));
        }

        if (usernameSupplied && !usernameValid)
        {
            errors.Add(ValidationError(
                nameof(AuthenticateLogin.username),
                $"username must be between {_registrationSettings.MinUsernameLength} and {_registrationSettings.MaxUsernameLength} characters when supplied."));
        }

        if (errors.Count > 0)
        {
            return new LoginIdentifierValidation(AccountLoginAction.NONE, errors);
        }

        AccountLoginAction action = (emailValid, usernameValid) switch
        {
            (true, true) => AccountLoginAction.BOTH,
            (true, false) => AccountLoginAction.EMAIL,
            (false, true) => AccountLoginAction.USERNAME,
            _ => AccountLoginAction.NONE
        };

        return new LoginIdentifierValidation(action, Array.Empty<ApiValidationError>());
    }


    protected AbuseCounterLimit BuildLoginAbuseLimit(int maxAttempts)
    {
        LoginAbusePolicySettings settings = _abuseControlSettings.Login;
        return new AbuseCounterLimit(
            maxAttempts,
            TimeSpan.FromSeconds(settings.WindowSeconds),
            TimeSpan.FromSeconds(settings.CooldownSeconds));
    }


    protected async Task<ApiOutcome<AuthenticateResponse>?> CheckLoginPreLookupAbusePolicy(AuthenticateLogin payload)
    {
        if (!_abuseControlSettings.Enabled || !_abuseControlSettings.Login.Enabled)
        {
            return null;
        }

        foreach (AbuseCounterKey key in BuildLoginPreLookupAbuseKeys(payload))
        {
            int maxAttempts = key.Dimension == AbuseCounterDimension.IpFingerprint
                ? _abuseControlSettings.Login.MaxAttemptsPerIpPerWindow
                : _abuseControlSettings.Login.MaxAttemptsPerIdentifierPerWindow;

            ApiOutcome<AuthenticateResponse>? blocked = await CheckLoginAbuseCounter(
                key,
                BuildLoginAbuseLimit(maxAttempts),
                exposeAbuseReason: true);
            if (blocked != null)
            {
                return blocked;
            }
        }

        return null;
    }


    protected async Task<ApiOutcome<AuthenticateResponse>?> CheckLoginAccountAbusePolicy(Guid accountId)
    {
        if (!_abuseControlSettings.Enabled || !_abuseControlSettings.Login.Enabled)
        {
            return null;
        }

        AbuseCounterKey key = _loginAbuseCounterKeyFactory.ForAccount(accountId);
        return await CheckLoginAbuseCounter(
            key,
            BuildLoginAbuseLimit(_abuseControlSettings.Login.MaxAttemptsPerAccountPerWindow),
            exposeAbuseReason: false);
    }


    protected async Task<ApiOutcome<AuthenticateResponse>?> CheckLoginAbuseCounter(
        AbuseCounterKey key,
        AbuseCounterLimit limit,
        bool exposeAbuseReason)
    {
        CounterDecision decision = await _abuseCounterStore.IncrementAsync(key, limit);
        if (decision.CanAdmit)
        {
            return null;
        }

        AbuseOperationalTelemetry.RecordLoginThrottled(key.Dimension, decision.ReasonCode ?? AbuseReasonCodes.LoginThrottleExceeded);

        if (!exposeAbuseReason)
        {
            return SerializeAuthenticate(HttpMessage.AUTHENTICATION_FAILED);
        }

        if (decision.RetryAfter.HasValue && HttpContext?.Response != null)
        {
            HttpContext.Response.Headers["Retry-After"] = Math.Ceiling(decision.RetryAfter.Value.TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }

        string reasonCode = decision.ReasonCode == AbuseReasonCodes.CounterStoreUnavailable || decision.ReasonCode == AbuseReasonCodes.CounterStoreTimeout
            ? decision.ReasonCode!
            : AbuseReasonCodes.LoginThrottleExceeded;
        int statusCode = reasonCode == AbuseReasonCodes.LoginThrottleExceeded
            ? StatusCodes.Status429TooManyRequests
            : StatusCodes.Status503ServiceUnavailable;

        return SerializeAuthenticate(
            HttpMessage.AUTHENTICATION_FAILED,
            statusCode: statusCode,
            code: reasonCode);
    }


    protected IEnumerable<AbuseCounterKey> BuildLoginPreLookupAbuseKeys(AuthenticateLogin payload)
    {
        yield return _loginAbuseCounterKeyFactory.ForIpAddress(ResolveRemoteIpAddress());

        if (!string.IsNullOrWhiteSpace(payload.emailAddress))
        {
            yield return _loginAbuseCounterKeyFactory.ForIdentifier("email", payload.emailAddress!);
        }

        if (!string.IsNullOrWhiteSpace(payload.username))
        {
            yield return _loginAbuseCounterKeyFactory.ForIdentifier("username", payload.username!);
        }
    }


    protected async Task ResetLoginAbusePolicyAfterSuccessfulPassword(Guid accountId, AuthenticateLogin payload)
    {
        if (!_abuseControlSettings.Enabled || !_abuseControlSettings.Login.Enabled)
        {
            return;
        }

        await _abuseCounterStore.ResetAsync(_loginAbuseCounterKeyFactory.ForAccount(accountId));

        if (!string.IsNullOrWhiteSpace(payload.emailAddress))
        {
            await _abuseCounterStore.ResetAsync(_loginAbuseCounterKeyFactory.ForIdentifier("email", payload.emailAddress!));
        }

        if (!string.IsNullOrWhiteSpace(payload.username))
        {
            await _abuseCounterStore.ResetAsync(_loginAbuseCounterKeyFactory.ForIdentifier("username", payload.username!));
        }
    }


    protected string? ResolveRemoteIpAddress()
    {
        return HttpContext?.Connection.RemoteIpAddress?.ToString();
    }


    protected async Task<AbuseDecision> CheckPublicTokenVerificationPolicy(string flow, string token)
    {
        if (!_abuseControlSettings.Enabled || !_abuseControlSettings.PublicTokenVerification.Enabled)
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

        AbuseDecision tokenDecision = await IncrementPublicTokenVerificationCounter(
            _accountTokenVerificationAbuseCounterKeyFactory.ForPublicToken(flow, token),
            tokenLimit);
        if (!tokenDecision.Allowed)
        {
            return tokenDecision;
        }

        return await IncrementPublicTokenVerificationCounter(
            _accountTokenVerificationAbuseCounterKeyFactory.ForPublicIpAddress(flow, ResolveRemoteIpAddress()),
            ipLimit);
    }


    protected async Task ResetPublicTokenVerificationPolicy(string flow, string token)
    {
        if (!_abuseControlSettings.Enabled || !_abuseControlSettings.PublicTokenVerification.Enabled)
        {
            return;
        }

        await _abuseCounterStore.ResetAsync(_accountTokenVerificationAbuseCounterKeyFactory.ForPublicToken(flow, token));
        await _abuseCounterStore.ResetAsync(_accountTokenVerificationAbuseCounterKeyFactory.ForPublicIpAddress(flow, ResolveRemoteIpAddress()));
    }


    protected async Task<AbuseDecision> IncrementPublicTokenVerificationCounter(
        AbuseCounterKey key,
        AbuseCounterLimit limit)
    {
        CounterDecision decision = await _abuseCounterStore.IncrementAsync(key, limit);
        if (decision.CanAdmit)
        {
            return AbuseDecision.Allow();
        }

        string reasonCode = decision.ReasonCode == AbuseReasonCodes.CounterStoreUnavailable || decision.ReasonCode == AbuseReasonCodes.CounterStoreTimeout
            ? decision.ReasonCode!
            : AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded;

        return AbuseDecision.Deny(reasonCode, decision.RetryAfter);
    }


    protected async Task<ApiOutcome<AuthenticateResponse>?> CheckVerificationStatus(IntraAccount singleAccount)
    {
        if (singleAccount.verifyStatus == VerificationStatus.SUCCESSFUL)
        {
            return null;
        }

        if (singleAccount.verifyStatus == VerificationStatus.SENT || singleAccount.verifyStatus == VerificationStatus.REFRESHED)
        {
            return SerializeAuthenticate(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING);
        }

        if (singleAccount.verifyStatus == VerificationStatus.EXPIRED)
        {
            LoginFailurePersistenceResult persistenceResult = await PersistLoginFailures(singleAccount, 3);
            // Expired verification is the trigger, but once the retry threshold locks the account,
            // return the current account state so clients stop prompting for verification renewal.
            return persistenceResult switch
            {
                LoginFailurePersistenceResult.Failed => LoginAttemptPersistenceFailed(),
                LoginFailurePersistenceResult.Locked => SerializeAuthenticate(HttpMessage.ACCOUNT_LOCKED),
                _ => SerializeAuthenticate(HttpMessage.ACCOUNT_CREATION_VERIFICATION_RENEW)
            };
        }

        return SerializeAuthenticate(HttpMessage.AUTHENTICATION_FAILED);
    }


    protected async Task<ApiOutcome<AuthenticateResponse>?> CheckLockout(IntraAccount singleAccount, Instant moment)
    {
        if (singleAccount.unlockWhen == null)
        {
            return null;
        }

        if (singleAccount.unlockWhen.Value > moment)
        {
            return SerializeAuthenticate(HttpMessage.ACCOUNT_TIME_LOCKED, lockoutDuration: singleAccount.unlockWhen.Value - moment);
        }

        var cleared = await _accountRepo.ClearLoginAttempts(singleAccount.accountId, singleAccount.accountSecurityStamp,
            singleAccount.loginAttemptVersion, singleAccount.loginFailures, singleAccount.unlockWhen, true, HttpContext.RequestAborted);
        if (!cleared.Result)
        {
            return LockoutCleanupFailed();
        }

        singleAccount.unlockWhen = cleared.UnlockWhen;
        singleAccount.loginFailures = cleared.Failures;
        singleAccount.loginAttemptVersion = cleared.Version;
        return null;
    }


    protected async Task<ApiOutcome<AuthenticateResponse>> FailPasswordAttempt(IntraAccount singleAccount)
    {
        LoginFailurePersistenceResult persistenceResult = await PersistLoginFailures(singleAccount, 1);

        return persistenceResult switch
        {
            LoginFailurePersistenceResult.Recorded => SerializeAuthenticate(HttpMessage.AUTHENTICATION_FAILED),
            LoginFailurePersistenceResult.Locked => SerializeAuthenticate(HttpMessage.ACCOUNT_LOCKED),
            _ => LoginAttemptPersistenceFailed()
        };
    }


    protected async Task<LoginFailurePersistenceResult> PersistLoginFailures(IntraAccount singleAccount, int charge)
    {
        var result = await _accountRepo.RecordLoginFailure(singleAccount.accountId, singleAccount.accountSecurityStamp,
            charge, _loginSettings.PasswordRetryLimit, HttpContext.RequestAborted);
        if (!result.Result) return LoginFailurePersistenceResult.Failed;
        singleAccount.loginFailures = result.Failures; singleAccount.unlockWhen = result.UnlockWhen; singleAccount.loginAttemptVersion = result.Version;
        return result.Code == "LOCKED" ? LoginFailurePersistenceResult.Locked : LoginFailurePersistenceResult.Recorded;
    }

    protected static ApiOutcome<AuthenticateResponse> LoginAttemptPersistenceFailed()
    {
        return new ApiOutcome<AuthenticateResponse>(
            new AuthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
            StatusCodes.Status500InternalServerError,
            LoginAttemptPersistenceFailedCode);
    }


    protected static ApiOutcome<AuthenticateResponse> LockoutCleanupFailed()
    {
        return new ApiOutcome<AuthenticateResponse>(
            new AuthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
            StatusCodes.Status500InternalServerError,
            LockoutCleanupFailedCode);
    }


    protected static ApiOutcome<AuthenticateResponse> TwoFactorPreAuthPersistenceFailed()
    {
        return new ApiOutcome<AuthenticateResponse>(
            new AuthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
            StatusCodes.Status500InternalServerError,
            TwoFactorPreAuthPersistenceFailedCode);
    }


    protected static ApiOutcome<AuthenticateResponse> TwoFactorSessionRevokeFailedAuthenticate()
    {
        return new ApiOutcome<AuthenticateResponse>(
            new AuthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
            StatusCodes.Status500InternalServerError,
            TwoFactorSessionRevokeFailedCode);
    }


    protected static ApiOutcome<AuthenticateResponse> TwoFactorChallengePersistenceFailedAuthenticate()
    {
        return new ApiOutcome<AuthenticateResponse>(
            new AuthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
            StatusCodes.Status500InternalServerError,
            TwoFactorChallengePersistenceFailedCode);
    }


    protected static ApiOutcome<AuthenticateResponse> TwoFactorDetailsLookupFailedAuthenticate()
    {
        return new ApiOutcome<AuthenticateResponse>(
            new AuthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
            StatusCodes.Status500InternalServerError,
            TwoFactorDetailsLookupFailedCode);
    }


    protected static ApiOutcome<AuthenticateResponse> TwoFactorDetailsNotConfiguredAuthenticate()
    {
        return new ApiOutcome<AuthenticateResponse>(
            new AuthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
            StatusCodes.Status500InternalServerError,
            TwoFactorDetailsNotConfiguredCode);
    }


    protected static ApiOutcome<AuthenticateResponse> ActiveSessionRollbackFailedAuthenticate(ActiveSessionRollbackResult rollback)
    {
        return new ApiOutcome<AuthenticateResponse>(
            new AuthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
            StatusCodes.Status500InternalServerError,
            ActiveSessionRollbackCode(rollback));
    }


    protected static ApiOutcome<LayeredAuthenticateResponse> ActiveSessionRollbackFailedTwoFactor(ActiveSessionRollbackResult rollback)
    {
        return new ApiOutcome<LayeredAuthenticateResponse>(
            new LayeredAuthenticateResponse(TwoFactorAuthOutcome.FAILURE),
            StatusCodes.Status500InternalServerError,
            ActiveSessionRollbackCode(rollback));
    }


    protected static string ActiveSessionRollbackCode(ActiveSessionRollbackResult rollback)
    {
        return rollback.Status switch
        {
            ActiveSessionRollbackStatus.DatabaseExpireFailed => ActiveSessionDbExpireFailedCode,
            ActiveSessionRollbackStatus.CacheAndDatabaseFailed => ActiveSessionRollbackFailedCode,
            _ => ActiveSessionRollbackFailedCode
        };
    }


    protected ApiOutcome<AuthenticateResponse> LoginSessionPersistenceFailed(LoginSessionPersistenceResult persistenceResult)
    {
        if (persistenceResult.Rollback is { Succeeded: false } rollback)
        {
            return ActiveSessionRollbackFailedAuthenticate(rollback);
        }

        string code = persistenceResult.Status switch
        {
            LoginSessionPersistenceStatus.DatabaseSessionFailed => ActiveSessionDbPersistenceFailedCode,
            _ => HttpMessage.AUTHENTICATION_FAILED.ToString()
        };

        return new ApiOutcome<AuthenticateResponse>(
            new AuthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
            StatusCodes.Status500InternalServerError,
            code);
    }


    protected ApiOutcome<AuthenticateResponse> AuthFailureAfterRollback(ActiveSessionRollbackResult rollback)
    {
        return rollback.Succeeded
            ? SerializeAuthenticate(HttpMessage.AUTHENTICATION_FAILED, statusCode: StatusCodes.Status500InternalServerError)
            : ActiveSessionRollbackFailedAuthenticate(rollback);
    }


    protected ApiOutcome<LayeredAuthenticateResponse> TwoFactorFailureAfterRollback(ActiveSessionRollbackResult rollback, string? code = null)
    {
        return rollback.Succeeded
            ? SerializeTwoFactorAuthenticate(TwoFactorAuthOutcome.FAILURE, statusCode: StatusCodes.Status500InternalServerError, code: code)
            : ActiveSessionRollbackFailedTwoFactor(rollback);
    }


    protected ApiOutcome<LayeredAuthenticateResponse> TwoFactorFinalizationFailureAfterRollback(ActiveSessionRollbackResult rollback)
    {
        return rollback.Succeeded
            ? SerializeTwoFactorAuthenticate(
                TwoFactorAuthOutcome.FAILURE,
                statusCode: StatusCodes.Status500InternalServerError,
                code: TwoFactorAccountFinalizationFailedCode)
            : SerializeTwoFactorAuthenticate(
                TwoFactorAuthOutcome.FAILURE,
                statusCode: StatusCodes.Status500InternalServerError,
                code: TwoFactorFinalizationRollbackFailedCode);
    }


    protected async Task<ApiOutcome<AuthenticateResponse>> AuthenticateAlreadyLoggedIn(IntraAccount singleAccount, Instant moment)
    {
        if (IsCutOffExpired(singleAccount, moment))
        {
            return SerializeAuthenticate(HttpMessage.AUTHENTICATION_EXPIRED);
        }

        if (singleAccount.hasTwoFactorAuth)
        {
            return await BeginTwoFactorLogin(singleAccount, moment);
        }

        if (singleAccount.refreshToken == null)
        {
            return SerializeAuthenticate(HttpMessage.AUTHENTICATION_FAILED, statusCode: StatusCodes.Status500InternalServerError);
        }

        string? oldHashedAccessToken = singleAccount.activeAccessTokenHash;
        if (string.IsNullOrWhiteSpace(oldHashedAccessToken))
        {
            return SerializeAuthenticate(HttpMessage.AUTHENTICATION_FAILED, statusCode: StatusCodes.Status500InternalServerError);
        }

        singleAccount.refreshToken = RandomNumberGenerator.GetBytes(_jwtSettings.RefreshTokenBytes);
        string newAccessToken = _jwtUtility.GenerateAccessToken(singleAccount.refreshToken, singleAccount.webKey);
        string? newHashedAccessToken = HashAccessToken(newAccessToken);
        if (newHashedAccessToken == null)
        {
            return SerializeAuthenticate(HttpMessage.AUTHENTICATION_FAILED, statusCode: StatusCodes.Status500InternalServerError);
        }

        ActiveSession rebuiltSession = BuildFreshPasswordRotatedActiveSession(singleAccount, moment, out Period cachePeriod);

        var databaseSession = rebuiltSession.toSession();
        SessionRotationResult? rotated = await SafeRotateActiveSession(
            singleAccount.accountId,
            oldHashedAccessToken,
            newHashedAccessToken,
            databaseSession);
        if (rotated?.Succeeded != true)
        {
            return SerializeAuthenticate(HttpMessage.AUTHENTICATION_FAILED, statusCode: StatusCodes.Status500InternalServerError);
        }

        rebuiltSession.entitlements = databaseSession.entitlements;
        rebuiltSession.features = databaseSession.features;
        ActiveCacheWriteResult cached = await SafeSetActiveSession(newHashedAccessToken, rebuiltSession, cachePeriod.ToDuration().ToTimeSpan());
        if (!cached.Stored)
        {
            // CORE-2: the database rotation is authoritative. A Redis write miss is a cache
            // miss, not a failed login; the next request can hydrate the active session from DB.
        }

        // The database rotation is now authoritative. Revoking the old Redis entry is best-effort:
        // if Redis fails here, the old DB session has already been expired and cached trust
        // validation will reject any stale old-cache hit.
        _ = await SafeRevokeActiveSession(oldHashedAccessToken);

        return SerializeAuthenticate(HttpMessage.AUTHENTICATION_PASSED, newAccessToken, issuedSession: rebuiltSession);
    }


    protected async Task<ApiOutcome<AuthenticateResponse>> AuthenticateNotLoggedIn(IntraAccount singleAccount, Instant moment)
    {
        if (IsCutOffExpired(singleAccount, moment))
        {
            return SerializeAuthenticate(HttpMessage.AUTHENTICATION_EXPIRED);
        }

        if (singleAccount.hasTwoFactorAuth)
        {
            return await BeginTwoFactorLogin(singleAccount, moment);
        }

        singleAccount.refreshToken = RandomNumberGenerator.GetBytes(_jwtSettings.RefreshTokenBytes);
        string accessToken = _jwtUtility.GenerateAccessToken(singleAccount.refreshToken, singleAccount.webKey);
        string? hashedAccessToken = HashAccessToken(accessToken);
        if (hashedAccessToken == null)
        {
            return SerializeAuthenticate(HttpMessage.AUTHENTICATION_FAILED, statusCode: StatusCodes.Status500InternalServerError);
        }

        ActiveSession activeSession = BuildActiveSession(singleAccount, moment, out Period cachePeriod, true);
        LoginSessionPersistenceResult persistenceResult = await PersistNewActiveSession(hashedAccessToken, activeSession, cachePeriod);
        if (!persistenceResult.Succeeded)
        {
            return LoginSessionPersistenceFailed(persistenceResult);
        }

        return SerializeAuthenticate(HttpMessage.AUTHENTICATION_PASSED, accessToken, issuedSession: activeSession);
    }


    protected async Task<LoginSessionPersistenceResult> PersistNewActiveSession(string hashedAccessToken, ActiveSession activeSession, Period cachePeriod)
    {
        var databaseSession = activeSession.toSession();
        IntraMessage? dbSessionResult = await SafeSetSession(hashedAccessToken, databaseSession);
        if (!IsSuccessfulSessionResult(dbSessionResult))
        {
            return new LoginSessionPersistenceResult(LoginSessionPersistenceStatus.DatabaseSessionFailed);
        }

        activeSession.entitlements = databaseSession.entitlements;
        activeSession.features = databaseSession.features;
        ActiveCacheWriteResult cached = await SafeSetActiveSession(hashedAccessToken, activeSession, cachePeriod.ToDuration().ToTimeSpan());
        if (!cached.Stored)
        {
            // CORE-2: DB session creation succeeded, so keep it. Redis is a cache and can be
            // hydrated from get_session on the next request.
        }

        return new LoginSessionPersistenceResult(LoginSessionPersistenceStatus.Success);
    }


    protected static bool IsSuccessfulSessionResult(IntraMessage? result)
    {
        return result is IntraMessage.SUCCESSFUL or IntraMessage.AUTHENTICATION_PASSED;
    }


    protected async Task<ActiveSessionRollbackResult> RollBackNewActiveSession(string hashedAccessToken)
    {
        ActiveSessionRevokeResult cacheResult = await SafeRevokeActiveSession(hashedAccessToken);
        bool dbExpired;
        try
        {
            dbExpired = await SafeExpireSession(hashedAccessToken, null) == true;
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            dbExpired = false;
        }

        return BuildRollbackResult(cacheResult.Revoked, dbExpired);
    }


    protected static ActiveSessionRollbackResult BuildRollbackResult(bool cacheRevoked, bool dbExpired)
    {
        // CORE-2: database invalidation is authoritative. If the DB row was expired, a failed
        // Redis revoke is non-fatal because stale cache entries fail DB trust validation.
        if (dbExpired)
        {
            return new ActiveSessionRollbackResult(ActiveSessionRollbackStatus.Success);
        }

        return new ActiveSessionRollbackResult(cacheRevoked
            ? ActiveSessionRollbackStatus.DatabaseExpireFailed
            : ActiveSessionRollbackStatus.CacheAndDatabaseFailed);
    }


    protected async Task<ApiOutcome<AuthenticateResponse>> BeginTwoFactorLogin(IntraAccount singleAccount, Instant moment)
    {
        if (IsCutOffExpired(singleAccount, moment))
        {
            return SerializeAuthenticate(HttpMessage.AUTHENTICATION_EXPIRED);
        }

        TwoFactorDetailsLookupResult? detailsLookup = await SafeGetTwoFactorDetails(singleAccount.accountId);
        if (detailsLookup == null || detailsLookup.Status == TwoFactorDetailsLookupStatus.Failed)
        {
            return TwoFactorDetailsLookupFailedAuthenticate();
        }

        if (detailsLookup.Status == TwoFactorDetailsLookupStatus.NotConfigured)
        {
            return TwoFactorDetailsNotConfiguredAuthenticate();
        }

        TwoFactorDetails twoFactorDetails = detailsLookup.Details!;
        List<TwoFactorAuthMethod> methods = GetUsableTwoFactorMethods(singleAccount, twoFactorDetails);
        List<TwoFactorAuthConfiguration> availableConfigurations = TwoFactorAuthConfigurationResolver.AvailableFromMethods(methods);
        if (methods.Count == 0 || availableConfigurations.Count == 0)
        {
            return TwoFactorDetailsNotConfiguredAuthenticate();
        }

        byte[] preAuthRefreshToken = RandomNumberGenerator.GetBytes(_jwtSettings.RefreshTokenBytes);
        string preAuthToken = _jwtUtility.GenerateAccessToken(preAuthRefreshToken, singleAccount.webKey, JsonWebTokenPurpose.PreAuthTwoFactor);
        string? hashedPreAuthToken = HashAccessToken(preAuthToken);
        if (hashedPreAuthToken == null)
        {
            return SerializeAuthenticate(HttpMessage.AUTHENTICATION_FAILED, statusCode: StatusCodes.Status500InternalServerError);
        }

        Period twoFactorPeriod = BuildPeriod(_jwtSettings.RefreshTokenAliveDays_2FA, _jwtSettings.RefreshTokenAliveHours_2FA, _jwtSettings.RefreshTokenAliveMinutes_2FA);
        Duration twoFactorDuration = twoFactorPeriod.ToDuration();
        Instant expiration = moment.Plus(twoFactorDuration);

        var twoFactorSession = new TwoFactorSession(
            singleAccount.accountId,
            singleAccount.webKey,
            preAuthRefreshToken,
            methods,
            twoFactorDetails.userAuthIds,
            twoFactorDetails.phoneNumbers,
            twoFactorDetails.phoneCountryCode,
            twoFactorDetails.emailAddresses,
            null,
            null,
            CountMethod(twoFactorDetails, TwoFactorAuthMethod.AUTHENTICATOR_APP),
            0,
            CountMethod(twoFactorDetails, TwoFactorAuthMethod.SMS_KEY),
            moment,
            expiration,
            singleAccount.features,
            singleAccount.cutOff,
            singleAccount.accountSecurityStamp,
            string.IsNullOrWhiteSpace(singleAccount.activeAccessTokenHash) ? null : singleAccount.activeAccessTokenHash);

        var stored = await LoginProofs.BeginAsync(hashedPreAuthToken, twoFactorSession, HttpContext.RequestAborted);
        if (!stored.Result) return TwoFactorPreAuthPersistenceFailed();
        if (stored.Snapshot is not null) twoFactorSession.ApplyDurableProofState(stored.Snapshot);
        _ = await SafeSetPendingTwoFactorSession(hashedPreAuthToken, twoFactorSession, twoFactorDuration.ToTimeSpan());

        if (!string.IsNullOrWhiteSpace(singleAccount.twoFactorAccessToken)
            && !string.Equals(singleAccount.twoFactorAccessToken, hashedPreAuthToken, StringComparison.Ordinal))
        {
            _ = await SafeRevokePendingTwoFactorSession(singleAccount.twoFactorAccessToken);
        }

        return SerializeAuthenticate(
            HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED,
            twoFactorAuthMethods: methods,
            twoFactorAccessToken: preAuthToken,
            availableTwoFactorAuthConfigurations: availableConfigurations);
    }


    // Repository lookup "Found" only means 2FA detail rows were loaded. The controller still
    // has to prove those rows contain a method the account can actually use for this login.
    protected List<TwoFactorAuthMethod> GetUsableTwoFactorMethods(IntraAccount singleAccount, TwoFactorDetails? twoFactorDetails)
    {
        // The account-level twoFactorAuthMethod field is summary metadata only. Login method
        // advertisement is driven by the verified 2FA detail rows so users with multiple
        // verified factors can choose any usable method.
        _ = singleAccount;

        if (twoFactorDetails?.methods == null || twoFactorDetails.methods.Count == 0)
        {
            return new List<TwoFactorAuthMethod>();
        }

        IEnumerable<TwoFactorAuthMethod> methods = twoFactorDetails.methods
            .Where(method => method != TwoFactorAuthMethod.NONE)
            .Where(IsSupportedTwoFactorMethod)
            .Where(method => HasUsableTwoFactorDestination(twoFactorDetails, method));

        return methods.Distinct().ToList();
    }


    protected static bool HasUsableTwoFactorDestination(TwoFactorDetails details, TwoFactorAuthMethod method)
    {
        return method switch
        {
            TwoFactorAuthMethod.EMAIL => details.emailAddresses?.Any(value => !string.IsNullOrWhiteSpace(value)) == true,
            TwoFactorAuthMethod.SMS_KEY => details.phoneNumbers?.Any(value => !string.IsNullOrWhiteSpace(value)) == true,
            TwoFactorAuthMethod.AUTHENTICATOR_APP => details.methods.Contains(TwoFactorAuthMethod.AUTHENTICATOR_APP),
            _ => false
        };
    }


    protected static short CountMethod(TwoFactorDetails details, TwoFactorAuthMethod method)
    {
        int count = details.methods.Count(item => item == method);
        return (short)Math.Min(short.MaxValue, count);
    }

    protected static short CountUsableTwoFactorDestinations(TwoFactorDetails details, IReadOnlyCollection<TwoFactorAuthMethod> usableMethods)
    {
        int count = details.methods.Count(method => method != TwoFactorAuthMethod.NONE && usableMethods.Contains(method));
        return (short)Math.Min(short.MaxValue, count);
    }


    protected short ResolveTwoFactorUsage(IntraAccount singleAccount, TwoFactorAuthMethod method)
    {
        return method switch
        {
            TwoFactorAuthMethod.AUTHENTICATOR_APP => singleAccount.authenticatorAppUsage,
            TwoFactorAuthMethod.SMS_KEY => singleAccount.smsUsage,
            _ => 0
        };
    }


    protected ActiveSession BuildFreshPasswordRotatedActiveSession(IntraAccount singleAccount, Instant moment, out Period cachePeriod)
    {
        return BuildActiveSession(
            singleAccount,
            moment,
            out cachePeriod,
            includeDatabaseLifespan: true,
            refreshesOverride: (short)0);
    }


    protected ActiveSession BuildActiveSession(
        IntraAccount singleAccount,
        Instant moment,
        out Period cachePeriod,
        bool includeDatabaseLifespan,
        short? refreshesOverride = null)
    {
        Period sessionLifespan = includeDatabaseLifespan
            ? BuildDatabaseSessionLifespan()
            : singleAccount.lifespan ?? BuildDatabaseSessionLifespan();
        Instant sessionExpiration = moment.Plus(sessionLifespan.ToDuration());
        Instant accessExpiration = ResolveAccessExpiration(moment, sessionExpiration, singleAccount.cutOff, out cachePeriod);

        if (singleAccount.refreshToken == null)
        {
            throw new InvalidOperationException("A refresh token is required before an active session can be created.");
        }

        return new ActiveSession(
            singleAccount.accountId,
            singleAccount.refreshToken,
            refreshesOverride ?? singleAccount.refreshes,
            moment,
            sessionLifespan,
            accessExpiration,
            sessionExpiration,
            singleAccount.cutOff,
            singleAccount.features,
            accountSecurityStamp: singleAccount.accountSecurityStamp, entitlements: singleAccount.entitlements);
    }


    protected Period BuildDatabaseSessionLifespan()
    {
        return BuildPeriod(_jwtSettings.RefreshTokenAliveDays_DB, _jwtSettings.RefreshTokenAliveHours_DB, _jwtSettings.RefreshTokenAliveMinutes_DB);
    }


    protected Instant ResolveAccessExpiration(Instant moment, Instant sessionExpiration, Instant? cutOff, out Period cachePeriod)
    {
        Period requestedAccessPeriod = BuildPeriod(_jwtSettings.RefreshTokenAliveDays_Short, _jwtSettings.RefreshTokenAliveHours_Short, _jwtSettings.RefreshTokenAliveMinutes_Short);

        Instant maxAccessExpiration = cutOff is not null && cutOff.Value < sessionExpiration
            ? cutOff.Value
            : sessionExpiration;
        Instant requestedAccessExpiration = moment.Plus(requestedAccessPeriod.ToDuration());

        if (maxAccessExpiration <= moment)
        {
            throw new InvalidOperationException("An active session cannot be created after the session expiration or account cutOff instant.");
        }

        if (requestedAccessExpiration <= maxAccessExpiration)
        {
            cachePeriod = requestedAccessPeriod;
            return requestedAccessExpiration;
        }

        Duration remaining = maxAccessExpiration - moment;
        int remainingMinutes = Math.Max(1, (int)Math.Ceiling(remaining.TotalMinutes));
        cachePeriod = BuildPeriod(0, 0, remainingMinutes);
        return maxAccessExpiration;
    }


    protected Period BuildPeriod(int days, int hours, int minutes)
    {
        return new PeriodBuilder
        {
            Days = days,
            Hours = hours,
            Minutes = minutes
        }.Build();
    }


    protected string? HashAccessToken(string accessToken)
    {
        return AccessTokenHashUtility.Hash(accessToken);
    }

}
