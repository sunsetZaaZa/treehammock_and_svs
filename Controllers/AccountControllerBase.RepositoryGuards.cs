using treehammock.Rigging.Dependencies;
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
{
    protected async Task<CredentialLookupResult?> SafeGetCredentials(AuthenticateLogin payload, AccountLoginAction action)
    {
        try
        {
            return await _accountRepo.GetCredentials(payload, action, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return CredentialLookupResult.Failed();
        }
    }

    protected async Task<TwoFactorDetailsLookupResult?> SafeGetTwoFactorDetails(Guid accountId)
    {
        try
        {
            return await _accountRepo.GetTwoFactorDetails(accountId, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return TwoFactorDetailsLookupResult.Failed();
        }
    }

    protected async Task<bool?> SafeSetLockOut(Guid accountId, short? loginFailures)
    {
        try
        {
            return await _accountRepo.SetLockOut(accountId, loginFailures, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<bool?> SafeRemoveLockOut(Guid accountId)
    {
        try
        {
            return await _accountRepo.RemoveLockOut(accountId, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<bool?> SafeSetLoginFailures(Guid accountId, int failures)
    {
        try
        {
            return await _accountRepo.SetLoginFailures(accountId, failures, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<bool?> SafeSuccessfulLogin(Guid accountId, Guid accountSecurityStamp)
    {
        try
        {
            return await _accountRepo.SuccessfulLogin(accountId, accountSecurityStamp, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }


    protected async Task<IntraMessage?> SafeSetSession(string hashedAccessToken, Session record)
    {
        try
        {
            return await _sessionRepo.SetSession(hashedAccessToken, record, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<SessionRotationResult?> SafeRotateActiveSession(Guid accountId, string expectedOldAccessTokenHash, string newAccessTokenHash, Session newSession)
    {
        try
        {
            return await _sessionRepo.RotateActiveSession(accountId, expectedOldAccessTokenHash, newAccessTokenHash, newSession, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<bool?> SafeExpireSession(string hashedAccessToken, Instant? newExpiration)
    {
        try
        {
            return await _sessionRepo.ExpireSession(hashedAccessToken, newExpiration, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<DbCommandResult?> SafeLogoutCurrentSession(Guid accountId, string hashedAccessToken, Guid accountSecurityStamp)
    {
        try
        {
            return await _sessionRepo.LogoutCurrentSession(accountId, hashedAccessToken, accountSecurityStamp, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountStampRotationResult?> SafeLogoutAllSessions(Guid accountId, Guid accountSecurityStamp)
    {
        try
        {
            return await _sessionRepo.LogoutAllSessions(accountId, accountSecurityStamp, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<IReadOnlyList<AccountSessionSummary>?> SafeListActiveSessions(Guid accountId, Guid accountSecurityStamp, string currentAccessTokenHash)
    {
        try
        {
            return await _sessionRepo.ListActiveSessions(accountId, accountSecurityStamp, currentAccessTokenHash, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountAdjustResult?> SafeModifyUsername(Guid accountId, Guid accountSecurityStamp, string username)
    {
        try
        {
            return await _accountRepo.ModifyUsername(accountId, accountSecurityStamp, username, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountAdjustResult?> SafeRequestEmailChange(Guid accountId, Guid accountSecurityStamp, string newEmailAddress, treehammock.DataLayer.Security.SensitiveActionGrant grant)
    {
        try
        {
            return await _accountService.RequestEmailChange(accountId, accountSecurityStamp, newEmailAddress, cancellationToken: HttpContext.RequestAborted, grant: grant);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountAdjustResult?> SafeCompleteEmailChange(string verifyKey)
    {
        try
        {
            return await _accountService.CompleteEmailChange(verifyKey, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountViewResult?> SafeViewAccount(Guid accountId, Guid accountSecurityStamp)
    {
        try
        {
            return await _accountRepo.ViewAccount(accountId, accountSecurityStamp, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountDeleteCommandResult?> SafeRequestAccountDelete(Guid accountId, Guid accountSecurityStamp, string? passPhrase, treehammock.DataLayer.Security.SensitiveActionGrant grant)
    {
        try
        {
            return await _accountService.RequestAccountDelete(accountId, accountSecurityStamp, passPhrase, cancellationToken: HttpContext.RequestAborted,grant:grant);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountDeleteCommandResult?> SafeVerifyAccountDeleteToken(string deleteToken)
    {
        try
        {
            return await _accountService.VerifyAccountDeleteToken(deleteToken, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountDeleteCommandResult?> SafeFinalizeAccountDelete(
        Guid accountId,
        Guid accountSecurityStamp,
        string deleteToken,
        string? passPhrase, string sessionHash)
    {
        try
        {
            return await _accountService.FinalizeAccountDelete(accountId, accountSecurityStamp, deleteToken, passPhrase, cancellationToken: HttpContext.RequestAborted,sessionHash:sessionHash);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }


    protected async Task<DbCommandResult?> SafeRevokeSessionForAccount(Guid accountId, Guid targetSessionId, Guid accountSecurityStamp, string currentAccessTokenHash)
    {
        try
        {
            return await _sessionRepo.RevokeSessionForAccount(accountId, targetSessionId, accountSecurityStamp, currentAccessTokenHash, cancellationToken: HttpContext.RequestAborted);
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return null;
        }
    }

    protected async Task<PendingSessionWriteResult> SafeSetPendingTwoFactorSession(string hashedPreAuthToken, TwoFactorSession session, TimeSpan ttl)
    {
        try
        {
            return new PendingSessionWriteResult(await treehammock.Rigging.Dependencies.DependencyDeadline.RunAsync(
                token => _twoFactorSessionService.SetSession(hashedPreAuthToken, session, ttl, cancellationToken: token),
                new SessionCacheFallbackSettings().CacheWriteTimeout, HttpContext.RequestAborted));
        }
        catch (OperationCanceledException) { throw; }
        catch (DependencyUnavailableException) { return new PendingSessionWriteResult(null, ExceptionThrown: true); }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return new PendingSessionWriteResult(null, ExceptionThrown: true);
        }
    }

    protected async Task<PendingSessionRevokeResult> SafeRevokePendingTwoFactorSession(string hashedPreAuthToken)
    {
        try
        {
            return new PendingSessionRevokeResult(await DependencyDeadline.RunAsync(
                token => _twoFactorSessionService.RevokeSession(hashedPreAuthToken, cancellationToken: token),
                new SessionCacheFallbackSettings().CacheWriteTimeout, HttpContext.RequestAborted));
        }
        catch (OperationCanceledException) when (HttpContext.RequestAborted.IsCancellationRequested) { throw; }
        catch { return new PendingSessionRevokeResult(false, ExceptionThrown: true); }
    }

    protected async Task<ActiveCacheWriteResult> SafeSetActiveSession(string hashedAccessToken, ActiveSession session, TimeSpan ttl)
    {
        try
        {
            var now = NodaTime.SystemClock.Instance.GetCurrentInstant();
            if (session.entitlements?.NextBoundary is { } boundary && boundary - now < NodaTime.Duration.FromTimeSpan(ttl))
                ttl = (boundary - now).ToTimeSpan();
            if (ttl <= TimeSpan.Zero || session.entitlements is null) return new ActiveCacheWriteResult(false);
            return new ActiveCacheWriteResult(await _activeUserCacheService.SetSession(hashedAccessToken, session, ttl, cancellationToken: HttpContext.RequestAborted));
        }
        catch (OperationCanceledException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return new ActiveCacheWriteResult(false, ExceptionThrown: true);
        }
    }

    protected async Task<ActiveSessionRevokeResult> SafeRevokeActiveSession(string hashedAccessToken)
    {
        try
        {
            return new ActiveSessionRevokeResult(await _activeUserCacheService.RevokeSession(hashedAccessToken, cancellationToken: HttpContext.RequestAborted));
        }
        catch (OperationCanceledException) { throw; }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return new ActiveSessionRevokeResult(false, ExceptionThrown: true);
        }
    }

    protected ActiveSession BuildPromotedActiveSession(TwoFactorSession session, byte[] refreshToken, Instant moment, out Period cachePeriod)
    {
        Period sessionLifespan = BuildDatabaseSessionLifespan();
        Instant sessionExpiration = moment.Plus(sessionLifespan.ToDuration());
        Instant accessExpiration = ResolveAccessExpiration(moment, sessionExpiration, session.cutOff, out cachePeriod);

        return new ActiveSession(
            session.accountId,
            refreshToken,
            0,
            moment,
            sessionLifespan,
            accessExpiration,
            sessionExpiration,
            session.cutOff,
            session.features,
            // A pending 2FA session cannot supply entitlement authority. PromoteAsync
            // loads the committed projection from YSQL before cache/output publication.
            accountSecurityStamp: session.accountSecurityStamp);
    }

}
