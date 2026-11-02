using treehammock.Rigging.Delivery;
using treehammock.Rigging.Dependencies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
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
{    protected static string NormalizeTwoFactorEmailContact(string contact)
    {
        return contact.Trim().ToLowerInvariant();
    }


    protected static string NormalizeTwoFactorSmsContact(string contact)
    {
        return contact.Trim();
    }


    protected static string BuildSmsSetupDestination(string phoneNumber, short countryCode)
    {
        return PhoneDestinationNormalizer.Normalize(countryCode.ToString(CultureInfo.InvariantCulture), phoneNumber);
    }


    protected AbuseCounterLimit BuildTwoFactorSetupVerifyAbuseLimit()
    {
        TwoFactorAbusePolicySettings settings = _abuseControlSettings.TwoFactor;
        TimeSpan cooldown = TimeSpan.FromSeconds(settings.SetupVerifyCooldownSecondsAfterExhaustion);
        return new AbuseCounterLimit(
            settings.MaxSetupVerifyAttemptsPerAccount,
            TimeSpan.FromSeconds(settings.SetupVerifyAttemptWindowSeconds),
            cooldown);
    }


    protected static AbuseCounterKey BuildTwoFactorSetupVerifyAbuseKey(ActiveSession activeSession, TwoFactorAuthMethod method)
    {
        string material = string.Join(
            ':',
            activeSession.accountId.ToString("N"),
            activeSession.accountSecurityStamp.ToString("N"),
            method.ToString());
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        string safeMethod = method.ToString().Trim().ToLowerInvariant();
        string safeId = $"{safeMethod}-{Convert.ToHexString(digest).ToLowerInvariant()[..24]}";
        return new AbuseCounterKey(AbuseFeature.TwoFactorSetup, AbuseCounterDimension.Account, safeId);
    }


    protected async Task<ApiOutcome<LayeredAuthenticateResponse>?> CheckTwoFactorSetupVerifyAttemptPolicy(
        ActiveSession activeSession,
        TwoFactorAuthMethod method)
    {
        if (!_abuseControlSettings.Enabled || !_abuseControlSettings.TwoFactor.Enabled)
        {
            return null;
        }

        AbuseCounterKey key = BuildTwoFactorSetupVerifyAbuseKey(activeSession, method);
        CounterDecision decision = await _abuseCounterStore.IncrementAsync(key, BuildTwoFactorSetupVerifyAbuseLimit());
        if (decision.CanAdmit)
        {
            return null;
        }

        if (decision.RetryAfter.HasValue && HttpContext?.Response != null)
        {
            HttpContext.Response.Headers["Retry-After"] = Math.Ceiling(decision.RetryAfter.Value.TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }

        string reasonCode = decision.ReasonCode == AbuseReasonCodes.CounterStoreUnavailable || decision.ReasonCode == AbuseReasonCodes.CounterStoreTimeout
            ? decision.ReasonCode!
            : AbuseReasonCodes.TwoFactorSetupAttemptsExceeded;
        int statusCode = reasonCode == AbuseReasonCodes.TwoFactorSetupAttemptsExceeded
            ? StatusCodes.Status429TooManyRequests
            : StatusCodes.Status503ServiceUnavailable;

        AbuseOperationalTelemetry.RecordTwoFactorThrottled(key.Dimension, reasonCode);

        return SerializeTwoFactorAuthenticate(
            TwoFactorAuthOutcome.FAILURE,
            statusCode: statusCode,
            code: reasonCode);
    }


    protected async Task ResetTwoFactorSetupVerifyAttemptPolicy(ActiveSession activeSession, TwoFactorAuthMethod method)
    {
        if (!_abuseControlSettings.Enabled || !_abuseControlSettings.TwoFactor.Enabled)
        {
            return;
        }

        AbuseCounterKey key = BuildTwoFactorSetupVerifyAbuseKey(activeSession, method);
        await _abuseCounterStore.ResetAsync(key);
    }


    protected ApiOutcome<LayeredAuthenticateMethodsResponse> SerializeTwoFactorMethod(
        bool outcome,
        HttpMessage result,
        TwoFactorAuthMethod? method = null,
        Instant? challengeExpiration = null,
        short? chosenDestination = null,
        int? statusCode = null,
        string? code = null,
        TwoFactorSession? session = null)
    {
        List<TwoFactorAuthMethod>? completedMethods = session?.completedMethods.ToList();
        List<TwoFactorAuthMethod>? remainingMethods = session?.remainingMethods.ToList();
        var response = new LayeredAuthenticateMethodsResponse(
            outcome,
            result,
            method,
            challengeExpiration?.ToString(),
            chosenDestination,
            session?.selectedConfiguration,
            session?.currentExpectedMethod,
            completedMethods,
            remainingMethods,
            session?.availableConfigurationsSnapshot.ToList()) { progressVersion = session?.progressVersion, challengeId = session?.challengeId };
        return new ApiOutcome<LayeredAuthenticateMethodsResponse>(response, statusCode ?? TwoFactorMethodStatus(result), code ?? result.ToString());
    }


    protected static ApiOutcome<LayeredAuthenticateMethodsResponse> TwoFactorMethodNotAvailable()
    {
        var response = new LayeredAuthenticateMethodsResponse(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        return ApiResponses.InvalidPayload(
            response,
            nameof(LayeredAuthenticateMethodsRequest.method),
            TwoFactorMethodNotAvailableMessage);
    }


    protected static ApiOutcome<LayeredAuthenticateMethodsResponse> TwoFactorConfigurationNotAvailable()
    {
        var response = new LayeredAuthenticateMethodsResponse(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        return ApiResponses.InvalidPayload(
            response,
            nameof(SelectTwoFactorConfigurationRequest.configuration),
            TwoFactorConfigurationNotAvailableMessage);
    }


    protected static ApiOutcome<LayeredAuthenticateMethodsResponse> TwoFactorMethodServerFailure(string code)
    {
        var response = new LayeredAuthenticateMethodsResponse(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        return new ApiOutcome<LayeredAuthenticateMethodsResponse>(response, StatusCodes.Status500InternalServerError, code);
    }


    protected ILoginProofRepo LoginProofs => HttpContext.RequestServices.GetRequiredService<ILoginProofRepo>();

    protected async Task<PendingTwoFactorSessionLoad> LoadValidTwoFactorSession(string? preAuthTokenOverride = null)
    {
        string? preAuthToken = !string.IsNullOrWhiteSpace(preAuthTokenOverride)
            ? preAuthTokenOverride.Trim()
            : AccessTokenTransport.ReadRequestToken(HttpContext.Request.Headers);
        if (string.IsNullOrWhiteSpace(preAuthToken))
        {
            return new PendingTwoFactorSessionLoad(null, null, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        }

        string hashedPreAuthToken;
        try
        {
            hashedPreAuthToken = AccessTokenHashUtility.Hash(preAuthToken);
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return new PendingTwoFactorSessionLoad(null, null, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        }

        // PostgreSQL supplies current metadata on every request. No cache object
        // can supply signing material, challenge lineage or completed proofs.
        TwoFactorSession? session;
        try
        {
            session = await DependencyDeadline.RunAsync(token => LoginProofs.LoadAsync(hashedPreAuthToken, token),
                new SessionCacheFallbackSettings().DatabaseFallbackTimeout, HttpContext.RequestAborted);
        }
        catch (TimeoutException exception)
        {
            throw DependencyUnavailableException.Database("cor10_login_snapshot", DependencyStage.Read, exception);
        }
        if (session is null) return new PendingTwoFactorSessionLoad(hashedPreAuthToken, null, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        Instant moment = SystemClock.Instance.GetCurrentInstant();
        (IntraMessage validation, string? webKey) = await _jwtUtility.ValidateAccessToken(preAuthToken, session.preAuthRefreshToken,
            moment, session.expiration, JsonWebTokenPurpose.PreAuthTwoFactor);
        if (validation != IntraMessage.TOKEN_PASSED_VALIDATION || webKey != session.webKey || session.expiration <= SystemClock.Instance.GetCurrentInstant())
            return new PendingTwoFactorSessionLoad(hashedPreAuthToken, null, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        return new PendingTwoFactorSessionLoad(hashedPreAuthToken, session);
    }


    protected static List<TwoFactorAuthMethod> RequiredMethodsForConfiguration(TwoFactorAuthConfiguration configuration)
    {
        return configuration switch
        {
            TwoFactorAuthConfiguration.SMS => [TwoFactorAuthMethod.SMS_KEY],
            TwoFactorAuthConfiguration.EMAIL => [TwoFactorAuthMethod.EMAIL],
            TwoFactorAuthConfiguration.AUTHENTICATOR_APP => [TwoFactorAuthMethod.AUTHENTICATOR_APP],
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP => [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP],
            TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP => [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP],
            _ => []
        };
    }


    protected static TwoFactorSessionState StateForTwoFactorMethod(TwoFactorAuthMethod method)
    {
        return TwoFactorSession.StateForMethod(method);
    }


    protected static HttpMessage WaitingMessageForTwoFactorMethod(TwoFactorAuthMethod method)
    {
        return method switch
        {
            TwoFactorAuthMethod.SMS_KEY => HttpMessage.TWOFACTOR_WAITING_SMS_KEY,
            TwoFactorAuthMethod.EMAIL => HttpMessage.TWOFACTOR_WAITING_INTRA_EMAIL,
            TwoFactorAuthMethod.AUTHENTICATOR_APP => HttpMessage.TWOFACTOR_WAITING_AUTHENTICATOR_APP,
            _ => HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED
        };
    }


    protected static bool CanSelectConfiguration(TwoFactorSession session, TwoFactorAuthConfiguration configuration)
    {
        return session.CanSelectConfiguration(configuration);
    }


    protected static void StoreSelectedTwoFactorConfiguration(TwoFactorSession session, TwoFactorAuthConfiguration configuration)
    {
        session.SelectConfiguration(configuration, RequiredMethodsForConfiguration(configuration));
    }


    protected async Task<TwoFactorChallengePreparationResult> PrepareSelectedTwoFactorChallenge(
        TwoFactorSession session,
        short chosenDestination,
        Instant moment,
        string hashedPreAuthToken)
    {
        if (session.currentExpectedMethod == null)
        {
            return TwoFactorChallengePreparationResult.PersistenceFailed;
        }

        return session.currentExpectedMethod.Value switch
        {
            TwoFactorAuthMethod.EMAIL => await PrepareEmailChallenge(session, chosenDestination, moment, hashedPreAuthToken),
            TwoFactorAuthMethod.SMS_KEY => await PrepareSmsChallenge(session, chosenDestination, moment, hashedPreAuthToken),
            TwoFactorAuthMethod.AUTHENTICATOR_APP => await PrepareAuthenticatorAppChallenge(session, moment, hashedPreAuthToken),
            _ => TwoFactorChallengePreparationResult.PersistenceFailed
        };
    }


    protected async Task<TwoFactorChallengePreparationResult> PrepareEmailChallenge(TwoFactorSession session, short chosenDestination, Instant moment, string hashedPreAuthToken)
    {
        if (!TryGetIndexedValue(session.emailAddresses, chosenDestination, out string emailAddress))
        {
            return TwoFactorChallengePreparationResult.InvalidDestination;
        }

        string code = TwoFactorChallengeCodeUtility.GenerateNumericCode();
        StoreCodeChallenge(session, TwoFactorAuthMethod.EMAIL, chosenDestination, code, moment);
        TwoFactorChallengePreparationResult durable = await PersistIssuedTwoFactorChallenge(session, hashedPreAuthToken, moment);
        if (durable != TwoFactorChallengePreparationResult.Prepared)
        {
            return durable;
        }

        bool sent;
        try
        {
            sent = await _twoFactorService.Email(emailAddress, code, token: HttpContext.RequestAborted);
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (DeliveryAcceptanceUnknownException) { return TwoFactorChallengePreparationResult.ProviderUnknown; }
        catch
        {
            return TwoFactorChallengePreparationResult.ProviderUnknown;
        }

        return sent
            ? TwoFactorChallengePreparationResult.Prepared
            : await CancelIssuedTwoFactorChallengeAfterProviderFailure(session, hashedPreAuthToken, moment);
    }


    protected async Task<TwoFactorChallengePreparationResult> PrepareSmsChallenge(TwoFactorSession session, short chosenDestination, Instant moment, string hashedPreAuthToken)
    {
        if (!TryGetIndexedValue(session.phoneNumbers, chosenDestination, out string phoneNumber))
        {
            return TwoFactorChallengePreparationResult.InvalidDestination;
        }

        TryGetIndexedValue(session.phoneCountryCode, chosenDestination, out string countryCode);
        string destination = PhoneDestinationNormalizer.Normalize(countryCode, phoneNumber);

        string code = TwoFactorChallengeCodeUtility.GenerateNumericCode();
        StoreCodeChallenge(session, TwoFactorAuthMethod.SMS_KEY, chosenDestination, code, moment);
        TwoFactorChallengePreparationResult durable = await PersistIssuedTwoFactorChallenge(session, hashedPreAuthToken, moment);
        if (durable != TwoFactorChallengePreparationResult.Prepared)
        {
            return durable;
        }

        bool? sent;
        try
        {
            sent = await _twoFactorService.SMS(destination, code, token: HttpContext.RequestAborted);
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch (DeliveryAcceptanceUnknownException) { return TwoFactorChallengePreparationResult.ProviderUnknown; }
        catch
        {
            return TwoFactorChallengePreparationResult.ProviderUnknown;
        }

        return sent == true
            ? TwoFactorChallengePreparationResult.Prepared
            : await CancelIssuedTwoFactorChallengeAfterProviderFailure(session, hashedPreAuthToken, moment);
    }


    protected async Task<TwoFactorChallengePreparationResult> PrepareAuthenticatorAppChallenge(TwoFactorSession session, Instant moment, string hashedPreAuthToken)
    {
        if (!session.methods.Contains(TwoFactorAuthMethod.AUTHENTICATOR_APP))
        {
            return TwoFactorChallengePreparationResult.InvalidDestination;
        }

        StoreAuthenticatorAppChallenge(session, moment);
        return await PersistIssuedTwoFactorChallenge(session, hashedPreAuthToken, moment);
    }


    protected async Task<TwoFactorChallengePreparationResult> CancelIssuedTwoFactorChallengeAfterProviderFailure(
        TwoFactorSession session,
        string hashedPreAuthToken,
        Instant moment)
    {
        var cancelled = await LoginProofs.CancelAsync(hashedPreAuthToken, session, HttpContext.RequestAborted);
        if (!cancelled.Result) return TwoFactorChallengePreparationResult.ProviderCleanupFailed;
        if (cancelled.Snapshot is not null) session.ApplyDurableProofState(cancelled.Snapshot);
        _ = await SafeSetPendingTwoFactorSession(hashedPreAuthToken, session, RemainingTtl(session, moment));
        return TwoFactorChallengePreparationResult.ProviderFailed;
    }


    protected async Task<TwoFactorChallengePreparationResult> PersistIssuedTwoFactorChallenge(TwoFactorSession session, string hashedPreAuthToken, Instant moment)
    {
        if (session.challengedMethod == null || session.chosenDestination == null || session.challengeExpiration == null || session.nextChallengeAllowedAt == null)
        {
            return TwoFactorChallengePreparationResult.PersistenceFailed;
        }

        var durable = await LoginProofs.IssueAsync(hashedPreAuthToken, session,
            (short)Math.Clamp(_loginSettings.TwoAuthRetryLimit, 1, short.MaxValue),
            _loginSettings.TwoFactorChallengeResendCooldownSeconds, HttpContext.RequestAborted);
        if (durable.Snapshot is not null) session.ApplyDurableProofState(durable.Snapshot);
        if (durable.Result) return TwoFactorChallengePreparationResult.Prepared;
        return durable.Code switch
        {
            "LOGIN_PROOF_STALE" => TwoFactorChallengePreparationResult.Stale,
            "LOGIN_PROOF_VERSION_LIMIT" => TwoFactorChallengePreparationResult.Stale,
            "TWO_FACTOR_CHALLENGE_COOLDOWN" => TwoFactorChallengePreparationResult.Cooldown,
            "TWO_FACTOR_CHALLENGE_RESEND_LIMIT" => TwoFactorChallengePreparationResult.RetryLimit,
            "PENDING_TWO_FACTOR_EXPIRED" => TwoFactorChallengePreparationResult.Expired,
            _ => TwoFactorChallengePreparationResult.PersistenceFailed
        };
    }


    protected void StoreCodeChallenge(TwoFactorSession session, TwoFactorAuthMethod method, short chosenDestination, string code, Instant moment)
    {
        StoreMethodChallenge(session, method, chosenDestination, moment);
        session.challengeCodeHash = TwoFactorChallengeCodeUtility.Hash(code, _loginSettings.TwoFactorChallengePepper);
        session.intraCodeKey = session.challengeCodeHash;
        session.challengeProviderTransactionId = null;
    }


    protected void StoreAuthenticatorAppChallenge(TwoFactorSession session, Instant moment)
    {
        StoreMethodChallenge(session, TwoFactorAuthMethod.AUTHENTICATOR_APP, 0, moment);
        session.challengeCodeHash = null;
        session.intraCodeKey = null;
        session.challengeProviderTransactionId = null;
    }


    protected void StoreMethodChallenge(TwoFactorSession session, TwoFactorAuthMethod method, short chosenDestination, Instant moment)
    {
        Instant challengeExpiration = moment.Plus(BuildTwoFactorChallengePeriod().ToDuration());
        if (challengeExpiration > session.expiration)
        {
            challengeExpiration = session.expiration;
        }

        session.StartChallenge(
            method,
            chosenDestination,
            challengeExpiration,
            moment.Plus(Duration.FromSeconds(_loginSettings.TwoFactorChallengeResendCooldownSeconds)));
    }


    protected Period BuildTwoFactorChallengePeriod()
    {
        return BuildPeriod(_jwtSettings.RefreshTokenAliveDays_2FA, _jwtSettings.RefreshTokenAliveHours_2FA, _jwtSettings.RefreshTokenAliveMinutes_2FA);
    }


    protected TimeSpan RemainingTtl(TwoFactorSession session, Instant moment)
    {
        Duration remaining = session.expiration - moment;
        if (remaining <= Duration.Zero)
        {
            return TimeSpan.FromSeconds(1);
        }

        return remaining.ToTimeSpan();
    }


    protected bool TryGetIndexedValue(List<string>? values, short destination, out string value)
    {
        value = string.Empty;
        if (values == null || destination < 0 || destination >= values.Count)
        {
            return false;
        }

        string? candidate = values[destination];
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }

        value = candidate;
        return true;
    }


    protected ApiOutcome<LayeredAuthenticateResponse> SerializeTwoFactorAuthenticate(
        TwoFactorAuthOutcome result,
        string? accessToken = null,
        int? statusCode = null,
        string? code = null,
        TwoFactorSession? session = null, ActiveSession? issuedSession = null)
    {
        if (issuedSession is not null) { Response.Headers.CacheControl = "no-store"; SessionProtocol.WriteHeaders(Response, issuedSession); }
        int resolvedStatusCode = statusCode ?? TwoFactorAuthenticateStatus(result);
        List<TwoFactorAuthMethod>? completedMethods = session?.completedMethods.ToList();
        List<TwoFactorAuthMethod>? remainingMethods = session?.remainingMethods.ToList();

        return new ApiOutcome<LayeredAuthenticateResponse>(
            new LayeredAuthenticateResponse(
                result,
                accessToken,
                session?.selectedConfiguration,
                session?.currentExpectedMethod,
                completedMethods,
                remainingMethods) { progressVersion = session?.progressVersion, challengeId = session?.challengeId, session = issuedSession is null ? null : SessionProtocol.Credentials(issuedSession) },
            resolvedStatusCode,
            code ?? result.ToString());
    }


    protected AbuseCounterLimit BuildTwoFactorChallengeAbuseLimit()
    {
        TwoFactorAbusePolicySettings settings = _abuseControlSettings.TwoFactor;
        TimeSpan cooldown = TimeSpan.FromSeconds(settings.CooldownSecondsAfterExhaustion);
        return new AbuseCounterLimit(
            settings.MaxAttemptsPerChallenge,
            TimeSpan.FromSeconds(settings.ChallengeAttemptWindowSeconds),
            cooldown);
    }


    protected static AbuseCounterKey BuildTwoFactorChallengeAbuseKey(TwoFactorSession session, string hashedPreAuthToken)
    {
        string challengeExpirationTicks = session.challengeExpiration.HasValue
            ? session.challengeExpiration.Value.ToUnixTimeTicks().ToString(CultureInfo.InvariantCulture)
            : "none";
        string material = string.Join(
            ':',
            session.accountId.ToString("N"),
            hashedPreAuthToken,
            session.challengedMethod?.ToString() ?? "none",
            session.challengeId?.ToString("N") ?? "none",
            challengeExpirationTicks);
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        string safeId = Convert.ToHexString(digest).ToLowerInvariant()[..24];
        return new AbuseCounterKey(AbuseFeature.TwoFactorChallenge, AbuseCounterDimension.Session, safeId);
    }


    protected async Task<TwoFactorChallengeVerification> CheckTwoFactorChallengeAttemptPolicy(
        TwoFactorSession session,
        string hashedPreAuthToken)
    {
        if (!_abuseControlSettings.Enabled || !_abuseControlSettings.TwoFactor.Enabled)
        {
            return new TwoFactorChallengeVerification(TwoFactorAuthOutcome.SUCCESS);
        }

        AbuseCounterKey key = BuildTwoFactorChallengeAbuseKey(session, hashedPreAuthToken);
        CounterDecision decision = await _abuseCounterStore.IncrementAsync(key, BuildTwoFactorChallengeAbuseLimit());
        if (decision.CanAdmit)
        {
            return new TwoFactorChallengeVerification(TwoFactorAuthOutcome.SUCCESS);
        }

        if (decision.RetryAfter.HasValue && HttpContext?.Response != null)
        {
            HttpContext.Response.Headers["Retry-After"] = Math.Ceiling(decision.RetryAfter.Value.TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }

        string reasonCode = decision.ReasonCode == AbuseReasonCodes.CounterStoreUnavailable || decision.ReasonCode == AbuseReasonCodes.CounterStoreTimeout
            ? decision.ReasonCode!
            : AbuseReasonCodes.TwoFactorAttemptsExceeded;
        int statusCode = reasonCode == AbuseReasonCodes.TwoFactorAttemptsExceeded
            ? StatusCodes.Status429TooManyRequests
            : StatusCodes.Status503ServiceUnavailable;

        AbuseOperationalTelemetry.RecordTwoFactorThrottled(key.Dimension, reasonCode);

        return new TwoFactorChallengeVerification(
            TwoFactorAuthOutcome.FAILURE,
            FailureReason: null,
            StatusCode: statusCode,
            Code: reasonCode);
    }


    protected async Task ResetTwoFactorChallengeAttemptPolicy(TwoFactorSession session, string hashedPreAuthToken)
    {
        if (!_abuseControlSettings.Enabled || !_abuseControlSettings.TwoFactor.Enabled)
        {
            return;
        }

        AbuseCounterKey key = BuildTwoFactorChallengeAbuseKey(session, hashedPreAuthToken);
        await _abuseCounterStore.ResetAsync(key);
    }


    protected static TwoFactorAuthMethod? NextRequiredTwoFactorMethod(TwoFactorSession session)
    {
        return session.NextRequiredMethod();
    }


    protected async Task<TwoFactorProofAdvanceResult> AdvanceTwoFactorSessionAfterAcceptedProof(
        TwoFactorSession session,
        Instant moment,
        string hashedPreAuthToken)
    {
        TwoFactorAuthMethod? nextMethod = NextRequiredTwoFactorMethod(session);
        if (!nextMethod.HasValue || nextMethod.Value == TwoFactorAuthMethod.NONE)
        {
            return new TwoFactorProofAdvanceResult(session.isComplete);
        }

        short nextDestination = nextMethod.Value == TwoFactorAuthMethod.AUTHENTICATOR_APP
            ? (short)0
            : session.chosenDestination ?? (short)0;

        TwoFactorChallengePreparationResult nextChallenge = await PrepareSelectedTwoFactorChallenge(
            session,
            nextDestination,
            moment,
            hashedPreAuthToken);

        if (nextChallenge != TwoFactorChallengePreparationResult.Prepared)
        {
            if (nextChallenge is TwoFactorChallengePreparationResult.RetryLimit or TwoFactorChallengePreparationResult.Expired)
            {
                PendingSessionRevokeResult revoked = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
                if (!revoked.Revoked)
                {
                    return new TwoFactorProofAdvanceResult(
                        false,
                        FailureReason: null,
                        StatusCode: StatusCodes.Status500InternalServerError,
                        Code: TwoFactorSessionRevokeFailedCode);
                }
            }

            HttpMessage? failureReason = nextChallenge switch
            {
                TwoFactorChallengePreparationResult.Cooldown => HttpMessage.AUTHENTICATION_TWO_FACTOR_CODE_TIMEOUT,
                TwoFactorChallengePreparationResult.Expired => HttpMessage.AUTHENTICATION_EXPIRED,
                _ => HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED
            };

            int statusCode = nextChallenge switch
            {
                TwoFactorChallengePreparationResult.ProviderUnknown => StatusCodes.Status503ServiceUnavailable,
                TwoFactorChallengePreparationResult.Stale => StatusCodes.Status409Conflict,
                TwoFactorChallengePreparationResult.Cooldown => StatusCodes.Status400BadRequest,
                TwoFactorChallengePreparationResult.Expired => StatusCodes.Status401Unauthorized,
                TwoFactorChallengePreparationResult.InvalidDestination => StatusCodes.Status400BadRequest,
                _ => StatusCodes.Status500InternalServerError
            };

            string code = nextChallenge switch
            {
                TwoFactorChallengePreparationResult.Stale => "LOGIN_PROOF_STALE",
                TwoFactorChallengePreparationResult.InvalidDestination => TwoFactorInvalidDestinationCode,
                TwoFactorChallengePreparationResult.ProviderUnknown => "DELIVERY_ACCEPTANCE_UNKNOWN",
                TwoFactorChallengePreparationResult.ProviderFailed => TwoFactorProviderFailedCode,
                TwoFactorChallengePreparationResult.ProviderCleanupFailed => TwoFactorChallengeCleanupFailedCode,
                TwoFactorChallengePreparationResult.PersistenceFailed => TwoFactorNextProofChallengePersistenceFailedCode,
                TwoFactorChallengePreparationResult.Cooldown => HttpMessage.AUTHENTICATION_TWO_FACTOR_CODE_TIMEOUT.ToString(),
                TwoFactorChallengePreparationResult.RetryLimit => HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED.ToString(),
                TwoFactorChallengePreparationResult.Expired => HttpMessage.AUTHENTICATION_EXPIRED.ToString(),
                _ => TwoFactorNextProofChallengePersistenceFailedCode
            };

            return new TwoFactorProofAdvanceResult(false, failureReason, statusCode, code);
        }

        PendingSessionWriteResult persisted = await SafeSetPendingTwoFactorSession(hashedPreAuthToken, session, RemainingTtl(session, moment));
        return new TwoFactorProofAdvanceResult(false);
    }


    protected async Task<TwoFactorChallengeVerification> VerifyTwoFactorChallenge(LayeredAuthenticateRequest payload, TwoFactorSession session, Instant moment, string hashedPreAuthToken)
    {
        if (payload.method == TwoFactorAuthMethod.NONE || string.IsNullOrWhiteSpace(payload.codeKey))
        {
            return new TwoFactorChallengeVerification(TwoFactorAuthOutcome.FAILURE, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        }

        if (!session.IsCurrentlyExpecting(payload.method))
        {
            return new TwoFactorChallengeVerification(
                TwoFactorAuthOutcome.FAILURE,
                HttpMessage.TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED,
                StatusCodes.Status400BadRequest,
                TwoFactorMethodNotCurrentlyRequiredCode);
        }

        TwoFactorChallengeVerification abusePolicy = await CheckTwoFactorChallengeAttemptPolicy(session, hashedPreAuthToken);
        if (abusePolicy.Outcome != TwoFactorAuthOutcome.SUCCESS)
        {
            return abusePolicy;
        }

        if (session.challengedMethod == null || session.challengedMethod.Value != payload.method)
        {
            return new TwoFactorChallengeVerification(
                TwoFactorAuthOutcome.FAILURE,
                HttpMessage.TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED,
                StatusCodes.Status400BadRequest,
                TwoFactorMethodNotCurrentlyRequiredCode);
        }

        bool totpVerified = false;
        if (payload.method == TwoFactorAuthMethod.AUTHENTICATOR_APP)
        {
            var verifier = HttpContext.RequestServices.GetRequiredService<IAuthenticatorAppLoginVerifier>();
            var verification = await verifier.VerifyForLoginAsync(session.accountId, payload.codeKey, moment, HttpContext.RequestAborted);
            if (verification.Status == ProofVerificationStatus.DependencyUnavailable)
                return new TwoFactorChallengeVerification(TwoFactorAuthOutcome.FAILURE, StatusCode: 503, Code: verification.Code);
            totpVerified = verification.Verified;
        }
        string? codeHash = payload.method == TwoFactorAuthMethod.AUTHENTICATOR_APP ? null
            : TwoFactorChallengeCodeUtility.Hash(payload.codeKey, _loginSettings.TwoFactorChallengePepper);
        var durable = await LoginProofs.CompleteAsync(hashedPreAuthToken, session, codeHash, totpVerified,
            (short)Math.Clamp(_loginSettings.TwoAuthRetryLimit, 1, short.MaxValue), HttpContext.RequestAborted);
        if (durable.Result) await ResetTwoFactorChallengeAttemptPolicy(session, hashedPreAuthToken);
        if (durable.Snapshot is not null) session.ApplyDurableProofState(durable.Snapshot);
        _ = await SafeSetPendingTwoFactorSession(hashedPreAuthToken, session, RemainingTtl(session, moment));
        if (!durable.Result)
            return new TwoFactorChallengeVerification(durable.Code == "TWO_FACTOR_CHALLENGE_INCORRECT" ? TwoFactorAuthOutcome.INCORRECT : TwoFactorAuthOutcome.FAILURE,
                StatusCode: durable.Code == "LOGIN_PROOF_STALE" ? 409 : 401, Code: durable.Code);
        return new TwoFactorChallengeVerification(TwoFactorAuthOutcome.SUCCESS);
    }


    protected static TwoFactorChallengeVerification TwoFactorAttemptPersistenceFailure()
    {
        return new TwoFactorChallengeVerification(
            TwoFactorAuthOutcome.FAILURE,
            FailureReason: null,
            StatusCode: StatusCodes.Status500InternalServerError,
            Code: TwoFactorAttemptPersistenceFailedCode);
    }


    protected static TwoFactorChallengeVerification TwoFactorSessionRevokeFailure()
    {
        return new TwoFactorChallengeVerification(
            TwoFactorAuthOutcome.FAILURE,
            FailureReason: null,
            StatusCode: StatusCodes.Status500InternalServerError,
            Code: TwoFactorSessionRevokeFailedCode);
    }


    protected TwoFactorAuthOutcome VerifyHashedCode(string codeKey, string? expectedCodeHash)
    {
        if (string.IsNullOrWhiteSpace(expectedCodeHash))
        {
            return TwoFactorAuthOutcome.FAILURE;
        }

        string submittedHash;
        try
        {
            submittedHash = TwoFactorChallengeCodeUtility.Hash(codeKey, _loginSettings.TwoFactorChallengePepper);
        }
        catch (treehammock.DataLayer.Operations.SecurityOperationException) { throw; }
        catch
        {
            return TwoFactorAuthOutcome.FAILURE;
        }

        byte[] expectedBytes = Encoding.UTF8.GetBytes(expectedCodeHash);
        byte[] submittedBytes = Encoding.UTF8.GetBytes(submittedHash);
        bool matches = expectedBytes.Length == submittedBytes.Length && CryptographicOperations.FixedTimeEquals(expectedBytes, submittedBytes);
        return matches ? TwoFactorAuthOutcome.SUCCESS : TwoFactorAuthOutcome.INCORRECT;
    }

}
