using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NodaTime;
using NSubstitute;
using StackExchange.Redis;
using Treehammock.SessionValidation.Core;
using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Dependencies;
using treehammock.Rigging.Replay;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;
using treehammock.Tests.Support;

namespace treehammock.Tests.Infrastructure;

// Actual token generation/verifier/middleware/filter/controllers/serialization run. Only
// cache/repository and unrelated controller dependencies are substitutes; no native SQL claim.
internal sealed class Svs03SessionFixture
{
    internal const string Issuer = "svs03.test";
    internal readonly ISessionRepo Repository = Substitute.For<ISessionRepo>();
    internal readonly IActiveUserCacheService Cache = Substitute.For<IActiveUserCacheService>();
    internal readonly ConcurrentQueue<string> Events = new();
    internal readonly Dictionary<string,ActiveSession> Cached = new(StringComparer.Ordinal);
    internal readonly JsonWebTokenUtility Tokens = new(NullLogger<JsonWebTokenUtility>.Instance,
        Options.Create(new JWTSettings { JsonWebTokenIssuer = Issuer }));
    internal ActiveSession Current;
    internal string Credential;
    internal string CurrentHash;
    internal string Scenario;
    internal bool Warm;
    internal bool Revoked;
    internal bool EmptyCapabilities;
    internal Action<ActiveSession>? OnCacheWrite;
    internal Func<ActiveSession,ActiveSession>? OnReload;
    internal Func<CancellationToken,Task<Session?>>? ReadOverride;
    internal int Gets, Trusts, Writes, Revokes, Lists, Verifies;
    internal TimeSpan? LastTtl;

    internal Svs03SessionFixture(bool warm = true, string scenario = "active")
    {
        Warm = warm; Scenario = scenario;
        var now = SystemClock.Instance.GetCurrentInstant();
        Current = new(Guid.Parse("11111111-1111-4111-8111-111111111111"), Enumerable.Repeat((byte)77,64).ToArray(), 0,
            now-Duration.FromMinutes(1), Period.FromHours(1), now+Duration.FromMinutes(5), now+Duration.FromHours(1), null,
            FeatureSet.basic, Guid.Parse("22222222-2222-4222-8222-222222222222"), Guid.Parse("33333333-3333-4333-8333-333333333333"),
            Guid.Parse("44444444-4444-4444-8444-444444444444"), 7, 2);
        Current.entitlements = EntitlementTestData.ForAccount(Current.accountId, evaluated: now-Duration.FromSeconds(1)) with
        { NextBoundary = now+Duration.FromMinutes(2) };
        Credential = Tokens.GenerateAccessToken(Current.refreshToken, "svs03-web", scenario == "preauth" ? JsonWebTokenPurpose.PreAuthTwoFactor : JsonWebTokenPurpose.Active);
        if (scenario is "wrong-issuer" or "wrong-key" or "missing-webkey" or "missing-purpose" or "missing-jti" or "wrong-algorithm") Credential = AdversarialToken(scenario);
        if (scenario == "malformed") Credential = "not.a.valid.jws";
        if (scenario == "opaque-refresh") Credential = SessionProtocol.RefreshCredential(Current.refreshToken, Current.securityStamp);
        if (scenario == "expired-access") Current.accessExpiration = now-Duration.FromSeconds(1);
        if (scenario == "expired-hard") Current.sessionExpiration = now-Duration.FromSeconds(1);
        if (scenario == "cutoff") Current.cutOff = now-Duration.FromSeconds(1);
        if (scenario == "capability-denied") { EmptyCapabilities = true; Current.entitlements = Current.entitlements with { Capabilities = [] }; }
        CurrentHash = AccessTokenHashUtility.Hash(Credential);
        Cached[CurrentHash] = Copy(Current);

        Cache.GetSession(Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(call =>
        {
            call.ArgAt<CancellationToken>(1).ThrowIfCancellationRequested(); Events.Enqueue("cache.get");
            if (Scenario == "cache-down") throw new RedisConnectionException(ConnectionFailureType.UnableToConnect,"owned-cache-failure");
            if (Scenario == "cache-corrupt") throw new StaleActiveSessionCachePayloadException("owned-malformed-projection");
            return Task.FromResult<ActiveSession?>(Warm && Cached.TryGetValue(call.ArgAt<string>(0),out var value) ? Copy(value) : null);
        });
        Cache.SetSession(Arg.Any<string>(),Arg.Any<ActiveSession>(),Arg.Any<TimeSpan>(),Arg.Any<CommandFlags>(),Arg.Any<CancellationToken>()).Returns(call =>
        {
            call.ArgAt<CancellationToken>(4).ThrowIfCancellationRequested(); Writes++; Events.Enqueue("cache.set"); LastTtl=call.ArgAt<TimeSpan>(2);
            OnCacheWrite?.Invoke(call.ArgAt<ActiveSession>(1));
            if (Scenario == "cache-write-throws") throw new RedisConnectionException(ConnectionFailureType.UnableToConnect,"owned-cache-write-failure");
            if (Scenario == "cache-write-false") return Task.FromResult(false);
            Cached[call.ArgAt<string>(0)] = Copy(call.ArgAt<ActiveSession>(1)); return Task.FromResult(true);
        });
        Cache.RevokeSession(Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(call =>
        { Revokes++;Events.Enqueue("cache.revoke");Cached.Remove(call.ArgAt<string>(0));return Task.FromResult(true); });
        Repository.GetSession(Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(async call =>
        {
            Gets++;Events.Enqueue("db.get");call.ArgAt<CancellationToken>(1).ThrowIfCancellationRequested();
            if(ReadOverride is not null)return await ReadOverride(call.ArgAt<CancellationToken>(1));
            if(Scenario == "db-down")throw DependencyUnavailableException.Database("owned-session-read",DependencyStage.Read);
            if(Revoked || call.ArgAt<string>(0)!=CurrentHash || Scenario is "authority-denied" or "no-session")return null;
            var result=Copy(Current);
            if(Gets>1 && OnReload is not null) result=OnReload(result);
            var row=result.toSession();if(Scenario=="malformed-db")row.sessionLifespan=null;return row;
        });
        Repository.ValidateCachedSessionTrust(Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<CancellationToken>()).Returns(call =>
        {
            Trusts++;Events.Enqueue("db.trust");call.ArgAt<CancellationToken>(4).ThrowIfCancellationRequested();
            if(Scenario=="db-down")throw DependencyUnavailableException.Database("owned-session-trust",DependencyStage.Read);
            if(Scenario=="trust-null")return Task.FromResult<CachedSessionTrustResult?>(null);
            if(Scenario=="trust-failed")return Task.FromResult<CachedSessionTrustResult?>(new(CachedSessionTrustStatus.Failed));
            if(Revoked || call.ArgAt<string>(0)!=CurrentHash || Scenario is "authority-denied" or "no-session")return Task.FromResult<CachedSessionTrustResult?>(new(CachedSessionTrustStatus.SessionNotFound));
            var status = call.ArgAt<Guid>(2)!=Current.securityStamp ? CachedSessionTrustStatus.SecurityStampMismatch :
                call.ArgAt<Guid>(3)!=Current.accountSecurityStamp ? CachedSessionTrustStatus.AccountSecurityStampMismatch : CachedSessionTrustStatus.Valid;
            return Task.FromResult<CachedSessionTrustResult?>(new(status,Current.accessExpiration,Current.sessionExpiration,Current.cutOff,
                Current.securityStamp,Current.accountSecurityStamp,FamilyId:Current.familyId,Generation:Current.generation,ProtocolVersion:Current.protocolVersion,Entitlements:Current.entitlements));
        });
        Repository.ListActiveSessions(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(call =>
        {
            Lists++;Events.Enqueue("controller.list");
            if(call.ArgAt<Guid>(0)!=Current.accountId || call.ArgAt<Guid>(1)!=Current.accountSecurityStamp || call.ArgAt<string>(2)!=CurrentHash)throw new InvalidOperationException("Wrong controller identity binding.");
            IReadOnlyList<AccountSessionSummary> result=new[] { new AccountSessionSummary(Current.familyId,Current.createdOn,Current.accessExpiration,Current.sessionExpiration,Current.features,true,Current.entitlements) };
            return Task.FromResult<IReadOnlyList<AccountSessionSummary>?>(result);
        });
    }

    internal static ActiveSession Copy(ActiveSession value) => SessionProtocol.FromSession(value.toSession());
    internal static Dictionary<string,string?> Settings()
    {
        var settings=Cor23EAuthorityFixture.Settings();settings["JWTSettings:JsonWebTokenIssuer"]=Issuer;
        settings["SessionCacheFallbackSettings:CacheReadTimeoutMilliseconds"]="500";
        return settings;
    }
    internal void Configure(IServiceCollection services)
    {
        services.RemoveAll<IHostedService>();
        Replace(services,Cache);Replace(services,Repository);Replace(services,Substitute.For<IAccountRepo>());
        Replace(services,Substitute.For<ITwoFactorSessionService>());Replace(services,Substitute.For<ITwoFactorAuthenticateService>());
        Replace(services,Substitute.For<IAccountService>());Replace(services,Substitute.For<IAbuseCounterStore>());
        Replace(services,Substitute.For<ILoginAbuseCounterKeyFactory>());
        Replace(services,Substitute.For<IAuthenticatedMutationIdempotencyService>());
        Replace<ITreehammockTokenVerifier>(services,new RecordingVerifier(this));
        // Keep the production IJsonWebTokenUtility registration and DI factory.
    }
    private static void Replace<T>(IServiceCollection services,T instance) where T:class
    {services.RemoveAll<T>();services.AddSingleton(instance);}

    internal void Rotate(bool replaceFamily)
    {
        var replacement=Copy(Current);replacement.refreshToken=RandomNumberGenerator.GetBytes(64);replacement.securityStamp=Guid.NewGuid();
        replacement.generation++;if(replaceFamily)replacement.familyId=Guid.NewGuid();
        Current=replacement;Credential=Tokens.GenerateAccessToken(Current.refreshToken,"svs03-web");CurrentHash=AccessTokenHashUtility.Hash(Credential);
        // Deliberately keep stale old cache material; current authority must reject it.
        Cached[CurrentHash]=Copy(Current);
    }
    private string AdversarialToken(string kind)
    {
        var claims=new List<Claim>();if(kind!="missing-webkey")claims.Add(new("webKey","svs03-web"));
        if(kind!="missing-purpose")claims.Add(new("purpose",JsonWebTokenPurpose.Active));if(kind!="missing-jti")claims.Add(new("jti",Guid.NewGuid().ToString("N")));
        var key=kind=="wrong-key"?Enumerable.Repeat((byte)19,64).ToArray():Current.refreshToken;
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(kind=="wrong-issuer"?"other.test":Issuer,null,claims,null,null,
            new SigningCredentials(new SymmetricSecurityKey(key),kind=="wrong-algorithm"?SecurityAlgorithms.HmacSha384:SecurityAlgorithms.HmacSha256)));
    }
    internal sealed class RecordingVerifier(Svs03SessionFixture fixture):ITreehammockTokenVerifier
    {
        private readonly TreehammockTokenVerifier _real=new();
        public Task<TokenVerificationResult> ValidateAsync(string token,byte[] signingKey,string issuer,Instant now,Instant accessExpiration,string expectedPurpose=TreehammockTokenPurpose.Active,Duration? refreshWindow=null)
        {fixture.Verifies++;fixture.Events.Enqueue("token.verify");return _real.ValidateAsync(token,signingKey,issuer,now,accessExpiration,expectedPurpose,refreshWindow);}
    }
}
