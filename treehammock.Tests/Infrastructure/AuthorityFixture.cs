using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using NodaTime;
using NSubstitute;
using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Models.Account;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Dependencies;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Support;

namespace treehammock.Tests.Infrastructure;

// Explicit authority/cache/JWT doubles. Actual middleware, authorization, controllers and serializers run.
internal sealed class Cor23EAuthorityFixture
{
    public const string FirstToken = "cor23e-account-one";
    public const string SecondToken = "cor23e-account-two";
    public readonly IActiveUserCacheService Cache = Substitute.For<IActiveUserCacheService>();
    public readonly ISessionRepo Sessions = Substitute.For<ISessionRepo>();
    public readonly IAccountRepo Accounts = Substitute.For<IAccountRepo>();
    public readonly IJsonWebTokenUtility Jwt = Substitute.For<IJsonWebTokenUtility>();
    public readonly Dictionary<string, ActiveSession> Subjects = new();
    public Cor23EAuthorityFixture()
    {
        var now = SystemClock.Instance.GetCurrentInstant();
        foreach (string token in new[] { FirstToken, SecondToken })
        {
            var session = EntitlementTestData.Attach(new ActiveSession(Guid.NewGuid(), RandomNumberGenerator.GetBytes(64), 0,
                now, Period.FromHours(1), now + Duration.FromMinutes(30), now + Duration.FromHours(1), null,
                FeatureSet.basic, accountSecurityStamp: Guid.NewGuid()));
            Subjects[token] = session;
            string hash = AccessTokenHashUtility.Hash(token);
            Cache.GetSession(hash, Arg.Any<CancellationToken>()).Returns(Task.FromResult<ActiveSession?>(session));
            Sessions.ValidateCachedSessionTrust(hash, session.accountId, session.securityStamp, session.accountSecurityStamp, Arg.Any<CancellationToken>())
                .Returns(Task.FromResult<CachedSessionTrustResult?>(new(CachedSessionTrustStatus.Valid, session.accessExpiration,
                    session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp,
                    Entitlements: EntitlementTestData.ForAccount(session.accountId))));
            Jwt.ValidateAccessToken(token, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration,
                JsonWebTokenPurpose.Active, Arg.Any<Duration?>()).Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)"fixture-web-key")));
            Accounts.ViewAccount(session.accountId, session.accountSecurityStamp, Arg.Any<CancellationToken>()).Returns(
                Task.FromResult<AccountViewResult?>(new(true, "ACCOUNT_VIEW_SUCCEEDED", new AccountProfile {
                    emailAddress = token + "@example.test", username = token, createdOn = now, verifyStatus = VerificationStatus.SUCCESSFUL,
                    country = Country.USA, features = FeatureSet.basic, twoFactorEnabled = false })));
            Sessions.ListActiveSessions(session.accountId, session.accountSecurityStamp, hash, Arg.Any<CancellationToken>()).Returns(
                Task.FromResult<IReadOnlyList<AccountSessionSummary>?>(new[] { new AccountSessionSummary(session.familyId, now,
                    session.accessExpiration, session.sessionExpiration, FeatureSet.basic, true, session.entitlements) }));
        }
        Sessions.GetSession(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(null));
    }
    public static Dictionary<string,string?> Settings()
    {
        var settings = TestConfiguration.ValidSettings();
        settings["RetentionSettings:Enabled"] = "false";
        settings["HostingSettings:ConfigureKestrel"] = "false";
        settings["HostingSettings:UseHttpsRedirection"] = "false";
        return settings;
    }
    private static void Replace<T>(IServiceCollection services, T value) where T : class
    { services.RemoveAll<T>(); services.AddSingleton(value); }
    public void Configure(IServiceCollection services)
    {
        services.RemoveAll<IHostedService>();
        Replace(services, Cache); Replace(services, Sessions); Replace(services, Accounts); Replace(services, Jwt);
    }
    public void Outage()
        => Sessions.ListActiveSessions(Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException<IReadOnlyList<AccountSessionSummary>?>(DependencyUnavailableException.Database("fixture", DependencyStage.Read)));
    public void UnexpectedAuthenticationFailure()
        => Jwt.ValidateAccessToken(Arg.Any<string>(), Arg.Any<byte[]>(), Arg.Any<Instant>(), Arg.Any<Instant>(), JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromException<(IntraMessage,string?)>(new InvalidOperationException("credential-body-must-not-leak")));
}
