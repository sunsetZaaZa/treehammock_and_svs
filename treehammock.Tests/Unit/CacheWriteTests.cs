using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;
using StackExchange.Redis;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Support;
namespace treehammock.Tests.Unit;

public class Cor22CacheWriteTests
{
    [Theory, InlineData("unchanged", 0), InlineData("evaluation", 0), InlineData("rights", 1),
        InlineData("boundary", 1), InlineData("expiry", 1), InlineData("miss", 1), InlineData("failed_repair", 1)]
    public async Task Only_hydration_or_material_authority_changes_write_cache(string change, int writes)
    {
        var now = SystemClock.Instance.GetCurrentInstant();
        var a = new ActiveSession(Guid.NewGuid(), new byte[64], 0, now, Period.FromHours(1),
            now + Duration.FromMinutes(10), now + Duration.FromHours(1), null, FeatureSet.basic, accountSecurityStamp: Guid.NewGuid());
        a.entitlements = EntitlementTestData.ForAccount(a.accountId, evaluated: now - Duration.FromSeconds(1));
        var projection = change switch
        {
            "rights" or "failed_repair" => a.entitlements with { RightsEnabled = true, Features = FeatureSet.premium, Version = 2 },
            "boundary" => a.entitlements with { NextBoundary = now + Duration.FromMinutes(2) },
            "evaluation" => a.entitlements with { EvaluatedAt = now },
            _ => a.entitlements
        };
        var expiry = change == "expiry" ? now + Duration.FromMinutes(1) : a.accessExpiration;
        var cache = Substitute.For<IActiveUserCacheService>(); var sql = Substitute.For<ISessionRepo>();
        var jwt = Substitute.For<IJsonWebTokenUtility>();
        cache.GetSession(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(change == "miss" ? null : a);
        cache.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), flags: CommandFlags.PreferMaster, cancellationToken: Arg.Any<CancellationToken>()).Returns(change != "failed_repair");
        sql.GetSession(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(a.toSession());
        sql.ValidateCachedSessionTrust(Arg.Any<string>(), a.accountId, a.securityStamp, a.accountSecurityStamp, Arg.Any<CancellationToken>())
            .Returns(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, expiry, a.sessionExpiration, null,
                a.securityStamp, a.accountSecurityStamp, FamilyId: a.familyId, Generation: a.generation,
                ProtocolVersion: a.protocolVersion, Entitlements: projection));
        jwt.ValidateAccessToken("token", a.refreshToken, Arg.Any<Instant>(), Arg.Any<Instant>(), JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)"web"));
        var context = new DefaultHttpContext(); context.Request.Headers["AccessToken"] = "token";
        await new JsonWebTokenMiddleware(_ => Task.CompletedTask).InvokeAsync(context, cache, jwt, sql,
            Options.Create(new JWTSettings { RefreshTokenAliveMinutes = 10 }));
        context.Items[AuthContextItems.ActiveSession].ShouldNotBeNull();
        await cache.Received(writes).SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), flags: CommandFlags.PreferMaster, cancellationToken: Arg.Any<CancellationToken>());
        if (change != "miss")
            await sql.Received(1).ValidateCachedSessionTrust(Arg.Any<string>(), a.accountId, a.securityStamp, a.accountSecurityStamp, Arg.Any<CancellationToken>());
        if (change == "boundary" || change == "expiry")
            await cache.Received(1).SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Is<TimeSpan>(t => t > TimeSpan.Zero && t <= TimeSpan.FromMinutes(change == "expiry" ? 1 : 2)), flags: CommandFlags.PreferMaster, cancellationToken: Arg.Any<CancellationToken>());
    }
}
