using Microsoft.Extensions.Options;
using NodaTime;
using Shouldly;
using treehammock.DataLayer.Cache;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite","SqlContracts")]
public class Cor10PendingProofCacheTests
{
    [Fact]
    public async Task Actual_cache_projection_rejects_regression_and_equal_version_does_not_extend_TTL()
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        await using var connection=await Cor06ReplayLeaseTests.Connect();
        await using var service=new TwoFactorSessionService(Options.Create(new TwoFactorSessionCacheSettings {database=0}),connection);
        string key="cor10-owned:"+Guid.NewGuid().ToString("N");var database=connection.GetDatabase(0);
        var now=SystemClock.Instance.GetCurrentInstant();
        var p=new TwoFactorSession(Guid.NewGuid(),"web",new byte[64],[TwoFactorAuthMethod.EMAIL],null,null,null,["test@example.invalid"],
            null,null,0,0,0,now,now.Plus(Duration.FromMinutes(5)),FeatureSet.basic,accountSecurityStamp:Guid.NewGuid())
            {progressVersion=3};
        try
        {
            (await service.SetSession(key,p,TimeSpan.FromSeconds(30),cancellationToken:deadline.Token)).ShouldBe(true);
            var before=await database.KeyTimeToLiveAsync(key);
            (await service.SetSession(key,p,TimeSpan.FromDays(1),cancellationToken:deadline.Token)).ShouldBe(false);
            before.ShouldNotBeNull();
            var after=await database.KeyTimeToLiveAsync(key);after.ShouldNotBeNull();
            after!.Value.ShouldBeLessThanOrEqualTo(before!.Value);
            p.progressVersion=2;
            (await service.SetSession(key,p,TimeSpan.FromDays(1),cancellationToken:deadline.Token)).ShouldBe(false);
            (await service.GetSession(key,deadline.Token))!.progressVersion.ShouldBe(3);
            p.progressVersion=4;
            (await service.SetSession(key,p,TimeSpan.FromSeconds(20),cancellationToken:deadline.Token)).ShouldBe(true);
            (await service.GetSession(key,deadline.Token))!.progressVersion.ShouldBe(4);
            await database.StringSetAsync(key,"42",TimeSpan.FromSeconds(5));
            (await service.SetSession(key,p,TimeSpan.FromSeconds(20),cancellationToken:deadline.Token)).ShouldBe(true);
        }
        finally {await database.KeyDeleteAsync(key);}
    }
}
