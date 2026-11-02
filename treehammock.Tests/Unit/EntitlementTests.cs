using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NodaTime;
using NodaTime.Text;
using NSubstitute;
using Shouldly;
using treehammock.DataLayer.Entitlements;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;
namespace treehammock.Tests.Unit;
public class Cor20EntitlementTests
{
    private static Instant I(string value) => InstantPattern.ExtendedIso.Parse(value).Value;
    [Theory]
    [InlineData("2023-01-31T12:34:56Z",6,1,"2023-02-28T12:34:56Z")]
    [InlineData("2023-01-31T12:34:56Z",6,2,"2023-03-31T12:34:56Z")]
    [InlineData("2024-01-31T12:34:56Z",6,1,"2024-02-29T12:34:56Z")]
    [InlineData("2024-02-29T12:34:56Z",10,1,"2025-02-28T12:34:56Z")]
    [InlineData("2024-02-29T12:34:56Z",10,4,"2028-02-29T12:34:56Z")]
    [InlineData("2024-01-31T12:34:56Z",7,1,"2024-04-30T12:34:56Z")]
    [InlineData("2024-01-31T12:34:56Z",8,1,"2024-07-31T12:34:56Z")]
    [InlineData("2024-01-31T12:34:56Z",9,1,"2024-10-31T12:34:56Z")]
    [InlineData("2024-02-28T12:34:56Z",1,1,"2024-02-29T12:34:56Z")]
    [InlineData("2024-02-28T12:34:56Z",2,1,"2024-03-06T12:34:56Z")]
    [InlineData("2024-02-28T12:34:56Z",3,1,"2024-03-13T12:34:56Z")]
    public void Original_utc_anchor_clamps_without_drift(string start,int term,int cycle,string expected)
        => CalendarTermCalculator.Boundary(I(start),(DayDuration)term,cycle).ShouldBe(I(expected));
    [Theory,InlineData(4),InlineData(5),InlineData(0),InlineData(12)]
    public void Ambiguous_or_unknown_terms_are_rejected(int term)
        => Should.Throw<ArgumentOutOfRangeException>(() => CalendarTermCalculator.Boundary(I("2024-01-31T00:00:00Z"),(DayDuration)term,1));
    [Fact]
    public void Start_is_inclusive_expiry_exclusive_and_late_recording_does_not_change_cycle()
    {
        var start=I("2024-01-31T00:00:00Z");var end=I("2024-04-30T00:00:00Z");
        CalendarTermCalculator.CycleAt(start,DayDuration.MONTHLY,3,end,start.Minus(Duration.FromNanoseconds(1))).ShouldBe(0);
        CalendarTermCalculator.CycleAt(start,DayDuration.MONTHLY,3,end,start).ShouldBe(1);
        CalendarTermCalculator.CycleAt(start,DayDuration.MONTHLY,3,end,I("2024-02-29T00:00:00Z")).ShouldBe(2);
        CalendarTermCalculator.CycleAt(start,DayDuration.MONTHLY,3,end,I("2024-04-01T00:00:00Z")).ShouldBe(3);
        CalendarTermCalculator.CycleAt(start,DayDuration.MONTHLY,3,end,end).ShouldBe(0);
    }
    [Fact]
    public void Indefinite_uses_null_end_and_approved_end_still_bounds_it()
    {
        var start=I("2024-01-01T00:00:00Z");var end=I("2025-01-01T00:00:00Z");
        CalendarTermCalculator.Boundary(start,DayDuration.INDEFINITE,1).ShouldBeNull();
        CalendarTermCalculator.CycleAt(start,DayDuration.INDEFINITE,1,null,end).ShouldBe(1);
        CalendarTermCalculator.CycleAt(start,DayDuration.INDEFINITE,1,end,end).ShouldBe(0);
    }
    [Theory,InlineData(FeatureSet.kong),InlineData(FeatureSet.rawrzilla),InlineData(FeatureSet.bigbrain),InlineData(FeatureSet.offsite),InlineData(FeatureSet.solokong),InlineData(FeatureSet.solorawrzilla)]
    public void Unsupported_named_tiers_never_inherit_by_number(FeatureSet tier) => CapabilityCatalog.ForTier(tier).Count.ShouldBe(0);
    [Fact]
    public void Strict_cache_contract_rejects_missing_projection()
    {
        var session=Stored();var json=Newtonsoft.Json.Linq.JObject.Parse(CacheJsonSettings.Serialize(SessionProtocol.FromSession(session)));
        json.Remove("entitlements");Should.Throw<Newtonsoft.Json.JsonSerializationException>(()=>CacheJsonSettings.Deserialize<ActiveSession>(json.ToString()));
    }
    private static Session Stored()
    {
        var now=SystemClock.Instance.GetCurrentInstant();var session=new Session(Guid.NewGuid(),new byte[64],0,0,now,Period.FromHours(1),now.Plus(Duration.FromMinutes(20)),now.Plus(Duration.FromHours(1)),accountSecurityStamp:Guid.NewGuid());
        session.entitlements=new(session.accountId,7,FeatureSet.basic,["account.manage"],true,now,null,null,[]);return session;
    }
    [Theory,InlineData(false),InlineData(true)]
    public async Task Warm_and_cold_cache_replace_stale_paid_features_with_current_denial(bool warm)
    {
        var stored=Stored();var current=stored.entitlements!;var cached=SessionProtocol.FromSession(stored);cached.features=FeatureSet.premium;
        cached.entitlements=current with {Version=6,Features=FeatureSet.premium,Capabilities=["account.read","account.manage"]};
        var cache=Substitute.For<IActiveUserCacheService>();var repo=Substitute.For<ISessionRepo>();var jwt=Substitute.For<IJsonWebTokenUtility>();
        cache.GetSession(Arg.Any<string>(),cancellationToken:Arg.Any<CancellationToken>()).Returns(warm?cached:null);
        repo.GetSession(Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(stored);
        repo.ValidateCachedSessionTrust(Arg.Any<string>(),stored.accountId,stored.securityStamp,stored.accountSecurityStamp,Arg.Any<CancellationToken>())
            .Returns(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid,stored.accessExpiration,stored.sessionExpiration,null,stored.securityStamp,stored.accountSecurityStamp,FamilyId:stored.familyId,Generation:stored.generation,ProtocolVersion:2,Entitlements:current));
        jwt.ValidateAccessToken("access",Arg.Any<byte[]>(),Arg.Any<Instant>(),Arg.Any<Instant>(),JsonWebTokenPurpose.Active,Arg.Any<Duration?>()).Returns((IntraMessage.TOKEN_PASSED_VALIDATION,(string?)"web"));
        var context=new DefaultHttpContext();context.Request.Headers["AccessToken"]="access";
        await new JsonWebTokenMiddleware(_=>Task.CompletedTask).InvokeAsync(context,cache,jwt,repo,Options.Create(new JWTSettings {RefreshTokenAliveMinutes=15}));
        var actual=context.Items[AuthContextItems.ActiveSession].ShouldBeOfType<ActiveSession>();
        actual.features.ShouldBe(FeatureSet.basic);actual.entitlements!.Version.ShouldBe(7);actual.entitlements.Allows("account.read").ShouldBeFalse();
    }
    [Theory,InlineData(false),InlineData(true)]
    public void Capability_filter_rejects_denial_but_leaves_anonymous_proof_endpoints_accessible(bool anonymous)
    {
        var session=SessionProtocol.FromSession(Stored());var http=new DefaultHttpContext();http.Items[AuthContextItems.ActiveSession]=session;
        var descriptor=new Microsoft.AspNetCore.Mvc.Abstractions.ActionDescriptor {EndpointMetadata=anonymous?[new treehammock.Rigging.Authorization.Attributes.AllowAnonymous()]:[]};
        var action=new Microsoft.AspNetCore.Mvc.ActionContext(http,new Microsoft.AspNetCore.Routing.RouteData(),descriptor);
        var context=new Microsoft.AspNetCore.Mvc.Filters.AuthorizationFilterContext(action,[]);
        new treehammock.Rigging.Authorization.Attributes.RequireCapability("account.read").OnAuthorization(context);
        if(anonymous)context.Result.ShouldBeNull();else context.Result.ShouldBeOfType<Microsoft.AspNetCore.Mvc.JsonResult>().StatusCode.ShouldBe(403);
    }
    [Fact]
    public void Projection_cannot_authorize_another_account_or_an_expired_boundary()
    {
        var session=Stored();var now=SystemClock.Instance.GetCurrentInstant();var p=session.entitlements!;
        p.IsCurrent(Guid.NewGuid(),now).ShouldBeFalse();(p with {NextBoundary=now}).IsCurrent(session.accountId,now).ShouldBeFalse();
        (p with {RightsEnabled=false,Features=FeatureSet.premium}).IsCurrent(session.accountId,now).ShouldBeFalse();
    }

}
