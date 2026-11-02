using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;
using treehammock.DataLayer.Cache;
using treehammock.DataLayer.Operations;
using treehammock.Entities;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Dependencies;
using treehammock.RiggingSupport.Status;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class Cor09SessionTests
{
    private static JWTSettings Settings() => new() { JsonWebTokenIssuer="cor09", RefreshTokenBytes=64,
        RefreshTokenAliveMinutes_Short=15, MinimumRefreshIntervalSeconds=60 };
    private static Session Stored() => treehammock.Tests.Support.EntitlementTestData.Attach(new Session(Guid.NewGuid(), RandomNumberGenerator.GetBytes(64), 3, 0,
        SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromHours(1)), Period.FromDays(7),
        SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromSeconds(1)),
        SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromDays(6)), accountSecurityStamp:Guid.NewGuid()));
    private static SessionRefreshService Service(ISessionRefreshRepo repo, IActiveUserCacheService cache, IJsonWebTokenUtility tokens) =>
        new(repo,tokens,cache,Options.Create(Settings()),Options.Create(new SessionCacheFallbackSettings()));
    private static RefreshSessionRequest Request(Session session) => new() {protocolVersion=2,sessionId=session.familyId,generation=session.generation,
        refreshToken=SessionProtocol.RefreshCredential(session.refreshToken,session.securityStamp)};

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Explicit_refresh_retains_family_and_hard_deadline_even_if_cache_repair_fails(bool throws)
    {
        var old=Stored(); var request=Request(old); var repo=Substitute.For<ISessionRefreshRepo>();
        var cache=Substitute.For<IActiveUserCacheService>(); var tokens=Substitute.For<IJsonWebTokenUtility>();
        repo.FindAsync(Arg.Any<string>(),old.familyId,old.generation,Arg.Any<CancellationToken>()).Returns(new RefreshSessionSnapshot(old,"old-hash","web"));
        var access=SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(15));
        repo.RotateAsync(Arg.Any<RefreshSessionSnapshot>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<byte[]>(),Arg.Any<Guid>(),900,60,Arg.Any<CancellationToken>())
            .Returns(new RefreshSessionResult(true,"SESSION_REFRESHED",access,old.sessionExpiration,old.cutOff, Entitlements: treehammock.Tests.Support.EntitlementTestData.ForAccount(old.accountId)));
        tokens.GenerateAccessToken(Arg.Any<byte[]>(),"web",JsonWebTokenPurpose.Active).Returns("new-access");
        if (throws)
        {
            cache.SetSession(Arg.Any<string>(),Arg.Any<ActiveSession>(),Arg.Any<TimeSpan>(),cancellationToken:Arg.Any<CancellationToken>()).Returns(Task.FromException<bool>(new IOException()));
            cache.RevokeSession(Arg.Any<string>(),cancellationToken:Arg.Any<CancellationToken>()).Returns(Task.FromException<bool>(new IOException()));
        }
        var outcome=await Service(repo,cache,tokens).RefreshAsync(request,TestContext.Current.CancellationToken);
        outcome.Status.ShouldBe(200); outcome.Response.session!.sessionId.ShouldBe(old.familyId);
        outcome.Response.session.generation.ShouldBe(old.generation+1); outcome.Response.session.accessExpiration.ShouldBe(access);
        outcome.Response.session.refreshExpiration.ShouldBe(old.sessionExpiration); outcome.Response.accessToken.ShouldBe("new-access");
        outcome.Response.session.refreshToken.ShouldNotBe(request.refreshToken);
    }

    [Theory]
    [InlineData("REFRESH_CONFLICT",409)] [InlineData("REFRESH_CREDENTIAL_STALE",409)]
    [InlineData("REFRESH_CREDENTIAL_EXPIRED",409)] [InlineData("REFRESH_TOO_EARLY",429)]
    public async Task Losing_or_expired_refresh_never_publishes_proposed_tokens(string code,int status)
    {
        var old=Stored(); var repo=Substitute.For<ISessionRefreshRepo>(); var cache=Substitute.For<IActiveUserCacheService>();
        var tokens=Substitute.For<IJsonWebTokenUtility>(); tokens.GenerateAccessToken(Arg.Any<byte[]>(),Arg.Any<string>(),JsonWebTokenPurpose.Active).Returns("proposed");
        repo.FindAsync(Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<long>(),Arg.Any<CancellationToken>()).Returns(new RefreshSessionSnapshot(old,"old","web"));
        repo.RotateAsync(Arg.Any<RefreshSessionSnapshot>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<byte[]>(),Arg.Any<Guid>(),Arg.Any<int>(),Arg.Any<int>(),Arg.Any<CancellationToken>())
            .Returns(new RefreshSessionResult(false,code));
        var outcome=await Service(repo,cache,tokens).RefreshAsync(Request(old),TestContext.Current.CancellationToken);
        outcome.Status.ShouldBe(status); outcome.Response.accessToken.ShouldBeNull(); outcome.Response.session.ShouldBeNull();
        _=cache.DidNotReceiveWithAnyArgs().SetSession(default!,default!,default,cancellationToken:default);
        _=cache.DidNotReceiveWithAnyArgs().RevokeSession(default!,cancellationToken:default);
    }

    [Fact]
    public async Task Committed_refresh_that_expires_before_publication_withholds_credentials()
    {
        var old=Stored(); var repo=Substitute.For<ISessionRefreshRepo>();
        var cache=Substitute.For<IActiveUserCacheService>(); var tokens=Substitute.For<IJsonWebTokenUtility>();
        tokens.GenerateAccessToken(Arg.Any<byte[]>(),Arg.Any<string>(),JsonWebTokenPurpose.Active).Returns("expired-output");
        repo.FindAsync(Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<long>(),Arg.Any<CancellationToken>())
            .Returns(new RefreshSessionSnapshot(old,"old","web"));
        repo.RotateAsync(Arg.Any<RefreshSessionSnapshot>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<byte[]>(),Arg.Any<Guid>(),Arg.Any<int>(),Arg.Any<int>(),Arg.Any<CancellationToken>())
            .Returns(new RefreshSessionResult(true,"SESSION_REFRESHED",SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromSeconds(1)),old.sessionExpiration, Entitlements: treehammock.Tests.Support.EntitlementTestData.ForAccount(old.accountId)));
        var result=await Service(repo,cache,tokens).RefreshAsync(Request(old),TestContext.Current.CancellationToken);
        result.Status.ShouldBe(409); result.Code.ShouldBe("REFRESH_OUTPUT_EXPIRED");
        result.Response.accessToken.ShouldBeNull(); result.Response.session.ShouldBeNull(); result.Session.ShouldBeNull();
    }

    [Fact]
    public async Task Unknown_commit_propagates_for_status_reconciliation_without_token_publication()
    {
        var old=Stored(); var repo=Substitute.For<ISessionRefreshRepo>(); var cache=Substitute.For<IActiveUserCacheService>();
        var tokens=Substitute.For<IJsonWebTokenUtility>(); tokens.GenerateAccessToken(Arg.Any<byte[]>(),Arg.Any<string>(),JsonWebTokenPurpose.Active).Returns("proposed");
        repo.FindAsync(Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<long>(),Arg.Any<CancellationToken>()).Returns(new RefreshSessionSnapshot(old,"old","web"));
        repo.RotateAsync(Arg.Any<RefreshSessionSnapshot>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<byte[]>(),Arg.Any<Guid>(),Arg.Any<int>(),Arg.Any<int>(),Arg.Any<CancellationToken>())
            .Returns(Task.FromException<RefreshSessionResult>(new SecurityOperationException("SECURITY_OPERATION_UNKNOWN",503)));
        await Should.ThrowAsync<SecurityOperationException>(()=>Service(repo,cache,tokens).RefreshAsync(Request(old),TestContext.Current.CancellationToken));
        _=cache.DidNotReceiveWithAnyArgs().SetSession(default!,default!,default,cancellationToken:default);
    }

    [Theory]
    [InlineData((short)0)] [InlineData(short.MaxValue)]
    public async Task Ordinary_request_in_former_refresh_window_never_rotates_and_old_counter_does_not_deny_it(short refreshes)
    {
        var stored=Stored(); stored.accessExpiration=SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(1));
        stored.refreshes=refreshes; var session=SessionProtocol.FromSession(stored);
        var context=new DefaultHttpContext(); context.Request.Headers["AccessToken"]="access";
        var cache=Substitute.For<IActiveUserCacheService>(); var repo=Substitute.For<ISessionRepo>(); var tokens=Substitute.For<IJsonWebTokenUtility>();
        cache.GetSession(Arg.Any<string>(),cancellationToken:Arg.Any<CancellationToken>()).Returns(session);
        repo.ValidateCachedSessionTrust(Arg.Any<string>(),session.accountId,session.securityStamp,session.accountSecurityStamp,cancellationToken:Arg.Any<CancellationToken>())
            .Returns(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid,session.accessExpiration,session.sessionExpiration, Entitlements: treehammock.Tests.Support.EntitlementTestData.ForAccount(session.accountId)));
        tokens.ValidateAccessToken("access",session.refreshToken,Arg.Any<Instant>(),session.accessExpiration,JsonWebTokenPurpose.Active,Duration.Zero)
            .Returns((IntraMessage.TOKEN_PASSED_VALIDATION,(string?)"web"));
        await new JsonWebTokenMiddleware(_=>Task.CompletedTask).InvokeAsync(context,cache,tokens,repo,Options.Create(Settings()));
        context.Items[AuthContextItems.WebKey].ShouldBe("web"); context.Response.Headers["AccessToken"].ToString().ShouldBeEmpty();
        context.Response.Headers[SessionProtocol.FamilyHeader].ToString().ShouldBe(session.familyId.ToString("D"));
        _=repo.DidNotReceiveWithAnyArgs().RotateActiveSession(default,default!,default!,default!,cancellationToken:default);
        tokens.DidNotReceiveWithAnyArgs().GenerateAccessToken(default!,default!,default!);
    }

    [Fact]
    public async Task Access_expiry_is_exclusive_and_rejects_ordinary_request_without_revoking_refresh()
    {
        var old=Stored(); var session=SessionProtocol.FromSession(old); var context=new DefaultHttpContext();
        context.Request.Headers["AccessToken"]="expired"; var cache=Substitute.For<IActiveUserCacheService>();
        var repo=Substitute.For<ISessionRepo>(); var tokens=Substitute.For<IJsonWebTokenUtility>();
        repo.GetSession(Arg.Any<string>(),cancellationToken:Arg.Any<CancellationToken>()).Returns(old);
        await new JsonWebTokenMiddleware(_=>Task.CompletedTask).InvokeAsync(context,cache,tokens,repo,Options.Create(Settings()));
        context.Items[AuthContextItems.WebKey].ShouldBeNull();
        context.Response.Headers[SessionProtocol.ClearTokenHashHeader].ToString().ShouldBe(AccessTokenHashUtility.Hash("expired"));
        _=repo.DidNotReceiveWithAnyArgs().ExpireSession(default!,default,cancellationToken:default);
        _=tokens.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!,default!,default,default,default!,default);
        var real=new JsonWebTokenUtility(NullLogger<JsonWebTokenUtility>.Instance,Options.Create(Settings()));
        string token=real.GenerateAccessToken(old.refreshToken,"web"); var boundary=SystemClock.Instance.GetCurrentInstant();
        (await real.ValidateAccessToken(token,old.refreshToken,boundary,boundary)).Item1.ShouldBe(IntraMessage.TOKEN_EXPIRED_VALIDATION);
        (await real.ValidateAccessToken(real.GenerateAccessToken(old.refreshToken,"web","active"),old.refreshToken,boundary,boundary.Plus(Duration.FromMinutes(1)))).Item1.ShouldBe(IntraMessage.TOKEN_FAILED_VALIDATION);
    }
}
