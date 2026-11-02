using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Rigging.Config;
using treehammock.Rigging.Dependencies;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

public sealed class Svs03MiddlewareParityTests
{
    private sealed record Snapshot(int Status,int Next,bool Identity,bool WebKey,bool Subject,
        string? AppStatus,string? Protocol,string? Family,string? Generation,bool HashMatches,string? Failure,
        string[] Calls);

    public static IEnumerable<object[]> Cases()
    {
        foreach(string scenario in new[]{"active","no-credential","wrong-key","wrong-issuer","wrong-algorithm","missing-jti",
            "missing-purpose","missing-webkey","preauth","opaque-refresh","malformed","expired-access","expired-hard","cutoff",
            "authority-denied","no-session","db-down","capability-denied","cache-down","cache-corrupt","cache-write-false","cache-write-throws","malformed-db","trust-null","trust-failed"})
        foreach(bool warm in new[]{false,true})
        {
            if(!warm && scenario is "trust-null" or "trust-failed")continue;
            if(warm && scenario is "cache-write-false" or "cache-write-throws" or "malformed-db")continue;
            yield return new object[]{scenario,warm};
        }
    }
    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Shared_core_middleware_matches_the_frozen_pre_extraction_pipeline(string scenario,bool warm)
    {
        Snapshot old=await Run(true,new(warm,scenario));Snapshot current=await Run(false,new(warm,scenario));
        Assert.Equal(old with { Calls=[] },current with { Calls=[] });Assert.Equal(old.Calls,current.Calls);
    }

    private static async Task<Snapshot> Run(bool frozen,Svs03SessionFixture state)
    {
        var context=new DefaultHttpContext();context.RequestAborted=TestContext.Current.CancellationToken;
        context.Items[AuthContextItems.HashedAccessToken]="untrusted-old-hash";
        context.Items[AuthContextItems.WebKey]="untrusted-old-web";context.Items[AuthContextItems.ActiveSession]=state.Current;
        if(state.Scenario!="no-credential")context.Request.Headers["Authorization"]="Bearer "+state.Credential;
        int next=0;
        Task Downstream(HttpContext http)
        {
            next++;var auth=new AuthorizationFilterContext(new ActionContext(http,new RouteData(),new ActionDescriptor()),new List<IFilterMetadata>());
            new Authenticate().OnAuthorization(auth);if(auth.Result is null)new RequireCapability("account.read").OnAuthorization(auth);
            http.Response.StatusCode=(auth.Result as JsonResult)?.StatusCode??200;return Task.CompletedTask;
        }
        string? failure=null;
        var tokens=new JsonWebTokenUtility(NullLogger<JsonWebTokenUtility>.Instance,Options.Create(new JWTSettings {JsonWebTokenIssuer=Svs03SessionFixture.Issuer}),new Svs03SessionFixture.RecordingVerifier(state));
        try
        {
            if(frozen)await new Svs03PreExtractionMiddleware(Downstream).InvokeAsync(context,state.Cache,tokens,state.Repository,Options.Create(new JWTSettings{RefreshTokenAliveMinutes=10}));
            else await new JsonWebTokenMiddleware(Downstream).InvokeAsync(context,state.Cache,tokens,state.Repository,Options.Create(new JWTSettings{RefreshTokenAliveMinutes=10}));
        }
        catch(DependencyUnavailableException ex){failure=ex.Failure.Dependency+":"+ex.Failure.Kind;}
        bool hash=context.Response.Headers[SessionProtocol.ClearTokenHashHeader].ToString()==AccessTokenHashUtility.Hash(state.Credential);
        return new(context.Response.StatusCode,next,context.Items[AuthContextItems.HashedAccessToken] is string,
            context.Items[AuthContextItems.WebKey] is string,context.Items[AuthContextItems.ActiveSession] is ActiveSession,
            Header("AppStatus"),Header(SessionProtocol.VersionHeader),Header(SessionProtocol.FamilyHeader),Header(SessionProtocol.GenerationHeader),hash,failure,state.Events.ToArray());
        string? Header(string key)=>context.Response.Headers.TryGetValue(key,out var value)?value.ToString():null;
    }

    [Theory]
    [InlineData("access")][InlineData("hard")][InlineData("cutoff")][InlineData("account")]
    [InlineData("family")][InlineData("generation")][InlineData("account-stamp")][InlineData("session-stamp")][InlineData("valid")]
    public async Task Rechecking_after_cache_await_cannot_publish_rebound_or_expired_identity(string boundary)
    {
        var state=new Svs03SessionFixture(false);
        state.OnCacheWrite=session=>session.entitlements=session.entitlements! with {NextBoundary=SystemClock.Instance.GetCurrentInstant()};
        state.OnReload=session=>
        {
            var now=SystemClock.Instance.GetCurrentInstant();
            if(boundary=="access")session.accessExpiration=now;
            if(boundary=="hard")session.sessionExpiration=now;
            if(boundary=="cutoff")session.cutOff=now;
            if(boundary=="account")session.accountId=Guid.NewGuid();
            if(boundary=="family")session.familyId=Guid.NewGuid();
            if(boundary=="generation")session.generation++;
            if(boundary=="account-stamp")session.accountSecurityStamp=Guid.NewGuid();
            if(boundary=="session-stamp")session.securityStamp=Guid.NewGuid();
            return session;
        };
        var result=await Run(false,state);Assert.Equal(2,state.Gets);Assert.Equal(boundary=="valid",result.Subject);
        Assert.Equal(boundary=="valid"?200:401,result.Status);if(boundary!="valid"){Assert.False(result.Identity);Assert.False(result.WebKey);Assert.Null(result.Family);}
    }

    [Theory]
    [InlineData("/account/refresh",true)][InlineData("/ACCOUNT/REFRESH/",true)]
    [InlineData("/account/refresh",false)][InlineData("/account/refresh-extra",true)]
    public async Task Refresh_bypass_is_limited_to_exact_POST_path_and_clears_old_context(string path,bool post)
    {
        var state=new Svs03SessionFixture(scenario:"expired-access");var context=new DefaultHttpContext();
        context.Request.Method=post?"POST":"GET";context.Request.Path=path;context.Request.Headers["AccessToken"]=state.Credential;
        context.Items[AuthContextItems.HashedAccessToken]="old";context.Items[AuthContextItems.WebKey]="old";context.Items[AuthContextItems.ActiveSession]=state.Current;
        int next=0;
        await new JsonWebTokenMiddleware(_=>{next++;return Task.CompletedTask;}).InvokeAsync(context,state.Cache,state.Tokens,state.Repository,Options.Create(new JWTSettings{RefreshTokenAliveMinutes=10}));
        bool bypass=post && !path.EndsWith("-extra",StringComparison.Ordinal);Assert.Equal(1,next);
        Assert.Null(context.Items[AuthContextItems.HashedAccessToken]);Assert.Null(context.Items[AuthContextItems.WebKey]);Assert.Null(context.Items[AuthContextItems.ActiveSession]);
        Assert.Equal(bypass?0:1,state.Gets+state.Trusts);Assert.Equal(!bypass,context.Response.Headers.ContainsKey(SessionProtocol.ClearTokenHashHeader));
    }

    [Fact]
    public async Task Request_cancellation_reaches_repository_and_never_publishes_identity()
    {
        var state=new Svs03SessionFixture(false);using var cancel=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var entered=new TaskCompletionSource<CancellationToken>(TaskCreationOptions.RunContinuationsAsynchronously);
        state.ReadOverride=async token=>{entered.SetResult(token);await Task.Delay(Timeout.InfiniteTimeSpan,token);return null;};
        var context=new DefaultHttpContext();context.RequestAborted=cancel.Token;context.Request.Headers["AccessToken"]=state.Credential;int next=0;
        var pending=new JsonWebTokenMiddleware(_=>{next++;return Task.CompletedTask;}).InvokeAsync(context,state.Cache,state.Tokens,state.Repository,Options.Create(new JWTSettings()));
        CancellationToken native=await entered.Task.WaitAsync(TestContext.Current.CancellationToken);cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>pending);Assert.True(native.IsCancellationRequested);
        Assert.Equal(0,next);Assert.Equal(0,state.Writes);Assert.Null(context.Items[AuthContextItems.ActiveSession]);Assert.Null(context.Items[AuthContextItems.WebKey]);
        Assert.Null(context.Items[AuthContextItems.HashedAccessToken]);Assert.False(context.Response.Headers.ContainsKey(SessionProtocol.FamilyHeader));
    }

    [Fact]
    public async Task Late_repository_completion_after_deadline_cannot_change_a_refusal()
    {
        var state=new Svs03SessionFixture(false);var late=new TaskCompletionSource<Session?>(TaskCreationOptions.RunContinuationsAsynchronously);
        state.ReadOverride=_=>late.Task;var context=new DefaultHttpContext();context.Request.Headers["AccessToken"]=state.Credential;int next=0;
        var middleware=new JsonWebTokenMiddleware(_=>{next++;return Task.CompletedTask;});
        await Assert.ThrowsAsync<DependencyUnavailableException>(()=>middleware.InvokeAsync(context,state.Cache,state.Tokens,state.Repository,
            Options.Create(new JWTSettings()),Options.Create(new SessionCacheFallbackSettings{DatabaseFallbackTimeoutMilliseconds=30})));
        late.SetResult(state.Current.toSession());await Task.Yield();
        Assert.Equal(0,next);Assert.Equal(0,state.Writes);Assert.Null(context.Items[AuthContextItems.ActiveSession]);Assert.Null(context.Items[AuthContextItems.WebKey]);
        Assert.Null(context.Items[AuthContextItems.HashedAccessToken]);Assert.False(context.Response.Headers.ContainsKey(SessionProtocol.FamilyHeader));
    }
}
